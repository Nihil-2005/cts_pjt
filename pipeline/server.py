"""FastAPI backend server for the DevSecOps Dashboard.

Provides:
- JWT authentication (login, token verification)
- REST API for products, scanners, pipeline, tickets
- WebSocket for real-time scanner progress updates
- Static file serving for the dashboard

Usage:
    python -m pipeline.server
    # or
    uvicorn pipeline.server:app --host 0.0.0.0 --port 8000 --reload
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Depends,
    Header,
    Query,
)
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .auth import create_token, verify_token, authenticate, _DEFAULT_USER
from .scanner_manager import get_manager, ScannerStatus
from .config import Config

# ─── App setup ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="DevSecOps Risk Intelligence Dashboard",
    description="Live security scanning dashboard with auto-ticketing",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Config path ─────────────────────────────────────────────────────────────

CONFIG_PATH = os.environ.get("CONFIG_PATH", "config.json")


def _load_config() -> Config:
    return Config.load(CONFIG_PATH)


def _save_config(cfg: Config):
    """Save config back to file."""
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg._data, f, indent=2)


# ─── Auth dependency ─────────────────────────────────────────────────────────

async def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    """Extract and verify JWT from Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    token = authorization.replace("Bearer ", "")
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload.get("sub", "unknown")


# ─── WebSocket manager ──────────────────────────────────────────────────────

class ConnectionManager:
    """Manages WebSocket connections for live updates."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_connections.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active_connections.discard(ws)

    async def broadcast(self, data: dict):
        dead = set()
        for ws in self.active_connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.add(ws)
        self.active_connections -= dead


ws_manager = ConnectionManager()


# ─── Pydantic models ────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    token: str
    expires_in: int
    username: str

class ProductCreate(BaseModel):
    product_id: str
    display_name: str
    url: str
    github_repo: str = ""
    owner: str = "unassigned"
    asset_criticality: int = 5
    data_sensitivity: int = 5
    exposure: int = 8
    business_impact: int = 5
    control_effectiveness: int = 3
    trivy_image: str = ""
    scanners: Dict[str, str] = {}

class ScanRequest(BaseModel):
    product: str
    scanners: Optional[List[str]] = None  # None = all configured

class PipelineRequest(BaseModel):
    products: Optional[List[str]] = None
    skip_enrich: bool = False
    skip_ai: bool = True


# ─── Auth routes ─────────────────────────────────────────────────────────────

@app.post("/api/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    """Authenticate and get JWT token."""
    if not authenticate(req.username, req.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    from .auth import _DEFAULT_TTL
    token = create_token(req.username, ttl_seconds=_DEFAULT_TTL)
    return LoginResponse(
        token=token,
        expires_in=_DEFAULT_TTL,
        username=req.username,
    )


@app.get("/api/auth/me")
async def auth_me(user: str = Depends(get_current_user)):
    """Get current user info."""
    return {"username": user, "authenticated": True}


# ─── Product routes ──────────────────────────────────────────────────────────

@app.get("/api/products")
async def list_products(user: str = Depends(get_current_user)):
    """List all configured products."""
    cfg = _load_config()
    products = cfg.products
    manager = get_manager()

    # Check app status for each product
    app_statuses = {}
    for pid, pcfg in products.items():
        url = pcfg.get("url", "")
        if url:
            app_statuses[pid] = manager.check_app_status(url)

    return {
        "products": products,
        "app_statuses": app_statuses,
    }


@app.post("/api/products")
async def create_product(req: ProductCreate, user: str = Depends(get_current_user)):
    """Add a new product to config."""
    cfg = _load_config()

    if req.product_id in cfg.products:
        raise HTTPException(status_code=409, detail="Product already exists")

    scanners = req.scanners
    if not scanners:
        scanners = {"nuclei": req.url, "zap": req.url, "wapiti": req.url}
        if req.trivy_image:
            scanners["trivy"] = req.trivy_image

    product_data = {
        "display_name": req.display_name,
        "owner": req.owner,
        "asset_criticality": req.asset_criticality,
        "business_impact": req.business_impact,
        "exposure": req.exposure,
        "control_effectiveness": req.control_effectiveness,
        "data_sensitivity": req.data_sensitivity,
        "url": req.url,
        "github_repo": req.github_repo,
        "scanners": scanners,
    }

    cfg._data.setdefault("products", {})[req.product_id] = product_data
    _save_config(cfg)

    return {"status": "created", "product_id": req.product_id}


@app.delete("/api/products/{product_id}")
async def delete_product(product_id: str, user: str = Depends(get_current_user)):
    """Remove a product from config."""
    cfg = _load_config()
    if product_id not in cfg.products:
        raise HTTPException(status_code=404, detail="Product not found")

    del cfg._data["products"][product_id]
    _save_config(cfg)

    return {"status": "deleted", "product_id": product_id}


@app.get("/api/products/{product_id}")
async def get_product(product_id: str, user: str = Depends(get_current_user)):
    """Get details for a single product."""
    cfg = _load_config()
    if product_id not in cfg.products:
        raise HTTPException(status_code=404, detail="Product not found")

    product = cfg.products[product_id]
    manager = get_manager()
    status = manager.check_app_status(product.get("url", ""))

    return {"product": product, "app_status": status}


# ─── Scanner routes ──────────────────────────────────────────────────────────

@app.get("/api/scanners/status")
async def scanner_status(user: str = Depends(get_current_user)):
    """Get Docker availability and scanner images status."""
    manager = get_manager()
    docker_ok = manager.check_docker()

    images_status = {}
    if docker_ok:
        for name, image in manager.__class__.__dict__.get("SCANNER_IMAGES", {}).items():
            images_status[name] = {"image": image, "status": "available"}

    return {
        "docker_available": docker_ok,
        "images": images_status,
        "active_jobs": len(manager.get_active_jobs()),
        "jobs_summary": manager.get_job_summary(),
    }


@app.post("/api/scans/start")
async def start_scan(req: ScanRequest, user: str = Depends(get_current_user)):
    """Start scanning a product with configured scanners."""
    cfg = _load_config()
    if req.product not in cfg.products:
        raise HTTPException(status_code=404, detail="Product not found")

    product_config = cfg.products[req.product]
    manager = get_manager()

    # Check if app is reachable first
    url = product_config.get("url", "")
    if url:
        app_status = manager.check_app_status(url)
        if app_status["status"] == "down":
            raise HTTPException(
                status_code=503,
                detail=f"Target app is not reachable at {url}"
            )

    jobs = manager.start_product_scans(
        product_id=req.product,
        product_config=product_config,
        scanners=req.scanners,
    )

    return {
        "status": "started",
        "product": req.product,
        "jobs": [j.to_dict() for j in jobs],
    }


@app.get("/api/scans/jobs")
async def list_jobs(user: str = Depends(get_current_user)):
    """List all scan jobs with their status."""
    manager = get_manager()
    return manager.get_job_summary()


@app.get("/api/scans/jobs/{job_id}")
async def get_job(job_id: str, user: str = Depends(get_current_user)):
    """Get details for a specific scan job."""
    manager = get_manager()
    job = manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.to_dict()


@app.get("/api/scans/products/{product_id}/status")
async def product_scan_status(product_id: str, user: str = Depends(get_current_user)):
    """Get scan status for a specific product."""
    manager = get_manager()
    all_jobs = manager.get_all_jobs()
    product_jobs = [j for j in all_jobs if j.product == product_id]

    return {
        "product": product_id,
        "total_jobs": len(product_jobs),
        "jobs": [j.to_dict() for j in product_jobs],
    }


# ─── Pipeline routes ─────────────────────────────────────────────────────────

_pipeline_running = False


@app.post("/api/pipeline/run")
async def run_pipeline(req: PipelineRequest, user: str = Depends(get_current_user)):
    """Run the full 8-stage pipeline. Runs in background thread."""
    global _pipeline_running
    if _pipeline_running:
        raise HTTPException(status_code=409, detail="Pipeline is already running")

    cfg = _load_config()
    manager = get_manager()

    def _run():
        global _pipeline_running
        _pipeline_running = True
        try:
            from . import run as pipeline_run
            pipeline_run.run_pipeline(
                reports_dir=manager.get_reports_dir(),
                config=cfg,
                out_dir="outputs",
                products=req.products,
                skip_enrich=req.skip_enrich,
                skip_ai=req.skip_ai,
            )
        except Exception as e:
            print(f"[PIPELINE ERROR] {e}")
        finally:
            _pipeline_running = False

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return {"status": "started", "message": "Pipeline running in background"}


@app.get("/api/pipeline/status")
async def pipeline_status(user: str = Depends(get_current_user)):
    """Check if pipeline is running."""
    return {"running": _pipeline_running}


# ─── GitHub ticket routes ────────────────────────────────────────────────────

@app.post("/api/tickets/create")
async def create_tickets(
    threshold: int = 60,
    dry_run: bool = False,
    user: str = Depends(get_current_user),
):
    """Auto-create GitHub Issues for findings above threshold."""
    findings_path = "outputs/ranked_findings.json"
    if not os.path.exists(findings_path):
        raise HTTPException(status_code=404, detail="No pipeline output found. Run pipeline first.")

    cfg = _load_config()
    products_config = cfg._data.get("products", {})

    from . import github_tickets

    results = {}
    for product_id, product_cfg in products_config.items():
        repo = product_cfg.get("github_repo", "")
        if not repo:
            continue

        result = github_tickets.create_tickets_per_product(
            findings_path=findings_path,
            products_config=products_config,
            product_id=product_id,
            repo=repo,
            threshold=threshold,
            dry_run=dry_run,
        )
        results[product_id] = result

    return {"results": results, "dry_run": dry_run}


# ─── WebSocket for live updates ──────────────────────────────────────────────

@app.websocket("/ws/live")
async def websocket_live(ws: WebSocket):
    """WebSocket endpoint for real-time scanner progress updates."""
    # Verify token from query param
    token = ws.query_params.get("token", "")
    if token:
        payload = verify_token(token)
        if not payload:
            await ws.close(code=4001, reason="Invalid token")
            return

    await ws_manager.connect(ws)
    manager = get_manager()

    # Register callback for live updates
    def on_job_update(job):
        data = {
            "type": "scan_update",
            "data": job.to_dict(),
        }
        asyncio.run_coroutine_threadsafe(
            ws_manager.broadcast(data),
            asyncio.get_event_loop() if asyncio.get_event_loop().is_running() else None,
        )

    manager.on_status_change(on_job_update)

    try:
        while True:
            # Keep connection alive, handle client messages
            data = await ws.receive_text()
            msg = json.loads(data)

            if msg.get("type") == "ping":
                await ws.send_json({"type": "pong"})

            elif msg.get("type") == "get_status":
                await ws.send_json({
                    "type": "status",
                    "data": manager.get_job_summary(),
                })

    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)


# ─── Dashboard static file ──────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the main dashboard HTML."""
    dashboard_path = Path("outputs/risk_dashboard.html")
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path))

    # Fallback: serve the login page
    return HTMLResponse(_LOGIN_HTML)


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard_alt():
    """Alternative route for the dashboard."""
    return await serve_dashboard()


# ─── Login page HTML ─────────────────────────────────────────────────────────

_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DevSecOps Dashboard — Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:#050a14;color:#e2e8f0;
min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-card{background:#0d1521;border:1px solid rgba(255,255,255,.07);border-radius:16px;
padding:40px;width:380px;box-shadow:0 8px 48px rgba(0,0,0,.5)}
.logo{text-align:center;margin-bottom:32px}
.logo-icon{font-size:40px;margin-bottom:8px}
.logo-text{font-size:20px;font-weight:800;background:linear-gradient(135deg,#3b82f6,#06b6d4);
-webkit-background-clip:text;-webkit-text-fill-color:transparent}
h2{font-size:14px;font-weight:500;color:#94a3b8;text-align:center;margin-bottom:24px}
.field{margin-bottom:16px}
.field label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;
letter-spacing:.8px;color:#64748b;margin-bottom:6px}
.field input{width:100%;padding:10px 14px;background:#131f30;border:1px solid rgba(255,255,255,.07);
border-radius:8px;color:#e2e8f0;font-size:14px;outline:none;transition:border-color .2s}
.field input:focus{border-color:rgba(59,130,246,.5)}
.btn{width:100%;padding:12px;border:none;border-radius:8px;font-size:14px;font-weight:600;
cursor:pointer;background:linear-gradient(135deg,#3b82f6,#6366f1);color:#fff;
transition:opacity .2s;margin-top:8px}
.btn:hover{opacity:.9}
.btn:disabled{opacity:.5;cursor:not-allowed}
.error{color:#ef4444;font-size:12px;text-align:center;margin-top:12px;display:none}
.hint{text-align:center;margin-top:16px;font-size:11px;color:#64748b}
</style>
</head>
<body>
<div class="login-card">
  <div class="logo">
    <div class="logo-icon">&#x1f6e1;&#xfe0f;</div>
    <div class="logo-text">RISK INTELLIGENCE</div>
  </div>
  <h2>Sign in to the dashboard</h2>
  <form id="login-form">
    <div class="field">
      <label>Username</label>
      <input id="username" type="text" value="admin" autofocus>
    </div>
    <div class="field">
      <label>Password</label>
      <input id="password" type="password" value="admin">
    </div>
    <button class="btn" type="submit" id="login-btn">Sign In</button>
    <div class="error" id="error-msg"></div>
  </form>
  <div class="hint">Default: admin / admin</div>
</div>
<script>
document.getElementById('login-form').addEventListener('submit', async(e)=>{
  e.preventDefault();
  const btn=document.getElementById('login-btn');
  const err=document.getElementById('error-msg');
  btn.disabled=true;btn.textContent='Signing in...';err.style.display='none';
  try{
    const resp=await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        username:document.getElementById('username').value,
        password:document.getElementById('password').value
      })
    });
    const data=await resp.json();
    if(!resp.ok)throw new Error(data.detail||'Login failed');
    localStorage.setItem('token',data.token);
    localStorage.setItem('token_exp',Date.now()+data.expires_in*1000);
    localStorage.setItem('username',data.username);
    window.location.href='/dashboard';
  }catch(e){err.textContent=e.message;err.style.display='block';}
  finally{btn.disabled=false;btn.textContent='Sign In';}
});
</script>
</body>
</html>"""


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    """Run the server."""
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    print(f"")
    print(f"  DevSecOps Risk Intelligence Dashboard")
    print(f"  Server starting on http://0.0.0.0:{port}")
    print(f"  Login: admin / admin")
    print(f"")
    uvicorn.run(
        "pipeline.server:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
