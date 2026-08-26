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
import re
import stat
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from fastapi import (
    FastAPI,
    Request,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Depends,
    Header,
)
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from .auth import create_token, verify_token, authenticate
from .scanner_manager import get_manager, SCANNER_IMAGES
from .config import Config

# ─── Load .env into os.environ at startup ────────────────────────────────────────────────────────────────────────────────

def _load_env_file():
    """Load .env file into os.environ (does not override existing vars)."""
    env_path = Path(".env")
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if k and (k not in os.environ or not os.environ[k]):  # Load if missing or empty
                os.environ[k] = v

_load_env_file()

# ─── App setup ────────────────────────────────────────────────────────────

app = FastAPI(
    title="DevSecOps Risk Intelligence Dashboard",
    description="Live security scanning dashboard with auto-ticketing",
    version="2.0.0",
)

# CORS: restrict to known origins (set via env var)
_ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:8000,http://localhost:3000,http://127.0.0.1:8000",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _ALLOWED_ORIGINS if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    max_age=600,
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── Config path ─────────────────────────────────────────────────────────────

CONFIG_PATH = os.environ.get("CONFIG_PATH", "config.json")


def _load_config() -> Config:
    return Config.load(CONFIG_PATH)


def _save_config(cfg: Config):
    """Save config back to file atomically."""
    cfg.save(CONFIG_PATH)


# ─── Auth dependency ─────────────────────────────────────────────────────────


async def get_current_user(
    request: Request, authorization: Optional[str] = Header(None)
) -> str:
    """Extract and verify JWT from cookie or Authorization header."""
    # Try cookie first
    token = request.cookies.get("access_token")
    # Fallback to Authorization header (for API clients)
    if not token and authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:]
        else:
            token = authorization
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication")
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload.get("sub", "unknown")


# ─── WebSocket manager ──────────────────────────────────────────────────────


class ConnectionManager:
    """Manages WebSocket connections for live updates (thread-safe)."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = threading.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        with self._lock:
            self.active_connections.add(ws)

    def disconnect(self, ws: WebSocket):
        with self._lock:
            self.active_connections.discard(ws)

    async def broadcast(self, data: dict):
        dead = set()
        with self._lock:
            connections = list(self.active_connections)
        for ws in connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.add(ws)
        if dead:
            with self._lock:
                self.active_connections -= dead


ws_manager = ConnectionManager()
_server_loop: Optional[asyncio.AbstractEventLoop] = None


@app.on_event("startup")
async def _capture_loop():
    global _server_loop
    _server_loop = asyncio.get_running_loop()


# ─── Pydantic models ────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    status: str = "ok"
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

    @field_validator("product_id")
    @classmethod
    def validate_product_id(cls, v):
        if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", v):
            raise ValueError(
                "product_id must be 1-64 alphanumeric chars, hyphens, or underscores"
            )
        return v

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http or https")
        if not parsed.netloc:
            raise ValueError("URL must have a valid host")
        return v


class ScanRequest(BaseModel):
    product: str
    scanners: Optional[List[str]] = None  # None = all configured


class PipelineRequest(BaseModel):
    products: Optional[List[str]] = None
    skip_enrich: bool = False
    skip_ai: bool = True


# ─── Auth routes ─────────────────────────────────────────────────────────────


@app.post("/api/login", response_model=LoginResponse)
@limiter.limit("5/minute")
async def login(request: Request, req: LoginRequest):
    """Authenticate and get JWT token (rate-limited)."""
    if not authenticate(req.username, req.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    from .auth import _DEFAULT_TTL

    token = create_token(req.username, ttl_seconds=_DEFAULT_TTL)
    response = JSONResponse(
        content={
            "status": "ok",
            "expires_in": _DEFAULT_TTL,
            "username": req.username,
        }
    )
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,  # Set True behind HTTPS
        samesite="lax",
        max_age=_DEFAULT_TTL,
    )
    return response


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
        scanners = {"nuclei": req.url, "zap": req.url, "wapiti": req.url, "nmap": req.url}
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

    cfg.data.setdefault("products", {})[req.product_id] = product_data
    _save_config(cfg)

    return {"status": "created", "product_id": req.product_id}


@app.delete("/api/products/{product_id}")
async def delete_product(product_id: str, user: str = Depends(get_current_user)):
    """Remove a product from config."""
    cfg = _load_config()
    if product_id not in cfg.products:
        raise HTTPException(status_code=404, detail="Product not found")

    del cfg.data["products"][product_id]
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
        for name, image in SCANNER_IMAGES.items():
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
                status_code=503, detail=f"Target app is not reachable at {url}"
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

_pipeline_lock = threading.Lock()


@app.post("/api/pipeline/run")
async def run_pipeline(req: PipelineRequest, user: str = Depends(get_current_user)):
    """Run the full 9-stage pipeline. Runs in background thread."""
    if not _pipeline_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Pipeline is already running")

    cfg = _load_config()
    manager = get_manager()

    def _run():
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
            _pipeline_lock.release()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return {"status": "started", "message": "Pipeline running in background"}


@app.get("/api/pipeline/status")
async def pipeline_status(user: str = Depends(get_current_user)):
    """Check if pipeline is running."""
    return {"running": _pipeline_lock.locked()}


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
        raise HTTPException(
            status_code=404, detail="No pipeline output found. Run pipeline first."
        )

    cfg = _load_config()
    products_config = cfg.data.get("products", {})

    from . import github_tickets
    from .models import Finding

    with open(findings_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    findings = []
    for item in data:
        f = Finding(**{k: v for k, v in item.items() if k != "raw"})
        f.score_breakdown = item.get("score_breakdown", {})
        f.remediation_suggestions = item.get("remediation_suggestions", [])
        findings.append(f)

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token and not dry_run:
        raise HTTPException(status_code=400, detail="GITHUB_TOKEN not configured")

    labels = cfg.data.get("reporting", {}).get(
        "github_labels", ["security", "auto-generated"]
    )

    # Lifecycle-gated ticketing when the tracking DB exists
    lifecycle_mgr = None
    if os.path.exists("outputs/lifecycle.db"):
        from .lifecycle import LifecycleManager

        lifecycle_mgr = LifecycleManager("outputs/lifecycle.db")
    try:
        result = github_tickets.create_tickets_per_product(
            findings=findings,
            products_config=products_config,
            token=token,
            threshold=float(threshold),
            labels=labels,
            dry_run=dry_run,
            lifecycle=lifecycle_mgr,
        )
    finally:
        if lifecycle_mgr is not None:
            lifecycle_mgr.close()

    return {"results": result, "dry_run": dry_run}


# ─── Lifecycle routes ─────────────────────────────────────────────────────


@app.get("/api/lifecycle/dashboard")
async def lifecycle_dashboard(user: str = Depends(get_current_user)):
    """Get lifecycle dashboard data."""
    from .lifecycle import LifecycleManager

    lc = LifecycleManager("outputs/lifecycle.db")
    data = lc.get_dashboard_data()
    lc.close()
    return data


@app.get("/api/lifecycle/overdue")
async def lifecycle_overdue(user: str = Depends(get_current_user)):
    """Get overdue findings (SLA breached)."""
    from .lifecycle import LifecycleManager

    lc = LifecycleManager("outputs/lifecycle.db")
    data = lc.get_overdue_summary()
    lc.close()
    return data


@app.post("/api/lifecycle/{finding_id}/transition")
async def lifecycle_transition(
    finding_id: str,
    status: str,
    reason: str = "",
    user: str = Depends(get_current_user),
):
    """Transition a finding's lifecycle status."""
    from .lifecycle import LifecycleManager

    lc = LifecycleManager("outputs/lifecycle.db")
    ok = lc.transition_status(finding_id, status, reason)
    lc.close()
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid transition")
    return {"status": status, "finding_id": finding_id}


# ─── API Key Management ────────────────────────────────────────────────────


class ApiKeysUpdate(BaseModel):
    groq_api_key: Optional[str] = None
    nvd_api_key: Optional[str] = None
    github_token: Optional[str] = None
    jira_url: Optional[str] = None
    jira_user: Optional[str] = None
    jira_token: Optional[str] = None
    jira_project: Optional[str] = None
    defectdojo_url: Optional[str] = None
    defectdojo_api_key: Optional[str] = None
    overwrite: Optional[bool] = True  # Default: overwrite existing keys


@app.get("/api/config/keys")
async def get_config_keys(user: str = Depends(get_current_user)):
    """Get API key configuration (masked)."""
    env_path = ".env"
    keys = {}
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip()
                    keys[k] = {"set": bool(v), "length": len(v) if v else 0}
    return {"keys": keys}


@app.post("/api/config/keys")
async def update_config_keys(req: ApiKeysUpdate, user: str = Depends(get_current_user)):
    """Update API key configuration."""
    env_path = ".env"
    existing = {}
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    existing[k.strip()] = v.strip()

    # Update only provided keys
    data = req.model_dump(exclude_none=True)
    overwrite = data.pop("overwrite", True)  # Extract overwrite flag
    # Pydantic camelCase -> UPPER_SNAKE_CASE mapping
    key_map = {
        "groq_api_key": "GROQ_API_KEY",
        "nvd_api_key": "NVD_API_KEY",
        "github_token": "GITHUB_TOKEN",
        "jira_url": "JIRA_URL",
        "jira_user": "JIRA_USER",
        "jira_token": "JIRA_TOKEN",
        "jira_project": "JIRA_PROJECT",
        "defectdojo_url": "DEFECTDOJO_URL",
        "defectdojo_api_key": "DEFECTDOJO_API_KEY",
    }
    for k, v in data.items():
        env_key = key_map.get(k, k.upper())
        if v:  # Only update if value is non-empty
            if overwrite or env_key not in existing:
                existing[env_key] = v

    # Write back atomically via temp file + rename
    import tempfile

    fd, tmp_path = tempfile.mkstemp(
        dir=os.path.dirname(env_path) or ".", suffix=".env.tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            for k, v in existing.items():
                f.write(f"{k}={v}\n")
        os.replace(tmp_path, env_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    try:
        os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600 — owner read/write only
    except OSError:
        pass  # no-op on Windows

    # Hot-reload: update os.environ so changes take effect immediately
    for k, v in existing.items():
        if v:
            os.environ[k] = v

    return {"status": "updated", "keys_updated": list(data.keys())}


@app.get("/api/config")
async def get_config(user: str = Depends(get_current_user)):
    """Get full config (products, scoring, etc.)."""
    cfg = _load_config()
    return cfg.data


class ConfigUpdate(BaseModel):
    scoring_weights: Optional[dict] = None
    sla_days: Optional[dict] = None
    quarantine_rules: Optional[list] = None


@app.post("/api/config")
async def update_config(req: ConfigUpdate, user: str = Depends(get_current_user)):
    """Update config with validated fields only."""
    cfg = _load_config()
    updates = req.model_dump(exclude_none=True)
    for key, value in updates.items():
        if (
            key in cfg.data
            and isinstance(value, dict)
            and isinstance(cfg.data[key], dict)
        ):
            cfg.data[key].update(value)
        else:
            cfg.data[key] = value
    _save_config(cfg)
    return {"status": "updated"}


# ─── Export routes ─────────────────────────────────────────────────────────


@app.get("/api/exports/sarif")
async def export_sarif(user: str = Depends(get_current_user)):
    """Download SARIF file."""
    path = "outputs/results.sarif"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Run pipeline first")
    return FileResponse(path, media_type="application/json", filename="results.sarif")


@app.get("/api/exports/cyclonedx")
async def export_cyclonedx(user: str = Depends(get_current_user)):
    """Download CycloneDX SBOM."""
    path = "outputs/bom.json"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Run pipeline first")
    return FileResponse(path, media_type="application/json", filename="bom.json")


@app.get("/api/exports/defectdojo")
async def export_defectdojo(user: str = Depends(get_current_user)):
    """Download DefectDojo import file."""
    path = "outputs/defectdojo_import.json"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Run pipeline first")
    return FileResponse(
        path, media_type="application/json", filename="defectdojo_import.json"
    )


# ─── Jira routes ───────────────────────────────────────────────────────────


@app.post("/api/jira/test")
async def jira_test(user: str = Depends(get_current_user)):
    """Test Jira connection."""
    from .jira_client import JiraClient

    client = JiraClient()
    return client.test_connection()


@app.post("/api/jira/create")
async def jira_create(threshold: int = 60, user: str = Depends(get_current_user)):
    """Create Jira Issues for findings above threshold."""
    from .jira_client import JiraClient

    client = JiraClient()
    if not client.configured:
        raise HTTPException(
            status_code=400,
            detail="Jira not configured. Set JIRA_URL, JIRA_USER, JIRA_TOKEN, JIRA_PROJECT",
        )

    findings_path = "outputs/ranked_findings.json"
    if not os.path.exists(findings_path):
        raise HTTPException(status_code=404, detail="No pipeline output found")

    import json as _json

    with open(findings_path) as fh:
        data = _json.load(fh)
    from .models import Finding

    findings = [
        Finding(
            scanner=r.get("scanner", ""),
            product=r.get("product", ""),
            title=r.get("title", ""),
            severity=r.get("severity", "info"),
            cve=r.get("cve"),
            cwe=r.get("cwe"),
            endpoint=r.get("endpoint"),
            score=r.get("score"),
            priority=r.get("priority"),
        )
        for r in data
    ]

    result = client.create_issues_bulk(findings)
    return result


# ─── DefectDojo routes ─────────────────────────────────────────────────────


@app.post("/api/defectdojo/test")
async def defectdojo_test(user: str = Depends(get_current_user)):
    """Test DefectDojo connection."""
    from .defectdojo_client import DefectDojoClient

    client = DefectDojoClient()
    return client.test_connection()


@app.post("/api/defectdojo/import")
async def defectdojo_import(product_name: str, user: str = Depends(get_current_user)):
    """Import findings into DefectDojo."""
    from .defectdojo_client import DefectDojoClient
    from .defectdojo_client import import_to_defectdojo

    client = DefectDojoClient()
    if not client.configured:
        raise HTTPException(
            status_code=400,
            detail="DefectDojo not configured. Set DEFECTDOJO_URL and DEFECTDOJO_API_KEY",
        )

    findings_path = "outputs/ranked_findings.json"
    if not os.path.exists(findings_path):
        raise HTTPException(status_code=404, detail="No pipeline output found")

    import json as _json
    from .models import Finding

    with open(findings_path) as fh:
        data = _json.load(fh)
    findings = [
        Finding(
            scanner=r.get("scanner", ""),
            product=r.get("product", ""),
            title=r.get("title", ""),
            severity=r.get("severity", "info"),
            cve=r.get("cve"),
            cwe=r.get("cwe"),
            endpoint=r.get("endpoint"),
            score=r.get("score"),
            description=r.get("description", ""),
        )
        for r in data
    ]

    return import_to_defectdojo(findings, product_name)


# ─── Dedup analytics ────────────────────────────────────────────────────────


@app.get("/api/analytics/dedup")
async def dedup_analytics(user: str = Depends(get_current_user)):
    """Get deduplication analytics: pre/post counts, cross-scanner redundancy."""
    noise_path = "outputs/noise_reduction.json"
    if not os.path.exists(noise_path):
        raise HTTPException(status_code=404, detail="Run pipeline first")
    with open(noise_path) as fh:
        data = json.load(fh)
    return {
        "raw_findings": data.get("raw_findings", 0),
        "unique_findings": data.get("unique_findings", 0),
        "dedup_pct": data.get("dedup_pct", 0),
        "noise_removed_pct": data.get("noise_removed_pct", 0),
        "per_scanner_counts": data.get("per_scanner_counts", {}),
        "cross_scanner_redundancy": data.get("cross_scanner_redundancy", []),
        "dedup_by_pass": data.get("dedup_by_pass", {}),
    }


@app.get("/api/lifecycle/all")
async def lifecycle_all_findings(user: str = Depends(get_current_user)):
    """Get all findings with lifecycle status."""
    from .lifecycle import LifecycleManager

    lc = LifecycleManager("outputs/lifecycle.db")
    data = lc.get_dashboard_data()
    lc.close()
    return data


@app.get("/api/lifecycle/breached")
async def lifecycle_breached(user: str = Depends(get_current_user)):
    """Get SLA-breached findings."""
    from .lifecycle import LifecycleManager

    lc = LifecycleManager("outputs/lifecycle.db")
    data = lc.get_overdue_summary()
    lc.close()
    return data


# ─── WebSocket for live updates ──────────────────────────────────────────────


@app.websocket("/ws/live")
async def websocket_live(ws: WebSocket):
    """WebSocket endpoint for real-time scanner progress updates."""
    token = ws.query_params.get("token", "") or ws.cookies.get("access_token", "")
    if not token:
        await ws.close(code=4001, reason="Missing authentication token")
        return
    payload = verify_token(token)
    if not payload:
        await ws.close(code=4001, reason="Invalid or expired token")
        return

    await ws_manager.connect(ws)
    manager = get_manager()

    def on_job_update(job):
        if ws not in ws_manager.active_connections:
            return
        data = {"type": "scan_update", "data": job.to_dict()}
        if _server_loop and _server_loop.is_running():
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast(data),
                _server_loop,
            )

    manager.on_status_change(on_job_update)

    try:
        while True:
            data = await ws.receive_text()
            if len(data.encode("utf-8")) > 4096:
                await ws.send_json({"type": "error", "data": "Payload too large"})
                continue
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await ws.send_json({"type": "pong"})
            elif msg.get("type") == "get_status":
                await ws.send_json(
                    {"type": "status", "data": manager.get_job_summary()}
                )
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.off_status_change(on_job_update)
        ws_manager.disconnect(ws)


# ─── Dashboard static file ──────────────────────────────────────────────────


@app.get("/login", response_class=HTMLResponse)
async def serve_login():
    """Login page."""
    return HTMLResponse(_LOGIN_HTML)


@app.get("/", response_class=HTMLResponse)
@app.get("/{page}", response_class=HTMLResponse)
async def serve_dashboard(request: Request, page: str = "overview"):
    """Serve the main dashboard HTML — requires valid JWT cookie.

    Routes: / = overview, /findings, /dedup, /lifecycle, etc.
    """
    # Skip API and static routes
    if page.startswith("api") or page.startswith("dash-static") or page == "login":
        raise HTTPException(status_code=404, detail="Not found")
    token = request.cookies.get("access_token", "")
    if not token or not verify_token(token):
        return HTMLResponse(_LOGIN_HTML, status_code=302, headers={"Location": "/login"})
    ALLOWED_DIR = Path("outputs").resolve()
    dashboard_path = (ALLOWED_DIR / "risk_dashboard.html").resolve()
    if not dashboard_path.is_relative_to(ALLOWED_DIR):
        raise HTTPException(status_code=403, detail="Access denied")
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path), headers={"Cache-Control": "no-store"})
    return HTMLResponse(_LOGIN_HTML)


@app.get("/dash-static/{fname}")
async def serve_dash_static(fname: str):
    """Vendored JS libraries for the dashboard (no CDN dependency)."""
    if "/" in fname or "\\" in fname or ".." in fname:
        raise HTTPException(status_code=403, detail="Access denied")
    static_dir = (Path(__file__).parent / "static").resolve()
    fpath = (static_dir / fname).resolve()
    if not fpath.is_relative_to(static_dir) or not fpath.exists():
        raise HTTPException(status_code=404, detail="Not found")
    media = "application/javascript" if fname.endswith(".js") else "text/plain"
    return FileResponse(
        str(fpath),
        media_type=media,
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/api/health")
async def api_health():
    """Health check endpoint (no auth required)."""
    return {
        "status": "ok",
        "version": "2.0.0",
    }


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
      <input id="password" type="password" placeholder="Enter password">
    </div>
    <button class="btn" type="submit" id="login-btn">Sign In</button>
    <div class="error" id="error-msg"></div>
  </form>
  <div class="hint">Check server console for credentials</div>
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
    window.location.href='/';
  }catch(e){err.textContent=e.message;err.style.display='block';}
  finally{btn.disabled=false;btn.textContent='Sign In';}
});
</script>
</body>
</html>"""


# ─── Entry point ─────────────────────────────────────────────────────────────


def _get_local_ip():
    """Get the LAN IP address for network access."""
    import socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    """Run the server."""
    import uvicorn
    from .auth import _init_password

    # Generate fresh password and write to .env
    _init_password()
    from .auth import _GENERATED_PASS

    port = int(os.environ.get("PORT", "8000"))
    local_ip = _get_local_ip()
    print("")
    print("  " + "=" * 56)
    print("  DevSecOps Risk Intelligence Dashboard v2.0")
    print("  " + "=" * 56)
    print("")
    print("  INBOUND PORTS (what the server listens on):")
    print(f"    {port}/tcp   HTTP  Dashboard + REST API + WebSocket")
    print("")
    print("  OUTBOUND PORTS (what the server connects to):")
    print(f"    27017/tcp MongoDB          (NodeGoat database)")
    print(f"    3000/tcp  Juice Shop       (target app)")
    print(f"    4000/tcp  NodeGoat          (target app)")
    print(f"    8080/tcp  bWAPP             (target app)")
    print(f"    443/tcp   CDN / API calls   (EPSS, NVD, Exploit-DB, Groq AI)")
    print("")
    print("  ACCESS URLS:")
    print(f"    Local:    http://localhost:{port}")
    print(f"    Network:  http://{local_ip}:{port}")
    print(f"    API Docs: http://localhost:{port}/docs")
    print("")
    print(f"  Login: admin / {_GENERATED_PASS}")
    print("  " + "=" * 56)
    print("")
    uvicorn.run(
        "pipeline.server:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
