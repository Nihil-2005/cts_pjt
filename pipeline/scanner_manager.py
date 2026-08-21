"""Docker-based scanner orchestration with live status tracking.

Manages scanner containers (Nuclei, ZAP, Trivy, Wapiti) and provides
real-time status updates via a callback system for WebSocket streaming.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class ScannerStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ScanJob:
    """Tracks a single scanner execution against a target."""
    job_id: str
    product: str
    scanner: str
    target_url: str
    output_file: str
    status: ScannerStatus = ScannerStatus.PENDING
    container_id: Optional[str] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    exit_code: Optional[int] = None
    logs: List[str] = field(default_factory=list)
    error: Optional[str] = None
    image: Optional[str] = None  # Docker image name

    def to_dict(self) -> Dict:
        return {
            "job_id": self.job_id,
            "product": self.product,
            "scanner": self.scanner,
            "target_url": self.target_url,
            "output_file": self.output_file,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "logs": self.logs[-50:],  # last 50 lines
            "error": self.error,
        }


# ─── Scanner Docker images ──────────────────────────────────────────────────

SCANNER_IMAGES = {
    "nuclei": "projectdiscovery/nuclei:latest",
    "zap": "ghcr.io/zaproxy/zaproxy:stable",
    "trivy": "aquasec/trivy:latest",
    "wapiti": "vulnlab/wapiti:latest",
}

# Scanner run commands (mounted inside container)
SCANNER_CMD = {
    "nuclei": "nuclei -u {target} -json -o /out/{output}",
    "zap": "zap-baseline.py -t {target} -J /out/{output}",
    "trivy": "image --format json -o /out/{output} {target}",
    "wapiti": "wapiti -u {target} -f json -o /out/{output} --max-depth 2",
}


class ScannerManager:
    """Manages Docker-based scanner execution with live status tracking."""

    def __init__(self, reports_dir: str = "scan_reports"):
        self.reports_dir = os.path.abspath(reports_dir)
        os.makedirs(self.reports_dir, exist_ok=True)
        self._jobs: Dict[str, ScanJob] = {}
        self._callbacks: List[Callable] = []
        self._lock = threading.Lock()
        self._job_counter = 0

    def on_status_change(self, callback: Callable[[ScanJob], None]):
        """Register a callback for job status changes (for WebSocket streaming)."""
        self._callbacks.append(callback)

    def _notify(self, job: ScanJob):
        """Notify all registered callbacks of a status change."""
        for cb in self._callbacks:
            try:
                cb(job)
            except Exception:
                pass

    def _next_job_id(self) -> str:
        with self._lock:
            self._job_counter += 1
            return f"scan-{self._job_counter:04d}"

    def check_docker(self) -> bool:
        """Check if Docker is available."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def check_app_status(self, url: str, timeout: int = 5) -> Dict[str, Any]:
        """Check if a target app is reachable."""
        import urllib.request
        import urllib.error
        start = time.time()
        try:
            req = urllib.request.Request(url, method="HEAD")
            resp = urllib.request.urlopen(req, timeout=timeout)
            elapsed = time.time() - start
            return {
                "url": url,
                "status": "up",
                "status_code": resp.status,
                "response_time_ms": round(elapsed * 1000),
            }
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            # HTTP error still means the server is up
            return {
                "url": url,
                "status": "up",
                "status_code": e.code,
                "response_time_ms": round(elapsed * 1000),
            }
        except Exception:
            elapsed = time.time() - start
            return {
                "url": url,
                "status": "down",
                "status_code": None,
                "response_time_ms": round(elapsed * 1000),
            }

    def check_all_apps(self, products_config: Dict) -> Dict[str, Dict]:
        """Check status of all configured product URLs."""
        results = {}
        for product_id, cfg in products_config.items():
            url = cfg.get("url", "")
            if url:
                results[product_id] = self.check_app_status(url)
        return results

    def _build_docker_run_cmd(self, job: ScanJob, target_url: str) -> List[str]:
        """Build the docker run command for a scanner."""
        image = SCANNER_IMAGES.get(job.scanner, "")
        job.image = image
        output_name = f"{job.product}_{job.scanner}.json"

        # Explicit container name for predictable tracking
        container_name = f"scanner-{job.scanner}-{job.product}"

        # Use host.docker.internal for Windows Docker Desktop access to host services
        host_access = target_url.replace("localhost", "host.docker.internal")

        if job.scanner == "nuclei":
            return [
                "docker", "run", "--rm",
                "--name", container_name,
                "--add-host=host.docker.internal:host-gateway",
                "-v", f"{self.reports_dir}:/out",
                image,
                "nuclei", "-u", host_access,
                "-jsonl", "-o", f"/out/{output_name}",
                "-silent", "-nc",
            ]
        elif job.scanner == "zap":
            return [
                "docker", "run", "--rm",
                "--name", container_name,
                "--add-host=host.docker.internal:host-gateway",
                "-v", f"{self.reports_dir}:/zap/wrk",
                image,
                "zap-baseline.py", "-t", host_access,
                "-J", f"{output_name}",
            ]
        elif job.scanner == "trivy":
            # Trivy scans a Docker image — mount Docker socket for host access
            docker_sock = "/var/run/docker.sock"
            if not os.path.exists(docker_sock):
                docker_sock = "//var/run/docker.sock"  # Windows
            return [
                "docker", "run", "--rm",
                "--name", container_name,
                "-v", f"{self.reports_dir}:/out",
                "-v", f"{docker_sock}:/var/run/docker.sock",
                image,
                "image", "--format", "json",
                "-o", f"/out/{output_name}",
                target_url,  # This is the image name for trivy
            ]
        elif job.scanner == "wapiti":
            return [
                "docker", "run", "--rm",
                "--name", container_name,
                "--add-host=host.docker.internal:host-gateway",
                "-v", f"{self.reports_dir}:/out",
                image,
                "wapiti", "-u", host_access,
                "-f", "json", "-o", f"/out/{output_name}",
                "--max-depth", "2",
            ]
        else:
            raise ValueError(f"Unknown scanner: {job.scanner}")

    def _run_scanner_thread(self, job: ScanJob, target_url: str):
        """Run scanner in a background thread."""
        try:
            job.status = ScannerStatus.RUNNING
            job.started_at = time.time()
            self._notify(job)

            cmd = self._build_docker_run_cmd(job, target_url)
            job.logs.append(f"[START] {' '.join(cmd)}")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            job.container_id = f"running-{process.pid}"

            # Stream output line by line
            for line in iter(process.stdout.readline, ""):
                line = line.rstrip()
                if line:
                    job.logs.append(line)
                    self._notify(job)

            process.wait(timeout=600)  # 10 min timeout
            job.exit_code = process.returncode
            job.finished_at = time.time()

            if process.returncode == 0:
                job.status = ScannerStatus.COMPLETED
                job.logs.append(f"[DONE] Scanner completed in {job.finished_at - job.started_at:.1f}s")
            else:
                job.status = ScannerStatus.FAILED
                job.error = f"Exit code {process.returncode}"
                job.logs.append(f"[ERROR] Exit code {process.returncode}")

        except subprocess.TimeoutExpired:
            job.status = ScannerStatus.FAILED
            job.error = "Scan timed out (10 min limit)"
            job.finished_at = time.time()
            job.logs.append("[ERROR] Scan timed out")
        except Exception as e:
            job.status = ScannerStatus.FAILED
            job.error = str(e)
            job.finished_at = time.time()
            job.logs.append(f"[ERROR] {e}")
        finally:
            self._notify(job)

    def start_scan(
        self,
        product: str,
        scanner: str,
        target_url: str,
    ) -> ScanJob:
        """Start a scanner against a target. Returns the ScanJob for tracking."""
        job_id = self._next_job_id()
        output_name = f"{product}_{scanner}.json"
        job = ScanJob(
            job_id=job_id,
            product=product,
            scanner=scanner,
            target_url=target_url,
            output_file=os.path.join(self.reports_dir, output_name),
        )
        self._jobs[job_id] = job

        thread = threading.Thread(
            target=self._run_scanner_thread,
            args=(job, target_url),
            daemon=True,
        )
        thread.start()
        return job

    def start_product_scans(
        self,
        product_id: str,
        product_config: Dict,
        scanners: Optional[List[str]] = None,
    ) -> List[ScanJob]:
        """Start all configured scanners for a product."""
        target_url = product_config.get("url", "")
        scanner_cfg = product_config.get("scanners", {})
        jobs = []

        active_scanners = scanners or list(scanner_cfg.keys())
        for scanner_name in active_scanners:
            if scanner_name in SCANNER_IMAGES:
                # Use the scanner-specific target if configured
                url = scanner_cfg.get(scanner_name, target_url)
                job = self.start_scan(product_id, scanner_name, url)
                jobs.append(job)

        return jobs

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def get_all_jobs(self) -> List[ScanJob]:
        return list(self._jobs.values())

    def get_active_jobs(self) -> List[ScanJob]:
        return [j for j in self._jobs.values() if j.status in (ScannerStatus.PENDING, ScannerStatus.RUNNING)]

    def get_job_summary(self) -> Dict[str, Any]:
        all_jobs = list(self._jobs.values())
        return {
            "total": len(all_jobs),
            "pending": sum(1 for j in all_jobs if j.status == ScannerStatus.PENDING),
            "running": sum(1 for j in all_jobs if j.status == ScannerStatus.RUNNING),
            "completed": sum(1 for j in all_jobs if j.status == ScannerStatus.COMPLETED),
            "failed": sum(1 for j in all_jobs if j.status == ScannerStatus.FAILED),
            "jobs": [j.to_dict() for j in all_jobs],
        }

    def get_reports_dir(self) -> str:
        return self.reports_dir


# ─── Singleton instance ─────────────────────────────────────────────────────
_manager: Optional[ScannerManager] = None


def get_manager() -> ScannerManager:
    global _manager
    if _manager is None:
        _manager = ScannerManager()
    return _manager
