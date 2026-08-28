"""Docker-based scanner orchestration with live status tracking."""

from __future__ import annotations
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse


class ScannerStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ScanJob:
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
    image: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "job_id": self.job_id, "product": self.product, "scanner": self.scanner,
            "target_url": self.target_url, "output_file": self.output_file,
            "status": self.status.value, "started_at": self.started_at,
            "finished_at": self.finished_at, "exit_code": self.exit_code,
            "logs": self.logs[-50:], "error": self.error,
        }


SCANNER_IMAGES = {
    "nuclei": "projectdiscovery/nuclei:latest",
    "zap": "ghcr.io/zaproxy/zaproxy:stable",
    "trivy": "aquasec/trivy:latest",
    "wapiti": "vulnlab/wapiti:latest",
    "nmap": "instrumentisto/nmap:latest",
}

SCANNER_RESOURCES = {
    "nuclei": {"memory": "1g", "cpus": "1.0"},
    "zap": {"memory": "1g", "cpus": "1"},
    "trivy": {"memory": "512m", "cpus": "0.5"},
    "wapiti": {"memory": "512m", "cpus": "0.5"},
    "nmap": {"memory": "512m", "cpus": "0.5"},
}

_manager_instance: Optional["ScannerManager"] = None
_manager_lock = threading.Lock()


def get_manager() -> "ScannerManager":
    global _manager_instance
    if _manager_instance is None:
        with _manager_lock:
            if _manager_instance is None:
                _manager_instance = ScannerManager()
    return _manager_instance


def _resolve_host_path(container_path: str) -> str:
    """Resolve a container-internal path to the host Docker mount path.

    When running inside Docker, `-v host_path:/app/scan_reports` means the
    scanner containers must mount `host_path`, not `/app/scan_reports`.
    We detect the host path by inspecting our own container's mounts.
    """
    if not os.path.exists("/.dockerenv"):
        return container_path  # Not in Docker, path is already host path

    # Try to read /proc/self/mountinfo to find the host path
    # Format: mount_id parent_id major:minor root mount_point ...
    # root (parts[3]) = host source path, mount_point (parts[4]) = container dest
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 5 and parts[4] == container_path:
                    host_path = parts[3]  # root = host source path
                    if host_path and host_path != container_path:
                        return host_path
    except Exception:
        pass

    # Fallback: use docker inspect on our own container
    try:
        import subprocess as _sp
        hostname = os.environ.get("HOSTNAME", "")
        if hostname:
            result = _sp.run(
                ["docker", "inspect", hostname],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                import json as _json
                info = _json.loads(result.stdout)
                if info and isinstance(info, list):
                    mounts = info[0].get("Mounts", [])
                    for m in mounts:
                        if m.get("Destination") == container_path:
                            host_src = m.get("Source", "")
                            if host_src and os.path.exists(host_src):
                                return host_src
    except Exception:
        pass

    return container_path  # Fallback to container path


def _get_scan_volume() -> str:
    """Determine the Docker volume name for scanner output.

    On Docker Desktop, host paths from /proc/self/mountinfo don't work
    when passed to docker run -v. Instead, use a Docker named volume
    that both the dashboard and scanner containers share.
    """
    if not os.path.exists("/.dockerenv"):
        return ""  # Not in Docker, use host path

    # The compose file creates 'devsecops-pipeline_scan-reports-vol'
    import subprocess as _sp
    compose_vol = "devsecops-pipeline_scan-reports-vol"
    standalone_vol = "devsecops-scan-reports"

    # Check which volume exists
    try:
        result = _sp.run(["docker", "volume", "inspect", compose_vol],
                        capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return compose_vol
    except Exception:
        pass

    # Fallback: create standalone volume
    try:
        _sp.run(["docker", "volume", "create", standalone_vol],
                capture_output=True, timeout=5)
    except Exception:
        pass
    return standalone_vol


class ScannerManager:
    def __init__(self, reports_dir: str = "scan_reports"):
        self.reports_dir = os.path.abspath(reports_dir)
        os.makedirs(self.reports_dir, exist_ok=True)
        self._jobs: Dict[str, ScanJob] = {}
        self._callbacks: List[Callable] = []
        self._lock = threading.Lock()
        self._scan_semaphore = threading.Semaphore(3)
        self._job_counter = 0
        # Named volume for scanner containers (works on Docker Desktop)
        self._scan_volume = _get_scan_volume()

    def on_status_change(self, callback: Callable[[ScanJob], None]):
        with self._lock:
            self._callbacks.append(callback)

    def off_status_change(self, callback: Callable[[ScanJob], None]):
        with self._lock:
            try:
                self._callbacks.remove(callback)
            except ValueError:
                pass

    def _notify(self, job: ScanJob):
        with self._lock:
            callbacks = list(self._callbacks)
        for cb in callbacks:
            try:
                cb(job)
            except Exception:
                pass

    def _next_job_id(self) -> str:
        with self._lock:
            self._job_counter += 1
            return f"scan-{self._job_counter:04d}"

    def check_docker(self) -> bool:
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def check_app_status(self, url: str, timeout: int = 5) -> Dict[str, Any]:
        import urllib.request
        import urllib.error
        import os as _os
        start = time.time()

        # Inside Docker, localhost refers to the container itself.
        # Replace with host.docker.internal to reach host services.
        check_url = url
        if _os.path.exists("/.dockerenv") and "localhost" in check_url:
            check_url = check_url.replace("localhost", "host.docker.internal")

        try:
            req = urllib.request.Request(check_url, method="HEAD")
            resp = urllib.request.urlopen(req, timeout=timeout)
            return {"url": url, "status": "up", "status_code": resp.status,
                    "response_time_ms": round((time.time() - start) * 1000)}
        except urllib.error.HTTPError as e:
            return {"url": url, "status": "up", "status_code": e.code,
                    "response_time_ms": round((time.time() - start) * 1000)}
        except Exception:
            return {"url": url, "status": "down", "status_code": None,
                    "response_time_ms": round((time.time() - start) * 1000)}

    def check_all_apps(self, products_config: Dict) -> Dict[str, Dict]:
        return {pid: self.check_app_status(cfg.get("url", "")) for pid, cfg in products_config.items() if cfg.get("url")}

    def _validate_target_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid URL scheme: {parsed.scheme!r}")
        if not parsed.netloc:
            raise ValueError("Missing host in URL")
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _build_docker_run_cmd(self, job: ScanJob, target_url: str) -> List[str]:
        image = SCANNER_IMAGES.get(job.scanner, "")
        job.image = image
        output_name = f"{job.product}_{job.scanner}.json"
        container_name = f"scanner-{job.scanner}-{job.product}"
        res = SCANNER_RESOURCES.get(job.scanner, {"memory": "1g", "cpus": "1.0"})
        resource_flags = ["--memory", res["memory"], "--cpus", res["cpus"]]

        # Detect Docker network — use devsecops-net if dashboard runs in compose
        # When on the compose network, use container names directly
        # (e.g. http://juiceshop:3000) instead of host.docker.internal
        use_compose_net = False
        network_flags = ["--network", "host"]
        import subprocess as _sp
        try:
            _sp.run(["docker", "network", "inspect", "devsecops-pipeline_devsecops-net"],
                    capture_output=True, timeout=5)
            use_compose_net = True
            network_flags = ["--network", "devsecops-pipeline_devsecops-net"]
        except Exception:
            pass

        # Map product names to container names on the compose network
        product_to_container = {
            "juice_shop": "juiceshop",
            "juiceshop": "juiceshop",
            "nodegoat": "nodegoat",
            "bwapp": "bwapp",
        }
        if use_compose_net and job.product in product_to_container:
            container_name_url = product_to_container[job.product]
            port = target_url.split(":")[-1].split("/")[0] if ":" in target_url else "80"
            host_access = f"http://{container_name_url}:{port}"
        else:
            host_access = target_url.replace("localhost", "host.docker.internal")

        if job.scanner == "nuclei":
            return ["docker", "run", "--rm", "--name", container_name] + resource_flags + network_flags + [
                "--add-host=host.docker.internal:host-gateway", "-v", f"{self._scan_volume}:/out",
                image, "-u", host_access,
                "-severity", "critical,high,medium,low",
                "-timeout", "30", "-retries", "2",
                "-jsonl", "-o", f"/out/{output_name}", "-nc",
            ]
        elif job.scanner == "zap":
            return ["docker", "run", "--rm", "--name", container_name] + resource_flags + network_flags + [
                "--add-host=host.docker.internal:host-gateway",
                "--user", "root",
                "-v", f"{self._scan_volume}:/zap/wrk",
                image, "zap-baseline.py", "-t", host_access, "-J", output_name,
            ]
        elif job.scanner == "trivy":
            docker_sock = "/var/run/docker.sock"
            if not os.path.exists(docker_sock):
                docker_sock = "//var/run/docker.sock"
            return ["docker", "run", "--rm", "--name", container_name] + resource_flags + [
                "-v", f"{self._scan_volume}:/out", "-v", f"{docker_sock}:/var/run/docker.sock",
                image, "image", "--format", "json", "-o", f"/out/{output_name}",
                self._resolve_trivy_image(target_url),
            ]
        elif job.scanner == "wapiti":
            return ["docker", "run", "--rm", "--name", container_name] + resource_flags + network_flags + [
                "--add-host=host.docker.internal:host-gateway", "-v", f"{self._scan_volume}:/out",
                image, "-u", host_access, "-f", "json", "-o", f"/out/{output_name}",
                "-t", "10", "--level", "1",
            ]
        elif job.scanner == "nmap":
            # Parse host and port separately — nmap needs host -p port
            from urllib.parse import urlparse as _urlparse
            parsed = _urlparse(host_access)
            nmap_host = parsed.hostname or host_access
            nmap_port = parsed.port
            nmap_flags = ["-p-", "-oX", f"/out/{job.product}_{job.scanner}.xml"]
            if nmap_port:
                nmap_flags = ["-p", str(nmap_port), "-oX", f"/out/{job.product}_{job.scanner}.xml"]
            return ["docker", "run", "--rm", "--name", container_name] + resource_flags + network_flags + [
                "--add-host=host.docker.internal:host-gateway", "-v", f"{self._scan_volume}:/out",
                image, "-sV", "-sC", "--script", "vulners,default",
                "--script-timeout", "120s",
            ] + nmap_flags + ["-T4", "--open", nmap_host]
        else:
            raise ValueError(f"Unknown scanner: {job.scanner}")

    def _kill_scanner(self, job: ScanJob):
        container_name = f"scanner-{job.scanner}-{job.product}"
        try:
            subprocess.run(["docker", "kill", container_name], capture_output=True, timeout=10)
        except Exception:
            pass

    def _resolve_trivy_image(self, target_url: str) -> str:
        if not target_url or target_url.startswith("http"):
            return target_url
        if ":" in target_url or "/" in target_url:
            return target_url
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format={{.Config.Image}}", target_url],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        return target_url

    def _run_scanner_thread(self, job: ScanJob, target_url: str):
        self._scan_semaphore.acquire()
        process = None
        try:
            job.status = ScannerStatus.RUNNING
            job.started_at = time.time()
            self._notify(job)

            # Skip URL validation for trivy (uses container names, not HTTP URLs)
            if job.scanner != "trivy":
                try:
                    target_url = self._validate_target_url(target_url)
                except ValueError as e:
                    job.status = ScannerStatus.FAILED
                    job.error = f"Invalid target URL: {e}"
                    job.finished_at = time.time()
                    job.logs.append(f"[ERROR] Invalid target URL: {e}")
                    self._notify(job)
                    return

            cmd = self._build_docker_run_cmd(job, target_url)
            job.logs.append(f"[START] {' '.join(cmd)}")

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            job.container_id = f"scanner-{job.scanner}-{job.product}"

            timed_out = threading.Event()
            def _watchdog():
                timed_out.set()
                try:
                    process.kill()
                except Exception:
                    pass
            watchdog = threading.Timer(600, _watchdog)
            watchdog.daemon = True
            watchdog.start()
            try:
                for line in iter(process.stdout.readline, ""):
                    if timed_out.is_set():
                        break
                    line = line.rstrip()
                    if line:
                        job.logs.append(line)
                        self._notify(job)
            finally:
                watchdog.cancel()

            if process.poll() is None:
                process.wait(timeout=5)

            job.exit_code = process.returncode
            job.finished_at = time.time()
            # Exit 0 = success, exit 1 = failure, exit 2 = warnings (ZAP uses 2 for findings)
            success_codes = {0, 2} if job.scanner == "zap" else {0}
            job.status = ScannerStatus.COMPLETED if process.returncode in success_codes else ScannerStatus.FAILED
            if process.returncode not in success_codes:
                job.error = f"Exit code {process.returncode}"
            else:
                # Copy results from Docker volume back to host reports_dir
                self._copy_results_to_host(job)
        except Exception as e:
            job.status = ScannerStatus.FAILED
            job.error = str(e)
            job.finished_at = time.time()
            self._kill_scanner(job)
        finally:
            self._notify(job)
            self._scan_semaphore.release()

    def _copy_results_to_host(self, job: ScanJob) -> None:
        """Copy scanner output from Docker volume to host reports_dir.

        After a scanner container completes, its output lives in the Docker
        named volume. This copies it back to the host-mounted reports_dir
        so the pipeline can read it locally.
        """
        if not self._scan_volume or not os.path.exists("/.dockerenv"):
            return  # Not in Docker or no volume
        output_name = f"{job.product}_{job.scanner}.json"
        xml_name = f"{job.product}_{job.scanner}.xml"
        try:
            import subprocess as _sp
            for fname in [output_name, xml_name]:
                _sp.run(
                    ["docker", "run", "--rm",
                     "-v", f"{self._scan_volume}:/vol:ro",
                     "-v", f"{self.reports_dir}:/host",
                     "alpine", "sh", "-c",
                     f"test -f /vol/{fname} && cp /vol/{fname} /host/ && echo copied {fname}"],
                    capture_output=True, text=True, timeout=10,
                )
        except Exception:
            pass  # Best-effort copy

    def start_product_scans(self, product_id: str, product_config: Dict, scanners: Optional[List[str]] = None) -> List[ScanJob]:
        url = product_config.get("url", "")
        scanner_targets = product_config.get("scanners", {})
        target_scanners = scanners or list(scanner_targets.keys())
        jobs = []

        for scanner in target_scanners:
            if scanner not in SCANNER_IMAGES:
                continue
            target = scanner_targets.get(scanner, url)
            if not target:
                continue
            job_id = self._next_job_id()
            output = f"{product_id}_{scanner}.json"
            job = ScanJob(job_id=job_id, product=product_id, scanner=scanner, target_url=target, output_file=output)
            with self._lock:
                self._jobs[job_id] = job
            thread = threading.Thread(target=self._run_scanner_thread, args=(job, target), daemon=True)
            thread.start()
            jobs.append(job)

        return jobs

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def get_all_jobs(self) -> List[ScanJob]:
        with self._lock:
            return list(self._jobs.values())

    def get_active_jobs(self) -> List[ScanJob]:
        return [j for j in self.get_all_jobs() if j.status == ScannerStatus.RUNNING]

    def get_job_summary(self) -> Dict[str, Any]:
        jobs = self.get_all_jobs()
        return {
            "total": len(jobs),
            "pending": sum(1 for j in jobs if j.status == ScannerStatus.PENDING),
            "running": sum(1 for j in jobs if j.status == ScannerStatus.RUNNING),
            "completed": sum(1 for j in jobs if j.status == ScannerStatus.COMPLETED),
            "failed": sum(1 for j in jobs if j.status == ScannerStatus.FAILED),
            "jobs": [j.to_dict() for j in jobs],
        }

    def get_reports_dir(self) -> str:
        return self.reports_dir
