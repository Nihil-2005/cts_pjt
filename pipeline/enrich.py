"""Threat-intelligence enrichment — concurrent NVD + retry + Exploit-DB CSV.

For every CVE found in the normalized dataset we fetch:

  - CISA KEV      : known-exploited status + date added   (free JSON feed)
  - FIRST.org EPSS: exploit-prediction score + percentile + 7-day trend
  - NVD           : CVSS v3 fallback — concurrent with NVD API key support
                    (50 req/30s with key vs 5 req/30s without)
  - Exploit-DB    : downloaded as a CSV once/day; no Docker required

All lookups are disk-cached so demo re-runs are instant and offline after
the first run.  Fetcher is injectable for tests.
"""
from __future__ import annotations

import concurrent.futures
import csv
import datetime as dt
import json
import os
import time
import urllib.parse
import urllib.request
from threading import BoundedSemaphore
from typing import Any, Dict, List, Optional

from .models import Finding

USER_AGENT = "devsecops-pipeline/2.0 (+hackathon)"
EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)


# ─────────────────────────────── Fetcher ─────────────────────────────────────

class Fetcher:
    """Thin urllib wrapper; tests inject a fake."""

    def get_json(self, url: str, headers: Optional[Dict] = None,
                 timeout: int = 20) -> Any:
        h = {"User-Agent": USER_AGENT}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def get_raw(self, url: str, timeout: int = 60) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()


# ──────────────────────────── cache helpers ───────────────────────────────────

def _load_cache(path: str) -> Optional[Any]:
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None
    return None


def _save_cache(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _is_stale(path: str, max_age_days: int = 1) -> bool:
    if not os.path.exists(path):
        return True
    age = time.time() - os.path.getmtime(path)
    return age > max_age_days * 86400


# ────────────────────────── rate limiter ─────────────────────────────────────

class _RateLimiter:
    """Token-bucket rate limiter, thread-safe."""

    def __init__(self, calls: int, window: float):
        self._sem = BoundedSemaphore(calls)
        self._delay = window / calls

    def acquire(self) -> None:
        self._sem.acquire()

    def release(self) -> None:
        time.sleep(self._delay)
        self._sem.release()


# ────────────────────────── retry helper ─────────────────────────────────────

def _fetch_with_retry(fn, *args, max_attempts: int = 3, **kwargs) -> Any:
    """Call fn(*args, **kwargs) with exponential-backoff retry."""
    last_exc: Exception = RuntimeError("no attempts")
    for attempt in range(max_attempts):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < max_attempts - 1:
                time.sleep(2 ** attempt)
    raise last_exc


# ──────────────────────────── Enricher ───────────────────────────────────────

class Enricher:
    def __init__(self, cfg: Dict, cache_dir: Optional[str] = None,
                 fetcher: Optional[Fetcher] = None):
        self.cfg = cfg
        self.cache_dir = cache_dir or cfg.get("cache_dir", "intel")
        self.fetcher = fetcher or Fetcher()
        self.kev_map:    Dict[str, Dict[str, Any]] = {}
        self.epss_map:   Dict[str, Dict[str, Any]] = {}
        self.nvd_map:    Dict[str, Dict[str, Any]] = {}
        self.exploit_map: Dict[str, List[str]]      = {}
        self.trend_map:  Dict[str, float]           = {}
        self.counts:     Dict[str, int] = {
            "kev": 0, "epss": 0, "nvd": 0, "exploit": 0}

    # ── KEV ───────────────────────────────────────────────────────────────
    def load_kev(self) -> None:
        cache = os.path.join(self.cache_dir, "cisa_kev.json")
        data = _load_cache(cache)
        if data and not _is_stale(cache,
                                   int(self.cfg.get("cache_ttl_days", 1))):
            self.kev_map = {v["cveID"]: v
                            for v in data.get("vulnerabilities", [])}
            return
        try:
            data = _fetch_with_retry(
                self.fetcher.get_json, self.cfg["kev_url"])
            vulns = data.get("vulnerabilities", [])
            self.kev_map = {v["cveID"]: v for v in vulns}
            _save_cache(cache, {
                "fetched": dt.datetime.now().isoformat(),
                "vulnerabilities": vulns,
            })
            print(f"  [OK] KEV: {len(self.kev_map)} known-exploited CVEs")
        except Exception as exc:
            print(f"  ! KEV fetch failed ({exc}); using cache")
            if data:
                self.kev_map = {v["cveID"]: v
                                for v in data.get("vulnerabilities", [])}

    # ── EPSS ──────────────────────────────────────────────────────────────
    def load_epss(self, cves: List[str]) -> None:
        cves = sorted({c.upper() for c in cves if c})
        cache_path = os.path.join(self.cache_dir, "epss_cache.json")
        cache = _load_cache(cache_path) or {}
        if _is_stale(cache_path, int(self.cfg.get("cache_ttl_days", 1))):
            cache = {"fetched": dt.datetime.now().isoformat(), "data": {}}
        missing = [c for c in cves if c not in cache["data"]]
        if missing:
            for chunk in _chunks(missing, 60):
                try:
                    q = urllib.parse.urlencode({"cve": ",".join(chunk)})
                    data = _fetch_with_retry(
                        self.fetcher.get_json,
                        f"{self.cfg['epss_url']}?{q}")
                    for entry in data.get("data", []):
                        cve = entry.get("cve", "").upper()
                        cache["data"][cve] = {
                            "epss":       float(entry.get("epss", 0) or 0),
                            "percentile": float(entry.get("percentile", 0) or 0),
                        }
                except Exception as exc:
                    print(f"  ! EPSS chunk failed ({exc})")
            _save_cache(cache_path, cache)
        self.epss_map = cache.get("data", {})

    def load_epss_trend(self, cves: List[str]) -> None:
        past = (dt.datetime.now(dt.timezone.utc)
                - dt.timedelta(days=7)).date().isoformat()
        cache_path = os.path.join(self.cache_dir, "epss_trend.json")
        cache = _load_cache(cache_path) or {}
        missing = [c for c in sorted({c.upper() for c in cves if c})
                   if c not in cache]
        if missing:
            for chunk in _chunks(missing, 60):
                try:
                    q = urllib.parse.urlencode(
                        {"cve": ",".join(chunk), "date": past})
                    data = _fetch_with_retry(
                        self.fetcher.get_json,
                        f"{self.cfg['epss_url']}?{q}")
                    for entry in data.get("data", []):
                        cache[entry.get("cve", "").upper()] = float(
                            entry.get("epss", 0) or 0)
                except Exception:
                    pass
            _save_cache(cache_path, cache)
        self.trend_map = cache

    # ── NVD (concurrent) ─────────────────────────────────────────────────
    def load_nvd(self, cves: List[str]) -> None:
        cache_path = os.path.join(self.cache_dir, "nvd_cache.json")
        cache = _load_cache(cache_path) or {}
        missing = [c for c in sorted({c.upper() for c in cves if c})
                   if c not in cache]
        if not missing:
            self.nvd_map = cache
            return

        # NVD rate limits: 50 req/30s with API key, 5 req/30s without
        api_key = (self.cfg.get("nvd_api_key")
                   or os.environ.get("NVD_API_KEY") or "")
        calls, window = (50, 30.0) if api_key else (5, 30.0)
        limiter = _RateLimiter(calls, window)

        def _fetch_one(cve: str) -> tuple:
            limiter.acquire()
            try:
                headers: Dict = {}
                if api_key:
                    headers["apiKey"] = api_key
                url = (f"{self.cfg['nvd_url']}?"
                       f"cveId={urllib.parse.quote(cve)}")
                data = self.fetcher.get_json(url, headers=headers)
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    metrics = (vulns[0].get("cve", {})
                                       .get("metrics", {}))
                    for key in ("cvssMetricV31",
                                "cvssMetricV30", "cvssMetricV2"):
                        if key in metrics and metrics[key]:
                            base = (metrics[key][0]
                                    .get("cvssData", {})
                                    .get("baseScore"))
                            return cve, {"cvss": base}
                return cve, None
            except Exception:
                return cve, None
            finally:
                limiter.release()

        max_workers = min(calls, len(missing), 20)
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers) as pool:
            for cve, result in pool.map(_fetch_one, missing):
                if result:
                    cache[cve] = result

        self.nvd_map = cache
        _save_cache(cache_path, cache)

    # ── Exploit-DB (CSV, no Docker) ───────────────────────────────────────
    def load_exploits_csv(self, cves: List[str]) -> None:
        """Download Exploit-DB CSV once/day, build CVE→exploit_ids map."""
        cache_path = os.path.join(self.cache_dir, "exploitdb.csv")
        if _is_stale(cache_path, max_age_days=1):
            try:
                raw = _fetch_with_retry(
                    self.fetcher.get_raw, EXPLOITDB_CSV_URL, timeout=60)
                os.makedirs(self.cache_dir, exist_ok=True)
                with open(cache_path, "wb") as fh:
                    fh.write(raw)
            except Exception as exc:
                print(f"  ! Exploit-DB CSV fetch failed ({exc})")
                return

        cve_map: Dict[str, List[str]] = {}
        try:
            with open(cache_path, encoding="utf-8",
                      errors="replace") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    codes = str(row.get("codes") or "")
                    eid   = str(row.get("id") or "")
                    for token in codes.replace(";", ",").split(","):
                        token = token.strip().upper()
                        if token.startswith("CVE-"):
                            cve_map.setdefault(token, []).append(eid)
        except Exception as exc:
            print(f"  ! Exploit-DB CSV parse failed ({exc})")
            return

        for cve in sorted({c.upper() for c in cves if c}):
            matches = cve_map.get(cve, [])
            self.exploit_map[cve] = matches
            if matches:
                self.counts["exploit"] += 1

    # ── apply enrichment to all findings ─────────────────────────────────
    def enrich(self, findings: List[Finding],
               use_searchsploit: Optional[bool] = None) -> None:
        use_exploitdb = self.cfg.get("use_searchsploit", True) \
            if use_searchsploit is None else use_searchsploit

        cves = sorted({f.cve.upper() for f in findings if f.cve})
        self.load_kev()
        if cves:
            self.load_epss(cves)
            self.load_epss_trend(cves)
            if self.cfg.get("use_nvd", True):
                needs_nvd = {
                    f.cve.upper() for f in findings
                    if f.cve and not _has_scanner_cvss(f)
                }
                needs_nvd_list = [c for c in sorted(needs_nvd)
                                  if c not in self.nvd_map]
                if needs_nvd_list:
                    self.load_nvd(needs_nvd_list)
            if use_exploitdb:
                self.load_exploits_csv(cves)

        for f in findings:
            if not f.cve:
                continue
            cve = f.cve.upper()

            kev = self.kev_map.get(cve)
            if kev:
                f.kev = True
                f.kev_date = kev.get("dateAdded")
                self.counts["kev"] += 1

            epss = self.epss_map.get(cve)
            if epss:
                f.epss_score      = epss["epss"]
                f.epss_percentile = epss["percentile"]
                self.counts["epss"] += 1

            trend = self.trend_map.get(cve)
            if trend is not None and f.epss_score is not None:
                f.epss_trend = round(f.epss_score - trend, 4)

            nvd = self.nvd_map.get(cve)
            if nvd and nvd.get("cvss") is not None:
                f.nvd_cvss = float(nvd["cvss"])
                self.counts["nvd"] += 1

            if use_exploitdb:
                exps = self.exploit_map.get(cve, [])
                if exps:
                    f.exploit_available = True
                    f.exploit_source    = "exploit-db:" + ",".join(exps[:3])
            elif f.kev:
                f.exploit_available = True
                f.exploit_source    = "cisa-kev"

    def counts_dict(self) -> Dict[str, int]:
        return dict(self.counts)


# ─────────────────────────── utilities ───────────────────────────────────────

def _chunks(items: List[str], size: int) -> List[List[str]]:
    return [items[i: i + size] for i in range(0, len(items), size)]


def _has_scanner_cvss(f: Finding) -> bool:
    cv = f.raw.get("cvss_score") if isinstance(f.raw, dict) else None
    return isinstance(cv, (int, float)) and 0 <= cv <= 10
