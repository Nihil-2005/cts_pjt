"""Target override parsing for remote scanning.

--target values: bare host[:port] → all products; product=host[:port] → per-product.
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


class TargetOverrideError(ValueError):
    pass


def _normalize_endpoint(host: str, port: Optional[int]) -> str:
    host = host.strip().strip("[]")
    scheme = "http"
    if "://" in host:
        parsed = urlparse(host)
        host = parsed.hostname or host
        port = port or parsed.port
        scheme = parsed.scheme or "http"
    if not port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def parse_target(value: str) -> tuple[Optional[str], str, Optional[int]]:
    """Parse one --target value into (product_key_or_None, host, port)."""
    value = value.strip()
    if not value:
        raise TargetOverrideError("empty --target value")

    product_key: Optional[str] = None
    endpoint = value
    if "=" in value:
        product_key, endpoint = value.split("=", 1)
        product_key = product_key.strip().lower()
        endpoint = endpoint.strip()
        if not product_key:
            raise TargetOverrideError(f"empty product name in --target {value!r}")
        if not endpoint:
            raise TargetOverrideError(f"missing host for {product_key!r}")

    endpoint = endpoint.rstrip("/")
    m = re.match(r"^(?:(https?)://)?\[?([A-Za-z0-9._-]+)\]?(?::(\d+))?(?:/.*)?$", endpoint)
    if not m:
        raise TargetOverrideError(f"cannot parse --target {value!r}")
    host, port_str = m.group(2), m.group(3)
    port = int(port_str) if port_str else None
    return product_key, host, port


def apply_targets(values: List[str], products: Dict[str, str], selected: Optional[List[str]] = None) -> Dict[str, str]:
    """Apply --target overrides to configured product URLs."""
    if selected:
        unknown_sel = [p for p in selected if p not in products]
        if unknown_sel:
            raise TargetOverrideError(f"unknown product(s) in selection: {', '.join(unknown_sel)}")
    scope = [p for p in (selected or list(products))]

    bare_host: Optional[str] = None
    overrides: Dict[str, str] = {}
    seen_keys: set[str] = set()

    for value in values or []:
        key, host, port = parse_target(value)
        url = _normalize_endpoint(host, port)
        if key is None:
            if bare_host is None:
                bare_host = url
            elif bare_host != url:
                raise TargetOverrideError("multiple bare --target values; use product=host for per-product overrides")
        else:
            if key not in products:
                raise TargetOverrideError(f"unknown product {key!r} (known: {', '.join(sorted(products))})")
            if key in seen_keys:
                raise TargetOverrideError(f"duplicate --target for {key!r}")
            seen_keys.add(key)
            overrides[key] = url

    out: Dict[str, str] = {}
    for pid in scope:
        if pid in overrides:
            out[pid] = overrides[pid]
        elif bare_host:
            cfg_port = urlparse(products.get(pid, "")).port
            out[pid] = _normalize_endpoint(bare_host, cfg_port)
        else:
            out[pid] = products.get(pid, "")
    return out


def is_remote(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname or ""
    except ValueError:
        return True
    return hostname.lower() not in LOCAL_HOSTS


def any_remote(urls: Dict[str, str]) -> bool:
    return any(is_remote(u) for u in urls.values())


def apply_overrides_to_config(products_cfg: Dict[str, Dict], target_values: List[str]) -> Dict[str, Dict]:
    """Apply --target overrides to a full products config block."""
    urls = {pid: (cfg.get("url") or "") for pid, cfg in products_cfg.items()}
    effective = apply_targets(target_values, urls)
    for pid, url in effective.items():
        if not url:
            continue
        cfg = products_cfg[pid]
        cfg["url"] = url
        for key, val in cfg.get("scanners", {}).items():
            if isinstance(val, str) and val.startswith("http"):
                cfg["scanners"][key] = url
    return products_cfg
