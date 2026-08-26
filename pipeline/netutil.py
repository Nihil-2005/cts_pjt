"""Shared HTTP helpers with retry for integration clients."""

from __future__ import annotations
import time
from typing import Any

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def requests_with_retry(
    method: str, url: str, retries: int = 3, backoff: float = 1.0, **kwargs: Any
):
    """requests.request with exponential-backoff retries on 429/5xx."""
    import requests
    last_exc: Any = None
    for attempt in range(retries):
        try:
            resp = requests.request(method, url, **kwargs)
            if resp.status_code in RETRYABLE_STATUS and attempt < retries - 1:
                time.sleep(backoff * (2**attempt))
                continue
            return resp
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(backoff * (2**attempt))
    raise last_exc
