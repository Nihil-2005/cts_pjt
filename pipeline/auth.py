"""JWT authentication with TTL for the dashboard.

Provides:
- Password hashing (bcrypt)
- JWT token creation/verification with configurable TTL
- FastAPI dependencies for protected routes
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

# Minimal JWT implementation — no external dependency needed.
# Uses HMAC-SHA256 for signing. For production, swap to python-jose.

_SECRET = os.environ.get("DASHBOARD_SECRET", secrets.token_hex(32))
_DEFAULT_TTL = int(os.environ.get("JWT_TTL_HOURS", "24")) * 3600  # 24h default


def _b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    import base64
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def _sign(msg: bytes) -> str:
    return _b64url_encode(
        hmac.new(_SECRET.encode(), msg, hashlib.sha256).digest()
    )


def create_token(username: str, ttl_seconds: int = _DEFAULT_TTL) -> str:
    """Create a JWT-like token with expiry."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now = int(time.time())
    payload_data = {
        "sub": username,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload = _b64url_encode(json.dumps(payload_data).encode())
    signature = _sign(f"{header}.{payload}".encode())
    return f"{header}.{payload}.{signature}"


def verify_token(token: str) -> Optional[dict]:
    """Verify token and return payload, or None if invalid/expired."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, signature = parts
        expected_sig = _sign(f"{header}.{payload}".encode())
        if not hmac.compare_digest(signature, expected_sig):
            return None
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            return None  # expired
        return data
    except Exception:
        return None


def hash_password(password: str) -> str:
    """Hash password with salt using PBKDF2-SHA256."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}:{key.hex()}"


def check_password(password: str, stored: str) -> bool:
    """Verify password against stored hash."""
    try:
        salt, key_hex = stored.split(":", 1)
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return hmac.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


# ─── Default admin credentials (override via env) ───────────────────────────
_DEFAULT_USER = os.environ.get("DASHBOARD_USER", "admin")
_DEFAULT_PASS_HASH = hash_password(os.environ.get("DASHBOARD_PASS", "admin"))


def authenticate(username: str, password: str) -> bool:
    """Check credentials against defaults."""
    if username == _DEFAULT_USER and check_password(password, _DEFAULT_PASS_HASH):
        return True
    return False
