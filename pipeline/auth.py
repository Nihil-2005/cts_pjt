"""JWT authentication with TTL for the dashboard.

Provides: PBKDF2-SHA256 hashing, JWT creation/verification, FastAPI deps.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

_SECRET = os.environ.get("DASHBOARD_SECRET")
if not _SECRET:
    _secret_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".secret")
    try:
        if os.path.isfile(_secret_file):
            with open(_secret_file, "r") as f:
                _SECRET = f.read().strip()
        if not _SECRET:
            _SECRET = secrets.token_hex(32)
            with open(_secret_file, "w") as f:
                f.write(_SECRET)
    except Exception:
        _SECRET = secrets.token_hex(32)
_DEFAULT_TTL = int(os.environ.get("JWT_TTL_HOURS", "24")) * 3600


def _b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))


def _sign(msg: bytes) -> str:
    return _b64url_encode(hmac.new(_SECRET.encode(), msg, hashlib.sha256).digest())


def create_token(username: str, ttl_seconds: int = _DEFAULT_TTL) -> str:
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now = int(time.time())
    payload = _b64url_encode(json.dumps({"sub": username, "iat": now, "exp": now + ttl_seconds}).encode())
    signature = _sign(f"{header}.{payload}".encode())
    return f"{header}.{payload}.{signature}"


def verify_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, signature = parts
        if not hmac.compare_digest(signature, _sign(f"{header}.{payload}".encode())):
            return None
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}:{key.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        salt, key_hex = stored.split(":", 1)
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return hmac.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


_DEFAULT_USER = os.environ.get("DASHBOARD_USER", "admin")
_DEFAULT_PASS_HASH: Optional[str] = None
_GENERATED_PASS: Optional[str] = None


def _update_env_password(new_pass: str) -> None:
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    lines = []
    found = False
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("DASHBOARD_PASS="):
                    lines.append(f"DASHBOARD_PASS={new_pass}\n")
                    found = True
                else:
                    lines.append(line)
    if not found:
        lines.append(f"DASHBOARD_PASS={new_pass}\n")
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _init_password() -> None:
    """Generate fresh password on server start, write to .env."""
    global _DEFAULT_PASS_HASH, _GENERATED_PASS
    if _DEFAULT_PASS_HASH is not None:
        return

    pwd = ""
    _env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if os.path.exists(_env_path):
        with open(_env_path, "r", encoding="utf-8") as ef:
            for line in ef:
                line = line.strip()
                if line.startswith("DASHBOARD_PASS="):
                    pwd = line.split("=", 1)[1].strip()
                    break

    if not pwd:
        pwd = os.environ.get("DASHBOARD_PASS", "")
    if not pwd:
        pwd = secrets.token_urlsafe(16)
        _update_env_password(pwd)

    os.environ["DASHBOARD_PASS"] = pwd
    _GENERATED_PASS = pwd
    _DEFAULT_PASS_HASH = hash_password(pwd)


def _get_default_pass_hash() -> str:
    global _DEFAULT_PASS_HASH
    if _DEFAULT_PASS_HASH is None:
        _init_password()
    return _DEFAULT_PASS_HASH


def authenticate(username: str, password: str) -> bool:
    if username == _DEFAULT_USER and check_password(password, _get_default_pass_hash()):
        return True
    return False
