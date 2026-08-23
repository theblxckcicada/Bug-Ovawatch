"""Authentication API — first-run password setup and login.

Flow:
  - GET  /api/auth/status  → {"initialized": bool}  (public)
  - POST /api/auth/setup   → set the password on first run only  (public until set)
  - POST /api/auth/login   → exchange the password for a bearer token  (public)

All other API routers depend on :func:`require_auth`, which accepts the token via
the ``Authorization: Bearer`` header or a ``token`` query parameter (the latter so
the SSE EventSource, which cannot set headers, can authenticate).
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

import auth as auth_lib
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/auth", tags=["auth"])

# Minimum password length enforced server-side (defence in depth alongside the UI).
MIN_PASSWORD_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
_failed_logins: dict[str, deque[float]] = defaultdict(deque)


def _enforce_login_rate_limit(client_ip: str) -> None:
    """Reject repeated password guesses from one address in a rolling window."""
    now = time.monotonic()
    attempts = _failed_logins[client_ip]
    while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        raise HTTPException(429, "Too many login attempts; retry later")


class PasswordBody(BaseModel):
    password: str = Field(min_length=1)


def _get_storage():
    from main import storage
    return storage


async def _load_record() -> dict:
    return await _get_storage().load_auth()


async def require_auth(request: Request) -> None:
    """FastAPI dependency that rejects unauthenticated requests.

    Accepts the bearer token from the Authorization header or a ``token`` query
    parameter. If no password has been configured yet, the API stays locked so a
    fresh install cannot be used before setup completes.
    """
    record = await _load_record()
    secret = record.get("secret", "")
    if not record.get("hash") or not secret:
        raise HTTPException(401, "Authentication is not initialized")

    token = None
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        token = header[7:].strip()
    if not token:
        token = request.query_params.get("token")

    if not auth_lib.verify_token(secret, token):
        raise HTTPException(401, "Invalid or expired token")


@router.get("/status")
async def auth_status():
    record = await _load_record()
    return {"initialized": bool(record.get("hash"))}


@router.post("/setup")
async def auth_setup(body: PasswordBody):
    storage = _get_storage()
    record = await storage.load_auth()
    if record.get("hash"):
        # Never allow silent password reset through the public setup endpoint.
        raise HTTPException(409, "Password already configured")

    if len(body.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(400, f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

    secret = auth_lib.new_secret()
    new_record = {**auth_lib.hash_password(body.password), "secret": secret}
    await storage.save_auth(new_record)
    return {"token": auth_lib.issue_token(secret)}


@router.post("/login")
async def auth_login(body: PasswordBody, request: Request):
    record = await _load_record()
    if not record.get("hash"):
        raise HTTPException(409, "Password not configured yet")

    client_ip = request.client.host if request.client else "unknown"
    _enforce_login_rate_limit(client_ip)
    if not auth_lib.verify_password(body.password, record):
        _failed_logins[client_ip].append(time.monotonic())
        raise HTTPException(401, "Invalid password")

    _failed_logins.pop(client_ip, None)
    return {"token": auth_lib.issue_token(record["secret"])}
