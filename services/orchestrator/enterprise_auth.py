"""
enterprise_auth.py — Zero-Trust Security Layer
==============================================

IBM Bob 2.0 Hackathon · /services/orchestrator/

JWT-based access control for the orchestrator. The ``/api/v1/modernize``
pipeline triggers AI agents that read source code and (in production) spend
real money — it must never be reachable anonymously.

Flow
----
1. Client POSTs credentials to ``/token`` (OAuth2 password form).
2. The mock identity provider validates against the enterprise directory
   (here: an env-configurable mock user store; swap ``_verify_password`` for
   LDAP/OIDC in production).
3. A signed JWT (HS256) is issued with role + expiry claims.
4. ``get_current_user`` — a strict FastAPI dependency built on
   ``OAuth2PasswordBearer`` — validates signature, expiry, and role on every
   protected request.

Dependency strategy
-------------------
``python-jose`` is used when installed. When it is not, a compact, stdlib
HMAC-SHA256 JWT implementation (same compact JWS format) takes over so the
system stays runnable anywhere. Both paths verify signature + ``exp`` claim;
neither ever accepts ``alg: none``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

logger = logging.getLogger("orchestrator.enterprise_auth")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

JWT_SECRET: str = os.getenv("JWT_SECRET", "hackathon-dev-secret-change-me")
JWT_ALGORITHM: str = "HS256"
JWT_TTL_SECONDS: int = int(os.getenv("JWT_TTL_SECONDS", "3600"))

#: Role allowed to trigger the AI pipeline.
REQUIRED_ROLE: str = os.getenv("PIPELINE_REQUIRED_ROLE", "modernizer")

if JWT_SECRET == "hackathon-dev-secret-change-me":
    logger.warning("JWT_SECRET is the development default — set it via env for any real deployment.")

try:  # pragma: no cover - environment dependent
    from jose import JWTError, jwt as jose_jwt  # type: ignore

    _JOSE_AVAILABLE = True
except Exception:
    _JOSE_AVAILABLE = False
    logger.info("python-jose not installed; using stdlib HMAC JWT implementation.")

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    """OAuth2 token endpoint response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class EnterpriseUser(BaseModel):
    """Authenticated principal, extracted from a validated JWT."""

    username: str
    role: str
    exp: int


# ---------------------------------------------------------------------------
# Mock enterprise directory (replace with LDAP/OIDC in production)
# ---------------------------------------------------------------------------

_MOCK_USERS: Dict[str, Dict[str, str]] = {
    # username -> {password, role}
    os.getenv("ADMIN_USERNAME", "admin"): {
        "password": os.getenv("ADMIN_PASSWORD", "bob-hackathon-2026"),
        "role": "modernizer",
    },
    "viewer": {"password": "viewer-readonly", "role": "viewer"},
}


def _verify_password(username: str, password: str) -> Optional[Dict[str, str]]:
    """Constant-time credential check against the mock directory."""
    record = _MOCK_USERS.get(username)
    if record and hmac.compare_digest(record["password"], password):
        return record
    return None


# ---------------------------------------------------------------------------
# JWT encode/decode — python-jose when available, stdlib JWS otherwise
# ---------------------------------------------------------------------------

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _stdlib_encode(claims: Dict[str, Any]) -> str:
    """Compact JWS (HS256) using only the stdlib."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url_encode(signature)}"


def _stdlib_decode(token: str) -> Dict[str, Any]:
    """Verify + decode a compact JWS. Raises ValueError on any failure."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise ValueError("malformed token")
    header = json.loads(_b64url_decode(header_b64))
    if header.get("alg") != "HS256":  # never accept 'none' or mismatched alg
        raise ValueError(f"unexpected alg: {header.get('alg')}")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(signature_b64)):
        raise ValueError("signature mismatch")
    claims = json.loads(_b64url_decode(payload_b64))
    if int(claims.get("exp", 0)) < int(time.time()):
        raise ValueError("token expired")
    return claims


def create_access_token(username: str, role: str) -> str:
    """Issue a signed JWT with subject, role, issued-at and expiry claims."""
    now = int(time.time())
    claims = {"sub": username, "role": role, "iat": now, "exp": now + JWT_TTL_SECONDS}
    if _JOSE_AVAILABLE:
        return jose_jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return _stdlib_encode(claims)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Verify signature + expiry, return claims. Raises on any failure."""
    if _JOSE_AVAILABLE:
        try:
            return jose_jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except JWTError as exc:
            raise ValueError(str(exc)) from exc
    return _stdlib_decode(token)


# ---------------------------------------------------------------------------
# FastAPI wiring
# ---------------------------------------------------------------------------

#: tokenUrl is informational for the OpenAPI docs' "Authorize" button.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

auth_router = APIRouter(tags=["auth"])

_CREDENTIALS_401 = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid authentication credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


@auth_router.post("/token", response_model=TokenResponse)
async def issue_token(form: OAuth2PasswordRequestForm = Depends()) -> TokenResponse:
    """
    OAuth2 password-grant token endpoint (mock IdP).

    Demo credentials: ``admin`` / ``bob-hackathon-2026`` (env-overridable).
    """
    record = _verify_password(form.username, form.password)
    if record is None:
        logger.warning("Failed login for user '%s'.", form.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(username=form.username, role=record["role"])
    logger.info("Issued token for user '%s' (role=%s).", form.username, record["role"])
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> EnterpriseUser:
    """
    Strict dependency: validates the Bearer token and enforces that the
    caller holds the ``modernizer`` role required to trigger the AI pipeline.
    """
    try:
        claims = decode_access_token(token)
    except ValueError as exc:
        logger.warning("Rejected token: %s", exc)
        raise _CREDENTIALS_401

    user = EnterpriseUser(
        username=str(claims.get("sub", "")),
        role=str(claims.get("role", "")),
        exp=int(claims.get("exp", 0)),
    )
    if not user.username:
        raise _CREDENTIALS_401
    if user.role != REQUIRED_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{REQUIRED_ROLE}' required to trigger the modernization pipeline.",
        )
    return user


# ---------------------------------------------------------------------------
# Self-test: `python enterprise_auth.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    backend = "python-jose" if _JOSE_AVAILABLE else "stdlib-hmac"
    tok = create_access_token("admin", "modernizer")
    claims = decode_access_token(tok)
    print(f"backend={backend}  token ok: sub={claims['sub']} role={claims['role']}")
    try:
        decode_access_token(tok[:-2] + "xx")
        print("ERROR: tampered token accepted!")
    except ValueError as exc:
        print(f"tampered token correctly rejected ({exc})")
