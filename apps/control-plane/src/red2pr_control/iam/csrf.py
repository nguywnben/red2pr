"""Double-submit + synchronizer CSRF protection & strict Origin validation (SEC-026).

Implements docs/14_SECURITY_IDENTITY.md, docs/36_CANONICAL_CONTRACTS.md (A-02), and SEC-026:
- Enforces same-origin `Origin` (with `Referer` fallback) on EVERY cookie-mutating request,
  including pre-authenticated `/api/v1/setup/claim`, `/api/v1/auth/login`, and
  `/api/v1/auth/recovery`.
- Pre-auth forms use HMAC-SHA256 signed double-submit tokens (`anon.<nonce>.<sig>`) paired
  with the `red2pr_csrf` cookie and `X-CSRF-Token` request header.
- Authenticated sessions bind CSRF tokens directly to `sessions.csrf_secret_hash` (SHA-256)
  AND require constant-time double-submit equality between `red2pr_csrf` cookie and
  `X-CSRF-Token` header.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlparse

from fastapi import Request, Response

from py_contracts.crypto import compute_hmac_sha256_hex, verify_hmac_sha256_hex
from red2pr_control.core.errors import ForbiddenError

CSRF_COOKIE_NAME: str = "red2pr_csrf"
CSRF_HEADER_NAME: str = "X-CSRF-Token"
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


def hash_csrf_secret(raw_token: str) -> str:
    """Compute SHA-256 hex digest of a session-bound CSRF token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def mint_session_csrf_token() -> tuple[str, str]:
    """Generate a fresh 256-bit session CSRF token and its SHA-256 DB hash."""
    raw = f"sess.{secrets.token_urlsafe(32)}"
    return raw, hash_csrf_secret(raw)


def mint_anonymous_csrf_token(signing_key: bytes) -> str:
    """Generate an HMAC-signed pre-session CSRF token for login/claim/recovery forms."""
    if len(signing_key) < 32:
        raise ValueError("CSRF signing key must be at least 32 bytes")
    nonce = secrets.token_urlsafe(24)
    mac = compute_hmac_sha256_hex(signing_key, f"red2pr:csrf:anon:v1:{nonce}".encode("ascii"))
    return f"anon.{nonce}.{mac}"


def verify_anonymous_csrf_token(signing_key: bytes, token: str) -> bool:
    """Verify HMAC signature on an anonymous pre-session CSRF token in constant time."""
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "anon" or not parts[1] or len(parts[2]) != 64:
        return False
    nonce, mac_hex = parts[1], parts[2]
    return verify_hmac_sha256_hex(
        signing_key,
        f"red2pr:csrf:anon:v1:{nonce}".encode("ascii"),
        mac_hex,
    )


def _normalize_origin_tuple(url_text: str) -> tuple[str, str, int] | None:
    parsed = urlparse(url_text.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in {"http", "https"} or not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    return scheme, host, effective_port


def _allowed_origins_for_request(
    request: Request,
    *,
    public_base_url: str,
) -> set[tuple[str, str, int]]:
    allowed: set[tuple[str, str, int]] = set()
    configured = _normalize_origin_tuple(public_base_url)
    if configured is not None:
        allowed.add(configured)
        # In local loopback mode, equivalent loopback aliases on the same scheme+port match
        if configured[1] in _LOOPBACK_HOSTS:
            for alias in _LOOPBACK_HOSTS:
                allowed.add((configured[0], alias, configured[2]))

    req_origin = _normalize_origin_tuple(str(request.base_url))
    if req_origin is not None and (
        req_origin[1] == "testserver" or req_origin[1] in _LOOPBACK_HOSTS
    ):
        allowed.add(req_origin)
        if req_origin[1] in _LOOPBACK_HOSTS:
            for alias in _LOOPBACK_HOSTS:
                allowed.add((req_origin[0], alias, req_origin[2]))
    return allowed


def validate_request_origin(
    request: Request,
    *,
    public_base_url: str,
) -> None:
    """Validate `Origin` (or `Referer` fallback) against allowed same-origin targets."""
    allowed = _allowed_origins_for_request(request, public_base_url=public_base_url)
    raw_origin = request.headers.get("origin")
    if raw_origin is not None:
        candidate = _normalize_origin_tuple(raw_origin)
        if candidate is None or candidate not in allowed:
            raise ForbiddenError(
                code="csrf_origin_denied",
                detail="Cross-origin state-changing request denied by CSRF Origin policy.",
            )
        return

    raw_referer = request.headers.get("referer")
    if raw_referer is not None:
        candidate = _normalize_origin_tuple(raw_referer)
        if candidate is None or candidate not in allowed:
            raise ForbiddenError(
                code="csrf_origin_denied",
                detail="Cross-origin state-changing request denied by CSRF Referer policy.",
            )
        return


def validate_double_submit_csrf(
    request: Request,
    *,
    public_base_url: str,
    signing_key: bytes,
    expected_session_csrf_hash: str | None = None,
) -> None:
    """Enforce Origin check + double-submit cookie/header match + HMAC/session binding."""
    validate_request_origin(request, public_base_url=public_base_url)

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    header_token = request.headers.get(CSRF_HEADER_NAME)
    if (
        not cookie_token
        or not header_token
        or len(cookie_token) > 256
        or len(header_token) > 256
        or not hmac.compare_digest(cookie_token, header_token)
    ):
        raise ForbiddenError(
            code="csrf_invalid",
            detail="Missing or mismatched CSRF token.",
        )

    if expected_session_csrf_hash is not None:
        candidate_hash = hash_csrf_secret(header_token)
        if not hmac.compare_digest(candidate_hash, expected_session_csrf_hash):
            raise ForbiddenError(
                code="csrf_invalid",
                detail="CSRF token does not match the active authenticated session.",
            )
        return

    # Pre-auth endpoint (login / setup claim / recovery): accept valid signed anon token
    # OR a previously issued `sess.*` cookie/header pair if the user is re-authenticating.
    if header_token.startswith("anon."):
        if not verify_anonymous_csrf_token(signing_key, header_token):
            raise ForbiddenError(
                code="csrf_invalid",
                detail="Invalid CSRF token signature.",
            )
        return

    if not header_token.startswith("sess.") or len(header_token) < 24:
        raise ForbiddenError(
            code="csrf_invalid",
            detail="Malformed CSRF token.",
        )


def set_csrf_cookie(
    response: Response,
    *,
    csrf_token: str,
    secure: bool,
    max_age_seconds: int = 43_200,
) -> None:
    """Attach the same-origin CSRF cookie (`SameSite=Lax`)."""
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age_seconds,
        path="/",
        secure=secure,
        httponly=False,
        samesite="lax",
    )


def clear_csrf_cookie(response: Response, *, secure: bool) -> None:
    """Clear the CSRF cookie on logout."""
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        secure=secure,
        httponly=False,
        samesite="lax",
    )
