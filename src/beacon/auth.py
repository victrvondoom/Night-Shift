"""Server-side console authentication: sessions, CSRF and the approver principal.

The approver recorded on an approval is derived here, from the authenticated session or passcode
check, and never from a client-supplied name.  This deployment has one shared passcode, so the only
honest principal is ``LOCAL_DEMO_OPERATOR`` with method ``LOCAL_PASSCODE`` -- it identifies *the
passcode holder*, not a verified individual.

* ``POST /api/auth/login``   passcode -> HttpOnly, SameSite=Strict session cookie (+ CSRF token)
* ``POST /api/auth/logout``  invalidates the session server-side
* ``GET  /api/auth/me``      current principal
* Mutations with a cookie session must send ``X-CSRF-Token``; the legacy ``X-Beacon-Passcode``
  header (scripts, tests) is still accepted and recorded as ``LOCAL_PASSCODE_HEADER``.
* Failed passcode attempts are rate limited per client address.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets as pysecrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from beacon import db, secrets

router = APIRouter()
COOKIE = "ns_session"
PRINCIPAL_ID = "LOCAL_DEMO_OPERATOR"


@dataclass(frozen=True)
class Principal:
    id: str
    method: str  # LOCAL_PASSCODE | LOCAL_PASSCODE_HEADER
    session: str  # hash prefix of the session id; "" for header auth


def _table() -> str:
    return os.environ.get("NS_SESSIONS_TABLE", "ns_sessions")


def _ttl() -> timedelta:
    return timedelta(minutes=int(os.environ.get("SESSION_TTL_MINUTES", "480")))


def _max_fails() -> int:
    return int(os.environ.get("LOGIN_MAX_FAILURES", "5"))


def _window() -> int:
    return int(os.environ.get("LOGIN_FAILURE_WINDOW_SECONDS", "300"))


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _fail_table() -> str:
    return os.environ.get("NS_AUTH_FAILURES_TABLE", "ns_auth_failures")


def _blocked(ip: str) -> bool:
    """Failed-attempt window kept in PostgreSQL, so the limit holds across every API process/replica."""
    row = db.get(_fail_table(), ip)
    now = time.time()
    recent = [t for t in (row or {}).get("times", []) if now - float(t) < _window()]
    return len(recent) >= _max_fails()


def _fail(ip: str) -> None:
    """Atomic append (single UPDATE ... || jsonb) so concurrent processes cannot lose or double-skip a failure."""
    now = time.time()
    t = db._ensure(_fail_table())
    from psycopg.types.json import Jsonb

    with db.pool().connection() as conn:
        conn.execute(
            f"INSERT INTO {t} (id, doc) VALUES (%s, %s) ON CONFLICT (id) DO UPDATE SET doc = jsonb_set({t}.doc, '{{times}}', "
            f"COALESCE((SELECT jsonb_agg(x) FROM jsonb_array_elements({t}.doc->'times') x WHERE (x::text)::float8 > %s), '[]'::jsonb) || to_jsonb(%s::float8))",
            (ip, Jsonb({"times": [now]}), now - _window(), now),
        )


def reset_rate_limits() -> None:
    t = db._ensure(_fail_table())
    with db.pool().connection() as conn:
        conn.execute(f"DELETE FROM {t}")


def _passcode_matches(given: str) -> bool:
    expected = secrets.get("PASSCODE")
    return bool(expected and given) and hmac.compare_digest(given.encode(), expected.encode())


def _session(request: Request) -> dict | None:
    token = request.cookies.get(COOKIE, "")
    if not token:
        return None
    row = db.get(_table(), _hash(token))
    if not row or row.get("revoked") or str(row.get("expires_at", "")) <= datetime.now(tz=UTC).isoformat():
        return None
    return row


def principal(request: Request) -> Principal | None:
    """The authenticated principal for this request, or None."""
    ip = _ip(request)
    row = _session(request)
    if row is not None:
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            given = request.headers.get("x-csrf-token", "")
            if not (given and hmac.compare_digest(given.encode(), str(row.get("csrf", "")).encode())):
                return None  # CSRF check failed
        return Principal(PRINCIPAL_ID, "LOCAL_PASSCODE", str(row["sid"])[:12])
    given = request.headers.get("x-beacon-passcode", "")
    if given:
        if _blocked(ip):
            return None
        if _passcode_matches(given):
            return Principal(PRINCIPAL_ID, "LOCAL_PASSCODE_HEADER", "")
        _fail(ip)
    return None


@router.post("/login")
async def login(request: Request) -> JSONResponse:
    ip = _ip(request)
    if _blocked(ip):
        return JSONResponse({"error": "too many failed attempts; try again later"}, status_code=429, headers={"retry-after": str(_window())})
    try:
        body = dict(await request.json())
    except Exception:
        body = {}
    if not _passcode_matches(str(body.get("passcode", ""))):
        _fail(ip)
        return JSONResponse({"error": "invalid passcode"}, status_code=401)
    token, csrf = pysecrets.token_urlsafe(32), pysecrets.token_urlsafe(24)
    now = datetime.now(tz=UTC)
    sid = _hash(token)
    db.put(_table(), sid, {"sid": sid, "principal": PRINCIPAL_ID, "method": "LOCAL_PASSCODE", "csrf": csrf, "created_at": now.isoformat(), "expires_at": (now + _ttl()).isoformat(), "revoked": False})
    resp = JSONResponse({"principal": PRINCIPAL_ID, "method": "LOCAL_PASSCODE", "verified_human_identity": False, "csrf_token": csrf, "expires_at": (now + _ttl()).isoformat()})
    secure = request.url.scheme == "https" or os.environ.get("COOKIE_SECURE", "").lower() == "true"
    resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure, max_age=int(_ttl().total_seconds()), path="/")
    return resp


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    row = _session(request)
    if row:
        db.patch(_table(), row["sid"], {"revoked": True})
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


@router.get("/me")
async def me(request: Request) -> JSONResponse:
    row = _session(request)
    if row is None:
        return JSONResponse({"authenticated": False}, status_code=401)
    return JSONResponse({"authenticated": True, "principal": PRINCIPAL_ID, "method": "LOCAL_PASSCODE", "csrf_token": row["csrf"], "expires_at": row["expires_at"], "verified_human_identity": False})
