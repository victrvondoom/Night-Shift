"""Cryptographic consent record: an HMAC-SHA256 signature over the exact approval, bound to a server-side key.

The signature covers incident, proposal, action, canonical params hash, approver principal + auth method, session
fingerprint, the typed phrase, the proposal expiry and the grant time.  Altering any stored field after the fact
(a changed approver, params or time) makes ``verify`` fail.  The key is ``CONSENT_SIGNING_KEY`` or, if unset, a random
key generated once and kept in the database (never derived from the passcode, never returned by any API).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as pysecrets
from typing import Any

from beacon import db

FIELDS = ("incident_id", "proposal_id", "approval_id", "action", "params_hash", "principal", "auth_method", "session", "typed_phrase", "proposal_expires_at", "granted_at", "idempotency_key")


def _key() -> bytes:
    env = os.environ.get("CONSENT_SIGNING_KEY", "")
    if env:
        return env.encode()
    table = os.environ.get("NS_SECRETS_TABLE", "ns_secrets")
    row = db.get(table, "consent_key")
    if row is None:
        db.insert(table, "consent_key", {"key": pysecrets.token_hex(32)})
        row = db.get(table, "consent_key") or {}
    return str(row["key"]).encode()


def canonical(rec: dict[str, Any]) -> bytes:
    return json.dumps({k: rec.get(k) for k in FIELDS}, sort_keys=True, separators=(",", ":")).encode()


def sign(rec: dict[str, Any]) -> dict[str, str]:
    mac = hmac.new(_key(), canonical(rec), hashlib.sha256).hexdigest()
    return {"alg": "HMAC-SHA256", "signature": mac, "digest": hashlib.sha256(canonical(rec)).hexdigest()}


def verify(rec: dict[str, Any], sig: dict[str, str] | None) -> bool:
    if not sig or sig.get("alg") != "HMAC-SHA256":
        return False
    return hmac.compare_digest(hmac.new(_key(), canonical(rec), hashlib.sha256).hexdigest(), str(sig.get("signature", "")))
