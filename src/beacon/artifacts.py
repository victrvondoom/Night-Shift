"""Audit artifacts in object storage (MinIO, S3 API).

When an incident resolves, the consent certificate (JSON + Markdown) and the
postmortem are written to the audit bucket, so the evidence outlives the
database row. Storage is optional: without ``MINIO_ENDPOINT`` nothing is written
and the same documents are still served from the API.
"""

from __future__ import annotations

import io
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def _client() -> Any | None:
    endpoint = os.environ.get("MINIO_ENDPOINT", "")
    if not endpoint:
        return None
    from minio import Minio

    from beacon import secrets

    return Minio(
        endpoint,
        access_key=os.environ.get("MINIO_ACCESS_KEY", "beacon"),
        secret_key=secrets.get("MINIO_SECRET_KEY"),
        secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
    )


def put(key: str, body: str, content_type: str) -> str | None:
    """Write one object; returns ``bucket/key`` or None when storage is off."""
    client = _client()
    if client is None:
        return None
    bucket = os.environ.get("MINIO_BUCKET", "beacon-audit")
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
    data = body.encode()
    client.put_object(
        bucket, key, io.BytesIO(data), len(data), content_type=content_type
    )
    return f"{bucket}/{key}"


def store_incident_record(
    incident: dict[str, Any],
    approval: dict[str, Any],
    contracts: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
) -> dict[str, Any]:
    """Certificate + postmortem for one resolved incident; returns their keys."""
    from beacon import certificate, reports

    cert = certificate.build(incident, approval)
    base = f"incidents/{incident.get('incident_id')}"
    out: dict[str, Any] = {"certificate_id": cert.get("certificate_id")}
    docs = (
        (
            "certificate.json",
            json.dumps(cert, indent=2, default=str),
            "application/json",
        ),
        ("certificate.md", certificate.to_markdown(cert), "text/markdown"),
        (
            "postmortem.md",
            reports.postmortem(incident, contracts=contracts, approvals=approvals),
            "text/markdown",
        ),
    )
    for name, body, ctype in docs:
        try:
            out[name] = put(f"{base}/{name}", body, ctype)
        except Exception as exc:
            logger.warning("artifact %s not stored: %s", name, exc)
            out[name] = None
    return out
