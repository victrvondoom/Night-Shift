"""Fix at source: after the runtime fix verifies, open the pull request.

The runtime fix patches the cluster; this makes the same fix durable in Git.
Everything in the PR is produced by code from the incident record:

* for ``networkpolicy.restore_ingress`` on a manifest that does **not** declare
  the rule, the rule (the golden snapshot's own object) is added to that
  NetworkPolicy document;
* when the manifest already declares it, the cluster drifted from Git and the
  PR says so, naming the actor from the Kubernetes audit ledger;
* for the Deployment actions there is no code change: the PR carries the
  postmortem only.

Nothing is merged. The token is a fine-grained GitHub token (``contents:write``
+ ``pull_requests:write`` on one repository) read from Vault.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any

from beacon import certificate, secrets

logger = logging.getLogger(__name__)

_GH = "https://api.github.com"
_TIMEOUT = 15
PHRASE = "open the pull request"
_PHRASES = (
    re.compile(r"\bopen (?:the )?pull request\b"),
    re.compile(r"\bopen (?:the |a )?pr\b"),
    re.compile(r"\bpull request (?:kholo|khol do|banao|bana do)\b"),
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def repo() -> str:
    return os.environ.get("FIX_PR_REPO", "").strip()


def base_branch() -> str:
    return os.environ.get("FIX_PR_BASE", "main").strip() or "main"


def template_path() -> str:
    return os.environ.get("FIX_PR_MANIFEST_PATH", "deploy/k8s/demo/demo.yaml")


def configured() -> bool:
    return bool(repo() and token())


def token() -> str:
    """A fine-grained GitHub token (contents + pull requests on one repository)."""
    return secrets.get("GITHUB_PR_TOKEN")


def said_phrase(transcript: str) -> bool:
    spoken = re.sub(r"[^a-z0-9\s]", " ", transcript.lower())
    spoken = re.sub(r"\s+", " ", spoken)
    return any(p.search(spoken) for p in _PHRASES)


# ---------------------------------------------------------------------------
# GitHub REST (urllib; no SDK)
# ---------------------------------------------------------------------------


def gh(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    req = urllib.request.Request(
        f"{_GH}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={
            "authorization": f"Bearer {token()}",
            "accept": "application/vnd.github+json",
            "x-github-api-version": "2022-11-28",
            "content-type": "application/json",
            "user-agent": "beacon-night-shift",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            raw = resp.read().decode()
            return dict(json.loads(raw)) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:300]
        raise RuntimeError(f"github {method} {path}: {exc.code} {detail}") from exc


def _get_file(path: str, ref: str) -> tuple[str, str] | None:
    """(text, blob sha) of a file at *ref*, or None when it does not exist."""
    try:
        got = gh("GET", f"/repos/{repo()}/contents/{path}?ref={ref}")
    except RuntimeError as exc:
        if " 404 " in str(exc):
            return None
        raise
    return base64.b64decode(str(got.get("content", ""))).decode(), str(got.get("sha"))


def _put_file(
    path: str, text: str, *, branch: str, message: str, sha: str | None
) -> None:
    body: dict[str, Any] = {
        "message": message,
        "content": base64.b64encode(text.encode()).decode(),
        "branch": branch,
    }
    if sha:
        body["sha"] = sha
    gh("PUT", f"/repos/{repo()}/contents/{path}", body)


# ---------------------------------------------------------------------------
# The deterministic patch
# ---------------------------------------------------------------------------


def _documents(text: str) -> list[str]:
    """A multi-document manifest split on ``---`` lines, text preserved."""
    return re.split(r"(?m)^---[ \t]*\n", text)


def _is_target(doc: Any, params: dict[str, Any]) -> bool:
    meta = (doc or {}).get("metadata") or {} if isinstance(doc, dict) else {}
    return (
        isinstance(doc, dict)
        and doc.get("kind") == "NetworkPolicy"
        and meta.get("name") == params.get("name")
        and meta.get("namespace", params.get("namespace")) == params.get("namespace")
    )


def manifest_declares_rule(text: str, params: dict[str, Any]) -> bool | None:
    """True/False when the manifest has the NetworkPolicy; None when it does not."""
    import yaml

    from beacon.remediation import actions_netpol

    for chunk in _documents(text):
        doc = yaml.safe_load(chunk) if chunk.strip() else None
        if _is_target(doc, params):
            rules = (doc.get("spec") or {}).get("ingress") or []
            return any(actions_netpol._matches(r, params) for r in rules)
    return None


def canonical_rule(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "from": [{"podSelector": {"matchLabels": {"app": params["from_app"]}}}],
        "ports": [{"protocol": params["protocol"], "port": params["port"]}],
    }


def patch_manifest(text: str, params: dict[str, Any], rule: dict[str, Any]) -> str:
    """Add *rule* to the NetworkPolicy's ingress; other documents are untouched."""
    import yaml

    chunks = _documents(text)
    for n, chunk in enumerate(chunks):
        doc = yaml.safe_load(chunk) if chunk.strip() else None
        if _is_target(doc, params):
            spec = doc.setdefault("spec", {})
            spec["ingress"] = [*(spec.get("ingress") or []), rule]
            chunks[n] = (
                f"# ingress rule restored by Night Shift: {params['protocol']}/"
                f"{params['port']} from app={params['from_app']}\n"
                + yaml.safe_dump(doc, sort_keys=False)
            )
            break
    return "---\n".join(chunks)


def plan_patch(
    *, action: str, params: dict[str, Any], incident_id: str, template_text: str | None
) -> dict[str, Any]:
    """What the PR will change, decided by code from the dry-run params."""
    if action != "networkpolicy.restore_ingress" or template_text is None:
        return {
            "kind": "postmortem_only",
            "reason": (
                "no manifest in the repository"
                if template_text is None
                else f"{action} has no code change"
            ),
        }
    logical = {
        "group": f"{params.get('namespace')}/{params.get('name')}",
        "source": f"app={params.get('from_app')}",
    }
    declared = manifest_declares_rule(template_text, params)
    if declared is None:
        return {
            "kind": "postmortem_only",
            "reason": "the NetworkPolicy is not declared in the manifest",
        }
    if declared:
        return {
            "kind": "postmortem_only",
            "reason": (
                "the manifest already declares this rule; it was removed from the "
                "cluster out of band (see the change ledger)"
            ),
            "logical": logical,
        }
    from beacon.remediation import actions_netpol

    rule = actions_netpol.golden_rule(
        params, actions_netpol.load_golden_snapshot() or {}
    ) or canonical_rule(params)
    return {
        "kind": "template_patch",
        "logical": logical,
        "resource": rule,
        "patched": patch_manifest(template_text, params, rule),
    }


# ---------------------------------------------------------------------------
# The pull request
# ---------------------------------------------------------------------------


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:48] or "incident"


def pr_body(
    incident: dict[str, Any],
    *,
    plan: dict[str, Any],
    approval: dict[str, Any] | None,
    link: str,
) -> str:
    rca = incident.get("rca_json") or {}
    verifies = [
        e for e in incident.get("timeline") or [] if e.get("event") == "verify_attempt"
    ]
    last = (verifies[-1].get("detail") or {}) if verifies else {}
    checks = last.get("checks") or []
    change = (incident.get("changes") or [{}])[0]
    att = (approval or {}).get("attestation") or {}
    lines = [
        f"**Incident** `{incident.get('incident_id')}` on alarm "
        f"`{incident.get('alarm_name')}` — "
        f"status **{incident.get('status')}**.",
        "",
        str(rca.get("summary") or ""),
        "",
        "### What this PR does",
    ]
    if plan["kind"] == "template_patch":
        lines.append(
            f"- Declares the ingress rule that was missing at runtime in the "
            f"NetworkPolicy `{plan['logical']['group']}` from pods "
            f"`{plan['logical']['source']}` (the same parameters that passed the "
            "dry run)."
        )
    else:
        lines.append(f"- No manifest change: {plan.get('reason')}.")
    lines.append("- Adds the postmortem under `docs/incidents/`.")

    # The certificate first: a reviewer reading this in six weeks wants to know why
    # the change was allowed before they want to know what it did.
    if approval:
        cert = certificate.build(incident, approval)
        lines += ["", certificate.to_markdown(cert)]

    lines += ["", "### The approval that applied the runtime fix"]
    if approval:
        lines.append(
            f"> “{approval.get('transcript_quote')}” — via "
            f"**{approval.get('channel')}** at "
            f"{str(approval.get('granted_at', ''))[:19]}Z"
            + (
                f", STT confidence {int(float(att['confidence']) * 100)}%"
                if isinstance(att.get("confidence"), int | float)
                else ""
            )
            + (
                f", preceded by Bolna call `{(att.get('voice_request') or {}).get('execution_id')}`"
                if (att.get("voice_request") or {}).get("execution_id")
                else ""
            )
        )
    else:
        lines.append("_no approval record_")
    if checks:
        passed = sum(1 for c in checks if c.get("ok"))
        attempt = last.get("attempt")
        lines += [
            "",
            f"### Verification: {passed}/{len(checks)} checks on attempt {attempt}",
        ]
        for c in checks:
            mark = "✅" if c.get("ok") else "❌"
            name = c.get("name") or c.get("check")
            lines.append(f"- {mark} {name}: {c.get('detail') or ''}".rstrip())
    if change:
        lines += [
            "",
            "### The change behind it (Kubernetes audit / GitHub)",
            f"`{change.get('event_name')}` by `{change.get('actor_short')}` at "
            f"{change.get('event_time')} on "
            f"{', '.join(str(i) for i in change.get('resource_ids', [])) or '-'}",
        ]
    if link:
        lines += ["", f"Console: {link}"]
    lines += [
        "",
        "_Opened by Night Shift after the engineer said “open the pull "
        "request”. Nothing is merged by Night Shift._",
    ]
    return "\n".join(lines)


def open_pr(
    incident: dict[str, Any],
    *,
    action: str,
    params: dict[str, Any],
    postmortem_md: str,
    approval: dict[str, Any] | None,
    link: str,
) -> dict[str, Any]:
    """Branch, commit the files, open the PR; returns {url, number, files, kind}."""
    if not configured():
        raise RuntimeError("fix-at-source is not configured (FIX_PR_REPO / token)")
    inc_id = str(incident.get("incident_id"))
    short = inc_id[:8]
    alarm = str(incident.get("alarm_name") or "incident")
    day = str(incident.get("timestamp") or datetime.now(tz=UTC).isoformat())[:10]
    branch = f"beacon/incident-{short}"
    base_sha = str(
        gh("GET", f"/repos/{repo()}/git/ref/heads/{base_branch()}")["object"]["sha"]
    )
    try:
        gh(
            "POST",
            f"/repos/{repo()}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
    except RuntimeError as exc:
        if " 422 " not in str(exc):  # already exists: reuse it
            raise

    files: list[str] = []
    tpl = _get_file(template_path(), base_branch())
    plan = plan_patch(
        action=action,
        params=params,
        incident_id=inc_id,
        template_text=tpl[0] if tpl else None,
    )
    if plan["kind"] == "template_patch" and tpl is not None:
        _put_file(
            template_path(),
            plan["patched"],
            branch=branch,
            message=f"Restore ingress rule missing at runtime (Night Shift {short})",
            sha=tpl[1],
        )
        files.append(template_path())
    pm_path = f"docs/incidents/{day}-{_slug(alarm)}-{short}.md"
    existing = _get_file(pm_path, branch)
    _put_file(
        pm_path,
        postmortem_md,
        branch=branch,
        message=f"Postmortem for {alarm} (Night Shift incident {short})",
        sha=existing[1] if existing else None,
    )
    files.append(pm_path)

    title = (
        f"Restore {plan['logical']['group']} ingress from "
        f"{plan['logical']['source']} (Night Shift incident {short})"
        if plan["kind"] == "template_patch"
        else f"Postmortem: {alarm} (Night Shift incident {short})"
    )
    pr = gh(
        "POST",
        f"/repos/{repo()}/pulls",
        {
            "title": title,
            "head": branch,
            "base": base_branch(),
            "body": pr_body(incident, plan=plan, approval=approval, link=link),
        },
    )
    return {
        "url": str(pr.get("html_url")),
        "number": int(pr.get("number", 0)),
        "branch": branch,
        "files": files,
        "kind": plan["kind"],
        "reason": plan.get("reason"),
        "title": title,
    }
