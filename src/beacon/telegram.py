"""Telegram as a typed on-call channel.

One bot, one allowlist of Telegram user ids, one webhook route on the API.
Night Shift pages the engineer here and accepts the same exact consent phrases the
console does, typed. Voice notes are not accepted as consent: there is no
speech-to-text in this path, so a voice note is answered with a request to
type the phrase (voice conversations happen over OmniDimension).
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
import uuid
from typing import Any

from beacon import secrets

logger = logging.getLogger(__name__)

API = "https://api.telegram.org/bot{token}/{method}"
FILE = "https://api.telegram.org/file/bot{token}/{path}"
_TIMEOUT = 10
_STT_WAIT_SECONDS = 25
MIN_CONSENT_CONFIDENCE = 0.85

_token_cache: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def bot_token() -> str:
    """The bot token from the environment, else from Vault."""
    return secrets.get("TELEGRAM_BOT_TOKEN")


def configured() -> bool:
    return bool(bot_token() and os.environ.get("TELEGRAM_CHAT_ID", ""))


def allowed(user_id: Any) -> bool:
    ids = {
        s.strip()
        for s in os.environ.get("TELEGRAM_ALLOWED_IDS", "").split(",")
        if s.strip()
    }
    return str(user_id) in ids


def webhook_secret_ok(headers: dict[str, str]) -> bool:
    want = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "")
    got = {k.lower(): v for k, v in headers.items()}.get(
        "x-telegram-bot-api-secret-token", ""
    )
    return bool(want) and got == want


# ---------------------------------------------------------------------------
# Bot API
# ---------------------------------------------------------------------------


def _multipart(
    fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]
) -> tuple[bytes, str]:
    boundary = f"----beacon{uuid.uuid4().hex}"
    body = bytearray()
    for name, value in fields.items():
        body += (
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f'name="{name}"\r\n\r\n{value}\r\n'
        ).encode()
    for name, (filename, data, ctype) in files.items():
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
            f'filename="{filename}"\r\nContent-Type: {ctype}\r\n\r\n'
        ).encode()
        body += data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def call(
    method: str,
    payload: dict[str, Any],
    *,
    files: dict[str, tuple[str, bytes, str]] | None = None,
) -> dict[str, Any]:
    """One Bot API call; never raises (a chat outage must not break a tool)."""
    token = bot_token()
    if not token:
        return {"ok": False, "description": "no bot token"}
    url = API.format(token=token, method=method)
    if files:
        data, ctype = _multipart({k: str(v) for k, v in payload.items()}, files)
        req = urllib.request.Request(url, data=data, headers={"content-type": ctype})
    else:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"content-type": "application/json"},
        )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            return dict(json.loads(resp.read().decode()))
    except Exception as exc:
        logger.warning("telegram %s failed: %s", method, exc)
        return {"ok": False, "description": str(exc)}


def download(file_id: str) -> bytes | None:
    info = call("getFile", {"file_id": file_id})
    path = ((info.get("result") or {}).get("file_path")) if info.get("ok") else None
    if not path:
        return None
    url = FILE.format(token=bot_token(), path=path)
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:  # noqa: S310
            return bytes(resp.read())
    except Exception as exc:
        logger.warning("telegram file download failed: %s", exc)
        return None


def page_keyboard(incident_id: str | None, link: str) -> dict[str, Any]:
    """*Talk* opens the console on the incident; *Fix 1* reads back, never applies."""
    row: list[dict[str, str]] = []
    if link:
        row.append({"text": "Talk", "url": link})
    if incident_id:
        row.append({"text": "Fix 1", "callback_data": f"propose:{incident_id}"})
        row.append({"text": "Ack", "callback_data": f"ack:{incident_id}"})
    return {"inline_keyboard": [row]} if row else {}


def send_event(
    kind: str, title: str, text: str, *, incident_id: str | None, link: str
) -> bool:
    """A page/escalation/resolution/contract as one message to the on-call chat."""
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not chat_id:
        return False
    icon = {
        "page": "🔴",
        "escalated": "🆘",
        "resolved": "🟢",
        "contract": "🌙",
        "undone": "↩️",
        "morning_report": "☀️",
    }.get(kind, "•")
    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "text": f"{icon} {title}\n{text}"[:4000],
        "disable_web_page_preview": True,
    }
    keyboard = page_keyboard(incident_id, link) if kind in ("page", "escalated") else {}
    if keyboard:
        payload["reply_markup"] = keyboard
    elif link:
        payload["reply_markup"] = {"inline_keyboard": [[{"text": "Open", "url": link}]]}
    return bool(call("sendMessage", payload).get("ok"))


# ---------------------------------------------------------------------------
# Phrase router: the same eight tools, no model in between
# ---------------------------------------------------------------------------

_NUM = (
    r"(\d+|one|two|three|four|five|six|seven|eight|nine|ten"
    r"|ek|do|teen|char|paanch|saat)"
)
_WORD_NUM = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "ek": 1, "do": 2, "teen": 3, "char": 4,
    "paanch": 5, "saat": 7,
}  # fmt: skip


def _num(token: str) -> int:
    return int(token) if token.isdigit() else _WORD_NUM.get(token, 1)


def route(text: str) -> tuple[str, dict[str, Any]] | None:
    """Map a typed line or transcript to (tool, args); None means 'help'."""
    t = re.sub(r"[^\w\s]", " ", text.lower()).strip()
    t = re.sub(r"\s+", " ", t)
    if m := re.search(rf"\bapprove fix {_NUM}\b", t):
        n = _num(m.group(1))
        return "approve_fix", {"fix_id": n, "confirmation_phrase": f"approve fix {n}"}
    if m := re.search(rf"\bundo fix {_NUM}\b", t):
        n = _num(m.group(1))
        return "undo_fix", {"fix_id": n, "confirmation_phrase": f"undo fix {n}"}
    if m := re.search(rf"\b(?:cancel|withdraw|drop) (?:fix|proposal) {_NUM}\b", t):
        return "cancel_proposal", {
            "fix_id": _num(m.group(1)),
            "reason": "engineer asked",
        }
    if m := re.search(rf"\bgrant (?:the )?contract for {_NUM} days?\b", t):
        return "grant_sleep_contract", {"days": _num(m.group(1)), "max_uses": 3}
    if m := re.search(rf"\b{_NUM} din ke liye contract\b", t):
        return "grant_sleep_contract", {"days": _num(m.group(1)), "max_uses": 3}
    if re.search(
        r"\b(open (?:the |a )?(?:pull request|pr)|pull request (?:kholo|banao))\b", t
    ):
        return "open_fix_pr", {"confirmation_phrase": text}
    if re.search(r"\b(contract|next time|handle it yourself|khud sambhal)\b", t):
        return "grant_sleep_contract", {"days": 7, "max_uses": 3}
    # "what are my options" is how people actually ask at 3 AM, and it means the
    # same thing as "fix it" — propose, read back, change nothing yet.
    if re.search(
        r"\b(options?|countermeasures?|what can (you|we) do|what do you suggest"
        r"|suggestions?|recommend|kya kar sakte ho|kya karna chahiye)\b",
        t,
    ):
        return "propose_fix", {}
    if re.search(r"\b(fix|repair|restore|propose|theek|thik)\b", t):
        return "propose_fix", {}
    if re.search(r"\b(changed|change|why|kyun|kyu|deploy|who)\b", t):
        return "get_evidence", {"kind": "changes"}
    if re.search(r"\b(logs?|errors?)\b", t):
        return "get_evidence", {"kind": "logs"}
    if re.search(
        r"\b(fixed|recovered|status|check|healthy|ok now|thik hai|theek hai)\b", t
    ):
        return "check_recovery", {}
    if re.search(r"\b(what|brief|happened|hua|kya|summary|tell me|update)\b", t):
        return "get_incident_brief", {}
    return None


HELP = (
    "I understand plain phrases, typed or as a voice note:\n"
    "• what happened / kya hua\n"
    "• what changed / what are my options\n"
    "• fix it / isko fix kar do\n"
    "• approve fix 1  (the exact phrase applies it)\n"
    "• undo fix 1\n"
    "• is it fixed\n"
    "• handle it next time → then: grant contract for 7 days\n"
    "• open the pull request  (after a fix: the durable fix, never merged)\n"
    "Commands: /status /contracts /report /use <incident id> /help"
)


def reply_text_and_voice(chat_id: Any, text: str, *, voice: bool = True) -> None:
    """Reply in text. (Speech is OmniDimension's job; Telegram is the typed channel.)"""
    call("sendMessage", {"chat_id": chat_id, "text": text[:4000]})
