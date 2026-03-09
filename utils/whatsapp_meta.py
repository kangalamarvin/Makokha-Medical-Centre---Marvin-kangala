"""Meta WhatsApp Cloud API helpers (server-to-WhatsApp).

This module is intentionally small and additive.
Env vars required:
- WHATSAPP_CLOUD_TOKEN
- WHATSAPP_PHONE_NUMBER_ID
Optional:
- WHATSAPP_API_VERSION (default: v19.0)
"""

from __future__ import annotations

import os
import re
from typing import Any

import requests


def normalize_msisdn(phone: str) -> str | None:
    """Normalize common Kenyan phone formats to WhatsApp MSISDN.

    Returns digits-only in international format (e.g. 2547XXXXXXXX) or None.
    """
    if not phone:
        return None

    s = str(phone).strip()
    if not s:
        return None

    # remove spaces, hyphens, parentheses
    s = re.sub(r"[^0-9+]", "", s)

    # strip leading +
    if s.startswith("+"):
        s = s[1:]

    # Handle 07XXXXXXXX (10 digits)
    if s.startswith("0") and len(s) == 10:
        s = "254" + s[1:]

    # Handle 7XXXXXXXX (9 digits)
    if s.startswith("7") and len(s) == 9:
        s = "254" + s

    # Handle 2547XXXXXXXX
    if s.startswith("254") and len(s) == 12:
        return s

    # Some users store 01XXXXXXXX (new prefixes); map to 2541XXXXXXXX
    if s.startswith("0") and len(s) == 10 and s[1] == "1":
        s = "254" + s[1:]
        if len(s) == 12:
            return s

    # Already digits-only but may be another country; accept if 10-15 digits
    if s.isdigit() and 10 <= len(s) <= 15:
        return s

    return None


class WhatsAppConfigError(RuntimeError):
    pass


def _get_config(*, token: str | None = None, phone_number_id: str | None = None, version: str | None = None) -> tuple[str, str, str]:
    t = (token or os.getenv("WHATSAPP_CLOUD_TOKEN") or "").strip()
    pid = (phone_number_id or os.getenv("WHATSAPP_PHONE_NUMBER_ID") or "").strip()
    ver = (version or os.getenv("WHATSAPP_API_VERSION") or "v19.0").strip() or "v19.0"

    if not t or not pid:
        raise WhatsAppConfigError(
            "WhatsApp Cloud API not configured. Set WHATSAPP_CLOUD_TOKEN and WHATSAPP_PHONE_NUMBER_ID (or configure in Admin settings)."
        )

    return t, pid, ver


def send_document(
    *,
    to_msisdn: str,
    pdf_bytes: bytes | None = None,
    document_bytes: bytes | None = None,
    mime_type: str = 'application/pdf',
    filename: str,
    caption: str | None = None,
    token: str | None = None,
    phone_number_id: str | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    """Upload a document to WhatsApp media and send it as a document message.

    Backward compatibility:
    - Existing callers can continue passing `pdf_bytes` only.
    - New callers can pass `document_bytes` + `mime_type` for non-PDF files.
    """
    token, phone_number_id, version = _get_config(token=token, phone_number_id=phone_number_id, version=version)

    if not to_msisdn or not str(to_msisdn).isdigit():
        raise ValueError("Invalid destination number")

    file_bytes = document_bytes if document_bytes is not None else pdf_bytes
    if not file_bytes:
        raise ValueError("Empty document")

    safe_mime = str(mime_type or 'application/pdf').strip().lower() or 'application/pdf'
    if '/' not in safe_mime:
        safe_mime = 'application/pdf'

    base_url = f"https://graph.facebook.com/{version}/{phone_number_id}"
    headers = {"Authorization": f"Bearer {token}"}

    # 1) Upload media
    media_url = f"{base_url}/media"
    files = {
        "file": (filename, file_bytes, safe_mime),
    }
    data = {
        "messaging_product": "whatsapp",
        "type": safe_mime,
    }

    r = requests.post(media_url, headers=headers, data=data, files=files, timeout=30)
    try:
        media_payload = r.json()
    except Exception:
        media_payload = {"raw": r.text}

    if r.status_code >= 400:
        raise RuntimeError(f"Media upload failed: {media_payload}")

    media_id = media_payload.get("id")
    if not media_id:
        raise RuntimeError(f"Media upload returned no id: {media_payload}")

    # 2) Send message
    msg_url = f"{base_url}/messages"
    body: dict[str, Any] = {
        "messaging_product": "whatsapp",
        "to": to_msisdn,
        "type": "document",
        "document": {
            "id": media_id,
            "filename": filename,
        },
    }
    if caption:
        body["document"]["caption"] = caption

    r2 = requests.post(msg_url, headers={**headers, "Content-Type": "application/json"}, json=body, timeout=30)
    try:
        msg_payload = r2.json()
    except Exception:
        msg_payload = {"raw": r2.text}

    if r2.status_code >= 400:
        raise RuntimeError(f"Message send failed: {msg_payload}")

    return {
        "media": media_payload,
        "message": msg_payload,
    }


def send_text(
    *,
    to_msisdn: str,
    text: str,
    token: str | None = None,
    phone_number_id: str | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    """Send a text message (useful for config tests)."""
    token, phone_number_id, version = _get_config(token=token, phone_number_id=phone_number_id, version=version)

    if not to_msisdn or not str(to_msisdn).isdigit():
        raise ValueError("Invalid destination number")

    msg = (text or "").strip()
    if not msg:
        raise ValueError("Empty text")

    base_url = f"https://graph.facebook.com/{version}/{phone_number_id}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body: dict[str, Any] = {
        "messaging_product": "whatsapp",
        "to": to_msisdn,
        "type": "text",
        "text": {"body": msg},
    }

    r = requests.post(f"{base_url}/messages", headers=headers, json=body, timeout=30)
    try:
        payload = r.json()
    except Exception:
        payload = {"raw": r.text}

    if r.status_code >= 400:
        raise RuntimeError(f"Message send failed: {payload}")

    return payload
