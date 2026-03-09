"""Persisted WhatsApp Cloud API settings.

We store settings under the app's instance folder (not in the DB) to avoid
migrations and keep the change additive.

Token is stored encrypted using the existing Fernet helpers.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from config import Config


SETTINGS_FILENAME = "whatsapp_settings.json"


@dataclass(frozen=True)
class WhatsAppSettings:
    phone_number_id: str
    api_version: str
    token: str
    updated_at: str | None = None


def _settings_path(instance_path: str) -> str:
    return os.path.join(instance_path, SETTINGS_FILENAME)


def load_whatsapp_settings(instance_path: str) -> WhatsAppSettings | None:
    path = _settings_path(instance_path)
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw: dict[str, Any] = json.load(f)
    except Exception:
        return None

    phone_number_id = (raw.get("phone_number_id") or "").strip()
    api_version = (raw.get("api_version") or "v19.0").strip() or "v19.0"
    token_enc = (raw.get("token_enc") or "").strip()
    token = (Config.decrypt_data_static(token_enc) or "").strip() if token_enc else ""
    updated_at = (raw.get("updated_at") or "").strip() or None

    if not phone_number_id or not token:
        return None

    return WhatsAppSettings(
        phone_number_id=phone_number_id,
        api_version=api_version,
        token=token,
        updated_at=updated_at,
    )


def save_whatsapp_settings(*, instance_path: str, token: str, phone_number_id: str, api_version: str | None = None) -> WhatsAppSettings:
    os.makedirs(instance_path, exist_ok=True)

    token = (token or "").strip()
    phone_number_id = (phone_number_id or "").strip()
    api_version = (api_version or "v19.0").strip() or "v19.0"

    token_enc = Config.encrypt_data_static(token)
    updated_at = datetime.utcnow().isoformat() + "Z"

    payload = {
        "phone_number_id": phone_number_id,
        "api_version": api_version,
        "token_enc": token_enc,
        "updated_at": updated_at,
    }

    path = _settings_path(instance_path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return WhatsAppSettings(
        phone_number_id=phone_number_id,
        api_version=api_version,
        token=token,
        updated_at=updated_at,
    )


def mask_token(token: str) -> str:
    t = (token or "").strip()
    if not t:
        return ""
    if len(t) <= 8:
        return "*" * len(t)
    return t[:4] + ("*" * (len(t) - 8)) + t[-4:]
