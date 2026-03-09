"""utils/feature_flags.py

Persisted feature flags for Phase 1/2/3 security features.

Design goals:
- Safe defaults: if flags are missing/corrupt, features remain enabled
- Persistence: instance/feature_flags.json
- No secrets stored
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict


_FLAGS_PATH = os.path.join(os.getcwd(), "instance", "feature_flags.json")


def default_feature_flags() -> Dict[str, bool]:
    # Default to enabled to preserve current behavior.
    return {
        # Phase 1
        "phase1_mfa_enforcement": True,
        "phase1_message_encryption": True,
        "phase1_immutable_backups": True,
        "phase1_db_encryption_at_rest": True,
        "phase1_db_activity_monitoring": True,

        # Phase 2
        "phase2_waf": True,
        "phase2_zero_knowledge": True,
        "phase2_adaptive_auth": True,
        "phase2_ai_threat_detection": True,
        "phase2_comprehensive_audit": True,

        # Phase 3
        "phase3_siem": True,
        "phase3_uba": True,
        "phase3_compliance": True,
        "phase3_dlp": True,
        "phase3_incident_response": True,
    }


def load_feature_flags() -> Dict[str, bool]:
    flags = default_feature_flags()
    try:
        os.makedirs(os.path.dirname(_FLAGS_PATH), exist_ok=True)
        if not os.path.exists(_FLAGS_PATH):
            return flags
        with open(_FLAGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        raw = data.get("flags") if isinstance(data, dict) else None
        if isinstance(raw, dict):
            for k, v in raw.items():
                if k in flags:
                    flags[k] = bool(v)
    except Exception:
        return flags
    return flags


def save_feature_flags(flags: Dict[str, Any]) -> Dict[str, bool]:
    clean = default_feature_flags()
    for k in clean.keys():
        if k in flags:
            clean[k] = bool(flags[k])

    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "flags": clean,
    }

    os.makedirs(os.path.dirname(_FLAGS_PATH), exist_ok=True)
    tmp = _FLAGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, _FLAGS_PATH)
    return clean


def apply_flags_to_app_config(app, flags: Dict[str, bool]) -> None:
    """Populate app.config keys consumed by Phase 3 hooks and runtime checks."""

    app.config["FEATURE_FLAGS"] = dict(flags)

    # Phase 1 behavior toggles
    app.config["MFA_ENFORCEMENT_ENABLED"] = bool(flags.get("phase1_mfa_enforcement", True))
    app.config["MESSAGE_ENCRYPTION_ENABLED"] = bool(flags.get("phase1_message_encryption", True))
    app.config["BACKUPS_ENABLED"] = bool(flags.get("phase1_immutable_backups", True))
    app.config["IMMUTABLE_BACKUPS_ENABLED"] = bool(flags.get("phase1_immutable_backups", True))
    app.config["DB_ENCRYPTION_AT_REST_ENABLED"] = bool(flags.get("phase1_db_encryption_at_rest", True))
    app.config["DB_ACTIVITY_MONITORING_ENABLED"] = bool(flags.get("phase1_db_activity_monitoring", True))

    # Phase 2
    app.config["WAF_ENABLED"] = bool(flags.get("phase2_waf", True))
    app.config["ZERO_KNOWLEDGE_ENABLED"] = bool(flags.get("phase2_zero_knowledge", True))
    app.config["ADAPTIVE_AUTH_ENABLED"] = bool(flags.get("phase2_adaptive_auth", True))
    app.config["AI_THREAT_DETECTION_ENABLED"] = bool(flags.get("phase2_ai_threat_detection", True))
    app.config["COMPREHENSIVE_AUDIT_ENABLED"] = bool(flags.get("phase2_comprehensive_audit", True))

    # Phase 3
    app.config["SIEM_ENABLED"] = bool(flags.get("phase3_siem", True))
    app.config["UBA_ENABLED"] = bool(flags.get("phase3_uba", True))
    app.config["COMPLIANCE_ENABLED"] = bool(flags.get("phase3_compliance", True))
    app.config["DLP_ENABLED"] = bool(flags.get("phase3_dlp", True))
    app.config["INCIDENT_RESPONSE_ENABLED"] = bool(flags.get("phase3_incident_response", True))
