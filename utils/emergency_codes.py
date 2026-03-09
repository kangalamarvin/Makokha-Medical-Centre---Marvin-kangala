from __future__ import annotations

from typing import Any, Dict, List, Optional


# NOTE: Keep this data free of PHI. Ward/bed selection happens at runtime.


_CODES: List[Dict[str, Any]] = [
    {
        "key": "code_blue",
        "name": "Code Blue",
        "category": "medical",
        "severity": "critical",
        # User requested: Code Blue -> screen turns red.
        "overlay_color": "#b00020",
        "description": "Life-threatening medical emergency requiring immediate response.",
        "conditions": [
            "Cardiac arrest / no pulse",
            "Respiratory arrest / not breathing",
            "Unresponsive patient (suspected arrest)",
            "Severe airway compromise",
        ],
        "states": [
            "No pulse",
            "Apnea or gasping",
            "Unconscious / unresponsive",
            "Severe cyanosis",
        ],
        "scopes": ["ward", "department"],
    },
    {
        "key": "code_red",
        "name": "Code Red",
        "category": "safety",
        "severity": "critical",
        "overlay_color": "#7f0000",
        "description": "Fire/smoke emergency requiring immediate evacuation and response.",
        "conditions": [
            "Visible smoke or flames",
            "Fire alarm activation",
            "Electrical fire risk",
            "Hazardous combustion smell",
        ],
        "states": [
            "Active fire",
            "Smoke present",
            "Evacuation required",
            "Area unsafe",
        ],
        "scopes": ["ward", "department"],
    },
]


def list_emergency_codes() -> List[Dict[str, Any]]:
    """Return a JSON-serializable list of emergency code definitions."""
    return [dict(c) for c in _CODES]


def get_emergency_code(code_key: str) -> Optional[Dict[str, Any]]:
    key = (code_key or "").strip().lower()
    for c in _CODES:
        if (c.get("key") or "").strip().lower() == key:
            return dict(c)
    return None

