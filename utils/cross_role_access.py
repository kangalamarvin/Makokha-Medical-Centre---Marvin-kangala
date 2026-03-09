"""utils/cross_role_access.py

Persisted allowlists for cross-dashboard role switching.

Use cases:
- A doctor can temporarily enter LabTech mode (sidebar + permissions), then return to Doctor mode.
- A pharmacist can temporarily enter Receptionist mode, then return to Pharmacist mode.

Security model:
- Default deny: nobody can switch unless explicitly allowed by an admin.
- The base role in the database never changes; we only store an "active role" in the session.
- No secrets are stored here.

Storage:
  instance/cross_role_access.json
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Set


PERM_DOCTOR_LABTECH = "doctor_labtech"
PERM_PHARMACIST_RECEPTIONIST = "pharmacist_receptionist"

_KNOWN_PERMS: Set[str] = {PERM_DOCTOR_LABTECH, PERM_PHARMACIST_RECEPTIONIST}
_PATH = os.path.join(os.getcwd(), "instance", "cross_role_access.json")


def _coerce_int_list(values: Any) -> List[int]:
    out: List[int] = []
    if not isinstance(values, list):
        return out
    for v in values:
        try:
            out.append(int(v))
        except Exception:
            continue
    # de-dupe while keeping order
    seen: Set[int] = set()
    clean: List[int] = []
    for i in out:
        if i in seen:
            continue
        seen.add(i)
        clean.append(i)
    return clean


def load_allowlists() -> Dict[str, Set[int]]:
    """Load allowlists as sets of user IDs. Missing/corrupt files -> empty allowlists."""
    allowlists: Dict[str, Set[int]] = {p: set() for p in _KNOWN_PERMS}
    try:
        os.makedirs(os.path.dirname(_PATH), exist_ok=True)
        if not os.path.exists(_PATH):
            return allowlists
        with open(_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return allowlists

        # Prefer nested "allowlists" but support legacy top-level keys.
        nested = data.get("allowlists") if isinstance(data.get("allowlists"), dict) else {}
        for perm in _KNOWN_PERMS:
            raw = nested.get(perm)
            if raw is None:
                raw = data.get(perm)
            allowlists[perm] = set(_coerce_int_list(raw))
    except Exception:
        return allowlists
    return allowlists


def save_allowlists(allowlists: Dict[str, Any]) -> Dict[str, Set[int]]:
    """Persist allowlists. Returns the normalized saved allowlists."""
    clean_lists: Dict[str, List[int]] = {p: [] for p in _KNOWN_PERMS}
    if isinstance(allowlists, dict):
        for perm in _KNOWN_PERMS:
            clean_lists[perm] = _coerce_int_list(allowlists.get(perm))

    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "allowlists": {p: clean_lists[p] for p in _KNOWN_PERMS},
        # Backward-compatible duplicates at top-level
        **{p: clean_lists[p] for p in _KNOWN_PERMS},
    }

    os.makedirs(os.path.dirname(_PATH), exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, _PATH)

    return {p: set(clean_lists[p]) for p in _KNOWN_PERMS}


def is_allowed(user_id: Any, perm: str) -> bool:
    """Return True if user_id is in the allowlist for perm."""
    try:
        uid = int(user_id)
    except Exception:
        return False
    p = str(perm or "").strip()
    if p not in _KNOWN_PERMS:
        return False
    allowlists = load_allowlists()
    return uid in allowlists.get(p, set())


def set_allowed(user_id: Any, perm: str, allowed: bool) -> Dict[str, Set[int]]:
    """Add/remove user_id from a permission allowlist and persist to disk."""
    try:
        uid = int(user_id)
    except Exception:
        return load_allowlists()
    p = str(perm or "").strip()
    if p not in _KNOWN_PERMS:
        return load_allowlists()

    allowlists = load_allowlists()
    s = set(allowlists.get(p, set()))
    if bool(allowed):
        s.add(uid)
    else:
        s.discard(uid)
    allowlists[p] = s

    return save_allowlists({k: sorted(list(v)) for k, v in allowlists.items()})


def get_user_permissions(user_id: Any) -> Dict[str, bool]:
    """Return all known permissions as booleans for this user_id."""
    try:
        uid = int(user_id)
    except Exception:
        return {p: False for p in _KNOWN_PERMS}
    allowlists = load_allowlists()
    return {p: (uid in allowlists.get(p, set())) for p in _KNOWN_PERMS}

