"""utils/dlp.py

Phase 3 Feature 4: Data Loss Prevention (DLP)

Approach (minimal + non-breaking):
- Inspect response metadata (content-type, content-length, attachment headers, export-like endpoints)
- Emit SIEM DLP events for suspicious exfiltration patterns
- Optionally block responses if explicitly enabled via config

This module intentionally does NOT inspect response bodies to avoid PHI exposure
and to keep compatibility with streaming responses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class DLPDecision:
    action: str  # allow|monitor|block
    severity: str  # INFO|WARNING|HIGH|CRITICAL
    reason: str
    meta: Dict[str, Any]


def _boolish(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "y", "on"):
            return True
        if v in ("0", "false", "no", "n", "off"):
            return False
    return None


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def evaluate_response_meta(
    *,
    endpoint: str,
    method: str,
    status_code: int,
    content_type: Optional[str],
    content_length: Optional[int],
    content_disposition: Optional[str],
    block_enabled: bool,
    max_export_bytes: int,
) -> Optional[DLPDecision]:
    """Return a DLP decision for this response, or None if not suspicious."""

    # Only consider successful-ish responses for exfil detection
    if int(status_code) < 200 or int(status_code) >= 400:
        return None

    endpoint_l = (endpoint or "").lower()
    method_u = (method or "").upper()

    ct = (content_type or "").lower()
    cd = (content_disposition or "").lower()

    is_attachment = "attachment" in cd
    is_csv = "text/csv" in ct or endpoint_l.endswith(".csv")
    is_export_endpoint = any(tok in endpoint_l for tok in ("/export", "export", "/download", "download"))
    is_api = endpoint_l.startswith("/api/")

    size = _safe_int(content_length)
    if size is None:
        size = 0

    # Signals for potential exfil.
    signals = []
    if is_attachment:
        signals.append("attachment")
    if is_csv:
        signals.append("csv")
    if is_export_endpoint:
        signals.append("export_endpoint")

    if not signals:
        return None

    # Severity/decision based on size + export signals.
    if size >= int(max_export_bytes):
        severity = "CRITICAL" if is_attachment else "HIGH"
        action = "block" if block_enabled else "monitor"
        reason = f"Large export-like response ({size} bytes)"
    else:
        severity = "WARNING" if (is_attachment or is_csv) else "INFO"
        action = "monitor" if (is_attachment or is_export_endpoint or is_csv) else "allow"
        reason = "Export-like response detected"

    # Never block non-GET by default; treat as monitoring only.
    if action == "block" and method_u not in ("GET",):
        action = "monitor"
        severity = "HIGH"
        reason = "Export-like response on non-GET (monitor only)"

    # Conservative: only consider API exports higher risk.
    tags = []
    if is_api:
        tags.append("api")

    meta = {
        "action": action,
        "signals": signals,
        "endpoint": endpoint,
        "method": method_u,
        "status_code": int(status_code),
        "content_type": (content_type or "")[:128],
        "content_length": int(size),
        "content_disposition": (content_disposition or "")[:128],
        "tags": tags,
        "max_export_bytes": int(max_export_bytes),
    }

    return DLPDecision(action=action, severity=severity, reason=reason, meta=meta)


def emit_dlp_event(*, decision: DLPDecision, user_id: Optional[int], ip: Optional[str]) -> None:
    """Emit a DLP event to SIEM if available."""

    try:
        from utils.siem import get_siem, SIEMEventType, SIEMSeverity

        client = get_siem()
        if client is None:
            return

        sev_map = {
            "INFO": SIEMSeverity.INFO,
            "WARNING": SIEMSeverity.WARNING,
            "HIGH": SIEMSeverity.HIGH,
            "CRITICAL": SIEMSeverity.CRITICAL,
        }

        client.emit_simple(
            event_type=SIEMEventType.DLP,
            severity=sev_map.get(decision.severity, SIEMSeverity.WARNING),
            source="dlp",
            message=f"DLP {decision.action}: {decision.reason}",
            user_id=user_id,
            ip=ip,
            endpoint=str(decision.meta.get("endpoint") or "") or None,
            meta={
                "action": decision.action,
                "reason": decision.reason,
                "signals": decision.meta.get("signals"),
                "content_length": decision.meta.get("content_length"),
                "content_type": decision.meta.get("content_type"),
                "status_code": decision.meta.get("status_code"),
            },
            tags=["dlp"],
        )
    except Exception:
        return


def init_dlp(app) -> None:
    """Register DLP hooks into Flask. Safe-by-default (monitor only)."""

    try:
        from flask import g, jsonify, request

        @app.after_request
        def _dlp_after_request(response):
            try:
                enabled = _boolish(app.config.get("DLP_ENABLED", True))
                if enabled is False:
                    return response

                block_enabled = _boolish(app.config.get("DLP_BLOCK_ENABLED", False)) is True
                max_export_bytes = int(app.config.get("DLP_MAX_EXPORT_BYTES", 2 * 1024 * 1024))

                endpoint = request.path
                method = request.method
                status_code = getattr(response, "status_code", 200)

                # Best-effort content-length (avoid reading body)
                content_length = None
                try:
                    content_length = response.calculate_content_length()
                except Exception:
                    content_length = None

                content_type = response.headers.get("Content-Type")
                content_disposition = response.headers.get("Content-Disposition")

                decision = evaluate_response_meta(
                    endpoint=endpoint,
                    method=method,
                    status_code=int(status_code),
                    content_type=content_type,
                    content_length=_safe_int(content_length),
                    content_disposition=content_disposition,
                    block_enabled=block_enabled,
                    max_export_bytes=max_export_bytes,
                )

                if decision is None:
                    return response

                ip = request.headers.get("X-Forwarded-For") or request.remote_addr
                uid = getattr(getattr(g, "user", None), "id", None)

                emit_dlp_event(decision=decision, user_id=uid, ip=ip)

                if decision.action == "block" and block_enabled:
                    # Block export-like response; keep response minimal.
                    return jsonify({"error": "Data export blocked by DLP policy"}), 403

                return response
            except Exception:
                return response

    except Exception:
        # Never break app initialization
        return
