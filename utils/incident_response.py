"""utils/incident_response.py

Phase 3 Feature 5: Incident Response Automation

Minimal automation driven by SIEM telemetry:
- React to correlation alerts (bruteforce, repeated WAF blocks, repeated DLP blocks)
- Optionally auto-block source IP via WAF blocklist
- Emit SIEM INCIDENT_RESPONSE events for traceability
- Log audit SECURITY_ALERT events (summary only)

Safe-by-default:
- Never inspects request/response bodies (no PHI)
- Never breaks runtime (all actions wrapped)
- Skips self-generated incident response events to prevent loops
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class IRAction:
    action: str  # block_ip|notify
    reason: str
    ip: Optional[str] = None
    user_id: Optional[int] = None
    meta: Optional[Dict[str, Any]] = None


def _emit_ir_event(action: IRAction) -> None:
    try:
        from utils.siem import get_siem, SIEMEventType, SIEMSeverity

        client = get_siem()
        if client is None:
            return

        sev = SIEMSeverity.HIGH if action.action == "block_ip" else SIEMSeverity.WARNING
        client.emit_simple(
            event_type=SIEMEventType.INCIDENT_RESPONSE,
            severity=sev,
            source="incident_response",
            message=f"IR {action.action}: {action.reason}",
            user_id=action.user_id,
            ip=action.ip,
            meta={
                "action": action.action,
                "reason": action.reason,
                **(action.meta or {}),
            },
            tags=["incident_response"],
        )
    except Exception:
        return


def _log_audit(action: IRAction) -> None:
    try:
        from utils.comprehensive_audit import comprehensive_audit, AuditEventType, AuditSeverity

        comprehensive_audit.log_event(
            event_type=AuditEventType.SECURITY_ALERT,
            user_id=action.user_id,
            action=f"Incident response: {action.action}",
            severity=AuditSeverity.HIGH,
            metadata={
                "reason": action.reason,
                "ip": action.ip,
                **(action.meta or {}),
            },
        )
    except Exception:
        return


def _block_ip(ip: str, reason: str) -> bool:
    try:
        from utils.custom_waf import waf

        waf.blocklist.block_ip(ip, reason=reason)
        return True
    except Exception:
        return False


class IncidentResponseListener:
    def __init__(self, app=None):
        self._app = app

    def on_event(self, ev: Dict[str, Any]):
        try:
            if not isinstance(ev, dict):
                return None

            if ev.get("source") == "incident_response":
                return None

            if self._app is not None and self._app.config.get("INCIDENT_RESPONSE_ENABLED") is False:
                return None

            event_type = ev.get("event_type")
            severity = (ev.get("severity") or "").upper()
            ip = ev.get("ip")
            user_id = ev.get("user_id")
            meta = ev.get("meta") or {}

            # React primarily to correlation alerts.
            if event_type == "CORRELATION_ALERT":
                reason = ev.get("message") or "Correlation alert"
                auto_block = True
                if self._app is not None and self._app.config.get("IR_AUTO_BLOCK_IP") is False:
                    auto_block = False

                if ip and auto_block and severity in ("HIGH", "CRITICAL"):
                    blocked = _block_ip(str(ip), reason=str(reason)[:240])
                    action = IRAction(
                        action="block_ip" if blocked else "notify",
                        reason=str(reason)[:240],
                        ip=str(ip),
                        user_id=user_id if isinstance(user_id, int) else None,
                        meta={"trigger": "correlation", "blocked": blocked},
                    )
                    _emit_ir_event(action)
                    _log_audit(action)
                else:
                    action = IRAction(
                        action="notify",
                        reason=str(reason)[:240],
                        ip=str(ip) if ip else None,
                        user_id=user_id if isinstance(user_id, int) else None,
                        meta={"trigger": "correlation"},
                    )
                    _emit_ir_event(action)
                    _log_audit(action)

            # React to DLP blocks (if enabled later).
            if event_type == "DLP" and meta.get("action") == "block":
                reason = ev.get("message") or "DLP block"
                action = IRAction(
                    action="notify",
                    reason=str(reason)[:240],
                    ip=str(ip) if ip else None,
                    user_id=user_id if isinstance(user_id, int) else None,
                    meta={"trigger": "dlp"},
                )
                _emit_ir_event(action)
                _log_audit(action)

            return None
        except Exception:
            return None


def init_incident_response(app=None) -> None:
    """Register incident response listener with SIEM if available."""

    try:
        from utils.siem import get_siem

        client = get_siem()
        if client is None:
            return

        client.register_listener(IncidentResponseListener(app=app))
    except Exception:
        return
