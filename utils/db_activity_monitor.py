"""utils/db_activity_monitor.py

Enhanced Database Activity Monitoring

Goal:
- Capture database activity at the SQLAlchemy engine level (statement timing + operation)
- Emit lightweight, non-sensitive telemetry to SIEM
- Optionally log write operations to the Comprehensive Audit system

Safety/privacy:
- Never logs bound parameters/values
- Truncates statements and provides a hash for correlation
- Best-effort only; must never break runtime
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Optional


_WS_RE = re.compile(r"\s+")


def _compact_sql(stmt: str, limit: int = 280) -> str:
    s = _WS_RE.sub(" ", (stmt or "").strip())
    if len(s) > limit:
        return s[:limit] + "…"
    return s


def _sql_op(stmt: str) -> str:
    s = (stmt or "").lstrip()
    if not s:
        return "UNKNOWN"
    head = s.split(None, 1)[0].upper()
    # Normalize common verbs
    if head in ("SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "TRUNCATE"):
        return head
    return head[:32]


def _stmt_hash(stmt: str) -> str:
    return hashlib.sha256((stmt or "").encode("utf-8", errors="ignore")).hexdigest()


def init_db_activity_monitor(app: Any, engine: Any) -> None:
    """Attach SQLAlchemy engine listeners.

    This function is safe to call multiple times; duplicate registration is avoided
    by storing a marker on the engine.
    """

    try:
        if app is None or engine is None:
            return

        if getattr(engine, "_db_activity_monitor_enabled", False):
            return

        # Default enabled unless explicitly disabled.
        if app.config.get("DB_ACTIVITY_MONITORING_ENABLED") is False:
            return

        from sqlalchemy import event

        @event.listens_for(engine, "before_cursor_execute")
        def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):  # type: ignore[no-redef]
            try:
                try:
                    if app.config.get("DB_ACTIVITY_MONITORING_ENABLED") is False:
                        return
                except Exception:
                    pass
                # context is a SQLAlchemy ExecutionContext; attach timing only.
                setattr(context, "_dbam_start", time.time())
            except Exception:
                return

        @event.listens_for(engine, "after_cursor_execute")
        def _after_cursor_execute(conn, cursor, statement, parameters, context, executemany):  # type: ignore[no-redef]
            try:
                try:
                    if app.config.get("DB_ACTIVITY_MONITORING_ENABLED") is False:
                        return
                except Exception:
                    pass
                start = getattr(context, "_dbam_start", None)
                duration_ms: Optional[int] = None
                if isinstance(start, (int, float)):
                    duration_ms = int((time.time() - float(start)) * 1000)

                op = _sql_op(statement)
                compact = _compact_sql(statement)
                h = _stmt_hash(statement)

                # Emit to SIEM if enabled/initialized.
                try:
                    from utils.siem import get_siem, SIEMEventType, SIEMSeverity

                    client = get_siem()
                    if client is not None and app.config.get("SIEM_ENABLED") is not False:
                        sev = SIEMSeverity.INFO
                        if op in ("INSERT", "UPDATE", "DELETE", "ALTER", "DROP", "CREATE", "TRUNCATE"):
                            sev = SIEMSeverity.WARNING

                        client.emit_simple(
                            event_type=SIEMEventType.DB_ACTIVITY,
                            severity=sev,
                            source="db.activity",
                            message=f"DB {op} ({duration_ms}ms)" if duration_ms is not None else f"DB {op}",
                            ip=None,
                            endpoint=None,
                            meta={
                                "op": op,
                                "duration_ms": duration_ms,
                                "statement": compact,
                                "statement_hash": h,
                                "executemany": bool(executemany),
                                "rowcount": getattr(cursor, "rowcount", None),
                            },
                            tags=["db"],
                        )
                except Exception:
                    pass

                # Comprehensive audit: only log write-ish operations to avoid noise.
                try:
                    if op in ("INSERT", "UPDATE", "DELETE", "ALTER", "DROP", "CREATE", "TRUNCATE"):
                        from utils.comprehensive_audit import comprehensive_audit, AuditEventType, AuditSeverity

                        if app.config.get("COMPREHENSIVE_AUDIT_ENABLED") is not False:
                            comprehensive_audit.log_event(
                                event_type=AuditEventType.SECURITY_ALERT,
                                user_id=None,
                                action="db_activity",
                                severity=AuditSeverity.MEDIUM,
                                metadata={
                                    "op": op,
                                    "duration_ms": duration_ms,
                                    "statement": compact,
                                    "statement_hash": h,
                                },
                            )
                except Exception:
                    pass

            except Exception:
                return

        @event.listens_for(engine, "handle_error")
        def _handle_error(exception_context):  # type: ignore[no-redef]
            try:
                try:
                    if app.config.get("DB_ACTIVITY_MONITORING_ENABLED") is False:
                        return
                except Exception:
                    pass
                stmt = getattr(exception_context, "statement", None) or ""
                op = _sql_op(stmt)
                compact = _compact_sql(stmt)
                h = _stmt_hash(stmt)

                try:
                    from utils.siem import get_siem, SIEMEventType, SIEMSeverity

                    client = get_siem()
                    if client is not None and app.config.get("SIEM_ENABLED") is not False:
                        client.emit_simple(
                            event_type=SIEMEventType.DB_ACTIVITY,
                            severity=SIEMSeverity.HIGH,
                            source="db.activity",
                            message=f"DB error during {op}",
                            meta={
                                "op": op,
                                "statement": compact,
                                "statement_hash": h,
                                "error": str(getattr(exception_context, "original_exception", None) or "DB error")[:240],
                            },
                            tags=["db", "error"],
                        )
                except Exception:
                    pass

            except Exception:
                return

        setattr(engine, "_db_activity_monitor_enabled", True)
        try:
            app.logger.info("DB activity monitoring enabled")
        except Exception:
            pass

    except Exception:
        try:
            app.logger.exception("DB activity monitoring initialization failed")
        except Exception:
            pass
