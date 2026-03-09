"""utils/compliance_checker.py

Phase 3 Feature 3: Automated Compliance Checking

Goal:
- Perform lightweight, non-invasive compliance posture checks
- Emit findings to SIEM as COMPLIANCE events (no secrets/PHI)
- Optionally log a CONFIG_CHANGED audit event for traceability

Constraints:
- Dependency-free (stdlib only)
- Must never break app runtime (caller should wrap in try/except)
- Must never log secret values (only presence/booleans)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


@dataclass(frozen=True)
class ComplianceFinding:
    ts: str
    severity: str  # INFO|WARNING|HIGH|CRITICAL
    check_id: str
    message: str
    meta: Optional[Dict[str, Any]] = None


class ComplianceChecker:
    """Run automated compliance posture checks.

    This is intentionally conservative and environment-aware: in dev, it will
    warn on settings that should be locked down in production, but it will not
    fail the app.
    """

    def __init__(self):
        pass

    def run(self, app=None, config: Optional[Dict[str, Any]] = None) -> List[ComplianceFinding]:
        cfg = config
        if cfg is None and app is not None:
            cfg = getattr(app, "config", None)
        if not isinstance(cfg, dict):
            cfg = {}

        findings: List[ComplianceFinding] = []

        # --- Secrets & cryptography keys (presence only; never values) ---
        findings.extend(self._check_required_secrets(cfg))

        # --- Transport / cookie security flags ---
        findings.extend(self._check_cookie_security(cfg))

        # --- Database transport security hints ---
        findings.extend(self._check_database_url(cfg))

        # --- Backup posture hints ---
        findings.extend(self._check_backups(cfg))

        return findings

    def _add(self, findings: List[ComplianceFinding], severity: str, check_id: str, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        findings.append(
            ComplianceFinding(
                ts=_utc_now_iso(),
                severity=severity,
                check_id=check_id,
                message=message,
                meta=meta,
            )
        )

    def _check_required_secrets(self, cfg: Dict[str, Any]) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []

        required = [
            ("SECRET_KEY", "Flask SECRET_KEY configured"),
            ("SECURITY_PASSWORD_SALT", "SECURITY_PASSWORD_SALT configured"),
            ("FERNET_KEY", "FERNET_KEY configured"),
        ]

        for key, label in required:
            present = bool(cfg.get(key))
            if not present:
                self._add(findings, "CRITICAL", f"secret.{key}.missing", f"Missing required secret: {key}")
            else:
                self._add(findings, "INFO", f"secret.{key}.present", label, meta={"present": True})

        # Optional but recommended keys used elsewhere
        recommended = [
            ("MESSAGE_ENCRYPTION_KEY", "MESSAGE_ENCRYPTION_KEY configured"),
            ("BACKUP_ENCRYPTION_KEY", "BACKUP_ENCRYPTION_KEY configured"),
        ]
        for key, label in recommended:
            present = bool(cfg.get(key))
            if not present:
                self._add(findings, "WARNING", f"secret.{key}.missing", f"Recommended secret not set: {key}")
            else:
                self._add(findings, "INFO", f"secret.{key}.present", label, meta={"present": True})

        return findings

    def _check_cookie_security(self, cfg: Dict[str, Any]) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []

        # Many Flask apps set these in config; if absent we warn (not critical).
        secure = _boolish(cfg.get("SESSION_COOKIE_SECURE"))
        httponly = _boolish(cfg.get("SESSION_COOKIE_HTTPONLY"))
        samesite = cfg.get("SESSION_COOKIE_SAMESITE")

        if secure is False:
            self._add(
                findings,
                "WARNING",
                "cookie.secure.disabled",
                "SESSION_COOKIE_SECURE is disabled (enable for production HTTPS)",
                meta={"SESSION_COOKIE_SECURE": False},
            )
        elif secure is True:
            self._add(findings, "INFO", "cookie.secure.enabled", "SESSION_COOKIE_SECURE enabled", meta={"SESSION_COOKIE_SECURE": True})
        else:
            self._add(findings, "WARNING", "cookie.secure.unset", "SESSION_COOKIE_SECURE not set (recommended True in production)")

        if httponly is False:
            self._add(findings, "HIGH", "cookie.httponly.disabled", "SESSION_COOKIE_HTTPONLY is disabled", meta={"SESSION_COOKIE_HTTPONLY": False})
        elif httponly is True:
            self._add(findings, "INFO", "cookie.httponly.enabled", "SESSION_COOKIE_HTTPONLY enabled", meta={"SESSION_COOKIE_HTTPONLY": True})
        else:
            self._add(findings, "WARNING", "cookie.httponly.unset", "SESSION_COOKIE_HTTPONLY not set (recommended True)")

        if samesite is None:
            self._add(findings, "WARNING", "cookie.samesite.unset", "SESSION_COOKIE_SAMESITE not set (recommended 'Lax' or 'Strict')")
        else:
            self._add(findings, "INFO", "cookie.samesite.set", f"SESSION_COOKIE_SAMESITE set to {str(samesite)}")

        return findings

    def _check_database_url(self, cfg: Dict[str, Any]) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []
        url = cfg.get("DATABASE_URL")
        if not url:
            self._add(findings, "WARNING", "db.url.missing", "DATABASE_URL not set")
            return findings

        # Presence checks only; do not parse/print credentials.
        url_s = str(url)
        # Encourage TLS for Postgres
        if url_s.startswith("postgresql://") or url_s.startswith("postgres://"):
            if "sslmode=require" not in url_s.lower():
                self._add(findings, "HIGH", "db.sslmode.missing", "PostgreSQL DATABASE_URL missing sslmode=require")
            else:
                self._add(findings, "INFO", "db.sslmode.present", "PostgreSQL sslmode=require present")

            if "channel_binding=require" not in url_s.lower():
                self._add(findings, "WARNING", "db.channel_binding.missing", "PostgreSQL DATABASE_URL missing channel_binding=require (recommended where supported)")
            else:
                self._add(findings, "INFO", "db.channel_binding.present", "PostgreSQL channel_binding=require present")

        return findings

    def _check_backups(self, cfg: Dict[str, Any]) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []

        bucket = cfg.get("AWS_BACKUP_BUCKET")
        key = cfg.get("AWS_ACCESS_KEY_ID")
        secret = cfg.get("AWS_SECRET_ACCESS_KEY")

        if bucket and key and secret:
            self._add(findings, "INFO", "backup.s3.configured", "S3 backup credentials/bucket configured", meta={"s3_configured": True})
        else:
            self._add(findings, "WARNING", "backup.s3.not_configured", "S3 backups not fully configured (local backups only)", meta={"s3_configured": False})

        return findings


def emit_findings_to_siem(findings: Iterable[ComplianceFinding], siem_client=None) -> None:
    """Emit findings as SIEM COMPLIANCE events.

    If siem_client is None, this will attempt to use utils.siem.get_siem().
    """

    try:
        from utils.siem import SIEMEventType, SIEMSeverity, get_siem

        client = siem_client or get_siem()
        if client is None:
            return

        sev_map = {
            "INFO": SIEMSeverity.INFO,
            "WARNING": SIEMSeverity.WARNING,
            "HIGH": SIEMSeverity.HIGH,
            "CRITICAL": SIEMSeverity.CRITICAL,
        }

        for f in list(findings or []):
            sev = sev_map.get(f.severity, SIEMSeverity.WARNING)
            client.emit_simple(
                event_type=SIEMEventType.COMPLIANCE,
                severity=sev,
                source="compliance",
                message=f"{f.check_id}: {f.message}",
                meta={
                    "check_id": f.check_id,
                    "severity": f.severity,
                    **(f.meta or {}),
                },
                tags=["compliance"],
            )
    except Exception:
        return


def log_findings_to_audit(findings: Iterable[ComplianceFinding], user_id: Optional[int] = None) -> None:
    """Log a summarized compliance result into the comprehensive audit log."""

    try:
        from utils.comprehensive_audit import comprehensive_audit, AuditEventType, AuditSeverity

        f_list = list(findings or [])
        highest = "INFO"
        rank = {"INFO": 0, "WARNING": 1, "HIGH": 2, "CRITICAL": 3}
        for f in f_list:
            if rank.get(f.severity, 1) > rank.get(highest, 0):
                highest = f.severity

        sev_map = {
            "INFO": AuditSeverity.INFO,
            "WARNING": AuditSeverity.MEDIUM,
            "HIGH": AuditSeverity.HIGH,
            "CRITICAL": AuditSeverity.CRITICAL,
        }

        metadata = {
            "finding_count": len(f_list),
            "highest_severity": highest,
            "finding_ids": [f.check_id for f in f_list[:50]],
        }

        comprehensive_audit.log_event(
            event_type=AuditEventType.CONFIG_CHANGED,
            user_id=user_id,
            action="Automated compliance check executed",
            severity=sev_map.get(highest, AuditSeverity.MEDIUM),
            metadata=metadata,
        )
    except Exception:
        return
