"""utils/phase3_init.py

Phase 3: Monitoring & Compliance initializers.

Keep this module small and resilient: if a Phase 3 component fails to init,
we log and continue so existing app functionality is not broken.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def init_phase3(app) -> None:
    # Feature 1: SIEM
    try:
        from utils.siem import init_siem

        siem_client = init_siem(app)
        # Allow runtime toggle without requiring restart.
        try:
            if app.config.get("SIEM_ENABLED") is False:
                siem_client.disable()
            else:
                siem_client.enable()
        except Exception:
            pass
        app.logger.info("Phase 3 SIEM initialized successfully")
    except Exception as e:
        app.logger.exception("Phase 3 SIEM initialization failed: %s", e)

    # Feature 2: User Behavior Analytics (UBA)
    try:
        from utils.siem import get_siem
        from utils.user_behavior_analytics import UserBehaviorAnalytics, alerts_to_siem_events

        client = get_siem()
        if client is not None:
            uba = UserBehaviorAnalytics(
                rate_threshold_per_minute=int(app.config.get("UBA_RATE_THRESHOLD_PER_MINUTE", 120)),
                window_seconds=int(app.config.get("UBA_WINDOW_SECONDS", 60)),
                min_baseline_events=int(app.config.get("UBA_MIN_BASELINE_EVENTS", 3)),
            )

            class _UBASiemListener:
                def on_event(self, ev: dict):
                    try:
                        if app.config.get("UBA_ENABLED") is False:
                            return None
                    except Exception:
                        pass
                    # Avoid loops handled in UBA, but keep this cheap.
                    alerts = uba.ingest(ev)
                    return alerts_to_siem_events(alerts)

            client.register_listener(_UBASiemListener())
            app.logger.info("Phase 3 UBA initialized successfully")
    except Exception as e:
        app.logger.exception("Phase 3 UBA initialization failed: %s", e)

    # Feature 3: Automated Compliance Checking
    try:
        if app.config.get("COMPLIANCE_ENABLED") is False:
            try:
                app.logger.info("Phase 3 compliance check disabled")
            except Exception:
                pass
        else:
            from utils.compliance_checker import ComplianceChecker, emit_findings_to_siem, log_findings_to_audit

            checker = ComplianceChecker()
            findings = checker.run(app=app)

            # Emit to SIEM (if initialized) and audit (non-PHI, no secrets)
            emit_findings_to_siem(findings)
            log_findings_to_audit(findings, user_id=None)

            app.logger.info("Phase 3 compliance check executed (%s findings)", len(findings))
    except Exception as e:
        app.logger.exception("Phase 3 compliance checking failed: %s", e)

    # Feature 4: Data Loss Prevention (DLP)
    try:
        from utils.dlp import init_dlp

        init_dlp(app)
        app.logger.info("Phase 3 DLP initialized successfully")
    except Exception as e:
        app.logger.exception("Phase 3 DLP initialization failed: %s", e)

    # Feature 5: Incident Response Automation
    try:
        from utils.incident_response import init_incident_response

        # Allow auto-block on correlation alerts by default.
        if "IR_AUTO_BLOCK_IP" not in app.config:
            app.config["IR_AUTO_BLOCK_IP"] = True

        init_incident_response(app)
        app.logger.info("Phase 3 Incident Response initialized successfully")
    except Exception as e:
        app.logger.exception("Phase 3 Incident Response initialization failed: %s", e)
