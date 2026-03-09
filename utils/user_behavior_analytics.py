"""utils/user_behavior_analytics.py

Phase 3 Feature 2: User Behavior Analytics (UBA)

Purpose:
- Consume SIEM events and build lightweight per-user behavioral baselines
- Generate monitoring alerts for anomalies (e.g., new IP, new endpoint, request-rate spikes)
- Convert UBA alerts into SIEM THREAT events (source='uba')

Design constraints:
- Dependency-free (stdlib only)
- Must not log PHI (avoid request bodies / nested meta)
- Must not break runtime: errors are swallowed by callers
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterable, List, Optional
from collections import deque


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_str(value: Any, max_len: int = 256) -> str:
    if value is None:
        return ""
    text = str(value)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _parse_ts(ts: Optional[str]) -> float:
    if not ts:
        return 0.0
    try:
        # Handles ISO8601 (including tz) produced by utils.siem.utc_now_iso
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


@dataclass(frozen=True)
class UBAAlert:
    ts: str
    severity: str
    alert_type: str
    message: str
    user_id: Optional[int] = None
    ip: Optional[str] = None
    endpoint: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


class _UserState:
    __slots__ = (
        "events_seen",
        "known_ips",
        "known_endpoints",
        "request_times",
        "auth_fail_times",
    )

    def __init__(self):
        self.events_seen: int = 0
        self.known_ips: set[str] = set()
        self.known_endpoints: set[str] = set()
        self.request_times: Deque[float] = deque(maxlen=2000)
        self.auth_fail_times: Deque[float] = deque(maxlen=500)


class UserBehaviorAnalytics:
    """Lightweight, in-memory user behavior analytics.

    This complements (does not replace) Phase 2 AI threat detection by operating on
    SIEM telemetry and emitting monitoring alerts.
    """

    def __init__(
        self,
        rate_threshold_per_minute: int = 120,
        window_seconds: int = 60,
        min_baseline_events: int = 3,
        auth_fail_threshold: int = 5,
    ):
        self.rate_threshold_per_minute = int(rate_threshold_per_minute)
        self.window_seconds = int(window_seconds)
        self.min_baseline_events = int(min_baseline_events)
        self.auth_fail_threshold = int(auth_fail_threshold)

        self._users: Dict[int, _UserState] = {}

    def _state(self, user_id: int) -> _UserState:
        st = self._users.get(user_id)
        if st is None:
            st = _UserState()
            self._users[user_id] = st
        return st

    def ingest(self, event: Dict[str, Any]) -> List[UBAAlert]:
        """Ingest one SIEM event (dict) and return any UBA alerts."""

        if not isinstance(event, dict):
            return []

        # Avoid loops (UBA-generated SIEM events)
        if event.get("source") == "uba":
            return []

        event_type = event.get("event_type")
        user_id = event.get("user_id")
        if user_id is None:
            return []

        try:
            user_id_int = int(user_id)
        except Exception:
            return []

        ip = event.get("ip")
        endpoint = event.get("endpoint")
        ts = event.get("ts")
        t = _parse_ts(ts) or datetime.now(timezone.utc).timestamp()

        st = self._state(user_id_int)
        st.events_seen += 1

        alerts: List[UBAAlert] = []

        # Learn first, then alert once baseline exists.
        has_baseline = st.events_seen >= self.min_baseline_events

        if ip:
            ip_s = _as_str(ip, 64)
            if has_baseline and ip_s not in st.known_ips:
                alerts.append(
                    UBAAlert(
                        ts=_utc_now_iso(),
                        severity="WARNING",
                        alert_type="NEW_IP",
                        message=f"New IP for user {user_id_int}: {ip_s}",
                        user_id=user_id_int,
                        ip=ip_s,
                        endpoint=_as_str(endpoint, 256) if endpoint else None,
                        meta={"baseline_events": st.events_seen, "window_seconds": self.window_seconds},
                    )
                )
            st.known_ips.add(ip_s)

        if endpoint:
            ep_s = _as_str(endpoint, 256)
            if has_baseline and ep_s not in st.known_endpoints:
                # Endpoint changes are common; keep at WARNING and tag it.
                alerts.append(
                    UBAAlert(
                        ts=_utc_now_iso(),
                        severity="WARNING",
                        alert_type="NEW_ENDPOINT",
                        message=f"New endpoint for user {user_id_int}: {ep_s}",
                        user_id=user_id_int,
                        ip=_as_str(ip, 64) if ip else None,
                        endpoint=ep_s,
                        meta={"baseline_events": st.events_seen, "window_seconds": self.window_seconds},
                    )
                )
            st.known_endpoints.add(ep_s)

        if event_type == "REQUEST":
            st.request_times.append(t)
            self._evict_old(st.request_times, t)
            if has_baseline:
                rate = len(st.request_times)
                if rate >= self.rate_threshold_per_minute:
                    alerts.append(
                        UBAAlert(
                            ts=_utc_now_iso(),
                            severity="HIGH",
                            alert_type="HIGH_REQUEST_RATE",
                            message=f"High request rate for user {user_id_int}: {rate} in {self.window_seconds}s",
                            user_id=user_id_int,
                            ip=_as_str(ip, 64) if ip else None,
                            endpoint=_as_str(endpoint, 256) if endpoint else None,
                            meta={"count": rate, "window_seconds": self.window_seconds},
                        )
                    )

        if event_type == "AUTH":
            meta = event.get("meta") or {}
            success = None
            try:
                success = meta.get("success")
            except Exception:
                success = None
            if success is False:
                st.auth_fail_times.append(t)
                self._evict_old(st.auth_fail_times, t)
                if has_baseline and len(st.auth_fail_times) >= self.auth_fail_threshold:
                    alerts.append(
                        UBAAlert(
                            ts=_utc_now_iso(),
                            severity="HIGH",
                            alert_type="AUTH_FAILURE_SPIKE",
                            message=f"Auth failure spike for user {user_id_int}: {len(st.auth_fail_times)} in {self.window_seconds}s",
                            user_id=user_id_int,
                            ip=_as_str(ip, 64) if ip else None,
                            endpoint=_as_str(endpoint, 256) if endpoint else None,
                            meta={"count": len(st.auth_fail_times), "window_seconds": self.window_seconds},
                        )
                    )

        return alerts

    def _evict_old(self, times: Deque[float], now: float) -> None:
        threshold = now - self.window_seconds
        while times and times[0] < threshold:
            times.popleft()


def alerts_to_siem_events(alerts: Iterable[UBAAlert]) -> List[dict]:
    """Convert UBA alerts into dicts compatible with utils.siem.SIEMEvent fields.

    Returned dicts can be passed to SIEM emission helpers.
    """

    out: List[dict] = []

    for a in alerts or []:
        sev = a.severity
        if sev not in ("INFO", "WARNING", "HIGH", "CRITICAL"):
            sev = "WARNING"

        meta = dict(a.meta or {})
        meta.update({"uba_alert_type": a.alert_type})

        out.append(
            {
                "ts": a.ts,
                "event_type": "THREAT",
                "severity": sev,
                "source": "uba",
                "message": _as_str(a.message, 512),
                "user_id": a.user_id,
                "ip": a.ip,
                "endpoint": a.endpoint,
                "tags": ["uba", a.alert_type.lower()],
                "meta": meta,
            }
        )

    return out
