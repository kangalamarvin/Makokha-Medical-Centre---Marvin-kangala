"""utils/siem.py

Phase 3 Feature 1: Security Information and Event Management (SIEM)

Goals:
- Provide a local SIEM event pipeline that is safe-by-default (no PHI logging)
- Support structured event ingestion (JSON)
- Persist events to instance storage with lightweight rotation
- Provide basic correlation rules (brute force, repeated WAF blocks, DLP violations)
- Integrate with Flask request lifecycle (optional)

This module is designed to be dependency-free (stdlib only) and not break
existing functionality if it cannot initialize (fails closed to logging only).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from collections import deque
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class SIEMSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SIEMEventType(str, Enum):
    REQUEST = "REQUEST"
    AUTH = "AUTH"
    WAF_BLOCK = "WAF_BLOCK"
    THREAT = "THREAT"
    DLP = "DLP"
    DB_ACTIVITY = "DB_ACTIVITY"
    COMPLIANCE = "COMPLIANCE"
    AUDIT = "AUDIT"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    CORRELATION_ALERT = "CORRELATION_ALERT"


@dataclass(frozen=True)
class SIEMEvent:
    ts: str
    event_type: str
    severity: str
    source: str
    message: str
    user_id: Optional[int] = None
    ip: Optional[str] = None
    endpoint: Optional[str] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    tags: Optional[List[str]] = None
    meta: Optional[Dict[str, Any]] = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_str(value: Any, max_len: int = 512) -> str:
    if value is None:
        return ""
    text = str(value)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _redact_meta(meta: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not meta:
        return meta
    redacted: Dict[str, Any] = {}
    for key, value in meta.items():
        key_l = str(key).lower()
        if any(s in key_l for s in ("password", "token", "secret", "authorization", "cookie", "csrf")):
            redacted[key] = "<redacted>"
            continue
        if isinstance(value, (dict, list)):
            # Avoid logging nested structures that may contain PHI
            redacted[key] = "<redacted>"
            continue
        # Preserve primitive types for analytics/correlation.
        if value is None or isinstance(value, (bool, int, float)):
            redacted[key] = value
        else:
            redacted[key] = _safe_str(value)
    return redacted


class SIEMStorage:
    """Append-only JSONL storage with daily rotation in instance/siem."""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)
        self._lock = threading.Lock()

    def _path_for_day(self, day: str) -> str:
        return os.path.join(self.base_dir, f"events-{day}.jsonl")

    def append(self, event: SIEMEvent) -> None:
        day = event.ts[:10].replace("-", "")  # YYYYMMDD
        path = self._path_for_day(day)
        payload = asdict(event)
        payload["meta"] = _redact_meta(payload.get("meta"))
        line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def iter_events(
        self,
        days: Iterable[str],
        limit: int = 5000,
    ) -> Iterable[Dict[str, Any]]:
        count = 0
        for day in days:
            path = self._path_for_day(day)
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                        count += 1
                        if count >= limit:
                            return
                    except Exception:
                        continue


class CorrelationEngine:
    """Basic correlation rules over a sliding window."""

    def __init__(self, window_seconds: int = 600, max_events: int = 2000):
        self.window_seconds = window_seconds
        self.events: Deque[Tuple[float, SIEMEvent]] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def ingest(self, event: SIEMEvent) -> List[SIEMEvent]:
        now = time.time()
        alerts: List[SIEMEvent] = []
        with self._lock:
            self.events.append((now, event))
            self._evict(now)
            alerts.extend(self._rule_bruteforce(now))
            alerts.extend(self._rule_repeated_waf_blocks(now))
            alerts.extend(self._rule_repeated_dlp_blocks(now))
        return alerts

    def _evict(self, now: float) -> None:
        threshold = now - self.window_seconds
        while self.events and self.events[0][0] < threshold:
            self.events.popleft()

    def _count(self, predicate) -> int:
        return sum(1 for _, ev in self.events if predicate(ev))

    def _count_by_ip(self, event_type: str, ip: str) -> int:
        return self._count(lambda ev: ev.event_type == event_type and ev.ip == ip)

    def _rule_bruteforce(self, now: float) -> List[SIEMEvent]:
        # 5+ AUTH failures from same IP within window
        alerts: List[SIEMEvent] = []
        ips = {ev.ip for _, ev in self.events if ev.event_type == SIEMEventType.AUTH.value and ev.meta and ev.meta.get("success") is False and ev.ip}
        for ip in ips:
            count = self._count(lambda ev: ev.event_type == SIEMEventType.AUTH.value and ev.ip == ip and ev.meta and ev.meta.get("success") is False)
            if count >= 5:
                alerts.append(
                    SIEMEvent(
                        ts=utc_now_iso(),
                        event_type=SIEMEventType.CORRELATION_ALERT.value,
                        severity=SIEMSeverity.HIGH.value,
                        source="siem.correlation",
                        message=f"Possible brute-force detected from IP {ip} ({count} failed auth attempts)",
                        ip=ip,
                        tags=["bruteforce"],
                        meta={"failed_auth_count": count, "window_seconds": self.window_seconds},
                    )
                )
        return alerts

    def _rule_repeated_waf_blocks(self, now: float) -> List[SIEMEvent]:
        # 3+ WAF blocks from same IP
        alerts: List[SIEMEvent] = []
        ips = {ev.ip for _, ev in self.events if ev.event_type == SIEMEventType.WAF_BLOCK.value and ev.ip}
        for ip in ips:
            count = self._count_by_ip(SIEMEventType.WAF_BLOCK.value, ip)
            if count >= 3:
                alerts.append(
                    SIEMEvent(
                        ts=utc_now_iso(),
                        event_type=SIEMEventType.CORRELATION_ALERT.value,
                        severity=SIEMSeverity.HIGH.value,
                        source="siem.correlation",
                        message=f"Repeated WAF blocks from IP {ip} ({count} blocks)",
                        ip=ip,
                        tags=["web-attack"],
                        meta={"waf_block_count": count, "window_seconds": self.window_seconds},
                    )
                )
        return alerts

    def _rule_repeated_dlp_blocks(self, now: float) -> List[SIEMEvent]:
        # 2+ DLP blocks from same user or ip
        alerts: List[SIEMEvent] = []
        keys: List[Tuple[Optional[int], Optional[str]]] = []
        for _, ev in self.events:
            if ev.event_type != SIEMEventType.DLP.value:
                continue
            if not ev.meta or ev.meta.get("action") != "block":
                continue
            keys.append((ev.user_id, ev.ip))

        for user_id, ip in set(keys):
            count = self._count(
                lambda ev: ev.event_type == SIEMEventType.DLP.value
                and ev.meta
                and ev.meta.get("action") == "block"
                and ev.user_id == user_id
                and ev.ip == ip
            )
            if count >= 2:
                alerts.append(
                    SIEMEvent(
                        ts=utc_now_iso(),
                        event_type=SIEMEventType.CORRELATION_ALERT.value,
                        severity=SIEMSeverity.CRITICAL.value,
                        source="siem.correlation",
                        message=f"Repeated DLP blocks detected (count={count})",
                        user_id=user_id,
                        ip=ip,
                        tags=["dlp", "exfiltration"],
                        meta={"dlp_block_count": count, "window_seconds": self.window_seconds},
                    )
                )
        return alerts


class SIEMClient:
    """SIEM client that persists events and runs correlation rules."""

    def __init__(
        self,
        storage: SIEMStorage,
        correlation: Optional[CorrelationEngine] = None,
    ):
        self.storage = storage
        self.correlation = correlation or CorrelationEngine()
        self.enabled = True
        self._listeners: List[Any] = []
        self._listener_lock = threading.Lock()

    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False

    def register_listener(self, listener: Any) -> None:
        """Register an event listener.

        Listener should expose `on_event(event_dict) -> Optional[List[SIEMEvent|dict]]`.
        Any exception inside listeners is swallowed to avoid breaking runtime.
        """

        if listener is None:
            return
        with self._listener_lock:
            self._listeners.append(listener)

    def _dispatch_listeners(self, event: SIEMEvent) -> None:
        try:
            payload = asdict(event)
        except Exception:
            payload = {
                "ts": event.ts,
                "event_type": event.event_type,
                "severity": event.severity,
                "source": event.source,
                "message": event.message,
                "user_id": event.user_id,
                "ip": event.ip,
                "endpoint": event.endpoint,
                "request_id": event.request_id,
                "correlation_id": event.correlation_id,
                "tags": event.tags,
                "meta": event.meta,
            }

        with self._listener_lock:
            listeners = list(self._listeners)

        for listener in listeners:
            try:
                on_event = getattr(listener, "on_event", None)
                if not callable(on_event):
                    continue
                produced = on_event(payload)
                if not produced:
                    continue
                for item in produced:
                    ev = _coerce_event(item)
                    if ev is None:
                        continue
                    self._emit(ev, call_listeners=False)
            except Exception:
                continue

    def _emit(self, event: SIEMEvent, call_listeners: bool) -> None:
        if not self.enabled:
            return
        try:
            self.storage.append(event)
        except Exception as e:
            logger.exception("SIEM storage append failed: %s", e)

        try:
            alerts = self.correlation.ingest(event)
            for alert in alerts:
                try:
                    self.storage.append(alert)
                    if call_listeners:
                        try:
                            self._dispatch_listeners(alert)
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            # Correlation must never break runtime
            logger.exception("SIEM correlation failed")

        if call_listeners:
            try:
                self._dispatch_listeners(event)
            except Exception:
                # Listener dispatch must never break runtime
                pass

    def emit(self, event: SIEMEvent) -> None:
        self._emit(event, call_listeners=True)

    def emit_simple(
        self,
        event_type: SIEMEventType,
        severity: SIEMSeverity,
        source: str,
        message: str,
        user_id: Optional[int] = None,
        ip: Optional[str] = None,
        endpoint: Optional[str] = None,
        request_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        self.emit(
            SIEMEvent(
                ts=utc_now_iso(),
                event_type=event_type.value,
                severity=severity.value,
                source=_safe_str(source, 128),
                message=_safe_str(message, 512),
                user_id=user_id,
                ip=ip,
                endpoint=_safe_str(endpoint, 256) if endpoint else None,
                request_id=request_id,
                tags=tags,
                meta=_redact_meta(meta),
            )
        )


def _coerce_event(item: Any) -> Optional[SIEMEvent]:
    if item is None:
        return None
    if isinstance(item, SIEMEvent):
        return item
    if isinstance(item, dict):
        try:
            # Best-effort: require core fields; tolerate missing optionals.
            ts = item.get("ts") or utc_now_iso()
            event_type = item.get("event_type")
            severity = item.get("severity")
            source = item.get("source")
            message = item.get("message")
            if not (event_type and severity and source and message):
                return None
            return SIEMEvent(
                ts=_safe_str(ts, 64),
                event_type=_safe_str(event_type, 64),
                severity=_safe_str(severity, 16),
                source=_safe_str(source, 128),
                message=_safe_str(message, 512),
                user_id=item.get("user_id"),
                ip=item.get("ip"),
                endpoint=_safe_str(item.get("endpoint"), 256) if item.get("endpoint") else None,
                request_id=item.get("request_id"),
                correlation_id=item.get("correlation_id"),
                tags=item.get("tags"),
                meta=_redact_meta(item.get("meta")),
            )
        except Exception:
            return None
    return None


_siem_client: Optional[SIEMClient] = None


def get_siem() -> Optional[SIEMClient]:
    return _siem_client


def init_siem(app=None) -> SIEMClient:
    """Initialize SIEM and (optionally) hook into Flask lifecycle."""
    global _siem_client

    base_dir = os.path.join(os.getcwd(), "instance", "siem")
    storage = SIEMStorage(base_dir)
    _siem_client = SIEMClient(storage)
    try:
        if app is not None and app.config.get("SIEM_ENABLED") is False:
            _siem_client.disable()
    except Exception:
        pass

    if app is not None:
        try:
            _init_flask_hooks(app, _siem_client)
        except Exception:
            logger.exception("SIEM Flask hook initialization failed")

    logger.info("SIEM initialized")
    return _siem_client


def _init_flask_hooks(app, client: SIEMClient) -> None:
    from flask import g, request

    @app.before_request
    def _siem_before_request():
        g._siem_start = time.time()

    @app.after_request
    def _siem_after_request(response):
        try:
            if app.config.get("SIEM_ENABLED") is False:
                return response
            duration_ms = None
            if hasattr(g, "_siem_start"):
                duration_ms = int((time.time() - g._siem_start) * 1000)

            ip = request.headers.get("X-Forwarded-For") or request.remote_addr
            endpoint = request.path

            client.emit_simple(
                event_type=SIEMEventType.REQUEST,
                severity=SIEMSeverity.INFO,
                source="flask.request",
                message=f"{request.method} {endpoint} -> {response.status_code}",
                user_id=getattr(getattr(g, "user", None), "id", None),
                ip=_safe_str(ip, 64) if ip else None,
                endpoint=endpoint,
                meta={
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "content_length": response.calculate_content_length(),
                },
                tags=["http"],
            )
        except Exception:
            # Never break response
            pass
        return response


def emit_waf_block(ip: str, attack_type: str, details: str, endpoint: Optional[str] = None) -> None:
    client = get_siem()
    if not client:
        return
    client.emit_simple(
        event_type=SIEMEventType.WAF_BLOCK,
        severity=SIEMSeverity.HIGH,
        source="custom_waf",
        message=f"WAF blocked request ({attack_type})",
        ip=ip,
        endpoint=endpoint,
        meta={"attack_type": attack_type, "details": _safe_str(details, 256)},
        tags=["waf", attack_type],
    )


def emit_auth_event(user_id: Optional[int], ip: Optional[str], success: bool, meta: Optional[Dict[str, Any]] = None) -> None:
    client = get_siem()
    if not client:
        return
    client.emit_simple(
        event_type=SIEMEventType.AUTH,
        severity=SIEMSeverity.INFO if success else SIEMSeverity.WARNING,
        source="auth",
        message="Authentication success" if success else "Authentication failure",
        user_id=user_id,
        ip=ip,
        meta={"success": success, **(meta or {})},
        tags=["auth"],
    )
