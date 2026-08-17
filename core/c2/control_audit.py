"""Control plane audit trail and secret redaction (§14.9)."""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from threading import RLock
from typing import Any

SENSITIVE_PATTERNS = [
    re.compile(
        r"(?i)(api[-_]?key|secret[-_]?key|password|token|ticket|hash)\s*[:=]\s*['\"]?([A-Za-z0-9+/=._-]+)['\"]?"
    ),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._-]+)"),
]

FORBIDDEN_FIELDS = {
    "api_key",
    "secret_key",
    "private_key",
    "password",
    "token",
    "enrollment_token",
    "raw_command",
    "raw_output",
    "hash",
    "ticket",
    "canary",
}


@dataclass(frozen=True)
class ControlAuditEventV1:
    event_id: str
    timestamp: float
    operator_id: str
    subject_id: str
    peer_pid: int
    peer_uid: int
    peer_gid: int
    mission_id: str
    action: str
    request_id: str
    request_digest: str
    result_code: str
    duration_ms: float
    is_replay: bool


ControlAuditEventV2 = ControlAuditEventV1


def redact_sensitive_text(text: str) -> str:
    """Redact sensitive keys/tokens from plain text strings."""
    redacted = text
    for pat in SENSITIVE_PATTERNS:
        redacted = pat.sub(r"\1: [REDACTED]", redacted)
    return redacted


def redact_sensitive_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow/deep copy with forbidden secret fields replaced with [REDACTED]."""
    clean: dict[str, Any] = {}
    for k, v in data.items():
        k_lower = k.lower()
        if any(f in k_lower for f in FORBIDDEN_FIELDS):
            clean[k] = "[REDACTED]"
        elif isinstance(v, dict):
            clean[k] = redact_sensitive_dict(v)
        elif isinstance(v, str):
            clean[k] = redact_sensitive_text(v)
        else:
            clean[k] = v
    return clean


class ControlAuditLoggerV1:
    """Thread-safe append-only audit logger for C2 control events."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._events: list[ControlAuditEventV1] = []

    def record_event(
        self,
        *,
        operator_id: str,
        subject_id: str,
        peer_pid: int,
        peer_uid: int,
        peer_gid: int,
        mission_id: str,
        action: str,
        request_id: str,
        request_digest: str,
        result_code: str,
        duration_ms: float,
        is_replay: bool = False,
        now: float | None = None,
    ) -> ControlAuditEventV1:
        ts = time.time() if now is None else now
        ev = ControlAuditEventV1(
            event_id=f"audit-{uuid.uuid4().hex[:12]}",
            timestamp=ts,
            operator_id=operator_id,
            subject_id=subject_id,
            peer_pid=peer_pid,
            peer_uid=peer_uid,
            peer_gid=peer_gid,
            mission_id=mission_id,
            action=action,
            request_id=request_id,
            request_digest=request_digest,
            result_code=result_code,
            duration_ms=duration_ms,
            is_replay=is_replay,
        )
        with self._lock:
            self._events.append(ev)
        return ev

    def list_events(
        self,
        *,
        mission_id: str | None = None,
        operator_id: str | None = None,
        limit: int = 100,
    ) -> Sequence[ControlAuditEventV1]:
        with self._lock:
            events = self._events
            if mission_id is not None:
                events = [e for e in events if e.mission_id == mission_id]
            if operator_id is not None:
                events = [e for e in events if e.operator_id == operator_id]
            return list(events[-limit:])


ControlAuditLoggerV2 = ControlAuditLoggerV1

__all__ = [
    "FORBIDDEN_FIELDS",
    "SENSITIVE_PATTERNS",
    "ControlAuditEventV1",
    "ControlAuditEventV2",
    "ControlAuditLoggerV1",
    "ControlAuditLoggerV2",
    "redact_sensitive_dict",
    "redact_sensitive_text",
]
