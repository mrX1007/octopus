"""Canonical, JSON-safe execution results and legacy-result adapters."""

from __future__ import annotations

import json
import math
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from typing import Any
from uuid import uuid4


class ExecutionStatus(str, Enum):
    """Normalized lifecycle status for every execution provider."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    CANCELLED = "cancelled"


_STATUS_ALIASES = {
    "success": ExecutionStatus.SUCCEEDED,
    "succeeded": ExecutionStatus.SUCCEEDED,
    "ok": ExecutionStatus.SUCCEEDED,
    "complete": ExecutionStatus.SUCCEEDED,
    "completed": ExecutionStatus.SUCCEEDED,
    "vulnerable": ExecutionStatus.SUCCEEDED,
    "not_vulnerable": ExecutionStatus.SUCCEEDED,
    "verified": ExecutionStatus.SUCCEEDED,
    "failed": ExecutionStatus.FAILED,
    "failure": ExecutionStatus.FAILED,
    "error": ExecutionStatus.FAILED,
    "timeout": ExecutionStatus.TIMEOUT,
    "timed_out": ExecutionStatus.TIMEOUT,
    "blocked": ExecutionStatus.BLOCKED,
    "denied": ExecutionStatus.BLOCKED,
    "skip": ExecutionStatus.BLOCKED,
    "skipped": ExecutionStatus.BLOCKED,
    "partial": ExecutionStatus.PARTIAL,
    "unavailable": ExecutionStatus.UNAVAILABLE,
    "missing": ExecutionStatus.UNAVAILABLE,
    "missing_dependency": ExecutionStatus.UNAVAILABLE,
    "tool_missing": ExecutionStatus.UNAVAILABLE,
    "cancelled": ExecutionStatus.CANCELLED,
    "canceled": ExecutionStatus.CANCELLED,
}

_CANONICAL_KEYS = {
    "artifact_refs",
    "artifacts",
    "duration",
    "duration_seconds",
    "error",
    "error_class",
    "error_message",
    "executed",
    "exit_code",
    "metadata",
    "output",
    "partial",
    "policy_decision_ref",
    "request_id",
    "schema_version",
    "status",
    "stderr",
    "stdout",
    "tool_name",
}

TextRedactor = Callable[..., str]
DataRedactor = Callable[..., Any]

MAX_ARTIFACT_REFS = 128
MAX_ARTIFACT_REF_BYTES = 4096
MAX_ARTIFACT_BYTES = 64 * 1024
MAX_METADATA_BYTES = 64 * 1024


def _new_id() -> str:
    return uuid4().hex


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _json_safe(value: Any, seen: set[int] | None = None) -> Any:
    """Convert arbitrary adapter metadata into strict JSON-compatible data."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Enum):
        return _json_safe(value.value, seen)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)

    seen = seen if seen is not None else set()
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            return "<recursive>"
        seen.add(identity)
        try:
            return {
                _as_text(key): _json_safe(item, seen)
                for key, item in value.items()
            }
        finally:
            seen.remove(identity)
    if isinstance(value, (list, tuple, set, frozenset)):
        identity = id(value)
        if identity in seen:
            return "<recursive>"
        seen.add(identity)
        try:
            items = value
            if isinstance(value, (set, frozenset)):
                items = sorted(value, key=repr)
            return [_json_safe(item, seen) for item in items]
        finally:
            seen.remove(identity)
    return str(value)


def _redact_text(redactor: TextRedactor | None, value: Any, *, kind: str) -> str:
    text = _as_text(value)
    if redactor is None:
        return text
    try:
        return _as_text(redactor(text, kind=kind))
    except TypeError:
        return _as_text(redactor(text))


def _redact_data(redactor: DataRedactor | None, value: Any) -> Any:
    safe = _json_safe(value)
    if redactor is None:
        return safe
    try:
        return _json_safe(redactor(safe, field="execution_metadata"))
    except TypeError:
        return _json_safe(redactor(safe))


def _redact_mapping_keys(value: Any, redactor: TextRedactor | None) -> Any:
    """Recursively redact mapping keys and retain colliding entries safely."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            original = _as_text(raw_key)
            safe_key = _redact_text(redactor, original, kind="execution_metadata_key")
            candidate = safe_key
            collision = 2
            while candidate in result:
                candidate = f"{safe_key}#{collision}"
                collision += 1
            result[candidate] = _redact_mapping_keys(item, redactor)
        return result
    if isinstance(value, list):
        return [_redact_mapping_keys(item, redactor) for item in value]
    return value


def _bounded_text(value: str, limit: int) -> tuple[str, bool]:
    raw = value.encode("utf-8", "replace")
    if len(raw) <= limit:
        return value, False
    return raw[:limit].decode("utf-8", "ignore"), True


def _bounded_outputs(stdout: str, stderr: str, limit: int) -> tuple[str, str, bool]:
    limit = max(0, int(limit))
    stdout_bytes = stdout.encode("utf-8", "replace")
    stderr_bytes = stderr.encode("utf-8", "replace")
    if len(stdout_bytes) + len(stderr_bytes) <= limit:
        return stdout, stderr, False

    if stdout_bytes and stderr_bytes:
        stderr_reserve = min(len(stderr_bytes), limit // 4)
    else:
        stderr_reserve = limit if stderr_bytes else 0
    stdout_value, stdout_truncated = _bounded_text(stdout, limit - stderr_reserve)
    remaining = max(0, limit - len(stdout_value.encode("utf-8", "replace")))
    stderr_value, stderr_truncated = _bounded_text(stderr, remaining)
    return stdout_value, stderr_value, stdout_truncated or stderr_truncated


def _bounded_json_string(value: str, limit: int) -> tuple[str, bool]:
    """Bound one string by its compact JSON representation, including quotes."""
    limit = max(0, int(limit))
    encoded = json.dumps(value, ensure_ascii=False).encode("utf-8")
    if len(encoded) <= limit:
        return value, False
    if limit < 2:
        return "", True

    raw = value.encode("utf-8", "replace")
    low = 0
    high = len(raw)
    best = ""
    while low <= high:
        midpoint = (low + high) // 2
        candidate = raw[:midpoint].decode("utf-8", "ignore")
        candidate_size = len(json.dumps(candidate, ensure_ascii=False).encode("utf-8"))
        if candidate_size <= limit:
            best = candidate
            low = midpoint + 1
        else:
            high = midpoint - 1
    return best, True


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_duration(value: Any, default: float) -> float:
    try:
        duration = float(value)
    except (TypeError, ValueError):
        duration = float(default)
    return duration if math.isfinite(duration) and duration >= 0 else max(0.0, float(default))


def _status_from_value(
    status: Any,
    *,
    success: Any,
    exit_code: int | None,
    error: str,
) -> ExecutionStatus:
    if isinstance(status, ExecutionStatus):
        return status
    normalized = _as_text(status).strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in _STATUS_ALIASES:
        return _STATUS_ALIASES[normalized]
    if exit_code not in (None, 0):
        return ExecutionStatus.FAILED
    if success is False or error:
        return ExecutionStatus.FAILED
    return ExecutionStatus.SUCCEEDED


def _legacy_marker_status(
    stdout: Any,
    stderr: Any,
    error: Any,
) -> tuple[ExecutionStatus | None, bool]:
    """Classify only explicit legacy failure markers, never fuzzy success."""
    output_present = bool(_as_text(stdout) or _as_text(stderr))
    text = "\n".join(part for part in (_as_text(stdout), _as_text(stderr), _as_text(error)) if part).lower()
    if any(marker in text for marker in ("[timeout]", "timed out", "killed after")):
        return ExecutionStatus.TIMEOUT, output_present
    if any(marker in text for marker in ("[partial output", "output limit reached", "output_limit")):
        return ExecutionStatus.PARTIAL, True
    if any(
        marker in text
        for marker in (
            "[!] tool not found",
            "tool not found:",
            "missing dependency",
            "no such file or directory",
        )
    ):
        return ExecutionStatus.UNAVAILABLE, False
    return None, False


def _artifact_values(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes, os.PathLike)):
        return (_as_text(value),)
    if isinstance(value, Sequence):
        return tuple(_as_text(item) for item in value)
    return (_as_text(value),)


def _bounded_artifact_refs(
    value: Any,
    redactor: TextRedactor | None,
) -> tuple[tuple[str, ...], bool, int]:
    raw_items = _artifact_values(value)
    safe_items: list[str] = []
    serialized_bytes = 2  # JSON list brackets
    truncated = len(raw_items) > MAX_ARTIFACT_REFS
    for item in raw_items[:MAX_ARTIFACT_REFS]:
        safe = _redact_text(redactor, item, kind="execution_artifact")
        safe, item_truncated = _bounded_text(safe, MAX_ARTIFACT_REF_BYTES)
        delimiter_bytes = 1 if safe_items else 0
        remaining = MAX_ARTIFACT_BYTES - serialized_bytes - delimiter_bytes
        if remaining < 2:
            truncated = True
            break
        safe, total_truncated = _bounded_json_string(safe, remaining)
        item_bytes = len(json.dumps(safe, ensure_ascii=False).encode("utf-8"))
        safe_items.append(safe)
        serialized_bytes += delimiter_bytes + item_bytes
        truncated = truncated or item_truncated or total_truncated
        if total_truncated:
            break
    return tuple(safe_items), truncated, len(raw_items)


def _bounded_metadata(value: Any) -> dict[str, Any]:
    safe = _json_safe(value)
    if not isinstance(safe, dict):
        safe = {"legacy_metadata": safe}
    encoded = json.dumps(safe, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) <= MAX_METADATA_BYTES:
        return safe

    retained = {
        key: safe[key]
        for key in (
            "artifact_ref_count",
            "artifact_refs_truncated",
            "legacy_result_type",
            "legacy_status",
            "output_truncated",
        )
        if key in safe
    }
    top_level_keys = []
    for key in list(safe)[:64]:
        bounded_key, _truncated = _bounded_text(str(key), 128)
        top_level_keys.append(bounded_key)
    return {
        **retained,
        "metadata_truncated": True,
        "metadata_original_bytes": len(encoded),
        "metadata_top_level_items": len(safe),
        "metadata_top_level_keys": top_level_keys,
    }


@dataclass
class ExecutionResult:
    """One canonical result crossing the PipelineRuntime I/O boundary."""

    schema_version: str = "1.0"
    status: ExecutionStatus = ExecutionStatus.SUCCEEDED
    request_id: str = ""
    execution_id: str = ""
    tool_name: str = ""
    stdout: str = field(default="", repr=False)
    stderr: str = field(default="", repr=False)
    artifact_refs: tuple[str, ...] = field(default_factory=tuple, repr=False)
    exit_code: int | None = None
    duration: float = 0.0
    error_class: str = ""
    error_message: str = field(default="", repr=False)
    partial: bool = False
    policy_decision_ref: str = ""
    metadata: dict[str, Any] = field(default_factory=dict, repr=False)
    executed: bool = True
    decision: Any = field(default=None, repr=False, compare=False)

    @property
    def output(self) -> str:
        """Legacy string-output facade retained during result migration."""
        return self.stdout

    def __str__(self) -> str:
        """Preserve legacy string coercion without exposing stderr or metadata."""
        return self.stdout

    @property
    def audit_command(self) -> str:
        if self.decision is None or not hasattr(self.decision, "to_dict"):
            return ""
        payload = self.decision.to_dict()
        return _as_text(payload.get("command", "")) if isinstance(payload, Mapping) else ""

    def to_dict(self) -> dict[str, Any]:
        """Return a strict JSON-safe, versioned representation."""
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "request_id": self.request_id,
            "execution_id": self.execution_id,
            "tool_name": self.tool_name,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "artifact_refs": list(self.artifact_refs),
            "exit_code": self.exit_code,
            "duration": self.duration,
            "error": {
                "class": self.error_class,
                "message": self.error_message,
            },
            "partial": self.partial,
            "policy_decision_ref": self.policy_decision_ref,
            "metadata": _json_safe(self.metadata),
            "executed": self.executed,
        }

    def to_audit_dict(self) -> dict[str, Any]:
        """Retain the old bounded audit facade without exposing output."""
        decision = self.decision.to_dict() if hasattr(self.decision, "to_dict") else None
        return {
            "decision": decision,
            "executed": self.executed,
            "status": self.status.value,
            "request_id": self.request_id,
            "execution_id": self.execution_id,
            "policy_decision_ref": self.policy_decision_ref,
            "output_bytes": len(self.stdout.encode("utf-8", "ignore")),
            "stderr_bytes": len(self.stderr.encode("utf-8", "ignore")),
            "partial": self.partial,
        }


def adapt_execution_result(
    value: Any,
    *,
    request_id: str = "",
    execution_id: str = "",
    tool_name: str = "",
    max_output_bytes: int = 1_000_000,
    default_duration: float = 0.0,
    policy_decision_ref: str = "",
    executed: bool | None = None,
    decision: Any = None,
    redact_text: TextRedactor | None = None,
    redact_data: DataRedactor | None = None,
) -> ExecutionResult:
    """Normalize legacy strings, mappings, and duck-typed result objects."""
    if isinstance(value, ExecutionResult):
        raw: dict[str, Any] = value.to_dict()
        raw["error_class"] = value.error_class
        raw["error_message"] = value.error_message
        raw["artifact_refs"] = value.artifact_refs
        raw["metadata"] = value.metadata
        raw["executed"] = value.executed
        source_decision = value.decision
    elif isinstance(value, Mapping):
        raw = dict(value)
        source_decision = None
    elif isinstance(value, str) or value is None:
        raw = {"stdout": _as_text(value), "success": True, "exit_code": 0}
        source_decision = None
    else:
        raw = {
            key: getattr(value, key)
            for key in (
                "artifact_refs",
                "artifacts",
                "credentials",
                "data",
                "duration",
                "error",
                "error_class",
                "error_message",
                "evidence",
                "executed",
                "exit_code",
                "facts",
                "metadata",
                "output",
                "partial",
                "sessions",
                "status",
                "stderr",
                "stdout",
                "success",
                "tool_name",
            )
            if hasattr(value, key)
        }
        raw["legacy_result_type"] = type(value).__name__
        source_decision = None

    raw_error = raw.get("error_message", raw.get("error", ""))
    if isinstance(raw_error, Mapping):
        error_class = _as_text(raw.get("error_class") or raw_error.get("class", ""))
        error_message = _as_text(raw_error.get("message", ""))
    else:
        error_class = _as_text(raw.get("error_class", ""))
        error_message = _as_text(raw_error)
    exit_code = _coerce_int(raw.get("exit_code"))
    explicit_status = raw.get("status")
    marker_status: ExecutionStatus | None = None
    marker_partial = False
    if explicit_status in (None, ""):
        marker_status, marker_partial = _legacy_marker_status(
            raw.get("stdout", raw.get("output", raw.get("evidence", ""))),
            raw.get("stderr", ""),
            error_message,
        )
    status = _status_from_value(
        marker_status or explicit_status,
        success=raw.get("success"),
        exit_code=exit_code,
        error=error_message,
    )

    stdout = raw.get("stdout")
    if stdout in (None, ""):
        stdout = raw.get("output")
    if stdout in (None, ""):
        stdout = raw.get("evidence", "")
    stderr = raw.get("stderr", "")
    if not stderr and error_message:
        stderr = error_message
    stdout_text = _redact_text(redact_text, stdout, kind="execution_stdout")
    stderr_text = _redact_text(redact_text, stderr, kind="execution_stderr")
    stdout_text, stderr_text, truncated = _bounded_outputs(
        stdout_text,
        stderr_text,
        max_output_bytes,
    )

    partial = (
        bool(raw.get("partial"))
        or marker_partial
        or status is ExecutionStatus.PARTIAL
        or truncated
    )
    if truncated and status is ExecutionStatus.SUCCEEDED:
        status = ExecutionStatus.PARTIAL

    metadata: dict[str, Any] = {}
    raw_metadata = raw.get("metadata")
    if isinstance(raw_metadata, Mapping):
        metadata.update(raw_metadata)
    for key in ("credentials", "data", "facts", "sessions"):
        if key in raw:
            metadata[key] = raw[key]
    for key, item in raw.items():
        if key not in _CANONICAL_KEYS and key not in metadata and key not in {"success", "evidence"}:
            metadata[key] = item
    if raw.get("status") and _as_text(raw.get("status")) not in {status.value, status.name}:
        metadata.setdefault("legacy_status", _as_text(raw.get("status")))
    if truncated:
        metadata["output_truncated"] = True
    artifacts = raw.get("artifact_refs", raw.get("artifacts"))
    artifact_refs, artifacts_truncated, artifact_ref_count = _bounded_artifact_refs(
        artifacts,
        redact_text,
    )
    if artifacts_truncated:
        metadata["artifact_refs_truncated"] = True
        metadata["artifact_ref_count"] = artifact_ref_count
    safe_metadata = _bounded_metadata(
        _redact_mapping_keys(
            _redact_data(redact_data, metadata),
            redact_text,
        )
    )
    default_executed = status not in {ExecutionStatus.BLOCKED, ExecutionStatus.UNAVAILABLE}
    was_executed = bool(raw.get("executed", default_executed)) if executed is None else bool(executed)
    error_limit = min(4096, max(0, int(max_output_bytes)))
    safe_error, _error_truncated = _bounded_text(
        _redact_text(redact_text, error_message, kind="execution_error"),
        error_limit,
    )

    return ExecutionResult(
        status=status,
        request_id=request_id or _as_text(raw.get("request_id")) or _new_id(),
        execution_id=execution_id or _as_text(raw.get("execution_id")) or _new_id(),
        tool_name=tool_name or _as_text(raw.get("tool_name")),
        stdout=stdout_text,
        stderr=stderr_text,
        artifact_refs=artifact_refs,
        exit_code=exit_code,
        duration=_coerce_duration(raw.get("duration", raw.get("duration_seconds")), default_duration),
        error_class=_as_text(error_class),
        error_message=safe_error,
        partial=partial,
        policy_decision_ref=policy_decision_ref or _as_text(raw.get("policy_decision_ref")),
        metadata=safe_metadata,
        executed=was_executed,
        decision=decision if decision is not None else source_decision,
    )


# Import compatibility while callers migrate to the canonical class name.
DispatchResult = ExecutionResult


__all__ = [
    "MAX_ARTIFACT_BYTES",
    "MAX_ARTIFACT_REFS",
    "MAX_METADATA_BYTES",
    "DispatchResult",
    "ExecutionResult",
    "ExecutionStatus",
    "adapt_execution_result",
]
