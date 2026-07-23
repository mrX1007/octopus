"""MissionStore validation, JSON codecs, redaction, and row decoders."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any

from core.ai.mission_store_models import (
    _MAX_IDENTIFIER_BYTES,
    _MAX_OUTCOME_BYTES,
    _MAX_REASON_BYTES,
    _MAX_RETRY_COMMAND_KEYS,
    _MAX_STATE_REPLANS,
    _VERSION_PATTERN,
    TASK_SCOPE_SCHEMA_VERSION,
    BackoffStrategy,
    MissionRecord,
    MissionStoreError,
    RetryErrorClass,
    TaskAttemptRecord,
    TaskBackoff,
    TaskRecord,
    TaskRetryNotAllowed,
    TaskScope,
    canonical_capability_id,
)
from core.ai.outcomes import TaskOutcome

# mypy: disable-error-code="attr-defined"


class MissionStoreCodecMixin:
    def _coerce_task_scope(
        self,
        value: TaskScope | str | Mapping[str, Any] | Sequence[str] | None,
    ) -> TaskScope:
        if value is None:
            return TaskScope()
        if isinstance(value, TaskScope):
            return value
        if isinstance(value, str):
            return TaskScope.from_legacy(value)
        if isinstance(value, Mapping):
            raw_ids = value.get("entity_ids", value.get("canonical_entity_ids", ()))
            entity_ids: tuple[str, ...]
            if isinstance(raw_ids, str):
                entity_ids = (raw_ids,)
            elif isinstance(raw_ids, Sequence):
                entity_ids = tuple(str(item) for item in raw_ids)
            else:
                raise MissionStoreError("task scope entity_ids must be a sequence")
            legacy_value = value.get("legacy_scope")
            if legacy_value is None and not entity_ids:
                legacy_value = json.dumps(
                    dict(value),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    default=str,
                )
            return TaskScope(
                entity_ids=entity_ids,
                legacy_scope=str(legacy_value or ""),
                schema_version=str(value.get("schema_version") or TASK_SCOPE_SCHEMA_VERSION),
            )
        if isinstance(value, Sequence):
            return TaskScope(entity_ids=tuple(str(item) for item in value))
        raise MissionStoreError("scope must be a TaskScope or legacy string")

    @staticmethod
    def _encode_task_scope(scope: TaskScope) -> str:
        return json.dumps(
            scope.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def _decode_task_scope(value: str) -> TaskScope:
        try:
            payload = json.loads(value or "{}")
            if not isinstance(payload, Mapping):
                raise TypeError("task scope must be an object")
            raw_ids = payload.get("entity_ids")
            if raw_ids is None:
                raw_ids = []
            if not isinstance(raw_ids, list):
                raise TypeError("task scope entity_ids must be a list")
            return TaskScope(
                entity_ids=tuple(str(item) for item in raw_ids),
                legacy_scope=str(payload.get("legacy_scope") or ""),
                schema_version=str(payload.get("schema_version") or TASK_SCOPE_SCHEMA_VERSION),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MissionStoreError("invalid persisted task scope") from exc

    def _task_scope_key(
        self,
        scope: TaskScope,
        *,
        legacy_scope_key: str,
    ) -> str:
        identity: dict[str, Any] = {
            "schema_version": scope.schema_version,
            "entity_ids": list(scope.entity_ids),
        }
        if not scope.entity_ids:
            identity["legacy_scope_key"] = str(legacy_scope_key or "")
        return self._stable_payload_key("mission_task_typed_scope", identity)

    @staticmethod
    def _capability_id(value: str | None) -> str:
        raw = str(value or "").strip()
        if not raw:
            raise MissionStoreError("capability_id is required")
        if re.fullmatch(r"capability:v[0-9]+:[0-9a-fA-F]{16,64}", raw):
            return raw.casefold()
        return canonical_capability_id(raw)

    @staticmethod
    def _task_definition_version(value: str) -> str:
        version = str(value or "")
        if not _VERSION_PATTERN.fullmatch(version):
            raise MissionStoreError("invalid task definition version")
        return version

    @staticmethod
    def _not_before(value: float | None) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool):
            raise MissionStoreError("not_before must be a finite timestamp")
        try:
            timestamp = float(value)
        except (TypeError, ValueError) as exc:
            raise MissionStoreError("not_before must be a finite timestamp") from exc
        if not math.isfinite(timestamp) or timestamp < 0:
            raise MissionStoreError("not_before must be a finite timestamp")
        return timestamp

    @staticmethod
    def _retry_not_before(
        now: float,
        retry_number: int,
        backoff: TaskBackoff,
        requested_not_before: float | None,
    ) -> float | None:
        candidates = []
        delay = backoff.delay_for_retry(retry_number)
        if delay > 0:
            candidates.append(float(now) + delay)
        if requested_not_before is not None:
            candidates.append(float(requested_not_before))
        return max(candidates) if candidates else None

    @staticmethod
    def _encode_backoff(backoff: TaskBackoff) -> str:
        return json.dumps(
            backoff.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _decode_backoff(value: str) -> TaskBackoff:
        try:
            payload = json.loads(value or "{}")
            if not isinstance(payload, Mapping):
                raise TypeError("task backoff must be an object")
            return TaskBackoff(
                strategy=BackoffStrategy(str(payload.get("strategy") or BackoffStrategy.NONE.value)),
                base_delay_seconds=float(payload.get("base_delay_seconds", 0.0)),
                max_delay_seconds=float(payload.get("max_delay_seconds", 0.0)),
                multiplier=float(payload.get("multiplier", 2.0)),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MissionStoreError("invalid persisted task backoff") from exc

    def _stable_key(self, kind: str, value: str) -> str:
        secret_store = getattr(self.redactor, "store", None)
        keyed_digest = getattr(secret_store, "keyed_digest", None)
        if not callable(keyed_digest):
            raise MissionStoreError("mission redactor must provide a keyed identity digest")
        return str(keyed_digest(value, kind=f"mission:{kind}"))

    def _stable_payload_key(self, kind: str, value: Any) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        return self._stable_key(kind, encoded)

    @staticmethod
    def _task_compat_key(agent: str, task: str) -> str:
        payload = json.dumps(
            ["task", agent, task],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()

    @staticmethod
    def _task_identity_key(
        compat_key: str,
        task_scope_key: str,
        task_definition_version: str,
    ) -> str:
        payload = json.dumps(
            [
                "task-definition",
                task_definition_version,
                compat_key,
                task_scope_key,
            ],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()

    def _safe_text(self, value: Any, kind: str, limit: int) -> str:
        text = str(value or "")
        if self.redactor is not None:
            try:
                text = str(self.redactor.redact_text(text, kind=kind))
            except TypeError:
                text = str(self.redactor.redact_text(text))
        encoded = text.encode("utf-8", "replace")
        if len(encoded) > limit:
            digest = hashlib.sha256(encoded).hexdigest()[:16]
            suffix = f"~sha256:{digest}".encode()
            prefix_limit = max(0, limit - len(suffix))
            prefix = encoded[:prefix_limit].decode("utf-8", "ignore")
            return prefix + suffix.decode()
        return text

    def _safe_data(self, value: Any) -> Any:
        if self.redactor is None:
            return value
        try:
            return self.redactor.redact_data(value, field="mission_task_outcome")
        except TypeError:
            return self.redactor.redact_data(value)

    def _safe_execution_ids(self, values: Sequence[str]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                self._safe_text(item, "mission_execution_id", _MAX_IDENTIFIER_BYTES) for item in values if str(item)
            )
        )

    def _safe_retry_command_keys(self, values: Sequence[str]) -> tuple[str, ...]:
        keys = tuple(
            dict.fromkeys(
                self._safe_text(item, "mission_retry_command", _MAX_IDENTIFIER_BYTES)
                for item in values
                if str(item).strip()
            )
        )
        if len(keys) > _MAX_RETRY_COMMAND_KEYS:
            raise MissionStoreError(f"retry command allowlist exceeds {_MAX_RETRY_COMMAND_KEYS} keys")
        return keys

    @staticmethod
    def _safe_fact_ids(values: Sequence[int]) -> tuple[int, ...]:
        result: list[int] = []
        for item in values:
            try:
                fact_id = int(item)
            except (TypeError, ValueError) as exc:
                raise MissionStoreError("fact ids must be integers") from exc
            if fact_id < 1:
                raise MissionStoreError("fact ids must be positive")
            result.append(fact_id)
        return tuple(dict.fromkeys(result))

    def _safe_outcome(
        self,
        outcome: TaskOutcome,
        *,
        agent: str,
        task: str,
    ) -> TaskOutcome:
        raw_commands = [dict(command) for command in outcome.commands]
        commands = self._safe_data(raw_commands)
        if not isinstance(commands, list):
            raise MissionStoreError("redacted task commands must remain a list")
        return TaskOutcome(
            agent=agent,
            task=task,
            status=outcome.status,
            reason=self._safe_text(
                outcome.reason,
                "mission_task_reason",
                _MAX_REASON_BYTES,
            ),
            new_facts=int(outcome.new_facts),
            parsed_facts=int(outcome.parsed_facts),
            commands=tuple(
                dict(command) if isinstance(command, Mapping) else {"value": str(command)} for command in commands
            ),
            duration=float(outcome.duration),
        )

    @staticmethod
    def _encode_outcome(outcome: TaskOutcome) -> str:
        encoded = json.dumps(
            outcome.to_legacy_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        if len(encoded.encode("utf-8", "replace")) > _MAX_OUTCOME_BYTES:
            raise MissionStoreError("task outcome exceeds the durable payload limit")
        return encoded

    @staticmethod
    def _decode_outcome(value: str) -> TaskOutcome | None:
        if not value:
            return None
        try:
            payload = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MissionStoreError("corrupt persisted task outcome") from exc
        if not isinstance(payload, Mapping):
            raise MissionStoreError("corrupt persisted task outcome")
        commands = []
        for raw_command in payload.get("commands") or ():
            command = dict(raw_command) if isinstance(raw_command, Mapping) else {"value": str(raw_command)}
            fact_pairs = command.get("fact_pairs")
            if isinstance(fact_pairs, list):
                command["fact_pairs"] = [
                    tuple(item) if isinstance(item, list) and len(item) == 2 else item for item in fact_pairs
                ]
            commands.append(command)
        return TaskOutcome(
            agent=str(payload.get("agent", "")),
            task=str(payload.get("task", "")),
            status=str(payload.get("status", "")),
            reason=str(payload.get("reason", "")),
            new_facts=int(payload.get("new_facts", 0) or 0),
            parsed_facts=int(payload.get("parsed_facts", 0) or 0),
            commands=tuple(commands),
            duration=float(payload.get("duration", 0.0) or 0.0),
        )

    @staticmethod
    def _load_string_tuple(value: str) -> tuple[str, ...]:
        try:
            loaded = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return ()
        return tuple(str(item) for item in loaded) if isinstance(loaded, list) else ()

    @staticmethod
    def _load_int_tuple(value: str) -> tuple[int, ...]:
        try:
            loaded = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return ()
        if not isinstance(loaded, list):
            return ()
        result = []
        for item in loaded:
            try:
                result.append(int(item))
            except (TypeError, ValueError):
                continue
        return tuple(result)

    @staticmethod
    def _encode_state_replan_signatures(values: Sequence[str]) -> str:
        return json.dumps(
            list(values),
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def _load_state_replan_signatures(value: str) -> tuple[str, ...]:
        try:
            loaded = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MissionStoreError("invalid persisted state replan signatures") from exc
        if not isinstance(loaded, list) or any(not isinstance(item, str) or not item for item in loaded):
            raise MissionStoreError("invalid persisted state replan signatures")
        return tuple(dict.fromkeys(loaded))

    @staticmethod
    def _state_replan_count_from_row(row: sqlite3.Row) -> int:
        try:
            count = int(row["state_replan_count"])
        except IndexError:
            count = 0
        if count < 0 or count > _MAX_STATE_REPLANS:
            raise MissionStoreError("invalid persisted state replan count")
        return count

    @classmethod
    def _state_replan_signatures_from_row(
        cls,
        row: sqlite3.Row,
    ) -> tuple[str, ...]:
        try:
            encoded = row["state_replan_signatures_json"]
        except IndexError:
            return ()
        return cls._load_state_replan_signatures(encoded)

    @staticmethod
    def _retry_error_class(value: RetryErrorClass | str) -> RetryErrorClass:
        try:
            return value if isinstance(value, RetryErrorClass) else RetryErrorClass(str(value))
        except ValueError as exc:
            raise TaskRetryNotAllowed(f"unsupported retry error class: {value}") from exc

    @staticmethod
    def _encode_retry_error_classes(
        values: Sequence[RetryErrorClass],
    ) -> str:
        return json.dumps(
            [item.value for item in values],
            separators=(",", ":"),
        )

    @staticmethod
    def _load_retry_error_classes(value: str) -> tuple[RetryErrorClass, ...]:
        try:
            loaded = json.loads(value or "[]")
            if not isinstance(loaded, list):
                raise TypeError("retry error classes must be a list")
            return tuple(dict.fromkeys(RetryErrorClass(str(item)) for item in loaded))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MissionStoreError("invalid persisted retry error classes") from exc

    @classmethod
    def _mission_from_row(cls, row: sqlite3.Row) -> MissionRecord:
        return MissionRecord(
            mission_id=row["mission_id"],
            scan_id=row["scan_id"],
            target=row["target"],
            status=row["status"],
            reason=row["reason"],
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            started_at=float(row["started_at"]),
            finished_at=float(row["finished_at"]) if row["finished_at"] is not None else None,
            run_count=int(row["run_count"]),
            schema_version=row["schema_version"],
            state_replan_count=cls._state_replan_count_from_row(row),
            state_replan_signatures=cls._state_replan_signatures_from_row(row),
        )

    def _task_from_row(self, conn: sqlite3.Connection, row: sqlite3.Row) -> TaskRecord:
        return TaskRecord(
            task_id=row["task_id"],
            mission_id=row["mission_id"],
            agent=row["agent"],
            task=row["task"],
            status=row["status"],
            reason=row["reason"],
            depends_on=self._dependency_ids(conn, row["task_id"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            started_at=float(row["started_at"]) if row["started_at"] is not None else None,
            finished_at=float(row["finished_at"]) if row["finished_at"] is not None else None,
            attempt_count=int(row["attempt_count"]),
            scope=row["scope"],
            task_scope=self._decode_task_scope(row["task_scope_json"]),
            capability=row["capability"],
            capability_id=row["capability_id"],
            task_definition_version=row["task_definition_version"],
            retry_budget=int(row["retry_budget"]),
            retry_count=int(row["retry_count"]),
            retryable_error_classes=self._load_retry_error_classes(row["retryable_error_classes_json"]),
            last_error_class=(self._retry_error_class(row["last_error_class"]) if row["last_error_class"] else None),
            not_before=(float(row["not_before"]) if row["not_before"] is not None else None),
            backoff=self._decode_backoff(row["backoff_json"]),
            provider_circuit_ref=row["provider_circuit_ref"],
            evaluated_snapshot_ref=row["evaluated_snapshot_ref"],
        )

    def _attempt_from_row(self, row: sqlite3.Row) -> TaskAttemptRecord:
        return TaskAttemptRecord(
            attempt_id=row["attempt_id"],
            task_id=row["task_id"],
            mission_id=row["mission_id"],
            attempt_number=int(row["attempt_number"]),
            status=row["status"],
            reason=row["reason"],
            started_at=float(row["started_at"]),
            finished_at=float(row["finished_at"]) if row["finished_at"] is not None else None,
            outcome=self._decode_outcome(row["outcome_json"]),
            execution_ids=self._load_string_tuple(row["execution_ids_json"]),
            fact_ids=self._load_int_tuple(row["fact_ids_json"]),
        )
