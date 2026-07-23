"""Public mission lifecycle value objects and validation contracts."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.ai.outcomes import TaskOutcome
from core.knowledge.identity import validate_canonical_entity_id

MISSION_LIFECYCLE_SCHEMA_VERSION = "1.4"
TASK_SCOPE_SCHEMA_VERSION = "1.0"
TASK_DEFINITION_SCHEMA_VERSION = "1.0"
_MIGRATABLE_SCHEMA_VERSIONS = frozenset({"1.0", "1.1", "1.2", "1.3", MISSION_LIFECYCLE_SCHEMA_VERSION})
_MAX_IDENTIFIER_BYTES = 4096
_MAX_REASON_BYTES = 16 * 1024
_MAX_OUTCOME_BYTES = 4 * 1024 * 1024
_MAX_RETRY_BUDGET = 100
_MAX_RETRY_COMMAND_KEYS = 64
_MAX_STATE_REPLANS = 100
_MAX_STATE_REPLAN_SIGNATURE_BYTES = 4096
_MAX_SCOPE_ENTITIES = 256
_MAX_EVALUATED_SNAPSHOT_BYTES = 64 * 1024 * 1024
_MAX_BACKOFF_SECONDS = 7 * 24 * 60 * 60
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class MissionStatus(str, Enum):
    RUNNING = "running"
    INTERRUPTED = "interrupted"
    COMPLETED = "completed"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    INTERRUPTED = "interrupted"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    FAILED = "failed"
    NO_NEW_FACTS = "no_new_facts"
    COMPLETED = "completed"


class RetryErrorClass(str, Enum):
    """Stable error taxonomy used by durable retry policies."""

    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    TRANSIENT_NETWORK = "transient_network"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TOOL_UNAVAILABLE = "tool_unavailable"
    EXECUTION_ERROR = "execution_error"


class BackoffStrategy(str, Enum):
    """Durable, deterministic delay strategy for a task retry."""

    NONE = "none"
    FIXED = "fixed"
    EXPONENTIAL = "exponential"


_RETRYABLE_TASK_STATUSES = {
    TaskStatus.PENDING.value,
    TaskStatus.INTERRUPTED.value,
}
_OUTCOME_STATUSES = {
    TaskStatus.BLOCKED.value,
    TaskStatus.SKIPPED.value,
    TaskStatus.FAILED.value,
    TaskStatus.NO_NEW_FACTS.value,
    TaskStatus.COMPLETED.value,
}


class MissionStoreError(ValueError):
    """Raised when a lifecycle mutation conflicts with persisted state."""


class TaskDependenciesIncomplete(MissionStoreError):
    """Raised when durable task prerequisites have not completed."""

    def __init__(self, incomplete: Sequence[tuple[str, str]]) -> None:
        self.incomplete = tuple(incomplete)
        details = ",".join(f"{task_id}:{status}" for task_id, status in self.incomplete)
        super().__init__(f"task dependencies are incomplete: {details}")


class TaskRetryError(MissionStoreError):
    """Base error for an invalid durable retry transition."""


class TaskRetryNotAllowed(TaskRetryError):
    """Raised when a failure class is not retryable for a task."""


class TaskRetryBudgetExhausted(TaskRetryError):
    """Raised when a task has consumed its explicit retry budget."""


class TaskNotReady(MissionStoreError):
    """Raised when a durable ``not_before`` gate has not elapsed."""

    def __init__(self, task_id: str, not_before: float, now: float) -> None:
        self.task_id = task_id
        self.not_before = float(not_before)
        self.remaining_seconds = max(0.0, self.not_before - float(now))
        super().__init__(f"task {task_id} is deferred until {self.not_before:.6f}")


@dataclass(frozen=True)
class TaskScope:
    """Versioned task scope over canonical graph entity identities.

    ``legacy_scope`` is a compatibility display value.  When canonical entity
    IDs are present, they alone define scope identity so aliases cannot create
    duplicate tasks.  A legacy-only scope remains supported and is keyed by a
    secret-store digest before it contributes to task identity.
    """

    entity_ids: tuple[str, ...] = ()
    legacy_scope: str = ""
    schema_version: str = TASK_SCOPE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TASK_SCOPE_SCHEMA_VERSION:
            raise MissionStoreError(f"unsupported task scope schema version: {self.schema_version}")
        try:
            normalized = tuple(
                sorted(
                    dict.fromkeys(validate_canonical_entity_id(item) for item in self.entity_ids if str(item).strip())
                )
            )
        except ValueError as exc:
            raise MissionStoreError("task scope entity_ids must be canonical graph identities") from exc
        if len(normalized) > _MAX_SCOPE_ENTITIES:
            raise MissionStoreError(f"task scope exceeds {_MAX_SCOPE_ENTITIES} canonical entities")
        if any(len(item.encode("utf-8", "replace")) > _MAX_IDENTIFIER_BYTES for item in normalized):
            raise MissionStoreError("canonical entity id is too large")
        if len(str(self.legacy_scope).encode("utf-8", "replace")) > _MAX_IDENTIFIER_BYTES:
            raise MissionStoreError("legacy task scope is too large")
        object.__setattr__(self, "entity_ids", normalized)
        object.__setattr__(self, "legacy_scope", str(self.legacy_scope or ""))

    @classmethod
    def from_legacy(cls, value: str) -> TaskScope:
        """Adapt the historical free-form scope writer."""
        return cls(legacy_scope=str(value or ""))

    @property
    def canonical_entity_ids(self) -> tuple[str, ...]:
        """Explicit alias used by schema/report consumers."""
        return self.entity_ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "entity_ids": list(self.entity_ids),
            "legacy_scope": self.legacy_scope,
        }


@dataclass(frozen=True)
class TaskBackoff:
    """Typed retry delay persisted with a mission task definition."""

    strategy: BackoffStrategy = BackoffStrategy.NONE
    base_delay_seconds: float = 0.0
    max_delay_seconds: float = 0.0
    multiplier: float = 2.0

    def __post_init__(self) -> None:
        try:
            strategy = (
                self.strategy if isinstance(self.strategy, BackoffStrategy) else BackoffStrategy(str(self.strategy))
            )
            base = float(self.base_delay_seconds)
            maximum = float(self.max_delay_seconds)
            multiplier = float(self.multiplier)
        except (TypeError, ValueError) as exc:
            raise MissionStoreError("invalid task backoff") from exc
        if not all(math.isfinite(item) for item in (base, maximum, multiplier)):
            raise MissionStoreError("task backoff values must be finite")
        if base < 0 or maximum < 0:
            raise MissionStoreError("task backoff delays cannot be negative")
        if base > _MAX_BACKOFF_SECONDS or maximum > _MAX_BACKOFF_SECONDS:
            raise MissionStoreError(f"task backoff cannot exceed {_MAX_BACKOFF_SECONDS} seconds")
        if strategy is BackoffStrategy.NONE:
            if base or maximum:
                raise MissionStoreError("none backoff cannot define a delay")
        elif strategy is BackoffStrategy.FIXED:
            if base <= 0:
                raise MissionStoreError("fixed backoff requires a positive base delay")
            maximum = base if maximum == 0 else maximum
            if maximum != base:
                raise MissionStoreError("fixed backoff maximum must equal its base delay")
            multiplier = 1.0
        else:
            if base <= 0:
                raise MissionStoreError("exponential backoff requires a positive base delay")
            maximum = base if maximum == 0 else maximum
            if maximum < base:
                raise MissionStoreError("exponential backoff maximum cannot be below its base delay")
            if multiplier < 1.0 or multiplier > 100.0:
                raise MissionStoreError("exponential backoff multiplier must be between 1 and 100")
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "base_delay_seconds", base)
        object.__setattr__(self, "max_delay_seconds", maximum)
        object.__setattr__(self, "multiplier", multiplier)

    def delay_for_retry(self, retry_number: int) -> float:
        if retry_number < 1 or self.strategy is BackoffStrategy.NONE:
            return 0.0
        if self.strategy is BackoffStrategy.FIXED:
            return self.base_delay_seconds
        exponent = min(int(retry_number) - 1, 64)
        delay = self.base_delay_seconds * (self.multiplier**exponent)
        return min(delay, self.max_delay_seconds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "base_delay_seconds": self.base_delay_seconds,
            "max_delay_seconds": self.max_delay_seconds,
            "multiplier": self.multiplier,
        }


# Compatibility spelling for callers that model retry and backoff policies
# side by side.
TaskBackoffPolicy = TaskBackoff


def canonical_capability_id(value: str) -> str:
    """Return a stable, versioned ID for a human-facing capability label."""

    normalized = "_".join(str(value or "").strip().casefold().split())
    if not normalized:
        raise MissionStoreError("capability id source is required")
    if len(normalized.encode("utf-8", "replace")) > _MAX_IDENTIFIER_BYTES:
        raise MissionStoreError("capability id source is too large")
    digest = hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:32]
    return f"capability:v1:{digest}"


@dataclass(frozen=True)
class TaskRetryPolicy:
    """Bounded retry policy persisted with a mission task definition."""

    retry_budget: int = 0
    retryable_error_classes: tuple[RetryErrorClass, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.retry_budget, bool) or not isinstance(self.retry_budget, int):
            raise MissionStoreError("retry_budget must be an integer")
        if not 0 <= self.retry_budget <= _MAX_RETRY_BUDGET:
            raise MissionStoreError(f"retry_budget must be between 0 and {_MAX_RETRY_BUDGET}")
        try:
            normalized = tuple(
                dict.fromkeys(
                    item if isinstance(item, RetryErrorClass) else RetryErrorClass(str(item))
                    for item in self.retryable_error_classes
                )
            )
        except ValueError as exc:
            raise MissionStoreError(f"unsupported retry error class: {exc}") from exc
        if self.retry_budget and not normalized:
            raise MissionStoreError("a positive retry_budget requires retryable_error_classes")
        if not self.retry_budget and normalized:
            raise MissionStoreError("retryable_error_classes require a positive retry_budget")
        object.__setattr__(self, "retryable_error_classes", normalized)


@dataclass(frozen=True)
class TaskDependencyRef:
    """Unambiguous selector for a dependency in an atomic mission plan.

    ``task_id`` addresses an already-persisted task.  New definitions in the
    same plan can instead use ``agent``/``task`` plus typed scope and definition
    version.  The historical ``(agent, task)`` pair remains supported when it
    resolves to exactly one task.
    """

    agent: str = ""
    task: str = ""
    scope: TaskScope | str | None = None
    task_definition_version: str | None = None
    task_id: str = ""


@dataclass(frozen=True)
class MissionTaskDefinition:
    """Typed planner-task definition accepted by :meth:`register_plan`."""

    agent: str
    task: str
    depends_on: tuple[TaskDependencyRef | tuple[str, str], ...] = ()
    scope: TaskScope | str = ""
    capability: str = ""
    capability_id: str = ""
    task_definition_version: str = TASK_DEFINITION_SCHEMA_VERSION
    retry_policy: TaskRetryPolicy = field(default_factory=TaskRetryPolicy)
    not_before: float | None = None
    backoff: TaskBackoff = field(default_factory=TaskBackoff)
    provider_circuit_ref: str = ""
    evaluated_snapshot_ref: str = ""


@dataclass(frozen=True)
class MissionRecord:
    mission_id: str
    scan_id: str
    target: str
    status: str
    reason: str
    created_at: float
    updated_at: float
    started_at: float
    finished_at: float | None
    run_count: int
    schema_version: str = MISSION_LIFECYCLE_SCHEMA_VERSION
    state_replan_count: int = 0
    state_replan_signatures: tuple[str, ...] = ()


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    mission_id: str
    agent: str
    task: str
    status: str
    reason: str
    depends_on: tuple[str, ...]
    created_at: float
    updated_at: float
    started_at: float | None
    finished_at: float | None
    attempt_count: int
    scope: str = ""
    task_scope: TaskScope = field(default_factory=TaskScope)
    capability: str = ""
    capability_id: str = ""
    task_definition_version: str = TASK_DEFINITION_SCHEMA_VERSION
    retry_budget: int = 0
    retry_count: int = 0
    retryable_error_classes: tuple[RetryErrorClass, ...] = ()
    last_error_class: RetryErrorClass | None = None
    not_before: float | None = None
    backoff: TaskBackoff = field(default_factory=TaskBackoff)
    provider_circuit_ref: str = ""
    evaluated_snapshot_ref: str = ""

    @property
    def scope_entity_ids(self) -> tuple[str, ...]:
        return self.task_scope.entity_ids

    @property
    def definition_version(self) -> str:
        return self.task_definition_version


@dataclass(frozen=True)
class TaskAttemptRecord:
    attempt_id: str
    task_id: str
    mission_id: str
    attempt_number: int
    status: str
    reason: str
    started_at: float
    finished_at: float | None
    outcome: TaskOutcome | None
    execution_ids: tuple[str, ...]
    fact_ids: tuple[int, ...]


@dataclass(frozen=True)
class AttemptCompletionResult:
    """Atomic result of terminalizing an attempt and evaluating its retry."""

    attempt: TaskAttemptRecord
    task: TaskRecord
    retry_scheduled: bool = False
    retry_rejection: str = ""
    retry_command_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class StateReplanResult:
    """Atomic result of deduplicating and reserving a state-change replan."""

    requested: bool
    reason: str
    count: int
    signatures: tuple[str, ...]


@dataclass(frozen=True)
class MissionSnapshot:
    mission: MissionRecord
    tasks: tuple[TaskRecord, ...]
    attempts: tuple[TaskAttemptRecord, ...]

    @property
    def task_outcomes(self) -> tuple[dict[str, Any], ...]:
        """Return completed attempt outcomes in legacy report order."""
        return tuple(attempt.outcome.to_legacy_dict() for attempt in self.attempts if attempt.outcome is not None)


# Preserve the historical public import path for repr, introspection, and
# pickle payloads even though implementations now live in this focused module.
for _compat_type in (
    MissionStatus,
    TaskStatus,
    RetryErrorClass,
    BackoffStrategy,
    MissionStoreError,
    TaskDependenciesIncomplete,
    TaskRetryError,
    TaskRetryNotAllowed,
    TaskRetryBudgetExhausted,
    TaskNotReady,
    TaskScope,
    TaskBackoff,
    TaskRetryPolicy,
    TaskDependencyRef,
    MissionTaskDefinition,
    MissionRecord,
    TaskRecord,
    TaskAttemptRecord,
    AttemptCompletionResult,
    StateReplanResult,
    MissionSnapshot,
):
    _compat_type.__module__ = "core.ai.mission_store"
canonical_capability_id.__module__ = "core.ai.mission_store"


__all__ = [
    "MISSION_LIFECYCLE_SCHEMA_VERSION",
    "TASK_DEFINITION_SCHEMA_VERSION",
    "TASK_SCOPE_SCHEMA_VERSION",
    "AttemptCompletionResult",
    "BackoffStrategy",
    "MissionRecord",
    "MissionSnapshot",
    "MissionStatus",
    "MissionStoreError",
    "MissionTaskDefinition",
    "RetryErrorClass",
    "StateReplanResult",
    "TaskAttemptRecord",
    "TaskBackoff",
    "TaskBackoffPolicy",
    "TaskDependenciesIncomplete",
    "TaskDependencyRef",
    "TaskNotReady",
    "TaskRecord",
    "TaskRetryBudgetExhausted",
    "TaskRetryError",
    "TaskRetryNotAllowed",
    "TaskRetryPolicy",
    "TaskScope",
    "TaskStatus",
    "canonical_capability_id",
]
