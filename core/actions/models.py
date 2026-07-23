"""Versioned models for the unified action-adapter lifecycle."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.execution import ExecutionContext, ExecutionResult

ACTION_DESCRIPTOR_SCHEMA_VERSION = "1.0"
ACTION_LIFECYCLE_SCHEMA_VERSION = "1.0"


class ActionKind(str, Enum):
    REGISTERED_TOOL = "registered_tool"
    EXPLOIT = "exploit_base"
    METASPLOIT = "metasploit"
    PLUGIN = "plugin"
    KILLCHAIN = "killchain"


class ActiveRiskClass(str, Enum):
    """Coarse action risk used for ranking and safe fallback boundaries."""

    READ_ONLY = "read_only"
    ACTIVE = "active"

    @property
    def score(self) -> float:
        return 1.0 if self is ActiveRiskClass.ACTIVE else 0.0


class ApplicabilityStatus(str, Enum):
    UNKNOWN = "unknown"
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


class CheckStatus(str, Enum):
    NOT_RUN = "not_run"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class AttemptStatus(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    BLOCKED = "blocked"
    ATTEMPTED = "attempted"


class OutcomeStatus(str, Enum):
    UNKNOWN = "unknown"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class VerificationStatus(str, Enum):
    NOT_RUN = "not_run"
    VERIFIED = "verified"
    UNVERIFIED = "unverified"


class CleanupStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class ActionRequirements:
    system_dependencies: tuple[str, ...] = ()
    python_dependencies: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    target_required: bool = True
    active: bool = False
    supports_check: bool = False
    supports_cleanup: bool = False
    positive_check_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "system_dependencies": list(self.system_dependencies),
            "python_dependencies": list(self.python_dependencies),
            "capabilities": list(self.capabilities),
            "target_required": self.target_required,
            "active": self.active,
            "supports_check": self.supports_check,
            "supports_cleanup": self.supports_cleanup,
            "positive_check_required": self.positive_check_required,
        }


@dataclass(frozen=True)
class ActionDescriptor:
    action_id: str
    name: str
    kind: ActionKind
    provider: str
    category: str = ""
    description: str = ""
    version: str = ""
    aliases: tuple[str, ...] = ()
    requirements: ActionRequirements = field(default_factory=ActionRequirements)
    schema_version: str = ACTION_DESCRIPTOR_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "name": self.name,
            "kind": self.kind.value,
            "provider": self.provider,
            "category": self.category,
            "description": self.description,
            "version": self.version,
            "aliases": list(self.aliases),
            "requirements": self.requirements.to_dict(),
        }


@dataclass(frozen=True)
class ActionRequest:
    target: str
    execution_context: ExecutionContext
    arguments: tuple[str, ...] = field(default_factory=tuple, repr=False)
    parameters: dict[str, Any] = field(default_factory=dict, repr=False)
    command: str = field(default="", repr=False)
    facts: tuple[dict[str, Any], ...] = field(default_factory=tuple, repr=False)
    handle: Any = field(default=None, repr=False, compare=False)
    evidence_fact_ids: tuple[int, ...] = ()
    assessment_refs: tuple[str, ...] = ()
    source_execution_ids: tuple[str, ...] = ()
    provider_commands: dict[str, str] = field(default_factory=dict, repr=False)

    def provider_command_for(self, action_name: str) -> str:
        """Look up one in-memory provider command without an audit fallback."""

        requested = str(action_name or "").strip().casefold()
        for name, command in self.provider_commands.items():
            if str(name).strip().casefold() == requested:
                return str(command)
        return ""

    def command_for(self, action_name: str) -> str:
        """Return an in-memory provider command without exposing it to audit."""

        provider_command = self.provider_command_for(action_name)
        if provider_command:
            return provider_command
        return self.command

    def audit_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "request_id": self.execution_context.request_id,
            "argument_count": len(self.arguments),
            "parameter_names": sorted(str(key) for key in self.parameters),
            "provider_command_count": len(self.provider_commands),
            "fact_count": len(self.facts),
            "evidence_fact_ids": list(self.evidence_fact_ids),
            "assessment_refs": list(self.assessment_refs),
            "source_execution_ids": list(self.source_execution_ids),
            "has_handle": self.handle is not None,
        }


@dataclass(frozen=True)
class ApplicabilityResult:
    applicable: bool
    reasons: tuple[str, ...] = ()
    missing_requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicable": self.applicable,
            "reasons": list(self.reasons),
            "missing_requirements": list(self.missing_requirements),
        }


@dataclass(frozen=True)
class ActionCheckResult:
    result: Any = field(repr=False)
    applicable: bool | None = None
    reason: str = ""
    evidence_fact_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class ActionVerificationResult:
    verified: bool
    reason: str
    evidence_fact_ids: tuple[int, ...] = ()
    assessment_refs: tuple[str, ...] = ()
    source_execution_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "reason": self.reason,
            "evidence_fact_ids": list(self.evidence_fact_ids),
            "assessment_refs": list(self.assessment_refs),
            "source_execution_ids": list(self.source_execution_ids),
        }


@dataclass(frozen=True)
class ActionCleanupResult:
    succeeded: bool
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"succeeded": self.succeeded, "reason": self.reason}


@dataclass(frozen=True)
class PolicyDenial:
    """Secret-safe typed policy denial retained separately from availability."""

    phase: str
    reason_code: str
    decision_ref: str = ""

    @classmethod
    def create(
        cls,
        phase: str,
        reason: str,
        decision_ref: str = "",
    ) -> PolicyDenial:
        raw = str(reason or "unknown").split(":", 1)[0].strip().casefold()
        reason_code = "".join(
            character if character.isalnum() or character in "_.-" else "_"
            for character in raw
        )[:128]
        return cls(
            phase=str(phase or "unknown")[:64],
            reason_code=reason_code or "unknown",
            decision_ref=str(decision_ref or "")[:256],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "phase": self.phase,
            "reason_code": self.reason_code,
            "decision_ref": self.decision_ref,
        }


@dataclass
class ActionLifecycle:
    candidate: bool = True
    applicability: ApplicabilityStatus = ApplicabilityStatus.UNKNOWN
    check: CheckStatus = CheckStatus.NOT_RUN
    check_positive: bool | None = None
    attempt: AttemptStatus = AttemptStatus.NOT_ATTEMPTED
    outcome: OutcomeStatus = OutcomeStatus.UNKNOWN
    verification: VerificationStatus = VerificationStatus.NOT_RUN
    cleanup: CleanupStatus = CleanupStatus.NOT_REQUIRED
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    events: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = ACTION_LIFECYCLE_SCHEMA_VERSION

    def record(self, event: str, *, reason: str = "") -> None:
        self.updated_at = time.time()
        if len(self.events) < 64:
            self.events.append({
                "event": str(event),
                "reason": str(reason),
                "timestamp": self.updated_at,
            })

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate": self.candidate,
            "applicability": self.applicability.value,
            "check": self.check.value,
            "check_positive": self.check_positive,
            "attempt": self.attempt.value,
            "outcome": self.outcome.value,
            "verification": self.verification.value,
            "cleanup": self.cleanup.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "events": list(self.events),
        }


@dataclass
class ActionExecutionReport:
    descriptor: ActionDescriptor
    lifecycle: ActionLifecycle
    applicability: ApplicabilityResult | None = None
    check_result: ExecutionResult | None = field(default=None, repr=False)
    execution_result: ExecutionResult | None = field(default=None, repr=False)
    verification_result: ActionVerificationResult | None = None
    cleanup_result: ActionCleanupResult | None = None
    policy_decision_refs: list[str] = field(default_factory=list)
    policy_denials: list[PolicyDenial] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ACTION_LIFECYCLE_SCHEMA_VERSION,
            "descriptor": self.descriptor.to_dict(),
            "lifecycle": self.lifecycle.to_dict(),
            "applicability": self.applicability.to_dict() if self.applicability else None,
            "check_result": self.check_result.to_dict() if self.check_result else None,
            "execution_result": self.execution_result.to_dict() if self.execution_result else None,
            "verification_result": (
                self.verification_result.to_dict() if self.verification_result else None
            ),
            "cleanup_result": self.cleanup_result.to_dict() if self.cleanup_result else None,
            "policy_decision_refs": list(self.policy_decision_refs),
            "policy_denials": [item.to_dict() for item in self.policy_denials],
        }

    def to_audit_dict(self) -> dict[str, Any]:
        payload = self.to_dict()
        for key in ("check_result", "execution_result"):
            result = payload.get(key)
            if isinstance(result, dict):
                result["stdout"] = ""
                result["stderr"] = ""
                result["error"] = {
                    "class": result.get("error", {}).get("class", ""),
                    "message": "",
                }
        return payload


__all__ = [
    "ACTION_DESCRIPTOR_SCHEMA_VERSION",
    "ACTION_LIFECYCLE_SCHEMA_VERSION",
    "ActionCheckResult",
    "ActionCleanupResult",
    "ActionDescriptor",
    "ActionExecutionReport",
    "ActionKind",
    "ActionLifecycle",
    "ActionRequest",
    "ActionRequirements",
    "ActionVerificationResult",
    "ActiveRiskClass",
    "ApplicabilityResult",
    "ApplicabilityStatus",
    "AttemptStatus",
    "CheckStatus",
    "CleanupStatus",
    "OutcomeStatus",
    "PolicyDenial",
    "VerificationStatus",
]
