"""PR-5 Module: Provider call types, phases, outcomes, and plans (§8.6)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal


class ProviderCallPhaseV2(str, Enum):
    CHECK = "check"
    EXECUTE = "execute"
    VERIFY = "verify"
    ROUTE = "route"


class ProviderTerminationReasonV2(str, Enum):
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    PROCESS_ERROR = "process_error"
    EXCEPTION = "exception"


@dataclass(frozen=True)
class ProviderPhaseCallPlanV2:
    execution_id: str
    action_id: str
    phase: ProviderCallPhaseV2
    timeout_seconds: float
    max_output_bytes: int
    sandbox_profile: str = "default"

    def canonical_digest(self) -> str:
        payload = {
            "execution_id": self.execution_id,
            "action_id": self.action_id,
            "phase": self.phase.value,
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "sandbox_profile": self.sandbox_profile,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"sha256:{hashlib.sha256(raw).hexdigest()}"


@dataclass(frozen=True)
class ProviderCallOutcomeV2:
    execution_id: str
    action_id: str
    phase: ProviderCallPhaseV2
    termination_reason: ProviderTerminationReasonV2
    duration_seconds: float
    raw_output_bytes_count: int
    redacted_error: str | None = None
    outcome_digest: str = ""

    def __post_init__(self) -> None:
        if not self.outcome_digest:
            payload = {
                "execution_id": self.execution_id,
                "action_id": self.action_id,
                "phase": self.phase.value,
                "termination_reason": self.termination_reason.value,
                "duration_seconds": self.duration_seconds,
                "raw_output_bytes_count": self.raw_output_bytes_count,
                "redacted_error": self.redacted_error,
            }
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            object.__setattr__(self, "outcome_digest", f"sha256:{hashlib.sha256(raw).hexdigest()}")


__all__ = [
    "ProviderCallOutcomeV2",
    "ProviderCallPhaseV2",
    "ProviderPhaseCallPlanV2",
    "ProviderTerminationReasonV2",
]
