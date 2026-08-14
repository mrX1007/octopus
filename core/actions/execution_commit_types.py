"""PR-5 Module: Canonical execution commit types (§8.2)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal


class ExecutionCommitStateV2(str, Enum):
    OPEN = "open"
    PREPARING = "preparing"
    PREPARED = "prepared"
    IN_DOUBT = "in_doubt"
    ABORT_DECIDED = "abort_decided"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    COMMIT_DECIDED = "commit_decided"
    COMMITTING = "committing"
    COMMIT_APPLIED = "commit_applied"
    FINALIZING_VISIBILITY = "finalizing_visibility"
    COMMITTED = "committed"
    FAILED_RECONCILIATION = "failed_reconciliation"


def canonical_execution_commit_decision_binding_digest(
    binding: ExecutionCommitDecisionBindingV2,
) -> str:
    """RFC-8785 execution-commit-decision-binding/1.0, excluding own digest."""
    payload = {
        "schema": "execution-commit-decision-binding/1.0",
        "no_return_admission_reference": binding.no_return_admission_reference,
        "no_return_admission_revision": binding.no_return_admission_revision,
        "no_return_admission_digest": binding.no_return_admission_digest,
        "decision_identity_digest": binding.decision_identity_digest,
        "external_effect_participant_id": binding.external_effect_participant_id,
        "external_effect_registration_digest": binding.external_effect_registration_digest,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


@dataclass(frozen=True)
class ExecutionCommitDecisionBindingV2:
    no_return_admission_reference: str
    no_return_admission_revision: int
    no_return_admission_digest: str
    decision_identity_digest: str
    external_effect_participant_id: str | None
    external_effect_registration_digest: str | None
    binding_digest: str

    def __post_init__(self) -> None:
        if (self.external_effect_participant_id is None) != (
            self.external_effect_registration_digest is None
        ):
            raise ValueError("commit_effect_binding_fields_all_or_none")
        if self.binding_digest != canonical_execution_commit_decision_binding_digest(self):
            raise ValueError("commit_decision_binding_digest_mismatch")


@dataclass(frozen=True)
class ExecutionCommitRecordV2:
    transaction_id: str
    revision: int
    state: ExecutionCommitStateV2
    external_effect_fenced: bool
    decision_digest: str | None
    commit_decision_binding: ExecutionCommitDecisionBindingV2 | None
    updated_at: float

    def __post_init__(self) -> None:
        committed_path_states = {
            ExecutionCommitStateV2.COMMIT_DECIDED,
            ExecutionCommitStateV2.COMMITTING,
            ExecutionCommitStateV2.COMMIT_APPLIED,
            ExecutionCommitStateV2.FINALIZING_VISIBILITY,
            ExecutionCommitStateV2.COMMITTED,
        }
        if self.state in committed_path_states:
            if self.commit_decision_binding is None:
                raise ValueError("commit_state_requires_admission_binding")
            if self.decision_digest != self.commit_decision_binding.binding_digest:
                raise ValueError("commit_decision_digest_mismatch")
        elif self.state is ExecutionCommitStateV2.IN_DOUBT:
            if (self.commit_decision_binding is None) != (self.decision_digest is None):
                raise ValueError("in_doubt_decision_fields_all_or_none")
        elif self.commit_decision_binding is not None or self.decision_digest is not None:
            raise ValueError("precommit_or_abort_state_forbids_decision_binding")


__all__ = [
    "ExecutionCommitDecisionBindingV2",
    "ExecutionCommitRecordV2",
    "ExecutionCommitStateV2",
    "canonical_execution_commit_decision_binding_digest",
]
