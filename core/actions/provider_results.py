"""Closed provider-result contracts for the V2 execution boundary.

The types in this module are transaction-private. They describe drafts staged
by an executor-owned facade; they are not public execution reports and they do
not contain raw backend output.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Protocol, Union, runtime_checkable

from typing_extensions import TypeAlias

from core.actions.execution_results_v2 import ExecutionResultRefV2, ExecutionStatusV2
from core.actions.provider_participants import ParticipantRegistrationRefV2
from core.actions.reference_types import ArtifactKind
from core.actions.sensitive_integrity import SensitiveIntegrityTagV2


class ProviderOutcomeV2(str, Enum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class ProviderResultKind(str, Enum):
    OPERATION = "operation"
    ARTIFACT = "artifact"
    CREDENTIAL = "credential"
    SESSION = "session"
    ROUTE = "route"
    C2_RESOURCE = "c2_resource"
    COMPOSITE = "composite"
    SENSITIVE = "sensitive"


class PartialCommitDispositionV2(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"


class _ProviderOutcomeNormalizationConstructionTokenV2:
    pass


@dataclass(frozen=True, init=False)
class ProviderOutcomeNormalizationV2:
    provider_outcome: ProviderOutcomeV2
    execution_status: ExecutionStatusV2
    commit_eligible: bool
    partial_disposition: PartialCommitDispositionV2 | None

    @classmethod
    def _from_normalizer(
        cls,
        *,
        _token: _ProviderOutcomeNormalizationConstructionTokenV2,
        provider_outcome: ProviderOutcomeV2,
        execution_status: ExecutionStatusV2,
        commit_eligible: bool,
        partial_disposition: PartialCommitDispositionV2 | None,
    ) -> ProviderOutcomeNormalizationV2:
        if not isinstance(_token, _ProviderOutcomeNormalizationConstructionTokenV2):
            raise TypeError("provider_outcome_normalization_construction_denied")
        instance = object.__new__(cls)
        object.__setattr__(instance, "provider_outcome", provider_outcome)
        object.__setattr__(instance, "execution_status", execution_status)
        object.__setattr__(instance, "commit_eligible", commit_eligible)
        object.__setattr__(instance, "partial_disposition", partial_disposition)
        return instance


@dataclass(frozen=True)
class PartialCommitRuleV2:
    action_id: str
    result_kind: ProviderResultKind
    accepted_reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_non_empty("action_id", self.action_id)
        _require_unique_non_empty("accepted_reason_codes", self.accepted_reason_codes)


@dataclass(frozen=True)
class PartialCommitPolicySnapshotV2:
    policy_id: str
    revision: int
    rules: tuple[PartialCommitRuleV2, ...]
    policy_digest: str

    def __post_init__(self) -> None:
        _require_non_empty("policy_id", self.policy_id)
        if self.revision < 1:
            raise ValueError("partial_commit_policy_revision_invalid")
        keys = tuple((rule.action_id, rule.result_kind) for rule in self.rules)
        if len(keys) != len(set(keys)):
            raise ValueError("partial_commit_policy_duplicate_rule")


def canonical_partial_commit_policy_digest(
    snapshot: PartialCommitPolicySnapshotV2,
) -> str:
    """Return the canonical digest, excluding ``policy_digest`` itself."""

    payload = {
        "schema": "partial-commit-policy/2.0",
        "policy_id": snapshot.policy_id,
        "revision": snapshot.revision,
        "rules": [
            {
                "action_id": rule.action_id,
                "result_kind": rule.result_kind.value,
                "accepted_reason_codes": list(rule.accepted_reason_codes),
            }
            for rule in snapshot.rules
        ],
    }
    return _sha256_canonical_json(payload)


@runtime_checkable
class PartialCommitPolicyRegistryV2(Protocol):
    def require_current(self, action_id: str) -> PartialCommitPolicySnapshotV2: ...

    def assert_current(self, snapshot: PartialCommitPolicySnapshotV2) -> None: ...


@runtime_checkable
class PartialCommitPolicyV2(Protocol):
    def decide(
        self,
        *,
        snapshot: PartialCommitPolicySnapshotV2,
        action_id: str,
        result_kind: ProviderResultKind,
        reason_codes: tuple[str, ...],
    ) -> PartialCommitDispositionV2: ...


class ProviderOutcomeNormalizerV2:
    """Sole constructor for the closed provider-outcome normalization matrix."""

    def __init__(
        self,
        *,
        policy: PartialCommitPolicyV2,
        registry: PartialCommitPolicyRegistryV2,
    ) -> None:
        self._construction_token = _ProviderOutcomeNormalizationConstructionTokenV2()
        self._policy = policy
        self._registry = registry

    def normalize(
        self,
        *,
        action_id: str,
        result_kind: ProviderResultKind,
        outcome: ProviderOutcomeV2,
        reason_codes: tuple[str, ...],
        partial_policy: PartialCommitPolicySnapshotV2,
    ) -> ProviderOutcomeNormalizationV2:
        _require_non_empty("action_id", action_id)
        _require_unique_non_empty("reason_codes", reason_codes, allow_empty=True)
        if partial_policy.policy_digest != canonical_partial_commit_policy_digest(partial_policy):
            raise ValueError("partial_commit_policy_digest_mismatch")

        partial_disposition: PartialCommitDispositionV2 | None = None
        if outcome is ProviderOutcomeV2.SUCCEEDED:
            execution_status = ExecutionStatusV2.SUCCEEDED
            commit_eligible = True
        elif outcome is ProviderOutcomeV2.PARTIAL:
            partial_disposition = self._policy.decide(
                snapshot=partial_policy,
                action_id=action_id,
                result_kind=result_kind,
                reason_codes=reason_codes,
            )
            commit_eligible = partial_disposition is PartialCommitDispositionV2.ACCEPT
            execution_status = ExecutionStatusV2.PARTIAL if commit_eligible else ExecutionStatusV2.FAILED
        elif outcome is ProviderOutcomeV2.FAILED:
            execution_status = ExecutionStatusV2.FAILED
            commit_eligible = False
        elif outcome is ProviderOutcomeV2.UNAVAILABLE:
            execution_status = ExecutionStatusV2.UNAVAILABLE
            commit_eligible = False
        elif outcome is ProviderOutcomeV2.TIMED_OUT:
            execution_status = ExecutionStatusV2.TIMED_OUT
            commit_eligible = False
        elif outcome is ProviderOutcomeV2.CANCELLED:
            execution_status = ExecutionStatusV2.CANCELLED
            commit_eligible = False
        else:  # pragma: no cover - Enum exhaustiveness guard
            raise TypeError("unknown_provider_outcome")

        self._registry.assert_current(partial_policy)
        return ProviderOutcomeNormalizationV2._from_normalizer(
            _token=self._construction_token,
            provider_outcome=outcome,
            execution_status=execution_status,
            commit_eligible=commit_eligible,
            partial_disposition=partial_disposition,
        )


class ManagedResourceKind(str, Enum):
    SESSION = "session"
    PIVOT_ROUTE = "pivot_route"
    C2_CHANNEL = "c2_channel"
    C2_ENROLLMENT = "c2_enrollment"
    C2_AGENT = "c2_agent"
    C2_TASK = "c2_task"
    DEPLOYMENT = "deployment"


@dataclass(frozen=True)
class ProviderProvenanceV2:
    implementation_id: str
    implementation_version: str
    request_digest: str
    started_at: float
    completed_at: float

    def __post_init__(self) -> None:
        _require_non_empty("implementation_id", self.implementation_id)
        _require_non_empty("implementation_version", self.implementation_version)
        _require_non_empty("request_digest", self.request_digest)
        if not math.isfinite(self.started_at) or not math.isfinite(self.completed_at):
            raise ValueError("provider_provenance_timestamp_not_finite")
        if self.started_at < 0 or self.completed_at < self.started_at:
            raise ValueError("provider_provenance_timestamp_invalid")


@dataclass(frozen=True)
class ProviderResultHeaderV2:
    schema_version: Literal["2.0"]
    provider_id: str
    outcome: ProviderOutcomeV2
    reason_codes: tuple[str, ...]
    duration_ms: int
    provenance: ProviderProvenanceV2

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("provider_result_schema_version_invalid")
        _require_non_empty("provider_id", self.provider_id)
        _require_unique_non_empty("reason_codes", self.reason_codes, allow_empty=True)
        if type(self.outcome) is not ProviderOutcomeV2:
            raise ValueError("provider_result_outcome_invalid")
        if type(self.duration_ms) is not int or self.duration_ms < 0:
            raise ValueError("provider_result_duration_invalid")


@runtime_checkable
class ProviderResultFoundationV2(Protocol):
    @property
    def header(self) -> ProviderResultHeaderV2: ...


@dataclass(frozen=True)
class ObservationDraftRefV2:
    transaction_id: str
    draft_id: str
    observation_schema_id: str
    payload_digest: str


@dataclass(frozen=True)
class NonSensitiveArtifactDraftRefV2:
    transaction_id: str
    draft_id: str
    artifact_kind: ArtifactKind
    content_digest: str
    size: int
    media_type: str
    target: str | None


@dataclass(frozen=True)
class SensitiveArtifactDraftRefV2:
    transaction_id: str
    draft_id: str
    artifact_kind: ArtifactKind
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    size: int
    media_type: str
    target: str | None


ArtifactDraftRefV2: TypeAlias = Union[
    NonSensitiveArtifactDraftRefV2,
    SensitiveArtifactDraftRefV2,
]


@dataclass(frozen=True)
class ManagedResourceDraftRefV2:
    transaction_id: str
    draft_id: str
    resource_kind: ManagedResourceKind
    target: str | None
    lifecycle_owner: str
    close_action_id: str | None
    expires_at: float | None


class SensitiveHandleStateV2(str, Enum):
    OPEN = "open"
    STAGING = "staging"
    CONSUMED = "consumed"
    CLEARED = "cleared"


@dataclass(frozen=True)
class SensitiveBatchDraftRefV2:
    transaction_id: str
    draft_id: str
    schema_id: str
    factory_id: str
    factory_provenance_digest: str
    source_handle_id: str
    item_count: int
    integrity_tag: SensitiveIntegrityTagV2
    total_bytes: int


@runtime_checkable
class SensitiveObservationHandleV2(Protocol):
    @property
    def schema_id(self) -> str: ...

    @property
    def transaction_id(self) -> str: ...

    @property
    def factory_id(self) -> str: ...

    @property
    def factory_provenance_digest(self) -> str: ...

    @property
    def handle_id(self) -> str: ...

    @property
    def state(self) -> SensitiveHandleStateV2: ...

    @property
    def item_count(self) -> int: ...

    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...

    @property
    def total_bytes(self) -> int: ...

    def clear(self) -> None: ...


@dataclass(frozen=True, repr=False)
class SensitiveBatchHandleV2:
    schema_id: str
    transaction_id: str
    factory_id: str
    factory_provenance_digest: str
    handle_id: str
    item_count: int
    integrity_tag: SensitiveIntegrityTagV2
    total_bytes: int
    handle: SensitiveObservationHandleV2 = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.handle, SensitiveObservationHandleV2):
            raise TypeError("sensitive_batch_handle_implementation_invalid")
        if (
            self.schema_id != self.handle.schema_id
            or self.transaction_id != self.handle.transaction_id
            or self.factory_id != self.handle.factory_id
            or self.factory_provenance_digest != self.handle.factory_provenance_digest
            or self.handle_id != self.handle.handle_id
            or self.item_count != self.handle.item_count
            or self.total_bytes != self.handle.total_bytes
            or self.integrity_tag.domain != self.handle.integrity_tag.domain
            or self.integrity_tag.key_id != self.handle.integrity_tag.key_id
            or self.integrity_tag.algorithm != self.handle.integrity_tag.algorithm
            or not hmac.compare_digest(
                self.integrity_tag.tag,
                self.handle.integrity_tag.tag,
            )
        ):
            raise ValueError("sensitive_batch_handle_metadata_mismatch")
        if type(self.item_count) is not int or self.item_count < 0:
            raise ValueError("sensitive_batch_handle_item_count_invalid")
        if type(self.total_bytes) is not int or self.total_bytes < 0:
            raise ValueError("sensitive_batch_handle_total_bytes_invalid")

    def __repr__(self) -> str:
        return "SensitiveBatchHandleV2(<redacted>)"


@dataclass(frozen=True)
class ParticipantPayloadDraftRefV2:
    transaction_id: str
    draft_id: str
    payload_schema_id: str
    payload_digest: str


@dataclass(frozen=True)
class StagedObservationV2:
    observation_draft_ref: ObservationDraftRefV2
    registration_ref: ParticipantRegistrationRefV2


@dataclass(frozen=True)
class StagedArtifactV2:
    artifact_draft_ref: ArtifactDraftRefV2
    registration_ref: ParticipantRegistrationRefV2


@dataclass(frozen=True)
class ExternalEffectRegistrationResultV2:
    registration_ref: ParticipantRegistrationRefV2
    resource_draft_ref: ManagedResourceDraftRefV2 | None
    effect_plan_ref: ParticipantPayloadDraftRefV2
    result_kind: Literal["external_effect"] = field(default="external_effect", init=False)


@dataclass(frozen=True)
class C2ArtifactStageReceiptV1:
    transaction_id: str
    artifact_draft_ref: SensitiveArtifactDraftRefV2
    artifact_participant_registration_ref: ParticipantRegistrationRefV2
    deployment_ref: str
    enrollment_ref: str
    channel_ref: str
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    artifact_binding_digest: str


@dataclass(frozen=True)
class OperationProviderResult:
    header: ProviderResultHeaderV2
    observations: tuple[StagedObservationV2, ...]
    effect_registration: ExternalEffectRegistrationResultV2 | None = None
    result_kind: Literal[ProviderResultKind.OPERATION] = field(
        default=ProviderResultKind.OPERATION,
        init=False,
    )


@dataclass(frozen=True)
class ArtifactProviderResult:
    header: ProviderResultHeaderV2
    artifacts: tuple[StagedArtifactV2, ...]
    result_kind: Literal[ProviderResultKind.ARTIFACT] = field(
        default=ProviderResultKind.ARTIFACT,
        init=False,
    )


@dataclass(frozen=True, repr=False)
class CredentialProviderResult:
    header: ProviderResultHeaderV2
    credential_batch: SensitiveBatchHandleV2 = field(repr=False, compare=False)
    result_kind: Literal[ProviderResultKind.CREDENTIAL] = field(
        default=ProviderResultKind.CREDENTIAL,
        init=False,
    )

    def __repr__(self) -> str:
        return "CredentialProviderResult(<redacted>)"

    def __reduce__(self) -> str:
        raise TypeError("sensitive_provider_result_is_not_serializable")


@dataclass(frozen=True)
class SessionProviderResult:
    header: ProviderResultHeaderV2
    session: ManagedResourceDraftRefV2
    observations: tuple[StagedObservationV2, ...] = ()
    result_kind: Literal[ProviderResultKind.SESSION] = field(
        default=ProviderResultKind.SESSION,
        init=False,
    )

    def __post_init__(self) -> None:
        if self.session.resource_kind is not ManagedResourceKind.SESSION:
            raise ValueError("session_provider_result_resource_kind_mismatch")


@dataclass(frozen=True)
class RouteProviderResult:
    header: ProviderResultHeaderV2
    route: ManagedResourceDraftRefV2
    observations: tuple[StagedObservationV2, ...] = ()
    result_kind: Literal[ProviderResultKind.ROUTE] = field(
        default=ProviderResultKind.ROUTE,
        init=False,
    )

    def __post_init__(self) -> None:
        if self.route.resource_kind is not ManagedResourceKind.PIVOT_ROUTE:
            raise ValueError("route_provider_result_resource_kind_mismatch")


_C2_RESOURCE_KINDS = frozenset(
    {
        ManagedResourceKind.C2_CHANNEL,
        ManagedResourceKind.C2_ENROLLMENT,
        ManagedResourceKind.C2_AGENT,
        ManagedResourceKind.C2_TASK,
        ManagedResourceKind.DEPLOYMENT,
    }
)


@dataclass(frozen=True)
class C2ProviderResult:
    header: ProviderResultHeaderV2
    resources: tuple[ManagedResourceDraftRefV2, ...]
    artifacts: tuple[StagedArtifactV2 | C2ArtifactStageReceiptV1, ...] = ()
    observations: tuple[StagedObservationV2, ...] = ()
    result_kind: Literal[ProviderResultKind.C2_RESOURCE] = field(
        default=ProviderResultKind.C2_RESOURCE,
        init=False,
    )

    def __post_init__(self) -> None:
        if any(resource.resource_kind not in _C2_RESOURCE_KINDS for resource in self.resources):
            raise ValueError("c2_provider_result_resource_kind_mismatch")


@dataclass(frozen=True)
class CompositeProviderResult:
    header: ProviderResultHeaderV2
    child_action_id: str
    child_execution_id: str
    child_result_ref: ExecutionResultRefV2
    result_kind: Literal[ProviderResultKind.COMPOSITE] = field(
        default=ProviderResultKind.COMPOSITE,
        init=False,
    )


@dataclass(frozen=True, repr=False)
class SensitiveProviderResult:
    header: ProviderResultHeaderV2
    sensitive_batch: SensitiveBatchHandleV2 = field(repr=False, compare=False)
    artifacts: tuple[StagedArtifactV2, ...] = ()
    result_kind: Literal[ProviderResultKind.SENSITIVE] = field(
        default=ProviderResultKind.SENSITIVE,
        init=False,
    )

    def __repr__(self) -> str:
        return "SensitiveProviderResult(<redacted>)"

    def __reduce__(self) -> str:
        raise TypeError("sensitive_provider_result_is_not_serializable")


RemoteAuthProviderResultV2: TypeAlias = Union[
    OperationProviderResult,
    SessionProviderResult,
]

ProviderResult: TypeAlias = Union[
    OperationProviderResult,
    ArtifactProviderResult,
    CredentialProviderResult,
    SessionProviderResult,
    RouteProviderResult,
    C2ProviderResult,
    CompositeProviderResult,
    SensitiveProviderResult,
]


def _require_non_empty(field_name: str, value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name}_must_be_non_empty")


def _require_unique_non_empty(
    field_name: str,
    values: tuple[str, ...],
    *,
    allow_empty: bool = False,
) -> None:
    if not allow_empty and not values:
        raise ValueError(f"{field_name}_must_be_non_empty")
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError(f"{field_name}_contains_empty_value")
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name}_contains_duplicates")


def _sha256_canonical_json(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


__all__ = [
    "ArtifactDraftRefV2",
    "ArtifactKind",
    "ArtifactProviderResult",
    "C2ArtifactStageReceiptV1",
    "C2ProviderResult",
    "CompositeProviderResult",
    "CredentialProviderResult",
    "ExternalEffectRegistrationResultV2",
    "ManagedResourceDraftRefV2",
    "ManagedResourceKind",
    "NonSensitiveArtifactDraftRefV2",
    "ObservationDraftRefV2",
    "OperationProviderResult",
    "PartialCommitDispositionV2",
    "PartialCommitPolicyRegistryV2",
    "PartialCommitPolicySnapshotV2",
    "PartialCommitPolicyV2",
    "PartialCommitRuleV2",
    "ParticipantPayloadDraftRefV2",
    "ProviderOutcomeNormalizationV2",
    "ProviderOutcomeNormalizerV2",
    "ProviderOutcomeV2",
    "ProviderProvenanceV2",
    "ProviderResult",
    "ProviderResultFoundationV2",
    "ProviderResultHeaderV2",
    "ProviderResultKind",
    "RemoteAuthProviderResultV2",
    "RouteProviderResult",
    "SensitiveArtifactDraftRefV2",
    "SensitiveBatchDraftRefV2",
    "SensitiveBatchHandleV2",
    "SensitiveHandleStateV2",
    "SensitiveObservationHandleV2",
    "SensitiveProviderResult",
    "SessionProviderResult",
    "StagedArtifactV2",
    "StagedObservationV2",
    "canonical_partial_commit_policy_digest",
]
