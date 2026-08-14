"""Exact closed ProviderResult variant tests from PR-7."""

from __future__ import annotations

import json
import pickle
from dataclasses import asdict, fields
from typing import get_args

import pytest

from core.actions.execution_commit_participants import ParticipantKindV2
from core.actions.execution_results_v2 import ExecutionResultRefV2
from core.actions.provider_participants import ParticipantRegistrationRefV2
from core.actions.provider_results import (
    ArtifactKind,
    ArtifactProviderResult,
    C2ProviderResult,
    CompositeProviderResult,
    CredentialProviderResult,
    ManagedResourceDraftRefV2,
    ManagedResourceKind,
    NonSensitiveArtifactDraftRefV2,
    OperationProviderResult,
    ProviderOutcomeV2,
    ProviderProvenanceV2,
    ProviderResult,
    ProviderResultHeaderV2,
    ProviderResultKind,
    RemoteAuthProviderResultV2,
    RouteProviderResult,
    SensitiveBatchHandleV2,
    SensitiveHandleStateV2,
    SensitiveProviderResult,
    SessionProviderResult,
    StagedArtifactV2,
)
from core.actions.sensitive_integrity import SensitiveIntegrityTagV2

pytestmark = pytest.mark.unit


def _header() -> ProviderResultHeaderV2:
    return ProviderResultHeaderV2(
        schema_version="2.0",
        provider_id="provider:test",
        outcome=ProviderOutcomeV2.SUCCEEDED,
        reason_codes=(),
        duration_ms=1,
        provenance=ProviderProvenanceV2(
            implementation_id="provider:test",
            implementation_version="1.0.0",
            request_digest="sha256:request",
            started_at=1.0,
            completed_at=1.001,
        ),
    )


def _registration() -> ParticipantRegistrationRefV2:
    return ParticipantRegistrationRefV2(
        registration_id="reg-1",
        participant_id="artifact-store",
        kind=ParticipantKindV2.LOCAL_STORE,
        registration_digest="sha256:registration",
    )


def _staged_artifact() -> StagedArtifactV2:
    return StagedArtifactV2(
        artifact_draft_ref=NonSensitiveArtifactDraftRefV2(
            transaction_id="tx-1",
            draft_id="artifact-1",
            artifact_kind=ArtifactKind.GENERIC,
            content_digest="sha256:artifact",
            size=4,
            media_type="application/octet-stream",
            target=None,
        ),
        registration_ref=_registration(),
    )


class _OpaqueSensitiveHandle:
    schema_id = "octopus:sensitive:test:2.0"
    transaction_id = "tx-1"
    factory_id = "factory-1"
    factory_provenance_digest = "sha256:factory"
    handle_id = "handle-1"
    state = SensitiveHandleStateV2.OPEN
    item_count = 1
    integrity_tag = SensitiveIntegrityTagV2(
        key_id="key-1",
        algorithm="hmac-sha256-v2",
        domain="test",
        tag="tag",
    )
    total_bytes = 8

    def clear(self) -> None:
        self.state = SensitiveHandleStateV2.CLEARED


def _sensitive_batch() -> SensitiveBatchHandleV2:
    handle = _OpaqueSensitiveHandle()
    return SensitiveBatchHandleV2(
        schema_id=handle.schema_id,
        transaction_id=handle.transaction_id,
        factory_id=handle.factory_id,
        factory_provenance_digest=handle.factory_provenance_digest,
        handle_id=handle.handle_id,
        item_count=handle.item_count,
        integrity_tag=handle.integrity_tag,
        total_bytes=handle.total_bytes,
        handle=handle,
    )


def _managed_resource(kind: ManagedResourceKind) -> ManagedResourceDraftRefV2:
    return ManagedResourceDraftRefV2(
        transaction_id="tx-1",
        draft_id=f"resource-{kind.value}",
        resource_kind=kind,
        target="host.example",
        lifecycle_owner="executor",
        close_action_id="resource:close",
        expires_at=None,
    )


def _all_variants() -> tuple[ProviderResult, ...]:
    return (
        OperationProviderResult(header=_header(), observations=()),
        ArtifactProviderResult(header=_header(), artifacts=(_staged_artifact(),)),
        CredentialProviderResult(header=_header(), credential_batch=_sensitive_batch()),
        SessionProviderResult(
            header=_header(),
            session=_managed_resource(ManagedResourceKind.SESSION),
        ),
        RouteProviderResult(
            header=_header(),
            route=_managed_resource(ManagedResourceKind.PIVOT_ROUTE),
        ),
        C2ProviderResult(
            header=_header(),
            resources=(_managed_resource(ManagedResourceKind.C2_CHANNEL),),
        ),
        CompositeProviderResult(
            header=_header(),
            child_action_id="killchain:ad_smbexec",
            child_execution_id="execution-child",
            child_result_ref=ExecutionResultRefV2(
                reference="result:child",
                revision=1,
                execution_id="execution-child",
                action_id="killchain:ad_smbexec",
                result_digest="sha256:child",
            ),
        ),
        SensitiveProviderResult(header=_header(), sensitive_batch=_sensitive_batch()),
    )


def test_each_provider_result_variant_has_exact_fields() -> None:
    expected = {
        OperationProviderResult: ("header", "observations", "effect_registration", "result_kind"),
        ArtifactProviderResult: ("header", "artifacts", "result_kind"),
        CredentialProviderResult: ("header", "credential_batch", "result_kind"),
        SessionProviderResult: ("header", "session", "observations", "result_kind"),
        RouteProviderResult: ("header", "route", "observations", "result_kind"),
        C2ProviderResult: ("header", "resources", "artifacts", "observations", "result_kind"),
        CompositeProviderResult: (
            "header",
            "child_action_id",
            "child_execution_id",
            "child_result_ref",
            "result_kind",
        ),
        SensitiveProviderResult: ("header", "sensitive_batch", "artifacts", "result_kind"),
    }
    for result_type, field_names in expected.items():
        assert tuple(field.name for field in fields(result_type)) == field_names
        assert fields(result_type)[-1].init is False


def test_provider_result_kind_matches_runtime_variant() -> None:
    expected = tuple(ProviderResultKind)
    assert tuple(result.result_kind for result in _all_variants()) == expected


def test_remote_auth_result_contract_accepts_only_operation_or_session() -> None:
    assert set(get_args(RemoteAuthProviderResultV2)) == {
        OperationProviderResult,
        SessionProviderResult,
    }


def test_provider_result_union_is_closed_and_exhaustive() -> None:
    assert set(get_args(ProviderResult)) == {
        OperationProviderResult,
        ArtifactProviderResult,
        CredentialProviderResult,
        SessionProviderResult,
        RouteProviderResult,
        C2ProviderResult,
        CompositeProviderResult,
        SensitiveProviderResult,
    }


def test_artifact_provider_result_has_artifacts_tuple_and_no_ticket_ref() -> None:
    result = ArtifactProviderResult(header=_header(), artifacts=(_staged_artifact(),))
    assert isinstance(result.artifacts, tuple)
    assert not hasattr(result, "ticket_ref")


def test_composite_provider_result_has_only_canonical_child_fields() -> None:
    result_type_fields = {field.name for field in fields(CompositeProviderResult)}
    assert result_type_fields == {
        "header",
        "child_action_id",
        "child_execution_id",
        "child_result_ref",
        "result_kind",
    }
    assert result_type_fields.isdisjoint(
        {"approval", "lifecycle", "decision_trace_ref", "parent_execution_id"}
    )


def test_non_sensitive_provider_results_are_json_safe() -> None:
    non_sensitive = (
        OperationProviderResult(header=_header(), observations=()),
        ArtifactProviderResult(header=_header(), artifacts=(_staged_artifact(),)),
        SessionProviderResult(
            header=_header(),
            session=_managed_resource(ManagedResourceKind.SESSION),
        ),
        RouteProviderResult(
            header=_header(),
            route=_managed_resource(ManagedResourceKind.PIVOT_ROUTE),
        ),
        C2ProviderResult(header=_header(), resources=()),
    )
    for result in non_sensitive:
        json.dumps(asdict(result), sort_keys=True)


@pytest.mark.parametrize("result_type", [CredentialProviderResult, SensitiveProviderResult])
def test_sensitive_provider_result_is_not_serializable(result_type: type[object]) -> None:
    kwargs = (
        {"credential_batch": _sensitive_batch()}
        if result_type is CredentialProviderResult
        else {"sensitive_batch": _sensitive_batch()}
    )
    result = result_type(header=_header(), **kwargs)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="not_serializable"):
        pickle.dumps(result)


@pytest.mark.parametrize("result_type", [CredentialProviderResult, SensitiveProviderResult])
def test_sensitive_provider_result_repr_is_redacted(result_type: type[object]) -> None:
    kwargs = (
        {"credential_batch": _sensitive_batch()}
        if result_type is CredentialProviderResult
        else {"sensitive_batch": _sensitive_batch()}
    )
    rendered = repr(result_type(header=_header(), **kwargs))  # type: ignore[call-arg]
    assert "<redacted>" in rendered
    assert "handle-1" not in rendered


def test_sensitive_batch_handle_metadata_mismatch_is_denied() -> None:
    handle = _OpaqueSensitiveHandle()
    with pytest.raises(ValueError, match="metadata_mismatch"):
        SensitiveBatchHandleV2(
            schema_id=handle.schema_id,
            transaction_id="tx-forged",
            factory_id=handle.factory_id,
            factory_provenance_digest=handle.factory_provenance_digest,
            handle_id=handle.handle_id,
            item_count=handle.item_count,
            integrity_tag=handle.integrity_tag,
            total_bytes=handle.total_bytes,
            handle=handle,
        )


def test_session_and_route_results_enforce_resource_kind() -> None:
    with pytest.raises(ValueError, match=r"session.*mismatch"):
        SessionProviderResult(
            header=_header(),
            session=_managed_resource(ManagedResourceKind.PIVOT_ROUTE),
        )
    with pytest.raises(ValueError, match=r"route.*mismatch"):
        RouteProviderResult(
            header=_header(),
            route=_managed_resource(ManagedResourceKind.SESSION),
        )


def test_c2_result_rejects_non_c2_managed_resource() -> None:
    with pytest.raises(ValueError, match=r"c2.*mismatch"):
        C2ProviderResult(
            header=_header(),
            resources=(_managed_resource(ManagedResourceKind.SESSION),),
        )
