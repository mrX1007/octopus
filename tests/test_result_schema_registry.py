"""Exact ProviderResultSchemaRegistry tests for the PR-7 matrix."""

from __future__ import annotations

from dataclasses import replace

import pytest

from core.actions.provider_results import (
    ArtifactProviderResult,
    ManagedResourceDraftRefV2,
    ManagedResourceKind,
    OperationProviderResult,
    ProviderOutcomeV2,
    ProviderProvenanceV2,
    ProviderResultHeaderV2,
    ProviderResultKind,
    SessionProviderResult,
)
from core.actions.result_schema_registry import (
    DuplicateResultSchemaRegistration,
    InvalidResultSchemaBinding,
    ProviderResultSchemaRegistry,
    ResultSchemaBindingMismatch,
    ResultSchemaNotRegistered,
    ResultVariantNotAllowed,
    canonical_provider_result_publication_binding_digest,
    canonical_provider_result_publication_bindings,
    get_provider_result_schema_registry,
)
from core.actions.schema_bindings import get_all_v2_schema_bindings

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


def _session_result() -> SessionProviderResult:
    return SessionProviderResult(
        header=_header(),
        session=ManagedResourceDraftRefV2(
            transaction_id="tx-1",
            draft_id="session-1",
            resource_kind=ManagedResourceKind.SESSION,
            target="host.example",
            lifecycle_owner="executor",
            close_action_id="session:close",
            expires_at=None,
        ),
    )


def test_result_schema_registry_has_20_entries() -> None:
    registry = get_provider_result_schema_registry()
    assert len(registry) == 20
    assert len(registry.publication_bindings()) == 20


def test_result_schema_matrix_matches_registry() -> None:
    registry_rows = {
        (binding.action_id, binding.result_schema_id)
        for binding in get_provider_result_schema_registry().publication_bindings()
    }
    schema_rows = {(binding.action_id, binding.result_schema_id) for binding in get_all_v2_schema_bindings()}
    assert registry_rows == schema_rows


def test_each_v2_action_has_registered_result_schema() -> None:
    registry = get_provider_result_schema_registry()
    for schema_binding in get_all_v2_schema_bindings():
        publication = registry.require_publication_binding(
            action_id=schema_binding.action_id,
            result_schema_id=schema_binding.result_schema_id,
        )
        assert publication.action_id == schema_binding.action_id
        assert publication.result_schema_id == schema_binding.result_schema_id
        assert publication.binding_digest == canonical_provider_result_publication_binding_digest(publication)


def test_registry_contains_exact_result_variant_matrix() -> None:
    actual = {
        binding.action_id: (binding.allowed_result_kinds, binding.allowed_runtime_type_ids)
        for binding in get_provider_result_schema_registry().publication_bindings()
    }
    assert actual["plugin:payload_keying"] == (
        (ProviderResultKind.ARTIFACT,),
        ("ArtifactProviderResult",),
    )
    assert actual["killchain:kerberos_crack_tickets"] == (
        (ProviderResultKind.CREDENTIAL,),
        ("CredentialProviderResult",),
    )
    assert actual["killchain:ad_pass_the_ticket"] == (
        (ProviderResultKind.OPERATION, ProviderResultKind.SESSION),
        ("OperationProviderResult", "SessionProviderResult"),
    )
    assert actual["killchain:ad_dump_lsass"] == (
        (ProviderResultKind.SENSITIVE,),
        ("SensitiveProviderResult",),
    )
    assert actual["killchain:ad_remote_execution"] == (
        (ProviderResultKind.COMPOSITE,),
        ("CompositeProviderResult",),
    )
    assert actual["killchain:pivot_remote_forward"] == (
        (ProviderResultKind.ROUTE,),
        ("RouteProviderResult",),
    )
    assert actual["c2:c2_task"] == (
        (ProviderResultKind.C2_RESOURCE,),
        ("C2ProviderResult",),
    )
    assert actual["c2:c2_cleanup"] == (
        (ProviderResultKind.OPERATION,),
        ("OperationProviderResult",),
    )


def test_unknown_result_schema_id_denied() -> None:
    with pytest.raises(ResultSchemaNotRegistered):
        get_provider_result_schema_registry().require_publication_binding(
            action_id="plugin:unknown",
            result_schema_id="octopus:result:unknown:2.0",
        )


def test_result_schema_id_mismatch_denied() -> None:
    with pytest.raises(ResultSchemaBindingMismatch):
        get_provider_result_schema_registry().require_publication_binding(
            action_id="plugin:payload_keying",
            result_schema_id="octopus:result:kerberos_extract_tickets:2.0",
        )


def test_duplicate_result_schema_registration_denied() -> None:
    binding = canonical_provider_result_publication_bindings()[0]
    with pytest.raises(DuplicateResultSchemaRegistration):
        ProviderResultSchemaRegistry((binding, binding))


def test_tampered_binding_digest_denied() -> None:
    binding = canonical_provider_result_publication_bindings()[0]
    with pytest.raises(InvalidResultSchemaBinding, match="digest"):
        ProviderResultSchemaRegistry((replace(binding, binding_digest="sha256:forged"),))


def test_canonical_pair_with_wrong_variant_denied_even_with_valid_digest() -> None:
    binding = canonical_provider_result_publication_bindings()[0]
    forged = replace(
        binding,
        allowed_result_kinds=(ProviderResultKind.OPERATION,),
        allowed_runtime_type_ids=("OperationProviderResult",),
        binding_digest="",
    )
    forged = replace(
        forged,
        binding_digest=canonical_provider_result_publication_binding_digest(forged),
    )
    with pytest.raises(InvalidResultSchemaBinding, match="variant_mismatch"):
        ProviderResultSchemaRegistry((forged,))


def test_result_runtime_variant_mismatch_denied() -> None:
    with pytest.raises(ResultVariantNotAllowed):
        get_provider_result_schema_registry().validate_result(
            action_id="plugin:payload_keying",
            result_schema_id="octopus:result:payload_keying:2.0",
            provider_result=OperationProviderResult(header=_header(), observations=()),
        )


def test_remote_auth_result_allows_only_operation_or_session() -> None:
    registry = get_provider_result_schema_registry()
    kwargs = {
        "action_id": "killchain:ad_pass_the_ticket",
        "result_schema_id": "octopus:result:ad_pass_the_ticket:2.0",
    }
    registry.validate_result(
        **kwargs,
        provider_result=OperationProviderResult(header=_header(), observations=()),
    )
    registry.validate_result(**kwargs, provider_result=_session_result())
    with pytest.raises(ResultVariantNotAllowed):
        registry.validate_result(
            **kwargs,
            provider_result=ArtifactProviderResult(header=_header(), artifacts=()),
        )


def test_raw_backend_result_requires_decoder() -> None:
    registry = get_provider_result_schema_registry()
    assert not hasattr(registry, "get_decoder")
    assert not hasattr(registry, "register_decoder")
    with pytest.raises(ResultVariantNotAllowed):
        registry.validate_result(
            action_id="plugin:payload_keying",
            result_schema_id="octopus:result:payload_keying:2.0",
            provider_result={},  # type: ignore[arg-type]
        )


def test_provider_result_subclasses_are_denied() -> None:
    class ForgedArtifactResult(ArtifactProviderResult):
        pass

    result = ForgedArtifactResult(header=_header(), artifacts=())
    with pytest.raises(ResultVariantNotAllowed):
        get_provider_result_schema_registry().validate_result(
            action_id="plugin:payload_keying",
            result_schema_id="octopus:result:payload_keying:2.0",
            provider_result=result,
        )
