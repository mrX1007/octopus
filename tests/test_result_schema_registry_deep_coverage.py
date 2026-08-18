"""Unit tests for result_schema_registry.py."""

from __future__ import annotations

import pytest

from core.actions.provider_results import (
    ArtifactProviderResult,
    CredentialProviderResult,
    ProviderProvenanceV2,
    ProviderResultKind,
)
from core.actions.result_schema_registry import (
    DuplicateResultSchemaRegistration,
    InvalidResultSchemaBinding,
    ProviderResultPublicationBindingV2,
    ProviderResultSchemaRegistry,
    ResultSchemaBindingMismatch,
    ResultSchemaNotRegistered,
    ResultVariantNotAllowed,
    get_provider_result_schema_registry,
)

pytestmark = pytest.mark.unit


def test_registry_lookup_and_errors():
    reg = get_provider_result_schema_registry()

    # Not registered
    with pytest.raises(ResultSchemaNotRegistered):
        reg.require_publication_binding(
            action_id="nonexistent_action",
            result_schema_id="nonexistent_schema",
        )

    # Mismatch (action exists, schema belongs to another action)
    with pytest.raises(ResultSchemaBindingMismatch):
        reg.require_publication_binding(
            action_id="plugin:payload_keying",
            result_schema_id="octopus:result:kerberos_crack_tickets:2.0",
        )

    # Variant not allowed (wrong result type)
    cred_result = object.__new__(CredentialProviderResult)
    object.__setattr__(cred_result, "result_kind", ProviderResultKind.CREDENTIAL)

    with pytest.raises(ResultVariantNotAllowed):
        reg.validate_result(
            action_id="plugin:payload_keying",
            result_schema_id="octopus:result:payload_keying:2.0",
            provider_result=cred_result,
        )


def test_custom_registry_validation_errors():
    # Empty IDs
    binding_empty = ProviderResultPublicationBindingV2(
        action_id="",
        result_schema_id="s1",
        allowed_result_kinds=(ProviderResultKind.ARTIFACT,),
        allowed_runtime_type_ids=("ArtifactProviderResult",),
        projector_id="provider-result-projector-v2",
        binding_digest="sha256:d",
    )
    with pytest.raises(InvalidResultSchemaBinding, match="result_publication_binding_has_empty_id"):
        ProviderResultSchemaRegistry(bindings=(binding_empty,))

    # No variants
    binding_no_var = ProviderResultPublicationBindingV2(
        action_id="a1",
        result_schema_id="s1",
        allowed_result_kinds=(),
        allowed_runtime_type_ids=(),
        projector_id="provider-result-projector-v2",
        binding_digest="sha256:d",
    )
    with pytest.raises(InvalidResultSchemaBinding, match="result_publication_binding_has_no_variants"):
        ProviderResultSchemaRegistry(bindings=(binding_no_var,))

    # Duplicate kind
    binding_dup_kind = ProviderResultPublicationBindingV2(
        action_id="a1",
        result_schema_id="s1",
        allowed_result_kinds=(ProviderResultKind.ARTIFACT, ProviderResultKind.ARTIFACT),
        allowed_runtime_type_ids=("ArtifactProviderResult", "ArtifactProviderResult"),
        projector_id="provider-result-projector-v2",
        binding_digest="sha256:d",
    )
    with pytest.raises(InvalidResultSchemaBinding, match="result_publication_binding_duplicate_kind"):
        ProviderResultSchemaRegistry(bindings=(binding_dup_kind,))

    # Type kind mismatch
    binding_mismatch = ProviderResultPublicationBindingV2(
        action_id="a1",
        result_schema_id="s1",
        allowed_result_kinds=(ProviderResultKind.ARTIFACT,),
        allowed_runtime_type_ids=("CredentialProviderResult",),
        projector_id="provider-result-projector-v2",
        binding_digest="sha256:d",
    )
    with pytest.raises(InvalidResultSchemaBinding, match="result_publication_binding_type_kind_mismatch"):
        ProviderResultSchemaRegistry(bindings=(binding_mismatch,))

    # Unknown pair
    binding_unknown = ProviderResultPublicationBindingV2(
        action_id="unknown:action",
        result_schema_id="unknown:schema",
        allowed_result_kinds=(ProviderResultKind.ARTIFACT,),
        allowed_runtime_type_ids=("ArtifactProviderResult",),
        projector_id="provider-result-projector-v2",
        binding_digest="sha256:d",
    )
    with pytest.raises(InvalidResultSchemaBinding, match="result_publication_binding_unknown_pair"):
        ProviderResultSchemaRegistry(bindings=(binding_unknown,))

    # Projector mismatch
    binding_bad_proj = ProviderResultPublicationBindingV2(
        action_id="plugin:payload_keying",
        result_schema_id="octopus:result:payload_keying:2.0",
        allowed_result_kinds=(ProviderResultKind.ARTIFACT,),
        allowed_runtime_type_ids=("ArtifactProviderResult",),
        projector_id="wrong_projector",
        binding_digest="sha256:d",
    )
    with pytest.raises(InvalidResultSchemaBinding, match="result_publication_binding_projector_mismatch"):
        ProviderResultSchemaRegistry(bindings=(binding_bad_proj,))
