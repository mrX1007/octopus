"""Contracts for V12 registration vocabulary and negotiation."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from core.actions.sensitive_integrity_runtime import (
    OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2,
    PersistentSensitiveIntegrityKeyringV2,
)
from core.actions.zeroizable_buffers import OwnedZeroizableSensitiveBufferFactoryV2
from core.c2.agent_protocol_v12 import (
    AgentCapabilitySetV12,
    AgentProtocolNegotiatorV12,
    AgentRegistrationV12,
    compute_capabilities_digest,
)
from core.c2.agent_task_protocol import (
    C2_AGENT_PROTOCOL_V11,
    C2_AGENT_PROTOCOL_V12,
    C2_TASK_SCHEMA_V12,
    AgentPayloadSchemaIdV12,
    AgentResultSchemaIdV12,
)
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.task_catalog import C2TaskOperationId
from core.secrets import OpaqueSecretValueFactoryV2, OpaqueSecretValueV2

pytestmark = pytest.mark.unit


def _capabilities() -> AgentCapabilitySetV12:
    return AgentCapabilitySetV12.create(
        supported_operation_ids=(C2TaskOperationId.IDENTITY,),
        supported_payload_schema_versions=(AgentPayloadSchemaIdV12.IDENTITY_V1,),
        supported_result_schema_versions=(AgentResultSchemaIdV12.IDENTITY_V1,),
    )


def _enrollment_token() -> OpaqueSecretValueV2:
    keyring = PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
        active_key_id="registration-model-test",
        keys={"registration-model-test": bytearray(b"k" * 32)},
    )
    authenticator = OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2().create(
        keyring=keyring,
        provenance_id="registration-model-test",
    )
    buffer = OwnedZeroizableSensitiveBufferFactoryV2(
        authenticator=authenticator,
    ).from_owned_mutable(
        source=bytearray(b"enrollment-fixture"),
        domain="octopus.c2.agent-registration.enrollment-token.v12",
    )
    return OpaqueSecretValueFactoryV2().from_owned_buffer(
        value_id="registration-model-token",
        buffer=buffer,
    )


def test_protocol_constants_are_exact() -> None:
    assert C2_AGENT_PROTOCOL_V11 == "11.0"
    assert C2_AGENT_PROTOCOL_V12 == "12.0"
    assert C2_TASK_SCHEMA_V12 == "12.0"


def test_agent_protocol_negotiation() -> None:
    negotiator = AgentProtocolNegotiatorV12()
    assert negotiator.negotiate_protocol((C2_AGENT_PROTOCOL_V11, C2_AGENT_PROTOCOL_V12)) == "12.0"
    assert negotiator.negotiate_protocol((C2_AGENT_PROTOCOL_V11,)) == "11.0"
    with pytest.raises(ValueError, match="no compatible"):
        negotiator.negotiate_protocol(("10.0",))


def test_capability_digest_is_canonical_and_recomputed() -> None:
    capabilities = _capabilities()
    assert capabilities.capabilities_digest == compute_capabilities_digest(
        supported_operation_ids=capabilities.supported_operation_ids,
        supported_payload_schema_versions=capabilities.supported_payload_schema_versions,
        supported_result_schema_versions=capabilities.supported_result_schema_versions,
    )
    with pytest.raises(ValueError, match="capabilities_digest"):
        AgentCapabilitySetV12(
            supported_operation_ids=(C2TaskOperationId.IDENTITY,),
            supported_payload_schema_versions=(AgentPayloadSchemaIdV12.IDENTITY_V1,),
            supported_result_schema_versions=(AgentResultSchemaIdV12.IDENTITY_V1,),
            capabilities_digest="caller-controlled",
        )


def test_registration_is_exact_frozen_and_secret_redacted() -> None:
    enrollment_token = _enrollment_token()
    registration = AgentRegistrationV12(
        protocol_version="12.0",
        capabilities=_capabilities(),
        deployment_ref="deployment://fixture",
        artifact_binding_digest="a" * 64,
        enrollment_token=enrollment_token,
        hostname="host-1",
        os=C2TargetOS.LINUX,
        arch=C2TargetArch.AMD64,
        user="agent-user",
    )
    try:
        assert registration.capabilities.supported_operation_ids == (C2TaskOperationId.IDENTITY,)
        assert "enrollment-fixture" not in repr(registration)
        with pytest.raises(FrozenInstanceError):
            registration.hostname = "changed"  # type: ignore[misc]
    finally:
        enrollment_token.clear()
