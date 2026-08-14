"""Tests for C2 artifact bindings (§15.4)."""

import pytest

from core.actions.sensitive_integrity_runtime import (
    OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2,
    PersistentSensitiveIntegrityKeyringV2,
)
from core.actions.zeroizable_buffers import OwnedZeroizableSensitiveBufferFactoryV2
from core.c2.agent_protocol_v12 import AgentCapabilitySetV12, AgentRegistrationV12
from core.c2.agent_task_protocol import AgentPayloadSchemaIdV12, AgentResultSchemaIdV12
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.task_catalog import C2TaskOperationId
from core.secrets import OpaqueSecretValueFactoryV2


@pytest.mark.unit
def test_artifact_bindings():
    keyring = PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
        active_key_id="artifact-binding-test",
        keys={"artifact-binding-test": bytearray(b"k" * 32)},
    )
    authenticator = OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2().create(
        keyring=keyring,
        provenance_id="artifact-binding-test",
    )
    buffer = OwnedZeroizableSensitiveBufferFactoryV2(
        authenticator=authenticator,
    ).from_owned_mutable(
        source=bytearray(b"enrollment-fixture"),
        domain="octopus.c2.agent-registration.enrollment-token.v12",
    )
    enrollment_token = OpaqueSecretValueFactoryV2().from_owned_buffer(
        value_id="artifact-binding-token",
        buffer=buffer,
    )
    reg = AgentRegistrationV12(
        protocol_version="12.0",
        capabilities=AgentCapabilitySetV12.create(
            supported_operation_ids=(C2TaskOperationId.IDENTITY,),
            supported_payload_schema_versions=(AgentPayloadSchemaIdV12.IDENTITY_V1,),
            supported_result_schema_versions=(AgentResultSchemaIdV12.IDENTITY_V1,),
        ),
        deployment_ref="deployment://fixture",
        artifact_binding_digest="a" * 64,
        enrollment_token=enrollment_token,
        hostname="host-1",
        os=C2TargetOS.LINUX,
        arch=C2TargetArch.AMD64,
        user="agent-user",
    )
    try:
        assert reg.artifact_binding_digest == "a" * 64
    finally:
        enrollment_token.clear()
