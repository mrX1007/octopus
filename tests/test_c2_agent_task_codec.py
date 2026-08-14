"""Golden round trips and malformed-frame tests for the sole V12 wire codec."""

from __future__ import annotations

import hashlib
import json
import struct

import pytest

from core.actions.sensitive_integrity_runtime import (
    OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2,
    OwnedHmacSensitiveIntegrityAuthenticatorV2,
    PersistentSensitiveIntegrityKeyringV2,
)
from core.actions.target_scope import NetworkProtocol
from core.actions.zeroizable_buffers import (
    OwnedZeroizableSensitiveBufferFactoryV2,
    ZeroizableDestinationBufferV2,
)
from core.c2.agent_protocol_v12 import AgentCapabilitySetV12, AgentRegistrationV12
from core.c2.agent_result_models import (
    AgentConnectionSummaryV12,
    AgentHostInventoryTaskOutputV12,
    AgentIdentityTaskOutputV12,
    AgentInterfaceSummaryV12,
    AgentNetworkInventoryTaskOutputV12,
    AgentProcessSummaryV12,
    AgentRouteSummaryV12,
    AgentServiceInventoryTaskOutputV12,
    AgentServiceSummaryV12,
    AgentTaskResultV12,
)
from core.c2.agent_task_codec import (
    AgentTaskCodecV12,
    AgentTaskResultDecodeLimitsV12,
    AgentTaskResultDecodePolicyV12,
    StaticAgentTaskResultDecodePolicyRegistryV12,
    canonical_agent_task_result_decode_policy,
)
from core.c2.agent_task_models import (
    AgentHostInventoryTaskPayloadV12,
    AgentIdentityTaskPayloadV12,
    AgentNetworkInventoryTaskPayloadV12,
    AgentServiceInventoryTaskPayloadV12,
    AgentTaskDeliveryAckV12,
    AgentTaskEnvelopeV12,
    AgentTaskStatus,
)
from core.c2.agent_task_protocol import AgentPayloadSchemaIdV12, AgentResultSchemaIdV12
from core.c2.control_protocol import MemoryFrameReaderV1
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.task_catalog import C2TaskOperationId
from core.secrets import OpaqueSecretValueFactoryV2, OpaqueSecretValueV2, SecretValueState

pytestmark = pytest.mark.unit

_HEADER = struct.Struct(">5sBBII32sH")


class _OwnershipRegistry:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def assert_agent_owns_task(
        self,
        *,
        authenticated_agent_ref: str,
        expected_envelope: AgentTaskEnvelopeV12,
    ) -> None:
        if authenticated_agent_ref != "agent://fixture":
            raise ValueError("authenticated agent does not own task")
        self.calls.append((authenticated_agent_ref, expected_envelope.task_id))


_RegistrationServices = tuple[
    OwnedHmacSensitiveIntegrityAuthenticatorV2,
    OwnedZeroizableSensitiveBufferFactoryV2,
    OpaqueSecretValueFactoryV2,
]


def _registration_services() -> _RegistrationServices:
    keyring = PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
        active_key_id="agent-wire-test-key",
        keys={"agent-wire-test-key": bytearray(b"k" * 32)},
    )
    authenticator = OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2().create(
        keyring=keyring,
        provenance_id="agent-wire-test-authenticator",
    )
    return (
        authenticator,
        OwnedZeroizableSensitiveBufferFactoryV2(authenticator=authenticator),
        OpaqueSecretValueFactoryV2(),
    )


def _secret_value(
    value: str,
    *,
    buffer_factory: OwnedZeroizableSensitiveBufferFactoryV2,
    secret_value_factory: OpaqueSecretValueFactoryV2,
) -> OpaqueSecretValueV2:
    source = bytearray(value.encode("utf-8"))
    buffer = buffer_factory.from_owned_mutable(
        source=source,
        domain="octopus.c2.agent-registration.enrollment-token.v12",
    )
    return secret_value_factory.from_owned_buffer(
        value_id=f"test-secret-{value.rsplit('/', 1)[-1]}",
        buffer=buffer,
    )


def _codec(
    *,
    limits: AgentTaskResultDecodeLimitsV12 | None = None,
    ownership: _OwnershipRegistry | None = None,
    registration_services: _RegistrationServices | None = None,
) -> tuple[AgentTaskCodecV12, _OwnershipRegistry]:
    registry = StaticAgentTaskResultDecodePolicyRegistryV12(
        AgentTaskResultDecodePolicyV12.create(
            policy_id="test-policy",
            policy_revision=1,
            limits=limits or canonical_agent_task_result_decode_policy().limits,
        )
    )
    ownership = ownership or _OwnershipRegistry()
    services = registration_services or (None, None, None)
    return (
        AgentTaskCodecV12(
            policy_registry=registry,
            ownership_registry=ownership,
            secret_authenticator=services[0],
            zeroizable_buffer_factory=services[1],
            secret_value_factory=services[2],
        ),
        ownership,
    )


def _vectors() -> tuple[tuple[AgentTaskEnvelopeV12, AgentTaskResultV12], ...]:
    definitions = (
        (
            C2TaskOperationId.IDENTITY,
            AgentPayloadSchemaIdV12.IDENTITY_V1,
            AgentResultSchemaIdV12.IDENTITY_V1,
            AgentIdentityTaskPayloadV12(),
            AgentIdentityTaskOutputV12(
                hostname="host-1",
                os=C2TargetOS.LINUX,
                arch=C2TargetArch.AMD64,
                user="agent-user",
                process_id=42,
            ),
        ),
        (
            C2TaskOperationId.HOST_INVENTORY,
            AgentPayloadSchemaIdV12.HOST_INVENTORY_V1,
            AgentResultSchemaIdV12.HOST_INVENTORY_V1,
            AgentHostInventoryTaskPayloadV12(
                include_processes=True,
                include_services=True,
                max_items=10,
            ),
            AgentHostInventoryTaskOutputV12(
                processes=(AgentProcessSummaryV12(pid=42, name="agent"),),
                services=(AgentServiceSummaryV12(name="service-a", status="running"),),
                truncated=False,
            ),
        ),
        (
            C2TaskOperationId.NETWORK_INVENTORY,
            AgentPayloadSchemaIdV12.NETWORK_INVENTORY_V1,
            AgentResultSchemaIdV12.NETWORK_INVENTORY_V1,
            AgentNetworkInventoryTaskPayloadV12(
                include_routes=True,
                include_connections=True,
                max_items=10,
            ),
            AgentNetworkInventoryTaskOutputV12(
                interfaces=(AgentInterfaceSummaryV12(name="eth0", addresses=("192.0.2.10",)),),
                routes=(
                    AgentRouteSummaryV12(
                        destination="0.0.0.0/0",
                        gateway="192.0.2.1",
                        interface="eth0",
                    ),
                ),
                connections=(
                    AgentConnectionSummaryV12(
                        protocol=NetworkProtocol.TCP,
                        local_endpoint="192.0.2.10:443",
                        remote_endpoint=None,
                        state="listen",
                    ),
                ),
                truncated=False,
            ),
        ),
        (
            C2TaskOperationId.SERVICE_INVENTORY,
            AgentPayloadSchemaIdV12.SERVICE_INVENTORY_V1,
            AgentResultSchemaIdV12.SERVICE_INVENTORY_V1,
            AgentServiceInventoryTaskPayloadV12(
                service_names=("service-a",),
                include_status=True,
            ),
            AgentServiceInventoryTaskOutputV12(
                services=(AgentServiceSummaryV12(name="service-a", status="running"),),
                truncated=False,
            ),
        ),
    )
    vectors = []
    for index, (operation, payload_schema, result_schema, payload, output) in enumerate(definitions):
        task_id = f"task-{index}"
        envelope = AgentTaskEnvelopeV12(
            schema_version="12.0",
            task_id=task_id,
            operation_id=operation,
            payload_schema_version=payload_schema,
            result_schema_version=result_schema,
            expected_agent_capabilities_revision=7,
            expected_agent_capabilities_digest="c" * 64,
            expected_agent_artifact_binding_digest="a" * 64,
            payload=payload,
            issued_at=100.0,
            expires_at=200.0,
            delivery_attempt=1,
        )
        result = AgentTaskResultV12(
            schema_version="12.0",
            result_schema_version=result_schema,
            result_id=f"result-{index}",
            task_id=task_id,
            operation_id=operation,
            status=AgentTaskStatus.SUCCEEDED,
            output=output,
            error_code=None,
            completed_at=150.0,
        )
        vectors.append((envelope, result))
    return tuple(vectors)


@pytest.mark.parametrize(("envelope", "result"), _vectors())
def test_v12_task_and_result_vectors_python(
    envelope: AgentTaskEnvelopeV12,
    result: AgentTaskResultV12,
) -> None:
    codec, ownership = _codec()
    task_frame = codec.encode_task(envelope)
    result_frame = codec.encode_result(result)
    assert task_frame.startswith(b"OCT12\x01\x02")
    assert result_frame.startswith(b"OCT12\x01\x03")
    assert codec.decode_task(task_frame) == envelope
    assert (
        codec.decode_result(
            result_frame,
            expected_envelope=envelope,
            authenticated_agent_ref="agent://fixture",
        )
        == result
    )
    assert ownership.calls == [("agent://fixture", envelope.task_id)]


def test_delivery_ack_exact_roundtrip() -> None:
    codec, _ = _codec()
    ack = AgentTaskDeliveryAckV12(
        schema_version="12.0",
        task_id="task-ack",
        delivery_attempt=2,
        received_at=150.0,
    )
    assert codec.decode_delivery_ack(codec.encode_delivery_ack(ack)) == ack


def test_v12_registration_capability_roundtrip() -> None:
    services = _registration_services()
    codec, _ = _codec(registration_services=services)
    capabilities = AgentCapabilitySetV12.create(
        supported_operation_ids=(C2TaskOperationId.IDENTITY,),
        supported_payload_schema_versions=(AgentPayloadSchemaIdV12.IDENTITY_V1,),
        supported_result_schema_versions=(AgentResultSchemaIdV12.IDENTITY_V1,),
    )
    enrollment_token = _secret_value(
        "enrollment://single-use",
        buffer_factory=services[1],
        secret_value_factory=services[2],
    )
    expected_tag = enrollment_token.integrity_tag
    registration = AgentRegistrationV12(
        protocol_version="12.0",
        capabilities=capabilities,
        deployment_ref="deployment://fixture",
        artifact_binding_digest="a" * 64,
        enrollment_token=enrollment_token,
        hostname="host-1",
        os=C2TargetOS.LINUX,
        arch=C2TargetArch.AMD64,
        user="agent-user",
    )
    destination = ZeroizableDestinationBufferV2.allocate(4096)
    try:
        written = codec.encode_registration_into_zeroizable(registration, destination)
        with destination.borrow_writable_view() as frame_view:
            frame = bytes(frame_view[:written])
    finally:
        destination.zeroize_and_close()
    assert enrollment_token.state is SecretValueState.CONSUMED
    decoded = codec.decode_registration_from_zeroizable(MemoryFrameReaderV1(frame))
    try:
        assert decoded.protocol_version == "12.0"
        assert decoded.capabilities == capabilities
        assert decoded.enrollment_token.byte_length == len(b"enrollment://single-use")
        assert decoded.enrollment_token.integrity_tag == expected_tag
        assert decoded.enrollment_token.state is SecretValueState.AVAILABLE
    finally:
        decoded.enrollment_token.clear()


def test_agent_registration_codec_never_generic_serializes_secret_value() -> None:
    services = _registration_services()
    codec, _ = _codec(registration_services=services)
    enrollment_token = _secret_value(
        "enrollment://secret-segment-only",
        buffer_factory=services[1],
        secret_value_factory=services[2],
    )
    registration = AgentRegistrationV12(
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
    destination = ZeroizableDestinationBufferV2.allocate(4096)
    try:
        written = codec.encode_registration_into_zeroizable(registration, destination)
        with destination.borrow_writable_view() as frame_view:
            frame = bytes(frame_view[:written])
    finally:
        destination.zeroize_and_close()
    _, _, _, body_length, secret_length, _, tag_length = _HEADER.unpack_from(frame)
    body_start = _HEADER.size + tag_length
    body = frame[body_start : body_start + body_length]
    assert b"secret-segment-only" not in body
    assert secret_length == len(b"enrollment://secret-segment-only")

    corrupted = bytearray(frame)
    corrupted[-1] ^= 1
    with pytest.raises(ValueError, match="integrity check failed"):
        codec.decode_registration_from_zeroizable(MemoryFrameReaderV1(bytes(corrupted)))


def _raw_frame(kind: int, body: bytes) -> bytes:
    return (
        _HEADER.pack(
            b"OCT12",
            1,
            kind,
            len(body),
            0,
            hashlib.sha256(body).digest(),
            0,
        )
        + body
    )


def test_decoder_rejects_unknown_duplicate_noncanonical_and_invalid_utf8() -> None:
    codec, _ = _codec()
    valid = _vectors()[0][0]
    valid_body = json.loads(codec.encode_task(valid)[_HEADER.size :].decode("utf-8"))

    unknown = dict(valid_body)
    unknown["unexpected"] = True
    unknown_bytes = json.dumps(unknown, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="fields are not exact"):
        codec.decode_task(_raw_frame(2, unknown_bytes))

    duplicate = b'{"task_id":"one","task_id":"two"}'
    with pytest.raises(ValueError, match="duplicate JSON field"):
        codec.decode_task(_raw_frame(2, duplicate))

    noncanonical = json.dumps(valid_body, indent=2).encode()
    with pytest.raises(ValueError, match="not canonical"):
        codec.decode_task(_raw_frame(2, noncanonical))

    with pytest.raises(ValueError, match="valid UTF-8"):
        codec.decode_task(_raw_frame(2, b"\xff"))


def test_decoder_rejects_trailing_bytes_digest_mismatch_and_excess_depth() -> None:
    codec, _ = _codec()
    frame = codec.encode_task(_vectors()[0][0])
    with pytest.raises(ValueError, match="trailing bytes"):
        codec.decode_task(frame + b"x")

    corrupted = bytearray(frame)
    corrupted[-1] ^= 1
    with pytest.raises(ValueError, match="digest mismatch"):
        codec.decode_task(bytes(corrupted))

    nested: object = "leaf"
    for _ in range(10):
        nested = [nested]
    body = json.dumps({"nested": nested}, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="nesting"):
        codec.decode_task(_raw_frame(2, body))


def test_frame_size_bound_is_server_owned() -> None:
    limits = AgentTaskResultDecodeLimitsV12(
        max_frame_bytes=128,
        max_depth=8,
        max_string_bytes=65_536,
        max_collection_items=1_024,
        max_processes=1_024,
        max_services=1_024,
        max_interfaces=256,
        max_routes=1_024,
        max_connections=2_048,
    )
    codec, _ = _codec(limits=limits)
    with pytest.raises(ValueError, match="frame bound"):
        codec.decode_task(b"x" * 129)
