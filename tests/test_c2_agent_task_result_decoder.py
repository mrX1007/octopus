"""Fail-closed policy and envelope checks for V12 task result decoding."""

from __future__ import annotations

import hashlib
import inspect
import json
import struct

import pytest

from core.actions.target_scope import NetworkProtocol
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
    AgentTaskResultDecoderV12,
    StaticAgentTaskResultDecodePolicyRegistryV12,
    canonical_agent_task_result_decode_policy,
)
from core.c2.agent_task_models import (
    AgentIdentityTaskPayloadV12,
    AgentTaskEnvelopeV12,
    AgentTaskErrorCode,
    AgentTaskStatus,
)
from core.c2.agent_task_protocol import AgentPayloadSchemaIdV12, AgentResultSchemaIdV12
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.task_catalog import C2TaskOperationId

pytestmark = pytest.mark.unit


class _Ownership:
    def assert_agent_owns_task(
        self,
        *,
        authenticated_agent_ref: str,
        expected_envelope: AgentTaskEnvelopeV12,
    ) -> None:
        if authenticated_agent_ref != "agent://owner":
            raise ValueError("agent does not own expected task")


class _CountingPolicyRegistry:
    def __init__(self, policy: AgentTaskResultDecodePolicyV12) -> None:
        self.policy = policy
        self.calls = 0

    def current(self) -> AgentTaskResultDecodePolicyV12:
        self.calls += 1
        return self.policy


def _envelope() -> AgentTaskEnvelopeV12:
    return AgentTaskEnvelopeV12(
        schema_version="12.0",
        task_id="task-1",
        operation_id=C2TaskOperationId.IDENTITY,
        payload_schema_version=AgentPayloadSchemaIdV12.IDENTITY_V1,
        result_schema_version=AgentResultSchemaIdV12.IDENTITY_V1,
        expected_agent_capabilities_revision=1,
        expected_agent_capabilities_digest="c" * 64,
        expected_agent_artifact_binding_digest="a" * 64,
        payload=AgentIdentityTaskPayloadV12(),
        issued_at=100.0,
        expires_at=200.0,
        delivery_attempt=1,
    )


def _identity_result(*, task_id: str = "task-1") -> AgentTaskResultV12:
    return AgentTaskResultV12(
        schema_version="12.0",
        result_schema_version=AgentResultSchemaIdV12.IDENTITY_V1,
        result_id="result-1",
        task_id=task_id,
        operation_id=C2TaskOperationId.IDENTITY,
        status=AgentTaskStatus.SUCCEEDED,
        output=AgentIdentityTaskOutputV12(
            hostname="host-1",
            os=C2TargetOS.LINUX,
            arch=C2TargetArch.AMD64,
            user="agent-user",
            process_id=10,
        ),
        error_code=None,
        completed_at=150.0,
    )


def _codec(
    policy: AgentTaskResultDecodePolicyV12 | None = None,
) -> AgentTaskCodecV12:
    return AgentTaskCodecV12(
        policy_registry=StaticAgentTaskResultDecodePolicyRegistryV12(
            policy or canonical_agent_task_result_decode_policy()
        ),
        ownership_registry=_Ownership(),
    )


def test_v12_result_decoder_uses_canonical_defaults() -> None:
    assert AgentTaskResultDecodeLimitsV12() == AgentTaskResultDecodeLimitsV12(
        max_frame_bytes=1_048_576,
        max_depth=8,
        max_string_bytes=65_536,
        max_collection_items=1_024,
        max_processes=1_024,
        max_services=1_024,
        max_interfaces=256,
        max_routes=1_024,
        max_connections=2_048,
    )


def test_v12_result_decoder_rejects_limit_above_hard_max() -> None:
    with pytest.raises(ValueError, match="max_depth"):
        AgentTaskResultDecodeLimitsV12(max_depth=17)
    with pytest.raises(ValueError, match="max_connections"):
        AgentTaskResultDecodeLimitsV12(max_connections=8_193)


def test_v12_result_decoder_has_no_call_site_limit_parameter() -> None:
    parameters = inspect.signature(AgentTaskResultDecoderV12.decode).parameters
    assert tuple(parameters) == (
        "self",
        "serialized_result",
        "expected_envelope",
        "authenticated_agent_ref",
    )
    assert "limits" not in parameters


def test_v12_result_decoder_loads_policy_only_from_registry() -> None:
    registry = _CountingPolicyRegistry(canonical_agent_task_result_decode_policy())
    ownership = _Ownership()
    codec = AgentTaskCodecV12(policy_registry=registry, ownership_registry=ownership)
    frame = codec.encode_result(_identity_result())
    before = registry.calls
    decoder = AgentTaskResultDecoderV12(
        policy_registry=registry,
        ownership_registry=ownership,
    )
    assert decoder.decode(
        frame,
        expected_envelope=_envelope(),
        authenticated_agent_ref="agent://owner",
    ) == _identity_result()
    assert registry.calls > before


def test_v12_result_decoder_config_validation_fail_closed() -> None:
    with pytest.raises(ValueError, match="config_digest"):
        AgentTaskResultDecodePolicyV12(
            policy_id="policy",
            policy_revision=1,
            limits=AgentTaskResultDecodeLimitsV12(),
            config_digest="caller-controlled",
        )
    with pytest.raises(ValueError, match="contradict"):
        AgentTaskResultDecodeLimitsV12(
            max_collection_items=1,
            max_processes=2,
            max_services=1,
            max_interfaces=1,
            max_routes=1,
            max_connections=2,
        )


def test_v12_result_decoder_task_and_operation_match_expected_envelope() -> None:
    codec = _codec()
    frame = codec.encode_result(_identity_result(task_id="different-task"))
    with pytest.raises(ValueError, match="agent_result_envelope_mismatch"):
        codec.decode_result(
            frame,
            expected_envelope=_envelope(),
            authenticated_agent_ref="agent://owner",
        )


def test_v12_result_task_id_matches_envelope() -> None:
    codec = _codec()
    with pytest.raises(ValueError, match="agent_result_envelope_mismatch"):
        codec.decode_result(
            codec.encode_result(_identity_result(task_id="other-task")),
            expected_envelope=_envelope(),
            authenticated_agent_ref="agent://owner",
        )


def test_v12_result_authenticated_agent_owns_task() -> None:
    codec = _codec()
    frame = codec.encode_result(_identity_result())
    with pytest.raises(ValueError, match="does not own"):
        codec.decode_result(
            frame,
            expected_envelope=_envelope(),
            authenticated_agent_ref="agent://other",
        )


def _raw_result_frame(body: bytes) -> bytes:
    header = struct.Struct(">5sBBII32sH")
    return header.pack(
        b"OCT12",
        1,
        3,
        len(body),
        0,
        hashlib.sha256(body).digest(),
        0,
    ) + body


def test_v12_result_decoder_rejects_unknown_fields_and_duplicate_keys() -> None:
    codec = _codec()
    frame = codec.encode_result(_identity_result())
    header_size = struct.calcsize(">5sBBII32sH")
    body = json.loads(frame[header_size:].decode("utf-8"))
    body["unknown"] = True
    unknown = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with pytest.raises(ValueError, match="fields are not exact"):
        codec.decode_result(
            _raw_result_frame(unknown),
            expected_envelope=_envelope(),
            authenticated_agent_ref="agent://owner",
        )

    duplicate = b'{"schema_version":"12.0","schema_version":"12.0"}'
    with pytest.raises(ValueError, match="duplicate JSON field"):
        codec.decode_result(
            _raw_result_frame(duplicate),
            expected_envelope=_envelope(),
            authenticated_agent_ref="agent://owner",
        )


def test_v12_result_decoder_exact_schema_and_bounds() -> None:
    codec = _codec()
    frame = codec.encode_result(_identity_result())
    header_size = struct.calcsize(">5sBBII32sH")
    body = json.loads(frame[header_size:].decode("utf-8"))
    body["schema_version"] = "12.1"
    serialized = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with pytest.raises(ValueError, match="schema_version"):
        codec.decode_result(
            _raw_result_frame(serialized),
            expected_envelope=_envelope(),
            authenticated_agent_ref="agent://owner",
        )


def test_v12_result_operation_id_matches_envelope() -> None:
    mismatched = AgentTaskResultV12(
        schema_version="12.0",
        result_schema_version=AgentResultSchemaIdV12.HOST_INVENTORY_V1,
        result_id="result-other-operation",
        task_id="task-1",
        operation_id=C2TaskOperationId.HOST_INVENTORY,
        status=AgentTaskStatus.FAILED,
        output=None,
        error_code=AgentTaskErrorCode.EXECUTION_FAILED,
        completed_at=150.0,
    )
    codec = _codec()
    with pytest.raises(ValueError, match="agent_result_envelope_mismatch"):
        codec.decode_result(
            codec.encode_result(mismatched),
            expected_envelope=_envelope(),
            authenticated_agent_ref="agent://owner",
        )


def test_v12_result_decoder_rejects_caller_dataclass() -> None:
    decoder = AgentTaskResultDecoderV12(
        policy_registry=StaticAgentTaskResultDecodePolicyRegistryV12(
            canonical_agent_task_result_decode_policy()
        ),
        ownership_registry=_Ownership(),
    )
    with pytest.raises(TypeError, match="must be bytes"):
        decoder.decode(  # type: ignore[arg-type]
            _identity_result(),
            expected_envelope=_envelope(),
            authenticated_agent_ref="agent://owner",
        )


def test_result_output_variant_matches_result_schema() -> None:
    mismatched = AgentTaskResultV12(
        schema_version="12.0",
        result_schema_version=AgentResultSchemaIdV12.IDENTITY_V1,
        result_id="result-mismatch",
        task_id="task-1",
        operation_id=C2TaskOperationId.HOST_INVENTORY,
        status=AgentTaskStatus.SUCCEEDED,
        output=AgentIdentityTaskOutputV12(
            hostname="host-1",
            os=C2TargetOS.LINUX,
            arch=C2TargetArch.AMD64,
            user="agent-user",
            process_id=10,
        ),
        error_code=None,
        completed_at=150.0,
    )
    with pytest.raises(ValueError, match="operation/result schema"):
        _codec().encode_result(mismatched)


def test_error_result_retains_requested_result_schema() -> None:
    result = AgentTaskResultV12(
        schema_version="12.0",
        result_schema_version=AgentResultSchemaIdV12.IDENTITY_V1,
        result_id="result-error",
        task_id="task-1",
        operation_id=C2TaskOperationId.IDENTITY,
        status=AgentTaskStatus.FAILED,
        output=None,
        error_code=AgentTaskErrorCode.EXECUTION_FAILED,
        completed_at=150.0,
    )
    codec = _codec()
    decoded = codec.decode_result(
        codec.encode_result(result),
        expected_envelope=_envelope(),
        authenticated_agent_ref="agent://owner",
    )
    assert decoded.result_schema_version is AgentResultSchemaIdV12.IDENTITY_V1
    assert decoded.output is None


def _bounded_policy() -> AgentTaskResultDecodePolicyV12:
    return AgentTaskResultDecodePolicyV12.create(
        policy_id="small-collections",
        policy_revision=1,
        limits=AgentTaskResultDecodeLimitsV12(
            max_collection_items=1,
            max_processes=1,
            max_services=1,
            max_interfaces=1,
            max_routes=1,
            max_connections=1,
        ),
    )


@pytest.mark.parametrize(
    "result",
    (
        AgentTaskResultV12(
            schema_version="12.0",
            result_schema_version=AgentResultSchemaIdV12.HOST_INVENTORY_V1,
            result_id="result-host",
            task_id="task-host",
            operation_id=C2TaskOperationId.HOST_INVENTORY,
            status=AgentTaskStatus.SUCCEEDED,
            output=AgentHostInventoryTaskOutputV12(
                processes=(
                    AgentProcessSummaryV12(pid=1, name="one"),
                    AgentProcessSummaryV12(pid=2, name="two"),
                ),
                services=(),
                truncated=True,
            ),
            error_code=None,
            completed_at=150.0,
        ),
        AgentTaskResultV12(
            schema_version="12.0",
            result_schema_version=AgentResultSchemaIdV12.NETWORK_INVENTORY_V1,
            result_id="result-network",
            task_id="task-network",
            operation_id=C2TaskOperationId.NETWORK_INVENTORY,
            status=AgentTaskStatus.SUCCEEDED,
            output=AgentNetworkInventoryTaskOutputV12(
                interfaces=(
                    AgentInterfaceSummaryV12(name="one", addresses=("192.0.2.1",)),
                    AgentInterfaceSummaryV12(name="two", addresses=("192.0.2.2",)),
                ),
                routes=(
                    AgentRouteSummaryV12(destination="0.0.0.0/0", gateway=None, interface="one"),
                ),
                connections=(
                    AgentConnectionSummaryV12(
                        protocol=NetworkProtocol.TCP,
                        local_endpoint="192.0.2.1:1",
                        remote_endpoint=None,
                        state="listen",
                    ),
                ),
                truncated=True,
            ),
            error_code=None,
            completed_at=150.0,
        ),
        AgentTaskResultV12(
            schema_version="12.0",
            result_schema_version=AgentResultSchemaIdV12.SERVICE_INVENTORY_V1,
            result_id="result-services",
            task_id="task-services",
            operation_id=C2TaskOperationId.SERVICE_INVENTORY,
            status=AgentTaskStatus.SUCCEEDED,
            output=AgentServiceInventoryTaskOutputV12(
                services=(
                    AgentServiceSummaryV12(name="one", status="running"),
                    AgentServiceSummaryV12(name="two", status="stopped"),
                ),
                truncated=True,
            ),
            error_code=None,
            completed_at=150.0,
        ),
    ),
)
def test_v12_result_decoder_bounds_each_collection_variant(result: AgentTaskResultV12) -> None:
    with pytest.raises(ValueError, match="collection bound"):
        _codec(_bounded_policy()).encode_result(result)
