"""Bounded, exact V12 agent wire codec.

The codec accepts and returns only closed DTOs.  It has no generic mapping,
caller-selected decoder limits, or wire-selected executable operation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import struct
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Literal, Protocol, cast, runtime_checkable

from core.actions.sensitive_integrity import SensitiveIntegrityTagV2
from core.actions.sensitive_integrity_runtime import (
    OwnedHmacSensitiveIntegrityAuthenticatorV2,
    SensitiveIntegrityError,
)
from core.actions.target_scope import NetworkProtocol
from core.actions.zeroizable_buffers import (
    OwnedZeroizableSensitiveBufferFactoryV2,
    OwnedZeroizableSensitiveBufferV2,
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
    AgentTaskOutput,
    AgentTaskResultV12,
)
from core.c2.agent_task_catalog import AgentTaskCatalogV12
from core.c2.agent_task_models import (
    AgentHostInventoryTaskPayloadV12,
    AgentIdentityTaskPayloadV12,
    AgentNetworkInventoryTaskPayloadV12,
    AgentServiceInventoryTaskPayloadV12,
    AgentTaskDeliveryAckV12,
    AgentTaskEnvelopeV12,
    AgentTaskErrorCode,
    AgentTaskPayloadV12,
    AgentTaskStatus,
)
from core.c2.agent_task_protocol import (
    C2_AGENT_PROTOCOL_V12,
    C2_TASK_SCHEMA_V12,
    AgentPayloadSchemaIdV12,
    AgentResultSchemaIdV12,
)
from core.c2.control_protocol import BoundedFrameReaderV1
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.task_catalog import C2TaskOperationId
from core.secrets import OpaqueSecretValueFactoryV2

_MAGIC = b"OCT12"
_WIRE_VERSION = 1
_HEADER = struct.Struct(">5sBBII32sH")
_REGISTRATION_SECRET_DOMAIN = "octopus.c2.agent-registration.enrollment-token.v12"


class AgentWireMessageKindV12(IntEnum):
    REGISTRATION = 1
    TASK = 2
    RESULT = 3
    DELIVERY_ACK = 4


@dataclass(frozen=True)
class AgentWireFrameHeaderV12:
    magic: Literal["OCT12"]
    wire_version: Literal[1]
    message_kind: AgentWireMessageKindV12
    canonical_body_length: int
    secret_segment_length: int
    canonical_body_digest: str
    secret_integrity_tag_length: int
    secret_segment_integrity_tag: SensitiveIntegrityTagV2 | None


_HARD_MAXIMA = {
    "max_frame_bytes": 4_194_304,
    "max_depth": 16,
    "max_string_bytes": 262_144,
    "max_collection_items": 4_096,
    "max_processes": 4_096,
    "max_services": 4_096,
    "max_interfaces": 1_024,
    "max_routes": 4_096,
    "max_connections": 8_192,
}


@dataclass(frozen=True)
class AgentTaskResultDecodeLimitsV12:
    max_frame_bytes: int = 1_048_576
    max_depth: int = 8
    max_string_bytes: int = 65_536
    max_collection_items: int = 1_024
    max_processes: int = 1_024
    max_services: int = 1_024
    max_interfaces: int = 256
    max_routes: int = 1_024
    max_connections: int = 2_048

    def __post_init__(self) -> None:
        for field_name, hard_maximum in _HARD_MAXIMA.items():
            value = getattr(self, field_name)
            if type(value) is not int or not 1 <= value <= hard_maximum:
                raise ValueError(f"{field_name} must be an integer in 1..{hard_maximum}")
        if any(
            item > self.max_collection_items
            for item in (
                self.max_processes,
                self.max_services,
                self.max_interfaces,
                self.max_routes,
            )
        ):
            raise ValueError("variant collection limits contradict max_collection_items")
        if self.max_connections > self.max_collection_items * 2:
            raise ValueError("max_connections may not exceed twice max_collection_items")


def compute_result_decode_config_digest(limits: AgentTaskResultDecodeLimitsV12) -> str:
    if type(limits) is not AgentTaskResultDecodeLimitsV12:
        raise TypeError("limits must be AgentTaskResultDecodeLimitsV12")
    return hashlib.sha256(_canonical_json(asdict(limits))).hexdigest()


@dataclass(frozen=True)
class AgentTaskResultDecodePolicyV12:
    policy_id: str
    policy_revision: int
    limits: AgentTaskResultDecodeLimitsV12
    config_digest: str

    def __post_init__(self) -> None:
        _require_text(self.policy_id, "policy_id", 65_536)
        if type(self.policy_revision) is not int or self.policy_revision < 1:
            raise ValueError("policy_revision must be a positive integer")
        if type(self.limits) is not AgentTaskResultDecodeLimitsV12:
            raise TypeError("limits must be AgentTaskResultDecodeLimitsV12")
        expected = compute_result_decode_config_digest(self.limits)
        if type(self.config_digest) is not str or not hmac.compare_digest(
            self.config_digest,
            expected,
        ):
            raise ValueError("config_digest does not match the canonical limits")

    @classmethod
    def create(
        cls,
        *,
        policy_id: str,
        policy_revision: int,
        limits: AgentTaskResultDecodeLimitsV12,
    ) -> AgentTaskResultDecodePolicyV12:
        return cls(
            policy_id=policy_id,
            policy_revision=policy_revision,
            limits=limits,
            config_digest=compute_result_decode_config_digest(limits),
        )


@runtime_checkable
class AgentTaskResultDecodePolicyRegistryV12(Protocol):
    def current(self) -> AgentTaskResultDecodePolicyV12: ...


class StaticAgentTaskResultDecodePolicyRegistryV12:
    """Daemon-owned immutable policy registry suitable for one config revision."""

    def __init__(self, policy: AgentTaskResultDecodePolicyV12) -> None:
        if type(policy) is not AgentTaskResultDecodePolicyV12:
            raise TypeError("policy must be AgentTaskResultDecodePolicyV12")
        self._policy = policy

    def current(self) -> AgentTaskResultDecodePolicyV12:
        return self._policy


def canonical_agent_task_result_decode_policy() -> AgentTaskResultDecodePolicyV12:
    return AgentTaskResultDecodePolicyV12.create(
        policy_id="c2-agent-v12-result-decoder",
        policy_revision=1,
        limits=AgentTaskResultDecodeLimitsV12(),
    )


@runtime_checkable
class AgentTaskOwnershipRegistryV12(Protocol):
    def assert_agent_owns_task(
        self,
        *,
        authenticated_agent_ref: str,
        expected_envelope: AgentTaskEnvelopeV12,
    ) -> None: ...


@runtime_checkable
class AgentWireCodecV12(Protocol):
    def encode_registration_into_zeroizable(
        self,
        registration: AgentRegistrationV12,
        destination: ZeroizableDestinationBufferV2,
    ) -> int: ...

    def decode_registration_from_zeroizable(
        self,
        frame_reader: BoundedFrameReaderV1,
    ) -> AgentRegistrationV12: ...

    def encode_task(self, task: AgentTaskEnvelopeV12) -> bytes: ...

    def decode_task(self, frame: bytes) -> AgentTaskEnvelopeV12: ...

    def encode_result(self, result: AgentTaskResultV12) -> bytes: ...

    def decode_result(
        self,
        frame: bytes,
        *,
        expected_envelope: AgentTaskEnvelopeV12,
        authenticated_agent_ref: str,
    ) -> AgentTaskResultV12: ...

    def encode_delivery_ack(self, ack: AgentTaskDeliveryAckV12) -> bytes: ...

    def decode_delivery_ack(self, frame: bytes) -> AgentTaskDeliveryAckV12: ...


class AgentTaskCodecV12:
    """The sole concrete V12 registration/task/result/delivery wire codec."""

    def __init__(
        self,
        *,
        policy_registry: AgentTaskResultDecodePolicyRegistryV12,
        ownership_registry: AgentTaskOwnershipRegistryV12,
        secret_authenticator: OwnedHmacSensitiveIntegrityAuthenticatorV2 | None = None,
        zeroizable_buffer_factory: OwnedZeroizableSensitiveBufferFactoryV2 | None = None,
        secret_value_factory: OpaqueSecretValueFactoryV2 | None = None,
    ) -> None:
        if not isinstance(policy_registry, AgentTaskResultDecodePolicyRegistryV12):
            raise TypeError("policy_registry does not implement the canonical registry protocol")
        if not isinstance(ownership_registry, AgentTaskOwnershipRegistryV12):
            raise TypeError("ownership_registry does not implement the task ownership protocol")
        registration_services = (
            secret_authenticator,
            zeroizable_buffer_factory,
            secret_value_factory,
        )
        if any(service is not None for service in registration_services) and any(
            service is None for service in registration_services
        ):
            raise TypeError("registration codec services must be supplied as one complete set")
        if secret_authenticator is not None and type(secret_authenticator) is not OwnedHmacSensitiveIntegrityAuthenticatorV2:
            raise TypeError("registration codec requires the canonical sensitive authenticator")
        if zeroizable_buffer_factory is not None and type(
            zeroizable_buffer_factory
        ) is not OwnedZeroizableSensitiveBufferFactoryV2:
            raise TypeError("registration codec requires the canonical zeroizable buffer factory")
        if secret_value_factory is not None and type(secret_value_factory) is not OpaqueSecretValueFactoryV2:
            raise TypeError("registration codec requires the canonical secret value factory")
        self._policy_registry = policy_registry
        self._ownership_registry = ownership_registry
        self._secret_authenticator = secret_authenticator
        self._zeroizable_buffer_factory = zeroizable_buffer_factory
        self._secret_value_factory = secret_value_factory
        self._result_decoder = AgentTaskResultDecoderV12(
            policy_registry=policy_registry,
            ownership_registry=ownership_registry,
        )

    def encode_registration_into_zeroizable(
        self,
        registration: AgentRegistrationV12,
        destination: ZeroizableDestinationBufferV2,
    ) -> int:
        if type(registration) is not AgentRegistrationV12:
            raise TypeError("registration must be AgentRegistrationV12")
        if type(destination) is not ZeroizableDestinationBufferV2:
            raise TypeError("registration destination must be an owned zeroizable destination")
        self._require_registration_services()
        lease = registration.enrollment_token.acquire_single_use(
            consumer_id="agent-registration-wire-encoder-v12",
        )
        token_destination = ZeroizableDestinationBufferV2.allocate(lease.byte_length)
        frame: bytearray | None = None
        try:
            limits = self._current_limits()
            if lease.byte_length > limits.max_string_bytes:
                raise ValueError("enrollment token exceeds the configured string bound")
            if lease.integrity_tag.domain != _REGISTRATION_SECRET_DOMAIN:
                raise ValueError("enrollment token integrity domain is not registration-bound")
            copied = lease.read_into(token_destination)
            if copied != lease.byte_length:
                raise ValueError("enrollment token lease length mismatch")
            body = _registration_to_wire(
                registration,
                enrollment_token_byte_length=lease.byte_length,
            )
            with token_destination.borrow_writable_view() as token_view:
                frame = _encode_frame_mutable(
                    kind=AgentWireMessageKindV12.REGISTRATION,
                    body_value=body,
                    secret=token_view[:copied],
                    integrity_tag=lease.integrity_tag,
                    limits=limits,
                )
            with destination.borrow_writable_view() as writable:
                if writable.readonly or len(writable) < len(frame):
                    raise ValueError("zeroizable destination capacity is smaller than the frame")
                writable[: len(frame)] = frame
            return len(frame)
        finally:
            token_destination.zeroize_and_close()
            lease.close_and_zeroize()
            if frame is not None:
                _wipe(frame)

    def decode_registration_from_zeroizable(
        self,
        frame_reader: BoundedFrameReaderV1,
    ) -> AgentRegistrationV12:
        if not isinstance(frame_reader, BoundedFrameReaderV1):
            raise TypeError("frame_reader must implement BoundedFrameReaderV1")
        limits = self._current_limits()
        if frame_reader.remaining_bytes > limits.max_frame_bytes:
            raise ValueError("registration frame exceeds the configured frame bound")
        source = bytearray()
        frame_reader.read_exact_into(source, byte_count=frame_reader.remaining_bytes)
        frame_reader.require_eof()
        secret = bytearray()
        try:
            body, secret, header = _decode_frame(
                source,
                expected_kind=AgentWireMessageKindV12.REGISTRATION,
                limits=limits,
            )
            if header.secret_segment_integrity_tag is None:
                raise ValueError("registration secret segment has no integrity tag")
            authenticator, buffer_factory, secret_value_factory = self._require_registration_services()
            if header.secret_segment_integrity_tag.domain != _REGISTRATION_SECRET_DOMAIN:
                raise ValueError("registration secret segment integrity domain mismatch")
            try:
                with memoryview(secret) as secret_view:
                    authenticator.verify(
                        expected=header.secret_segment_integrity_tag,
                        source=secret_view,
                    )
            except SensitiveIntegrityError as exc:
                raise ValueError("registration secret segment integrity check failed") from exc
            return _registration_from_wire(
                body,
                secret=secret,
                limits=limits,
                buffer_factory=buffer_factory,
                secret_value_factory=secret_value_factory,
                integrity_tag=header.secret_segment_integrity_tag,
            )
        finally:
            _wipe(secret)
            _wipe(source)

    def encode_task(self, task: AgentTaskEnvelopeV12) -> bytes:
        AgentTaskCatalogV12.validate_envelope(task)
        limits = self._current_limits()
        _validate_task_collection_limits(task, limits)
        return bytes(
            _encode_frame_mutable(
                kind=AgentWireMessageKindV12.TASK,
                body_value=_task_to_wire(task),
                secret=bytearray(),
                integrity_tag=None,
                limits=limits,
            )
        )

    def decode_task(self, frame: bytes) -> AgentTaskEnvelopeV12:
        limits = self._current_limits()
        body, _, _ = _decode_frame(
            frame,
            expected_kind=AgentWireMessageKindV12.TASK,
            limits=limits,
        )
        task = _task_from_wire(body, limits=limits)
        AgentTaskCatalogV12.validate_envelope(task)
        _validate_task_collection_limits(task, limits)
        return task

    def encode_result(self, result: AgentTaskResultV12) -> bytes:
        limits = self._current_limits()
        _validate_result_variant(result, limits)
        return bytes(
            _encode_frame_mutable(
                kind=AgentWireMessageKindV12.RESULT,
                body_value=_result_to_wire(result),
                secret=bytearray(),
                integrity_tag=None,
                limits=limits,
            )
        )

    def decode_result(
        self,
        frame: bytes,
        *,
        expected_envelope: AgentTaskEnvelopeV12,
        authenticated_agent_ref: str,
    ) -> AgentTaskResultV12:
        return self._result_decoder.decode(
            frame,
            expected_envelope=expected_envelope,
            authenticated_agent_ref=authenticated_agent_ref,
        )

    def encode_delivery_ack(self, ack: AgentTaskDeliveryAckV12) -> bytes:
        if type(ack) is not AgentTaskDeliveryAckV12:
            raise TypeError("ack must be AgentTaskDeliveryAckV12")
        limits = self._current_limits()
        return bytes(
            _encode_frame_mutable(
                kind=AgentWireMessageKindV12.DELIVERY_ACK,
                body_value=_delivery_ack_to_wire(ack),
                secret=bytearray(),
                integrity_tag=None,
                limits=limits,
            )
        )

    def decode_delivery_ack(self, frame: bytes) -> AgentTaskDeliveryAckV12:
        limits = self._current_limits()
        body, _, _ = _decode_frame(
            frame,
            expected_kind=AgentWireMessageKindV12.DELIVERY_ACK,
            limits=limits,
        )
        return _delivery_ack_from_wire(body)

    def _current_limits(self) -> AgentTaskResultDecodeLimitsV12:
        policy = self._policy_registry.current()
        if type(policy) is not AgentTaskResultDecodePolicyV12:
            raise TypeError("policy registry returned a non-canonical policy")
        return policy.limits

    def _require_registration_services(
        self,
    ) -> tuple[
        OwnedHmacSensitiveIntegrityAuthenticatorV2,
        OwnedZeroizableSensitiveBufferFactoryV2,
        OpaqueSecretValueFactoryV2,
    ]:
        if (
            self._secret_authenticator is None
            or self._zeroizable_buffer_factory is None
            or self._secret_value_factory is None
        ):
            raise RuntimeError("registration codec has no server-owned secret services")
        return (
            self._secret_authenticator,
            self._zeroizable_buffer_factory,
            self._secret_value_factory,
        )


def _decode_result_body(
    frame: bytes,
    *,
    limits: AgentTaskResultDecodeLimitsV12,
) -> dict[str, object]:
    body, _, _ = _decode_frame(
        frame,
        expected_kind=AgentWireMessageKindV12.RESULT,
        limits=limits,
    )
    return body


class AgentTaskResultDecoderV12:
    """Application validator for one authenticated agent's expected task result."""

    def __init__(
        self,
        *,
        policy_registry: AgentTaskResultDecodePolicyRegistryV12,
        ownership_registry: AgentTaskOwnershipRegistryV12,
    ) -> None:
        if not isinstance(policy_registry, AgentTaskResultDecodePolicyRegistryV12):
            raise TypeError("policy_registry does not implement the canonical registry protocol")
        if not isinstance(ownership_registry, AgentTaskOwnershipRegistryV12):
            raise TypeError("ownership_registry does not implement the task ownership protocol")
        self._policy_registry = policy_registry
        self._ownership_registry = ownership_registry

    def decode(
        self,
        serialized_result: bytes,
        *,
        expected_envelope: AgentTaskEnvelopeV12,
        authenticated_agent_ref: str,
    ) -> AgentTaskResultV12:
        if type(serialized_result) is not bytes:
            raise TypeError("serialized_result must be bytes")
        if type(expected_envelope) is not AgentTaskEnvelopeV12:
            raise TypeError("expected_envelope must be AgentTaskEnvelopeV12")
        _require_text(authenticated_agent_ref, "authenticated_agent_ref", 65_536)
        AgentTaskCatalogV12.validate_envelope(expected_envelope)

        policy = self._policy_registry.current()
        if type(policy) is not AgentTaskResultDecodePolicyV12:
            raise TypeError("policy registry returned a non-canonical policy")
        body = _decode_result_body(serialized_result, limits=policy.limits)
        _require_result_fields(body)
        if (
            _as_text(body["task_id"], "task_id") != expected_envelope.task_id
            or _as_text(body["operation_id"], "operation_id")
            != expected_envelope.operation_id.value
            or _as_text(body["result_schema_version"], "result_schema_version")
            != expected_envelope.result_schema_version.value
        ):
            raise ValueError("agent_result_envelope_mismatch")
        self._ownership_registry.assert_agent_owns_task(
            authenticated_agent_ref=authenticated_agent_ref,
            expected_envelope=expected_envelope,
        )
        result = _result_from_wire(body, limits=policy.limits)
        _validate_result_variant(result, policy.limits)
        if float(result.completed_at) < float(expected_envelope.issued_at):
            raise ValueError("agent result predates the expected task envelope")
        return result


def _current_max_collection(limits: AgentTaskResultDecodeLimitsV12) -> int:
    return max(
        limits.max_collection_items,
        limits.max_processes,
        limits.max_services,
        limits.max_interfaces,
        limits.max_routes,
        limits.max_connections,
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_non_finite(token: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {token}")


def _decode_canonical_json(
    serialized: bytes,
    *,
    limits: AgentTaskResultDecodeLimitsV12,
) -> dict[str, object]:
    try:
        text = serialized.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("V12 JSON body is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_non_finite,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("V12 JSON body is malformed") from exc
    _validate_json_shape(
        value,
        limits=limits,
        depth=1,
        max_collection_items=_current_max_collection(limits),
    )
    if type(value) is not dict:
        raise ValueError("V12 JSON body must be an object")
    if not hmac.compare_digest(_canonical_json(value), serialized):
        raise ValueError("V12 JSON body is not canonical")
    return value


def _validate_json_shape(
    value: object,
    *,
    limits: AgentTaskResultDecodeLimitsV12,
    depth: int,
    max_collection_items: int,
) -> None:
    if depth > limits.max_depth:
        raise ValueError("V12 JSON nesting exceeds the configured depth bound")
    if type(value) is str:
        if len(value.encode("utf-8")) > limits.max_string_bytes:
            raise ValueError("V12 JSON string exceeds the configured byte bound")
        return
    if value is None or type(value) in (bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("V12 JSON contains a non-finite number")
        return
    if type(value) is list:
        if len(value) > max_collection_items:
            raise ValueError("V12 JSON collection exceeds the configured item bound")
        for item in value:
            _validate_json_shape(
                item,
                limits=limits,
                depth=depth + 1,
                max_collection_items=max_collection_items,
            )
        return
    if type(value) is dict:
        if len(value) > limits.max_collection_items:
            raise ValueError("V12 JSON object exceeds the configured field bound")
        for key, item in value.items():
            _require_text(key, "JSON field name", limits.max_string_bytes)
            _validate_json_shape(
                item,
                limits=limits,
                depth=depth + 1,
                max_collection_items=max_collection_items,
            )
        return
    raise ValueError(f"unsupported JSON value type: {type(value).__name__}")


def _encode_frame_mutable(
    *,
    kind: AgentWireMessageKindV12,
    body_value: Mapping[str, object],
    secret: bytearray | memoryview,
    integrity_tag: SensitiveIntegrityTagV2 | None,
    limits: AgentTaskResultDecodeLimitsV12,
) -> bytearray:
    body = _canonical_json(body_value)
    _decode_canonical_json(body, limits=limits)
    if kind is AgentWireMessageKindV12.REGISTRATION:
        if not secret or integrity_tag is None:
            raise ValueError("registration requires a non-empty authenticated secret segment")
    elif secret or integrity_tag is not None:
        raise ValueError("only registration may contain a secret segment")
    tag_bytes = b"" if integrity_tag is None else _canonical_json(_tag_to_wire(integrity_tag))
    if len(tag_bytes) > 65_535:
        raise ValueError("secret integrity metadata exceeds its frame bound")
    digest = hashlib.sha256(body).digest()
    header = _HEADER.pack(
        _MAGIC,
        _WIRE_VERSION,
        int(kind),
        len(body),
        len(secret),
        digest,
        len(tag_bytes),
    )
    frame = bytearray(header)
    frame.extend(tag_bytes)
    frame.extend(body)
    frame.extend(secret)
    if len(frame) > limits.max_frame_bytes:
        _wipe(frame)
        raise ValueError("V12 wire frame exceeds the configured frame bound")
    return frame


def _decode_frame(
    frame: bytes | bytearray,
    *,
    expected_kind: AgentWireMessageKindV12,
    limits: AgentTaskResultDecodeLimitsV12,
) -> tuple[dict[str, object], bytearray, AgentWireFrameHeaderV12]:
    if type(frame) not in (bytes, bytearray):
        raise TypeError("V12 wire frame must be bytes or owned mutable storage")
    if len(frame) > limits.max_frame_bytes:
        raise ValueError("V12 wire frame exceeds the configured frame bound")
    if len(frame) < _HEADER.size:
        raise ValueError("V12 wire frame header is truncated")
    magic, wire_version, raw_kind, body_length, secret_length, digest, tag_length = _HEADER.unpack_from(frame)
    if magic != _MAGIC:
        raise ValueError("invalid V12 wire frame magic")
    if wire_version != _WIRE_VERSION:
        raise ValueError("unsupported V12 wire frame version")
    try:
        kind = AgentWireMessageKindV12(raw_kind)
    except ValueError as exc:
        raise ValueError("unknown V12 wire message kind") from exc
    if kind is not expected_kind:
        raise ValueError(f"unexpected V12 wire message kind: {kind.name}")
    total_length = _HEADER.size + tag_length + body_length + secret_length
    if total_length != len(frame):
        raise ValueError("V12 wire frame length mismatch or trailing bytes")
    tag_start = _HEADER.size
    body_start = tag_start + tag_length
    secret_start = body_start + body_length
    frame_view = memoryview(frame)
    try:
        tag_bytes = bytes(frame_view[tag_start:body_start])
        body_bytes = bytes(frame_view[body_start:secret_start])
        secret = bytearray(frame_view[secret_start:])
    finally:
        frame_view.release()
    try:
        if not hmac.compare_digest(hashlib.sha256(body_bytes).digest(), digest):
            raise ValueError("V12 canonical body digest mismatch")

        tag: SensitiveIntegrityTagV2 | None = None
        if kind is AgentWireMessageKindV12.REGISTRATION:
            if secret_length < 1 or tag_length < 1:
                raise ValueError("registration requires secret data and integrity metadata")
            tag = _tag_from_wire(_decode_canonical_json(tag_bytes, limits=limits))
        elif secret_length != 0 or tag_length != 0:
            raise ValueError("non-registration frame contains a secret segment")
        body = _decode_canonical_json(body_bytes, limits=limits)
        header = AgentWireFrameHeaderV12(
            magic="OCT12",
            wire_version=1,
            message_kind=kind,
            canonical_body_length=body_length,
            secret_segment_length=secret_length,
            canonical_body_digest=digest.hex(),
            secret_integrity_tag_length=tag_length,
            secret_segment_integrity_tag=tag,
        )
        return body, secret, header
    except BaseException:
        _wipe(secret)
        raise


def _exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    object_name: str,
) -> None:
    actual = frozenset(value)
    if actual != expected:
        unknown = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise ValueError(f"{object_name} fields are not exact; unknown={unknown}, missing={missing}")


def _as_text(value: object, field_name: str) -> str:
    _require_text(value, field_name, 65_536)
    return cast(str, value)


def _as_bool(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{field_name} must be a boolean")
    return value


def _as_int(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    return value


def _as_float(value: object, field_name: str) -> float:
    if type(value) not in (int, float):
        raise TypeError(f"{field_name} must be a finite number")
    numeric = float(cast(float, value))
    if not math.isfinite(numeric):
        raise TypeError(f"{field_name} must be a finite number")
    return numeric


def _as_object(value: object, field_name: str) -> dict[str, object]:
    if type(value) is not dict:
        raise TypeError(f"{field_name} must be an object")
    return value


def _as_list(value: object, field_name: str) -> list[object]:
    if type(value) is not list:
        raise TypeError(f"{field_name} must be an array")
    return value


def _tag_to_wire(tag: SensitiveIntegrityTagV2) -> dict[str, object]:
    if type(tag) is not SensitiveIntegrityTagV2:
        raise TypeError("integrity tag must be SensitiveIntegrityTagV2")
    return {
        "algorithm": tag.algorithm,
        "domain": tag.domain,
        "key_id": tag.key_id,
        "tag": tag.tag,
    }


def _tag_from_wire(value: dict[str, object]) -> SensitiveIntegrityTagV2:
    _exact_fields(
        value,
        frozenset({"algorithm", "domain", "key_id", "tag"}),
        "integrity tag",
    )
    return SensitiveIntegrityTagV2(
        key_id=_as_text(value["key_id"], "integrity tag key_id"),
        algorithm=_require_integrity_algorithm(value["algorithm"]),
        domain=_as_text(value["domain"], "integrity tag domain"),
        tag=_as_text(value["tag"], "integrity tag"),
    )


def _registration_to_wire(
    registration: AgentRegistrationV12,
    *,
    enrollment_token_byte_length: int,
) -> dict[str, object]:
    capabilities = registration.capabilities
    return {
        "arch": registration.arch.value,
        "artifact_binding_digest": registration.artifact_binding_digest,
        "capabilities": {
            "capabilities_digest": capabilities.capabilities_digest,
            "supported_operation_ids": [item.value for item in capabilities.supported_operation_ids],
            "supported_payload_schema_versions": [
                item.value for item in capabilities.supported_payload_schema_versions
            ],
            "supported_result_schema_versions": [item.value for item in capabilities.supported_result_schema_versions],
        },
        "deployment_ref": registration.deployment_ref,
        "enrollment_token_byte_length": enrollment_token_byte_length,
        "hostname": registration.hostname,
        "os": registration.os.value,
        "protocol_version": registration.protocol_version,
        "user": registration.user,
    }


def _registration_from_wire(
    value: dict[str, object],
    *,
    secret: bytearray,
    limits: AgentTaskResultDecodeLimitsV12,
    buffer_factory: OwnedZeroizableSensitiveBufferFactoryV2,
    secret_value_factory: OpaqueSecretValueFactoryV2,
    integrity_tag: SensitiveIntegrityTagV2,
) -> AgentRegistrationV12:
    _exact_fields(
        value,
        frozenset(
            {
                "arch",
                "artifact_binding_digest",
                "capabilities",
                "deployment_ref",
                "enrollment_token_byte_length",
                "hostname",
                "os",
                "protocol_version",
                "user",
            }
        ),
        "registration",
    )
    if _as_int(value["enrollment_token_byte_length"], "enrollment_token_byte_length") != len(secret):
        raise ValueError("registration token length does not match the secret segment")
    capabilities_value = _as_object(value["capabilities"], "capabilities")
    _exact_fields(
        capabilities_value,
        frozenset(
            {
                "capabilities_digest",
                "supported_operation_ids",
                "supported_payload_schema_versions",
                "supported_result_schema_versions",
            }
        ),
        "capabilities",
    )
    operation_values = _as_list(capabilities_value["supported_operation_ids"], "supported_operation_ids")
    payload_values = _as_list(
        capabilities_value["supported_payload_schema_versions"],
        "supported_payload_schema_versions",
    )
    result_values = _as_list(
        capabilities_value["supported_result_schema_versions"],
        "supported_result_schema_versions",
    )
    if any(len(items) > limits.max_collection_items for items in (operation_values, payload_values, result_values)):
        raise ValueError("registration capability set exceeds the configured collection bound")
    for field_name, items in (
        ("supported_operation_ids", operation_values),
        ("supported_payload_schema_versions", payload_values),
        ("supported_result_schema_versions", result_values),
    ):
        text_items = [_as_text(item, field_name) for item in items]
        if text_items != sorted(text_items) or len(text_items) != len(set(text_items)):
            raise ValueError(f"{field_name} must be sorted and unique")
    capabilities = AgentCapabilitySetV12(
        supported_operation_ids=tuple(
            C2TaskOperationId(_as_text(item, "supported operation ID")) for item in operation_values
        ),
        supported_payload_schema_versions=tuple(
            AgentPayloadSchemaIdV12(_as_text(item, "supported payload schema")) for item in payload_values
        ),
        supported_result_schema_versions=tuple(
            AgentResultSchemaIdV12(_as_text(item, "supported result schema")) for item in result_values
        ),
        capabilities_digest=_as_text(capabilities_value["capabilities_digest"], "capabilities_digest"),
    )
    owned_buffer: OwnedZeroizableSensitiveBufferV2 | None = None
    try:
        owned_buffer = buffer_factory.from_owned_mutable(
            source=secret,
            domain=_REGISTRATION_SECRET_DOMAIN,
        )
        if owned_buffer.integrity_tag != integrity_tag:
            raise ValueError("decoded registration secret tag is not canonical")
        enrollment_token = secret_value_factory.from_owned_buffer(
            value_id=f"agent-registration-{integrity_tag.tag[:24]}",
            buffer=owned_buffer,
        )
        owned_buffer = None
        try:
            return AgentRegistrationV12(
                protocol_version=_require_literal(
                    value["protocol_version"], C2_AGENT_PROTOCOL_V12, "protocol_version"
                ),
                capabilities=capabilities,
                deployment_ref=_as_text(value["deployment_ref"], "deployment_ref"),
                artifact_binding_digest=_as_text(
                    value["artifact_binding_digest"], "artifact_binding_digest"
                ),
                enrollment_token=enrollment_token,
                hostname=_as_text(value["hostname"], "hostname"),
                os=C2TargetOS(_as_text(value["os"], "os")),
                arch=C2TargetArch(_as_text(value["arch"], "arch")),
                user=_as_text(value["user"], "user"),
            )
        except BaseException:
            enrollment_token.clear()
            raise
    finally:
        if owned_buffer is not None:
            owned_buffer.zeroize()


def _payload_to_wire(payload: object) -> dict[str, object]:
    if type(payload) is AgentIdentityTaskPayloadV12:
        return {"payload_kind": payload.payload_kind, "schema_version": payload.schema_version}
    if type(payload) is AgentHostInventoryTaskPayloadV12:
        return {
            "include_processes": payload.include_processes,
            "include_services": payload.include_services,
            "max_items": payload.max_items,
            "payload_kind": payload.payload_kind,
            "schema_version": payload.schema_version,
        }
    if type(payload) is AgentNetworkInventoryTaskPayloadV12:
        return {
            "include_connections": payload.include_connections,
            "include_routes": payload.include_routes,
            "max_items": payload.max_items,
            "payload_kind": payload.payload_kind,
            "schema_version": payload.schema_version,
        }
    if type(payload) is AgentServiceInventoryTaskPayloadV12:
        return {
            "include_status": payload.include_status,
            "payload_kind": payload.payload_kind,
            "schema_version": payload.schema_version,
            "service_names": list(payload.service_names),
        }
    raise TypeError("payload is not a closed V12 task payload")


def _payload_from_wire(
    value: dict[str, object],
    *,
    limits: AgentTaskResultDecodeLimitsV12,
) -> AgentTaskPayloadV12:
    kind = _as_text(value.get("payload_kind"), "payload_kind")
    schema = _as_text(value.get("schema_version"), "payload schema_version")
    if kind == "identity" and schema == AgentPayloadSchemaIdV12.IDENTITY_V1.value:
        _exact_fields(value, frozenset({"payload_kind", "schema_version"}), "identity payload")
        return AgentIdentityTaskPayloadV12()
    if kind == "host_inventory" and schema == AgentPayloadSchemaIdV12.HOST_INVENTORY_V1.value:
        _exact_fields(
            value,
            frozenset({"include_processes", "include_services", "max_items", "payload_kind", "schema_version"}),
            "host inventory payload",
        )
        max_items = _as_int(value["max_items"], "max_items")
        if max_items > limits.max_collection_items:
            raise ValueError("host inventory max_items exceeds the configured collection bound")
        return AgentHostInventoryTaskPayloadV12(
            include_processes=_as_bool(value["include_processes"], "include_processes"),
            include_services=_as_bool(value["include_services"], "include_services"),
            max_items=max_items,
        )
    if kind == "network_inventory" and schema == AgentPayloadSchemaIdV12.NETWORK_INVENTORY_V1.value:
        _exact_fields(
            value,
            frozenset({"include_connections", "include_routes", "max_items", "payload_kind", "schema_version"}),
            "network inventory payload",
        )
        max_items = _as_int(value["max_items"], "max_items")
        if max_items > limits.max_collection_items:
            raise ValueError("network inventory max_items exceeds the configured collection bound")
        return AgentNetworkInventoryTaskPayloadV12(
            include_routes=_as_bool(value["include_routes"], "include_routes"),
            include_connections=_as_bool(value["include_connections"], "include_connections"),
            max_items=max_items,
        )
    if kind == "service_inventory" and schema == AgentPayloadSchemaIdV12.SERVICE_INVENTORY_V1.value:
        _exact_fields(
            value,
            frozenset({"include_status", "payload_kind", "schema_version", "service_names"}),
            "service inventory payload",
        )
        names = _as_list(value["service_names"], "service_names")
        if len(names) > limits.max_collection_items:
            raise ValueError("service_names exceeds the configured collection bound")
        return AgentServiceInventoryTaskPayloadV12(
            service_names=tuple(_as_text(item, "service name") for item in names),
            include_status=_as_bool(value["include_status"], "include_status"),
        )
    raise ValueError("unknown V12 task payload kind/schema pair")


def _task_to_wire(task: AgentTaskEnvelopeV12) -> dict[str, object]:
    return {
        "delivery_attempt": task.delivery_attempt,
        "expected_agent_artifact_binding_digest": task.expected_agent_artifact_binding_digest,
        "expected_agent_capabilities_digest": task.expected_agent_capabilities_digest,
        "expected_agent_capabilities_revision": task.expected_agent_capabilities_revision,
        "expires_at": task.expires_at,
        "issued_at": task.issued_at,
        "operation_id": task.operation_id.value,
        "payload": _payload_to_wire(task.payload),
        "payload_schema_version": task.payload_schema_version.value,
        "result_schema_version": task.result_schema_version.value,
        "schema_version": task.schema_version,
        "task_id": task.task_id,
    }


def _task_from_wire(
    value: dict[str, object],
    *,
    limits: AgentTaskResultDecodeLimitsV12,
) -> AgentTaskEnvelopeV12:
    _exact_fields(
        value,
        frozenset(
            {
                "delivery_attempt",
                "expected_agent_artifact_binding_digest",
                "expected_agent_capabilities_digest",
                "expected_agent_capabilities_revision",
                "expires_at",
                "issued_at",
                "operation_id",
                "payload",
                "payload_schema_version",
                "result_schema_version",
                "schema_version",
                "task_id",
            }
        ),
        "task envelope",
    )
    payload = _payload_from_wire(
        _as_object(value["payload"], "payload"),
        limits=limits,
    )
    return AgentTaskEnvelopeV12(
        schema_version=_require_literal(value["schema_version"], C2_TASK_SCHEMA_V12, "schema_version"),
        task_id=_as_text(value["task_id"], "task_id"),
        operation_id=C2TaskOperationId(_as_text(value["operation_id"], "operation_id")),
        payload_schema_version=AgentPayloadSchemaIdV12(
            _as_text(value["payload_schema_version"], "payload_schema_version")
        ),
        result_schema_version=AgentResultSchemaIdV12(_as_text(value["result_schema_version"], "result_schema_version")),
        expected_agent_capabilities_revision=_as_int(
            value["expected_agent_capabilities_revision"],
            "expected_agent_capabilities_revision",
        ),
        expected_agent_capabilities_digest=_as_text(
            value["expected_agent_capabilities_digest"],
            "expected_agent_capabilities_digest",
        ),
        expected_agent_artifact_binding_digest=_as_text(
            value["expected_agent_artifact_binding_digest"],
            "expected_agent_artifact_binding_digest",
        ),
        payload=payload,
        issued_at=_as_float(value["issued_at"], "issued_at"),
        expires_at=_as_float(value["expires_at"], "expires_at"),
        delivery_attempt=_as_int(value["delivery_attempt"], "delivery_attempt"),
    )


def _summary_to_wire(value: object) -> dict[str, object]:
    if type(value) is AgentProcessSummaryV12:
        return {"name": value.name, "pid": value.pid}
    if type(value) is AgentServiceSummaryV12:
        return {"name": value.name, "status": value.status}
    if type(value) is AgentInterfaceSummaryV12:
        return {"addresses": list(value.addresses), "name": value.name}
    if type(value) is AgentRouteSummaryV12:
        return {"destination": value.destination, "gateway": value.gateway, "interface": value.interface}
    if type(value) is AgentConnectionSummaryV12:
        return {
            "local_endpoint": value.local_endpoint,
            "protocol": value.protocol.value,
            "remote_endpoint": value.remote_endpoint,
            "state": value.state,
        }
    raise TypeError("unsupported V12 result summary")


def _output_to_wire(output: object) -> dict[str, object]:
    if type(output) is AgentIdentityTaskOutputV12:
        return {
            "arch": output.arch.value,
            "hostname": output.hostname,
            "os": output.os.value,
            "output_kind": output.output_kind,
            "process_id": output.process_id,
            "schema_version": output.schema_version,
            "user": output.user,
        }
    if type(output) is AgentHostInventoryTaskOutputV12:
        return {
            "output_kind": output.output_kind,
            "processes": [_summary_to_wire(item) for item in output.processes],
            "schema_version": output.schema_version,
            "services": [_summary_to_wire(item) for item in output.services],
            "truncated": output.truncated,
        }
    if type(output) is AgentNetworkInventoryTaskOutputV12:
        return {
            "connections": [_summary_to_wire(item) for item in output.connections],
            "interfaces": [_summary_to_wire(item) for item in output.interfaces],
            "output_kind": output.output_kind,
            "routes": [_summary_to_wire(item) for item in output.routes],
            "schema_version": output.schema_version,
            "truncated": output.truncated,
        }
    if type(output) is AgentServiceInventoryTaskOutputV12:
        return {
            "output_kind": output.output_kind,
            "schema_version": output.schema_version,
            "services": [_summary_to_wire(item) for item in output.services],
            "truncated": output.truncated,
        }
    raise TypeError("output is not a closed V12 result variant")


def _process_from_wire(value: object) -> AgentProcessSummaryV12:
    item = _as_object(value, "process summary")
    _exact_fields(item, frozenset({"name", "pid"}), "process summary")
    return AgentProcessSummaryV12(pid=_as_int(item["pid"], "pid"), name=_as_text(item["name"], "name"))


def _service_from_wire(value: object) -> AgentServiceSummaryV12:
    item = _as_object(value, "service summary")
    _exact_fields(item, frozenset({"name", "status"}), "service summary")
    return AgentServiceSummaryV12(
        name=_as_text(item["name"], "name"),
        status=_as_text(item["status"], "status"),
    )


def _interface_from_wire(
    value: object,
    *,
    limits: AgentTaskResultDecodeLimitsV12,
) -> AgentInterfaceSummaryV12:
    item = _as_object(value, "interface summary")
    _exact_fields(item, frozenset({"addresses", "name"}), "interface summary")
    addresses = _as_list(item["addresses"], "addresses")
    if len(addresses) > limits.max_collection_items:
        raise ValueError("interface addresses exceed the configured collection bound")
    return AgentInterfaceSummaryV12(
        name=_as_text(item["name"], "name"),
        addresses=tuple(_as_text(address, "address") for address in addresses),
    )


def _route_from_wire(value: object) -> AgentRouteSummaryV12:
    item = _as_object(value, "route summary")
    _exact_fields(item, frozenset({"destination", "gateway", "interface"}), "route summary")
    gateway = item["gateway"]
    return AgentRouteSummaryV12(
        destination=_as_text(item["destination"], "destination"),
        gateway=None if gateway is None else _as_text(gateway, "gateway"),
        interface=_as_text(item["interface"], "interface"),
    )


def _connection_from_wire(value: object) -> AgentConnectionSummaryV12:
    item = _as_object(value, "connection summary")
    _exact_fields(
        item,
        frozenset({"local_endpoint", "protocol", "remote_endpoint", "state"}),
        "connection summary",
    )
    remote_endpoint = item["remote_endpoint"]
    return AgentConnectionSummaryV12(
        protocol=NetworkProtocol(_as_text(item["protocol"], "protocol")),
        local_endpoint=_as_text(item["local_endpoint"], "local_endpoint"),
        remote_endpoint=(None if remote_endpoint is None else _as_text(remote_endpoint, "remote_endpoint")),
        state=_as_text(item["state"], "state"),
    )


def _output_from_wire(
    value: dict[str, object],
    *,
    limits: AgentTaskResultDecodeLimitsV12,
) -> AgentTaskOutput:
    kind = _as_text(value.get("output_kind"), "output_kind")
    schema = _as_text(value.get("schema_version"), "output schema_version")
    if kind == "identity" and schema == AgentResultSchemaIdV12.IDENTITY_V1.value:
        _exact_fields(
            value,
            frozenset({"arch", "hostname", "os", "output_kind", "process_id", "schema_version", "user"}),
            "identity output",
        )
        return AgentIdentityTaskOutputV12(
            hostname=_as_text(value["hostname"], "hostname"),
            os=C2TargetOS(_as_text(value["os"], "os")),
            arch=C2TargetArch(_as_text(value["arch"], "arch")),
            user=_as_text(value["user"], "user"),
            process_id=_as_int(value["process_id"], "process_id"),
        )
    if kind == "host_inventory" and schema == AgentResultSchemaIdV12.HOST_INVENTORY_V1.value:
        _exact_fields(
            value,
            frozenset({"output_kind", "processes", "schema_version", "services", "truncated"}),
            "host inventory output",
        )
        processes = _as_list(value["processes"], "processes")
        services = _as_list(value["services"], "services")
        if len(processes) > limits.max_processes or len(services) > limits.max_services:
            raise ValueError("host inventory output exceeds its configured collection bound")
        return AgentHostInventoryTaskOutputV12(
            processes=tuple(_process_from_wire(item) for item in processes),
            services=tuple(_service_from_wire(item) for item in services),
            truncated=_as_bool(value["truncated"], "truncated"),
        )
    if kind == "network_inventory" and schema == AgentResultSchemaIdV12.NETWORK_INVENTORY_V1.value:
        _exact_fields(
            value,
            frozenset({"connections", "interfaces", "output_kind", "routes", "schema_version", "truncated"}),
            "network inventory output",
        )
        interfaces = _as_list(value["interfaces"], "interfaces")
        routes = _as_list(value["routes"], "routes")
        connections = _as_list(value["connections"], "connections")
        if (
            len(interfaces) > limits.max_interfaces
            or len(routes) > limits.max_routes
            or len(connections) > limits.max_connections
        ):
            raise ValueError("network inventory output exceeds its configured collection bound")
        return AgentNetworkInventoryTaskOutputV12(
            interfaces=tuple(_interface_from_wire(item, limits=limits) for item in interfaces),
            routes=tuple(_route_from_wire(item) for item in routes),
            connections=tuple(_connection_from_wire(item) for item in connections),
            truncated=_as_bool(value["truncated"], "truncated"),
        )
    if kind == "service_inventory" and schema == AgentResultSchemaIdV12.SERVICE_INVENTORY_V1.value:
        _exact_fields(
            value,
            frozenset({"output_kind", "schema_version", "services", "truncated"}),
            "service inventory output",
        )
        services = _as_list(value["services"], "services")
        if len(services) > limits.max_services:
            raise ValueError("service inventory output exceeds its configured collection bound")
        return AgentServiceInventoryTaskOutputV12(
            services=tuple(_service_from_wire(item) for item in services),
            truncated=_as_bool(value["truncated"], "truncated"),
        )
    raise ValueError("unknown V12 result output kind/schema pair")


def _result_to_wire(result: AgentTaskResultV12) -> dict[str, object]:
    return {
        "completed_at": result.completed_at,
        "error_code": None if result.error_code is None else result.error_code.value,
        "operation_id": result.operation_id.value,
        "output": None if result.output is None else _output_to_wire(result.output),
        "result_id": result.result_id,
        "result_schema_version": result.result_schema_version.value,
        "schema_version": result.schema_version,
        "status": result.status.value,
        "task_id": result.task_id,
    }


_RESULT_FIELDS = frozenset(
    {
        "completed_at",
        "error_code",
        "operation_id",
        "output",
        "result_id",
        "result_schema_version",
        "schema_version",
        "status",
        "task_id",
    }
)


def _require_result_fields(value: Mapping[str, object]) -> None:
    _exact_fields(value, _RESULT_FIELDS, "task result")


def _result_from_wire(
    value: dict[str, object],
    *,
    limits: AgentTaskResultDecodeLimitsV12,
) -> AgentTaskResultV12:
    _require_result_fields(value)
    operation_id = C2TaskOperationId(_as_text(value["operation_id"], "operation_id"))
    result_schema_version = AgentResultSchemaIdV12(
        _as_text(value["result_schema_version"], "result_schema_version")
    )
    if AgentTaskCatalogV12.require_spec(operation_id).result_schema_version is not result_schema_version:
        raise ValueError("operation/result schema mapping is not canonical")
    raw_output = value["output"]
    raw_error = value["error_code"]
    status = AgentTaskStatus(_as_text(value["status"], "status"))
    error = None if raw_error is None else AgentTaskErrorCode(_as_text(raw_error, "error_code"))
    if status is AgentTaskStatus.SUCCEEDED:
        if raw_output is None or error is not None:
            raise ValueError("SUCCEEDED requires output and error_code=None")
    elif status is AgentTaskStatus.PARTIAL:
        if raw_output is None:
            raise ValueError("PARTIAL requires output")
    elif error is None:
        raise ValueError("non-success result status requires error_code")
    output = None if raw_output is None else _output_from_wire(_as_object(raw_output, "output"), limits=limits)
    if output is not None:
        AgentTaskCatalogV12.validate_output(
            operation_id=operation_id,
            result_schema_version=result_schema_version,
            output=output,
        )
    return AgentTaskResultV12(
        schema_version=_require_literal(value["schema_version"], C2_TASK_SCHEMA_V12, "schema_version"),
        result_schema_version=result_schema_version,
        result_id=_as_text(value["result_id"], "result_id"),
        task_id=_as_text(value["task_id"], "task_id"),
        operation_id=operation_id,
        status=status,
        output=output,
        error_code=error,
        completed_at=_as_float(value["completed_at"], "completed_at"),
    )


def _delivery_ack_to_wire(ack: AgentTaskDeliveryAckV12) -> dict[str, object]:
    return {
        "delivery_attempt": ack.delivery_attempt,
        "received_at": ack.received_at,
        "schema_version": ack.schema_version,
        "task_id": ack.task_id,
    }


def _delivery_ack_from_wire(value: dict[str, object]) -> AgentTaskDeliveryAckV12:
    _exact_fields(
        value,
        frozenset({"delivery_attempt", "received_at", "schema_version", "task_id"}),
        "delivery acknowledgement",
    )
    return AgentTaskDeliveryAckV12(
        schema_version=_require_literal(value["schema_version"], C2_TASK_SCHEMA_V12, "schema_version"),
        task_id=_as_text(value["task_id"], "task_id"),
        delivery_attempt=_as_int(value["delivery_attempt"], "delivery_attempt"),
        received_at=_as_float(value["received_at"], "received_at"),
    )


def _validate_task_collection_limits(
    task: AgentTaskEnvelopeV12,
    limits: AgentTaskResultDecodeLimitsV12,
) -> None:
    payload = task.payload
    if (
        type(payload) is AgentServiceInventoryTaskPayloadV12
        and len(payload.service_names) > limits.max_collection_items
    ):
        raise ValueError("service_names exceeds the configured collection bound")
    if type(payload) is AgentHostInventoryTaskPayloadV12 and payload.max_items > limits.max_collection_items:
        raise ValueError("task max_items exceeds the configured collection bound")
    if type(payload) is AgentNetworkInventoryTaskPayloadV12 and payload.max_items > limits.max_collection_items:
        raise ValueError("task max_items exceeds the configured collection bound")


def _validate_result_variant(
    result: AgentTaskResultV12,
    limits: AgentTaskResultDecodeLimitsV12,
) -> None:
    if type(result) is not AgentTaskResultV12:
        raise TypeError("result must be AgentTaskResultV12")
    spec = AgentTaskCatalogV12.require_spec(result.operation_id)
    if result.result_schema_version is not spec.result_schema_version:
        raise ValueError("operation/result schema mapping is not canonical")
    if result.output is not None:
        AgentTaskCatalogV12.validate_output(
            operation_id=result.operation_id,
            result_schema_version=result.result_schema_version,
            output=result.output,
        )
    output = result.output
    if type(output) is AgentHostInventoryTaskOutputV12:
        if len(output.processes) > limits.max_processes or len(output.services) > limits.max_services:
            raise ValueError("host inventory output exceeds its configured collection bound")
    elif type(output) is AgentNetworkInventoryTaskOutputV12:
        if (
            len(output.interfaces) > limits.max_interfaces
            or len(output.routes) > limits.max_routes
            or len(output.connections) > limits.max_connections
        ):
            raise ValueError("network inventory output exceeds its configured collection bound")
    elif type(output) is AgentServiceInventoryTaskOutputV12 and len(output.services) > limits.max_services:
        raise ValueError("service inventory output exceeds its configured collection bound")


def _require_literal(value: object, expected: str, field_name: str) -> Literal["12.0"]:
    if value != expected or type(value) is not str:
        raise ValueError(f"{field_name} must equal {expected!r}")
    return cast(Literal["12.0"], value)


def _require_integrity_algorithm(value: object) -> Literal["hmac-sha256-v2"]:
    if value != "hmac-sha256-v2" or type(value) is not str:
        raise ValueError("integrity tag algorithm is not canonical")
    return cast(Literal["hmac-sha256-v2"], value)


def _require_text(value: object, field_name: str, max_bytes: int) -> None:
    if type(value) is not str or not value or len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field_name} must be a non-empty bounded string")


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


__all__ = [
    "AgentTaskCodecV12",
    "AgentTaskOwnershipRegistryV12",
    "AgentTaskResultDecodeLimitsV12",
    "AgentTaskResultDecodePolicyRegistryV12",
    "AgentTaskResultDecodePolicyV12",
    "AgentTaskResultDecoderV12",
    "AgentWireCodecV12",
    "AgentWireFrameHeaderV12",
    "AgentWireMessageKindV12",
    "StaticAgentTaskResultDecodePolicyRegistryV12",
    "canonical_agent_task_result_decode_policy",
    "compute_result_decode_config_digest",
]
