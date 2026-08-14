"""Fail-closed exact decoders for the 20 V2 action input schemas."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import MISSING, fields, is_dataclass
from enum import Enum
from typing import Callable, Literal, TypeVar, Union, cast, get_args, get_origin, get_type_hints

from core.actions.input_contracts import (
    C2ChannelCreateInputV2,
    C2CleanupInputV2,
    C2DeployInputV3,
    C2EnrollmentIssueInput,
    C2TaskInputV2,
    CredentialDumpInputV2,
    DNSC2ChannelInputV2,
    KerberosCrackInputV2,
    KerberosExtractInputV2,
    PassTheHashInputV2,
    PassTheTicketInputV2,
    PayloadKeyingInputV2,
    PivotProxyScanInputV2,
    RemoteExecInputV2,
    RemoteForwardInputV2,
    SSHChainInputV2,
    V2InputUnion,
)
from core.actions.request_v2 import BoundedTypedInputPayloadV2

_MAX_TYPED_INPUT_BYTES = 10 * 1024 * 1024
_T = TypeVar("_T")


class TypedInputDecoderError(ValueError):
    pass


class TypedInputDecoderNotRegistered(TypedInputDecoderError):
    def __init__(self, action_id: str, input_schema_id: str) -> None:
        super().__init__(f"No typed input decoder registered for action '{action_id}' (schema '{input_schema_id}')")
        self.action_id = action_id
        self.input_schema_id = input_schema_id


class DuplicateTypedInputDecoder(TypedInputDecoderError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TypedInputDecoderError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _decode_json(payload: BoundedTypedInputPayloadV2) -> dict[str, object]:
    if type(payload) is not BoundedTypedInputPayloadV2:
        raise TypedInputDecoderError("decoder accepts only a bounded typed-input payload")
    if type(payload.canonical_json) is not bytes:
        raise TypedInputDecoderError("canonical_json must be bytes")
    if len(payload.canonical_json) > _MAX_TYPED_INPUT_BYTES:
        raise TypedInputDecoderError("typed input exceeds maximum size")
    if isinstance(payload.byte_length, bool) or payload.byte_length != len(payload.canonical_json):
        raise TypedInputDecoderError("typed input byte length mismatch")
    expected_digest = "sha256:" + hashlib.sha256(payload.canonical_json).hexdigest()
    if payload.sha256_digest != expected_digest:
        raise TypedInputDecoderError("typed input digest mismatch")
    try:
        decoded = json.loads(
            payload.canonical_json.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                TypedInputDecoderError(f"non-finite JSON number: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TypedInputDecoderError("typed input is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise TypedInputDecoderError("typed input must be a JSON object")
    schema_id = decoded.get("schema_id")
    if schema_id != payload.schema_id:
        raise TypedInputDecoderError("typed input schema_id mismatch")
    return {key: value for key, value in decoded.items() if key != "schema_id"}


def _coerce_value(value: object, annotation: object, *, path: str) -> object:
    origin = get_origin(annotation)
    arguments = get_args(annotation)

    if origin is Union:
        successes: list[object] = []
        for variant in arguments:
            if variant is type(None) and value is None:
                successes.append(None)
                continue
            try:
                successes.append(_coerce_value(value, variant, path=path))
            except TypedInputDecoderError:
                continue
        if len(successes) != 1:
            raise TypedInputDecoderError(f"{path} does not match exactly one closed variant")
        return successes[0]

    if origin is Literal:
        if not any(type(value) is type(candidate) and value == candidate for candidate in arguments):
            raise TypedInputDecoderError(f"{path} has an unsupported literal value")
        return value

    if origin in (tuple,):
        if not isinstance(value, list):
            raise TypedInputDecoderError(f"{path} must be a JSON array")
        if len(arguments) != 2 or arguments[1] is not Ellipsis:
            raise TypedInputDecoderError(f"{path} uses an unsupported tuple schema")
        return tuple(_coerce_value(item, arguments[0], path=f"{path}[{index}]") for index, item in enumerate(value))

    if isinstance(annotation, type) and issubclass(annotation, Enum):
        if not isinstance(value, str):
            raise TypedInputDecoderError(f"{path} must be a string enum")
        try:
            return annotation(value)
        except ValueError as exc:
            raise TypedInputDecoderError(f"{path} has an unknown enum value") from exc

    if isinstance(annotation, type) and is_dataclass(annotation):
        if not isinstance(value, dict):
            raise TypedInputDecoderError(f"{path} must be an object")
        return _decode_dataclass(value, annotation, path=path)

    if annotation is str:
        if type(value) is not str or not value.strip() or any(ord(character) < 32 for character in value):
            raise TypedInputDecoderError(f"{path} must be a non-empty bounded string")
        return value.strip()
    if annotation is bool:
        if type(value) is not bool:
            raise TypedInputDecoderError(f"{path} must be a boolean")
        return value
    if annotation is int:
        if type(value) is not int:
            raise TypedInputDecoderError(f"{path} must be an integer")
        return value

    raise TypedInputDecoderError(f"{path} uses an unsupported schema type")


def _decode_dataclass(raw: Mapping[str, object], target_type: type[_T], *, path: str) -> _T:
    hints = get_type_hints(target_type)
    # ``is_dataclass`` is checked before this helper is called.  The stdlib
    # typing stubs cannot express that refinement for an otherwise-generic
    # runtime class, so narrow it explicitly at the single reflection point.
    dataclass_type = cast(type[object], target_type)
    target_fields = {item.name: item for item in fields(dataclass_type)}  # type: ignore[arg-type]
    unknown = set(raw) - set(target_fields)
    if unknown:
        raise TypedInputDecoderError(f"{path} contains unknown fields: {', '.join(sorted(unknown))}")

    kwargs: dict[str, object] = {}
    for name, item in target_fields.items():
        if not item.init:
            if name in raw:
                expected = item.default
                if expected is MISSING or raw[name] != expected:
                    raise TypedInputDecoderError(f"{path}.{name} has an invalid discriminator")
            continue
        if name not in raw:
            if item.default is not MISSING or item.default_factory is not MISSING:
                continue
            raise TypedInputDecoderError(f"{path}.{name} is required")
        kwargs[name] = _coerce_value(raw[name], hints[name], path=f"{path}.{name}")
    try:
        return target_type(**kwargs)
    except (TypeError, ValueError) as exc:
        raise TypedInputDecoderError(f"{path} failed closed validation: {exc}") from exc


_INPUT_TYPES: tuple[tuple[str, str, type[V2InputUnion]], ...] = (
    ("plugin:payload_keying", "octopus:input:payload_keying:2.0", PayloadKeyingInputV2),
    ("killchain:kerberos_extract_tickets", "octopus:input:kerberos_extract_tickets:2.0", KerberosExtractInputV2),
    ("killchain:kerberos_crack_tickets", "octopus:input:kerberos_crack_tickets:2.0", KerberosCrackInputV2),
    ("killchain:ad_pass_the_ticket", "octopus:input:ad_pass_the_ticket:2.0", PassTheTicketInputV2),
    ("killchain:pass_the_hash", "octopus:input:pass_the_hash:2.0", PassTheHashInputV2),
    ("killchain:ad_dump_lsass", "octopus:input:ad_dump_lsass:2.0", CredentialDumpInputV2),
    ("killchain:ad_sam_dump", "octopus:input:ad_sam_dump:2.0", CredentialDumpInputV2),
    ("killchain:ad_smbexec", "octopus:input:ad_smbexec:2.0", RemoteExecInputV2),
    ("killchain:ad_winrm_exec", "octopus:input:ad_winrm_exec:2.0", RemoteExecInputV2),
    ("killchain:ad_dcom_exec", "octopus:input:ad_dcom_exec:2.0", RemoteExecInputV2),
    ("killchain:ad_remote_execution", "octopus:input:ad_remote_execution:2.0", RemoteExecInputV2),
    ("killchain:pivot_remote_forward", "octopus:input:pivot_remote_forward:2.0", RemoteForwardInputV2),
    ("killchain:pivot_ssh_chain", "octopus:input:pivot_ssh_chain:2.0", SSHChainInputV2),
    ("killchain:pivot_proxy_scan", "octopus:input:pivot_proxy_scan:2.0", PivotProxyScanInputV2),
    ("c2:dns_c2_channel", "octopus:input:dns_c2_channel:2.0", DNSC2ChannelInputV2),
    ("c2:c2_enroll", "octopus:input:c2_enroll:2.0", C2EnrollmentIssueInput),
    ("c2:c2_deploy", "octopus:input:c2_deploy:3.0", C2DeployInputV3),
    ("c2:c2_channel_create", "octopus:input:c2_channel_create:2.0", C2ChannelCreateInputV2),
    ("c2:c2_task", "octopus:input:c2_task:2.0", C2TaskInputV2),
    ("c2:c2_cleanup", "octopus:input:c2_cleanup:2.0", C2CleanupInputV2),
)


class TypedInputDecoderRegistry:
    def __init__(self, *, register_defaults: bool = True) -> None:
        self._decoders: dict[tuple[str, str], Callable[[BoundedTypedInputPayloadV2], V2InputUnion]] = {}
        self._types: dict[tuple[str, str], type[V2InputUnion]] = {}
        if register_defaults:
            for action_id, schema_id, input_type in _INPUT_TYPES:
                self.register_exact(action_id, schema_id, input_type)

    def register_exact(
        self,
        action_id: str,
        input_schema_id: str,
        input_type: type[V2InputUnion],
    ) -> None:
        key = (action_id, input_schema_id)
        if key in self._decoders:
            raise DuplicateTypedInputDecoder(f"duplicate typed input decoder: {key!r}")

        def decode(payload: BoundedTypedInputPayloadV2) -> V2InputUnion:
            if payload.schema_id != input_schema_id:
                raise TypedInputDecoderError("decoder/schema binding mismatch")
            raw = _decode_json(payload)
            decoded = _decode_dataclass(raw, input_type, path="typed_input")
            if type(decoded) is not input_type:
                raise TypedInputDecoderError("decoder returned an unexpected runtime type")
            if type(decoded) is C2EnrollmentIssueInput:
                from core.runtime_config import load_c2_enrollment_bounds

                bounds = load_c2_enrollment_bounds()
                if not bounds.ttl_min_seconds <= decoded.ttl_seconds <= bounds.ttl_max_seconds:
                    raise TypedInputDecoderError("typed_input.ttl_seconds is outside configured bounds")
                if decoded.max_uses != bounds.max_uses_default:
                    raise TypedInputDecoderError("typed_input.max_uses violates configured single-use policy")
            return decoded

        self._decoders[key] = decode
        self._types[key] = input_type

    def decode(self, action_id: str, payload: BoundedTypedInputPayloadV2) -> V2InputUnion:
        if type(payload) is not BoundedTypedInputPayloadV2:
            raise TypedInputDecoderError("decoder accepts only a bounded typed-input payload")
        return self.require_decoder(action_id, payload.schema_id)(payload)

    def require_decoder(
        self,
        action_id: str,
        input_schema_id: str,
    ) -> Callable[[BoundedTypedInputPayloadV2], V2InputUnion]:
        try:
            return self._decoders[(action_id, input_schema_id)]
        except KeyError as exc:
            raise TypedInputDecoderNotRegistered(action_id, input_schema_id) from exc

    def bindings(self) -> tuple[tuple[str, str, type[V2InputUnion]], ...]:
        return tuple(
            (action_id, schema_id, self._types[(action_id, schema_id)]) for action_id, schema_id in self._types
        )


_GLOBAL_DECODER_REGISTRY = TypedInputDecoderRegistry()


def get_typed_input_decoder_registry() -> TypedInputDecoderRegistry:
    return _GLOBAL_DECODER_REGISTRY


__all__ = [
    "DuplicateTypedInputDecoder",
    "TypedInputDecoderError",
    "TypedInputDecoderNotRegistered",
    "TypedInputDecoderRegistry",
    "get_typed_input_decoder_registry",
]
