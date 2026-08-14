"""Closed result-publication bindings for the canonical 20 V2 actions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from core.actions.provider_results import (
    ArtifactProviderResult,
    C2ProviderResult,
    CompositeProviderResult,
    CredentialProviderResult,
    OperationProviderResult,
    ProviderResult,
    ProviderResultKind,
    RouteProviderResult,
    SensitiveProviderResult,
    SessionProviderResult,
)
from core.actions.schema_bindings import get_all_v2_schema_bindings


class ProviderResultSchemaRegistryError(RuntimeError):
    """Base class for fail-closed registry errors."""


class ResultSchemaNotRegistered(ProviderResultSchemaRegistryError):
    def __init__(self, action_id: str, result_schema_id: str) -> None:
        super().__init__(f"No result publication binding for action {action_id!r} and schema {result_schema_id!r}")
        self.action_id = action_id
        self.result_schema_id = result_schema_id


class ResultSchemaBindingMismatch(ProviderResultSchemaRegistryError):
    pass


class DuplicateResultSchemaRegistration(ProviderResultSchemaRegistryError):
    pass


class InvalidResultSchemaBinding(ProviderResultSchemaRegistryError):
    pass


class ResultVariantNotAllowed(ProviderResultSchemaRegistryError):
    pass


@dataclass(frozen=True)
class ProviderResultPublicationBindingV2:
    action_id: str
    result_schema_id: str
    allowed_result_kinds: tuple[ProviderResultKind, ...]
    allowed_runtime_type_ids: tuple[str, ...]
    projector_id: str
    binding_digest: str


_PROJECTOR_ID = "provider-result-projector-v2"

_RUNTIME_TYPES = {
    OperationProviderResult.__name__: OperationProviderResult,
    ArtifactProviderResult.__name__: ArtifactProviderResult,
    CredentialProviderResult.__name__: CredentialProviderResult,
    SessionProviderResult.__name__: SessionProviderResult,
    RouteProviderResult.__name__: RouteProviderResult,
    C2ProviderResult.__name__: C2ProviderResult,
    CompositeProviderResult.__name__: CompositeProviderResult,
    SensitiveProviderResult.__name__: SensitiveProviderResult,
}

_RUNTIME_KINDS = {
    OperationProviderResult.__name__: ProviderResultKind.OPERATION,
    ArtifactProviderResult.__name__: ProviderResultKind.ARTIFACT,
    CredentialProviderResult.__name__: ProviderResultKind.CREDENTIAL,
    SessionProviderResult.__name__: ProviderResultKind.SESSION,
    RouteProviderResult.__name__: ProviderResultKind.ROUTE,
    C2ProviderResult.__name__: ProviderResultKind.C2_RESOURCE,
    CompositeProviderResult.__name__: ProviderResultKind.COMPOSITE,
    SensitiveProviderResult.__name__: ProviderResultKind.SENSITIVE,
}

_CANONICAL_RESULT_TYPES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "plugin:payload_keying",
        "octopus:result:payload_keying:2.0",
        (ArtifactProviderResult.__name__,),
    ),
    (
        "killchain:kerberos_extract_tickets",
        "octopus:result:kerberos_extract_tickets:2.0",
        (ArtifactProviderResult.__name__,),
    ),
    (
        "killchain:kerberos_crack_tickets",
        "octopus:result:kerberos_crack_tickets:2.0",
        (CredentialProviderResult.__name__,),
    ),
    (
        "killchain:ad_pass_the_ticket",
        "octopus:result:ad_pass_the_ticket:2.0",
        (OperationProviderResult.__name__, SessionProviderResult.__name__),
    ),
    (
        "killchain:pass_the_hash",
        "octopus:result:pass_the_hash:2.0",
        (OperationProviderResult.__name__, SessionProviderResult.__name__),
    ),
    (
        "killchain:ad_dump_lsass",
        "octopus:result:ad_dump_lsass:2.0",
        (SensitiveProviderResult.__name__,),
    ),
    (
        "killchain:ad_sam_dump",
        "octopus:result:ad_sam_dump:2.0",
        (SensitiveProviderResult.__name__,),
    ),
    (
        "killchain:ad_smbexec",
        "octopus:result:ad_smbexec:2.0",
        (OperationProviderResult.__name__,),
    ),
    (
        "killchain:ad_winrm_exec",
        "octopus:result:ad_winrm_exec:2.0",
        (OperationProviderResult.__name__,),
    ),
    (
        "killchain:ad_dcom_exec",
        "octopus:result:ad_dcom_exec:2.0",
        (OperationProviderResult.__name__,),
    ),
    (
        "killchain:ad_remote_execution",
        "octopus:result:ad_remote_execution:2.0",
        (CompositeProviderResult.__name__,),
    ),
    (
        "killchain:pivot_remote_forward",
        "octopus:result:pivot_remote_forward:2.0",
        (RouteProviderResult.__name__,),
    ),
    (
        "killchain:pivot_ssh_chain",
        "octopus:result:pivot_ssh_chain:2.0",
        (SessionProviderResult.__name__,),
    ),
    (
        "killchain:pivot_proxy_scan",
        "octopus:result:pivot_proxy_scan:2.0",
        (OperationProviderResult.__name__,),
    ),
    (
        "c2:dns_c2_channel",
        "octopus:result:dns_c2_channel:2.0",
        (C2ProviderResult.__name__,),
    ),
    (
        "c2:c2_enroll",
        "octopus:result:c2_enroll:2.0",
        (C2ProviderResult.__name__,),
    ),
    (
        "c2:c2_deploy",
        "octopus:result:c2_deploy:2.0",
        (C2ProviderResult.__name__,),
    ),
    (
        "c2:c2_channel_create",
        "octopus:result:c2_channel_create:2.0",
        (CompositeProviderResult.__name__,),
    ),
    (
        "c2:c2_task",
        "octopus:result:c2_task:2.0",
        (C2ProviderResult.__name__,),
    ),
    (
        "c2:c2_cleanup",
        "octopus:result:c2_cleanup:2.0",
        (OperationProviderResult.__name__,),
    ),
)

_CANONICAL_RUNTIME_TYPES_BY_PAIR = {
    (action_id, result_schema_id): runtime_type_ids
    for action_id, result_schema_id, runtime_type_ids in _CANONICAL_RESULT_TYPES
}


def canonical_provider_result_publication_binding_digest(
    binding: ProviderResultPublicationBindingV2,
) -> str:
    """Digest every binding field except ``binding_digest`` itself."""

    payload = {
        "schema": "provider-result-publication-binding/2.0",
        "action_id": binding.action_id,
        "result_schema_id": binding.result_schema_id,
        "allowed_result_kinds": [kind.value for kind in binding.allowed_result_kinds],
        "allowed_runtime_type_ids": list(binding.allowed_runtime_type_ids),
        "projector_id": binding.projector_id,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _canonical_binding(
    action_id: str,
    result_schema_id: str,
    runtime_type_ids: tuple[str, ...],
) -> ProviderResultPublicationBindingV2:
    binding = ProviderResultPublicationBindingV2(
        action_id=action_id,
        result_schema_id=result_schema_id,
        allowed_result_kinds=tuple(_RUNTIME_KINDS[type_id] for type_id in runtime_type_ids),
        allowed_runtime_type_ids=runtime_type_ids,
        projector_id=_PROJECTOR_ID,
        binding_digest="",
    )
    return replace(
        binding,
        binding_digest=canonical_provider_result_publication_binding_digest(binding),
    )


def canonical_provider_result_publication_bindings() -> tuple[ProviderResultPublicationBindingV2, ...]:
    return tuple(_canonical_binding(*row) for row in _CANONICAL_RESULT_TYPES)


class ProviderResultSchemaRegistry:
    """Exact action/schema/variant registry; no raw-result decoder exists here."""

    def __init__(
        self,
        bindings: tuple[ProviderResultPublicationBindingV2, ...] | None = None,
    ) -> None:
        self._by_pair: dict[tuple[str, str], ProviderResultPublicationBindingV2] = {}
        self._by_action: dict[str, ProviderResultPublicationBindingV2] = {}
        self._by_schema: dict[str, ProviderResultPublicationBindingV2] = {}
        source = canonical_provider_result_publication_bindings() if bindings is None else bindings
        for binding in source:
            self.register_publication_binding(binding)
        if bindings is None:
            self._assert_canonical_matrix()

    def register_publication_binding(
        self,
        binding: ProviderResultPublicationBindingV2,
    ) -> None:
        self._validate_binding(binding)
        pair = (binding.action_id, binding.result_schema_id)
        if pair in self._by_pair or binding.action_id in self._by_action or binding.result_schema_id in self._by_schema:
            raise DuplicateResultSchemaRegistration(
                f"Duplicate result publication binding for {binding.action_id!r} / {binding.result_schema_id!r}"
            )
        self._by_pair[pair] = binding
        self._by_action[binding.action_id] = binding
        self._by_schema[binding.result_schema_id] = binding

    def require_publication_binding(
        self,
        *,
        action_id: str,
        result_schema_id: str,
    ) -> ProviderResultPublicationBindingV2:
        binding = self._by_pair.get((action_id, result_schema_id))
        if binding is not None:
            self._validate_binding(binding)
            return binding
        if action_id in self._by_action or result_schema_id in self._by_schema:
            raise ResultSchemaBindingMismatch(
                f"Result schema {result_schema_id!r} is not bound to action {action_id!r}"
            )
        raise ResultSchemaNotRegistered(action_id, result_schema_id)

    def validate_result(
        self,
        *,
        action_id: str,
        result_schema_id: str,
        provider_result: ProviderResult,
    ) -> ProviderResultPublicationBindingV2:
        binding = self.require_publication_binding(
            action_id=action_id,
            result_schema_id=result_schema_id,
        )
        runtime_type_id = type(provider_result).__name__
        if runtime_type_id not in binding.allowed_runtime_type_ids:
            raise ResultVariantNotAllowed(f"Runtime result type {runtime_type_id!r} is not allowed for {action_id!r}")
        expected_kind = _RUNTIME_KINDS.get(runtime_type_id)
        if expected_kind is None or provider_result.result_kind is not expected_kind:
            raise ResultVariantNotAllowed("provider_result_kind_runtime_type_mismatch")
        if provider_result.result_kind not in binding.allowed_result_kinds:
            raise ResultVariantNotAllowed(
                f"Result kind {provider_result.result_kind.value!r} is not allowed for {action_id!r}"
            )
        if type(provider_result) is not _RUNTIME_TYPES[runtime_type_id]:
            raise ResultVariantNotAllowed("provider_result_subclass_denied")
        return binding

    def publication_bindings(self) -> tuple[ProviderResultPublicationBindingV2, ...]:
        return tuple(self._by_pair.values())

    def __len__(self) -> int:
        return len(self._by_pair)

    @staticmethod
    def _validate_binding(binding: ProviderResultPublicationBindingV2) -> None:
        if not binding.action_id or not binding.result_schema_id or not binding.projector_id:
            raise InvalidResultSchemaBinding("result_publication_binding_has_empty_id")
        if not binding.allowed_result_kinds or not binding.allowed_runtime_type_ids:
            raise InvalidResultSchemaBinding("result_publication_binding_has_no_variants")
        if len(binding.allowed_result_kinds) != len(binding.allowed_runtime_type_ids):
            raise InvalidResultSchemaBinding("result_publication_binding_variant_arity_mismatch")
        if len(set(binding.allowed_result_kinds)) != len(binding.allowed_result_kinds):
            raise InvalidResultSchemaBinding("result_publication_binding_duplicate_kind")
        if len(set(binding.allowed_runtime_type_ids)) != len(binding.allowed_runtime_type_ids):
            raise InvalidResultSchemaBinding("result_publication_binding_duplicate_runtime_type")
        for kind, runtime_type_id in zip(
            binding.allowed_result_kinds,
            binding.allowed_runtime_type_ids,
        ):
            if _RUNTIME_KINDS.get(runtime_type_id) is not kind:
                raise InvalidResultSchemaBinding("result_publication_binding_type_kind_mismatch")
        canonical_runtime_types = _CANONICAL_RUNTIME_TYPES_BY_PAIR.get((binding.action_id, binding.result_schema_id))
        if canonical_runtime_types is None:
            raise InvalidResultSchemaBinding("result_publication_binding_unknown_pair")
        if binding.allowed_runtime_type_ids != canonical_runtime_types:
            raise InvalidResultSchemaBinding("result_publication_binding_variant_mismatch")
        if binding.projector_id != _PROJECTOR_ID:
            raise InvalidResultSchemaBinding("result_publication_binding_projector_mismatch")
        expected_digest = canonical_provider_result_publication_binding_digest(binding)
        if binding.binding_digest != expected_digest:
            raise InvalidResultSchemaBinding("result_publication_binding_digest_mismatch")

    def _assert_canonical_matrix(self) -> None:
        schema_rows = {(binding.action_id, binding.result_schema_id) for binding in get_all_v2_schema_bindings()}
        registry_rows = set(self._by_pair)
        if len(schema_rows) != 20 or registry_rows != schema_rows:
            raise InvalidResultSchemaBinding("result_publication_matrix_mismatch")


_GLOBAL_RESULT_SCHEMA_REGISTRY = ProviderResultSchemaRegistry()


def get_provider_result_schema_registry() -> ProviderResultSchemaRegistry:
    return _GLOBAL_RESULT_SCHEMA_REGISTRY


__all__ = [
    "DuplicateResultSchemaRegistration",
    "InvalidResultSchemaBinding",
    "ProviderResultPublicationBindingV2",
    "ProviderResultSchemaRegistry",
    "ProviderResultSchemaRegistryError",
    "ResultSchemaBindingMismatch",
    "ResultSchemaNotRegistered",
    "ResultVariantNotAllowed",
    "canonical_provider_result_publication_binding_digest",
    "canonical_provider_result_publication_bindings",
    "get_provider_result_schema_registry",
]
