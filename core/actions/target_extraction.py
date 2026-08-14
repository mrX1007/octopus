"""Executor-owned exact target extraction for decoded V2 inputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, Protocol, TypeVar

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
)
from core.actions.operation_catalog import RemoteExecService
from core.actions.reference_snapshots import ReferenceMetadataSnapshot
from core.actions.target_scope import (
    ExtractedActionTarget,
    NetworkProtocol,
    TargetRole,
    TargetScopeCanonicalizer,
)

TDecodedV2Input = TypeVar("TDecodedV2Input", contravariant=True)


class ActionTargetExtractor(Protocol, Generic[TDecodedV2Input]):
    def extract(
        self,
        typed_input: TDecodedV2Input,
        reference_snapshots: tuple[ReferenceMetadataSnapshot, ...],
    ) -> tuple[ExtractedActionTarget, ...]: ...


@dataclass(frozen=True)
class _CallableTargetExtractor(Generic[TDecodedV2Input]):
    callback: Callable[[TDecodedV2Input], tuple[ExtractedActionTarget, ...]]

    def extract(
        self,
        typed_input: TDecodedV2Input,
        reference_snapshots: tuple[ReferenceMetadataSnapshot, ...],
    ) -> tuple[ExtractedActionTarget, ...]:
        del reference_snapshots
        return self.callback(typed_input)


@dataclass(frozen=True)
class _TargetExtractorSlot:
    input_type: type[object]
    extractor: ActionTargetExtractor[object]


class ActionTargetExtractorRegistry:
    def __init__(self) -> None:
        self._extractors: dict[tuple[str, str], _TargetExtractorSlot] = {}

    def register(
        self,
        *,
        action_id: str,
        input_schema_id: str,
        input_type: type[TDecodedV2Input],
        extractor: ActionTargetExtractor[TDecodedV2Input],
    ) -> None:
        key = (action_id, input_schema_id)
        if key in self._extractors:
            raise ValueError(f"duplicate target extractor registration: {key!r}")
        self._extractors[key] = _TargetExtractorSlot(
            input_type=input_type,
            extractor=extractor,  # type: ignore[arg-type]
        )

    def extract_checked(
        self,
        *,
        action_id: str,
        input_schema_id: str,
        decoded_input: object,
        reference_snapshots: tuple[ReferenceMetadataSnapshot, ...],
    ) -> tuple[ExtractedActionTarget, ...]:
        try:
            slot = self._extractors[(action_id, input_schema_id)]
        except KeyError as exc:
            raise ValueError(f"no target extractor registered for {(action_id, input_schema_id)!r}") from exc
        if type(decoded_input) is not slot.input_type:
            raise TypeError(
                f"target extractor runtime type mismatch: expected {slot.input_type.__name__}, "
                f"got {type(decoded_input).__name__}"
            )
        targets = slot.extractor.extract(decoded_input, reference_snapshots)
        if not targets:
            raise ValueError("target extractor returned no authorization target")
        if any(type(target) is not ExtractedActionTarget for target in targets):
            raise TypeError("target extractor returned a non-canonical target")
        return targets

    def bindings(self) -> tuple[tuple[str, str, type[object]], ...]:
        return tuple((action_id, schema_id, slot.input_type) for (action_id, schema_id), slot in self._extractors.items())


def _canonical(
    value: str,
    role: TargetRole,
    *,
    port: int | None = None,
    protocol: NetworkProtocol | None = None,
    resource_bound: bool = False,
) -> ExtractedActionTarget:
    return TargetScopeCanonicalizer.canonicalize(
        value,
        role=role,
        port=port,
        protocol=protocol,
        resource_bound=resource_bound,
    )


def _resource(reference: str) -> ExtractedActionTarget:
    return _canonical(reference, TargetRole.RESOURCE_BOUND, resource_bound=True)


def _remote_protocol(service: RemoteExecService | None) -> NetworkProtocol | None:
    return {
        RemoteExecService.SMB: NetworkProtocol.SMB,
        RemoteExecService.WINRM: NetworkProtocol.WINRM,
        RemoteExecService.DCOM: NetworkProtocol.DCOM,
        None: None,
    }[service]


def _build_default_registry() -> ActionTargetExtractorRegistry:
    registry = ActionTargetExtractorRegistry()

    def add(action_id: str, schema_id: str, input_type: type[TDecodedV2Input], callback: Callable[[TDecodedV2Input], tuple[ExtractedActionTarget, ...]]) -> None:
        registry.register(
            action_id=action_id,
            input_schema_id=schema_id,
            input_type=input_type,
            extractor=_CallableTargetExtractor(callback),
        )

    add(
        "plugin:payload_keying",
        "octopus:input:payload_keying:2.0",
        PayloadKeyingInputV2,
        lambda value: (_resource(value.payload_ref),)
        + ((_resource(value.target_metadata_ref),) if value.target_metadata_ref is not None else ()),
    )
    add(
        "killchain:kerberos_extract_tickets",
        "octopus:input:kerberos_extract_tickets:2.0",
        KerberosExtractInputV2,
        lambda value: (_canonical(value.target, TargetRole.PRIMARY), _resource(value.credential_ref)),
    )
    add(
        "killchain:kerberos_crack_tickets",
        "octopus:input:kerberos_crack_tickets:2.0",
        KerberosCrackInputV2,
        lambda value: (_resource(value.ticket_ref), _resource(value.wordlist_ref)),
    )
    add(
        "killchain:ad_pass_the_ticket",
        "octopus:input:ad_pass_the_ticket:2.0",
        PassTheTicketInputV2,
        lambda value: (_canonical(value.target, TargetRole.PRIMARY), _resource(value.ticket_ref)),
    )
    add(
        "killchain:pass_the_hash",
        "octopus:input:pass_the_hash:2.0",
        PassTheHashInputV2,
        lambda value: (_canonical(value.target, TargetRole.PRIMARY), _resource(value.credential_ref)),
    )
    for action_id, schema_id in (
        ("killchain:ad_dump_lsass", "octopus:input:ad_dump_lsass:2.0"),
        ("killchain:ad_sam_dump", "octopus:input:ad_sam_dump:2.0"),
    ):
        add(
            action_id,
            schema_id,
            CredentialDumpInputV2,
            lambda value: (_canonical(value.target, TargetRole.PRIMARY), _resource(value.credential_ref)),
        )
    for action_id, schema_id in (
        ("killchain:ad_smbexec", "octopus:input:ad_smbexec:2.0"),
        ("killchain:ad_winrm_exec", "octopus:input:ad_winrm_exec:2.0"),
        ("killchain:ad_dcom_exec", "octopus:input:ad_dcom_exec:2.0"),
        ("killchain:ad_remote_execution", "octopus:input:ad_remote_execution:2.0"),
    ):
        add(
            action_id,
            schema_id,
            RemoteExecInputV2,
            lambda value: (
                _canonical(value.target, TargetRole.PRIMARY, protocol=_remote_protocol(value.service)),
                _resource(value.credential_ref),
            ),
        )
    add(
        "killchain:pivot_remote_forward",
        "octopus:input:pivot_remote_forward:2.0",
        RemoteForwardInputV2,
        lambda value: (
            _canonical(value.target, TargetRole.PRIMARY, port=value.remote_port, protocol=NetworkProtocol.SSH),
            _canonical(
                value.destination_host,
                TargetRole.DESTINATION,
                port=value.destination_port,
                protocol=NetworkProtocol.TCP,
            ),
            _resource(value.session_ref),
        ),
    )
    add(
        "killchain:pivot_ssh_chain",
        "octopus:input:pivot_ssh_chain:2.0",
        SSHChainInputV2,
        lambda value: tuple(
            target
            for hop in value.hops
            for target in (
                _canonical(hop.target, TargetRole.HOP, port=hop.port, protocol=NetworkProtocol.SSH),
                _resource(hop.credential_ref),
            )
        ),
    )
    add(
        "killchain:pivot_proxy_scan",
        "octopus:input:pivot_proxy_scan:2.0",
        PivotProxyScanInputV2,
        lambda value: tuple(
            _canonical(value.target, TargetRole.PRIMARY, port=port, protocol=NetworkProtocol.TCP)
            for port in value.ports
        )
        + (_resource(value.route_ref),),
    )

    def dns_targets(value: DNSC2ChannelInputV2) -> tuple[ExtractedActionTarget, ...]:
        return (
            _canonical(value.target, TargetRole.PRIMARY),
            _canonical(
                value.config.listen_address,
                TargetRole.LISTEN,
                port=value.config.listen_port,
                protocol=NetworkProtocol.DNS,
            ),
        )

    add("c2:dns_c2_channel", "octopus:input:dns_c2_channel:2.0", DNSC2ChannelInputV2, dns_targets)
    add(
        "c2:c2_enroll",
        "octopus:input:c2_enroll:2.0",
        C2EnrollmentIssueInput,
        lambda value: (_canonical(value.target, TargetRole.PRIMARY), _resource(value.channel_ref)),
    )
    add(
        "c2:c2_deploy",
        "octopus:input:c2_deploy:3.0",
        C2DeployInputV3,
        lambda value: (
            _canonical(value.target, TargetRole.PRIMARY),
            _resource(value.channel_ref),
            _resource(value.enrollment_ref),
            _resource(value.access_session_ref),
        ),
    )
    add(
        "c2:c2_channel_create",
        "octopus:input:c2_channel_create:2.0",
        C2ChannelCreateInputV2,
        lambda value: dns_targets(DNSC2ChannelInputV2(value.target, value.config)),
    )
    add(
        "c2:c2_task",
        "octopus:input:c2_task:2.0",
        C2TaskInputV2,
        lambda value: ((_canonical(value.target, TargetRole.PRIMARY),) if value.target is not None else ())
        + (_resource(value.agent_ref),),
    )
    add(
        "c2:c2_cleanup",
        "octopus:input:c2_cleanup:2.0",
        C2CleanupInputV2,
        lambda value: (_resource(value.resource_ref),),
    )
    return registry


_DEFAULT_TARGET_EXTRACTOR_REGISTRY = _build_default_registry()


def get_action_target_extractor_registry() -> ActionTargetExtractorRegistry:
    return _DEFAULT_TARGET_EXTRACTOR_REGISTRY


__all__ = [
    "ActionTargetExtractor",
    "ActionTargetExtractorRegistry",
    "TDecodedV2Input",
    "get_action_target_extractor_registry",
]
