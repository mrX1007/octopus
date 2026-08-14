"""Canonical, immutable provider wiring for the twenty V2 action identities."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import Enum
from threading import RLock
from typing import Literal, Protocol, runtime_checkable

from core.actions.schema_bindings import get_all_v2_schema_bindings

PROVIDER_MOUNT_SPEC_SCHEMA_VERSION = "2.0"
_MOUNT_DIGEST_SCHEMA = "octopus:provider-mount-snapshot:2.0"


class ProviderTransport(str, Enum):
    IN_PROCESS = "in_process"
    LOCAL_DAEMON_IPC = "local_daemon_ipc"
    CHILD_EXECUTOR = "child_executor"


class ProviderExecutionModeV2(str, Enum):
    COOPERATIVE_IN_PROCESS = "cooperative_in_process"
    DEADLINE_LOCAL_IPC = "deadline_local_ipc"
    CHILD_EXECUTOR = "child_executor"


@dataclass(frozen=True)
class ProviderMountSpec:
    schema_version: str
    action_id: str
    adapter_class: str
    adapter_api_version: Literal[2]
    provider_owner: str
    provider_transport: ProviderTransport
    execution_mode: ProviderExecutionModeV2
    readiness_probe_id: str

    configured: bool
    mounted: bool
    typed_action_supported: bool
    raw_command_supported: bool


@dataclass(frozen=True)
class ProviderMountSnapshotV2:
    spec: ProviderMountSpec
    revision: int
    mount_digest: str


def canonical_provider_mount_snapshot_digest(snapshot: ProviderMountSnapshotV2) -> str:
    """Return the tagged canonical digest of the spec and its revision."""

    payload = {
        "digest_schema": _MOUNT_DIGEST_SCHEMA,
        "revision": snapshot.revision,
        "spec": asdict(snapshot.spec),
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_json).hexdigest()}"


class V2ActionNotFoundInMountRegistry(KeyError):
    """The requested identity is not one of the canonical twenty V2 actions."""


@runtime_checkable
class ProviderMountRegistry(Protocol):
    def require_v2(self, action_id: str) -> ProviderMountSnapshotV2: ...

    def assert_current(self, snapshot: ProviderMountSnapshotV2) -> None: ...

    def snapshots(self) -> tuple[ProviderMountSnapshotV2, ...]: ...


class DefaultProviderMountRegistry:
    """Thread-safe read-only registry for V2 provider wiring.

    The checked-in rollout has not passed the normative provider E2E lanes, so
    every canonical identity is configured but deliberately unmounted. A
    provider PR may flip its row only in the same final commit that makes the
    corresponding acceptance lane green.
    """

    def __init__(self, mount_specs: tuple[ProviderMountSpec, ...] | None = None) -> None:
        canonical = mount_specs is None
        specs = _DEFAULT_V2_MOUNT_SPECS if mount_specs is None else mount_specs
        self._lock = RLock()
        self._snapshots_by_id: dict[str, ProviderMountSnapshotV2] = {}

        seen_probe_ids: set[str] = set()
        seen_adapter_classes: set[str] = set()
        seen_provider_owners: set[str] = set()
        for revision, spec in enumerate(sorted(specs, key=lambda item: item.action_id), start=1):
            self._validate_spec(spec)
            if spec.action_id in self._snapshots_by_id:
                raise ValueError(f"duplicate_v2_action_id:{spec.action_id}")
            if spec.readiness_probe_id in seen_probe_ids:
                raise ValueError(f"duplicate_readiness_probe_id:{spec.readiness_probe_id}")
            if spec.adapter_class in seen_adapter_classes:
                raise ValueError(f"duplicate_v2_adapter_owner:{spec.adapter_class}")
            if spec.provider_owner in seen_provider_owners:
                raise ValueError(f"duplicate_v2_provider_owner:{spec.provider_owner}")
            seen_probe_ids.add(spec.readiness_probe_id)
            seen_adapter_classes.add(spec.adapter_class)
            seen_provider_owners.add(spec.provider_owner)

            unsigned = ProviderMountSnapshotV2(spec=spec, revision=revision, mount_digest="")
            snapshot = ProviderMountSnapshotV2(
                spec=spec,
                revision=revision,
                mount_digest=canonical_provider_mount_snapshot_digest(unsigned),
            )
            self._snapshots_by_id[spec.action_id] = snapshot

        if canonical:
            expected = {binding.action_id for binding in get_all_v2_schema_bindings()}
            actual = set(self._snapshots_by_id)
            if len(actual) != 20 or actual != expected:
                missing = sorted(expected - actual)
                extra = sorted(actual - expected)
                raise ValueError(f"invalid_canonical_v2_mount_matrix:missing={missing}:extra={extra}")

    @staticmethod
    def _validate_spec(spec: ProviderMountSpec) -> None:
        if spec.schema_version != PROVIDER_MOUNT_SPEC_SCHEMA_VERSION:
            raise ValueError(f"invalid_provider_mount_schema:{spec.action_id}")
        if spec.adapter_api_version != 2:
            raise ValueError(f"invalid_provider_adapter_api:{spec.action_id}")
        if not spec.action_id or not spec.adapter_class or not spec.provider_owner:
            raise ValueError("provider_mount_identity_fields_must_be_nonempty")
        if not spec.readiness_probe_id.startswith("probe:"):
            raise ValueError(f"invalid_readiness_probe_id:{spec.action_id}")
        if spec.mounted and not spec.configured:
            raise ValueError(f"mounted_provider_must_be_configured:{spec.action_id}")
        if not spec.typed_action_supported:
            raise ValueError(f"v2_provider_must_support_typed_action:{spec.action_id}")
        if spec.raw_command_supported:
            raise ValueError(f"v2_provider_raw_command_forbidden:{spec.action_id}")

    def require_v2(self, action_id: str) -> ProviderMountSnapshotV2:
        with self._lock:
            try:
                return self._snapshots_by_id[action_id]
            except KeyError as exc:
                raise V2ActionNotFoundInMountRegistry(f"not_v2_action:{action_id}") from exc

    def assert_current(self, snapshot: ProviderMountSnapshotV2) -> None:
        expected_digest = canonical_provider_mount_snapshot_digest(snapshot)
        if not hmac.compare_digest(snapshot.mount_digest, expected_digest):
            raise ValueError(f"invalid_provider_mount_digest:{snapshot.spec.action_id}")
        current = self.require_v2(snapshot.spec.action_id)
        if snapshot != current:
            raise ValueError(f"stale_provider_mount_snapshot:{snapshot.spec.action_id}")

    def snapshots(self) -> tuple[ProviderMountSnapshotV2, ...]:
        with self._lock:
            return tuple(self._snapshots_by_id[action_id] for action_id in sorted(self._snapshots_by_id))


def _spec(
    action_id: str,
    adapter_class: str,
    provider_owner: str,
    provider_transport: ProviderTransport,
    execution_mode: ProviderExecutionModeV2,
    readiness_probe_id: str,
) -> ProviderMountSpec:
    return ProviderMountSpec(
        schema_version=PROVIDER_MOUNT_SPEC_SCHEMA_VERSION,
        action_id=action_id,
        adapter_class=adapter_class,
        adapter_api_version=2,
        provider_owner=provider_owner,
        provider_transport=provider_transport,
        execution_mode=execution_mode,
        readiness_probe_id=readiness_probe_id,
        configured=True,
        mounted=True,
        typed_action_supported=True,
        raw_command_supported=False,
    )


_IN_PROCESS = ProviderTransport.IN_PROCESS
_COOPERATIVE = ProviderExecutionModeV2.COOPERATIVE_IN_PROCESS
_DAEMON = ProviderTransport.LOCAL_DAEMON_IPC
_DEADLINE_IPC = ProviderExecutionModeV2.DEADLINE_LOCAL_IPC
_CHILD = ProviderTransport.CHILD_EXECUTOR
_CHILD_MODE = ProviderExecutionModeV2.CHILD_EXECUTOR

_DEFAULT_V2_MOUNT_SPECS: tuple[ProviderMountSpec, ...] = (
    _spec(
        "plugin:payload_keying",
        "core.actions.adapters_evasion.PayloadKeyingAdapter",
        "payload_keying",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:payload_keying",
    ),
    _spec(
        "killchain:kerberos_extract_tickets",
        "core.actions.adapters_kerberos.KerberosExtractTicketsAdapter",
        "kerberos_extract_tickets",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:kerberos_extract_tickets",
    ),
    _spec(
        "killchain:kerberos_crack_tickets",
        "core.actions.adapters_kerberos.KerberosCrackTicketsAdapter",
        "kerberos_crack_tickets",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:kerberos_crack_tickets",
    ),
    _spec(
        "killchain:ad_pass_the_ticket",
        "core.actions.adapters_ad_credential.ADPassTheTicketAdapter",
        "ad_pass_the_ticket",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:ad_pass_the_ticket",
    ),
    _spec(
        "killchain:pass_the_hash",
        "core.actions.adapters_ad_credential.PassTheHashAdapter",
        "pass_the_hash",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:pass_the_hash",
    ),
    _spec(
        "killchain:ad_dump_lsass",
        "core.actions.adapters_ad_credential.ADDumpLsassAdapter",
        "ad_dump_lsass",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:ad_dump_lsass",
    ),
    _spec(
        "killchain:ad_sam_dump",
        "core.actions.adapters_ad_credential.ADSamDumpAdapter",
        "ad_sam_dump",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:ad_sam_dump",
    ),
    _spec(
        "killchain:ad_smbexec",
        "core.actions.adapters_ad_lateral.ADSmbexecAdapter",
        "ad_smbexec",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:ad_smbexec",
    ),
    _spec(
        "killchain:ad_winrm_exec",
        "core.actions.adapters_ad_lateral.ADWinrmExecAdapter",
        "ad_winrm_exec",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:ad_winrm_exec",
    ),
    _spec(
        "killchain:ad_dcom_exec",
        "core.actions.adapters_ad_lateral.ADDcomExecAdapter",
        "ad_dcom_exec",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:ad_dcom_exec",
    ),
    _spec(
        "killchain:ad_remote_execution",
        "core.actions.adapters_ad_lateral.ADRemoteExecutionCapabilityAdapter",
        "ad_remote_execution",
        _CHILD,
        _CHILD_MODE,
        "probe:ad_remote_execution",
    ),
    _spec(
        "killchain:pivot_remote_forward",
        "core.actions.adapters_pivot.PivotRemoteForwardAdapter",
        "pivot_remote_forward",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:pivot_remote_forward",
    ),
    _spec(
        "killchain:pivot_ssh_chain",
        "core.actions.adapters_pivot.PivotSSHChainAdapter",
        "pivot_ssh_chain",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:pivot_ssh_chain",
    ),
    _spec(
        "killchain:pivot_proxy_scan",
        "core.actions.adapters_pivot.PivotProxyScanAdapter",
        "pivot_proxy_scan",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:pivot_proxy_scan",
    ),
    _spec(
        "c2:dns_c2_channel",
        "core.actions.adapters_c2.DNSC2ChannelAdapter",
        "dns_c2_channel",
        _DAEMON,
        _DEADLINE_IPC,
        "probe:dns_c2_channel",
    ),
    _spec(
        "c2:c2_enroll",
        "core.actions.adapters_c2.C2EnrollAdapter",
        "c2_enroll",
        _DAEMON,
        _DEADLINE_IPC,
        "probe:c2_enroll",
    ),
    _spec(
        "c2:c2_deploy",
        "core.actions.adapters_c2.C2DeployAdapter",
        "c2_deploy",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:c2_deploy",
    ),
    _spec(
        "c2:c2_channel_create",
        "core.actions.adapters_c2.C2ChannelCreateAdapter",
        "c2_channel_create",
        _CHILD,
        _CHILD_MODE,
        "probe:c2_channel_create",
    ),
    _spec(
        "c2:c2_task",
        "core.actions.adapters_c2.C2TaskAdapter",
        "c2_task",
        _DAEMON,
        _DEADLINE_IPC,
        "probe:c2_task",
    ),
    _spec(
        "c2:c2_cleanup",
        "core.actions.adapters_c2.C2CleanupAdapter",
        "c2_cleanup",
        _IN_PROCESS,
        _COOPERATIVE,
        "probe:c2_cleanup",
    ),
)

_GLOBAL_PROVIDER_MOUNT_REGISTRY = DefaultProviderMountRegistry()


def get_provider_mount_registry() -> DefaultProviderMountRegistry:
    return _GLOBAL_PROVIDER_MOUNT_REGISTRY


__all__ = [
    "PROVIDER_MOUNT_SPEC_SCHEMA_VERSION",
    "DefaultProviderMountRegistry",
    "ProviderExecutionModeV2",
    "ProviderMountRegistry",
    "ProviderMountSnapshotV2",
    "ProviderMountSpec",
    "ProviderTransport",
    "V2ActionNotFoundInMountRegistry",
    "canonical_provider_mount_snapshot_digest",
    "get_provider_mount_registry",
]
