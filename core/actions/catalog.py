"""Collision-safe registry for action adapters and legacy aliases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Union

from .adapter_registration import ActionAdapterV1, TypedActionAdapterRegistrationV2
from .base import ActionAdapter
from .models import ActionDescriptor, ActionDescriptorV2, ActionRequest, ApplicabilityResult, LegacyActionDescriptorV1
from .provider_mounts import ProviderMountSnapshotV2, get_provider_mount_registry
from .schema_bindings import get_all_v2_schema_bindings
from .semantic_bindings import get_all_v2_semantic_bindings, resolve_action_id_alias


@dataclass(frozen=True)
class LegacyActionCatalogEntry:
    descriptor: LegacyActionDescriptorV1
    adapter: ActionAdapterV1
    adapter_api_version: Literal[1] = 1


@dataclass(frozen=True)
class TypedActionCatalogEntry:
    descriptor: ActionDescriptorV2
    mount: ProviderMountSnapshotV2
    adapter: TypedActionAdapterRegistrationV2
    adapter_api_version: Literal[2] = 2


ActionCatalogEntry = Union[LegacyActionCatalogEntry, TypedActionCatalogEntry]


@dataclass(frozen=True)
class _DormantTypedActionRegistrationV2:
    """PR-1 structural registration used until an identity is mounted."""

    descriptor: ActionDescriptorV2
    adapter_api_version: Literal[2] = 2


@dataclass(frozen=True)
class ResolvedAction:
    adapter: ActionAdapter
    canonical_id: str
    requested_name: str
    alias_used: bool


class ActionCatalog:
    def __init__(self, *, include_manual_gated: bool = False) -> None:
        self._adapters: dict[str, ActionAdapter] = {}
        self._names: dict[str, str] = {}
        self._v2_entries: dict[str, TypedActionCatalogEntry] = {}
        self._v2_names: dict[str, str] = {}
        self._register_v2_structural_entries()
        if include_manual_gated:
            self._register_canonical_adapters()

    def _register_v2_structural_entries(self) -> None:
        schemas = {binding.action_id: binding for binding in get_all_v2_schema_bindings()}
        semantics = {binding.action_id: binding for binding in get_all_v2_semantic_bindings()}
        if len(schemas) != 20 or set(schemas) != set(semantics):
            raise ValueError("V2 schema/semantic binding matrix mismatch")

        mount_registry = get_provider_mount_registry()
        for action_id in sorted(schemas):
            schema = schemas[action_id]
            semantic = semantics[action_id]
            descriptor = ActionDescriptorV2(
                schema_version="2.0",
                action_id=action_id,
                name=semantic.name,
                aliases=semantic.aliases,
                input_schema_id=schema.input_schema_id,
                result_schema_id=schema.result_schema_id,
                kind=semantic.kind,
                execution_node_kind=semantic.execution_node_kind,
                capability_class=semantic.capability_class,
                risk_class=semantic.risk_class,
                required_fact_type_ids=semantic.required_fact_type_ids,
                killchain_stage=semantic.killchain_stage,
                manual_gate=semantic.manual_gate,
                check_policy=semantic.check_policy,
                verify_policy=semantic.verify_policy,
            )
            mount = mount_registry.require_v2(action_id)
            registration = _DormantTypedActionRegistrationV2(descriptor=descriptor)
            entry = TypedActionCatalogEntry(
                descriptor=descriptor,
                mount=mount,
                adapter=registration,
            )
            self._v2_entries[action_id] = entry
            for name in (action_id, semantic.name, *semantic.aliases):
                key = self._key(name)
                owner = self._v2_names.get(key)
                if owner is not None and owner != action_id:
                    raise ValueError(f"V2 action alias collision: {key} -> {owner}, {action_id}")
                self._v2_names[key] = action_id

    def _register_canonical_adapters(self) -> None:
        from .adapters_ad_credential import (
            ADDumpLsassAdapter,
            ADPassTheTicketAdapter,
            ADSamDumpAdapter,
            PassTheHashAdapter,
        )
        from .adapters_ad_lateral import (
            ADDcomExecAdapter,
            ADRemoteExecutionCapabilityAdapter,
            ADSmbexecAdapter,
            ADWinrmExecAdapter,
        )
        from .adapters_c2 import (
            C2ChannelCreateAdapter,
            C2CleanupAdapter,
            C2DeployAdapter,
            C2EnrollAdapter,
            C2TaskAdapter,
            DNSC2ChannelAdapter,
        )
        from .adapters_evasion import PayloadKeyingAdapter
        from .adapters_kerberos import (
            KerberosCrackTicketsAdapter,
            KerberosExtractTicketsAdapter,
        )
        from .adapters_pivot import (
            PivotProxyScanAdapter,
            PivotRemoteForwardAdapter,
            PivotSSHChainAdapter,
        )

        canonical_adapters: tuple[ActionAdapter, ...] = (
            PivotRemoteForwardAdapter(),
            PivotSSHChainAdapter(),
            PivotProxyScanAdapter(),
            KerberosExtractTicketsAdapter(),
            KerberosCrackTicketsAdapter(),
            ADPassTheTicketAdapter(),
            PassTheHashAdapter(),
            ADDumpLsassAdapter(),
            ADSamDumpAdapter(),
            ADSmbexecAdapter(),
            ADWinrmExecAdapter(),
            ADDcomExecAdapter(),
            ADRemoteExecutionCapabilityAdapter(),
            DNSC2ChannelAdapter(),
            C2EnrollAdapter(),
            C2DeployAdapter(),
            C2ChannelCreateAdapter(),
            C2TaskAdapter(),
            C2CleanupAdapter(),
            PayloadKeyingAdapter(),
        )
        for adapter in canonical_adapters:
            self.register(adapter)

    @staticmethod
    def _key(value: str) -> str:
        return str(value or "").strip().casefold()

    def _register(self, adapter: ActionAdapter, *, claim_display_name: bool) -> None:
        descriptor = adapter.descriptor
        action_id = self._key(descriptor.action_id)
        if not action_id:
            raise ValueError("Action descriptor requires a non-empty action_id")
        current = self._adapters.get(action_id)
        if current is not None and current is not adapter:
            raise ValueError(f"Duplicate action_id: {descriptor.action_id}")
        names = {
            action_id,
            *(self._key(alias) for alias in descriptor.aliases),
        }
        if claim_display_name:
            names.add(self._key(descriptor.name))
        for name in names:
            if not name:
                continue
            v2_owner = self._v2_names.get(name)
            if v2_owner is not None and v2_owner != action_id:
                raise ValueError(f"Action alias collision with V2 identity: {name} -> {v2_owner}, {action_id}")
            owner = self._names.get(name)
            if owner is not None and owner != action_id:
                raise ValueError(f"Action alias collision: {name} -> {owner}, {action_id}")
        self._adapters[action_id] = adapter
        for name in names:
            if name:
                self._names[name] = action_id

    def register(self, adapter: ActionAdapter) -> None:
        self._register(adapter, claim_display_name=True)

    @staticmethod
    def _is_disabled_registry_adapter(adapter: ActionAdapter) -> bool:
        """Read the wrapped registry metadata without probing the provider."""

        tool_def = getattr(adapter, "tool_def", None)
        return tool_def is not None and getattr(tool_def, "enabled", True) is False

    def resolve(self, name: str) -> ResolvedAction | None:
        requested = self._key(name)
        action_id = self._names.get(requested)
        if action_id is None:
            return None
        return ResolvedAction(
            adapter=self._adapters[action_id],
            canonical_id=action_id,
            requested_name=str(name),
            alias_used=requested not in {action_id, self._key(self._adapters[action_id].descriptor.name)},
        )

    def require(self, name: str) -> ResolvedAction:
        resolved = self.resolve(name)
        if resolved is None:
            raise KeyError(f"Unknown action: {name}")
        return resolved

    def resolve_entry(self, action_id: str) -> ActionCatalogEntry:
        requested = self._key(action_id)
        v2_id = self._v2_names.get(requested)
        if v2_id is None:
            resolved_alias = resolve_action_id_alias(requested)
            v2_id = resolved_alias if resolved_alias in self._v2_entries else None
        if v2_id is not None:
            return self._v2_entries[v2_id]

        resolved = self.require(action_id)
        return LegacyActionCatalogEntry(
            descriptor=resolved.adapter.descriptor,
            adapter=resolved.adapter,
            adapter_api_version=1,
        )

    def v2_entries(self) -> tuple[TypedActionCatalogEntry, ...]:
        return tuple(self._v2_entries[action_id] for action_id in sorted(self._v2_entries))

    def descriptors(self) -> tuple[ActionDescriptor, ...]:
        return tuple(self._adapters[action_id].descriptor for action_id in sorted(self._adapters))

    def register_exploit(self, exploit: Any) -> ActionAdapter:
        from .adapters import ExploitBaseAdapter

        adapter = ExploitBaseAdapter(exploit)
        self.register(adapter)
        return adapter

    def register_metasploit(self, module: str, **adapter_options: Any) -> ActionAdapter:
        from .adapters import MetasploitActionAdapter

        adapter = MetasploitActionAdapter(module, **adapter_options)
        self.register(adapter)
        return adapter

    def register_plugins(
        self,
        manager: Any,
        plugin_names: tuple[str, ...] | list[str] | None = None,
    ) -> tuple[ActionAdapter, ...]:
        from .adapters import PluginActionAdapter

        names = plugin_names if plugin_names is not None else sorted(manager.plugins)
        result_adapters: list[ActionAdapter] = []
        staged = ActionCatalog()
        staged._adapters = dict(self._adapters)
        staged._names = dict(self._names)
        for name in names:
            action_id = staged._key(f"plugin:{name}")
            display_name = staged._key(name)
            existing_id = staged._names.get(action_id) or staged._names.get(display_name)
            existing = staged._adapters.get(existing_id) if existing_id else None
            if (
                existing is not None
                and not isinstance(existing, PluginActionAdapter)
                and existing.descriptor.manual_gate
                and existing.descriptor.action_id.strip().casefold() == action_id
            ):
                result_adapters.append(existing)
                continue

            adapter = PluginActionAdapter(manager, name)
            display_owner = staged._names.get(display_name)
            preserve_disabled_owner = (
                display_owner is not None
                and display_owner != action_id
                and staged._is_disabled_registry_adapter(staged._adapters[display_owner])
            )
            staged._register(adapter, claim_display_name=not preserve_disabled_owner)
            result_adapters.append(adapter)
        self._adapters = staged._adapters
        self._names = staged._names
        return tuple(result_adapters)

    def candidates(
        self,
        request: ActionRequest,
        *,
        kind: str = "",
        category: str = "",
    ) -> tuple[tuple[ActionDescriptor, ApplicabilityResult], ...]:
        candidates = []
        for descriptor in self.descriptors():
            if kind and descriptor.kind.value != kind:
                continue
            if category and descriptor.category != category:
                continue
            adapter = self._adapters[self._key(descriptor.action_id)]
            candidates.append((descriptor, adapter.applicability(request)))
        return tuple(candidates)

    def __len__(self) -> int:
        return len(self._adapters)


__all__ = [
    "ActionCatalog",
    "ActionCatalogEntry",
    "LegacyActionCatalogEntry",
    "ResolvedAction",
    "TypedActionCatalogEntry",
]
