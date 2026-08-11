"""Collision-safe registry for action adapters and legacy aliases."""

from __future__ import annotations

from dataclasses import dataclass

from .base import ActionAdapter
from .models import ActionDescriptor, ActionRequest, ApplicabilityResult


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
        if include_manual_gated:
            self._register_canonical_adapters()

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

    def descriptors(self) -> tuple[ActionDescriptor, ...]:
        return tuple(self._adapters[action_id].descriptor for action_id in sorted(self._adapters))

    def register_exploit(self, exploit) -> ActionAdapter:
        from .adapters import ExploitBaseAdapter

        adapter = ExploitBaseAdapter(exploit)
        self.register(adapter)
        return adapter

    def register_metasploit(self, module: str, **adapter_options) -> ActionAdapter:
        from .adapters import MetasploitActionAdapter

        adapter = MetasploitActionAdapter(module, **adapter_options)
        self.register(adapter)
        return adapter

    def register_plugins(
        self,
        manager,
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


__all__ = ["ActionCatalog", "ResolvedAction"]
