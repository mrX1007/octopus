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
    def __init__(self) -> None:
        self._adapters: dict[str, ActionAdapter] = {}
        self._names: dict[str, str] = {}

    @staticmethod
    def _key(value: str) -> str:
        return str(value or "").strip().casefold()

    def register(self, adapter: ActionAdapter) -> None:
        descriptor = adapter.descriptor
        action_id = self._key(descriptor.action_id)
        if not action_id:
            raise ValueError("Action descriptor requires a non-empty action_id")
        current = self._adapters.get(action_id)
        if current is not None and current is not adapter:
            raise ValueError(f"Duplicate action_id: {descriptor.action_id}")
        names = {
            action_id,
            self._key(descriptor.name),
            *(self._key(alias) for alias in descriptor.aliases),
        }
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

    def resolve(self, name: str) -> ResolvedAction | None:
        requested = self._key(name)
        action_id = self._names.get(requested)
        if action_id is None:
            return None
        return ResolvedAction(
            adapter=self._adapters[action_id],
            canonical_id=action_id,
            requested_name=str(name),
            alias_used=requested != action_id,
        )

    def require(self, name: str) -> ResolvedAction:
        resolved = self.resolve(name)
        if resolved is None:
            raise KeyError(f"Unknown action: {name}")
        return resolved

    def descriptors(self) -> tuple[ActionDescriptor, ...]:
        return tuple(
            self._adapters[action_id].descriptor
            for action_id in sorted(self._adapters)
        )

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
        adapters = tuple(PluginActionAdapter(manager, name) for name in names)
        for adapter in adapters:
            self.register(adapter)
        return adapters

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
