"""Adapter registration protocols and versioned aliases."""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from core.actions.base import ActionAdapter
from core.actions.models import ActionDescriptorV2

ActionAdapterV1 = ActionAdapter


@runtime_checkable
class TypedActionAdapterRegistrationV2(Protocol):
    """PR-1 structural header only; execution methods are added in PR-7."""

    @property
    def adapter_api_version(self) -> Literal[2]: ...

    @property
    def descriptor(self) -> ActionDescriptorV2: ...


__all__ = [
    "ActionAdapterV1",
    "TypedActionAdapterRegistrationV2",
]
