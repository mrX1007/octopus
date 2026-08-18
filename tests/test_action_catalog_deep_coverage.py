"""Unit tests for ActionCatalog validations and branch coverage."""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from core.actions.base import ActionAdapter
from core.actions.catalog import ActionCatalog
from core.actions.models import ActionKind, LegacyActionDescriptorV1

pytestmark = pytest.mark.unit


class DummyLegacyAdapter(ActionAdapter):
    def __init__(self, action_id: str, name: str, aliases: tuple[str, ...] = ()) -> None:
        self._descriptor = LegacyActionDescriptorV1(
            action_id=action_id,
            name=name,
            aliases=aliases,
            kind=ActionKind.REGISTERED_TOOL,
            provider="test",
        )

    @property
    def descriptor(self):
        return self._descriptor

    def invocation(self, request, phase):
        return None  # type: ignore

    def is_applicable(self, *args, **kwargs):
        return None

    def execute(self, *args, **kwargs):
        return None


def test_action_catalog_validations():
    catalog = ActionCatalog(include_manual_gated=False)

    # Empty action_id
    bad_adapter = DummyLegacyAdapter(action_id="", name="bad")
    with pytest.raises(ValueError, match="Action descriptor requires a non-empty action_id"):
        catalog.register(bad_adapter)

    # Valid registration
    a1 = DummyLegacyAdapter(action_id="custom:legacy1", name="Custom Legacy 1", aliases=("legacy1_alias",))
    catalog.register(a1)

    # Duplicate action_id
    a1_dup = DummyLegacyAdapter(action_id="custom:legacy1", name="Custom Legacy 1 Dup")
    with pytest.raises(ValueError, match="Duplicate action_id"):
        catalog.register(a1_dup)

    # Collision with V2 identity
    v2_collision = DummyLegacyAdapter(action_id="custom:collision", name="plugin:payload_keying")
    with pytest.raises(ValueError, match="Action alias collision with V2 identity"):
        catalog.register(v2_collision)

    # Collision with existing legacy alias
    legacy_collision = DummyLegacyAdapter(action_id="custom:legacy2", name="legacy1_alias")
    with pytest.raises(ValueError, match="Action alias collision"):
        catalog.register(legacy_collision)

    # Require unknown action
    with pytest.raises(KeyError, match="Unknown action"):
        catalog.require("unknown_action_name")

    # Resolve entry for legacy
    entry = catalog.resolve_entry("custom:legacy1")
    assert entry.adapter_api_version == 1

    # Descriptors & v2 entries
    assert len(catalog.v2_entries()) == 20
    assert len(catalog.descriptors()) >= 1
