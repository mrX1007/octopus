"""Tests for TypedActionAdapterRegistrationV2 and ActionCatalogEntry tagging."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

from core.actions.adapter_registration import ActionAdapterV1, TypedActionAdapterRegistrationV2
from core.actions.catalog import ActionCatalog, LegacyActionCatalogEntry, TypedActionCatalogEntry


def test_catalog_resolves_entries_with_tagged_union() -> None:
    catalog = ActionCatalog(include_manual_gated=True)

    # V2 entry lookup
    entry_v2 = catalog.resolve_entry("plugin:payload_keying")
    assert isinstance(entry_v2, TypedActionCatalogEntry)
    assert entry_v2.adapter_api_version == 2
    assert entry_v2.descriptor.action_id == "plugin:payload_keying"
    assert entry_v2.mount.spec.action_id == "plugin:payload_keying"
    assert entry_v2.descriptor.schema_version == "2.0"
    assert isinstance(entry_v2.adapter, TypedActionAdapterRegistrationV2)
    assert not isinstance(entry_v2.adapter, ActionAdapterV1)

    # Verify ActionDescriptorV2 has no provider or provider_mounted
    assert not hasattr(entry_v2.descriptor, "provider")
    assert not hasattr(entry_v2.descriptor, "provider_mounted")


def test_pth_alias_resolves_to_pass_the_hash() -> None:
    catalog = ActionCatalog(include_manual_gated=True)
    entry = catalog.resolve_entry("pth")
    assert isinstance(entry, TypedActionCatalogEntry)
    assert entry.descriptor.action_id == "killchain:pass_the_hash"


def test_catalog_has_twenty_independent_v2_registrations() -> None:
    catalog = ActionCatalog()
    entries = catalog.v2_entries()
    assert len(entries) == 20
    assert len({entry.descriptor.action_id for entry in entries}) == 20
    assert all(entry.adapter.descriptor is entry.descriptor for entry in entries)


def test_v2_registration_does_not_convert_a_v1_descriptor() -> None:
    catalog = ActionCatalog(include_manual_gated=True)
    v1_facade = catalog.require("plugin:payload_keying").adapter
    v2_entry = catalog.resolve_entry("plugin:payload_keying")
    assert isinstance(v2_entry, TypedActionCatalogEntry)
    assert v2_entry.adapter is not v1_facade
    assert v2_entry.descriptor is v2_entry.adapter.descriptor
