"""Hermetic branch coverage for the collision-safe action catalog."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.actions import adapters as adapter_module
from core.actions.catalog import ActionCatalog
from core.actions.models import (
    ActionDescriptor,
    ActionKind,
    ApplicabilityResult,
)

pytestmark = pytest.mark.unit


class FakeAdapter:
    def __init__(
        self,
        action_id: str,
        name: str,
        *,
        aliases: tuple[str, ...] = (),
        kind: ActionKind = ActionKind.REGISTERED_TOOL,
        category: str = "",
    ) -> None:
        self.descriptor = ActionDescriptor(
            action_id=action_id,
            name=name,
            aliases=aliases,
            kind=kind,
            provider="fixture",
            category=category,
        )
        self.applicability_requests = []

    def applicability(self, request):
        self.applicability_requests.append(request)
        return ApplicabilityResult(applicable=True, reasons=("fixture",))


def test_registration_normalizes_names_resolves_aliases_and_sorts_descriptors() -> None:
    catalog = ActionCatalog()
    zulu = FakeAdapter(
        " Tool:Zulu ",
        " Zulu Name ",
        aliases=(" ZULU-ALIAS ",),
    )
    alpha = FakeAdapter("tool:alpha", "Alpha")

    catalog.register(zulu)
    catalog.register(alpha)
    catalog.register(zulu)

    assert len(catalog) == 2
    assert [item.action_id for item in catalog.descriptors()] == [
        "tool:alpha",
        " Tool:Zulu ",
    ]

    canonical = catalog.require(" TOOL:ZULU ")
    assert canonical.adapter is zulu
    assert canonical.canonical_id == "tool:zulu"
    assert canonical.requested_name == " TOOL:ZULU "
    assert canonical.alias_used is False

    display_name = catalog.resolve("zulu name")
    assert display_name is not None
    assert display_name.alias_used is False

    alias = catalog.resolve("zulu-alias")
    assert alias is not None
    assert alias.alias_used is True
    assert catalog.resolve("missing") is None
    with pytest.raises(KeyError, match="Unknown action: missing"):
        catalog.require("missing")


def test_registration_rejects_empty_duplicate_and_colliding_identifiers() -> None:
    catalog = ActionCatalog()
    with pytest.raises(ValueError, match="non-empty action_id"):
        catalog.register(FakeAdapter("  ", "empty"))

    first = FakeAdapter("tool:first", "First", aliases=("shared",))
    catalog.register(first)
    with pytest.raises(ValueError, match="Duplicate action_id"):
        catalog.register(FakeAdapter(" TOOL:FIRST ", "duplicate"))
    with pytest.raises(ValueError, match="Action alias collision"):
        catalog.register(
            FakeAdapter("tool:second", "Second", aliases=("SHARED",))
        )


def test_empty_display_names_and_aliases_are_ignored() -> None:
    catalog = ActionCatalog()
    adapter = FakeAdapter("tool:only-id", " ", aliases=("", "   "))

    catalog.register(adapter)

    assert len(catalog) == 1
    assert catalog.resolve("") is None
    assert catalog.require("tool:only-id").adapter is adapter


def test_convenience_registration_wraps_providers_and_plugin_order(
    monkeypatch,
) -> None:
    calls = []

    def fake_exploit(exploit):
        calls.append(("exploit", exploit))
        return FakeAdapter("exploit:fixture", "fixture-exploit")

    def fake_metasploit(module, **options):
        calls.append(("metasploit", module, options))
        return FakeAdapter(
            f"metasploit:{module}",
            module,
            kind=ActionKind.METASPLOIT,
        )

    def fake_plugin(manager, name):
        calls.append(("plugin", manager, name))
        return FakeAdapter(
            f"plugin:{name}",
            name,
            kind=ActionKind.PLUGIN,
        )

    monkeypatch.setattr(adapter_module, "ExploitBaseAdapter", fake_exploit)
    monkeypatch.setattr(adapter_module, "MetasploitActionAdapter", fake_metasploit)
    monkeypatch.setattr(adapter_module, "PluginActionAdapter", fake_plugin)

    catalog = ActionCatalog()
    exploit = object()
    exploit_adapter = catalog.register_exploit(exploit)
    metasploit_adapter = catalog.register_metasploit(
        "fixture/module",
        timeout=7,
        runner="fixture-runner",
    )
    manager = SimpleNamespace(plugins={"zulu": object(), "alpha": object()})
    plugin_adapters = catalog.register_plugins(manager)

    assert exploit_adapter is catalog.require("exploit:fixture").adapter
    assert metasploit_adapter is catalog.require(
        "metasploit:fixture/module"
    ).adapter
    assert [item.descriptor.name for item in plugin_adapters] == ["alpha", "zulu"]
    assert calls[:2] == [
        ("exploit", exploit),
        (
            "metasploit",
            "fixture/module",
            {"timeout": 7, "runner": "fixture-runner"},
        ),
    ]

    explicit_catalog = ActionCatalog()
    explicit = explicit_catalog.register_plugins(manager, ["zulu"])
    assert [item.descriptor.name for item in explicit] == ["zulu"]


def test_plugin_batch_registration_is_transactional_on_late_collision(
    monkeypatch,
) -> None:
    def fake_plugin(_manager, name):
        aliases = ("shared",) if name == "zulu" else ()
        return FakeAdapter(
            f"plugin:{name}",
            name,
            aliases=aliases,
            kind=ActionKind.PLUGIN,
        )

    monkeypatch.setattr(adapter_module, "PluginActionAdapter", fake_plugin)
    catalog = ActionCatalog()
    owner = FakeAdapter("tool:owner", "owner", aliases=("shared",))
    catalog.register(owner)
    before_descriptors = catalog.descriptors()

    manager = SimpleNamespace(plugins={"alpha": object(), "zulu": object()})
    with pytest.raises(ValueError, match="Action alias collision"):
        catalog.register_plugins(manager)

    assert catalog.descriptors() == before_descriptors
    assert catalog.resolve("plugin:alpha") is None
    assert catalog.require("shared").adapter is owner


def test_candidates_apply_kind_and_category_filters_without_execution() -> None:
    catalog = ActionCatalog()
    exploit = FakeAdapter(
        "action:exploit",
        "Exploit",
        kind=ActionKind.EXPLOIT,
        category="active",
    )
    recon = FakeAdapter(
        "action:recon",
        "Recon",
        kind=ActionKind.REGISTERED_TOOL,
        category="recon",
    )
    catalog.register(recon)
    catalog.register(exploit)
    request = object()

    assert [item[0].name for item in catalog.candidates(request)] == [
        "Exploit",
        "Recon",
    ]
    assert [
        item[0].name
        for item in catalog.candidates(
            request,
            kind=ActionKind.EXPLOIT.value,
        )
    ] == ["Exploit"]
    assert [
        item[0].name
        for item in catalog.candidates(request, category="recon")
    ] == ["Recon"]
    assert exploit.applicability_requests == [request, request]
    assert recon.applicability_requests == [request, request]
