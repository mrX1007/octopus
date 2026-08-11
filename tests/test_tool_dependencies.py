"""Contracts for exact registered-tool dependency declarations."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.actions import ActionRequest
from core.actions.adapters import RegisteredToolAdapter
from core.execution import ExecutionContext
from core.tools import (
    MANUAL_GATED_CAPABILITY_NAMES,
    QUARANTINED_CAPABILITY_NAMES,
    dispatch_registered_tool,
)
from core.tools import dependencies as dependency_model
from core.tools.dependencies import (
    DependencyContext,
    DependencyMode,
    ResourceType,
    all_of,
    any_of,
    binary,
    dependency_leaves,
    dependency_to_dict,
    evaluate_dependency,
    normalize_dependencies,
    python,
    resource,
    service,
    vendor,
)
from core.tools.registry import ToolDef, dependency_inventory, get_tool

pytestmark = [pytest.mark.unit, pytest.mark.security]


def test_dependency_identifiers_and_legacy_adapter_are_strict() -> None:
    normalized = normalize_dependencies("python:sys")
    assert dependency_to_dict(normalized) == {
        "items": [{"import_name": "sys", "kind": "python", "name": "sys"}],
        "mode": "all",
    }
    empty_any = normalize_dependencies("any:")
    assert empty_any.items[0].mode is DependencyMode.ANY
    assert evaluate_dependency(empty_any).available is False

    with pytest.raises(ValueError, match="executable name"):
        binary("./curl")
    with pytest.raises(ValueError, match="dotted import"):
        python("duckduckgo-search")
    with pytest.raises(ValueError, match="relative POSIX"):
        resource("", "../secret")
    with pytest.raises(ValueError, match="identifier"):
        service("catalog", environment=("TOKEN-NAME",))
    with pytest.raises(TypeError, match="sequence"):
        service("catalog", environment="TOKEN")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="SHA-256"):
        vendor("vendor/tool", sha256="short")
    with pytest.raises(TypeError, match="must be text"):
        normalize_dependencies([None])  # type: ignore[list-item]


def test_all_dependency_families_evaluate_without_running_or_networking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = tmp_path / "assets" / "schema.json"
    asset.parent.mkdir()
    asset.write_text("{}\n", encoding="utf-8")
    module_directory = tmp_path / "modules"
    module_directory.mkdir()
    vendored = tmp_path / "vendor" / "helper.bin"
    vendored.parent.mkdir()
    vendored.write_bytes(b"reviewed fixture")
    digest = hashlib.sha256(vendored.read_bytes()).hexdigest()
    manifest = tmp_path / "quality" / "vendor-manifest.json"
    manifest.parent.mkdir()
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "submodules": [],
                "artifacts": [{"path": "vendor/helper.bin", "sha256": digest}],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        dependency_model.shutil,
        "which",
        lambda name: "/fixture/bin/curl" if name == "curl" else None,
    )
    monkeypatch.setattr(
        dependency_model.importlib.util,
        "find_spec",
        lambda name: object() if name == "requests" else None,
    )
    context = DependencyContext(
        root=tmp_path,
        environment={"CATALOG_TOKEN": "configured"},
        vendor_manifest=manifest,
        secret_resolver=lambda _name: "",
    )
    expression = all_of(
        binary("curl"),
        python("requests"),
        resource("", "assets/schema.json"),
        resource("", "modules", resource_type=ResourceType.DIRECTORY),
        service("catalog", environment=("CATALOG_TOKEN",)),
        vendor("vendor/helper.bin", sha256=digest),
    )

    evaluation = evaluate_dependency(expression, context)

    assert evaluation.available is True
    assert evaluation.missing == ()
    assert [leaf.kind.value for leaf in dependency_leaves(expression)] == [
        "binary",
        "python",
        "resource",
        "resource",
        "service",
        "vendor",
    ]
    secret_calls = []
    secret_context = DependencyContext(
        root=tmp_path,
        environment={},
        secret_resolver=lambda name: secret_calls.append(name) or "configured",
    )
    assert evaluate_dependency(service("shodan", secret_name="SHODAN_API_KEY"), secret_context).available
    assert secret_calls == ["SHODAN_API_KEY"]


def test_dependency_failures_are_exact_and_symlinks_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = tmp_path / "real.txt"
    real.write_text("fixture", encoding="utf-8")
    linked = tmp_path / "linked.txt"
    try:
        linked.symlink_to(real)
    except OSError:
        pytest.skip("filesystem does not permit symlink fixtures")

    monkeypatch.setattr(dependency_model.shutil, "which", lambda _name: None)
    context = DependencyContext(root=tmp_path, environment={}, service_states={"catalog": False})
    expression = all_of(
        binary("curl"),
        resource("", "linked.txt"),
        service("catalog", environment=("CATALOG_TOKEN",)),
        any_of(python("missing_one"), python("missing_two")),
    )

    evaluation = evaluate_dependency(expression, context)

    assert evaluation.available is False
    assert evaluation.missing == (
        "binary:curl",
        "resource:file:linked.txt",
        "service:catalog",
        "any(python:missing_one,python:missing_two)",
    )


def test_registry_inventory_is_stable_and_preserves_typed_expression() -> None:
    definitions = [
        ToolDef(
            name="zeta",
            aliases=["z"],
            category="util",
            dependencies=service("catalog", secret_name="CATALOG_TOKEN"),
        ),
        ToolDef(name="alpha", dependencies=all_of(binary("curl"), python("requests"))),
    ]

    first = dependency_inventory(definitions)
    second = dependency_inventory(reversed(definitions))

    assert first == second
    assert [item["name"] for item in first["tools"]] == ["alpha", "zeta"]
    assert first["tools"][1]["dependencies"]["kind"] == "service"


def test_registered_action_uses_one_canonical_dependency_evaluation() -> None:
    calls = []

    def availability():
        calls.append("evaluated")
        return SimpleNamespace(available=False, missing=("service:catalog",))

    tool_def = SimpleNamespace(
        name="fixture",
        aliases=(),
        category="recon",
        description="fixture",
        requires=("service:catalog",),
        needs_target=False,
        enabled=True,
        availability=availability,
        dependency_manifest=lambda: {"kind": "service", "name": "catalog"},
    )
    adapter = RegisteredToolAdapter(tool_def, lambda _command, _context: "unused")

    result = adapter.applicability(ActionRequest("", ExecutionContext.automatic()))

    assert calls == ["evaluated"]
    assert result.missing_requirements == ("dependency:service:catalog",)
    assert adapter.descriptor.requirements.dependency_expression == {
        "kind": "service",
        "name": "catalog",
    }


def test_public_registered_runtime_fails_closed_before_unavailable_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    web = get_tool("web_search")
    assert web is not None
    called = []
    monkeypatch.setattr(web, "dependencies", python("octopus_dependency_fixture_missing"))
    monkeypatch.setattr(web, "requires", ["python:octopus_dependency_fixture_missing"])
    monkeypatch.setattr(web, "func", lambda _query: called.append(True) or "unexpected")
    monkeypatch.setattr(dependency_model.importlib.util, "find_spec", lambda _name: None)

    result = dispatch_registered_tool("web_search passive query", ExecutionContext.automatic())

    assert "provider_unavailable:python:octopus_dependency_fixture_missing" in result
    assert called == []


def test_passive_search_providers_use_canonical_registry_and_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, str]] = []
    fake_search = SimpleNamespace(
        web_search=lambda query, max_results=5: observed.append(("web", f"{query}:{max_results}")) or "web-result",
        search_cve=lambda cve_id: observed.append(("cve", cve_id)) or "cve-result",
    )
    monkeypatch.setitem(sys.modules, "search", fake_search)

    web = get_tool("search_web")
    cve = get_tool("search_cve")
    assert web is not None and web.name == "web_search" and web.needs_target is False
    assert cve is not None and cve.name == "cve_lookup" and cve.needs_target is False
    assert {leaf.kind.value for leaf in dependency_leaves(web.dependency_expression)} == {"python"}
    monkeypatch.setattr(web, "dependencies", None)
    monkeypatch.setattr(web, "requires", [])
    monkeypatch.setattr(cve, "dependencies", None)
    monkeypatch.setattr(cve, "requires", [])

    context = ExecutionContext.automatic()
    assert dispatch_registered_tool("search_web passive source", context) == "web-result"
    assert dispatch_registered_tool("search_cve CVE-2024-12345", context) == "cve-result"
    assert cve.func("not-a-cve").startswith("[!] CVE lookup requires")
    assert observed == [("web", "passive source:5"), ("cve", "CVE-2024-12345")]


def test_fallback_and_database_tools_declare_their_real_python_graphs() -> None:
    browser = get_tool("browser_surface_analysis")
    scrapling = get_tool("scrapling")
    crawl = get_tool("scrapling_crawl")
    database = get_tool("db_inventory")

    assert all(item is not None for item in (browser, scrapling, crawl, database))
    expected_browser = {
        "python:requests",
        "python:beautifulsoup4",
    }
    for definition in (browser, scrapling, crawl):
        assert definition is not None
        assert {leaf.label for leaf in dependency_leaves(definition.dependency_expression)} == expected_browser
        assert definition.dependency_expression.mode is DependencyMode.ALL

    assert database is not None
    assert database.dependency_expression.mode is DependencyMode.ANY
    assert {leaf.label for leaf in dependency_leaves(database.dependency_expression)} == {
        "python:psycopg2-binary",
        "python:psycopg",
        "python:PyMySQL",
        "python:mysql-connector-python",
    }


def test_source_only_high_risk_capabilities_are_registered_and_fail_closed() -> None:
    inventory = dependency_inventory()
    records = {item["name"]: item for item in inventory["tools"]}

    assert QUARANTINED_CAPABILITY_NAMES == ()
    assert len(MANUAL_GATED_CAPABILITY_NAMES) == 20
    for name in MANUAL_GATED_CAPABILITY_NAMES:
        definition = get_tool(name)
        assert definition is not None
        assert definition.enabled is False
        assert definition.provider_path
        assert definition.disabled_reason == "provider_not_configured"
        assert records[name]["provider_path"] == definition.provider_path
        assert records[name]["disabled_reason"] == definition.disabled_reason
        result = dispatch_registered_tool(
            f"{name} fixture.example",
            ExecutionContext.automatic(("fixture.example",)),
        )
        assert "provider_disabled" in result

    assert get_tool("pth") is get_tool("pass_the_hash")
