"""Remaining recursion and optional-boundary coverage for the AI tool registry."""

from __future__ import annotations

import builtins
import shlex
from types import SimpleNamespace

import pytest

import core.ai.tool_registry as ai_registry_module
import core.plugins.loader as plugin_loader_module
import core.tools.registry as tool_registry_module
from core.ai.tool_registry import PLANNER_TASKS, ToolRegistry

pytestmark = pytest.mark.contract


def test_profiles_availability_cache_registry_nested_and_path(monkeypatch):
    registry = ToolRegistry()
    assert registry.task_profile("service-discovery")["risk"] == "safe"
    assert registry.task_profile("missing") == {
        "cost": 5,
        "time": "medium",
        "risk": "unknown",
        "preconditions": [],
    }

    registered = SimpleNamespace(is_available=lambda: True)
    monkeypatch.setattr(
        tool_registry_module,
        "get_tool",
        lambda name: registered if name == "registered" else None,
    )
    assert registry._is_tool_available("registered") is True
    assert registry._is_tool_available("registered") is True

    registry.task_map = {
        "nested": [("leaf {target}", "leaf")],
        "self-only": [("self-only {target}", "self-only")],
    }
    monkeypatch.setattr(
        ai_registry_module.shutil,
        "which",
        lambda name: "/fixture/bin/leaf" if name == "leaf" else None,
    )
    assert registry._is_tool_available("nested") is True
    assert registry._is_tool_available("self-only") is False
    assert registry._is_tool_available("missing") is False


def test_tool_availability_tolerates_registry_import_failure(monkeypatch):
    registry = ToolRegistry()
    real_import = builtins.__import__

    def fail_registry_import(name, *args, **kwargs):
        if name == "core.tools.registry":
            raise ImportError("registry unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_registry_import)
    monkeypatch.setattr(ai_registry_module.shutil, "which", lambda _name: None)

    assert registry._is_tool_available("missing") is False


def test_recursive_task_expansion_and_command_resolution_stop_on_cycles(capsys):
    registry = ToolRegistry()
    registry.task_map = {
        "outer": [("inner {target}", "inner")],
        "inner": [("missing {target}", "missing")],
        "cycle": [("cycle {target}", "cycle")],
    }
    registry._is_tool_available = lambda _name: False

    assert registry._tool_names_for_task("cycle", {"cycle"}) == []
    assert registry.get_commands_for_task("cycle", "host", _seen={"cycle"}) == []
    assert registry.get_commands_for_task("outer", "host") == []

    output = capsys.readouterr().out
    assert "Skipped unavailable tools: missing" in output
    assert "Skipped unavailable tools: inner" in output
    assert "No tools available for task 'inner'" in output
    assert "No tools available for task 'outer'" in output


def test_command_resolution_rejects_plaintext_credentials(capsys):
    registry = ToolRegistry()
    registry.task_map = {"probe": [("probe {target}", "probe")]}
    registry._is_tool_available = lambda _name: True
    canary = "command-expansion-secret-canary"

    commands = registry.get_commands_for_task(
        "probe",
        "127.0.0.1",
        user="alice",
        password=canary,
    )

    output = capsys.readouterr().out
    assert commands == []
    assert "Credential-bearing command expansion is disabled" in output
    assert canary not in output


def test_provider_expansion_stops_cycles_and_deduplicates_records():
    registry = ToolRegistry()
    registry.task_map = {
        "cycle": [("cycle {target}", "cycle")],
        "outer": [
            ("leaf {target}", "leaf"),
            ("leaf {target}", "leaf"),
        ],
        "nested_outer": [("nested_inner {target}", "nested_inner")],
        "nested_inner": [("probe {target}", "probe")],
    }
    registry._is_tool_available = lambda _name: True

    assert registry._provider_statuses_for_task("cycle", {"cycle"}, "cycle") == []
    assert registry.get_provider_statuses_for_task("outer") == [
        {
            "task": "outer",
            "provider": "leaf",
            "command_template": "leaf {target}",
            "available": True,
        }
    ]
    assert registry.get_provider_statuses_for_task("nested_outer") == [
        {
            "task": "nested_outer",
            "provider": "probe",
            "command_template": "probe {target}",
            "available": True,
        }
    ]
    assert registry.task_has_available_tools("missing") is False


def test_available_and_unavailable_summaries_cover_each_provider_state():
    registry = ToolRegistry()
    registry.task_map = {
        "task": [("ok {target}", "ok"), ("bad {target}", "bad")],
        "empty": [],
    }
    registry._is_tool_available = lambda name: name == "ok"

    assert registry.get_available_tools_summary() == {
        "task": ["ok"],
        "empty": [],
    }
    assert registry.get_unavailable_tools_summary() == {
        "task": ["bad"],
        "empty": [],
    }
    assert registry.has_task("task") is True
    assert registry.has_task("missing") is False


def test_default_coverage_discovery_supports_success_and_failure(monkeypatch):
    registry = ToolRegistry()
    monkeypatch.setattr(
        tool_registry_module,
        "list_tools",
        lambda: [SimpleNamespace(name="unknown-provider")],
    )

    assert registry.get_coverage_report()["unknown"] == ["unknown-provider"]

    def unavailable():
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(tool_registry_module, "list_tools", unavailable)
    assert registry.get_coverage_report()["registered"] == 0


def test_plugin_summary_caches_success_and_degrades_to_empty(monkeypatch):
    class Manager:
        def __init__(self, path):
            assert path == plugin_loader_module.default_modules_dir()

        def list_plugins(self):
            return [{"name": "demo", "description": "fixture"}]

    monkeypatch.setattr(plugin_loader_module, "PluginManager", Manager)
    registry = ToolRegistry()
    first = registry.get_discovered_plugins_summary()
    assert first == [{"name": "demo", "description": "fixture"}]

    monkeypatch.setattr(
        plugin_loader_module,
        "PluginManager",
        lambda _path: (_ for _ in ()).throw(RuntimeError("unavailable")),
    )
    assert registry.get_discovered_plugins_summary() is first

    failed = ToolRegistry()
    assert failed.get_discovered_plugins_summary() == []


def test_plugin_summary_uses_injected_runtime_manager_snapshot() -> None:
    calls = []
    manager = SimpleNamespace(
        list_plugins=lambda: calls.append("list") or [{"name": "runtime-plugin", "type": "recon"}]
    )
    registry = ToolRegistry(plugin_manager_provider=lambda: calls.append("provider") or manager)

    first = registry.get_discovered_plugins_summary()

    assert first == [{"name": "runtime-plugin", "type": "recon"}]
    assert registry.get_discovered_plugins_summary() is first
    assert calls == ["provider", "list"]


def test_typed_task_inputs_do_not_reuse_network_target_for_incompatible_providers(
    tmp_path,
) -> None:
    registry = ToolRegistry()
    registry._is_tool_available = lambda _name: True

    web_commands = registry.get_commands_for_task("web_app_deep_testing", "app.example.test")
    api_commands = registry.get_commands_for_task("api_security_testing", "app.example.test")

    assert {shlex.split(command)[0] for command in web_commands} == {
        "authenticated_crawl",
        "cors_check",
        "js_route_extract",
        "security_headers_check",
    }
    assert {shlex.split(command)[0] for command in api_commands} == {
        "api_auth_check",
        "graphql_check",
        "katana_crawl",
    }
    assert registry.get_commands_for_task("cloud_security_assessment", "app.example.test") == []
    assert registry.get_commands_for_task("code_security_assessment", "app.example.test") == []
    assert registry.get_commands_for_task("secrets_scanning", "app.example.test") == []

    workspace = tmp_path / "authorized workspace"
    workspace.mkdir()
    files = {}
    for name in ("session.json", "jwt.txt", "burp.xml", "zap.json", "openapi.yaml"):
        path = workspace / name
        path.write_text("fixture", encoding="utf-8")
        files[name] = str(path)

    inputs = registry.resolve_task_inputs(
        "app.example.test",
        [
            {"type": "session_profile_path", "value": files["session.json"]},
            {"type": "jwt_artifact", "value": files["jwt.txt"]},
            {"type": "burp_export", "value": files["burp.xml"]},
            {"type": "zap_export", "value": files["zap.json"]},
            {"type": "openapi_spec_path", "value": files["openapi.yaml"]},
            {"type": "cloud_provider", "value": "azure"},
        ],
        {"filesystem_scopes": [str(workspace)]},
    )

    assert inputs["filesystem_scope"] == (str(workspace.resolve()),)
    assert inputs["cloud_provider"] == ("azure",)
    bound_web = registry.get_commands_for_task(
        "web_app_deep_testing",
        "app.example.test",
        task_inputs=inputs,
    )
    bound_api = registry.get_commands_for_task(
        "api_security_testing",
        "app.example.test",
        task_inputs=inputs,
    )
    assert {
        tuple(shlex.split(command)[:2])
        for command in bound_web
        if shlex.split(command)[0] in {"session_profile_import", "jwt_analyze", "burp_import", "zap_import"}
    } == {
        ("session_profile_import", files["session.json"]),
        ("jwt_analyze", files["jwt.txt"]),
        ("burp_import", files["burp.xml"]),
        ("zap_import", files["zap.json"]),
    }
    assert ("openapi_import", files["openapi.yaml"]) in {tuple(shlex.split(command)[:2]) for command in bound_api}
    assert registry.get_commands_for_task(
        "cloud_security_assessment",
        "app.example.test",
        task_inputs=inputs,
    ) == ["prowler_scan azure", "scoutsuite_scan azure"]
    assert all(
        shlex.split(command)[1] == str(workspace.resolve())
        for task in ("code_security_assessment", "secrets_scanning")
        for command in registry.get_commands_for_task(task, "app.example.test", task_inputs=inputs)
    )


def test_local_artifact_facts_cannot_escape_configured_filesystem_scope(tmp_path) -> None:
    registry = ToolRegistry()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    inputs = registry.resolve_task_inputs(
        "app.example.test",
        [{"type": "session_profile", "value": str(outside)}],
        {"filesystem_scopes": [str(allowed)]},
    )

    assert inputs == {"filesystem_scope": (str(allowed.resolve()),)}


def test_remote_artifact_facts_are_bound_to_the_scan_target_scope() -> None:
    registry = ToolRegistry()

    inputs = registry.resolve_task_inputs(
        "app.example.test",
        [
            {
                "type": "openapi_spec_url",
                "value": "https://app.example.test/schema/v3.json",
            },
            {
                "type": "web_link",
                "value": "https://app.example.test/api-docs",
            },
            {
                "type": "web_link",
                "value": "https://app.example.test/schema/ordinary.json",
            },
        ],
        {
            "openapi_specs": [
                "https://app.example.test/configured/schema.json",
                "https://outside.example/openapi.json",
            ]
        },
    )

    assert inputs == {
        "openapi_spec": (
            "https://app.example.test/configured/schema.json",
            "https://app.example.test/schema/v3.json",
            "https://app.example.test/api-docs",
        )
    }


def test_reachability_report_separates_planner_routes_from_input_readiness() -> None:
    registry = ToolRegistry()
    report = registry.get_reachability_report("app.example.test")
    rows = {row["task"]: row for row in report["tasks"]}

    assert set(PLANNER_TASKS) == set(registry.task_map)
    assert report["task_map_total"] == report["planner_allowed_total"] == report["routed_total"] == 56
    assert report["unreachable"] == []
    assert rows["payload_generation"]["input_state"] == "ready"
    assert rows["web_app_deep_testing"]["input_state"] == "partial"
    assert rows["api_security_testing"]["input_state"] == "partial"
    assert rows["cloud_security_assessment"]["input_state"] == "blocked_by_input"
    assert rows["code_security_assessment"]["missing_input_kinds"] == ["filesystem_scope"]
    assert rows["secrets_scanning"]["missing_input_kinds"] == ["filesystem_scope"]


def test_non_scan_provider_templates_use_only_their_declared_input_kind() -> None:
    registry = ToolRegistry()

    for entries in registry.task_map.values():
        for template, provider in entries:
            if provider in registry.task_map:
                continue
            kind = registry.provider_input_contract(provider).kind
            if kind == "scan_target":
                continue
            assert "{target}" not in template, provider
            if kind == "none":
                assert "{" not in template, provider
            else:
                assert f"{{{kind}}}" in template, provider


def test_plugin_action_reachability_requires_schema_complete_inputs_without_exposing_values() -> None:
    canary = "credential://secret-reference-canary"
    manager = SimpleNamespace(
        list_plugins=lambda: [
            {
                "name": "typed_plugin",
                "type": "post",
                "supports_check": True,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "artifact": {"type": "string", "format": "artifact-ref"},
                        "credential": {"type": "string", "format": "credential-ref"},
                        "attempts": {"type": "integer"},
                    },
                    "required": ["artifact", "credential"],
                    "additionalProperties": False,
                },
            }
        ]
    )
    registry = ToolRegistry(plugin_manager_provider=lambda: manager)

    blocked = registry.get_discovered_plugin_action_reachability(
        "host.example.test",
        {"typed_plugin": {"artifact": "artifact://payload"}},
    )[0]
    ready = registry.get_discovered_plugin_action_reachability(
        "host.example.test",
        {
            "typed_plugin": {
                "artifact": "artifact://payload",
                "credential": canary,
                "attempts": 2,
            }
        },
    )[0]

    assert blocked["input_state"] == "blocked_by_input"
    assert blocked["missing_parameter_names"] == ["credential"]
    assert blocked["planner_visible"] is False
    assert ready["input_state"] == "ready"
    assert ready["planner_visible"] is True
    assert ready["actions"] == ["check", "run"]
    assert ready["resolved_parameter_names"] == ["artifact", "attempts", "credential"]
    assert canary not in str(ready)
