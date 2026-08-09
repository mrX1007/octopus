"""Remaining recursion and optional-boundary coverage for the AI tool registry."""

from __future__ import annotations

import builtins
from types import SimpleNamespace

import pytest

import core.ai.tool_registry as ai_registry_module
import core.plugins.loader as plugin_loader_module
import core.tools.registry as tool_registry_module
from core.ai.tool_registry import ToolRegistry

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
