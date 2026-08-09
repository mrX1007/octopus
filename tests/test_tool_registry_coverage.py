"""Hermetic edge coverage for the decorator-based tool registry."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from core.tools import dependencies as dependency_model
from core.tools import registry

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated_registry():
    original = dict(registry._REGISTRY)
    registry._REGISTRY.clear()
    try:
        yield
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(original)


def test_tool_availability_covers_any_python_and_binary_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dependency_model.shutil,
        "which",
        lambda dependency: "/bin/present" if dependency == "present" else None,
    )
    assert registry.ToolDef(name="empty-any", requires=["any:"]).is_available() is False
    assert registry.ToolDef(name="some-any", requires=["any:missing, present"]).is_available() is True
    assert registry.ToolDef(name="missing-any", requires=["any:missing,also-missing"]).is_available() is False

    monkeypatch.setattr(
        dependency_model.importlib.util,
        "find_spec",
        lambda name: object() if name == "present_module" else None,
    )
    assert registry.ToolDef(
        name="python-present",
        requires=["python:present_module"],
    ).is_available()
    assert not registry.ToolDef(
        name="python-missing",
        requires=["python:missing_module"],
    ).is_available()

    monkeypatch.setattr(
        dependency_model.shutil,
        "which",
        lambda name: f"/bin/{name}" if name == "present-bin" else None,
    )
    available = registry.ToolDef(
        name="binary-present",
        description="available tool",
        requires=["present-bin"],
    )
    unavailable = registry.ToolDef(
        name="binary-missing",
        requires=["missing-bin"],
    )
    assert available.is_available() is True
    assert unavailable.is_available() is False
    assert str(available) == "[✓] binary-present — available tool"
    assert unavailable.status_icon == "✗"

    for special_dependency in (
        "any:python:present_module",
        "python:present_module",
    ):
        assert not registry.ToolDef(
            name="chained-dependencies",
            requires=[special_dependency, "missing-bin"],
        ).is_available()


def test_dependency_helper_covers_each_dependency_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dependency_model.importlib.util,
        "find_spec",
        lambda name: object() if name == "present_module" else None,
    )
    assert registry._dependency_available("python:present_module") is True
    assert registry._dependency_available("python:missing_module") is False

    monkeypatch.setattr(
        dependency_model.shutil,
        "which",
        lambda name: f"/bin/{name}" if name == "present-bin" else None,
    )
    assert registry._dependency_available("present-bin") is True
    assert registry._dependency_available("missing-bin") is False


def test_alias_collision_available_filter_names_and_menu(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @registry.tool("first", category="recon")
    def first_tool():
        return "first"

    before = dict(registry._REGISTRY)
    with pytest.raises(ValueError, match="Tool registration collision"):

        @registry.tool("replacement", aliases=["first"], category="post")
        def replacement_tool():
            return "replacement"

    assert before == registry._REGISTRY

    @registry.tool("available", aliases=["available-alias"], category="util")
    def available_tool():
        return "available"

    @registry.tool("unavailable", category="util", requires=["missing-bin"])
    def unavailable_tool():
        return "unavailable"

    assert registry.get_tool("first").func is first_tool
    assert registry.get_tool("replacement") is None
    monkeypatch.setattr(
        registry.ToolDef,
        "is_available",
        lambda self: self.name != "unavailable",
    )
    assert [item.name for item in registry.list_tools(available_only=True)] == [
        "first",
        "available",
    ]
    assert [item.name for item in registry.list_tools(category="util")] == [
        "available",
        "unavailable",
    ]
    assert registry.get_all_names() == ["available", "first", "unavailable"]
    assert [item.name for item in registry.build_menu().values()] == [
        "first",
        "available",
        "unavailable",
    ]
    assert first_tool() == "first"
    assert available_tool() == "available"
    assert unavailable_tool() == "unavailable"


def test_plugin_discovery_default_missing_failure_and_success(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(registry.os.path, "isdir", lambda _path: False)
    assert registry.discover_plugins() == 0

    monkeypatch.setattr(registry.os.path, "isdir", lambda _path: True)
    failing_loader = ModuleType("core.plugins.loader")

    class FailingManager:
        def __init__(self, _directory: str) -> None:
            raise RuntimeError("isolated discovery failed")

    failing_loader.PluginManager = FailingManager  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "core.plugins.loader", failing_loader)
    assert registry.discover_plugins("/virtual/plugins") == 0
    assert "Isolated plugin discovery failed" in caplog.text

    observed: list[str] = []
    successful_loader = ModuleType("core.plugins.loader")

    class SuccessfulManager:
        def __init__(self, directory: str) -> None:
            observed.append(directory)
            self.plugins = {"one": object(), "two": object()}

        @staticmethod
        def list_skipped_plugins():
            return ({"module": "skipped", "reason": "invalid"},)

    successful_loader.PluginManager = SuccessfulManager  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "core.plugins.loader", successful_loader)
    assert registry.discover_plugins("/virtual/plugins") == 2
    assert observed == ["/virtual/plugins"]


def test_registry_stats_reports_categories_and_availability(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    available = registry.ToolDef(name="available", category="recon")
    unavailable = registry.ToolDef(name="unavailable", category="post")
    registry._REGISTRY.update(
        {
            "available": available,
            "available-alias": available,
            "unavailable": unavailable,
        },
    )
    monkeypatch.setattr(
        registry.ToolDef,
        "is_available",
        lambda self: self.name == "available",
    )

    registry.print_registry_stats()

    output = capsys.readouterr().out
    assert "2 tools registered (1 available)" in output
    assert "post: 1 total, 0 available" in output
    assert "recon: 1 total, 1 available" in output
