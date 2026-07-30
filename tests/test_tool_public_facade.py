"""Hermetic contracts for the policy-bound public tool facade."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

from core.execution import ExecutionContext, bind_execution_context

pytestmark = pytest.mark.contract


def test_public_dispatch_requires_context_and_forwards_to_registered_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools import public

    context = ExecutionContext.automatic(target_scope=("fixture.invalid",))
    calls: list[tuple[str, ExecutionContext]] = []
    monkeypatch.setattr(
        public,
        "run_tool_by_command",
        lambda command, supplied_context: calls.append(
            (command, supplied_context),
        ) or "fixture result",
    )

    assert public.dispatch_registered_tool("fixture fixture.invalid", context) == (
        "fixture result"
    )
    assert calls == [("fixture fixture.invalid", context)]

    with pytest.raises(TypeError, match="must be an ExecutionContext"):
        public.dispatch_registered_tool("fixture fixture.invalid", object())  # type: ignore[arg-type]


def test_package_and_legacy_module_advertise_one_canonical_dispatch() -> None:
    import core.tools as package

    legacy = importlib.import_module("tools")
    compatibility_names = {
        *package.LOW_LEVEL_EXECUTION_EXPORTS,
        *package.DIRECT_PROVIDER_EXPORTS,
    }

    assert package.dispatch_registered_tool is legacy.dispatch_registered_tool
    assert legacy.__all__ == tuple(package.__all__)
    assert legacy.__deprecated_exports__ is package.DEPRECATED_TOOL_EXPORTS
    assert set(package.DEPRECATED_TOOL_EXPORTS) == compatibility_names
    assert compatibility_names <= set(package.__all__)
    assert "dispatch_registered_tool" in package.__all__
    assert "dispatch_registered_tool" not in compatibility_names
    assert set(package.DEPRECATED_TOOL_EXPORTS.values()) == {
        "Use core.tools.dispatch_registered_tool with an ExecutionContext",
    }
    execution_like_exports = {
        name
        for name in package.__all__
        if name.startswith(("run_", "_run_"))
    }
    assert execution_like_exports == {
        name
        for name in compatibility_names
        if name.startswith(("run_", "_run_"))
    }


def test_pipeline_compatibility_name_uses_safe_facade_and_bound_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import core.ai.pipeline as pipeline

    context = ExecutionContext.automatic(target_scope=("fixture.invalid",))
    calls: list[tuple[str, ExecutionContext]] = []
    monkeypatch.setattr(
        pipeline,
        "dispatch_registered_tool",
        lambda command, supplied_context: calls.append(
            (command, supplied_context),
        ) or "fixture result",
    )

    with bind_execution_context(context):
        assert pipeline.run_arbitrary_cmd("fixture fixture.invalid") == "fixture result"

    assert calls == [("fixture fixture.invalid", context)]


def test_production_does_not_import_top_level_tools_compatibility_module() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = list(root.glob("*.py"))
    for directory in ("core", "modules", "plugins", "scripts"):
        paths.extend((root / directory).rglob("*.py"))

    callers = []
    for path in paths:
        if path == root / "tools.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            imports_tools = (
                isinstance(node, ast.ImportFrom)
                and node.module == "tools"
            ) or (
                isinstance(node, ast.Import)
                and any(alias.name == "tools" for alias in node.names)
            )
            if imports_tools:
                callers.append(str(path.relative_to(root)))

    assert callers == []
