"""Regression contract for retired vendor-specific integrations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.execution import ExecutionContext, bind_execution_context
from core.tools import post_tools
from core.tools.registry import get_tool

pytestmark = [pytest.mark.contract, pytest.mark.security]

ROOT = Path(__file__).resolve().parents[1]
PANEL_ID = "c" + "panel"
BROWSER_VENDOR_ID = "shard" + "browser"
BROWSER_PRODUCT_ID = "shard" + "x"


def test_retired_vendor_paths_and_runtime_ids_are_absent() -> None:
    removed_paths = (
        ROOT / ".gitmodules",
        ROOT / "vendor" / f"{PANEL_ID}_sniper",
        ROOT / "vendor" / BROWSER_VENDOR_ID,
        ROOT / "modules" / "exploits" / f"{PANEL_ID}_auth_bypass.py",
        ROOT / "core" / "osint" / f"{BROWSER_VENDOR_ID}.py",
    )
    assert all(not path.exists() for path in removed_paths)

    removed_tool_ids = (
        f"{PANEL_ID}_exploit",
        f"{PANEL_ID}_auth_bypass",
        f"{BROWSER_VENDOR_ID}_osint",
        BROWSER_VENDOR_ID,
    )
    assert all(get_tool(tool_id) is None for tool_id in removed_tool_ids)

    manifest = json.loads((ROOT / "quality" / "vendor-manifest.json").read_text(encoding="utf-8"))
    assert manifest["submodules"] == []
    assert manifest["artifacts"] == []


def test_runtime_sources_have_no_retired_vendor_references() -> None:
    forbidden = (
        PANEL_ID,
        "w" + "hm",
        BROWSER_VENDOR_ID,
        BROWSER_PRODUCT_ID,
        "proxy" + "shard",
    )
    roots = (ROOT / "core", ROOT / "modules", ROOT / "scripts", ROOT / "quality")
    candidates = [
        path
        for source_root in roots
        for path in source_root.rglob("*")
        if path.is_file() and path.suffix in {".py", ".json", ".toml", ".yaml", ".yml"}
    ]
    candidates.extend((ROOT / "pyproject.toml", ROOT / "requirements" / "osint-browser.txt"))

    violations = []
    for path in candidates:
        text = path.read_text(encoding="utf-8", errors="ignore").casefold()
        if any(token in text for token in forbidden):
            violations.append(str(path.relative_to(ROOT)))
    assert violations == []


def test_generic_browser_surface_uses_scoped_web_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    tool = get_tool("browser_surface_analysis")
    assert tool is not None
    assert BROWSER_VENDOR_ID not in tool.aliases

    monkeypatch.setattr(post_tools, "run_scrapling_fetch", lambda url: f"fetched:{url}")
    context = ExecutionContext.automatic(
        ("example.test",),
        actor="retired-vendor-contract",
        origin="tests",
    )
    with bind_execution_context(context):
        output = post_tools.ai_browser_surface_analysis("example.test")

    assert "Backend: scrapling/requests" in output
    assert "fetched:https://example.test" in output
