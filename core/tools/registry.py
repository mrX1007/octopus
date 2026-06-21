#!/usr/bin/env python3
"""
Decorator-based Tool Registry for OCTOPUS.

Replaces the 620-line if/elif dispatch in runner.py with automatic
registration via decorators.

Usage (defining a tool):
    from core.tools.registry import tool

    @tool("nmap", aliases=["nmap_scan"], category="recon",
          description="TCP/UDP port scan with service detection",
          requires=["nmap"])
    def run_nmap(target, ports="", opts=""):
        ...

Usage (dispatching):
    from core.tools.registry import get_tool, list_tools, build_menu

    t = get_tool("nmap")
    if t:
        result = t.func(target)

    # Auto-build interactive menu
    menu = build_menu()  # {1: ToolDef(...), 2: ToolDef(...), ...}

Architecture:
    ┌───────────────────┐
    │   @tool decorator  │ ─── registers into ───▶ _REGISTRY dict
    └───────────────────┘
            │
    ┌───────────────────┐
    │   get_tool(name)   │ ─── lookup by name or alias
    │   list_tools()     │ ─── filter by category
    │   build_menu()     │ ─── auto-numbered menu dict
    │   discover_plugins │ ─── scan plugins/ directory
    └───────────────────┘
"""

import os
import sys
import shutil
import logging
import importlib
import importlib.util
from dataclasses import dataclass, field
from typing import Callable, Optional, Any

logger = logging.getLogger("octopus.registry")

# ─── Tool Definition ────────────────────────────────────

@dataclass
class ToolDef:
    """Metadata and callable for a registered tool."""

    name: str
    aliases: list[str] = field(default_factory=list)
    category: str = "recon"        # recon | exploit | post | osint | util
    func: Callable = None
    description: str = ""
    requires: list[str] = field(default_factory=list)  # system binary deps
    needs_target: bool = True
    enabled: bool = True
    menu_group: str = ""           # for grouping in interactive menu

    def is_available(self) -> bool:
        """Check if all required system binaries are installed."""
        for dep in self.requires:
            if shutil.which(dep) is None:
                return False
        return True

    @property
    def status_icon(self) -> str:
        """Return ✓ or ✗ based on availability."""
        return "✓" if self.is_available() else "✗"

    def __str__(self) -> str:
        avail = self.status_icon
        return f"[{avail}] {self.name} — {self.description}"


# ─── Global Registry ────────────────────────────────────

_REGISTRY: dict[str, ToolDef] = {}


def tool(
    name: str,
    *,
    aliases: list[str] | None = None,
    category: str = "recon",
    description: str = "",
    requires: list[str] | None = None,
    needs_target: bool = True,
    menu_group: str = "",
):
    """Decorator to register a function as an OCTOPUS tool.

    Args:
        name: Canonical tool name (used in dispatch and AI calls).
        aliases: Alternative names that also resolve to this tool.
        category: Tool category for menu grouping.
        description: Human-readable description shown in menus.
        requires: System binaries that must be in PATH.
        needs_target: Whether the tool requires a target argument.
        menu_group: Logical group for interactive menu display.

    Returns:
        The original function, unchanged.
    """
    def decorator(func: Callable) -> Callable:
        tool_def = ToolDef(
            name=name,
            aliases=aliases or [],
            category=category,
            func=func,
            description=description,
            requires=requires or [],
            needs_target=needs_target,
            menu_group=menu_group,
        )
        _REGISTRY[name] = tool_def

        # Also register aliases for fast lookup
        for alias in tool_def.aliases:
            if alias in _REGISTRY and _REGISTRY[alias].name != name:
                logger.warning(
                    f"Tool alias '{alias}' conflicts with existing tool "
                    f"'{_REGISTRY[alias].name}'. Overwriting."
                )
            _REGISTRY[alias] = tool_def

        logger.debug(f"Registered tool: {name} ({category})")
        return func

    return decorator


# ─── Lookup Functions ────────────────────────────────────

def get_tool(name: str) -> Optional[ToolDef]:
    """Look up a tool by name or alias.

    Args:
        name: Tool name or alias (case-insensitive).

    Returns:
        ToolDef if found, None otherwise.
    """
    key = name.lower().strip()
    if key in _REGISTRY:
        return _REGISTRY[key]

    # Fuzzy match: try removing common prefixes/suffixes
    for prefix in ("run_", "_run_"):
        stripped = key.removeprefix(prefix)
        if stripped in _REGISTRY:
            return _REGISTRY[stripped]

    return None


def list_tools(category: str | None = None, available_only: bool = False) -> list[ToolDef]:
    """List all registered tools, optionally filtered.

    Args:
        category: Filter by category (recon/exploit/post/osint/util).
        available_only: Only return tools whose dependencies are met.

    Returns:
        Sorted list of unique ToolDef objects.
    """
    # Deduplicate (aliases point to same ToolDef)
    seen_names = set()
    tools = []
    for t in _REGISTRY.values():
        if t.name not in seen_names:
            seen_names.add(t.name)
            if category and t.category != category:
                continue
            if available_only and not t.is_available():
                continue
            tools.append(t)

    return sorted(tools, key=lambda t: (t.category, t.name))


def build_menu(category: str | None = None) -> dict[int, ToolDef]:
    """Build numbered menu dict for interactive tool selection.

    Args:
        category: Optional category filter.

    Returns:
        Dict mapping menu number (1-based) to ToolDef.
    """
    tools = list_tools(category=category)
    return {i: t for i, t in enumerate(tools, 1)}


def get_all_names() -> list[str]:
    """Return all registered tool names (no aliases), sorted."""
    seen = set()
    names = []
    for t in _REGISTRY.values():
        if t.name not in seen:
            seen.add(t.name)
            names.append(t.name)
    return sorted(names)


# ─── Plugin Discovery ───────────────────────────────────

def discover_plugins(plugin_dir: str | None = None) -> int:
    """Scan plugins/ directory and import all Python modules.

    Each module is expected to use @tool() decorators which
    auto-register tools on import.

    Args:
        plugin_dir: Path to plugins directory. Defaults to
                    <project_root>/plugins/

    Returns:
        Number of plugins successfully loaded.
    """
    if plugin_dir is None:
        base = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)
        )))
        plugin_dir = os.path.join(base, "plugins")

    if not os.path.isdir(plugin_dir):
        logger.debug(f"Plugin directory not found: {plugin_dir}")
        return 0

    loaded = 0
    for filename in sorted(os.listdir(plugin_dir)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue

        filepath = os.path.join(plugin_dir, filename)
        module_name = f"plugins.{filename[:-3]}"

        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = mod
                spec.loader.exec_module(mod)
                loaded += 1
                logger.info(f"Loaded plugin: {filename}")
        except Exception as e:
            logger.warning(f"Failed to load plugin {filename}: {e}")

    return loaded


# ─── Utility ────────────────────────────────────────────

def print_registry_stats() -> None:
    """Print registry statistics for debugging."""
    unique = list_tools()
    available = list_tools(available_only=True)
    categories = {}
    for t in unique:
        categories.setdefault(t.category, []).append(t)

    print(f"\n  Tool Registry: {len(unique)} tools registered "
          f"({len(available)} available)")
    for cat, tools in sorted(categories.items()):
        avail = sum(1 for t in tools if t.is_available())
        print(f"    {cat}: {len(tools)} total, {avail} available")
    print()
