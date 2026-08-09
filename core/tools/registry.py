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

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from core.tools.dependencies import (
    DependencyContext,
    DependencyEvaluation,
    DependencySpec,
    dependency_to_dict,
    evaluate_dependency,
    normalize_dependencies,
    requirement_labels,
)

logger = logging.getLogger("octopus.registry")

# ─── Tool Definition ────────────────────────────────────


@dataclass
class ToolDef:
    """Metadata and callable for a registered tool."""

    name: str
    aliases: list[str] = field(default_factory=list)
    category: str = "recon"  # recon | exploit | post | osint | util
    func: Callable[..., Any] | None = None
    description: str = ""
    requires: list[str] = field(default_factory=list)  # system binary deps
    dependencies: DependencySpec | None = None
    needs_target: bool = True
    enabled: bool = True
    provider_path: str = ""
    disabled_reason: str = ""
    menu_group: str = ""  # for grouping in interactive menu

    def is_available(self) -> bool:
        """Return whether the complete dependency expression is satisfied."""
        try:
            return self.availability().available
        except (TypeError, ValueError):
            return False

    @property
    def dependency_expression(self) -> DependencySpec:
        """Return the canonical typed expression, adapting legacy tokens."""

        source = self.dependencies if self.dependencies is not None else self.requires
        return normalize_dependencies(source)

    def availability(self, context: DependencyContext | None = None) -> DependencyEvaluation:
        """Evaluate dependencies without running binaries or contacting services."""

        return evaluate_dependency(self.dependency_expression, context)

    def dependency_manifest(self) -> dict[str, Any]:
        """Return stable metadata for preflight, action descriptors, and docs."""

        return dependency_to_dict(self.dependency_expression)

    def requirement_labels(self) -> tuple[str, ...]:
        return requirement_labels(self.dependency_expression)

    @property
    def status_icon(self) -> str:
        """Return ✓ or ✗ based on availability."""
        return "✓" if self.is_available() else "✗"

    def __str__(self) -> str:
        avail = self.status_icon
        return f"[{avail}] {self.name} — {self.description}"


# ─── Global Registry ────────────────────────────────────

_REGISTRY: dict[str, ToolDef] = {}


def _registry_key(value: str) -> str:
    """Return the case-insensitive, whitespace-trimmed registry key."""
    return str(value or "").strip().casefold()


def _dependency_available(dep: str) -> bool:
    """Return availability for one dependency token used in ToolDef.requires."""
    try:
        return evaluate_dependency(normalize_dependencies(dep)).available
    except (TypeError, ValueError):
        return False


def tool(
    name: str,
    *,
    aliases: list[str] | None = None,
    category: str = "recon",
    description: str = "",
    requires: list[str] | None = None,
    dependencies: DependencySpec | None = None,
    needs_target: bool = True,
    enabled: bool = True,
    provider_path: str = "",
    disabled_reason: str = "",
    menu_group: str = "",
):
    """Decorator to register a function as an OCTOPUS tool.

    Args:
        name: Canonical tool name (used in dispatch and AI calls).
        aliases: Alternative names that also resolve to this tool.
        category: Tool category for menu grouping.
        description: Human-readable description shown in menus.
        requires: Legacy dependency tokens (adapted into the typed model).
        dependencies: Typed dependency expression. Mutually exclusive with
            ``requires``.
        needs_target: Whether the tool requires a target argument.
        enabled: Whether the provider is executable through the runtime.
        provider_path: Import-style source owner for capability inventory.
        disabled_reason: Stable reason for a deliberately quarantined provider.
        menu_group: Logical group for interactive menu display.

    Returns:
        The original function, unchanged.

    Raises:
        ValueError: If the canonical name or an alias is empty, duplicated in
            this declaration, or already owned by another registry entry.
    """

    def decorator(func: Callable) -> Callable:
        if requires is not None and dependencies is not None:
            raise ValueError("Use either requires or dependencies, not both")
        if not enabled and not str(disabled_reason or "").strip():
            raise ValueError("Disabled tools require a stable disabled_reason")
        canonical_name = _registry_key(name)
        normalized_aliases = [_registry_key(alias) for alias in aliases or []]
        declared_names = [canonical_name, *normalized_aliases]

        if any(not declared_name for declared_name in declared_names):
            raise ValueError("Tool registration names must be non-empty")

        duplicate_names = {declared_name for declared_name in declared_names if declared_names.count(declared_name) > 1}
        if duplicate_names:
            duplicates = ", ".join(sorted(duplicate_names))
            raise ValueError(
                f"Tool registration collision within declaration: {duplicates}",
            )

        registry_collisions = {
            declared_name: _REGISTRY[declared_name] for declared_name in declared_names if declared_name in _REGISTRY
        }
        if registry_collisions:
            collisions = ", ".join(
                f"{declared_name} -> {tool_def.name}" for declared_name, tool_def in sorted(registry_collisions.items())
            )
            raise ValueError(f"Tool registration collision: {collisions}")

        typed_dependencies = normalize_dependencies(dependencies) if dependencies is not None else None
        compatibility_requires = list(requires or [])
        if typed_dependencies is not None:
            compatibility_requires = list(requirement_labels(typed_dependencies))
        tool_def = ToolDef(
            name=canonical_name,
            aliases=normalized_aliases,
            category=category,
            func=func,
            description=description,
            requires=compatibility_requires,
            dependencies=typed_dependencies,
            needs_target=needs_target,
            enabled=bool(enabled),
            provider_path=str(provider_path or "").strip(),
            disabled_reason=str(disabled_reason or "").strip(),
            menu_group=menu_group,
        )
        _REGISTRY.update(dict.fromkeys(declared_names, tool_def))

        logger.debug(f"Registered tool: {canonical_name} ({category})")
        return func

    return decorator


# ─── Lookup Functions ────────────────────────────────────


def get_tool(name: str) -> ToolDef | None:
    """Look up a tool by name or alias.

    Args:
        name: Tool name or alias (case-insensitive).

    Returns:
        ToolDef if found, None otherwise.
    """
    key = _registry_key(name)
    if key in _REGISTRY:
        return _REGISTRY[key]
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
    return dict(enumerate(tools, 1))


def get_all_names() -> list[str]:
    """Return all registered tool names (no aliases), sorted."""
    seen = set()
    names = []
    for t in _REGISTRY.values():
        if t.name not in seen:
            seen.add(t.name)
            names.append(t.name)
    return sorted(names)


def dependency_inventory(tool_defs: Iterable[ToolDef] | None = None) -> dict[str, Any]:
    """Return deterministic declared dependencies for SBOM and diagnostics."""

    definitions = list_tools() if tool_defs is None else sorted(tool_defs, key=lambda item: item.name)
    records = []
    seen = set()
    for tool_def in definitions:
        if tool_def.name in seen:
            continue
        seen.add(tool_def.name)
        record = {
            "aliases": sorted(dict.fromkeys(tool_def.aliases)),
            "category": str(tool_def.category),
            "dependencies": tool_def.dependency_manifest(),
            "enabled": bool(tool_def.enabled),
            "name": tool_def.name,
        }
        if tool_def.provider_path:
            record["provider_path"] = tool_def.provider_path
        if tool_def.disabled_reason:
            record["disabled_reason"] = tool_def.disabled_reason
        records.append(record)
    return {"schema_version": "1.0", "tools": records}


# ─── Plugin Discovery ───────────────────────────────────


def discover_plugins(plugin_dir: str | None = None) -> int:
    """Discover class plugins through isolated metadata workers.

    Dynamic extension code is never imported into this process. Plugins are
    invoked through the registered ``plugin`` gateway and ``PluginManager``.

    Args:
        plugin_dir: Path to plugins directory. Defaults to
                    <project_root>/plugins/

    Returns:
        Number of plugins successfully loaded.
    """
    if plugin_dir is None:
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        plugin_dir = os.path.join(base, "plugins")

    if not os.path.isdir(plugin_dir):
        logger.debug(f"Plugin directory not found: {plugin_dir}")
        return 0

    try:
        from core.plugins.loader import PluginManager

        manager = PluginManager(plugin_dir)
    except Exception as exc:
        logger.warning("Isolated plugin discovery failed for %s: %s", plugin_dir, exc)
        return 0
    for skipped in manager.list_skipped_plugins():
        logger.debug("Skipped plugin %s: %s", skipped["module"], skipped["reason"])
    return len(manager.plugins)


# ─── Utility ────────────────────────────────────────────


def print_registry_stats() -> None:
    """Print registry statistics for debugging."""
    unique = list_tools()
    available = list_tools(available_only=True)
    categories: dict[str, list[ToolDef]] = {}
    for t in unique:
        categories.setdefault(t.category, []).append(t)

    print(f"\n  Tool Registry: {len(unique)} tools registered ({len(available)} available)")
    for cat, tools in sorted(categories.items()):
        avail = sum(1 for t in tools if t.is_available())
        print(f"    {cat}: {len(tools)} total, {avail} available")
    print()
