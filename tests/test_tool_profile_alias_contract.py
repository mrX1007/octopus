"""Hermetic contracts for registered tool execution-profile diagnostics."""

from itertools import combinations

import pytest

import core.tools
from core.ai.tool_registry import ToolRegistry
from core.tools.registry import get_tool

pytestmark = [pytest.mark.contract, pytest.mark.security]


def _builtin_definitions():
    definitions = []
    for name in core.tools.BUILTIN_TOOL_NAMES:
        tool_def = get_tool(name)
        assert tool_def is not None
        definitions.append(tool_def)
    return definitions


def test_every_builtin_alias_inherits_its_canonical_execution_profile():
    registry = ToolRegistry()
    checked_aliases = []
    non_auto_aliases = []

    for tool_def in _builtin_definitions():
        canonical_profile = registry.tool_execution_profile(tool_def.name)
        for alias in tool_def.aliases:
            checked_aliases.append(alias)
            assert registry.tool_execution_profile(alias) == canonical_profile
            if canonical_profile != "auto":
                non_auto_aliases.append(alias)

    assert checked_aliases
    assert non_auto_aliases
    assert registry.tool_execution_profile("unregistered-tool") == "unknown"


def test_coverage_buckets_partition_every_builtin_name_and_alias():
    registry = ToolRegistry()
    spellings = {spelling for tool_def in _builtin_definitions() for spelling in (tool_def.name, *tool_def.aliases)}
    registered = spellings | {"unregistered-tool"}

    report = registry.get_coverage_report(list(registered))
    bucket_names = (
        "auto",
        "followup",
        "manual_gated",
        "legacy_wrappers",
        "disabled",
        "unknown",
    )
    buckets = {name: set(report[name]) for name in bucket_names}

    for left, right in combinations(bucket_names, 2):
        assert buckets[left].isdisjoint(buckets[right]), (left, right)
    assert set().union(*buckets.values()) == registered
    assert report["registered"] == len(registered)
    assert report["covered"] == len(registered - buckets["unknown"])
    assert buckets["unknown"] == {"unregistered-tool"}

    disabled_spellings = {
        spelling
        for tool_def in _builtin_definitions()
        if not tool_def.enabled
        for spelling in (tool_def.name, *tool_def.aliases)
    }
    assert buckets["disabled"] == disabled_spellings

    ssh_inventory = get_tool("ssh_inventory")
    assert ssh_inventory is not None
    ssh_spellings = {ssh_inventory.name, *ssh_inventory.aliases}
    assert ssh_spellings <= buckets["followup"]
    assert ssh_spellings.isdisjoint(buckets["auto"])
