#!/usr/bin/env python3
"""Tests for core/tools/registry.py — tool registration and lookup."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.tools.registry import _REGISTRY, build_menu, get_tool, list_tools, tool

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def clean_registry():
    """Clear registry before each test."""
    _REGISTRY.clear()
    yield
    _REGISTRY.clear()


# ─── Registration Tests ─────────────────────────

class TestToolDecorator:
    """Test @tool() decorator registration."""

    def test_registers_by_name(self):
        @tool("test_scanner", category="recon", description="A test tool")
        def my_scanner(target):
            return f"scanning {target}"

        assert "test_scanner" in _REGISTRY
        assert _REGISTRY["test_scanner"].name == "test_scanner"
        assert _REGISTRY["test_scanner"].category == "recon"

    def test_registers_aliases(self):
        @tool("nmap", aliases=["nmap_scan", "portscan"], category="recon")
        def run_nmap(target):
            return "nmap output"

        assert "nmap" in _REGISTRY
        assert "nmap_scan" in _REGISTRY
        assert "portscan" in _REGISTRY
        # All should point to the same ToolDef
        assert _REGISTRY["nmap"].func is _REGISTRY["nmap_scan"].func

    def test_function_unchanged(self):
        @tool("echo", category="util")
        def echo_tool(msg):
            return msg

        assert echo_tool("hello") == "hello"

    def test_default_category_is_recon(self):
        @tool("scanner")
        def run_scanner(target):
            pass

        assert _REGISTRY["scanner"].category == "recon"


# ─── Lookup Tests ────────────────────────────────

class TestGetTool:
    """Test tool lookup by name and alias."""

    def test_lookup_by_name(self):
        @tool("nikto", category="recon")
        def run_nikto(target):
            pass

        result = get_tool("nikto")
        assert result is not None
        assert result.name == "nikto"

    def test_lookup_by_alias(self):
        @tool("sqlmap", aliases=["sqli", "sql_injection"], category="exploit")
        def run_sqlmap(target):
            pass

        result = get_tool("sqli")
        assert result is not None
        assert result.name == "sqlmap"

    def test_lookup_case_insensitive(self):
        @tool("dirfuzz", category="recon")
        def run_dirfuzz(target):
            pass

        result = get_tool("DIRFUZZ")
        assert result is not None

    def test_lookup_nonexistent_returns_none(self):
        result = get_tool("nonexistent_tool_xyz")
        assert result is None

    def test_lookup_strips_run_prefix(self):
        @tool("hydra", category="exploit")
        def run_hydra(target):
            pass

        result = get_tool("run_hydra")
        assert result is not None
        assert result.name == "hydra"


# ─── List and Menu Tests ─────────────────────────

class TestListTools:
    """Test tool listing and filtering."""

    def test_list_all_tools(self):
        @tool("a_tool", category="recon")
        def t1(x): pass

        @tool("b_tool", category="exploit")
        def t2(x): pass

        tools = list_tools()
        assert len(tools) == 2

    def test_filter_by_category(self):
        @tool("recon1", category="recon")
        def t1(x): pass

        @tool("exploit1", category="exploit")
        def t2(x): pass

        @tool("recon2", category="recon")
        def t3(x): pass

        recon = list_tools(category="recon")
        assert len(recon) == 2
        assert all(t.category == "recon" for t in recon)

    def test_deduplicates_aliases(self):
        @tool("scanner", aliases=["scan", "s"], category="recon")
        def run_scanner(x): pass

        tools = list_tools()
        assert len(tools) == 1  # Not 3

    def test_build_menu_numbered(self):
        @tool("tool_a", category="recon")
        def t1(x): pass

        @tool("tool_b", category="recon")
        def t2(x): pass

        menu = build_menu()
        assert 1 in menu
        assert 2 in menu
        assert len(menu) == 2


# ─── Availability Tests ─────────────────────────

class TestToolAvailability:
    """Test dependency checking."""

    def test_available_when_no_requires(self):
        @tool("simple", category="util", requires=[])
        def simple(x): pass

        t = get_tool("simple")
        assert t.is_available()

    def test_available_with_existing_binary(self):
        @tool("with_python", category="util", requires=["python3"])
        def with_dep(x): pass

        t = get_tool("with_python")
        assert t.is_available()

    def test_unavailable_with_missing_binary(self):
        @tool("needs_fake", category="util", requires=["totally_fake_binary_xyz"])
        def needs_fake(x): pass

        t = get_tool("needs_fake")
        assert not t.is_available()

    def test_status_icon(self):
        @tool("avail", category="util", requires=[])
        def t1(x): pass

        @tool("unavail", category="util", requires=["nonexistent_bin_xyz"])
        def t2(x): pass

        assert get_tool("avail").status_icon == "✓"
        assert get_tool("unavail").status_icon == "✗"
