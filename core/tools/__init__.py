#!/usr/bin/env python3
"""
Tool package — backward-compatible re-exports.
"""

# Base utilities
from core.tools.base import (
    run_tool, is_tool_available, _fmt_elapsed, get_tool_config, ToolResult,
    C_GREY, C_RESET, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_BLUE, C_MAGENTA,
)

# TOOLS_MENU and dispatchers
from core.tools.runner import TOOLS_MENU, run_tool_by_command, run_arbitrary_cmd
