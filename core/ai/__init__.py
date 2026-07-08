#!/usr/bin/env python3
"""
AI package — backward-compatible re-exports.
"""

from .ollama_client import ask_ollama
from .tag_parser import extract_tags, validate_and_fix_cmd
from .fact_engine import extract_facts_from_output
from .vuln_builder import (
    build_vulns_from_facts, parse_vulnerabilities,
    parse_exploits, parse_risk_level, parse_summary
)
from .agent_loop import analyse_target, run_tool_calls
from .system_prompt import SYSTEM_PROMPT

__all__ = [
    "ask_ollama",
    "extract_tags", "validate_and_fix_cmd",
    "extract_facts_from_output",
    "build_vulns_from_facts", "parse_vulnerabilities",
    "parse_exploits", "parse_risk_level", "parse_summary",
    "analyse_target", "run_tool_calls",
    "SYSTEM_PROMPT",
]
