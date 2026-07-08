#!/usr/bin/env python3
"""Compatibility boundary for the legacy multi-agent implementation.

The current evidence-first pipeline lives under ``core.ai.pipeline``. The
classes re-exported here are the older prompt-driven multi-agent loop kept for
backward compatibility with ``analyse_target`` callers.
"""

from agents import (  # noqa: F401
    AttackState,
    BaseAgent,
    DirectorAgent,
    ExploitAgent,
    KillChainStage,
    PostExploitAgent,
    ReconAgent,
)

__all__ = [
    "AttackState",
    "BaseAgent",
    "DirectorAgent",
    "ExploitAgent",
    "KillChainStage",
    "PostExploitAgent",
    "ReconAgent",
]
