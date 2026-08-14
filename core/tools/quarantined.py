"""Compatibility re-export of manual_actions module for legacy consumers."""

from __future__ import annotations

from core.tools.manual_actions import MANUAL_GATED_CAPABILITY_NAMES, QUARANTINED_CAPABILITY_NAMES

__all__ = ["MANUAL_GATED_CAPABILITY_NAMES", "QUARANTINED_CAPABILITY_NAMES"]
