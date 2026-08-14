"""V1 compatibility layer for existing adapters."""

from __future__ import annotations

from typing import Any


def compat_v1(v1_input: dict[str, Any]) -> dict[str, Any]:
    """Compatibility wrapper for converting legacy V1 adapter parameters to normalized dictionary format."""
    normalized = dict(v1_input)
    if "target_host" in normalized and "target" not in normalized:
        normalized["target"] = normalized["target_host"]
    return normalized
