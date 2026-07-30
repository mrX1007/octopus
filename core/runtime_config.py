"""Small runtime helpers for configuration shared across subsystems."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def effective_runtime_limit(requested: Any = None, configured: Any = None) -> int | None:
    """Return the smallest positive caller/configured limit, or no limit.

    Caller limits remain authoritative when they are tighter, while a configured
    safety cap still applies when the caller requests the legacy ``0``/unlimited
    value.
    """

    limits = [
        value
        for value in (_positive_int(requested), _positive_int(configured))
        if value is not None
    ]
    return min(limits) if limits else None


def effective_parallel_workers(
    requested: Any = None,
    *,
    config: Mapping[str, Any] | None = None,
) -> int:
    """Return the smallest positive caller/LLM/strategy worker limit."""

    if config is None:
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        config = CFG
    ollama = config.get("ollama", {}) if isinstance(config, Mapping) else {}
    strategy = config.get("strategy", {}) if isinstance(config, Mapping) else {}
    candidates = [
        _positive_int(requested),
        _positive_int(ollama.get("concurrent_tools")) if isinstance(ollama, Mapping) else None,
        _positive_int(strategy.get("parallel_tools")) if isinstance(strategy, Mapping) else None,
    ]
    limits = [value for value in candidates if value is not None]
    return min(limits) if limits else 1
