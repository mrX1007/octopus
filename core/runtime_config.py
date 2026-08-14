"""Small runtime helpers for configuration shared across subsystems."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class C2EnrollmentBounds:
    ttl_min_seconds: int = 60
    ttl_default_seconds: int = 900
    ttl_max_seconds: int = 3600
    max_uses_default: int = 1
    max_uses_max: int = 1

    def __post_init__(self) -> None:
        values = (
            self.ttl_min_seconds,
            self.ttl_default_seconds,
            self.ttl_max_seconds,
            self.max_uses_default,
            self.max_uses_max,
        )
        if any(type(value) is not int for value in values):
            raise ValueError("C2 enrollment bounds must be integers")
        if not 1 <= self.ttl_min_seconds <= self.ttl_default_seconds <= self.ttl_max_seconds:
            raise ValueError("invalid C2 enrollment TTL bounds")
        if self.ttl_max_seconds > 86_400:
            raise ValueError("C2 enrollment maximum TTL exceeds the hard safety bound")
        if self.max_uses_default != 1 or self.max_uses_max != 1:
            raise ValueError("C2 enrollment is single-use")


_ENROLLMENT_ENV_KEYS = {
    "ttl_min_seconds": "OCTOPUS_C2_ENROLLMENT_TTL_MIN_SECONDS",
    "ttl_default_seconds": "OCTOPUS_C2_ENROLLMENT_TTL_DEFAULT_SECONDS",
    "ttl_max_seconds": "OCTOPUS_C2_ENROLLMENT_TTL_MAX_SECONDS",
    "max_uses_default": "OCTOPUS_C2_ENROLLMENT_MAX_USES_DEFAULT",
    "max_uses_max": "OCTOPUS_C2_ENROLLMENT_MAX_USES_MAX",
}


def _strict_config_int(value: object, *, key: str) -> int:
    if type(value) is int:
        return value
    if isinstance(value, str) and value and value.isascii() and value.isdecimal():
        return int(value)
    raise ValueError(f"{key} must be a bounded integer")


def load_c2_enrollment_bounds(
    *,
    config: Mapping[str, object] | None = None,
    environ: Mapping[str, str] | None = None,
) -> C2EnrollmentBounds:
    """Resolve canonical enrollment bounds and fail closed on bad overrides."""

    if config is None:
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        config = CFG
    environment = os.environ if environ is None else environ
    c2_config = config.get("c2", {}) if isinstance(config, Mapping) else {}
    enrollment = c2_config.get("enrollment", {}) if isinstance(c2_config, Mapping) else {}
    if not isinstance(enrollment, Mapping):
        raise ValueError("c2.enrollment must be a mapping")

    defaults = C2EnrollmentBounds()
    resolved: dict[str, int] = {}
    for field_name, environment_key in _ENROLLMENT_ENV_KEYS.items():
        raw_value: object = getattr(defaults, field_name)
        if field_name in enrollment:
            raw_value = enrollment[field_name]
        if environment_key in environment:
            raw_value = environment[environment_key]
        resolved[field_name] = _strict_config_int(raw_value, key=environment_key)
    return C2EnrollmentBounds(**resolved)


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

    limits = [value for value in (_positive_int(requested), _positive_int(configured)) if value is not None]
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
