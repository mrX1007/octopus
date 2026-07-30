#!/usr/bin/env python3
"""Configuration-owned, fail-closed kill-chain stage policy.

Named stages in :data:`STAGE_REGISTRY` are the public contract. Numeric labels
in legacy output are deliberately not used for policy decisions because they
have changed over time.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StageSpec:
    """Canonical names that refer to one configuration-owned stage."""

    name: str
    aliases: tuple[str, ...] = ()
    tasks: tuple[str, ...] = ()
    goals: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()


STAGE_REGISTRY: tuple[StageSpec, ...] = (
    StageSpec(
        name="vuln_assess",
        tasks=("vulnerability_assessment",),
        goals=("vulnerability_assessment",),
        tools=("killchain_vuln_assess", "killchain_vuln", "vuln_assess"),
    ),
    StageSpec(
        name="exploitation",
        aliases=("auto_exploit", "exploit"),
        tools=("killchain_exploit", "auto_exploit"),
    ),
    StageSpec(
        name="privesc",
        tasks=("exploit_privesc",),
        goals=("privilege_escalation",),
        tools=("killchain_privesc", "privesc"),
    ),
    StageSpec(
        name="persistence",
        aliases=("persist",),
        tasks=("establish_persistence",),
        goals=("persistence",),
        tools=("killchain_persist", "persist", "persistence"),
    ),
    StageSpec(
        name="lateral_movement",
        aliases=("lateral",),
        tasks=("lateral_movement",),
        tools=("killchain_lateral", "lateral_move", "lateral"),
    ),
    StageSpec(
        name="data_exfil",
        aliases=("exfil",),
        tasks=("exfiltrate_data",),
        goals=("data_exfiltration",),
        tools=("killchain_exfil", "data_exfil", "exfil"),
    ),
    StageSpec(
        name="cleanup",
        aliases=("stealth_cleanup",),
        tasks=("stealth_cleanup",),
        goals=("cleanup",),
        tools=("killchain_cleanup", "cleanup", "stealth_cleanup"),
    ),
)


def _derive_unique_map(attribute: str) -> dict[str, str]:
    """Derive one public lookup and reject ambiguous registry declarations."""

    lookup: dict[str, str] = {}
    for spec in STAGE_REGISTRY:
        for raw_name in getattr(spec, attribute):
            name = str(raw_name).strip().casefold()
            existing = lookup.get(name)
            if existing is not None and existing != spec.name:
                raise RuntimeError(f"kill-chain registry name {name!r} maps to both {existing!r} and {spec.name!r}")
            lookup[name] = spec.name
    return lookup


KILLCHAIN_STAGES: tuple[str, ...] = tuple(spec.name for spec in STAGE_REGISTRY)
_STAGE_ALIASES = _derive_unique_map("aliases")
TASK_STAGE_MAP: dict[str, str] = _derive_unique_map("tasks")
GOAL_STAGE_MAP: dict[str, str] = _derive_unique_map("goals")
TOOL_STAGE_MAP: dict[str, str] = _derive_unique_map("tools")

_TOOL_CANONICAL_MAP: dict[str, str] = {tool_name: spec.tools[0] for spec in STAGE_REGISTRY for tool_name in spec.tools}
_FULL_KILLCHAIN_TOOLS = {
    "killchain_full": "killchain_full",
    "full_killchain": "killchain_full",
}


def _runtime_config(config: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    if config is not None:
        return config if isinstance(config, Mapping) else {}
    try:
        from config import CFG
    except ImportError:
        return {}
    return CFG if isinstance(CFG, Mapping) else {}


def _normalized_name(value: Any) -> str:
    return str(value or "").strip().casefold()


def _normalized_tool_name(tool_name: Any) -> str:
    normalized = _normalized_name(tool_name)
    for prefix in ("run_", "_run_"):
        if normalized.startswith(prefix):
            return normalized.removeprefix(prefix)
    return normalized


def normalize_stage(stage: str) -> str:
    """Return the canonical name for a configured kill-chain stage."""

    normalized = _normalized_name(stage)
    return _STAGE_ALIASES.get(normalized, normalized)


def registered_tool_stage(tool_name: str) -> str | None:
    """Return the canonical stage for a registered name or registry alias."""

    return TOOL_STAGE_MAP.get(_normalized_tool_name(tool_name))


def canonical_killchain_tool(tool_name: str) -> str | None:
    """Return the canonical registered kill-chain tool, including full-run aliases."""

    normalized = _normalized_tool_name(tool_name)
    return _TOOL_CANONICAL_MAP.get(normalized) or _FULL_KILLCHAIN_TOOLS.get(normalized)


def killchain_enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Return the validated master switch, failing closed when it is absent."""

    cfg = _runtime_config(config)
    section = cfg.get("killchain")
    if not isinstance(section, Mapping):
        return False
    return _strict_config_bool(section.get("enabled"))


def stage_enabled(
    stage: str,
    config: Mapping[str, Any] | None = None,
) -> bool:
    """Return whether both the master switch and a named stage are enabled."""

    canonical = normalize_stage(stage)
    cfg = _runtime_config(config)
    if canonical not in KILLCHAIN_STAGES or not killchain_enabled(cfg):
        return False
    section = cfg.get("killchain")
    stages = section.get("stages")
    if not isinstance(stages, Mapping):
        return False
    return _strict_config_bool(stages.get(canonical))


def master_gate_message(config: Mapping[str, Any] | None = None) -> str:
    if killchain_enabled(config):
        return ""
    return "[BLOCKED] killchain_disabled: killchain.enabled=false"


def stage_gate_reason(
    stage: str,
    config: Mapping[str, Any] | None = None,
) -> str:
    """Return a stable machine reason for the master and named-stage gates."""

    cfg = _runtime_config(config)
    if not killchain_enabled(cfg):
        return "killchain_disabled"
    canonical = normalize_stage(stage)
    if canonical not in KILLCHAIN_STAGES:
        return f"killchain_unknown_stage:{canonical or 'empty'}"
    if not stage_enabled(canonical, cfg):
        return f"killchain_stage_disabled:{canonical}"
    return ""


def stage_gate_message(
    stage: str,
    config: Mapping[str, Any] | None = None,
) -> str:
    """Return an empty string when allowed, otherwise a stable status line."""

    reason = stage_gate_reason(stage, config)
    if not reason:
        return ""
    if reason == "killchain_disabled":
        return master_gate_message(config)
    if reason.startswith("killchain_unknown_stage:"):
        return f"[BLOCKED] {reason}"
    return f"[SKIPPED] {reason}"


def registered_tool_gate_reason(
    tool_name: str,
    config: Mapping[str, Any] | None = None,
) -> str:
    """Return the final execution denial for a registered kill-chain name.

    Names outside the reserved kill-chain namespace are not classified here.
    Registered aliases and the registry's ``run_`` compatibility prefix are
    normalized before policy evaluation.
    """

    normalized = _normalized_tool_name(tool_name)
    if normalized in _FULL_KILLCHAIN_TOOLS:
        return "" if killchain_enabled(config) else "killchain_disabled"
    stage = TOOL_STAGE_MAP.get(normalized)
    if stage is not None:
        return stage_gate_reason(stage, config)
    if normalized.startswith("killchain_"):
        return f"killchain_unknown_tool:{normalized}"
    return ""


def policy_snapshot(config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return the serializable master/stage policy used by AI planning."""

    cfg = _runtime_config(config)
    strategy = cfg.get("strategy")
    auto_killchain = _strict_config_bool(strategy.get("auto_killchain")) if isinstance(strategy, Mapping) else False
    return {
        "enabled": killchain_enabled(cfg),
        "auto_killchain": auto_killchain,
        "stages": {stage: stage_enabled(stage, cfg) for stage in KILLCHAIN_STAGES},
        "automated_stages": {stage: automated_stage_enabled(stage, cfg) for stage in KILLCHAIN_STAGES},
    }


def automated_stage_enabled(
    stage: str,
    config: Mapping[str, Any] | None = None,
) -> bool:
    """Return whether autonomous planning may select a kill-chain stage.

    ``strategy.auto_killchain`` is an automation master switch. It never
    overrides the hard ``killchain.enabled`` or per-stage switches.
    """

    cfg = _runtime_config(config)
    strategy = cfg.get("strategy")
    auto_killchain = _strict_config_bool(strategy.get("auto_killchain")) if isinstance(strategy, Mapping) else False
    return auto_killchain and stage_enabled(stage, cfg)


def _strict_config_bool(value: Any) -> bool:
    """Accept only a validated YAML boolean at a policy boundary."""

    return value if isinstance(value, bool) else False
