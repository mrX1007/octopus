"""Schema 1.0 models for repeatable OCTOPUS benchmark scenarios."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BENCHMARK_SCHEMA_VERSION = "1.0"
MIN_BENCHMARK_REPETITIONS = 5
REQUIRED_SCENARIO_CATEGORIES = (
    "service_discovery_verification",
    "web_api_mapping",
    "credential_discovery_safe_validation",
    "verified_ssh_inventory",
    "authorized_internal_discovery",
    "clean_negative",
    "timeout_partial_result",
    "invalid_empty_llm",
    "crash_resume",
    "contradictions",
)

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_MAX_ITEMS = 256
_MAX_TEXT_BYTES = 4_096


class BenchmarkSchemaError(ValueError):
    """Raised when scenario metadata cannot satisfy the versioned contract."""


@dataclass(frozen=True)
class BenchmarkScenario:
    scenario_id: str
    name: str
    category: str
    lab: dict[str, Any]
    target: dict[str, Any]
    model: dict[str, Any]
    tool_versions: dict[str, str]
    strategy_config: dict[str, Any]
    seed: int
    budgets: dict[str, Any]
    allowed_actions: tuple[str, ...]
    ground_truth: dict[str, Any]
    artifacts: dict[str, Any]
    repetitions: int = MIN_BENCHMARK_REPETITIONS
    ablations: tuple[dict[str, Any], ...] = ()
    tags: tuple[str, ...] = ()
    schema_version: str = BENCHMARK_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> BenchmarkScenario:
        schema_version = str(payload.get("schema_version") or "")
        if schema_version != BENCHMARK_SCHEMA_VERSION:
            raise BenchmarkSchemaError(
                f"unsupported_schema_version:{schema_version or 'missing'}"
            )
        scenario_id = _identifier(payload.get("scenario_id"), "scenario_id")
        name = _text(payload.get("name"), "name")
        category = _identifier(payload.get("category"), "category")
        lab = _mapping(payload.get("lab"), "lab")
        target = _mapping(payload.get("target"), "target")
        model = _mapping(payload.get("model"), "model")
        tool_versions_raw = _mapping(payload.get("tool_versions"), "tool_versions")
        strategy_config = _mapping(payload.get("strategy_config"), "strategy_config")
        budgets = _mapping(payload.get("budgets"), "budgets")
        ground_truth = _mapping(payload.get("ground_truth"), "ground_truth")
        artifacts = _mapping(payload.get("artifacts"), "artifacts")
        _required_version(lab, "lab")
        _required_version(target, "target")
        if not _text(model.get("provider"), "model.provider"):
            raise BenchmarkSchemaError("missing:model.provider")
        if not _text(model.get("name"), "model.name"):
            raise BenchmarkSchemaError("missing:model.name")
        if "parameters" not in model or not isinstance(model.get("parameters"), Mapping):
            raise BenchmarkSchemaError("invalid:model.parameters")
        tool_versions = {
            _identifier(key, "tool_name"): _text(value, "tool_version")
            for key, value in tool_versions_raw.items()
        }
        if not tool_versions:
            raise BenchmarkSchemaError("empty:tool_versions")
        allowed_actions = _identifiers(
            payload.get("allowed_actions"), "allowed_actions"
        )
        if not allowed_actions:
            raise BenchmarkSchemaError("empty:allowed_actions")
        repetitions = _integer(payload.get("repetitions", MIN_BENCHMARK_REPETITIONS))
        if repetitions < MIN_BENCHMARK_REPETITIONS:
            raise BenchmarkSchemaError(
                f"repetitions_below_minimum:{MIN_BENCHMARK_REPETITIONS}"
            )
        seed = _integer(payload.get("seed", 0), minimum=0)
        _validate_budgets(budgets)
        ablations_raw = payload.get("ablations") or []
        if not isinstance(ablations_raw, Sequence) or isinstance(
            ablations_raw, (str, bytes)
        ):
            raise BenchmarkSchemaError("invalid:ablations")
        ablations = tuple(
            _mapping(item, f"ablations[{index}]")
            for index, item in enumerate(ablations_raw[:_MAX_ITEMS])
        )
        for ablation in ablations:
            _identifier(ablation.get("toggle"), "ablation.toggle")
            values = ablation.get("values")
            if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
                raise BenchmarkSchemaError("invalid:ablation.values")
            if len(values) < 2:
                raise BenchmarkSchemaError("ablation_requires_multiple_values")
        tags = _identifiers(payload.get("tags") or [], "tags", allow_empty=True)
        return cls(
            scenario_id=scenario_id,
            name=name,
            category=category,
            lab=lab,
            target=target,
            model=model,
            tool_versions=tool_versions,
            strategy_config=strategy_config,
            seed=seed,
            budgets=budgets,
            allowed_actions=allowed_actions,
            ground_truth=ground_truth,
            artifacts=artifacts,
            repetitions=repetitions,
            ablations=ablations,
            tags=tags,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "name": self.name,
            "category": self.category,
            "lab": dict(self.lab),
            "target": dict(self.target),
            "model": dict(self.model),
            "tool_versions": dict(self.tool_versions),
            "strategy_config": dict(self.strategy_config),
            "seed": self.seed,
            "budgets": dict(self.budgets),
            "allowed_actions": list(self.allowed_actions),
            "ground_truth": dict(self.ground_truth),
            "artifacts": dict(self.artifacts),
            "repetitions": self.repetitions,
            "ablations": [dict(item) for item in self.ablations],
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class BenchmarkRun:
    run_id: str
    scenario_id: str
    repetition: int
    seed: int
    status: str
    actions: tuple[str, ...]
    policy_violations: tuple[str, ...]
    metrics: dict[str, float]
    result_summary: dict[str, Any]
    artifact_refs: tuple[str, ...]
    duration_seconds: float
    started_at: float
    finished_at: float
    environment: dict[str, Any]
    error_class: str = ""
    schema_version: str = BENCHMARK_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "repetition": self.repetition,
            "seed": self.seed,
            "status": self.status,
            "actions": list(self.actions),
            "policy_violations": list(self.policy_violations),
            "metrics": dict(self.metrics),
            "result_summary": dict(self.result_summary),
            "artifact_refs": list(self.artifact_refs),
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "environment": dict(self.environment),
            "error_class": self.error_class,
        }


@dataclass(frozen=True)
class BenchmarkAggregate:
    aggregate_id: str
    scenario: BenchmarkScenario
    runs: tuple[BenchmarkRun, ...]
    metric_statistics: dict[str, dict[str, float]]
    status_counts: dict[str, int]
    generated_at: float
    schema_version: str = BENCHMARK_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "aggregate_id": self.aggregate_id,
            "scenario": self.scenario.to_dict(),
            "runs": [item.to_dict() for item in self.runs],
            "metric_statistics": {
                key: dict(value) for key, value in self.metric_statistics.items()
            },
            "status_counts": dict(self.status_counts),
            "generated_at": self.generated_at,
        }


def load_scenario(path: str | Path) -> BenchmarkScenario:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkSchemaError(
            f"scenario_load_failed:{source.name}:{type(exc).__name__}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise BenchmarkSchemaError(f"scenario_not_mapping:{source.name}")
    return BenchmarkScenario.from_dict(payload)


def load_scenarios(directory: str | Path) -> tuple[BenchmarkScenario, ...]:
    root = Path(directory)
    scenarios = tuple(load_scenario(path) for path in sorted(root.glob("*.json")))
    ids = [item.scenario_id for item in scenarios]
    if len(ids) != len(set(ids)):
        raise BenchmarkSchemaError("duplicate_scenario_id")
    return scenarios


def _required_version(value: Mapping[str, Any], name: str) -> None:
    if not _text(value.get("version"), f"{name}.version"):
        raise BenchmarkSchemaError(f"missing:{name}.version")


def _validate_budgets(budgets: Mapping[str, Any]) -> None:
    required = ("max_tools", "max_seconds", "max_output_bytes")
    for name in required:
        if name not in budgets:
            raise BenchmarkSchemaError(f"missing:budgets.{name}")
        _integer(budgets[name], minimum=1)


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkSchemaError(f"invalid:{name}")
    if len(value) > _MAX_ITEMS:
        raise BenchmarkSchemaError(f"too_many_items:{name}")
    return {str(key): _json_safe(item) for key, item in value.items()}


def _identifiers(
    values: Any,
    name: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise BenchmarkSchemaError(f"invalid:{name}")
    result = tuple(
        dict.fromkeys(_identifier(value, name) for value in values[:_MAX_ITEMS])
    )
    if not allow_empty and not result:
        raise BenchmarkSchemaError(f"empty:{name}")
    return result


def _identifier(value: Any, name: str) -> str:
    text = str(value or "").strip().lower()
    if not _IDENTIFIER.fullmatch(text):
        raise BenchmarkSchemaError(f"invalid_identifier:{name}")
    return text


def _text(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise BenchmarkSchemaError(f"missing:{name}")
    if len(text.encode("utf-8", "replace")) > _MAX_TEXT_BYTES:
        raise BenchmarkSchemaError(f"text_too_long:{name}")
    return text


def _integer(value: Any, *, minimum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise BenchmarkSchemaError("invalid_integer") from exc
    if minimum is not None and parsed < minimum:
        raise BenchmarkSchemaError(f"integer_below_minimum:{minimum}")
    return parsed


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    if depth >= 6:
        return "[depth-bounded]"
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item, depth=depth + 1)
            for key, item in list(value.items())[:_MAX_ITEMS]
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [
            _json_safe(item, depth=depth + 1) for item in value[:_MAX_ITEMS]
        ]
    return str(value)


__all__ = [
    "BENCHMARK_SCHEMA_VERSION",
    "MIN_BENCHMARK_REPETITIONS",
    "REQUIRED_SCENARIO_CATEGORIES",
    "BenchmarkAggregate",
    "BenchmarkRun",
    "BenchmarkScenario",
    "BenchmarkSchemaError",
    "load_scenario",
    "load_scenarios",
]
