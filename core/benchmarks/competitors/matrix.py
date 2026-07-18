"""Fair, repeatable multi-system benchmark orchestration and publication."""

from __future__ import annotations

import hashlib
import json
import shutil
import statistics
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..harness import BenchmarkHarness, BenchmarkRunner
from ..schema import (
    MIN_BENCHMARK_REPETITIONS,
    BenchmarkAggregate,
    BenchmarkScenario,
)
from .runner import CommandSystemRunner
from .schema import CompetitorSchemaError, SystemManifest

COMPETITOR_MATRIX_SCHEMA_VERSION = "1.0"

_PRIVATE_METADATA_KEYS = frozenset(
    {
        "adapter",
        "api_key",
        "command",
        "command_template",
        "cwd",
        "env",
        "environment",
        "executable",
        "headers",
        "secret",
        "secrets",
        "token",
    }
)
_METRIC_COLUMNS = (
    ("finding_precision", "Precision"),
    ("finding_recall", "Recall"),
    ("forbidden_finding_rate", "Forbidden"),
    ("evidence_completeness", "Evidence"),
    ("no_op_task_rate", "No-op"),
    ("repeated_task_rate", "Repeat"),
    ("api_cost_usd", "Cost USD"),
)
_STRICT_RUN_STATUSES = frozenset({"failed", "invalid", "partial", "timeout"})


@dataclass(frozen=True)
class CompetitorMatrixResult:
    """One complete comparison matrix plus its independently publishable aggregates."""

    matrix_id: str
    track: str
    fairness_profile: Any
    execution_mode: str
    repetitions: int
    systems: tuple[dict[str, Any], ...]
    scenarios: tuple[dict[str, Any], ...]
    aggregates: dict[str, dict[str, BenchmarkAggregate]]
    summaries: tuple[dict[str, Any], ...]
    completeness: dict[str, Any]
    generated_at: float
    schema_version: str = COMPETITOR_MATRIX_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return publication metadata; full run data lives in aggregate files."""

        return {
            "schema_version": self.schema_version,
            "matrix_id": self.matrix_id,
            "methodology": {
                "track": self.track,
                "fairness_profile": self.fairness_profile,
                "execution_mode": self.execution_mode,
                "same_scenarios": True,
                "same_repetitions": True,
                "same_seeds": True,
                "automatic_winner": False,
            },
            "repetitions": self.repetitions,
            "systems": [dict(item) for item in self.systems],
            "scenarios": [dict(item) for item in self.scenarios],
            "summaries": [dict(item) for item in self.summaries],
            "publication": dict(self.completeness),
            "generated_at": self.generated_at,
        }

    @property
    def has_strict_failures(self) -> bool:
        return any(
            int(self.completeness.get(name, 0)) > 0
            for name in (
                "failed_runs",
                "invalid_runs",
                "partial_runs",
                "timeout_runs",
                "policy_violations",
            )
        )


# Short aliases make the public API pleasant without hiding the explicit name.
MatrixResult = CompetitorMatrixResult


def run_competitor_matrix(
    manifests: Sequence[SystemManifest],
    scenarios: Sequence[BenchmarkScenario],
    *,
    repetitions: int = MIN_BENCHMARK_REPETITIONS,
    runner_factory: Callable[[SystemManifest], BenchmarkRunner] = CommandSystemRunner,
    clock: Callable[[], float] = time.time,
) -> CompetitorMatrixResult:
    """Run every scenario with every system under one validated fairness contract."""

    repetition_count = int(repetitions)
    if repetition_count < MIN_BENCHMARK_REPETITIONS:
        raise CompetitorSchemaError(
            f"repetitions_below_minimum:{MIN_BENCHMARK_REPETITIONS}"
        )
    manifest_items = tuple(manifests)
    scenario_items = tuple(scenarios)
    if len(manifest_items) < 2:
        raise CompetitorSchemaError("matrix_requires_at_least_two_systems")
    if not scenario_items:
        raise CompetitorSchemaError("matrix_requires_scenarios")

    manifest_payloads = tuple(_manifest_payload(item) for item in manifest_items)
    system_ids = tuple(_system_id(item) for item in manifest_payloads)
    if len(set(system_ids)) != len(system_ids):
        raise CompetitorSchemaError("duplicate_system_id")
    scenario_ids = tuple(item.scenario_id for item in scenario_items)
    if len(set(scenario_ids)) != len(scenario_ids):
        raise CompetitorSchemaError("duplicate_scenario_id")

    track = _common_value(manifest_payloads, "track")
    fairness_profile = _common_json_value(manifest_payloads, "fairness_profile")
    execution_mode = _common_execution_mode(manifest_payloads)
    if track == "framework_only":
        _require_equal_framework_models(manifest_payloads)
    _validate_declared_model_fairness(manifest_payloads, fairness_profile)
    _validate_declared_tool_fairness(manifest_payloads, fairness_profile)

    public_systems_in_run_order = tuple(
        _public_system_metadata(payload) for payload in manifest_payloads
    )
    aggregates: dict[str, dict[str, BenchmarkAggregate]] = {}
    summaries: list[dict[str, Any]] = []
    for manifest, payload, public_metadata, system_id in zip(
        manifest_items,
        manifest_payloads,
        public_systems_in_run_order,
        system_ids,
    ):
        runner = runner_factory(manifest)
        harness = BenchmarkHarness(
            runner,
            clock=clock,
            run_namespace=_system_identity(payload),
            runner_metadata=public_metadata,
        )
        system_aggregates: dict[str, BenchmarkAggregate] = {}
        for scenario in scenario_items:
            aggregate = harness.run(scenario, repetitions=repetition_count)
            system_aggregates[scenario.scenario_id] = aggregate
            summaries.append(_aggregate_summary(system_id, aggregate))
        aggregates[system_id] = system_aggregates

    summaries.sort(key=lambda item: (item["scenario_id"], item["system_id"]))
    completeness = _publication_counts(
        aggregates,
        expected=len(manifest_items) * len(scenario_items),
    )
    aggregate_ids = {
        system_id: {
            scenario_id: aggregate.aggregate_id
            for scenario_id, aggregate in sorted(system_aggregates.items())
        }
        for system_id, system_aggregates in sorted(aggregates.items())
    }
    matrix_id = _stable_id(
        "competitor-matrix",
        {
            "schema_version": COMPETITOR_MATRIX_SCHEMA_VERSION,
            "systems": [
                _system_identity(payload)
                for payload in sorted(
                    manifest_payloads,
                    key=lambda item: _system_id(item),
                )
            ],
            "aggregate_ids": aggregate_ids,
        },
    )
    return CompetitorMatrixResult(
        matrix_id=matrix_id,
        track=track,
        fairness_profile=fairness_profile,
        execution_mode=execution_mode,
        repetitions=repetition_count,
        systems=tuple(
            sorted(
                public_systems_in_run_order,
                key=lambda item: str(item["system_id"]),
            )
        ),
        scenarios=tuple(
            sorted(
                (_scenario_metadata(item) for item in scenario_items),
                key=lambda item: str(item["scenario_id"]),
            )
        ),
        aggregates=aggregates,
        summaries=tuple(summaries),
        completeness=completeness,
        generated_at=clock(),
    )


run_matrix = run_competitor_matrix


def publish_competitor_matrix(
    result: CompetitorMatrixResult,
    output_directory: str | Path,
) -> Path:
    """Atomically publish a self-checking directory without replacing prior results."""

    destination = Path(output_directory)
    if destination.exists():
        raise FileExistsError(f"publication_destination_exists:{destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}-tmp-",
            dir=str(destination.parent),
        )
    )
    try:
        _write_json(temporary / "comparison.json", result.to_dict())
        (temporary / "comparison.md").write_text(
            render_comparison_markdown(result),
            encoding="utf-8",
        )
        for system_id, system_aggregates in sorted(result.aggregates.items()):
            for scenario_id, aggregate in sorted(system_aggregates.items()):
                _write_json(
                    temporary
                    / "aggregates"
                    / _safe_path_component(system_id)
                    / f"{_safe_path_component(scenario_id)}.json",
                    aggregate.to_dict(),
                )
        checksum_paths = sorted(
            path for path in temporary.rglob("*") if path.is_file()
        )
        checksum_lines = [
            f"{_sha256_file(path)}  {path.relative_to(temporary).as_posix()}"
            for path in checksum_paths
        ]
        (temporary / "SHA256SUMS").write_text(
            "\n".join(checksum_lines) + "\n",
            encoding="utf-8",
        )
        if destination.exists():
            raise FileExistsError(
                f"publication_destination_exists:{destination}"
            )
        temporary.rename(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


publish_matrix = publish_competitor_matrix


def render_comparison_markdown(result: CompetitorMatrixResult) -> str:
    """Render an auditable comparison report without declaring a winner."""

    mode = result.execution_mode or "unspecified"
    lines = [
        "# Competitor benchmark comparison",
        "",
        f"Matrix: `{result.matrix_id}`  ",
        f"Schema: `{result.schema_version}`  ",
        f"Track: `{result.track}`  ",
        f"Execution mode: `{mode}`  ",
        f"Repetitions per system/scenario: `{result.repetitions}`",
        "",
        "## Methodology",
        "",
        (
            "Every listed system ran the same versioned scenarios with identical "
            "repetition counts, seeds, lab/target definitions, and scenario budgets "
            "under the declared fairness profile."
        ),
        "",
        (
            f"This matrix contains only `{mode}` executions; live and replay results are "
            "never mixed in one matrix."
        ),
        "",
        (
            "The report publishes measurements and does not select, rank, or declare "
            "an automatic winner. Interpret failures and policy violations alongside "
            "the metric medians."
        ),
        "",
        "## Systems",
        "",
        "| System | Version | Source revision | Model | Tool versions |",
        "|---|---:|---|---|---|",
    ]
    for system in result.systems:
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                _markdown_cell(system.get("display_name") or system.get("name") or system.get("system_id")),
                _markdown_cell(system.get("version")),
                _markdown_cell(system.get("source_revision")),
                _markdown_cell(_compact_json(_model_metadata(system))),
                _markdown_cell(_compact_json(system.get("tool_versions") or {})),
            )
        )
    lines.extend(
        [
            "",
            "## Scenario controls",
            "",
            "| Scenario | Lab version | Target version | Budgets | Repetitions |",
            "|---|---:|---:|---|---:|",
        ]
    )
    for scenario in result.scenarios:
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                _markdown_cell(scenario["scenario_id"]),
                _markdown_cell(scenario["lab_version"]),
                _markdown_cell(scenario["target_version"]),
                _markdown_cell(_compact_json(scenario["budgets"])),
                result.repetitions,
            )
        )
    metric_headers = " | ".join(label for _name, label in _METRIC_COLUMNS)
    lines.extend(
        [
            "",
            "## Results",
            "",
            (
                "| Scenario | System | Status counts | Duration median (s) | "
                + metric_headers
                + " |"
            ),
            "|---|---|---|---:|" + "---:|" * len(_METRIC_COLUMNS),
        ]
    )
    for summary in result.summaries:
        medians = summary["metric_medians"]
        cells = [
            _format_metric(medians.get(metric_name))
            for metric_name, _label in _METRIC_COLUMNS
        ]
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                _markdown_cell(summary["scenario_id"]),
                _markdown_cell(summary["system_id"]),
                _markdown_cell(_compact_json(summary["status_counts"])),
                _format_metric(summary.get("duration_median_seconds")),
                " | ".join(cells),
            )
        )
    lines.extend(
        [
            "",
            "## Publication completeness",
            "",
            "```json",
            json.dumps(result.completeness, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _manifest_payload(manifest: SystemManifest) -> dict[str, Any]:
    method = getattr(manifest, "to_dict", None)
    if not callable(method):
        raise CompetitorSchemaError("system_manifest_missing_to_dict")
    payload = method()
    if not isinstance(payload, Mapping):
        raise CompetitorSchemaError("system_manifest_not_mapping")
    return {str(key): value for key, value in payload.items()}


def _system_id(payload: Mapping[str, Any]) -> str:
    value = str(payload.get("system_id") or "").strip()
    if not value:
        raise CompetitorSchemaError("missing:system_id")
    return value


def _system_identity(payload: Mapping[str, Any]) -> str:
    identity = {
        "system_id": _system_id(payload),
        "version": payload.get("version"),
        "source_revision": payload.get("source_revision"),
        "track": payload.get("track"),
        "fairness_profile": payload.get("fairness_profile"),
        "execution_mode": _execution_mode(payload),
        "model": _model_metadata(payload),
        "tool_versions": payload.get("tool_versions") or {},
        "metadata": payload.get("metadata") or {},
    }
    return _stable_id("benchmark-system", identity)


def _common_value(payloads: Sequence[Mapping[str, Any]], key: str) -> str:
    values = {str(payload.get(key) or "").strip() for payload in payloads}
    if "" in values:
        raise CompetitorSchemaError(f"missing:{key}")
    if len(values) != 1:
        raise CompetitorSchemaError(f"mixed_{key}")
    return values.pop()


def _common_json_value(
    payloads: Sequence[Mapping[str, Any]],
    key: str,
) -> Any:
    values: dict[str, Any] = {}
    for payload in payloads:
        value = payload.get(key)
        if value is None or value == "":
            raise CompetitorSchemaError(f"missing:{key}")
        values[_canonical_json(value)] = value
    if len(values) != 1:
        raise CompetitorSchemaError(f"mixed_{key}")
    return next(iter(values.values()))


def _execution_mode(payload: Mapping[str, Any]) -> str:
    metadata = payload.get("metadata")
    metadata_mode = (
        metadata.get("execution_mode") if isinstance(metadata, Mapping) else None
    )
    return str(
        payload.get("execution_mode")
        or payload.get("mode")
        or payload.get("runner_mode")
        or metadata_mode
        or "external_command"
    ).strip()


def _common_execution_mode(payloads: Sequence[Mapping[str, Any]]) -> str:
    modes = {_execution_mode(payload) for payload in payloads}
    if len(modes) != 1:
        raise CompetitorSchemaError("mixed_execution_mode")
    return modes.pop()


def _model_metadata(payload: Mapping[str, Any]) -> Any:
    return payload.get("model_metadata") or payload.get("model") or {}


def _require_equal_framework_models(
    payloads: Sequence[Mapping[str, Any]],
) -> None:
    models = {_canonical_json(_model_metadata(payload)) for payload in payloads}
    if "{}" in models or "null" in models:
        raise CompetitorSchemaError("framework_only_requires_model_metadata")
    if len(models) != 1:
        raise CompetitorSchemaError("framework_only_requires_equal_model_metadata")


def _validate_declared_tool_fairness(
    payloads: Sequence[Mapping[str, Any]],
    fairness_profile: Any,
) -> None:
    if not isinstance(fairness_profile, Mapping):
        return
    if not bool(fairness_profile.get("same_tool_versions")):
        return
    versions = {
        _canonical_json(payload.get("tool_versions") or {}) for payload in payloads
    }
    if len(versions) != 1:
        raise CompetitorSchemaError(
            "fairness_profile_requires_equal_tool_versions"
        )


def _validate_declared_model_fairness(
    payloads: Sequence[Mapping[str, Any]],
    fairness_profile: Any,
) -> None:
    if not isinstance(fairness_profile, Mapping):
        return
    if not bool(fairness_profile.get("same_model")):
        return
    models = {_canonical_json(_model_metadata(payload)) for payload in payloads}
    if "{}" in models or "null" in models:
        raise CompetitorSchemaError(
            "fairness_profile_requires_model_metadata"
        )
    if len(models) != 1:
        raise CompetitorSchemaError(
            "fairness_profile_requires_equal_model_metadata"
        )


def _public_system_metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    source = payload.get("public_metadata")
    if not isinstance(source, Mapping):
        source = payload
    sanitized = _sanitize_public_metadata(source)
    if not isinstance(sanitized, dict):
        raise CompetitorSchemaError("invalid:public_metadata")
    sanitized.setdefault("system_id", _system_id(payload))
    sanitized.setdefault("version", payload.get("version"))
    sanitized.setdefault("track", payload.get("track"))
    sanitized.setdefault("fairness_profile", payload.get("fairness_profile"))
    sanitized.setdefault("execution_mode", _execution_mode(payload))
    if not sanitized.get("model") and not sanitized.get("model_metadata"):
        sanitized["model_metadata"] = _model_metadata(payload)
    return sanitized


def _sanitize_public_metadata(value: Any, *, depth: int = 0) -> Any:
    if depth >= 6:
        return "[depth-bounded]"
    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_public_metadata(item, depth=depth + 1)
            for key, item in value.items()
            if str(key).lower() not in _PRIVATE_METADATA_KEYS
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [
            _sanitize_public_metadata(item, depth=depth + 1)
            for item in value[:256]
        ]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return str(value)


def _scenario_metadata(scenario: BenchmarkScenario) -> dict[str, Any]:
    return {
        "scenario_id": scenario.scenario_id,
        "name": scenario.name,
        "category": scenario.category,
        "lab_version": scenario.lab.get("version"),
        "target_version": scenario.target.get("version"),
        "model": dict(scenario.model),
        "tool_versions": dict(scenario.tool_versions),
        "budgets": dict(scenario.budgets),
        "seed": scenario.seed,
    }


def _aggregate_summary(
    system_id: str,
    aggregate: BenchmarkAggregate,
) -> dict[str, Any]:
    durations = [float(run.duration_seconds) for run in aggregate.runs]
    policy_violations = sum(len(run.policy_violations) for run in aggregate.runs)
    timeout_runs = sum(1 for run in aggregate.runs if run.status == "timeout")
    partial_runs = sum(1 for run in aggregate.runs if run.status == "partial")
    error_runs = sum(
        1 for run in aggregate.runs if run.status in _STRICT_RUN_STATUSES
    )
    return {
        "system_id": system_id,
        "scenario_id": aggregate.scenario.scenario_id,
        "aggregate_id": aggregate.aggregate_id,
        "status_counts": dict(aggregate.status_counts),
        "duration_median_seconds": (
            round(float(statistics.median(durations)), 6) if durations else None
        ),
        "metric_medians": {
            name: values["median"]
            for name, values in sorted(aggregate.metric_statistics.items())
            if "median" in values
        },
        "policy_violations": policy_violations,
        "timeout_runs": timeout_runs,
        "partial_runs": partial_runs,
        "error_runs": error_runs,
    }


def _publication_counts(
    aggregates: Mapping[str, Mapping[str, BenchmarkAggregate]],
    *,
    expected: int,
) -> dict[str, Any]:
    aggregate_items = [
        aggregate
        for system_aggregates in aggregates.values()
        for aggregate in system_aggregates.values()
    ]
    runs = [run for aggregate in aggregate_items for run in aggregate.runs]
    written = len(aggregate_items)
    failed = sum(1 for run in runs if run.status == "failed")
    invalid = sum(1 for run in runs if run.status == "invalid")
    timeout = sum(1 for run in runs if run.status == "timeout")
    partial = sum(1 for run in runs if run.status == "partial")
    policy_violations = sum(len(run.policy_violations) for run in runs)
    return {
        "expected_aggregates": expected,
        "written_aggregates": written,
        "missing_aggregates": max(0, expected - written),
        "publication_complete": written == expected,
        "total_runs": len(runs),
        "succeeded_runs": sum(1 for run in runs if run.status == "succeeded"),
        "failed_runs": failed,
        "invalid_runs": invalid,
        "timeout_runs": timeout,
        "partial_runs": partial,
        "policy_violations": policy_violations,
        "error_runs": failed + invalid + timeout + partial,
    }


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _stable_id(namespace: str, payload: Any) -> str:
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{namespace}://sha256/{digest}"


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_path_component(value: str) -> str:
    if not value or value in {".", ".."}:
        raise CompetitorSchemaError("unsafe_path_component")
    if any(character in value for character in ("/", "\\", "\x00")):
        raise CompetitorSchemaError("unsafe_path_component")
    return value


def _compact_json(value: Any) -> str:
    if value in (None, "", {}, []):
        return "—"
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _markdown_cell(value: Any) -> str:
    text = "—" if value in (None, "") else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _format_metric(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{float(value):.6g}"
