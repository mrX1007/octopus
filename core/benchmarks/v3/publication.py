"""Deterministic CSV, JSON, and GitHub-safe SVG publication for v3."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
import shutil
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .analysis import AnalysisPlan, analyze_runs, freeze_analysis_plan, load_analysis_plan
from .evaluation import ReportedClaim, evaluate_claims, verified_truth_ids_from_evidence
from .fixture import FixtureVariant
from .ledger import iter_verified_ledger_entries
from .schema import (
    ActionEvent,
    BenchmarkRunV3,
    BenchmarkV3SchemaError,
    BudgetEnforcement,
    RunEvaluation,
    canonical_json,
    stable_digest,
)
from .tracks import validate_single_track

RUNS_CSV_SCHEMA_VERSION = "1.0"
PUBLICATION_SCHEMA_VERSION = "1.1"
_LEGACY_PUBLICATION_SCHEMA_VERSION = "1.0"
_MAX_JSONL_SHARD_BYTES = 48_000_000
_MAX_JSONL_ARTIFACT_BYTES = 512_000_000
SVG_PANEL_IDS = (
    "execution-outcomes",
    "task-outcomes",
    "verified-recall",
    "censored-completion-time",
)


@dataclass(frozen=True)
class _RunProjection:
    """Memory-bounded run view used after action telemetry is verified."""

    run_id: str
    track_id: str
    system_id: str
    scenario_id: str
    repetition: int
    execution_status: str
    evaluation: RunEvaluation
    matched_fixture_seed: int
    fixture_variant_digest: str
    applied_model_seed: int | None
    model_seed_status: str
    budget_enforcement: tuple[BudgetEnforcement, ...]
    action_event_count: int
    action_projection_digest: str
    action_telemetry_available: bool
    action_telemetry_reliability: str
    duration_seconds: float
    duration_censored: bool
    censor_limit_seconds: float | None
    policy_violations: tuple[str, ...]
    artifact_refs: tuple[str, ...]
    environment: Mapping[str, Any]
    schema_version: str

    @property
    def task_status(self) -> str:
        return self.evaluation.task_status

    @property
    def completion_rule_id(self) -> str:
        return self.evaluation.completion_rule_id


@dataclass(frozen=True)
class _JsonlLocation:
    path: Path
    offset: int
    length: int
    sort_key: tuple[Any, ...]


@dataclass(frozen=True)
class _JsonlRecord:
    path: Path
    offset: int
    raw_line: bytes
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class _VerifiedBundle:
    result: dict[str, Any]
    publication: Mapping[str, Any]
    run_locations: tuple[_JsonlLocation, ...]
    ledger_locations: tuple[_JsonlLocation, ...]


def render_runs_csv(
    plan: AnalysisPlan,
    runs: Sequence[BenchmarkRunV3],
) -> str:
    """Render one stable row per scheduled run without private environment data."""

    items = sorted(runs, key=_run_sort_key)
    metric_columns = [(population, metric) for population in plan.populations for metric in plan.metrics]
    fields = [
        "csv_schema_version",
        "analysis_plan_digest",
        "run_schema_version",
        "run_id",
        "track_id",
        "system_id",
        "scenario_id",
        "repetition",
        "matched_fixture_seed",
        "fixture_variant_digest",
        "execution_status",
        "task_status",
        "completion_rule_id",
        "duration_seconds",
        "duration_censored",
        "censor_limit_seconds",
        "applied_model_seed",
        "model_seed_status",
        "reported_claims",
        "supported_claims",
        "verified_claims",
        "unmatched_claims",
        "action_telemetry_available",
        "action_event_count",
        "policy_violations_json",
        "budget_enforcement_json",
    ]
    for population, metric_name in metric_columns:
        prefix = f"{population}.{metric_name}"
        fields.extend(
            [
                f"{prefix}.available",
                f"{prefix}.reliability",
                f"{prefix}.value",
                f"{prefix}.numerator",
                f"{prefix}.denominator",
            ]
        )
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=fields,
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for run in items:
        row: dict[str, Any] = {
            "action_event_count": run.action_event_count,
            "action_telemetry_available": _bool(run.action_telemetry_available),
            "analysis_plan_digest": plan.digest,
            "applied_model_seed": _empty(run.applied_model_seed),
            "budget_enforcement_json": canonical_json([item.to_dict() for item in run.budget_enforcement]),
            "censor_limit_seconds": _empty(run.censor_limit_seconds),
            "completion_rule_id": run.completion_rule_id,
            "csv_schema_version": RUNS_CSV_SCHEMA_VERSION,
            "duration_censored": _bool(run.duration_censored),
            "duration_seconds": _float(run.duration_seconds),
            "execution_status": run.execution_status,
            "fixture_variant_digest": run.fixture_variant_digest,
            "matched_fixture_seed": run.matched_fixture_seed,
            "model_seed_status": run.model_seed_status,
            "policy_violations_json": canonical_json(list(run.policy_violations)),
            "repetition": run.repetition,
            "reported_claims": len(run.evaluation.claims),
            "run_id": run.run_id,
            "run_schema_version": run.schema_version,
            "scenario_id": run.scenario_id,
            "supported_claims": sum(item.supported for item in run.evaluation.claims),
            "system_id": run.system_id,
            "task_status": run.task_status,
            "track_id": run.track_id,
            "unmatched_claims": sum(not item.supported for item in run.evaluation.claims),
            "verified_claims": sum(item.verified for item in run.evaluation.claims),
        }
        for population, metric_name in metric_columns:
            metric = run.evaluation.metric(metric_name, population)
            prefix = f"{population}.{metric_name}"
            row[f"{prefix}.available"] = _bool(metric.available)
            row[f"{prefix}.reliability"] = metric.reliability
            row[f"{prefix}.value"] = _empty(metric.value)
            row[f"{prefix}.numerator"] = _empty(metric.numerator)
            row[f"{prefix}.denominator"] = _empty(metric.denominator)
        writer.writerow(row)
    return stream.getvalue()


def render_run_records(runs: Sequence[BenchmarkRunV3]) -> str:
    """Render complete, canonical run objects for independent re-analysis."""

    return "".join(canonical_json(run.to_dict()) + "\n" for run in sorted(runs, key=_run_sort_key))


def svg_contract() -> dict[str, Any]:
    return {
        "external_resources": False,
        "panels": list(SVG_PANEL_IDS),
        "scripts": False,
        "separate_execution_and_task_outcomes": True,
        "verified_recall_confidence_intervals": True,
        "censor_aware_completion_time": True,
    }


def render_statistics_svg(
    plan: AnalysisPlan,
    statistics_payload: Mapping[str, Any],
) -> str:
    """Render four semantically separate panels without scripts or fonts."""

    systems_raw = statistics_payload.get("systems")
    if not isinstance(systems_raw, Mapping):
        raise BenchmarkV3SchemaError("invalid_statistics_systems")
    system_ids = [item for item in plan.system_ids if item in systems_raw]
    if len(system_ids) != len(plan.system_ids):
        raise BenchmarkV3SchemaError("statistics_missing_system")
    width = 1200
    panel_height = 205
    top = 78
    gap = 18
    height = top + len(SVG_PANEL_IDS) * (panel_height + gap) + 30
    colors = ("#2563eb", "#059669", "#d97706", "#7c3aed", "#dc2626", "#0891b2")
    fragments = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="chart-title chart-desc">',
        '<title id="chart-title">Benchmark v3 outcome and evidence statistics</title>',
        '<desc id="chart-desc">Separate panels for execution outcomes, task outcomes, verified recall with Wilson confidence intervals, and censor-aware completion time.</desc>',
        "<style>text{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;fill:#172033}.panel{fill:#fff;stroke:#cbd5e1}.grid{stroke:#e2e8f0}.label{font-size:13px}.small{font-size:11px;fill:#475569}.title{font-size:18px;font-weight:700}.heading{font-size:24px;font-weight:700}</style>",
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        '<text class="heading" x="38" y="38">Benchmark v3 — separated outcomes</text>',
        f'<text class="small" x="38" y="59">Track: {html.escape(plan.track_id)} · Plan: {html.escape(plan.digest[:16])} · No cross-track ranking</text>',
    ]
    panels = (
        ("execution-outcomes", "Execution outcomes", _render_outcome_panel, "execution_outcomes"),
        ("task-outcomes", "Task outcomes", _render_outcome_panel, "task_outcomes"),
        ("verified-recall", "Verified recall (all scheduled, Wilson 95% CI)", _render_recall_panel, ""),
        ("censored-completion-time", "Censor-aware completion time", _render_duration_panel, ""),
    )
    for panel_index, (panel_id, title, renderer, field) in enumerate(panels):
        y = top + panel_index * (panel_height + gap)
        fragments.extend(
            [
                f'<g id="{panel_id}" data-panel="{panel_id}">',
                f'<rect class="panel" x="28" y="{y}" width="1144" height="{panel_height}" rx="8"/>',
                f'<text class="title" x="48" y="{y + 28}">{html.escape(title)}</text>',
                *renderer(
                    systems_raw,
                    system_ids,
                    colors,
                    y + 42,
                    field,
                    plan,
                ),
                "</g>",
            ]
        )
    fragments.append("</svg>")
    return "\n".join(fragments) + "\n"


def publish_v3_results(
    plan: AnalysisPlan,
    runs: Sequence[BenchmarkRunV3],
    output_directory: str | Path,
    *,
    campaign_context: Mapping[str, Any],
    controller_ledgers: Sequence[Mapping[str, Any]],
) -> Path:
    """Atomically publish deterministic v3 artifacts in one isolated track."""

    if plan.publication_tier == "diagnostic":
        raise BenchmarkV3SchemaError("diagnostic_runs_are_not_publishable")
    items = tuple(runs)
    track = validate_single_track(items)
    if track.track_id != plan.track_id:
        raise BenchmarkV3SchemaError("publication_track_mismatch")
    statistics_payload = analyze_runs(plan, items)
    context_payload = _validated_campaign_context(campaign_context)
    ledger_payload = _validated_controller_ledgers(controller_ledgers)
    destination = Path(output_directory).resolve()
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
        freeze_analysis_plan(plan, temporary / "analysis-plan.json")
        (temporary / "runs.csv").write_text(
            render_runs_csv(plan, items),
            encoding="utf-8",
        )
        run_record_names = _write_jsonl_shards(
            temporary,
            prefix="runs",
            records=(run.to_dict() for run in sorted(items, key=_run_sort_key)),
        )
        (temporary / "statistics.json").write_text(
            json.dumps(
                statistics_payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n",
            encoding="utf-8",
        )
        (temporary / "comparison.svg").write_text(
            render_statistics_svg(plan, statistics_payload),
            encoding="utf-8",
        )
        (temporary / "campaign-context.json").write_text(
            json.dumps(
                context_payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n",
            encoding="utf-8",
        )
        ledger_names = _write_jsonl_shards(
            temporary,
            prefix="ledgers",
            records=ledger_payload,
        )
        manifest = {
            "analysis_plan_digest": plan.digest,
            "artifacts": {
                "analysis_plan": "analysis-plan.json",
                "runs": "runs.csv",
                "run_records": list(run_record_names),
                "statistics": "statistics.json",
                "visualization": "comparison.svg",
                "campaign_context": "campaign-context.json",
                "controller_ledgers": list(ledger_names),
            },
            "leaderboard_merge_group": track.merge_group,
            "publication_tier": plan.publication_tier,
            "schema_version": PUBLICATION_SCHEMA_VERSION,
            "svg_contract": svg_contract(),
            "track_id": plan.track_id,
        }
        (temporary / "publication.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        checksum_paths = sorted(path for path in temporary.iterdir() if path.is_file())
        checksum_lines = [f"{_sha256(path)}  {path.name}" for path in checksum_paths]
        (temporary / "SHA256SUMS").write_text(
            "\n".join(checksum_lines) + "\n",
            encoding="utf-8",
        )
        if destination.exists():
            raise FileExistsError(f"publication_destination_exists:{destination}")
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def repack_v3_results(
    source_directory: str | Path,
    destination_directory: str | Path,
) -> Path:
    """Verify and atomically repack a v3 bundle with bounded peak memory."""

    source = Path(source_directory).resolve()
    destination = Path(destination_directory).resolve()
    if destination == source or source in destination.parents:
        raise ValueError("v3_repack_destination_inside_source")
    if destination.exists():
        raise FileExistsError(f"publication_destination_exists:{destination}")
    verified = _verify_v3_bundle(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}-tmp-",
            dir=str(destination.parent),
        )
    )
    try:
        for name in (
            "analysis-plan.json",
            "campaign-context.json",
            "comparison.svg",
            "runs.csv",
            "statistics.json",
        ):
            shutil.copyfile(source / name, temporary / name)
        run_names = _write_repacked_jsonl_shards(
            verified.run_locations,
            temporary,
            prefix="runs",
        )
        ledger_names = _write_repacked_jsonl_shards(
            verified.ledger_locations,
            temporary,
            prefix="ledgers",
        )
        publication = verified.publication
        manifest = {
            "analysis_plan_digest": publication.get("analysis_plan_digest"),
            "artifacts": {
                "analysis_plan": "analysis-plan.json",
                "campaign_context": "campaign-context.json",
                "controller_ledgers": list(ledger_names),
                "run_records": list(run_names),
                "runs": "runs.csv",
                "statistics": "statistics.json",
                "visualization": "comparison.svg",
            },
            "leaderboard_merge_group": publication.get("leaderboard_merge_group"),
            "publication_tier": publication.get("publication_tier"),
            "schema_version": PUBLICATION_SCHEMA_VERSION,
            "svg_contract": publication.get("svg_contract"),
            "track_id": publication.get("track_id"),
        }
        (temporary / "publication.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        checksum_paths = sorted(path for path in temporary.iterdir() if path.is_file())
        (temporary / "SHA256SUMS").write_text(
            "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_paths),
            encoding="utf-8",
        )
        verify_v3_results(temporary)
        if destination.exists():
            raise FileExistsError(f"publication_destination_exists:{destination}")
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def verify_v3_results(directory: str | Path) -> dict[str, Any]:
    """Verify a v3 publication without retaining bulk telemetry in memory."""

    return _verify_v3_bundle(Path(directory).resolve()).result


def _verify_v3_bundle(root: Path) -> _VerifiedBundle:
    """Return verified metadata plus byte locations needed for lossless repack."""

    checksum_path = root / "SHA256SUMS"
    try:
        lines = checksum_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise BenchmarkV3SchemaError("v3_publication_checksums_missing") from exc
    expected: dict[str, str] = {}
    for line in lines:
        digest, separator, name = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not name
            or "/" in name
            or name in expected
        ):
            raise BenchmarkV3SchemaError("invalid_v3_publication_checksums")
        expected[name] = digest
    actual_files = {path.name for path in root.iterdir() if path.is_file() and path.name != "SHA256SUMS"}
    if actual_files != set(expected):
        raise BenchmarkV3SchemaError("v3_publication_file_set_mismatch")
    for name, digest in expected.items():
        if _sha256(root / name) != digest:
            raise BenchmarkV3SchemaError("v3_publication_checksum_mismatch")

    plan = load_analysis_plan(root / "analysis-plan.json")
    try:
        publication = json.loads((root / "publication.json").read_text(encoding="utf-8"))
        statistics = json.loads((root / "statistics.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkV3SchemaError("invalid_v3_publication_payload") from exc
    if not isinstance(publication, Mapping) or not isinstance(statistics, Mapping):
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    artifacts = publication.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    publication_version, run_record_names, ledger_names = _validated_publication_artifacts(publication, artifacts)
    contract_files = {
        "analysis-plan.json",
        "campaign-context.json",
        "comparison.svg",
        "publication.json",
        "runs.csv",
        "statistics.json",
        *run_record_names,
        *ledger_names,
    }
    if actual_files != contract_files:
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    if publication_version == PUBLICATION_SCHEMA_VERSION:
        _validate_jsonl_shard_sizes(root, run_record_names)
        _validate_jsonl_shard_sizes(root, ledger_names)
    try:
        loaded_context = json.loads((root / "campaign-context.json").read_text(encoding="utf-8"))
        with (root / "runs.csv").open("r", encoding="utf-8", newline="") as handle:
            rows = tuple(csv.DictReader(handle))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkV3SchemaError("invalid_v3_publication_payload") from exc
    if not isinstance(loaded_context, Mapping):
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    context_payload = loaded_context
    run_records, run_locations = _load_run_projections(
        root,
        run_record_names,
        publication_version=publication_version,
    )
    expected_schedule = {
        (system_id, scenario_id, repetition, plan.fixture_seeds[scenario_id][repetition - 1])
        for system_id in plan.system_ids
        for scenario_id in plan.scenario_ids
        for repetition in range(1, plan.repetitions + 1)
    }
    observed_schedule = {
        (
            run.system_id,
            run.scenario_id,
            run.repetition,
            run.matched_fixture_seed,
        )
        for run in run_records
    }
    track = validate_single_track([run.track_id for run in run_records])
    run_ids = {run.run_id for run in run_records}
    csv_run_ids = {str(row.get("run_id") or "") for row in rows}
    if (
        publication.get("analysis_plan_digest") != plan.digest
        or publication.get("track_id") != plan.track_id
        or publication.get("publication_tier") != plan.publication_tier
        or publication.get("leaderboard_merge_group") != track.merge_group
        or publication.get("svg_contract") != svg_contract()
        or statistics.get("analysis_plan_digest") != plan.digest
        or not isinstance(statistics.get("leaderboard_contract"), Mapping)
        or statistics["leaderboard_contract"].get("track_id") != plan.track_id
        or len(rows) != len(plan.system_ids) * len(plan.scenario_ids) * plan.repetitions
        or len(run_records) != len(expected_schedule)
        or len(run_ids) != len(run_records)
        or observed_schedule != expected_schedule
        or csv_run_ids != run_ids
        or any(row.get("analysis_plan_digest") != plan.digest for row in rows)
        or any(row.get("track_id") != plan.track_id for row in rows)
        or (
            not _campaign_context_matches_plan(
                context_payload,
                plan,
                cast(Sequence[BenchmarkRunV3], run_records),
            )
        )
    ):
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    if (root / "runs.csv").read_text(encoding="utf-8") != render_runs_csv(
        plan,
        cast(Sequence[BenchmarkRunV3], run_records),
    ):
        raise BenchmarkV3SchemaError("v3_publication_runs_csv_mismatch")
    variants = _fixture_variants(context_payload)
    ledger_locations = _verify_streamed_ledgers(
        root,
        ledger_names,
        run_records,
        publication_version=publication_version,
        variants=variants,
    )
    recomputed_statistics = analyze_runs(
        plan,
        cast(Sequence[BenchmarkRunV3], run_records),
    )
    if statistics != recomputed_statistics:
        raise BenchmarkV3SchemaError("v3_publication_statistics_mismatch")
    if (root / "comparison.svg").read_text(encoding="utf-8") != render_statistics_svg(plan, recomputed_statistics):
        raise BenchmarkV3SchemaError("v3_publication_visualization_mismatch")
    return _VerifiedBundle(
        result={
            "analysis_plan_digest": plan.digest,
            "files": len(expected),
            "runs": len(rows),
            "track_id": plan.track_id,
        },
        publication=publication,
        run_locations=run_locations,
        ledger_locations=ledger_locations,
    )


def _validated_publication_artifacts(
    publication: Mapping[str, Any],
    artifacts: Mapping[str, Any],
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    static_artifacts = {
        "analysis_plan": "analysis-plan.json",
        "campaign_context": "campaign-context.json",
        "runs": "runs.csv",
        "statistics": "statistics.json",
        "visualization": "comparison.svg",
    }
    required_keys = {*static_artifacts, "controller_ledgers", "run_records"}
    if set(artifacts) != required_keys or any(artifacts.get(key) != value for key, value in static_artifacts.items()):
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    version = publication.get("schema_version")
    if not isinstance(version, str):
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    if version == _LEGACY_PUBLICATION_SCHEMA_VERSION:
        if artifacts.get("run_records") != "runs.jsonl" or artifacts.get("controller_ledgers") != "ledgers.jsonl":
            raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
        return version, ("runs.jsonl",), ("ledgers.jsonl",)
    if version != PUBLICATION_SCHEMA_VERSION:
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    return (
        version,
        _validated_shard_names(artifacts.get("run_records"), prefix="runs"),
        _validated_shard_names(
            artifacts.get("controller_ledgers"),
            prefix="ledgers",
        ),
    )


def _validated_shard_names(value: Any, *, prefix: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    names = tuple(value)
    if not names or any(not isinstance(item, str) for item in names):
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    expected = tuple(f"{prefix}-{index:04d}.jsonl" for index in range(len(names)))
    if names != expected:
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    return names


def _validate_jsonl_shard_sizes(root: Path, names: Sequence[str]) -> None:
    aggregate_bytes = 0
    try:
        for name in names:
            size = (root / name).stat().st_size
            if size <= 0 or size > _MAX_JSONL_SHARD_BYTES:
                raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
            aggregate_bytes += size
    except OSError as exc:
        raise BenchmarkV3SchemaError("invalid_v3_publication_payload") from exc
    if aggregate_bytes > _MAX_JSONL_ARTIFACT_BYTES:
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")


def _iter_jsonl_records(
    root: Path,
    names: Sequence[str],
) -> Iterator[_JsonlRecord]:
    for name in names:
        path = root / name
        record_count = 0
        try:
            with path.open("rb") as handle:
                while True:
                    offset = handle.tell()
                    raw_line = handle.readline()
                    if not raw_line:
                        break
                    try:
                        payload = json.loads(raw_line.decode("utf-8"))
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl") from exc
                    if not isinstance(payload, Mapping):
                        raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl")
                    record_count += 1
                    yield _JsonlRecord(
                        path=path,
                        offset=offset,
                        raw_line=raw_line,
                        payload=payload,
                    )
        except OSError as exc:
            raise BenchmarkV3SchemaError("invalid_v3_publication_payload") from exc
        if not record_count:
            raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl")


def _canonical_jsonl_line(payload: Mapping[str, Any]) -> bytes:
    try:
        return (canonical_json(payload) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl") from exc


def _validate_canonical_shard_record(
    record: _JsonlRecord,
    canonical_line: bytes,
    *,
    first_in_shard: bool,
    previous_shard_bytes: int | None,
    mismatch_error: str,
) -> None:
    if record.raw_line != canonical_line:
        raise BenchmarkV3SchemaError(mismatch_error)
    if (
        first_in_shard
        and previous_shard_bytes is not None
        and previous_shard_bytes + len(canonical_line) <= _MAX_JSONL_SHARD_BYTES
    ):
        raise BenchmarkV3SchemaError(mismatch_error)


def _load_run_projections(
    root: Path,
    names: Sequence[str],
    *,
    publication_version: str,
) -> tuple[tuple[_RunProjection, ...], tuple[_JsonlLocation, ...]]:
    runs: list[_RunProjection] = []
    locations: list[_JsonlLocation] = []
    previous_shard_bytes: int | None = None
    previous_sort_key: tuple[str, str, int, int, str] | None = None
    for name in names:
        shard_bytes = 0
        first_in_shard = True
        for record in _iter_jsonl_records(root, (name,)):
            canonical_line = _canonical_jsonl_line(record.payload)
            _validate_canonical_shard_record(
                record,
                canonical_line,
                first_in_shard=first_in_shard,
                previous_shard_bytes=(
                    previous_shard_bytes if publication_version == PUBLICATION_SCHEMA_VERSION else None
                ),
                mismatch_error="v3_publication_run_records_mismatch",
            )
            run = _validated_run_projection(record.payload)
            sort_key = (
                run.system_id,
                run.scenario_id,
                run.repetition,
                run.matched_fixture_seed,
                run.run_id,
            )
            if previous_sort_key is not None and sort_key <= previous_sort_key:
                raise BenchmarkV3SchemaError("v3_publication_run_records_mismatch")
            previous_sort_key = sort_key
            runs.append(run)
            locations.append(
                _JsonlLocation(
                    path=record.path,
                    offset=record.offset,
                    length=len(record.raw_line),
                    sort_key=sort_key,
                )
            )
            shard_bytes += len(record.raw_line)
            first_in_shard = False
        previous_shard_bytes = shard_bytes
    return tuple(runs), tuple(locations)


def _validated_run_projection(payload: Mapping[str, Any]) -> _RunProjection:
    raw_actions = payload.get("action_telemetry")
    if not isinstance(raw_actions, Sequence) or isinstance(raw_actions, (str, bytes, bytearray)):
        raise BenchmarkV3SchemaError("invalid:run_telemetry")
    slim_payload = dict(payload)
    slim_payload["action_telemetry"] = []
    run = BenchmarkRunV3.from_dict(slim_payload)
    if canonical_json(run.to_dict()) != canonical_json(slim_payload):
        raise BenchmarkV3SchemaError("v3_publication_run_records_mismatch")
    action_event_count, action_projection_digest = _validated_action_projection(raw_actions)
    return _RunProjection(
        run_id=run.run_id,
        track_id=run.track_id,
        system_id=run.system_id,
        scenario_id=run.scenario_id,
        repetition=run.repetition,
        execution_status=run.execution_status,
        evaluation=run.evaluation,
        matched_fixture_seed=run.matched_fixture_seed,
        fixture_variant_digest=run.fixture_variant_digest,
        applied_model_seed=run.applied_model_seed,
        model_seed_status=run.model_seed_status,
        budget_enforcement=run.budget_enforcement,
        action_event_count=action_event_count,
        action_projection_digest=action_projection_digest,
        action_telemetry_available=run.action_telemetry_available,
        action_telemetry_reliability=run.action_telemetry_reliability,
        duration_seconds=run.duration_seconds,
        duration_censored=run.duration_censored,
        censor_limit_seconds=run.censor_limit_seconds,
        policy_violations=run.policy_violations,
        artifact_refs=run.artifact_refs,
        environment=run.environment,
        schema_version=run.schema_version,
    )


def _validated_action_projection(
    raw_actions: Sequence[Any],
) -> tuple[int, str]:
    digest = hashlib.sha256()
    previous_sequence: int | None = None
    sequences: set[int] = set()
    event_ids: set[str] = set()
    for raw_action in raw_actions:
        if not isinstance(raw_action, Mapping):
            raise BenchmarkV3SchemaError("invalid:action_telemetry")
        action = ActionEvent.from_dict(raw_action)
        if canonical_json(action.to_dict()) != canonical_json(raw_action):
            raise BenchmarkV3SchemaError("v3_publication_run_records_mismatch")
        if previous_sequence is not None and action.sequence < previous_sequence:
            raise BenchmarkV3SchemaError("action_telemetry_not_ordered")
        if action.sequence in sequences:
            raise BenchmarkV3SchemaError("duplicate_action_sequence")
        if action.event_id in event_ids:
            raise BenchmarkV3SchemaError("duplicate_action_event_id")
        previous_sequence = action.sequence
        sequences.add(action.sequence)
        event_ids.add(action.event_id)
        _update_action_projection_digest(
            digest,
            event_id=action.event_id,
            sequence=action.sequence,
            action_name=action.action_name,
            action_type=action.action_type,
            status=action.status,
            method=action.method,
            target_class=action.target_class,
            evidence_refs=action.evidence_refs,
        )
    return len(raw_actions), digest.hexdigest()


def _update_action_projection_digest(
    digest: Any,
    *,
    event_id: str,
    sequence: int,
    action_name: str,
    action_type: str,
    status: str,
    method: str,
    target_class: str,
    evidence_refs: Sequence[str],
) -> None:
    digest.update(
        (
            canonical_json(
                {
                    "action_name": action_name,
                    "action_type": action_type,
                    "event_id": event_id,
                    "evidence_refs": list(evidence_refs),
                    "method": method,
                    "sequence": sequence,
                    "status": status,
                    "target_class": target_class,
                }
            )
            + "\n"
        ).encode("utf-8")
    )


def _fixture_variants(
    context: Mapping[str, Any],
) -> dict[tuple[str, int], FixtureVariant]:
    reveals = context.get("fixture_reveals")
    if not isinstance(reveals, Sequence) or isinstance(reveals, (str, bytes, bytearray)):
        raise BenchmarkV3SchemaError("v3_publication_fixture_reveals_missing")
    variants: dict[tuple[str, int], FixtureVariant] = {}
    for reveal in reveals:
        if not isinstance(reveal, Mapping):
            raise BenchmarkV3SchemaError("invalid_v3_fixture_reveal")
        variant = FixtureVariant.from_private_dict(reveal)
        key = (variant.scenario_id, variant.matched_fixture_seed)
        if key in variants:
            raise BenchmarkV3SchemaError("duplicate_v3_fixture_reveal")
        variants[key] = variant
    return variants


def _verify_streamed_ledgers(
    root: Path,
    names: Sequence[str],
    runs: Sequence[_RunProjection],
    *,
    publication_version: str,
    variants: Mapping[tuple[str, int], FixtureVariant],
) -> tuple[_JsonlLocation, ...]:
    runs_by_id = {run.run_id: run for run in runs}
    seen_run_ids: set[str] = set()
    locations: list[_JsonlLocation] = []
    previous_run_id: str | None = None
    previous_shard_bytes: int | None = None
    for name in names:
        shard_bytes = 0
        first_in_shard = True
        for record in _iter_jsonl_records(root, (name,)):
            if publication_version == PUBLICATION_SCHEMA_VERSION:
                canonical_line = _canonical_jsonl_line(record.payload)
                _validate_canonical_shard_record(
                    record,
                    canonical_line,
                    first_in_shard=first_in_shard,
                    previous_shard_bytes=previous_shard_bytes,
                    mismatch_error="v3_publication_controller_ledgers_mismatch",
                )
            run_id = str(record.payload.get("run_id") or "")
            if (
                publication_version == PUBLICATION_SCHEMA_VERSION
                and previous_run_id is not None
                and run_id <= previous_run_id
            ):
                raise BenchmarkV3SchemaError("v3_publication_controller_ledgers_mismatch")
            if run_id in seen_run_ids or run_id not in runs_by_id:
                raise BenchmarkV3SchemaError("v3_public_ledger_run_set_mismatch")
            run = runs_by_id[run_id]
            _verify_streamed_ledger_record(
                record.payload,
                run,
                variants=variants,
            )
            seen_run_ids.add(run_id)
            previous_run_id = run_id
            locations.append(
                _JsonlLocation(
                    path=record.path,
                    offset=record.offset,
                    length=len(record.raw_line),
                    sort_key=(run_id,),
                )
            )
            shard_bytes += len(record.raw_line)
            first_in_shard = False
        previous_shard_bytes = shard_bytes
    if seen_run_ids != set(runs_by_id):
        raise BenchmarkV3SchemaError("v3_public_ledger_run_set_mismatch")
    return tuple(locations)


def _verify_streamed_ledger_record(
    record: Mapping[str, Any],
    run: _RunProjection,
    *,
    variants: Mapping[tuple[str, int], FixtureVariant],
) -> None:
    if (
        record.get("schema_version") != "1.0"
        or record.get("system_id") != run.system_id
        or record.get("scenario_id") != run.scenario_id
        or record.get("repetition") != run.repetition
        or record.get("matched_fixture_seed") != run.matched_fixture_seed
        or record.get("fixture_variant_digest") != run.fixture_variant_digest
    ):
        raise BenchmarkV3SchemaError("v3_public_ledger_run_mismatch")
    raw_entries = record.get("entries")
    if not isinstance(raw_entries, Sequence) or isinstance(raw_entries, (str, bytes, bytearray)):
        raise BenchmarkV3SchemaError("invalid_v3_public_ledger_entries")
    action_digest = hashlib.sha256()
    observed_evidence_ids: set[str] = set()
    root_digest = "0" * 64
    entry_count = 0
    for entry in iter_verified_ledger_entries(
        raw_entries,
        variant_digest=run.fixture_variant_digest,
    ):
        entry_count += 1
        root_digest = entry.entry_digest
        observed_evidence_ids.update(entry.evidence_ids)
        _update_action_projection_digest(
            action_digest,
            event_id=f"ledger-event-{entry.sequence}",
            sequence=entry.sequence - 1,
            action_name="fixture-http-request",
            action_type="http",
            status=_ledger_action_status(entry.status),
            method=entry.method,
            target_class="fixture-route",
            evidence_refs=entry.evidence_ids,
        )
    try:
        declared_entry_count = int(run.environment.get("controller_ledger_entries", -1))
    except (TypeError, ValueError):
        declared_entry_count = -1
    if (
        record.get("ledger_root_digest") != root_digest
        or f"sha256:{root_digest}" not in run.artifact_refs
        or declared_entry_count != entry_count
        or not run.action_telemetry_available
        or run.action_telemetry_reliability != "verified"
        or entry_count != run.action_event_count
    ):
        raise BenchmarkV3SchemaError("v3_public_ledger_run_mismatch")
    if action_digest.hexdigest() != run.action_projection_digest:
        raise BenchmarkV3SchemaError("v3_public_ledger_telemetry_mismatch")
    _verify_projection_evaluation(
        run,
        variants=variants,
        observed_evidence_ids=tuple(sorted(observed_evidence_ids)),
    )


def _verify_projection_evaluation(
    run: _RunProjection,
    *,
    variants: Mapping[tuple[str, int], FixtureVariant],
    observed_evidence_ids: Sequence[str],
) -> None:
    variant = variants.get((run.scenario_id, run.matched_fixture_seed))
    if variant is None:
        raise BenchmarkV3SchemaError("v3_evaluation_audit_material_missing")
    evidence_by_alias = {
        " ".join(alias.casefold().split()): truth.required_evidence_ids
        for truth in variant.truth_claims
        for alias in truth.aliases
        if alias.startswith("OCTOBENCH_V3_")
    }
    reported_claims: list[ReportedClaim] = []
    for claim in run.evaluation.claims:
        expected_refs = evidence_by_alias.get(
            " ".join(claim.text.casefold().split()),
            (),
        )
        if claim.evidence_refs != expected_refs:
            raise BenchmarkV3SchemaError("v3_claim_evidence_projection_mismatch")
        reported_claims.append(
            ReportedClaim(
                text=claim.text,
                evidence_refs=expected_refs,
            )
        )
    recomputed = evaluate_claims(
        execution_status=run.execution_status,
        reported_claims=reported_claims,
        truth_claims=variant.truth_claims,
        completion_rule=variant.completion_rule,
        observed_evidence_ids=observed_evidence_ids,
        verified_truth_ids=verified_truth_ids_from_evidence(
            variant.truth_claims,
            observed_evidence_ids,
        ),
        policy_violations=run.policy_violations,
    )
    if recomputed.to_dict() != run.evaluation.to_dict():
        raise BenchmarkV3SchemaError("v3_run_evaluation_mismatch")


def _write_repacked_jsonl_shards(
    locations: Sequence[_JsonlLocation],
    directory: Path,
    *,
    prefix: str,
) -> tuple[str, ...]:
    if not locations:
        raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl")
    names: list[str] = []
    handle: Any = None
    shard_bytes = 0
    aggregate_bytes = 0
    try:
        for location in sorted(locations, key=lambda item: item.sort_key):
            try:
                with location.path.open("rb") as source:
                    source.seek(location.offset)
                    raw_line = source.read(location.length)
            except OSError as exc:
                raise BenchmarkV3SchemaError("invalid_v3_publication_payload") from exc
            if len(raw_line) != location.length:
                raise BenchmarkV3SchemaError("invalid_v3_publication_payload")
            try:
                payload = json.loads(raw_line.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl") from exc
            if not isinstance(payload, Mapping):
                raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl")
            canonical_line = _canonical_jsonl_line(payload)
            line_bytes = len(canonical_line)
            if line_bytes > _MAX_JSONL_SHARD_BYTES:
                raise BenchmarkV3SchemaError("v3_publication_jsonl_record_too_large")
            aggregate_bytes += line_bytes
            if aggregate_bytes > _MAX_JSONL_ARTIFACT_BYTES:
                raise BenchmarkV3SchemaError("v3_publication_jsonl_too_large")
            if handle is None or shard_bytes + line_bytes > _MAX_JSONL_SHARD_BYTES:
                if handle is not None:
                    handle.close()
                name = f"{prefix}-{len(names):04d}.jsonl"
                handle = (directory / name).open("wb")
                names.append(name)
                shard_bytes = 0
            handle.write(canonical_line)
            shard_bytes += line_bytes
    except Exception:
        if handle is not None:
            handle.close()
        raise
    if handle is not None:
        handle.close()
    return tuple(names)


def _validated_campaign_context(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkV3SchemaError("invalid_v3_campaign_context")
    try:
        encoded = canonical_json(value)
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BenchmarkV3SchemaError("invalid_v3_campaign_context") from exc
    if not isinstance(decoded, dict) or len(encoded.encode("utf-8")) > 8_000_000:
        raise BenchmarkV3SchemaError("invalid_v3_campaign_context")
    return decoded


def _write_jsonl_shards(
    directory: Path,
    *,
    prefix: str,
    records: Iterable[Mapping[str, Any]],
) -> tuple[str, ...]:
    names: list[str] = []
    for name, payload in _iter_jsonl_shards(prefix=prefix, records=records):
        (directory / name).write_bytes(payload.encode("utf-8"))
        names.append(name)
    return tuple(names)


def _iter_jsonl_shards(
    *,
    prefix: str,
    records: Iterable[Mapping[str, Any]],
) -> Iterator[tuple[str, str]]:
    lines: list[str] = []
    shard_bytes = 0
    aggregate_bytes = 0
    shard_index = 0
    record_count = 0
    for record in records:
        try:
            line = canonical_json(record) + "\n"
        except (TypeError, ValueError) as exc:
            raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl") from exc
        encoded_bytes = len(line.encode("utf-8"))
        if encoded_bytes > _MAX_JSONL_SHARD_BYTES:
            raise BenchmarkV3SchemaError("v3_publication_jsonl_record_too_large")
        aggregate_bytes += encoded_bytes
        if aggregate_bytes > _MAX_JSONL_ARTIFACT_BYTES:
            raise BenchmarkV3SchemaError("v3_publication_jsonl_too_large")
        if lines and shard_bytes + encoded_bytes > _MAX_JSONL_SHARD_BYTES:
            yield f"{prefix}-{shard_index:04d}.jsonl", "".join(lines)
            shard_index += 1
            lines = []
            shard_bytes = 0
        lines.append(line)
        shard_bytes += encoded_bytes
        record_count += 1
    if not record_count:
        raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl")
    yield f"{prefix}-{shard_index:04d}.jsonl", "".join(lines)


def _validated_controller_ledgers(
    value: Sequence[Mapping[str, Any]],
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise BenchmarkV3SchemaError("invalid_v3_controller_ledgers")
    records: list[Mapping[str, Any]] = []
    encoded_bytes = 0
    for item in value:
        if not isinstance(item, Mapping):
            raise BenchmarkV3SchemaError("invalid_v3_controller_ledgers")
        try:
            encoded = canonical_json(item)
        except (TypeError, ValueError) as exc:
            raise BenchmarkV3SchemaError("invalid_v3_controller_ledgers") from exc
        encoded_bytes += len(encoded.encode("utf-8")) + 1
        records.append(item)
    if encoded_bytes > _MAX_JSONL_ARTIFACT_BYTES:
        raise BenchmarkV3SchemaError("v3_controller_ledgers_too_large")
    return tuple(sorted(records, key=lambda item: str(item.get("run_id") or "")))


def _ledger_action_status(status: int) -> str:
    if status in {408, 504}:
        return "timeout"
    if 200 <= status < 400:
        return "succeeded"
    if status in {401, 403, 405}:
        return "blocked"
    return "failed"


def _campaign_context_matches_plan(
    context: Mapping[str, Any],
    plan: AnalysisPlan,
    runs: Sequence[BenchmarkRunV3],
) -> bool:
    campaign = context.get("campaign")
    benchmark_v3 = campaign.get("benchmark_v3") if isinstance(campaign, Mapping) else None
    reveals = context.get("fixture_reveals")
    expected_fixture_keys = {
        (scenario_id, seed) for scenario_id in plan.scenario_ids for seed in plan.fixture_seeds[scenario_id]
    }
    observed_fixture_keys: set[tuple[str, int]] = set()
    reveal_digests: dict[tuple[str, int], str] = {}
    if isinstance(reveals, Sequence) and not isinstance(
        reveals,
        (str, bytes, bytearray),
    ):
        for reveal in reveals:
            if not isinstance(reveal, Mapping):
                return False
            scenario = reveal.get("scenario")
            generator = reveal.get("generator")
            reveal_contract = reveal.get("reveal")
            if (
                not isinstance(scenario, Mapping)
                or not isinstance(generator, Mapping)
                or not isinstance(reveal_contract, Mapping)
                or reveal_contract.get("campaign_closed") is not True
                or reveal_contract.get("reproducible") is not True
                or reveal_contract.get("generator_digest") != stable_digest(generator)
                or not reveal.get("variant_digest")
            ):
                return False
            try:
                variant = FixtureVariant.from_private_dict(reveal)
                matched_seed = generator.get("matched_fixture_seed")
                if matched_seed is None:
                    return False
                key = (
                    str(scenario.get("scenario_id") or ""),
                    int(matched_seed),
                )
                if key in reveal_digests or variant.scenario_id != key[0] or variant.matched_fixture_seed != key[1]:
                    return False
                observed_fixture_keys.add(key)
                reveal_digests[key] = variant.variant_digest
            except (BenchmarkV3SchemaError, TypeError, ValueError):
                return False
    if not isinstance(reveals, Sequence) or isinstance(
        reveals,
        (str, bytes, bytearray),
    ):
        return False
    return (
        context.get("schema_version") == "1.0"
        and isinstance(benchmark_v3, Mapping)
        and benchmark_v3.get("analysis_plan_digest") == plan.digest
        and benchmark_v3.get("track_id") == plan.track_id
        and observed_fixture_keys == expected_fixture_keys
        and len(observed_fixture_keys) == len(reveals)
        and all(
            reveal_digests.get((run.scenario_id, run.matched_fixture_seed)) == run.fixture_variant_digest
            for run in runs
        )
    )


def _render_outcome_panel(
    systems: Mapping[str, Any],
    system_ids: Sequence[str],
    colors: Sequence[str],
    y: int,
    field: str,
    plan: AnalysisPlan,
) -> list[str]:
    fragments: list[str] = []
    for index, system_id in enumerate(system_ids):
        overall = _overall(systems, system_id)
        outcome = overall.get(field)
        if not isinstance(outcome, Mapping):
            raise BenchmarkV3SchemaError("invalid_statistics_outcome")
        counts = outcome.get("counts")
        if not isinstance(counts, Mapping):
            raise BenchmarkV3SchemaError("invalid_statistics_outcome_counts")
        total = max(1, sum(int(value) for value in counts.values()))
        row_y = y + 27 + index * 40
        fragments.append(f'<text class="label" x="48" y="{row_y + 13}">{html.escape(system_id)}</text>')
        x = 260.0
        for status_index, (status, count_raw) in enumerate(sorted(counts.items())):
            count = int(count_raw)
            segment = 780.0 * count / total
            fragments.append(
                f'<rect x="{x:.2f}" y="{row_y}" width="{segment:.2f}" height="20" fill="{colors[status_index % len(colors)]}"><title>{html.escape(str(status))}: {count}/{total}</title></rect>'
            )
            x += segment
        fragments.append(f'<text class="small" x="1055" y="{row_y + 14}">n={total}</text>')
    return fragments


def _render_recall_panel(
    systems: Mapping[str, Any],
    system_ids: Sequence[str],
    colors: Sequence[str],
    y: int,
    field: str,
    plan: AnalysisPlan,
) -> list[str]:
    fragments = _grid(y, unit="1.0")
    for index, system_id in enumerate(system_ids):
        overall = _overall(systems, system_id)
        metrics = overall.get("metrics")
        if not isinstance(metrics, Mapping):
            raise BenchmarkV3SchemaError("statistics_missing_verified_recall")
        all_scheduled = metrics.get("all_scheduled")
        if not isinstance(all_scheduled, Mapping):
            raise BenchmarkV3SchemaError("statistics_missing_verified_recall")
        verified_recall = all_scheduled.get("verified_recall")
        if not isinstance(verified_recall, Mapping):
            raise BenchmarkV3SchemaError("statistics_missing_verified_recall")
        wilson = verified_recall.get("wilson")
        if not isinstance(wilson, Mapping):
            raise BenchmarkV3SchemaError("statistics_missing_verified_recall")
        estimate = wilson.get("estimate")
        lower = wilson.get("lower")
        upper = wilson.get("upper")
        if estimate is not None and (lower is None or upper is None):
            raise BenchmarkV3SchemaError("statistics_missing_verified_recall")
        row_y = y + 27 + index * 40
        fragments.append(f'<text class="label" x="48" y="{row_y + 13}">{html.escape(system_id)}</text>')
        if estimate is None:
            fragments.append(f'<text class="small" x="260" y="{row_y + 13}">unavailable</text>')
            continue
        if lower is None or upper is None:
            raise BenchmarkV3SchemaError("statistics_missing_verified_recall")
        bar_width = 780.0 * float(estimate)
        lower_x = 260.0 + 780.0 * float(lower)
        upper_x = 260.0 + 780.0 * float(upper)
        fragments.extend(
            [
                f'<rect x="260" y="{row_y}" width="{bar_width:.2f}" height="20" fill="{colors[index % len(colors)]}" opacity="0.8"/>',
                f'<line x1="{lower_x:.2f}" y1="{row_y + 10}" x2="{upper_x:.2f}" y2="{row_y + 10}" stroke="#111827" stroke-width="2"/>',
                f'<line x1="{lower_x:.2f}" y1="{row_y + 5}" x2="{lower_x:.2f}" y2="{row_y + 15}" stroke="#111827"/>',
                f'<line x1="{upper_x:.2f}" y1="{row_y + 5}" x2="{upper_x:.2f}" y2="{row_y + 15}" stroke="#111827"/>',
                f'<text class="small" x="1055" y="{row_y + 14}">{float(estimate):.3f}</text>',
            ]
        )
    return fragments


def _render_duration_panel(
    systems: Mapping[str, Any],
    system_ids: Sequence[str],
    colors: Sequence[str],
    y: int,
    field: str,
    plan: AnalysisPlan,
) -> list[str]:
    horizon = max(plan.deadlines_seconds)
    fragments = _grid(y, unit=f"{horizon:g}s")
    for index, system_id in enumerate(system_ids):
        overall = _overall(systems, system_id)
        duration = overall.get("duration")
        if not isinstance(duration, Mapping) or not duration.get("available"):
            raise BenchmarkV3SchemaError("statistics_missing_duration")
        rmst = float(duration.get("restricted_mean_completion_seconds") or 0.0)
        median = duration.get("median_completion_seconds")
        events = int(duration.get("completion_events") or 0)
        sample_size = int(duration.get("sample_size") or 0)
        row_y = y + 27 + index * 40
        fragments.extend(
            [
                f'<text class="label" x="48" y="{row_y + 13}">{html.escape(system_id)}</text>',
                f'<rect x="260" y="{row_y}" width="{780.0 * min(1.0, rmst / horizon):.2f}" height="20" fill="{colors[index % len(colors)]}" opacity="0.8"><title>Restricted mean completion time: {rmst:.3f}s</title></rect>',
                f'<text class="small" x="1055" y="{row_y + 14}">median={html.escape(str(median) if median is not None else "not reached")}; events={events}/{sample_size}</text>',
            ]
        )
    return fragments


def _grid(y: int, *, unit: str) -> list[str]:
    fragments: list[str] = []
    for index in range(5):
        x = 260 + index * 195
        fragments.append(f'<line class="grid" x1="{x}" y1="{y + 20}" x2="{x}" y2="{y + 155}"/>')
        fragments.append(
            f'<text class="small" x="{x}" y="{y + 172}">{index / 4:.2f}{" x " + unit if index == 4 else ""}</text>'
        )
    return fragments


def _overall(systems: Mapping[str, Any], system_id: str) -> Mapping[str, Any]:
    system = systems.get(system_id)
    if not isinstance(system, Mapping):
        raise BenchmarkV3SchemaError("invalid_statistics_system")
    overall = system.get("overall")
    if not isinstance(overall, Mapping):
        raise BenchmarkV3SchemaError("invalid_statistics_overall")
    return overall


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bool(value: bool) -> str:
    return "true" if value else "false"


def _empty(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, float):
        return _float(value)
    return value


def _float(value: float) -> str:
    return format(float(value), ".9g")


def _run_sort_key(run: BenchmarkRunV3) -> tuple[str, str, int, int, str]:
    return (
        run.system_id,
        run.scenario_id,
        run.repetition,
        run.matched_fixture_seed,
        run.run_id,
    )
