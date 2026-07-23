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
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .analysis import AnalysisPlan, analyze_runs, freeze_analysis_plan, load_analysis_plan
from .evaluation import ReportedClaim, evaluate_claims, verified_truth_ids_from_evidence
from .fixture import FixtureVariant
from .ledger import verify_ledger_entries
from .schema import BenchmarkRunV3, BenchmarkV3SchemaError, canonical_json, stable_digest
from .tracks import validate_single_track

RUNS_CSV_SCHEMA_VERSION = "1.0"
PUBLICATION_SCHEMA_VERSION = "1.0"
SVG_PANEL_IDS = (
    "execution-outcomes",
    "task-outcomes",
    "verified-recall",
    "censored-completion-time",
)


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
            "action_event_count": len(run.action_telemetry),
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

    return "".join(
        canonical_json(run.to_dict()) + "\n"
        for run in sorted(runs, key=_run_sort_key)
    )


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
        (temporary / "runs.jsonl").write_text(
            render_run_records(items),
            encoding="utf-8",
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
        (temporary / "ledgers.jsonl").write_text(
            "".join(canonical_json(item) + "\n" for item in ledger_payload),
            encoding="utf-8",
        )
        manifest = {
            "analysis_plan_digest": plan.digest,
            "artifacts": {
                "analysis_plan": "analysis-plan.json",
                "runs": "runs.csv",
                "run_records": "runs.jsonl",
                "statistics": "statistics.json",
                "visualization": "comparison.svg",
                "campaign_context": "campaign-context.json",
                "controller_ledgers": "ledgers.jsonl",
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


def verify_v3_results(directory: str | Path) -> dict[str, Any]:
    """Verify checksums and the self-identifying v3 publication contract."""

    root = Path(directory).resolve()
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
    actual_files = {
        path.name
        for path in root.iterdir()
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if actual_files != set(expected):
        raise BenchmarkV3SchemaError("v3_publication_file_set_mismatch")
    for name, digest in expected.items():
        if _sha256(root / name) != digest:
            raise BenchmarkV3SchemaError("v3_publication_checksum_mismatch")

    plan = load_analysis_plan(root / "analysis-plan.json")
    try:
        publication = json.loads((root / "publication.json").read_text(encoding="utf-8"))
        statistics = json.loads((root / "statistics.json").read_text(encoding="utf-8"))
        run_records = _load_run_records(root / "runs.jsonl")
        with (root / "runs.csv").open("r", encoding="utf-8", newline="") as handle:
            rows = tuple(csv.DictReader(handle))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkV3SchemaError("invalid_v3_publication_payload") from exc
    artifacts = publication.get("artifacts") if isinstance(publication, Mapping) else None
    required_artifacts = {
        "analysis_plan": "analysis-plan.json",
        "campaign_context": "campaign-context.json",
        "controller_ledgers": "ledgers.jsonl",
        "runs": "runs.csv",
        "run_records": "runs.jsonl",
        "statistics": "statistics.json",
        "visualization": "comparison.svg",
    }
    context_name = (
        artifacts.get("campaign_context") if isinstance(artifacts, Mapping) else None
    )
    context_payload: Mapping[str, Any] | None = None
    if context_name is not None:
        if context_name != "campaign-context.json":
            raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
        try:
            loaded_context = json.loads(
                (root / context_name).read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BenchmarkV3SchemaError("invalid_v3_publication_payload") from exc
        if not isinstance(loaded_context, Mapping):
            raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
        context_payload = loaded_context
    ledgers_name = (
        artifacts.get("controller_ledgers")
        if isinstance(artifacts, Mapping)
        else None
    )
    ledger_records: tuple[Mapping[str, Any], ...] | None = None
    if ledgers_name is not None:
        if ledgers_name != "ledgers.jsonl":
            raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
        ledger_records = _load_jsonl_mappings(root / ledgers_name)
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
    track = validate_single_track(run_records)
    run_ids = {run.run_id for run in run_records}
    csv_run_ids = {str(row.get("run_id") or "") for row in rows}
    if (
        not isinstance(publication, Mapping)
        or not isinstance(statistics, Mapping)
        or not isinstance(artifacts, Mapping)
        or any(artifacts.get(key) != value for key, value in required_artifacts.items())
        or set(artifacts)
        - {*required_artifacts, "campaign_context", "controller_ledgers"}
        or publication.get("schema_version") != PUBLICATION_SCHEMA_VERSION
        or publication.get("analysis_plan_digest") != plan.digest
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
            context_payload is not None
            and not _campaign_context_matches_plan(
                context_payload,
                plan,
                run_records,
            )
        )
    ):
        raise BenchmarkV3SchemaError("v3_publication_contract_mismatch")
    if (root / "runs.csv").read_text(encoding="utf-8") != render_runs_csv(
        plan,
        run_records,
    ):
        raise BenchmarkV3SchemaError("v3_publication_runs_csv_mismatch")
    if (root / "runs.jsonl").read_text(encoding="utf-8") != render_run_records(
        run_records
    ):
        raise BenchmarkV3SchemaError("v3_publication_run_records_mismatch")
    recomputed_statistics = analyze_runs(plan, run_records)
    if statistics != recomputed_statistics:
        raise BenchmarkV3SchemaError("v3_publication_statistics_mismatch")
    if (root / "comparison.svg").read_text(
        encoding="utf-8"
    ) != render_statistics_svg(plan, recomputed_statistics):
        raise BenchmarkV3SchemaError("v3_publication_visualization_mismatch")
    if context_payload is None or ledger_records is None:
        raise BenchmarkV3SchemaError("v3_publication_audit_evidence_missing")
    _verify_controller_ledgers(ledger_records, run_records)
    _verify_recomputed_evaluations(
        context_payload,
        ledger_records,
        run_records,
    )
    return {
        "analysis_plan_digest": plan.digest,
        "files": len(expected),
        "runs": len(rows),
        "track_id": plan.track_id,
    }


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


def _validated_controller_ledgers(
    value: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise BenchmarkV3SchemaError("invalid_v3_controller_ledgers")
    records: list[dict[str, Any]] = []
    encoded_bytes = 0
    for item in value:
        if not isinstance(item, Mapping):
            raise BenchmarkV3SchemaError("invalid_v3_controller_ledgers")
        try:
            encoded = canonical_json(item)
            decoded = json.loads(encoded)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BenchmarkV3SchemaError("invalid_v3_controller_ledgers") from exc
        if not isinstance(decoded, dict):
            raise BenchmarkV3SchemaError("invalid_v3_controller_ledgers")
        encoded_bytes += len(encoded.encode("utf-8")) + 1
        records.append(decoded)
    if encoded_bytes > 64_000_000:
        raise BenchmarkV3SchemaError("v3_controller_ledgers_too_large")
    return tuple(sorted(records, key=lambda item: str(item.get("run_id") or "")))


def _load_jsonl_mappings(path: Path) -> tuple[Mapping[str, Any], ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise BenchmarkV3SchemaError("invalid_v3_publication_payload") from exc
    if not lines or any(not line for line in lines):
        raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl")
    records: list[Mapping[str, Any]] = []
    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl") from exc
        if not isinstance(payload, Mapping):
            raise BenchmarkV3SchemaError("invalid_v3_publication_jsonl")
        records.append(payload)
    return tuple(records)


def _load_run_records(path: Path) -> tuple[BenchmarkRunV3, ...]:
    return tuple(
        BenchmarkRunV3.from_dict(item) for item in _load_jsonl_mappings(path)
    )


def _verify_controller_ledgers(
    records: Sequence[Mapping[str, Any]],
    runs: Sequence[BenchmarkRunV3],
) -> None:
    runs_by_id = {run.run_id: run for run in runs}
    record_ids = [str(item.get("run_id") or "") for item in records]
    if len(record_ids) != len(set(record_ids)) or set(record_ids) != set(runs_by_id):
        raise BenchmarkV3SchemaError("v3_public_ledger_run_set_mismatch")
    for record in records:
        run = runs_by_id[str(record.get("run_id") or "")]
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
        if not isinstance(raw_entries, Sequence) or isinstance(
            raw_entries,
            (str, bytes, bytearray),
        ):
            raise BenchmarkV3SchemaError("invalid_v3_public_ledger_entries")
        entries = verify_ledger_entries(
            raw_entries,
            variant_digest=run.fixture_variant_digest,
        )
        root_digest = entries[-1].entry_digest if entries else "0" * 64
        try:
            declared_entry_count = int(
                run.environment.get("controller_ledger_entries", -1)
            )
        except (TypeError, ValueError):
            declared_entry_count = -1
        if (
            record.get("ledger_root_digest") != root_digest
            or f"sha256:{root_digest}" not in run.artifact_refs
            or declared_entry_count != len(entries)
            or not run.action_telemetry_available
            or run.action_telemetry_reliability != "verified"
            or len(entries) != len(run.action_telemetry)
        ):
            raise BenchmarkV3SchemaError("v3_public_ledger_run_mismatch")
        for entry, action in zip(entries, run.action_telemetry):
            if (
                action.event_id != f"ledger-event-{entry.sequence}"
                or action.sequence != entry.sequence - 1
                or action.action_name != "fixture-http-request"
                or action.action_type != "http"
                or action.status != _ledger_action_status(entry.status)
                or action.method != entry.method
                or action.target_class != "fixture-route"
                or action.evidence_refs != entry.evidence_ids
            ):
                raise BenchmarkV3SchemaError("v3_public_ledger_telemetry_mismatch")


def _verify_recomputed_evaluations(
    context: Mapping[str, Any],
    ledger_records: Sequence[Mapping[str, Any]],
    runs: Sequence[BenchmarkRunV3],
) -> None:
    reveals = context.get("fixture_reveals")
    if not isinstance(reveals, Sequence) or isinstance(
        reveals,
        (str, bytes, bytearray),
    ):
        raise BenchmarkV3SchemaError("v3_publication_fixture_reveals_missing")
    variants: dict[tuple[str, int], FixtureVariant] = {}
    for reveal in reveals:
        if not isinstance(reveal, Mapping):
            raise BenchmarkV3SchemaError("invalid_v3_fixture_reveal")
        revealed_variant = FixtureVariant.from_private_dict(reveal)
        key = (
            revealed_variant.scenario_id,
            revealed_variant.matched_fixture_seed,
        )
        if key in variants:
            raise BenchmarkV3SchemaError("duplicate_v3_fixture_reveal")
        variants[key] = revealed_variant
    ledgers_by_run = {
        str(record.get("run_id") or ""): record for record in ledger_records
    }
    for run in runs:
        run_variant = variants.get((run.scenario_id, run.matched_fixture_seed))
        ledger_record = ledgers_by_run.get(run.run_id)
        if run_variant is None or ledger_record is None:
            raise BenchmarkV3SchemaError("v3_evaluation_audit_material_missing")
        raw_entries = ledger_record.get("entries")
        if not isinstance(raw_entries, Sequence) or isinstance(
            raw_entries,
            (str, bytes, bytearray),
        ):
            raise BenchmarkV3SchemaError("invalid_v3_public_ledger_entries")
        entries = verify_ledger_entries(
            raw_entries,
            variant_digest=run_variant.variant_digest,
        )
        observed_evidence_ids = tuple(
            sorted({evidence for entry in entries for evidence in entry.evidence_ids})
        )
        evidence_by_alias = {
            " ".join(alias.casefold().split()): truth.required_evidence_ids
            for truth in run_variant.truth_claims
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
            truth_claims=run_variant.truth_claims,
            completion_rule=run_variant.completion_rule,
            observed_evidence_ids=observed_evidence_ids,
            verified_truth_ids=verified_truth_ids_from_evidence(
                run_variant.truth_claims,
                observed_evidence_ids,
            ),
            policy_violations=run.policy_violations,
        )
        if recomputed.to_dict() != run.evaluation.to_dict():
            raise BenchmarkV3SchemaError("v3_run_evaluation_mismatch")


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
        (scenario_id, seed)
        for scenario_id in plan.scenario_ids
        for seed in plan.fixture_seeds[scenario_id]
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
                or reveal_contract.get("generator_digest")
                != stable_digest(generator)
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
                if (
                    key in reveal_digests
                    or variant.scenario_id != key[0]
                    or variant.matched_fixture_seed != key[1]
                ):
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
            reveal_digests.get((run.scenario_id, run.matched_fixture_seed))
            == run.fixture_variant_digest
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
