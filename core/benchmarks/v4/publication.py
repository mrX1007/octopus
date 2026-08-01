"""Deterministic companion publication for Benchmark v4 efficiency evidence."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
import shutil
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from ..v3.analysis import AnalysisPlan, load_analysis_plan
from ..v3.publication import verify_v3_results
from ..v3.schema import BenchmarkRunV3, canonical_json, load_run
from .analysis import analyze_efficiency, extract_efficiency_runs
from .schema import (
    ALL_RESOURCES,
    BenchmarkV4SchemaError,
    EfficiencyPlan,
    EfficiencyRunProjection,
    freeze_efficiency_plan,
    load_efficiency_plan,
)

EFFICIENCY_CSV_SCHEMA_VERSION = "1.0"
SOURCE_ATTESTATION_SCHEMA_VERSION = "1.0"
EFFICIENCY_PUBLICATION_SCHEMA_VERSION = "1.0"
SVG_PANEL_IDS = (
    "quality-and-stability",
    "resource-consumption",
    "quality-qualified-effects",
    "telemetry-coverage",
)


@dataclass(frozen=True)
class VerifiedV3Evidence:
    """Compact, already-verified source evidence used by the v4 analyzer."""

    root: Path
    source_plan: AnalysisPlan
    runs: tuple[BenchmarkRunV3, ...]
    controller_ledgers: tuple[Mapping[str, Any], ...]
    campaign_context: Mapping[str, Any]
    bundle_digest: str
    verification: Mapping[str, Any]


def load_verified_v3_evidence(directory: str | Path) -> VerifiedV3Evidence:
    """Verify v3 first, then stream compact run and ledger projections.

    The public v3 verifier has already checked every complete action projection
    and ledger chain. V4 therefore retains compact run objects and ledger
    summaries instead of holding hundreds of thousands of duplicate action
    objects in memory.
    """

    root = Path(directory).resolve()
    verification = verify_v3_results(root)
    try:
        publication = json.loads((root / "publication.json").read_text(encoding="utf-8"))
        campaign_context = json.loads((root / "campaign-context.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkV4SchemaError("v4_source_payload_invalid") from exc
    if not isinstance(publication, Mapping) or not isinstance(campaign_context, Mapping):
        raise BenchmarkV4SchemaError("v4_source_payload_invalid")
    artifacts = publication.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise BenchmarkV4SchemaError("v4_source_publication_invalid")
    run_names = _artifact_names(artifacts.get("run_records"), prefix="runs")
    ledger_names = _artifact_names(artifacts.get("controller_ledgers"), prefix="ledgers")
    source_plan = load_analysis_plan(root / "analysis-plan.json")
    runs = tuple(_iter_compact_runs(root, run_names))
    ledgers = tuple(_iter_compact_ledgers(root, ledger_names))
    try:
        expected_runs = int(verification.get("runs") or 0)
    except (TypeError, ValueError) as exc:
        raise BenchmarkV4SchemaError("v4_source_verification_invalid") from exc
    if expected_runs != len(runs) or len(ledgers) != len(runs):
        raise BenchmarkV4SchemaError("v4_source_evidence_count_mismatch")
    return VerifiedV3Evidence(
        root=root,
        source_plan=source_plan,
        runs=runs,
        controller_ledgers=ledgers,
        campaign_context=dict(campaign_context),
        bundle_digest=_sha256(root / "SHA256SUMS"),
        verification=dict(verification),
    )


def render_efficiency_runs_csv(
    plan: EfficiencyPlan,
    projections: Sequence[EfficiencyRunProjection],
) -> str:
    """Render a stable, flat row for every source run and resource."""

    fields = [
        "csv_schema_version",
        "efficiency_plan_digest",
        "run_schema_version",
        "run_id",
        "efficiency_track_id",
        "source_track_id",
        "system_id",
        "scenario_id",
        "repetition",
        "matched_fixture_seed",
        "execution_status",
        "task_status",
        "started_at",
        "finished_at",
        "batch_id",
        "host_id",
        "efficiency_plan_attested",
        "quality.available",
        "quality.reliability",
        "quality.source",
        "quality.unit",
        "quality.value",
        "quality.reason",
    ]
    for name in ALL_RESOURCES:
        fields.extend(
            [
                f"{name}.available",
                f"{name}.reliability",
                f"{name}.source",
                f"{name}.unit",
                f"{name}.value",
                f"{name}.reason",
            ]
        )
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="raise", lineterminator="\n")
    writer.writeheader()
    for item in sorted(projections, key=lambda value: _projection_sort_key(plan, value)):
        quality = item.quality
        row: dict[str, Any] = {
            "batch_id": item.batch_id,
            "csv_schema_version": EFFICIENCY_CSV_SCHEMA_VERSION,
            "efficiency_plan_attested": _bool(item.efficiency_plan_attested),
            "efficiency_plan_digest": plan.digest,
            "efficiency_track_id": item.efficiency_track_id,
            "execution_status": item.execution_status,
            "finished_at": _float(item.finished_at),
            "host_id": item.host_id,
            "matched_fixture_seed": item.matched_fixture_seed,
            "quality.available": _bool(quality.available),
            "quality.reason": quality.reason,
            "quality.reliability": quality.reliability,
            "quality.source": quality.source,
            "quality.unit": quality.unit,
            "quality.value": _optional_float(quality.value),
            "repetition": item.repetition,
            "run_id": item.run_id,
            "run_schema_version": item.schema_version,
            "scenario_id": item.scenario_id,
            "source_track_id": item.source_track_id,
            "started_at": _float(item.started_at),
            "system_id": item.system_id,
            "task_status": item.task_status,
        }
        for name in ALL_RESOURCES:
            observation = item.resources[name]
            row[f"{name}.available"] = _bool(observation.available)
            row[f"{name}.reason"] = observation.reason
            row[f"{name}.reliability"] = observation.reliability
            row[f"{name}.source"] = observation.source
            row[f"{name}.unit"] = observation.unit
            row[f"{name}.value"] = _optional_float(observation.value)
        writer.writerow(row)
    return stream.getvalue()


def render_efficiency_run_records(
    plan: EfficiencyPlan,
    projections: Sequence[EfficiencyRunProjection],
) -> str:
    return "".join(
        canonical_json(item.to_dict()) + "\n"
        for item in sorted(projections, key=lambda value: _projection_sort_key(plan, value))
    )


def svg_contract() -> dict[str, Any]:
    return {
        "automatic_winner": False,
        "external_resources": False,
        "panels": list(SVG_PANEL_IDS),
        "scripts": False,
        "source_v3_required_for_verification": True,
    }


def render_efficiency_svg(
    plan: EfficiencyPlan,
    statistics_payload: Mapping[str, Any],
) -> str:
    """Render a deterministic script-free summary without inventing rankings."""

    systems = statistics_payload.get("systems")
    if not isinstance(systems, Mapping) or set(systems) != set(plan.system_ids):
        raise BenchmarkV4SchemaError("v4_statistics_systems_invalid")
    effects = statistics_payload.get("paired_effects")
    if not isinstance(effects, Sequence) or isinstance(effects, (str, bytes, bytearray)):
        raise BenchmarkV4SchemaError("v4_statistics_effects_invalid")
    width = 1200
    top = 78
    panel_height = 195
    gap = 18
    height = top + len(SVG_PANEL_IDS) * (panel_height + gap) + 30
    colors = ("#2563eb", "#059669", "#d97706", "#7c3aed", "#dc2626", "#0891b2")
    fragments = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="chart-title chart-desc">',
        '<title id="chart-title">Benchmark v4 efficiency companion</title>',
        '<desc id="chart-desc">Separate quality, resource, paired-effect, and telemetry panels. No automatic winner.</desc>',
        "<style>text{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;fill:#172033}.panel{fill:#fff;stroke:#cbd5e1}.bar-bg{fill:#e2e8f0}.label{font-size:13px}.small{font-size:11px;fill:#475569}.title{font-size:18px;font-weight:700}.heading{font-size:24px;font-weight:700}</style>",
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        '<text class="heading" x="38" y="38">Benchmark v4 — quality and resource efficiency</text>',
        f'<text class="small" x="38" y="59">Track: {html.escape(plan.efficiency_track_id)} · Plan: {plan.digest[:16]} · No overall winner</text>',
    ]
    renderers = (
        ("quality-and-stability", "Quality and stability (all scheduled)", _render_quality_panel),
        ("resource-consumption", "Primary resource consumption (all scheduled)", _render_resource_panel),
        ("quality-qualified-effects", "Quality-qualified paired effects", _render_effect_panel),
        ("telemetry-coverage", "Telemetry and fairness gates", _render_coverage_panel),
    )
    for index, (panel_id, title, renderer) in enumerate(renderers):
        y = top + index * (panel_height + gap)
        fragments.extend(
            [
                f'<g id="{panel_id}" data-panel="{panel_id}">',
                f'<rect class="panel" x="28" y="{y}" width="1144" height="{panel_height}" rx="8"/>',
                f'<text class="title" x="48" y="{y + 28}">{html.escape(title)}</text>',
                *renderer(plan, statistics_payload, systems, effects, colors, y + 48),
                "</g>",
            ]
        )
    fragments.append("</svg>")
    return "\n".join(fragments) + "\n"


def publish_v4_results(
    plan: EfficiencyPlan,
    source_v3_directory: str | Path,
    output_directory: str | Path,
) -> Path:
    """Publish a small companion whose source digest binds verified v3 evidence."""

    source = load_verified_v3_evidence(source_v3_directory)
    if source.source_plan.digest != plan.source_analysis_plan_digest:
        raise BenchmarkV4SchemaError("v4_source_plan_digest_mismatch")
    projections = extract_efficiency_runs(
        plan,
        source.source_plan,
        source.runs,
        source.controller_ledgers,
    )
    statistics_payload = analyze_efficiency(
        plan,
        source.source_plan,
        source.runs,
        source.controller_ledgers,
        source.campaign_context,
    )
    destination = Path(output_directory).resolve()
    if destination.exists():
        raise FileExistsError(f"v4_publication_destination_exists:{destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}-tmp-", dir=str(destination.parent)))
    try:
        freeze_efficiency_plan(plan, temporary / "efficiency-plan.json")
        (temporary / "efficiency-runs.csv").write_text(
            render_efficiency_runs_csv(plan, projections),
            encoding="utf-8",
        )
        (temporary / "efficiency-runs.jsonl").write_text(
            render_efficiency_run_records(plan, projections),
            encoding="utf-8",
        )
        (temporary / "efficiency-statistics.json").write_text(
            _pretty_json(statistics_payload),
            encoding="utf-8",
        )
        (temporary / "efficiency.svg").write_text(
            render_efficiency_svg(plan, statistics_payload),
            encoding="utf-8",
        )
        source_attestation = _source_attestation(source)
        (temporary / "source-attestation.json").write_text(
            _pretty_json(source_attestation),
            encoding="utf-8",
        )
        manifest = _publication_manifest(plan, source)
        (temporary / "publication.json").write_text(_pretty_json(manifest), encoding="utf-8")
        checksum_paths = sorted(path for path in temporary.iterdir() if path.is_file())
        (temporary / "SHA256SUMS").write_text(
            "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_paths),
            encoding="utf-8",
        )
        _verify_v4_results(temporary, source)
        if destination.exists():
            raise FileExistsError(f"v4_publication_destination_exists:{destination}")
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def verify_v4_results(
    directory: str | Path,
    *,
    source_v3_directory: str | Path,
) -> dict[str, Any]:
    source = load_verified_v3_evidence(source_v3_directory)
    return _verify_v4_results(Path(directory).resolve(), source)


def _verify_v4_results(root: Path, source: VerifiedV3Evidence) -> dict[str, Any]:
    expected = _read_checksums(root / "SHA256SUMS")
    entries = tuple(root.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise BenchmarkV4SchemaError("v4_publication_file_set_mismatch")
    actual = {path.name for path in entries if path.name != "SHA256SUMS"}
    if actual != set(expected):
        raise BenchmarkV4SchemaError("v4_publication_file_set_mismatch")
    for name, digest in expected.items():
        if _sha256(root / name) != digest:
            raise BenchmarkV4SchemaError("v4_publication_checksum_mismatch")
    required = {
        "efficiency-plan.json",
        "efficiency-runs.csv",
        "efficiency-runs.jsonl",
        "efficiency-statistics.json",
        "efficiency.svg",
        "publication.json",
        "source-attestation.json",
    }
    if actual != required:
        raise BenchmarkV4SchemaError("v4_publication_file_set_mismatch")
    canonical_checksums = "".join(f"{expected[name]}  {name}\n" for name in sorted(expected))
    if (root / "SHA256SUMS").read_text(encoding="utf-8") != canonical_checksums:
        raise BenchmarkV4SchemaError("v4_publication_checksums_invalid")
    plan = load_efficiency_plan(root / "efficiency-plan.json")
    try:
        publication = json.loads((root / "publication.json").read_text(encoding="utf-8"))
        statistics_payload = json.loads((root / "efficiency-statistics.json").read_text(encoding="utf-8"))
        source_attestation = json.loads((root / "source-attestation.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkV4SchemaError("v4_publication_payload_invalid") from exc
    if not all(isinstance(item, Mapping) for item in (publication, statistics_payload, source_attestation)):
        raise BenchmarkV4SchemaError("v4_publication_payload_invalid")
    _validate_publication_manifest(cast(Mapping[str, Any], publication), plan, source)
    _validate_source_attestation(cast(Mapping[str, Any], source_attestation), source)
    if source.source_plan.digest != plan.source_analysis_plan_digest:
        raise BenchmarkV4SchemaError("v4_source_plan_digest_mismatch")
    projections = extract_efficiency_runs(
        plan,
        source.source_plan,
        source.runs,
        source.controller_ledgers,
    )
    regenerated_statistics = analyze_efficiency(
        plan,
        source.source_plan,
        source.runs,
        source.controller_ledgers,
        source.campaign_context,
    )
    expected_bytes = {
        "efficiency-plan.json": _pretty_json(plan.to_dict()).encode(),
        "efficiency-runs.csv": render_efficiency_runs_csv(plan, projections).encode(),
        "efficiency-runs.jsonl": render_efficiency_run_records(plan, projections).encode(),
        "efficiency-statistics.json": _pretty_json(regenerated_statistics).encode(),
        "efficiency.svg": render_efficiency_svg(plan, regenerated_statistics).encode(),
        "publication.json": _pretty_json(_publication_manifest(plan, source)).encode(),
        "source-attestation.json": _pretty_json(_source_attestation(source)).encode(),
    }
    for name, payload in expected_bytes.items():
        if (root / name).read_bytes() != payload:
            raise BenchmarkV4SchemaError("v4_publication_recompute_mismatch")
    if dict(statistics_payload) != regenerated_statistics:
        raise BenchmarkV4SchemaError("v4_publication_recompute_mismatch")
    return {
        "efficiency_plan_digest": plan.digest,
        "efficiency_track_id": plan.efficiency_track_id,
        "files": len(actual) + 1,
        "runs": len(projections),
        "source_bundle_digest": source.bundle_digest,
        "source_track_id": source.source_plan.track_id,
        "status": "verified",
    }


def _iter_compact_runs(root: Path, names: Sequence[str]) -> Iterable[BenchmarkRunV3]:
    for name in names:
        try:
            with (root / name).open("r", encoding="utf-8") as handle:
                for line in handle:
                    payload = json.loads(line)
                    if not isinstance(payload, Mapping):
                        raise BenchmarkV4SchemaError("v4_source_run_invalid")
                    compact = dict(payload)
                    compact["action_telemetry"] = []
                    yield load_run(compact)
        except BenchmarkV4SchemaError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BenchmarkV4SchemaError("v4_source_run_invalid") from exc


def _iter_compact_ledgers(root: Path, names: Sequence[str]) -> Iterable[Mapping[str, Any]]:
    for name in names:
        try:
            with (root / name).open("r", encoding="utf-8") as handle:
                for line in handle:
                    payload = json.loads(line)
                    if not isinstance(payload, Mapping):
                        raise BenchmarkV4SchemaError("v4_source_ledger_invalid")
                    entries = payload.get("entries")
                    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
                        raise BenchmarkV4SchemaError("v4_source_ledger_invalid")
                    targets: set[tuple[str, str]] = set()
                    unsuccessful = 0
                    evidence_bearing = 0
                    for entry in entries:
                        if not isinstance(entry, Mapping):
                            raise BenchmarkV4SchemaError("v4_source_ledger_invalid")
                        targets.add((str(entry.get("method") or ""), str(entry.get("target_digest") or "")))
                        raw_status = entry.get("status")
                        if isinstance(raw_status, bool) or not isinstance(raw_status, int):
                            raise BenchmarkV4SchemaError("v4_source_ledger_invalid")
                        status = raw_status
                        unsuccessful += int(status >= 400)
                        evidence = entry.get("evidence_ids") or ()
                        if not isinstance(evidence, Sequence) or isinstance(evidence, (str, bytes, bytearray)):
                            raise BenchmarkV4SchemaError("v4_source_ledger_invalid")
                        evidence_bearing += int(bool(evidence))
                    count = len(entries)
                    compact = {key: value for key, value in payload.items() if key != "entries"}
                    compact["efficiency_summary"] = {
                        "entry_count": count,
                        "evidence_bearing_request_count": evidence_bearing,
                        "repeated_request_count": count - len(targets),
                        "unique_target_count": len(targets),
                        "unsuccessful_request_count": unsuccessful,
                    }
                    yield compact
        except BenchmarkV4SchemaError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BenchmarkV4SchemaError("v4_source_ledger_invalid") from exc


def _artifact_names(value: Any, *, prefix: str) -> tuple[str, ...]:
    # V3 publication 1.0 used one JSONL filename; 1.1 uses ordered shards.
    # Both are independently verified by ``verify_v3_results`` before this
    # compatibility projection is reached.
    if isinstance(value, str):
        if value != f"{prefix}.jsonl":
            raise BenchmarkV4SchemaError("v4_source_publication_invalid")
        return (value,)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)) or not value:
        raise BenchmarkV4SchemaError("v4_source_publication_invalid")
    names = tuple(str(item) for item in value)
    if len(set(names)) != len(names) or any(name != f"{prefix}-{index:04d}.jsonl" for index, name in enumerate(names)):
        raise BenchmarkV4SchemaError("v4_source_publication_invalid")
    return names


def _read_checksums(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise BenchmarkV4SchemaError("v4_publication_checksums_missing") from exc
    result: dict[str, str] = {}
    for line in lines:
        digest, separator, name = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not name
            or "/" in name
            or name in result
        ):
            raise BenchmarkV4SchemaError("v4_publication_checksums_invalid")
        result[name] = digest
    return result


def _validate_publication_manifest(
    payload: Mapping[str, Any],
    plan: EfficiencyPlan,
    source: VerifiedV3Evidence,
) -> None:
    if payload != _publication_manifest(plan, source):
        raise BenchmarkV4SchemaError("v4_publication_manifest_invalid")


def _validate_source_attestation(payload: Mapping[str, Any], source: VerifiedV3Evidence) -> None:
    if payload != _source_attestation(source):
        raise BenchmarkV4SchemaError("v4_source_attestation_invalid")


def _source_attestation(source: VerifiedV3Evidence) -> dict[str, Any]:
    return {
        "analysis_plan_digest": source.source_plan.digest,
        "run_count": len(source.runs),
        "schema_version": SOURCE_ATTESTATION_SCHEMA_VERSION,
        "source_bundle_digest": source.bundle_digest,
        "source_kind": "benchmark-v3-publication",
        "source_track_id": source.source_plan.track_id,
    }


def _publication_manifest(
    plan: EfficiencyPlan,
    source: VerifiedV3Evidence,
) -> dict[str, Any]:
    return {
        "artifacts": {
            "efficiency_plan": "efficiency-plan.json",
            "efficiency_run_records": "efficiency-runs.jsonl",
            "efficiency_runs": "efficiency-runs.csv",
            "efficiency_statistics": "efficiency-statistics.json",
            "source_attestation": "source-attestation.json",
            "visualization": "efficiency.svg",
        },
        "automatic_winner": False,
        "efficiency_plan_digest": plan.digest,
        "efficiency_track_id": plan.efficiency_track_id,
        "schema_version": EFFICIENCY_PUBLICATION_SCHEMA_VERSION,
        "source_bundle_digest": source.bundle_digest,
        "source_v3_required_for_verification": True,
        "svg_contract": svg_contract(),
    }


def _projection_sort_key(plan: EfficiencyPlan, item: EfficiencyRunProjection) -> tuple[int, int, str]:
    order: dict[tuple[str, int, int, str], tuple[int, int]] = {}
    for block_index, block in enumerate(plan.schedule):
        for system_index, system_id in enumerate(block.system_order):
            order[(block.scenario_id, block.repetition, block.matched_fixture_seed, system_id)] = (
                block_index,
                system_index,
            )
    position = order.get((*item.block_key, item.system_id))
    if position is None:
        raise BenchmarkV4SchemaError("v4_projection_not_in_schedule")
    return (*position, item.run_id)


def _render_quality_panel(
    plan: EfficiencyPlan,
    _statistics: Mapping[str, Any],
    systems: Mapping[str, Any],
    _effects: Sequence[Any],
    colors: Sequence[str],
    y: int,
) -> list[str]:
    result: list[str] = []
    for index, system_id in enumerate(plan.system_ids):
        summary = _mapping_value(systems, system_id)
        stability = _mapping_value(summary, "stability")
        quality = _mapping_value(summary, "quality")
        execution = _display_number(_nested_number(stability, "execution_success_rate"), percent=True)
        completion = _display_number(_nested_number(stability, "task_completion_rate"), percent=True)
        verified_f1 = _display_number(_nested_number(quality, "verified_f1_mean"), percent=True)
        x = 58 + index * max(1, 1080 // len(plan.system_ids))
        result.extend(
            [
                f'<circle cx="{x}" cy="{y + 14}" r="6" fill="{colors[index % len(colors)]}"/>',
                f'<text class="label" x="{x + 12}" y="{y + 18}">{html.escape(system_id)}</text>',
                f'<text class="small" x="{x}" y="{y + 48}">execution success: {execution}</text>',
                f'<text class="small" x="{x}" y="{y + 70}">task completion: {completion}</text>',
                f'<text class="small" x="{x}" y="{y + 92}">mean verified F1: {verified_f1}</text>',
            ]
        )
    return result


def _render_resource_panel(
    plan: EfficiencyPlan,
    _statistics: Mapping[str, Any],
    systems: Mapping[str, Any],
    _effects: Sequence[Any],
    colors: Sequence[str],
    y: int,
) -> list[str]:
    result: list[str] = []
    for index, system_id in enumerate(plan.system_ids):
        summary = _mapping_value(systems, system_id)
        resources = _mapping_value(summary, "resources")
        wall = _mapping_value(resources, "wall_time_seconds")
        requests = _mapping_value(resources, "fixture_http_requests")
        x = 58 + index * max(1, 1080 // len(plan.system_ids))
        result.extend(
            [
                f'<circle cx="{x}" cy="{y + 14}" r="6" fill="{colors[index % len(colors)]}"/>',
                f'<text class="label" x="{x + 12}" y="{y + 18}">{html.escape(system_id)}</text>',
                f'<text class="small" x="{x}" y="{y + 48}">median wall: {_display_number(_nested_number(wall, "median"))} s</text>',
                f'<text class="small" x="{x}" y="{y + 70}">median requests: {_display_number(_nested_number(requests, "median"))}</text>',
                f'<text class="small" x="{x}" y="{y + 92}">wall coverage: {_display_number(_nested_number(wall, "coverage"), percent=True)}</text>',
                f'<text class="small" x="{x}" y="{y + 114}">request coverage: {_display_number(_nested_number(requests, "coverage"), percent=True)}</text>',
            ]
        )
    return result


def _render_effect_panel(
    _plan: EfficiencyPlan,
    _statistics: Mapping[str, Any],
    _systems: Mapping[str, Any],
    effects: Sequence[Any],
    _colors: Sequence[str],
    y: int,
) -> list[str]:
    result: list[str] = []
    for index, raw in enumerate(effects[:4]):
        effect = raw if isinstance(raw, Mapping) else {}
        resource = html.escape(str(effect.get("resource") or "unknown"))
        left = html.escape(str(effect.get("left_system_id") or "left"))
        right = html.escape(str(effect.get("right_system_id") or "right"))
        claim = html.escape(str(effect.get("directional_claim") or "inconclusive"))
        qualified_raw = effect.get("quality_qualified_pairs")
        if isinstance(qualified_raw, bool) or not isinstance(qualified_raw, int) or qualified_raw < 0:
            raise BenchmarkV4SchemaError("v4_statistics_effect_count_invalid")
        qualified = qualified_raw
        result.append(
            f'<text class="small" x="58" y="{y + 18 + index * 28}">{left} → {right} · {resource} · n={qualified} · {claim}</text>'
        )
    if not result:
        result.append(f'<text class="small" x="58" y="{y + 18}">No paired effects available.</text>')
    return result


def _render_coverage_panel(
    plan: EfficiencyPlan,
    statistics: Mapping[str, Any],
    _systems: Mapping[str, Any],
    _effects: Sequence[Any],
    _colors: Sequence[str],
    y: int,
) -> list[str]:
    fairness = statistics.get("fairness")
    fairness_map = fairness if isinstance(fairness, Mapping) else {}
    lines = [
        f"overall fairness gate: {fairness_map.get('eligible', False)}",
        f"run-plan attestation: {fairness_map.get('run_attestation', False)}",
        f"frozen schedule order: {fairness_map.get('schedule_order', False)}",
        f"same paired host/batch: {fairness_map.get('paired_host_batch', False)}",
        "missing measurements remain unavailable; no imputation or automatic winner",
    ]
    return [
        f'<text class="small" x="58" y="{y + 18 + index * 24}">{html.escape(str(line))}</text>'
        for index, line in enumerate(lines)
    ]


def _mapping_value(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = payload.get(key)
    return value if isinstance(value, Mapping) else {}


def _nested_number(payload: Mapping[str, Any], key: str) -> float | None:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _display_number(value: float | None, *, percent: bool = False) -> str:
    if value is None:
        return "N/A"
    if percent:
        return f"{value * 100:.1f}%"
    return f"{value:.3f}"


def _pretty_json(payload: Mapping[str, Any]) -> str:
    return (
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bool(value: bool) -> str:
    return "true" if value else "false"


def _float(value: float) -> str:
    return f"{float(value):.9f}".rstrip("0").rstrip(".") or "0"


def _optional_float(value: float | None) -> str:
    return "" if value is None else _float(value)


__all__ = [
    "EFFICIENCY_CSV_SCHEMA_VERSION",
    "EFFICIENCY_PUBLICATION_SCHEMA_VERSION",
    "SOURCE_ATTESTATION_SCHEMA_VERSION",
    "SVG_PANEL_IDS",
    "VerifiedV3Evidence",
    "load_verified_v3_evidence",
    "publish_v4_results",
    "render_efficiency_run_records",
    "render_efficiency_runs_csv",
    "render_efficiency_svg",
    "svg_contract",
    "verify_v4_results",
]
