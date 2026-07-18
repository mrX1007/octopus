"""Self-contained, checksummed publication bundles for benchmark campaigns."""

from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import statistics
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from ..schema import BenchmarkScenario
from .matrix import CompetitorMatrixResult, render_comparison_markdown
from .schema import SystemManifest
from .state import schedule_run_key

CAMPAIGN_PUBLICATION_SCHEMA_VERSION = "1.0"
_STRICT_RUN_STATUSES = frozenset({"failed", "invalid", "partial", "timeout"})
_RUN_STATUSES = _STRICT_RUN_STATUSES | {"succeeded"}
_RUN_TIMING_TOLERANCE_SECONDS = 1.0
_ERROR_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_PUBLIC_PROVENANCE_KEYS = frozenset(
    {
        "controller_source_sha256",
        "fingerprint",
        "input_sha256",
        "repository_revision",
        "runtime",
        "schema_version",
    }
)
_PUBLIC_PROVENANCE_INPUT_KEYS = frozenset({"campaign", "scenarios", "systems"})
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


class CampaignPublicationError(RuntimeError):
    """Raised when a bundle cannot be published or verified safely."""


class SecretCanaryDetected(CampaignPublicationError):
    """A known secret value reached a would-be publication file."""


def publish_campaign_bundle(
    *,
    destination: str | Path,
    matrix: CompetitorMatrixResult,
    campaign: Mapping[str, Any],
    fingerprint: str,
    manifests: Sequence[SystemManifest],
    scenarios: Sequence[BenchmarkScenario],
    preflight: Mapping[str, Any],
    schedule: Sequence[Mapping[str, Any]],
    attestations: Sequence[Mapping[str, Any]],
    cleanup: Mapping[str, Any],
    provenance: Mapping[str, Any],
    campaign_status: Mapping[str, Any],
    secret_canaries: Sequence[str] = (),
) -> Path:
    """Atomically write and verify a complete immutable campaign directory."""

    output = Path(destination)
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"publication_destination_exists:{output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=str(output.parent))
    )
    try:
        _write_json(temporary / "comparison.json", matrix.to_dict())
        (temporary / "comparison.md").write_text(
            render_comparison_markdown(matrix),
            encoding="utf-8",
        )
        for system_id, aggregates in sorted(matrix.aggregates.items()):
            for scenario_id, aggregate in sorted(aggregates.items()):
                _write_json(
                    temporary
                    / "aggregates"
                    / _safe_component(system_id)
                    / f"{_safe_component(scenario_id)}.json",
                    aggregate.to_dict(),
                )

        public_campaign = {
            **dict(campaign),
            "schema_version": CAMPAIGN_PUBLICATION_SCHEMA_VERSION,
            "fingerprint": fingerprint,
        }
        _write_json(temporary / "inputs" / "campaign.json", public_campaign)
        public_systems: dict[str, dict[str, Any]] = {}
        for manifest in manifests:
            public_systems[manifest.system_id] = manifest.to_public_dict()
            _write_json(
                temporary / "inputs" / "systems" / f"{manifest.system_id}.json",
                public_systems[manifest.system_id],
            )
        public_scenarios: dict[str, dict[str, Any]] = {}
        for scenario in scenarios:
            public_scenarios[scenario.scenario_id] = scenario.to_dict()
            _write_json(
                temporary
                / "inputs"
                / "scenarios"
                / f"{scenario.scenario_id}.json",
                public_scenarios[scenario.scenario_id],
            )
        _write_json(temporary / "preflight.json", dict(preflight))
        _write_json(
            temporary / "schedule.json",
            {
                "schema_version": CAMPAIGN_PUBLICATION_SCHEMA_VERSION,
                "fingerprint": fingerprint,
                "runs": [dict(item) for item in schedule],
            },
        )
        for index, attestation in enumerate(attestations, 1):
            raw_key = str(attestation.get("run_key") or "")
            key = raw_key if _is_digest(raw_key) else f"attestation-{index:06d}"
            _write_json(
                temporary / "attestations" / f"{key}.json",
                dict(attestation),
            )
        _write_json(temporary / "cleanup.json", dict(cleanup))
        _write_json(
            temporary / "provenance.json",
            _published_provenance(
                provenance,
                campaign=public_campaign,
                systems=public_systems,
                scenarios=public_scenarios,
            ),
        )
        _write_json(
            temporary / "campaign-status.json",
            {
                **dict(campaign_status),
                "schema_version": CAMPAIGN_PUBLICATION_SCHEMA_VERSION,
                "fingerprint": fingerprint,
                "matrix_id": matrix.matrix_id,
            },
        )

        _scan_secret_canaries(temporary, secret_canaries)
        checksum_paths = sorted(path for path in temporary.rglob("*") if path.is_file())
        lines = [
            f"{_sha256_file(path)}  {path.relative_to(temporary).as_posix()}"
            for path in checksum_paths
        ]
        (temporary / "SHA256SUMS").write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )
        verify_campaign_bundle(temporary)
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"publication_destination_exists:{output}")
        temporary.rename(output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return output


def verify_campaign_bundle(directory: str | Path) -> dict[str, Any]:
    """Verify checksum coverage and reject symlinks, traversal, or extra files."""

    root = Path(directory)
    checksum_file = root / "SHA256SUMS"
    if (
        not root.is_dir()
        or root.is_symlink()
        or not checksum_file.is_file()
        or checksum_file.is_symlink()
    ):
        raise CampaignPublicationError("publication_checksum_file_missing")
    expected: dict[str, str] = {}
    try:
        lines = checksum_file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise CampaignPublicationError("publication_checksum_read_failed") from exc
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or not _is_digest(parts[0]):
            raise CampaignPublicationError("publication_checksum_format_invalid")
        relative = PurePosixPath(parts[1])
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or "\\" in parts[1]
            or "\x00" in parts[1]
            or relative.as_posix() == "SHA256SUMS"
        ):
            raise CampaignPublicationError("publication_checksum_path_invalid")
        name = relative.as_posix()
        if name in expected:
            raise CampaignPublicationError("publication_checksum_duplicate_path")
        expected[name] = parts[0]

    observed: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CampaignPublicationError("publication_symlink_forbidden")
        if path.is_file() and path != checksum_file:
            observed[path.relative_to(root).as_posix()] = path
    if set(expected) != set(observed):
        raise CampaignPublicationError("publication_checksum_coverage_mismatch")
    for name, digest in expected.items():
        if _sha256_file(observed[name]) != digest:
            raise CampaignPublicationError("publication_checksum_mismatch")

    required = {
        "campaign-status.json",
        "cleanup.json",
        "comparison.json",
        "comparison.md",
        "inputs/campaign.json",
        "preflight.json",
        "provenance.json",
        "schedule.json",
    }
    if not required.issubset(observed):
        raise CampaignPublicationError("publication_required_file_missing")
    _verify_semantic_completeness(root, observed)
    return {
        "schema_version": CAMPAIGN_PUBLICATION_SCHEMA_VERSION,
        "status": "verified",
        "file_count": len(observed),
    }


def _verify_semantic_completeness(root: Path, observed: Mapping[str, Path]) -> None:
    comparison = _read_json_mapping(root / "comparison.json")
    schedule_document = _read_json_mapping(root / "schedule.json")
    campaign = _read_json_mapping(root / "inputs" / "campaign.json")
    campaign_status = _read_json_mapping(root / "campaign-status.json")
    provenance = _read_json_mapping(root / "provenance.json")
    cleanup = _read_json_mapping(root / "cleanup.json")

    fingerprint = str(schedule_document.get("fingerprint") or "")
    if not fingerprint.startswith("benchmark-campaign://sha256/"):
        raise CampaignPublicationError("publication_semantic_invalid")
    if any(
        str(payload.get("fingerprint") or "") != fingerprint
        for payload in (campaign, campaign_status, provenance, cleanup)
    ):
        raise CampaignPublicationError("publication_semantic_invalid")
    matrix_id = str(comparison.get("matrix_id") or "")
    if campaign_status.get("matrix_id") != matrix_id:
        raise CampaignPublicationError("publication_semantic_invalid")

    comparison_systems = _mapping_sequence(comparison.get("systems"))
    comparison_scenarios = _mapping_sequence(comparison.get("scenarios"))
    systems = _identity_values(comparison_systems, "system_id")
    scenarios = _identity_values(comparison_scenarios, "scenario_id")
    repetitions = _positive_integer(comparison.get("repetitions"))
    if _positive_integer(campaign.get("repetitions")) != repetitions:
        raise CampaignPublicationError("publication_semantic_invalid")
    expected_combinations = {
        (system_id, scenario_id, repetition)
        for system_id in systems
        for scenario_id in scenarios
        for repetition in range(1, repetitions + 1)
    }

    schedule_by_combination: dict[tuple[str, str, int], dict[str, Any]] = {}
    schedule_by_key: dict[str, dict[str, Any]] = {}
    for order, item in enumerate(
        _mapping_sequence(schedule_document.get("runs")),
        start=1,
    ):
        system_id = str(item.get("system_id") or "")
        scenario_id = str(item.get("scenario_id") or "")
        repetition = _positive_integer(item.get("repetition"))
        seed = _nonnegative_integer(item.get("seed"))
        run_key = str(item.get("run_key") or "")
        combination = (system_id, scenario_id, repetition)
        if (
            item.get("order") != order
            or combination not in expected_combinations
            or combination in schedule_by_combination
            or run_key in schedule_by_key
            or run_key
            != schedule_run_key(system_id, scenario_id, repetition, seed)
        ):
            raise CampaignPublicationError("publication_semantic_invalid")
        normalized = {
            "run_key": run_key,
            "system_id": system_id,
            "scenario_id": scenario_id,
            "repetition": repetition,
            "seed": seed,
        }
        schedule_by_combination[combination] = normalized
        schedule_by_key[run_key] = normalized
    if set(schedule_by_combination) != expected_combinations:
        raise CampaignPublicationError("publication_semantic_incomplete")

    expected_system_inputs = {
        f"inputs/systems/{_safe_component(system_id)}.json" for system_id in systems
    }
    expected_scenario_inputs = {
        f"inputs/scenarios/{_safe_component(scenario_id)}.json"
        for scenario_id in scenarios
    }
    expected_aggregates = {
        f"aggregates/{_safe_component(system_id)}/{_safe_component(scenario_id)}.json"
        for system_id in systems
        for scenario_id in scenarios
    }
    expected_attestations = {
        f"attestations/{run_key}.json" for run_key in schedule_by_key
    }
    for prefix, expected_paths in (
        ("inputs/systems/", expected_system_inputs),
        ("inputs/scenarios/", expected_scenario_inputs),
        ("aggregates/", expected_aggregates),
        ("attestations/", expected_attestations),
    ):
        actual_paths = {name for name in observed if name.startswith(prefix)}
        if actual_paths != expected_paths:
            raise CampaignPublicationError("publication_semantic_incomplete")

    system_inputs = {
        system_id: _read_json_mapping(
            root / "inputs" / "systems" / f"{_safe_component(system_id)}.json"
        )
        for system_id in systems
    }
    scenario_inputs = {
        scenario_id: _read_json_mapping(
            root / "inputs" / "scenarios" / f"{_safe_component(scenario_id)}.json"
        )
        for scenario_id in scenarios
    }
    if any(
        payload.get("system_id") != system_id
        for system_id, payload in system_inputs.items()
    ) or any(
        payload.get("scenario_id") != scenario_id
        for scenario_id, payload in scenario_inputs.items()
    ):
        raise CampaignPublicationError("publication_semantic_invalid")

    expected_systems = tuple(
        sorted(
            (_comparison_system_metadata(payload) for payload in system_inputs.values()),
            key=lambda item: str(item["system_id"]),
        )
    )
    expected_scenarios = tuple(
        sorted(
            (
                _comparison_scenario_metadata(payload)
                for payload in scenario_inputs.values()
            ),
            key=lambda item: str(item["scenario_id"]),
        )
    )
    if not _json_equal(comparison_systems, expected_systems) or not _json_equal(
        comparison_scenarios,
        expected_scenarios,
    ):
        raise CampaignPublicationError("publication_semantic_invalid")
    if not _json_equal(
        comparison.get("methodology"),
        _comparison_methodology(system_inputs),
    ):
        raise CampaignPublicationError("publication_semantic_invalid")
    _verify_provenance_inputs(
        provenance,
        campaign=campaign,
        systems=system_inputs,
        scenarios=scenario_inputs,
    )

    observed_statuses: Counter[str] = Counter()
    policy_violations = 0
    expected_summaries: list[dict[str, Any]] = []
    aggregate_ids: dict[str, dict[str, str]] = {}
    system_identities = {
        system_id: _system_identity(payload)
        for system_id, payload in system_inputs.items()
    }
    for system_id in systems:
        aggregate_ids[system_id] = {}
        for scenario_id in scenarios:
            aggregate = _read_json_mapping(
                root
                / "aggregates"
                / _safe_component(system_id)
                / f"{_safe_component(scenario_id)}.json"
            )
            scenario_payload = aggregate.get("scenario")
            if not _json_equal(scenario_payload, scenario_inputs[scenario_id]):
                raise CampaignPublicationError("publication_semantic_invalid")
            runs = _mapping_sequence(aggregate.get("runs"))
            seen_repetitions: set[int] = set()
            run_ids: list[str] = []
            run_metrics: list[tuple[str, dict[str, float]]] = []
            durations: list[float] = []
            aggregate_statuses: Counter[str] = Counter()
            aggregate_policy_violations = 0
            allowed_actions = set(
                _string_sequence(scenario_inputs[scenario_id].get("allowed_actions"))
            )
            ground_truth = _required_mapping(
                scenario_inputs[scenario_id].get("ground_truth")
            )
            expected_findings = set(
                _string_sequence(ground_truth.get("expected_findings"))
            )
            for run in runs:
                repetition = _positive_integer(run.get("repetition"))
                seed = _nonnegative_integer(run.get("seed"))
                combination = (system_id, scenario_id, repetition)
                scheduled = schedule_by_combination.get(combination)
                status = str(run.get("status") or "")
                actions = _string_sequence(run.get("actions"))
                violations = _string_sequence(run.get("policy_violations"))
                expected_violations = tuple(
                    sorted({action for action in actions if action not in allowed_actions})
                )
                metrics = _metrics_mapping(run.get("metrics"))
                duration = _nonnegative_number(run.get("duration_seconds"))
                started_at = _nonnegative_number(run.get("started_at"))
                finished_at = _nonnegative_number(run.get("finished_at"))
                error_class = run.get("error_class")
                result_summary = run.get("result_summary")
                if not isinstance(result_summary, Mapping):
                    raise CampaignPublicationError("publication_semantic_invalid")
                reported_findings = set(
                    _string_sequence(result_summary.get("reported_findings"))
                )
                coverage_gaps = set(
                    _string_sequence(result_summary.get("coverage_gaps"))
                )
                if (
                    status not in _RUN_STATUSES
                    or run.get("scenario_id") != scenario_id
                    or scheduled is None
                    or scheduled["seed"] != seed
                    or repetition in seen_repetitions
                    or violations != expected_violations
                    or finished_at < started_at
                    or duration
                    > finished_at - started_at + _RUN_TIMING_TOLERANCE_SECONDS
                    or not isinstance(error_class, str)
                    or (
                        bool(error_class)
                        and not _ERROR_CLASS.fullmatch(error_class)
                    )
                    or result_summary.get("status") != status
                    or not expected_findings.difference(reported_findings).issubset(
                        coverage_gaps
                    )
                ):
                    raise CampaignPublicationError("publication_semantic_invalid")
                expected_run_id = _stable_id(
                    "benchmark-run",
                    {
                        "run_namespace": system_identities[system_id],
                        "scenario_id": scenario_id,
                        "scenario_contract": scenario_inputs[scenario_id],
                        "repetition": repetition,
                        "seed": seed,
                        "status": status,
                        "metrics": metrics,
                        "actions": actions,
                    },
                )
                if run.get("run_id") != expected_run_id:
                    raise CampaignPublicationError("publication_semantic_invalid")
                seen_repetitions.add(repetition)
                run_ids.append(expected_run_id)
                run_metrics.append((status, metrics))
                durations.append(duration)
                aggregate_statuses[status] += 1
                aggregate_policy_violations += len(violations)
            if seen_repetitions != set(range(1, repetitions + 1)):
                raise CampaignPublicationError("publication_semantic_incomplete")

            expected_aggregate_id = _stable_id(
                "benchmark-aggregate",
                {
                    "scenario_id": scenario_id,
                    "run_ids": run_ids,
                },
            )
            expected_status_counts = dict(sorted(aggregate_statuses.items()))
            expected_metric_statistics = _aggregate_metric_statistics(run_metrics)
            if (
                aggregate.get("aggregate_id") != expected_aggregate_id
                or not _json_equal(
                    aggregate.get("status_counts"),
                    expected_status_counts,
                )
                or not _json_equal(
                    aggregate.get("metric_statistics"),
                    expected_metric_statistics,
                )
            ):
                raise CampaignPublicationError("publication_semantic_invalid")

            aggregate_ids[system_id][scenario_id] = expected_aggregate_id
            observed_statuses.update(aggregate_statuses)
            policy_violations += aggregate_policy_violations
            expected_summaries.append(
                {
                    "system_id": system_id,
                    "scenario_id": scenario_id,
                    "aggregate_id": expected_aggregate_id,
                    "status_counts": expected_status_counts,
                    "duration_median_seconds": round(
                        float(statistics.median(durations)),
                        6,
                    ),
                    "metric_medians": {
                        name: values["median"]
                        for name, values in sorted(expected_metric_statistics.items())
                    },
                    "policy_violations": aggregate_policy_violations,
                    "timeout_runs": aggregate_statuses.get("timeout", 0),
                    "partial_runs": aggregate_statuses.get("partial", 0),
                    "error_runs": sum(
                        aggregate_statuses.get(status, 0)
                        for status in _STRICT_RUN_STATUSES
                    ),
                }
            )

    expected_summaries.sort(key=lambda item: (item["scenario_id"], item["system_id"]))
    if not _json_equal(comparison.get("summaries"), expected_summaries):
        raise CampaignPublicationError("publication_semantic_invalid")

    comparison_schema = str(comparison.get("schema_version") or "")
    expected_matrix_id = _stable_id(
        "competitor-matrix",
        {
            "schema_version": comparison_schema,
            "systems": [system_identities[system_id] for system_id in sorted(systems)],
            "aggregate_ids": {
                system_id: dict(sorted(aggregate_ids[system_id].items()))
                for system_id in sorted(aggregate_ids)
            },
        },
    )
    if (
        comparison_schema != CAMPAIGN_PUBLICATION_SCHEMA_VERSION
        or matrix_id != expected_matrix_id
    ):
        raise CampaignPublicationError("publication_semantic_invalid")

    for run_key, scheduled in schedule_by_key.items():
        attestation = _read_json_mapping(root / "attestations" / f"{run_key}.json")
        if (
            attestation.get("fingerprint") != fingerprint
            or attestation.get("run_key") != run_key
            or attestation.get("status") != "healthy"
            or attestation.get("system_id") != scheduled["system_id"]
            or attestation.get("scenario_id") != scheduled["scenario_id"]
            or attestation.get("repetition") != scheduled["repetition"]
            or attestation.get("seed") != scheduled["seed"]
        ):
            raise CampaignPublicationError("publication_semantic_invalid")

    cleanup_status = str(cleanup.get("status") or "")
    cleanup_combination = (
        str(cleanup.get("system_id") or ""),
        str(cleanup.get("scenario_id") or ""),
        _positive_integer(cleanup.get("repetition")),
    )
    cleanup_scheduled = schedule_by_combination.get(cleanup_combination)
    if (
        cleanup_status not in {"succeeded", "failed"}
        or campaign_status.get("cleanup_status") != cleanup_status
        or cleanup.get("campaign_id") != campaign.get("campaign_id")
        or cleanup_scheduled is None
        or cleanup_scheduled["seed"] != _nonnegative_integer(cleanup.get("seed"))
    ):
        raise CampaignPublicationError("publication_semantic_invalid")

    expected_status_counts = dict(sorted(observed_statuses.items()))
    if (
        not _json_equal(campaign_status.get("status_counts"), expected_status_counts)
        or _nonnegative_integer(campaign_status.get("policy_violations"))
        != policy_violations
        or _nonnegative_integer(campaign_status.get("executed_runs"))
        + _nonnegative_integer(campaign_status.get("resumed_runs"))
        != len(expected_combinations)
    ):
        raise CampaignPublicationError("publication_semantic_invalid")
    strict_statuses = set(_string_sequence(campaign.get("strict_statuses")))
    run_failure = policy_violations > 0 or any(
        observed_statuses.get(status, 0) > 0 for status in strict_statuses
    )
    expected_campaign_status = (
        "partial"
        if cleanup_status == "failed"
        else "completed_with_failures"
        if run_failure
        else "succeeded"
    )
    if campaign_status.get("status") != expected_campaign_status:
        raise CampaignPublicationError("publication_semantic_invalid")

    total_runs = len(expected_combinations)
    expected_publication = {
        "expected_aggregates": len(systems) * len(scenarios),
        "written_aggregates": len(systems) * len(scenarios),
        "missing_aggregates": 0,
        "publication_complete": True,
        "total_runs": total_runs,
        "succeeded_runs": observed_statuses.get("succeeded", 0),
        "failed_runs": observed_statuses.get("failed", 0),
        "invalid_runs": observed_statuses.get("invalid", 0),
        "timeout_runs": observed_statuses.get("timeout", 0),
        "partial_runs": observed_statuses.get("partial", 0),
        "policy_violations": policy_violations,
        "error_runs": sum(
            observed_statuses.get(status, 0) for status in _STRICT_RUN_STATUSES
        ),
    }
    if not _json_equal(comparison.get("publication"), expected_publication):
        raise CampaignPublicationError("publication_semantic_invalid")


def _read_json_mapping(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CampaignPublicationError("publication_semantic_invalid") from exc
    if not isinstance(payload, Mapping):
        raise CampaignPublicationError("publication_semantic_invalid")
    return {str(key): value for key, value in payload.items()}


def _mapping_sequence(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise CampaignPublicationError("publication_semantic_invalid")
    if any(not isinstance(item, Mapping) for item in value):
        raise CampaignPublicationError("publication_semantic_invalid")
    return tuple(value)


def _identity_values(value: Any, field: str) -> tuple[str, ...]:
    items = _mapping_sequence(value)
    result = tuple(str(item.get(field) or "") for item in items)
    if not result or len(result) != len(set(result)):
        raise CampaignPublicationError("publication_semantic_invalid")
    for item in result:
        _safe_component(item)
    return result


def _positive_integer(value: Any) -> int:
    parsed = _integer(value)
    if parsed <= 0:
        raise CampaignPublicationError("publication_semantic_invalid")
    return parsed


def _nonnegative_integer(value: Any) -> int:
    parsed = _integer(value)
    if parsed < 0:
        raise CampaignPublicationError("publication_semantic_invalid")
    return parsed


def _integer(value: Any) -> int:
    if isinstance(value, bool):
        raise CampaignPublicationError("publication_semantic_invalid")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise CampaignPublicationError("publication_semantic_invalid") from None
    if parsed != value:
        raise CampaignPublicationError("publication_semantic_invalid")
    return parsed


def _nonnegative_number(value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise CampaignPublicationError("publication_semantic_invalid")
    return float(value)


def _string_sequence(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise CampaignPublicationError("publication_semantic_invalid")
    if any(not isinstance(item, str) for item in value):
        raise CampaignPublicationError("publication_semantic_invalid")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise CampaignPublicationError("publication_semantic_invalid")
    return result


def _metrics_mapping(value: Any) -> dict[str, float]:
    if not isinstance(value, Mapping):
        raise CampaignPublicationError("publication_semantic_invalid")
    return {
        str(name): _nonnegative_number(metric)
        for name, metric in value.items()
    }


def _aggregate_metric_statistics(
    runs: Sequence[tuple[str, Mapping[str, float]]],
) -> dict[str, dict[str, float]]:
    names = sorted({name for _status, metrics in runs for name in metrics})
    result: dict[str, dict[str, float]] = {}
    for name in names:
        values = [
            float(metrics[name])
            for status, metrics in runs
            if status == "succeeded" and name in metrics
        ]
        if not values:
            continue
        result[name] = {
            "count": float(len(values)),
            "median": round(float(statistics.median(values)), 6),
            "variance": round(float(statistics.pvariance(values)), 6),
            "minimum": round(min(values), 6),
            "maximum": round(max(values), 6),
        }
    return result


def _comparison_system_metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    sanitized = _sanitize_public_metadata(payload)
    if not isinstance(sanitized, dict):
        raise CampaignPublicationError("publication_semantic_invalid")
    sanitized.setdefault("system_id", str(payload.get("system_id") or ""))
    sanitized.setdefault("version", payload.get("version"))
    sanitized.setdefault("track", payload.get("track"))
    sanitized.setdefault("fairness_profile", payload.get("fairness_profile"))
    sanitized.setdefault("execution_mode", _execution_mode(payload))
    if not sanitized.get("model") and not sanitized.get("model_metadata"):
        sanitized["model_metadata"] = _model_metadata(payload)
    return sanitized


def _comparison_scenario_metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    lab = _required_mapping(payload.get("lab"))
    target = _required_mapping(payload.get("target"))
    return {
        "scenario_id": str(payload.get("scenario_id") or ""),
        "name": payload.get("name"),
        "category": payload.get("category"),
        "lab_version": lab.get("version"),
        "target_version": target.get("version"),
        "model": dict(_required_mapping(payload.get("model"))),
        "tool_versions": dict(_required_mapping(payload.get("tool_versions"))),
        "budgets": dict(_required_mapping(payload.get("budgets"))),
        "seed": _nonnegative_integer(payload.get("seed")),
    }


def _comparison_methodology(
    systems: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    payloads = tuple(systems.values())
    return {
        "track": _common_value(payloads, "track"),
        "fairness_profile": _common_json_value(payloads, "fairness_profile"),
        "execution_mode": _common_execution_mode(payloads),
        "same_scenarios": True,
        "same_repetitions": True,
        "same_seeds": True,
        "automatic_winner": False,
    }


def _system_identity(payload: Mapping[str, Any]) -> str:
    system_id = str(payload.get("system_id") or "")
    _safe_component(system_id)
    return _stable_id(
        "benchmark-system",
        {
            "system_id": system_id,
            "version": payload.get("version"),
            "source_revision": payload.get("source_revision"),
            "track": payload.get("track"),
            "fairness_profile": payload.get("fairness_profile"),
            "execution_mode": _execution_mode(payload),
            "model": _model_metadata(payload),
            "tool_versions": payload.get("tool_versions") or {},
            "metadata": payload.get("metadata") or {},
        },
    )


def _execution_mode(payload: Mapping[str, Any]) -> str:
    metadata = payload.get("metadata")
    metadata_mode = (
        metadata.get("execution_mode") if isinstance(metadata, Mapping) else None
    )
    mode = str(
        payload.get("execution_mode")
        or payload.get("mode")
        or payload.get("runner_mode")
        or metadata_mode
        or "external_command"
    ).strip()
    if not mode:
        raise CampaignPublicationError("publication_semantic_invalid")
    return mode


def _model_metadata(payload: Mapping[str, Any]) -> Any:
    return payload.get("model_metadata") or payload.get("model") or {}


def _common_value(payloads: Sequence[Mapping[str, Any]], key: str) -> str:
    values = {str(payload.get(key) or "").strip() for payload in payloads}
    if len(values) != 1 or "" in values:
        raise CampaignPublicationError("publication_semantic_invalid")
    return values.pop()


def _common_json_value(payloads: Sequence[Mapping[str, Any]], key: str) -> Any:
    values: dict[str, Any] = {}
    for payload in payloads:
        value = payload.get(key)
        if value is None or value == "":
            raise CampaignPublicationError("publication_semantic_invalid")
        values[_canonical_json(value)] = value
    if len(values) != 1:
        raise CampaignPublicationError("publication_semantic_invalid")
    return next(iter(values.values()))


def _common_execution_mode(payloads: Sequence[Mapping[str, Any]]) -> str:
    modes = {_execution_mode(payload) for payload in payloads}
    if len(modes) != 1:
        raise CampaignPublicationError("publication_semantic_invalid")
    return modes.pop()


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


def _required_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CampaignPublicationError("publication_semantic_invalid")
    return value


def _published_provenance(
    provenance: Mapping[str, Any],
    *,
    campaign: Mapping[str, Any],
    systems: Mapping[str, Mapping[str, Any]],
    scenarios: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    # Provenance is a public allowlisted contract. In particular, never copy
    # the internal per-variable environment digests: low-entropy values such
    # as private IPs, HOME, PATH, ports, and acknowledgement flags are readily
    # recoverable from an unsalted SHA-256 oracle. Those values still affect
    # the aggregate campaign fingerprint used by the private resume journal.
    payload = {
        str(key): value
        for key, value in provenance.items()
        if str(key) in _PUBLIC_PROVENANCE_KEYS and str(key) != "input_sha256"
    }
    payload["input_sha256"] = {
        "campaign": _canonical_digest(campaign),
        "systems": {
            system_id: _canonical_digest(value)
            for system_id, value in sorted(systems.items())
        },
        "scenarios": {
            scenario_id: _canonical_digest(value)
            for scenario_id, value in sorted(scenarios.items())
        },
    }
    return payload


def _verify_provenance_inputs(
    provenance: Mapping[str, Any],
    *,
    campaign: Mapping[str, Any],
    systems: Mapping[str, Mapping[str, Any]],
    scenarios: Mapping[str, Mapping[str, Any]],
) -> None:
    if set(provenance) != _PUBLIC_PROVENANCE_KEYS:
        raise CampaignPublicationError("publication_semantic_invalid")
    inputs = _required_mapping(provenance.get("input_sha256"))
    if set(inputs) != _PUBLIC_PROVENANCE_INPUT_KEYS:
        raise CampaignPublicationError("publication_semantic_invalid")
    observed_systems = _required_mapping(inputs.get("systems"))
    observed_scenarios = _required_mapping(inputs.get("scenarios"))
    expected_systems = {
        system_id: _canonical_digest(value)
        for system_id, value in sorted(systems.items())
    }
    expected_scenarios = {
        scenario_id: _canonical_digest(value)
        for scenario_id, value in sorted(scenarios.items())
    }
    if (
        inputs.get("campaign") != _canonical_digest(campaign)
        or not _json_equal(observed_systems, expected_systems)
        or not _json_equal(observed_scenarios, expected_scenarios)
    ):
        raise CampaignPublicationError("publication_semantic_invalid")


def _stable_id(namespace: str, payload: Any) -> str:
    return f"{namespace}://sha256/{_canonical_digest(payload)}"


def _canonical_digest(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _json_equal(left: Any, right: Any) -> bool:
    return _canonical_json(left) == _canonical_json(right)


def _scan_secret_canaries(root: Path, canaries: Sequence[str]) -> None:
    encoded = tuple(
        dict.fromkeys(
            str(value).encode("utf-8")
            for value in canaries
            if str(value)
        )
    )
    if not encoded:
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        content = path.read_bytes()
        if any(value in content for value in encoded):
            raise SecretCanaryDetected("secret_canary_detected")


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_component(value: str) -> str:
    candidate = str(value)
    if (
        not candidate
        or candidate in {".", ".."}
        or any(character in candidate for character in ("/", "\\", "\x00"))
    ):
        raise CampaignPublicationError("unsafe_publication_path")
    return candidate


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


__all__ = [
    "CAMPAIGN_PUBLICATION_SCHEMA_VERSION",
    "CampaignPublicationError",
    "SecretCanaryDetected",
    "publish_campaign_bundle",
    "verify_campaign_bundle",
]
