"""Versioned, resumable lifecycle for one-command competitor campaigns."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..harness import BenchmarkRunner
from ..schema import (
    MIN_BENCHMARK_REPETITIONS,
    BenchmarkScenario,
    BenchmarkSchemaError,
    load_scenarios,
)
from ..v3.analysis import AnalysisPlan
from ..v3.publication import publish_v3_results, verify_v3_results
from ..v3.schema import BenchmarkRunV3, BenchmarkV3SchemaError
from .lab import (
    CommandLabController,
    LabCommand,
    LabControlError,
    LabResetError,
    LabRunContext,
    ResetAttestation,
)
from .matrix import CompetitorMatrixResult, run_competitor_matrix
from .preflight import (
    CampaignPreflightError,
    run_campaign_preflight,
)
from .publication import publish_campaign_bundle, verify_campaign_bundle
from .runner import CommandSystemRunner
from .schema import (
    CompetitorSchemaError,
    SystemManifest,
    load_system_manifest,
)
from .state import CampaignJournal, campaign_fingerprint, schedule_run_key
from .v3_integration import (
    BenchmarkV3CampaignConfig,
    build_v3_run,
    controller_ledger_records,
    fixture_reveals,
    planned_fixture_seed,
    validate_campaign_plan,
)

CAMPAIGN_CONFIG_SCHEMA_VERSION = "1.0"
_KNOWN_STRICT_STATUSES = frozenset({"failed", "invalid", "partial", "timeout"})
_RUN_STATUSES = _KNOWN_STRICT_STATUSES | {"succeeded"}
_ERROR_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_CAMPAIGN_CONFIG_KEYS = frozenset(
    {
        "$schema",
        "benchmark_v3",
        "campaign_id",
        "campaign_definition",
        "environment_file",
        "lab",
        "output_directory",
        "repetitions",
        "required_environment",
        "scenario_directory",
        "schema_version",
        "secret_environment",
        "state_directory",
        "strict_statuses",
        "system_manifests",
    }
)


class CampaignConfigError(ValueError):
    """A campaign config cannot satisfy schema 1.0."""


class CampaignAbortedError(RuntimeError):
    """Lab control aborted a resumable campaign before the next adapter run."""


class LabController(Protocol):
    def reset_and_health(self, context: LabRunContext) -> ResetAttestation: ...

    def cleanup(self, context: LabRunContext) -> None: ...


@dataclass(frozen=True)
class CampaignConfig:
    campaign_id: str
    system_manifest_paths: tuple[Path, ...]
    scenario_directory: Path
    output_directory: Path
    state_directory: Path
    repetitions: int
    reset_command: LabCommand
    health_command: LabCommand
    cleanup_command: LabCommand | None = None
    required_environment: tuple[str, ...] = ()
    secret_environment: tuple[str, ...] = ()
    environment_file: Path | None = None
    campaign_definition: str | None = None
    benchmark_v3: BenchmarkV3CampaignConfig | None = None
    strict_statuses: tuple[str, ...] = tuple(sorted(_KNOWN_STRICT_STATUSES))
    source_path: Path | None = None
    schema_version: str = CAMPAIGN_CONFIG_SCHEMA_VERSION

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        source_path: str | Path | None = None,
    ) -> CampaignConfig:
        if str(payload.get("schema_version") or "") != CAMPAIGN_CONFIG_SCHEMA_VERSION:
            raise CampaignConfigError("unsupported_campaign_config_schema")
        if set(payload) - _CAMPAIGN_CONFIG_KEYS:
            raise CampaignConfigError("unknown_campaign_config_key")
        campaign_id = _identifier(payload.get("campaign_id"), "campaign_id")
        base = (
            Path(source_path).resolve().parent
            if source_path is not None
            else Path.cwd().resolve()
        )
        manifests = _path_sequence(
            payload.get("system_manifests"),
            base=base,
            name="system_manifests",
        )
        if len(manifests) < 2:
            raise CampaignConfigError("campaign_requires_two_system_manifests")
        scenario_directory = _resolved_path(
            payload.get("scenario_directory"), base=base, name="scenario_directory"
        )
        output_directory = _resolved_path(
            payload.get("output_directory"), base=base, name="output_directory"
        )
        state_directory = _resolved_path(
            payload.get("state_directory"), base=base, name="state_directory"
        )
        repetitions = _positive_integer(payload.get("repetitions", MIN_BENCHMARK_REPETITIONS))
        if repetitions < MIN_BENCHMARK_REPETITIONS:
            raise CampaignConfigError(
                f"repetitions_below_minimum:{MIN_BENCHMARK_REPETITIONS}"
            )
        lab = payload.get("lab")
        if not isinstance(lab, Mapping):
            raise CampaignConfigError("invalid:lab")
        if set(lab) - {"reset", "health", "cleanup"}:
            raise CampaignConfigError("unknown_lab_config_key")
        reset_payload = lab.get("reset")
        health_payload = lab.get("health")
        if not isinstance(reset_payload, Mapping) or not isinstance(health_payload, Mapping):
            raise CampaignConfigError("lab_requires_reset_and_health")
        try:
            reset = LabCommand.from_dict(reset_payload, base_directory=base)
            health = LabCommand.from_dict(health_payload, base_directory=base)
            cleanup_payload = lab.get("cleanup")
            cleanup = (
                LabCommand.from_dict(cleanup_payload, base_directory=base)
                if isinstance(cleanup_payload, Mapping)
                else None
            )
        except LabControlError as exc:
            raise CampaignConfigError(str(exc)) from exc
        required_environment = _environment_names(
            payload.get("required_environment") or [],
            "required_environment",
        )
        secret_environment = _environment_names(
            payload.get("secret_environment") or [],
            "secret_environment",
        )
        if not set(secret_environment).issubset(required_environment):
            raise CampaignConfigError("secret_environment_must_be_required")
        raw_environment_file = payload.get("environment_file")
        environment_file = (
            _resolved_path(raw_environment_file, base=base, name="environment_file")
            if raw_environment_file
            else None
        )
        raw_campaign_definition = payload.get("campaign_definition")
        campaign_definition = (
            _identifier(raw_campaign_definition, "campaign_definition")
            if raw_campaign_definition
            else None
        )
        raw_benchmark_v3 = payload.get("benchmark_v3")
        if raw_benchmark_v3 is not None and not isinstance(raw_benchmark_v3, Mapping):
            raise CampaignConfigError("invalid:benchmark_v3")
        try:
            benchmark_v3 = (
                BenchmarkV3CampaignConfig.from_dict(
                    raw_benchmark_v3,
                    base_directory=base,
                )
                if isinstance(raw_benchmark_v3, Mapping)
                else None
            )
        except BenchmarkV3SchemaError as exc:
            raise CampaignConfigError(str(exc)) from exc
        strict_statuses = tuple(
            sorted(
                set(
                    _identifiers(
                        payload.get("strict_statuses") or sorted(_KNOWN_STRICT_STATUSES),
                        "strict_statuses",
                    )
                )
            )
        )
        if not set(strict_statuses).issubset(_KNOWN_STRICT_STATUSES):
            raise CampaignConfigError("invalid:strict_statuses")
        return cls(
            campaign_id=campaign_id,
            system_manifest_paths=manifests,
            scenario_directory=scenario_directory,
            output_directory=output_directory,
            state_directory=state_directory,
            repetitions=repetitions,
            reset_command=reset,
            health_command=health,
            cleanup_command=cleanup,
            required_environment=required_environment,
            secret_environment=secret_environment,
            environment_file=environment_file,
            campaign_definition=campaign_definition,
            benchmark_v3=benchmark_v3,
            strict_statuses=strict_statuses,
            source_path=Path(source_path).resolve() if source_path is not None else None,
        )

    def fingerprint_payload(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "repetitions": self.repetitions,
            "required_environment": list(self.required_environment),
            "secret_environment": list(self.secret_environment),
            "strict_statuses": list(self.strict_statuses),
            "lab": {
                "reset": self.reset_command.to_dict(),
                "health": self.health_command.to_dict(),
                "cleanup": (
                    self.cleanup_command.to_dict()
                    if self.cleanup_command is not None
                    else None
                ),
            },
        }
        if self.campaign_definition is not None:
            payload["campaign_definition"] = self.campaign_definition
        if self.benchmark_v3 is not None:
            payload["benchmark_v3"] = self.benchmark_v3.fingerprint_payload()
        return payload

    def public_payload(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "repetitions": self.repetitions,
            "required_environment": list(self.required_environment),
            "secret_environment": list(self.secret_environment),
            "strict_statuses": list(self.strict_statuses),
            "system_manifest_names": [path.name for path in self.system_manifest_paths],
            "scenario_directory_name": self.scenario_directory.name,
            "lab_control": {
                "reset_sha256": _canonical_digest(self.reset_command.to_dict()),
                "health_sha256": _canonical_digest(self.health_command.to_dict()),
                "cleanup_sha256": (
                    _canonical_digest(self.cleanup_command.to_dict())
                    if self.cleanup_command is not None
                    else None
                ),
            },
        }
        if self.campaign_definition is not None:
            payload["campaign_definition"] = self.campaign_definition
        if self.benchmark_v3 is not None:
            payload["benchmark_v3"] = self.benchmark_v3.public_payload()
        return payload


@dataclass(frozen=True)
class CampaignOutcome:
    campaign_id: str
    fingerprint: str
    status: str
    bundle_path: Path
    matrix: CompetitorMatrixResult
    executed_runs: int
    resumed_runs: int
    exit_code: int


def load_campaign_config(path: str | Path) -> CampaignConfig:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CampaignConfigError("campaign_config_load_failed") from exc
    if not isinstance(payload, Mapping):
        raise CampaignConfigError("campaign_config_not_mapping")
    return CampaignConfig.from_dict(payload, source_path=source)


def run_campaign(
    config: CampaignConfig | str | Path,
    *,
    environment: Mapping[str, str] | None = None,
    runner_factory: Callable[[SystemManifest], BenchmarkRunner] = CommandSystemRunner,
    lab_controller: LabController | None = None,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> CampaignOutcome:
    """Preflight, execute/resume, aggregate, and publish one campaign."""

    resolved = load_campaign_config(config) if isinstance(config, (str, Path)) else config
    manifests = tuple(load_system_manifest(path) for path in resolved.system_manifest_paths)
    scenarios = load_scenarios(resolved.scenario_directory)
    v3_plan = (
        validate_campaign_plan(
            resolved.benchmark_v3,
            system_ids=tuple(item.system_id for item in manifests),
            scenarios=scenarios,
            repetitions=resolved.repetitions,
        )
        if resolved.benchmark_v3 is not None
        else None
    )
    effective_environment = _effective_environment(resolved, environment)
    required_environment = tuple(
        sorted(
            set(resolved.required_environment).union(
                name
                for manifest in manifests
                for name in manifest.adapter.env_passthrough
            ).union(resolved.reset_command.environment_passthrough)
            .union(resolved.health_command.environment_passthrough)
            .union(
                resolved.cleanup_command.environment_passthrough
                if resolved.cleanup_command is not None
                else ()
            )
        )
    )
    secret_names = set(resolved.secret_environment).union(
        name for name in required_environment if _looks_secret_name(name)
    )
    secret_canaries = tuple(
        effective_environment[name]
        for name in sorted(secret_names)
        if effective_environment.get(name)
    )
    environment_identity = {
        name: hashlib.sha256(effective_environment.get(name, "").encode("utf-8")).hexdigest()
        for name in required_environment
        if name not in secret_names
    }
    preflight = run_campaign_preflight(
        campaign_id=resolved.campaign_id,
        output_directory=resolved.output_directory,
        manifests=manifests,
        scenarios=scenarios,
        required_environment=required_environment,
        environment=effective_environment,
        reset_command=resolved.reset_command,
        health_command=resolved.health_command,
        placeholder_inputs=(("campaign", resolved.fingerprint_payload()),),
        environment_file=resolved.environment_file,
    )
    preflight.raise_for_failure()

    schedule = _build_schedule(
        resolved,
        manifests,
        scenarios,
        v3_plan=v3_plan,
    )
    controller_source_identity = _controller_source_identity()
    fingerprint = campaign_fingerprint(
        {
            "config": resolved.fingerprint_payload(),
            "systems": [item.to_dict() for item in manifests],
            "scenarios": [item.to_dict() for item in scenarios],
            "schedule": schedule,
            "environment_sha256": environment_identity,
            "controller_source_sha256": controller_source_identity,
        }
    )
    journal = CampaignJournal(
        resolved.state_directory,
        campaign_id=resolved.campaign_id,
        fingerprint=fingerprint,
    )
    controller = lab_controller or CommandLabController(
        resolved.reset_command,
        resolved.health_command,
        cleanup=resolved.cleanup_command,
        environment=effective_environment,
        clock=clock,
        monotonic=monotonic,
    )
    scenario_by_id = {item.scenario_id: item for item in scenarios}
    final_context = _scheduled_context(
        resolved.campaign_id,
        schedule[-1],
        scenario_by_id,
    )
    executed_runs = 0
    resumed_runs = 0
    last_context: LabRunContext | None = None
    cleanup_attestation: dict[str, Any] | None = None

    with journal.lock():
        journal.initialize(schedule)
        journal.write_preflight(preflight.to_dict())
        completed_at_start = journal.completed_run_count()
        journal.set_status("running", completed_runs=completed_at_start)
        _emit_progress(
            "campaign_started",
            campaign_id=resolved.campaign_id,
            completed_runs=completed_at_start,
            total_runs=len(schedule),
        )
        runners = {item.system_id: runner_factory(item) for item in manifests}
        with _temporary_environment(effective_environment):
            try:
                for scheduled in schedule:
                    run_key = str(scheduled["run_key"])
                    if journal.read_run(run_key) is not None:
                        resumed_runs += 1
                        continue
                    system_id = str(scheduled["system_id"])
                    scenario_id = str(scheduled["scenario_id"])
                    scenario = scenario_by_id[scenario_id]
                    _emit_progress(
                        "run_started",
                        campaign_id=resolved.campaign_id,
                        order=int(scheduled["order"]),
                        total_runs=len(schedule),
                        system_id=system_id,
                        scenario_id=scenario_id,
                        repetition=int(scheduled["repetition"]),
                    )
                    context = _scheduled_context(
                        resolved.campaign_id,
                        scheduled,
                        scenario_by_id,
                    )
                    last_context = context
                    attestation = controller.reset_and_health(context)
                    journal.write_attestation(run_key, attestation.to_dict())
                    started_at = float(clock())
                    started = monotonic()
                    error_class = ""
                    try:
                        raw_result = runners[system_id](
                            scenario,
                            context.repetition,
                            context.seed,
                        )
                        if not isinstance(raw_result, Mapping):
                            raise TypeError("campaign runner must return a mapping")
                        result = dict(raw_result)
                    except Exception as exc:
                        error_class = type(exc).__name__
                        result = _failed_result(max(0.0, monotonic() - started))
                    result["duration_seconds"] = _nonnegative_duration(
                        result.get("duration_seconds"),
                        default=max(0.0, monotonic() - started),
                    )
                    result["status"] = str(result.get("status") or "succeeded").lower()
                    if result["status"] not in _RUN_STATUSES:
                        error_class = "InvalidRunnerStatus"
                        result = _failed_result(max(0.0, monotonic() - started))
                    if _contains_secret_canary(result, secret_canaries):
                        error_class = "SecretCanaryDetected"
                        result = _failed_result(max(0.0, monotonic() - started))
                    reported_error_class = result.pop("error_class", "")
                    if not error_class and reported_error_class:
                        error_class = _safe_error_class(reported_error_class)
                    # Persist the wall-clock interval at execution time.  The
                    # matrix is assembled later by replaying the journal, so
                    # timing it again would publish replay timestamps beside
                    # the original (potentially minutes-long) duration.
                    result["started_at"] = started_at
                    result["finished_at"] = float(clock())
                    v3_run = (
                        build_v3_run(
                            config=resolved.benchmark_v3,
                            plan=v3_plan,
                            scenario=scenario,
                            system_id=system_id,
                            repetition=context.repetition,
                            seed=context.seed,
                            result={**result, "error_class": error_class},
                            started_at=started_at,
                            finished_at=float(result["finished_at"]),
                            reset_attestation=attestation.to_dict(),
                        )
                        if resolved.benchmark_v3 is not None and v3_plan is not None
                        else None
                    )
                    journal.write_run(
                        run_key,
                        {
                            "system_id": system_id,
                            "scenario_id": scenario_id,
                            "repetition": context.repetition,
                            "seed": context.seed,
                            "error_class": error_class,
                            "result": result,
                            **(
                                {"benchmark_v3": v3_run.to_dict()}
                                if v3_run is not None
                                else {}
                            ),
                        },
                    )
                    executed_runs += 1
                    _emit_progress(
                        "run_finished",
                        campaign_id=resolved.campaign_id,
                        order=int(scheduled["order"]),
                        total_runs=len(schedule),
                        system_id=system_id,
                        scenario_id=scenario_id,
                        repetition=context.repetition,
                        status=str(result["status"]),
                        duration_seconds=round(
                            float(result["duration_seconds"]),
                            6,
                        ),
                    )
            except LabResetError as exc:
                journal.set_status(
                    "aborted",
                    reason=str(exc),
                    completed_runs=journal.completed_run_count(),
                )
                raise CampaignAbortedError(str(exc)) from None
            except KeyboardInterrupt:
                journal.set_status(
                    "interrupted",
                    completed_runs=journal.completed_run_count(),
                )
                _emit_progress(
                    "campaign_interrupted",
                    campaign_id=resolved.campaign_id,
                    completed_runs=journal.completed_run_count(),
                    total_runs=len(schedule),
                )
                raise
            finally:
                cleanup_attestation = _run_cleanup(
                    controller,
                    last_context or final_context,
                    command_configured=resolved.cleanup_command is not None,
                    clock=clock,
                    monotonic=monotonic,
                )
                journal.write_cleanup_attestation(cleanup_attestation)

        cleanup_attestation = journal.read_cleanup_attestation()
        if cleanup_attestation is None:
            raise RuntimeError("campaign_cleanup_attestation_missing")
        cleanup_failed = cleanup_attestation["status"] != "succeeded"

        matrix = run_competitor_matrix(
            manifests,
            scenarios,
            repetitions=resolved.repetitions,
            runner_factory=_journal_runner_factory(journal, v3_plan=v3_plan),
            clock=clock,
        )
        status_counts = Counter(
            run.status
            for aggregates in matrix.aggregates.values()
            for aggregate in aggregates.values()
            for run in aggregate.runs
        )
        v3_runs = (
            _journal_v3_runs(journal, schedule)
            if v3_plan is not None
            else ()
        )
        if v3_runs:
            status_counts = Counter(run.execution_status for run in v3_runs)
            task_status_counts = Counter(run.task_status for run in v3_runs)
            policy_violations = sum(
                len(run.policy_violations) for run in v3_runs
            )
        else:
            task_status_counts = Counter()
            policy_violations = sum(
                len(run.policy_violations)
                for aggregates in matrix.aggregates.values()
                for aggregate in aggregates.values()
                for run in aggregate.runs
            )
        run_failure = policy_violations > 0 or any(
            status_counts.get(status, 0) > 0 for status in resolved.strict_statuses
        )
        if v3_runs and task_status_counts.get("completed", 0) != len(v3_runs):
            run_failure = True
        strict_failure = run_failure or cleanup_failed
        campaign_outcome_status = (
            "partial"
            if cleanup_failed
            else "completed_with_failures"
            if run_failure
            else "succeeded"
        )
        campaign_status = {
            "status": campaign_outcome_status,
            "status_counts": dict(sorted(status_counts.items())),
            **(
                {"task_status_counts": dict(sorted(task_status_counts.items()))}
                if v3_runs
                else {}
            ),
            "policy_violations": policy_violations,
            "executed_runs": executed_runs,
            "resumed_runs": resumed_runs,
            "cleanup_status": cleanup_attestation["status"],
        }
        provenance = _provenance(
            resolved,
            manifests,
            scenarios,
            fingerprint=fingerprint,
            controller_source_identity=controller_source_identity,
        )
        try:
            if v3_plan is not None:
                v3_config = resolved.benchmark_v3
                if v3_config is None:
                    raise CampaignConfigError("missing_benchmark_v3_config")
                campaign_context = {
                    "attestations": journal.read_attestations(),
                    "campaign": resolved.public_payload(),
                    "campaign_status": campaign_status,
                    "cleanup": cleanup_attestation,
                    "fingerprint": fingerprint,
                    "fixture_reveals": fixture_reveals(
                        v3_config,
                        v3_plan,
                        campaign_id=resolved.campaign_id,
                    ),
                    "preflight": preflight.to_dict(),
                    "provenance": provenance,
                    "scenarios": [item.to_dict() for item in scenarios],
                    "schema_version": "1.0",
                    "systems": [item.to_dict() for item in manifests],
                }
                if _contains_secret_canary(campaign_context, secret_canaries):
                    raise CampaignConfigError("secret_canary_detected")
                bundle = publish_v3_results(
                    v3_plan,
                    v3_runs,
                    resolved.output_directory,
                    campaign_context=campaign_context,
                    controller_ledgers=controller_ledger_records(
                        v3_config,
                        v3_runs,
                        campaign_id=resolved.campaign_id,
                    ),
                )
                verify_v3_results(bundle)
            else:
                bundle = publish_campaign_bundle(
                    destination=resolved.output_directory,
                    matrix=matrix,
                    campaign=resolved.public_payload(),
                    fingerprint=fingerprint,
                    manifests=manifests,
                    scenarios=scenarios,
                    preflight=preflight.to_dict(),
                    schedule=schedule,
                    attestations=journal.read_attestations(),
                    cleanup=cleanup_attestation,
                    provenance=provenance,
                    campaign_status=campaign_status,
                    secret_canaries=secret_canaries,
                )
        except Exception as exc:
            journal.set_status("publication_failed", reason=type(exc).__name__)
            raise
        if v3_plan is None:
            verify_campaign_bundle(bundle)
        journal.set_status(
            "published",
            matrix_id=matrix.matrix_id,
            output_directory_name=resolved.output_directory.name,
            cleanup_status=cleanup_attestation["status"],
        )
        _emit_progress(
            "campaign_published",
            campaign_id=resolved.campaign_id,
            completed_runs=journal.completed_run_count(),
            total_runs=len(schedule),
            status=campaign_outcome_status,
        )
        return CampaignOutcome(
            campaign_id=resolved.campaign_id,
            fingerprint=fingerprint,
            status=campaign_outcome_status,
            bundle_path=bundle,
            matrix=matrix,
            executed_runs=executed_runs,
            resumed_runs=resumed_runs,
            exit_code=1 if strict_failure else 0,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a resumable competitor benchmark campaign.")
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        outcome = run_campaign(args.config)
    except CampaignPreflightError as exc:
        print(json.dumps(exc.report.to_dict(), sort_keys=True), file=sys.stderr)
        return 2
    except CampaignAbortedError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except (
        BenchmarkSchemaError,
        BenchmarkV3SchemaError,
        CampaignConfigError,
        CompetitorSchemaError,
        LabControlError,
        OSError,
    ) as exc:
        print(f"campaign failed: {exc}", file=sys.stderr)
        return 2
    print(outcome.bundle_path)
    return outcome.exit_code


def _build_schedule(
    config: CampaignConfig,
    manifests: Sequence[SystemManifest],
    scenarios: Sequence[BenchmarkScenario],
    *,
    v3_plan: AnalysisPlan | None = None,
) -> tuple[dict[str, Any], ...]:
    schedule: list[dict[str, Any]] = []
    order = 0
    for repetition in range(1, config.repetitions + 1):
        for scenario in scenarios:
            seed = (
                planned_fixture_seed(
                    v3_plan,
                    scenario_id=scenario.scenario_id,
                    repetition=repetition,
                )
                if v3_plan is not None
                else scenario.seed + repetition - 1
            )
            for manifest in _counterbalanced_order(manifests, repetition):
                order += 1
                schedule.append(
                    {
                        "order": order,
                        "run_key": schedule_run_key(
                            manifest.system_id,
                            scenario.scenario_id,
                            repetition,
                            seed,
                        ),
                        "system_id": manifest.system_id,
                        "scenario_id": scenario.scenario_id,
                        "repetition": repetition,
                        "seed": seed,
                    }
                )
    return tuple(schedule)


def _scheduled_context(
    campaign_id: str,
    scheduled: Mapping[str, Any],
    scenarios: Mapping[str, BenchmarkScenario],
) -> LabRunContext:
    scenario_id = str(scheduled["scenario_id"])
    scenario = scenarios[scenario_id]
    return LabRunContext(
        campaign_id=campaign_id,
        system_id=str(scheduled["system_id"]),
        scenario_id=scenario_id,
        repetition=int(scheduled["repetition"]),
        seed=int(scheduled["seed"]),
        lab_version=str(scenario.lab.get("version") or ""),
        snapshot_ref=str(scenario.lab.get("snapshot_ref") or ""),
    )


def _counterbalanced_order(
    manifests: Sequence[SystemManifest],
    repetition: int,
) -> tuple[SystemManifest, ...]:
    """Return a deterministic Williams-style order for the repetition."""

    ordered = list(manifests)
    if not ordered:
        return ()
    size = len(ordered)
    offset = (repetition - 1) % size
    cycle = (repetition - 1) // size
    if size % 2 == 0:
        # Williams base row for even N: 0, 1, N-1, 2, N-2, ... . Its N
        # modular rotations contain every directed adjacent pair once.
        indices = [0]
        low, high = 1, size - 1
        while low <= high:
            indices.append(low)
            low += 1
            if low <= high:
                indices.append(high)
                high -= 1
        ordered = [ordered[(index + offset) % size] for index in indices]
    else:
        ordered = ordered[offset:] + ordered[:offset]
    if cycle % 2:
        ordered.reverse()
    return tuple(ordered)


def _journal_runner_factory(
    journal: CampaignJournal,
    *,
    v3_plan: AnalysisPlan | None = None,
) -> Callable[[SystemManifest], BenchmarkRunner]:
    def factory(manifest: SystemManifest) -> BenchmarkRunner:
        def replay(
            scenario: BenchmarkScenario,
            repetition: int,
            seed: int,
        ) -> Mapping[str, Any]:
            scheduled_seed = (
                planned_fixture_seed(
                    v3_plan,
                    scenario_id=scenario.scenario_id,
                    repetition=repetition,
                )
                if v3_plan is not None
                else seed
            )
            run_key = schedule_run_key(
                manifest.system_id,
                scenario.scenario_id,
                repetition,
                scheduled_seed,
            )
            record = journal.read_run(run_key)
            if record is None:
                raise RuntimeError("campaign_journal_run_missing")
            result = record.get("result")
            if not isinstance(result, Mapping):
                raise RuntimeError("campaign_journal_result_invalid")
            replayed = dict(result)
            replayed["error_class"] = _safe_error_class(
                record.get("error_class") or ""
            )
            return replayed

        return replay

    return factory


def _journal_v3_runs(
    journal: CampaignJournal,
    schedule: Sequence[Mapping[str, Any]],
) -> tuple[BenchmarkRunV3, ...]:
    runs: list[BenchmarkRunV3] = []
    for scheduled in schedule:
        record = journal.read_run(str(scheduled["run_key"]))
        payload = record.get("benchmark_v3") if isinstance(record, Mapping) else None
        if not isinstance(payload, Mapping):
            raise BenchmarkV3SchemaError("campaign_v3_run_missing")
        runs.append(BenchmarkRunV3.from_dict(payload))
    return tuple(runs)


def _effective_environment(
    config: CampaignConfig,
    supplied: Mapping[str, str] | None,
) -> dict[str, str]:
    environment: dict[str, str] = {}
    if config.environment_file is not None:
        environment.update(_load_environment_file(config.environment_file))
    environment.update(
        {
            str(key): str(value)
            for key, value in (os.environ if supplied is None else supplied).items()
        }
    )
    return environment


def _load_environment_file(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise CampaignConfigError("environment_file_load_failed") from exc
    result: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or "=" not in line:
            raise CampaignConfigError("invalid_environment_file")
        name, value = line.split("=", 1)
        name = name.strip()
        if not _valid_environment_name(name):
            raise CampaignConfigError("invalid_environment_file_name")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if "\x00" in value or "\n" in value:
            raise CampaignConfigError("invalid_environment_file_value")
        result[name] = value
    return result


@contextmanager
def _temporary_environment(values: Mapping[str, str]) -> Iterator[None]:
    previous = dict(os.environ)
    os.environ.clear()
    os.environ.update({str(key): str(value) for key, value in values.items()})
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def _provenance(
    config: CampaignConfig,
    manifests: Sequence[SystemManifest],
    scenarios: Sequence[BenchmarkScenario],
    *,
    fingerprint: str,
    controller_source_identity: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": CAMPAIGN_CONFIG_SCHEMA_VERSION,
        "fingerprint": fingerprint,
        "repository_revision": _repository_revision(),
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "controller_source_sha256": dict(sorted(controller_source_identity.items())),
        "input_sha256": {
            "campaign": _canonical_digest(config.fingerprint_payload()),
            "systems": {
                item.system_id: _canonical_digest(item.to_dict()) for item in manifests
            },
            "scenarios": {
                item.scenario_id: _canonical_digest(item.to_dict()) for item in scenarios
            },
        },
    }


def _repository_revision() -> str:
    root = Path(__file__).resolve().parents[3]
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=2,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    revision = completed.stdout.strip().lower()
    return revision if len(revision) == 40 else "unknown"


def _emit_progress(event: str, **fields: Any) -> None:
    """Write one bounded, secret-free progress event for long live campaigns."""

    payload = {"event": event, **fields}
    print(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        file=sys.stderr,
        flush=True,
    )


def _controller_source_identity() -> dict[str, str]:
    competitor_root = Path(__file__).resolve().parent
    benchmark_root = competitor_root.parent
    sources = [
        *sorted(competitor_root.glob("*.py")),
        *sorted((benchmark_root / "v3").glob("*.py")),
        benchmark_root / "harness.py",
        benchmark_root / "schema.py",
    ]
    return {
        path.relative_to(benchmark_root.parent.parent).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sources
    }


def _failed_result(duration_seconds: float) -> dict[str, Any]:
    return {
        "status": "failed",
        "actions": [],
        "reported_findings": [],
        "verified_findings": [],
        "coverage_gaps": [],
        "metrics": {},
        "artifact_refs": [],
        "duration_seconds": duration_seconds,
    }


def _safe_error_class(value: Any) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    return candidate if _ERROR_CLASS.fullmatch(candidate) else "InvalidRunnerErrorClass"


def _nonnegative_duration(value: Any, *, default: float) -> float:
    if isinstance(value, bool):
        return float(default)
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return float(default)
    return parsed if math.isfinite(parsed) and parsed >= 0 else float(default)


def _run_cleanup(
    controller: LabController,
    context: LabRunContext,
    *,
    command_configured: bool,
    clock: Callable[[], float],
    monotonic: Callable[[], float],
) -> dict[str, Any]:
    started = monotonic()
    status = "succeeded"
    error_class = ""
    try:
        controller.cleanup(context)
    except Exception as exc:
        status = "failed"
        error_class = type(exc).__name__
    return {
        "status": status,
        "command_configured": command_configured,
        "campaign_id": context.campaign_id,
        "system_id": context.system_id,
        "scenario_id": context.scenario_id,
        "repetition": context.repetition,
        "seed": context.seed,
        "lab_version": context.lab_version,
        "snapshot_ref": context.snapshot_ref,
        "duration_seconds": round(max(0.0, monotonic() - started), 6),
        "observed_at": float(clock()),
        "error_class": error_class,
    }


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _resolved_path(value: Any, *, base: Path, name: str) -> Path:
    text = str(value or "").strip()
    if not text or "\x00" in text:
        raise CampaignConfigError(f"invalid:{name}")
    return (base / text).resolve()


def _path_sequence(value: Any, *, base: Path, name: str) -> tuple[Path, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise CampaignConfigError(f"invalid:{name}")
    paths = tuple(_resolved_path(item, base=base, name=name) for item in value)
    if len(paths) != len(set(paths)):
        raise CampaignConfigError(f"duplicate:{name}")
    return paths


def _positive_integer(value: Any) -> int:
    if isinstance(value, bool):
        raise CampaignConfigError("invalid_integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CampaignConfigError("invalid_integer") from exc
    if parsed <= 0:
        raise CampaignConfigError("invalid_integer")
    return parsed


def _identifier(value: Any, name: str) -> str:
    candidate = str(value or "").strip().lower()
    if (
        not candidate
        or len(candidate) > 128
        or not candidate[0].isalnum()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for character in candidate)
    ):
        raise CampaignConfigError(f"invalid_identifier:{name}")
    return candidate


def _identifiers(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise CampaignConfigError(f"invalid:{name}")
    return tuple(_identifier(item, name) for item in value)


def _environment_names(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise CampaignConfigError(f"invalid:{name}")
    result: list[str] = []
    for item in value:
        candidate = str(item or "").strip()
        if not _valid_environment_name(candidate):
            raise CampaignConfigError(f"invalid:{name}")
        if candidate not in result:
            result.append(candidate)
    return tuple(result)


def _valid_environment_name(value: str) -> bool:
    return bool(value) and value.isascii() and (value[0].isalpha() or value[0] == "_") and all(
        character.isalnum() or character == "_" for character in value
    )


def _looks_secret_name(value: str) -> bool:
    upper = value.upper()
    return any(
        marker in upper
        for marker in ("API_KEY", "CREDENTIAL", "PASSWORD", "SECRET", "TOKEN")
    )


def _contains_secret_canary(value: Any, canaries: Sequence[str]) -> bool:
    if not canaries:
        return False
    encoded = json.dumps(value, sort_keys=True, default=str)
    return any(canary and canary in encoded for canary in canaries)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CAMPAIGN_CONFIG_SCHEMA_VERSION",
    "CampaignAbortedError",
    "CampaignConfig",
    "CampaignConfigError",
    "CampaignOutcome",
    "load_campaign_config",
    "main",
    "run_campaign",
]
