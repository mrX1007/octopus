"""Private execution lifecycle for the prospective Benchmark v4 readiness gate."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from ..harness import BenchmarkRunner
from ..schema import BenchmarkScenario
from ..v3.analysis import AnalysisPlan
from ..v3.fixture import load_private_fixture
from ..v3.schema import BenchmarkRunV3, canonical_json, stable_digest
from ..v4 import EfficiencyPlan
from ..v4.readiness import (
    READINESS_PHASE,
    BenchmarkV4ReadinessError,
    ReadinessEvidence,
    ReadinessPlan,
    ReadinessProfile,
    assert_full_campaign_ready,
    assess_readiness,
    freeze_readiness_evidence,
    load_readiness_evidence,
    load_readiness_plan,
    load_readiness_profile,
    validate_readiness_plan,
    verify_readiness_evidence,
)
from .lab import (
    LAB_CONTROL_SCHEMA_VERSION,
    CommandLabController,
    LabRunContext,
    ResetAttestation,
    _command_digest,
)
from .labctl import LabControlError as LabCtlError
from .labctl import _canonical_target
from .runner import CommandSystemRunner
from .schema import SystemManifest
from .state import CampaignJournal, campaign_fingerprint, schedule_run_key
from .v3_integration import BenchmarkV3CampaignConfig, build_v3_run, run_artifacts

READINESS_CAMPAIGN_CONFIG_SCHEMA_VERSION = "1.0"
APPROVED_V4_READINESS_PROFILE_ID = "small-model-efficiency-v4-readiness"
APPROVED_V4_READINESS_PROFILE_DIGEST = "7c83880e2c277d84d2eb5b431946afa5b39be59a1a496db3087e3879e9c65689"
APPROVED_V4_READINESS_TRACK_ID = "small-model-readiness-v4"
_READINESS_CONFIG_KEYS = frozenset({"evidence", "journal_directory", "plan", "profile", "schema_version"})
_CALIBRATION_FINGERPRINT_VERSION = "benchmark-v4-readiness-calibration-v1"
_RESULT_STATUSES = frozenset({"failed", "invalid", "partial", "succeeded", "timeout"})
_RESET_ATTESTATION_KEYS = frozenset(
    {
        "campaign_id",
        "health_command_sha256",
        "health_duration_seconds",
        "lab_version",
        "observed_at",
        "repetition",
        "reset_command_sha256",
        "reset_duration_seconds",
        "scenario_id",
        "schema_version",
        "seed",
        "snapshot_ref",
        "status",
        "system_id",
    }
)
_CLEANUP_ATTESTATION_KEYS = frozenset(
    {
        "campaign_id",
        "cleanup_command_sha256",
        "command_configured",
        "duration_seconds",
        "error_class",
        "lab_version",
        "observed_at",
        "repetition",
        "scenario_id",
        "schema_version",
        "seed",
        "snapshot_ref",
        "status",
        "system_id",
    }
)


class ReadinessCalibrationError(RuntimeError):
    """A calibration lifecycle cannot safely produce reusable evidence."""


class LabController(Protocol):
    def reset_and_health(self, context: LabRunContext) -> ResetAttestation: ...

    def cleanup(self, context: LabRunContext) -> None: ...


@dataclass(frozen=True)
class FullCampaignReadiness:
    """Verified readiness material safe to bind into a public campaign."""

    evidence: ReadinessEvidence
    public_attestation: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "public_attestation",
            MappingProxyType(dict(self.public_attestation)),
        )


@dataclass(frozen=True)
class ReadinessCampaignConfig:
    """Controller-private paths binding a full campaign to calibration evidence."""

    profile_path: Path
    plan_path: Path
    evidence_path: Path
    journal_directory: Path
    schema_version: str = READINESS_CAMPAIGN_CONFIG_SCHEMA_VERSION

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        base_directory: str | Path,
    ) -> ReadinessCampaignConfig:
        if str(payload.get("schema_version") or "") != READINESS_CAMPAIGN_CONFIG_SCHEMA_VERSION:
            raise ReadinessCalibrationError("unsupported_readiness_campaign_config_schema")
        if set(payload) != _READINESS_CONFIG_KEYS:
            raise ReadinessCalibrationError("invalid_readiness_campaign_config")
        base = Path(base_directory).resolve()
        return cls(
            profile_path=_resolved_path(payload.get("profile"), base=base, name="profile"),
            plan_path=_resolved_path(payload.get("plan"), base=base, name="plan"),
            evidence_path=_resolved_path(payload.get("evidence"), base=base, name="evidence"),
            journal_directory=_resolved_path(
                payload.get("journal_directory"),
                base=base,
                name="journal_directory",
            ),
        )

    def profile(self) -> ReadinessProfile:
        return load_readiness_profile(self.profile_path)

    def plan(self) -> ReadinessPlan:
        plan = load_readiness_plan(self.plan_path)
        if plan.profile != self.profile():
            raise ReadinessCalibrationError("readiness_profile_plan_mismatch")
        return plan

    def validate_campaign_path(self, campaign_id: str) -> None:
        expected = (self.journal_directory / campaign_id / "readiness-evidence.json").resolve()
        if self.evidence_path != expected:
            raise ReadinessCalibrationError("readiness_evidence_path_mismatch")

    def fingerprint_payload(self) -> dict[str, Any]:
        plan = self.plan()
        return {
            "schema_version": self.schema_version,
            "profile_digest": plan.profile.digest,
            "plan_digest": plan.digest,
            "calibration_track_id": plan.calibration_track_id,
        }

    def public_payload(self) -> dict[str, Any]:
        return self.fingerprint_payload()


def calibration_analysis_plan(plan: ReadinessPlan) -> AnalysisPlan:
    """Project the exact readiness schedule into the sealed v3 evaluator."""

    participants = (plan.profile.reference_runner_id, *plan.system_ids)
    return AnalysisPlan(
        track_id=plan.calibration_track_id,
        system_ids=participants,
        scenario_ids=plan.scenario_ids,
        repetitions=plan.profile.calibration_repetitions,
        fixture_seeds=plan.fixture_seeds,
        comparison_pairs=tuple((plan.profile.reference_runner_id, system_id) for system_id in plan.system_ids),
        deadlines_seconds=(float(plan.profile.calibration_hard_cap_seconds),),
        bootstrap_samples=100,
        bootstrap_seed=1,
        publication_tier="diagnostic",
        paired_blocks=len(plan.scenario_ids) * plan.profile.calibration_repetitions,
    )


def _emit_run_start(*, index: int, total: int, context: LabRunContext) -> None:
    """Report public run identity before reset/execution can block."""

    _emit_progress(
        "[readiness] run_start"
        f" index={index}"
        f" total={total}"
        f" system={context.system_id}"
        f" scenario={context.scenario_id}"
        f" repetition={context.repetition}"
    )


def _emit_run_finish(
    *,
    index: int,
    total: int,
    context: LabRunContext,
    result: Mapping[str, Any],
    run: BenchmarkRunV3,
) -> None:
    """Report bounded aggregate progress without claims, artifacts, seeds, or tokens."""

    _emit_progress(
        "[readiness] run_finish"
        f" index={index}"
        f" total={total}"
        f" system={context.system_id}"
        f" scenario={context.scenario_id}"
        f" repetition={context.repetition}"
        f" status={result['status']}"
        f" error={'present' if result.get('error_class') else 'none'}"
        f" duration_seconds={float(result['duration_seconds']):.3f}"
        f" task_status={run.task_status}"
        f" actions={run.action_event_count}"
        f" policy_violations={len(run.policy_violations)}"
    )


def _emit_progress(message: str) -> None:
    """Keep best-effort operator output outside the write-once run semantics."""

    try:
        print(message, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        return


def run_readiness_calibration(
    config: Any,
    *,
    environment: Mapping[str, str] | None = None,
    runner_factory: Callable[[SystemManifest], BenchmarkRunner] = CommandSystemRunner,
    lab_controller: LabController | None = None,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> Path:
    """Execute exactly one frozen calibration schedule and seal its evidence."""

    readiness_config, v3_config, efficiency_plan, plan = _bound_inputs(config)
    manifests = _calibration_manifests(config, plan)
    scenarios = _calibration_scenarios(config, plan)
    analysis_plan = calibration_analysis_plan(plan)
    calibration_v3 = BenchmarkV3CampaignConfig(
        analysis_plan_path=v3_config.analysis_plan_path,
        state_directory=v3_config.state_directory,
        batch_id=v3_config.batch_id,
        host_id=v3_config.host_id,
    )
    schedule = _calibration_schedule(plan)
    environment_source = os.environ if environment is None else environment
    effective_environment = {str(key): str(value) for key, value in environment_source.items()}
    readiness_config.validate_campaign_path(str(config.campaign_id))
    _prepare_private_journal_root(readiness_config.journal_directory)
    journal = CampaignJournal(
        readiness_config.journal_directory,
        campaign_id=str(config.campaign_id),
        fingerprint=_calibration_fingerprint(
            config=config,
            manifests=manifests,
            scenarios=scenarios,
            plan=plan,
            efficiency_plan=efficiency_plan,
            analysis_plan=analysis_plan,
            environment_identity=_calibration_environment_identity(
                config,
                manifests,
                effective_environment,
            ),
        ),
    )
    controller = lab_controller or CommandLabController(
        config.reset_command,
        config.health_command,
        cleanup=config.cleanup_command,
        environment=effective_environment,
        diagnostics_directory=journal.diagnostics_directory,
        clock=clock,
        monotonic=monotonic,
    )
    scenario_by_id = {item.scenario_id: item for item in scenarios}
    manifest_by_id = {item.system_id: item for item in manifests}

    with journal.lock():
        journal.initialize(schedule)
        completed = journal.completed_run_count()
        attempted = _validate_attempt_markers(journal, schedule, require_complete=False)
        if completed == len(schedule):
            if attempted != len(schedule):
                raise ReadinessCalibrationError("readiness_calibration_attempt_set_incomplete")
            _require_successful_cleanup(journal)
            return _assess_freeze_and_gate(
                journal,
                schedule,
                readiness_config,
                plan,
                efficiency_plan,
                campaign_config=config,
                scenarios=scenario_by_id,
            )
        if completed or attempted:
            raise ReadinessCalibrationError("readiness_calibration_retry_forbidden")

        runners = {system_id: runner_factory(manifest_by_id[system_id]) for system_id in plan.system_ids}
        last_context: LabRunContext | None = None
        cleanup_status = "succeeded"
        cleanup_error = ""
        with _temporary_environment(effective_environment):
            try:
                for run_index, scheduled in enumerate(schedule, start=1):
                    run_key = str(scheduled["run_key"])
                    journal.begin_run_attempt(run_key)
                    context = _context(str(config.campaign_id), scheduled, scenario_by_id)
                    last_context = context
                    _emit_run_start(index=run_index, total=len(schedule), context=context)
                    attestation = controller.reset_and_health(context)
                    attestation_payload = attestation.to_dict()
                    journal.write_attestation(run_key, attestation_payload)
                    scenario = _bounded_calibration_scenario(
                        scenario_by_id[context.scenario_id],
                        hard_cap_seconds=plan.profile.calibration_hard_cap_seconds,
                    )
                    started_at = float(clock())
                    started = monotonic()
                    if context.system_id == plan.profile.reference_runner_id:
                        try:
                            result = _reference_result(
                                v3_config,
                                context,
                                effective_environment,
                                hard_cap_seconds=plan.profile.calibration_hard_cap_seconds,
                                monotonic=monotonic,
                            )
                        except Exception as exc:
                            result = _failed_result(
                                max(0.0, monotonic() - started),
                                type(exc).__name__,
                            )
                    else:
                        try:
                            raw = runners[context.system_id](scenario, context.repetition, context.seed)
                            if not isinstance(raw, Mapping):
                                raise TypeError("readiness_runner_result_not_mapping")
                            result = dict(raw)
                        except Exception as exc:
                            result = _failed_result(
                                max(0.0, monotonic() - started),
                                type(exc).__name__,
                            )
                    result = _normalize_result(
                        result,
                        default_duration=max(0.0, monotonic() - started),
                        hard_cap_seconds=plan.profile.calibration_hard_cap_seconds,
                    )
                    finished_at = float(clock())
                    v3_run = build_v3_run(
                        config=calibration_v3,
                        plan=analysis_plan,
                        scenario=scenario,
                        system_id=context.system_id,
                        repetition=context.repetition,
                        seed=context.seed,
                        result=result,
                        started_at=started_at,
                        finished_at=finished_at,
                        reset_attestation=attestation_payload,
                    )
                    v3_run = replace(
                        v3_run,
                        environment={
                            **dict(v3_run.environment),
                            "efficiency_plan_digest": efficiency_plan.digest,
                            "readiness_phase": READINESS_PHASE,
                            "readiness_plan_digest": plan.digest,
                            "readiness_role": (
                                "reference" if context.system_id == plan.profile.reference_runner_id else "system"
                            ),
                        },
                    )
                    journal.write_run(
                        run_key,
                        {
                            "system_id": context.system_id,
                            "scenario_id": context.scenario_id,
                            "repetition": context.repetition,
                            "seed": context.seed,
                            "error_class": str(result.get("error_class") or ""),
                            "result": result,
                            "benchmark_v3": v3_run.to_dict(),
                        },
                    )
                    _emit_run_finish(
                        index=run_index,
                        total=len(schedule),
                        context=context,
                        result=result,
                        run=v3_run,
                    )
            finally:
                if last_context is not None:
                    try:
                        controller.cleanup(last_context)
                    except Exception as exc:
                        cleanup_status = "failed"
                        cleanup_error = type(exc).__name__
                    journal.write_cleanup_attestation(
                        {
                            "status": cleanup_status,
                            "command_configured": config.cleanup_command is not None,
                            "cleanup_command_sha256": (
                                _command_digest(config.cleanup_command) if config.cleanup_command is not None else None
                            ),
                            "campaign_id": last_context.campaign_id,
                            "system_id": last_context.system_id,
                            "scenario_id": last_context.scenario_id,
                            "repetition": last_context.repetition,
                            "seed": last_context.seed,
                            "lab_version": last_context.lab_version,
                            "snapshot_ref": last_context.snapshot_ref,
                            "duration_seconds": 0.0,
                            "observed_at": float(clock()),
                            "error_class": cleanup_error,
                        }
                    )
        if cleanup_status != "succeeded":
            raise ReadinessCalibrationError("readiness_calibration_cleanup_failed")
        if journal.completed_run_count() != len(schedule):
            raise ReadinessCalibrationError("readiness_calibration_incomplete")
        _validate_attempt_markers(journal, schedule, require_complete=True)
        return _assess_freeze_and_gate(
            journal,
            schedule,
            readiness_config,
            plan,
            efficiency_plan,
            campaign_config=config,
            scenarios=scenario_by_id,
        )


def require_full_campaign_readiness(
    config: Any,
    *,
    manifests: Sequence[SystemManifest],
    scenarios: Sequence[BenchmarkScenario],
    efficiency_plan: EfficiencyPlan,
    environment: Mapping[str, str] | None = None,
) -> ReadinessEvidence:
    """Recompute readiness from every raw calibration run before evaluation."""

    return require_full_campaign_readiness_material(
        config,
        manifests=manifests,
        scenarios=scenarios,
        efficiency_plan=efficiency_plan,
        environment=environment,
    ).evidence


def require_full_campaign_readiness_material(
    config: Any,
    *,
    manifests: Sequence[SystemManifest],
    scenarios: Sequence[BenchmarkScenario],
    efficiency_plan: EfficiencyPlan,
    environment: Mapping[str, str] | None = None,
) -> FullCampaignReadiness:
    """Verify private calibration and return its non-sensitive public binding."""

    readiness_config, _v3_config, bound_efficiency, plan = _bound_inputs(config)
    if bound_efficiency.digest != efficiency_plan.digest:
        raise ReadinessCalibrationError("readiness_efficiency_plan_mismatch")
    expected_manifests = _calibration_manifests(config, plan)
    expected_scenarios = _calibration_scenarios(config, plan)
    if tuple(item.to_dict() for item in manifests) != tuple(item.to_dict() for item in expected_manifests):
        raise ReadinessCalibrationError("readiness_system_manifest_mismatch")
    if tuple(item.to_dict() for item in scenarios) != tuple(item.to_dict() for item in expected_scenarios):
        raise ReadinessCalibrationError("readiness_scenario_mismatch")
    analysis_plan = calibration_analysis_plan(plan)
    schedule = _calibration_schedule(plan)
    environment_source = os.environ if environment is None else environment
    effective_environment = {str(key): str(value) for key, value in environment_source.items()}
    readiness_config.validate_campaign_path(str(config.campaign_id))
    _require_private_journal_root(readiness_config.journal_directory)
    journal = CampaignJournal(
        readiness_config.journal_directory,
        campaign_id=str(config.campaign_id),
        fingerprint=_calibration_fingerprint(
            config=config,
            manifests=expected_manifests,
            scenarios=expected_scenarios,
            plan=plan,
            efficiency_plan=efficiency_plan,
            analysis_plan=analysis_plan,
            environment_identity=_calibration_environment_identity(
                config,
                expected_manifests,
                effective_environment,
            ),
        ),
    )
    _require_existing_calibration_journal(journal)
    with journal.lock():
        journal.initialize(schedule)
        if journal.completed_run_count() != len(schedule):
            raise ReadinessCalibrationError("readiness_calibration_incomplete")
        _validate_attempt_markers(journal, schedule, require_complete=True)
        _validate_reset_attestations(journal, schedule)
        runs = _read_calibration_runs(journal, schedule)
        reset_attestation_set_digest, cleanup_attestation_digest = _validate_semantic_attestations(
            config=config,
            journal=journal,
            schedule=schedule,
            scenarios={item.scenario_id: item for item in expected_scenarios},
            runs=runs,
        )
        _require_private_file(readiness_config.evidence_path)
        evidence = load_readiness_evidence(readiness_config.evidence_path, plan=plan)
        verify_readiness_evidence(plan, efficiency_plan, runs, evidence)
        assert_full_campaign_ready(plan, efficiency_plan, evidence)
        public_attestation = {
            "campaign_id": str(config.campaign_id),
            "cleanup_attestation_digest": cleanup_attestation_digest,
            "evidence_digest": evidence.digest,
            "plan_digest": plan.digest,
            "profile_digest": plan.profile.digest,
            "reset_attestation_set_digest": reset_attestation_set_digest,
            "source_run_digest": evidence.source_run_digest,
            "status": "ready",
        }
        return FullCampaignReadiness(
            evidence=evidence,
            public_attestation=public_attestation,
        )


def _bound_inputs(
    config: Any,
) -> tuple[ReadinessCampaignConfig, BenchmarkV3CampaignConfig, EfficiencyPlan, ReadinessPlan]:
    readiness_config = getattr(config, "benchmark_v4_readiness", None)
    v3_config = getattr(config, "benchmark_v3", None)
    if not isinstance(readiness_config, ReadinessCampaignConfig):
        raise ReadinessCalibrationError("readiness_config_required")
    if not isinstance(v3_config, BenchmarkV3CampaignConfig):
        raise ReadinessCalibrationError("readiness_v3_config_required")
    efficiency_plan = v3_config.efficiency_plan()
    if efficiency_plan is None:
        raise ReadinessCalibrationError("readiness_efficiency_plan_required")
    plan = readiness_config.plan()
    validate_readiness_plan(plan, efficiency_plan)
    if (
        plan.profile.profile_id != APPROVED_V4_READINESS_PROFILE_ID
        or plan.profile.digest != APPROVED_V4_READINESS_PROFILE_DIGEST
        or plan.profile.calibration_repetitions != 1
        or plan.calibration_track_id != APPROVED_V4_READINESS_TRACK_ID
        or plan.system_ids != ("octopus", "strix")
        or len(plan.scenario_ids) != 12
        or plan.expected_run_count != 36
    ):
        raise ReadinessCalibrationError("readiness_campaign_contract_mismatch")
    return readiness_config, v3_config, efficiency_plan, plan


def _calibration_manifests(config: Any, plan: ReadinessPlan) -> tuple[SystemManifest, ...]:
    from .schema import load_system_manifest

    manifests = tuple(load_system_manifest(path) for path in config.system_manifest_paths)
    if tuple(item.system_id for item in manifests) != plan.system_ids:
        raise ReadinessCalibrationError("readiness_system_manifest_mismatch")
    return manifests


def _calibration_scenarios(config: Any, plan: ReadinessPlan) -> tuple[BenchmarkScenario, ...]:
    from ..schema import load_scenarios

    scenarios = load_scenarios(config.scenario_directory)
    if tuple(item.scenario_id for item in scenarios) != plan.scenario_ids:
        raise ReadinessCalibrationError("readiness_scenario_mismatch")
    return scenarios


def _calibration_schedule(plan: ReadinessPlan) -> tuple[dict[str, Any], ...]:
    schedule = []
    for order, (scenario_id, repetition, seed, system_id) in enumerate(plan.expected_run_keys(), start=1):
        schedule.append(
            {
                "order": order,
                "run_key": schedule_run_key(system_id, scenario_id, repetition, seed),
                "scenario_id": scenario_id,
                "repetition": repetition,
                "seed": seed,
                "system_id": system_id,
            }
        )
    return tuple(schedule)


def _calibration_fingerprint(
    *,
    config: Any,
    manifests: Sequence[SystemManifest],
    scenarios: Sequence[BenchmarkScenario],
    plan: ReadinessPlan,
    efficiency_plan: EfficiencyPlan,
    analysis_plan: AnalysisPlan,
    environment_identity: Mapping[str, str],
) -> str:
    v3_config = config.benchmark_v3
    return campaign_fingerprint(
        {
            "contract": _CALIBRATION_FINGERPRINT_VERSION,
            "campaign_id": config.campaign_id,
            "analysis_plan": analysis_plan.to_dict(),
            "readiness_plan": plan.to_dict(),
            "efficiency_plan": efficiency_plan.to_dict(),
            "systems": [item.to_dict() for item in manifests],
            "scenarios": [item.to_dict() for item in scenarios],
            "batch_id": v3_config.batch_id,
            "host_id": v3_config.host_id,
            "lab": {
                "cleanup": (config.cleanup_command.to_dict() if config.cleanup_command is not None else None),
                "health": config.health_command.to_dict(),
                "reset": config.reset_command.to_dict(),
            },
            "environment_sha256": dict(sorted(environment_identity.items())),
        }
    )


def _calibration_environment_identity(
    config: Any,
    manifests: Sequence[SystemManifest],
    environment: Mapping[str, str],
) -> dict[str, str]:
    names = (
        {str(item) for item in config.required_environment}.union(
            name for manifest in manifests for name in manifest.adapter.env_passthrough
        )
        .union(config.reset_command.environment_passthrough)
        .union(config.health_command.environment_passthrough)
        .union(config.cleanup_command.environment_passthrough if config.cleanup_command is not None else ())
    )
    secret_names = {str(item) for item in config.secret_environment}.union(
        name for name in names if _looks_secret_environment_name(name)
    )
    return {
        name: hashlib.sha256(str(environment.get(name, "")).encode("utf-8")).hexdigest()
        for name in sorted(names - secret_names)
    }


def _looks_secret_environment_name(value: str) -> bool:
    upper = value.upper()
    return any(marker in upper for marker in ("API_KEY", "CREDENTIAL", "PASSWORD", "SECRET", "TOKEN"))


def _bounded_calibration_scenario(scenario: BenchmarkScenario, *, hard_cap_seconds: int) -> BenchmarkScenario:
    payload = scenario.to_dict()
    budgets = dict(payload["budgets"])
    budgets["max_seconds"] = hard_cap_seconds
    policy = dict(budgets.get("policy") or {})
    policy["max_seconds"] = "hard"
    budgets["policy"] = policy
    payload["budgets"] = budgets
    return BenchmarkScenario.from_dict(payload)


def _reference_result(
    v3_config: BenchmarkV3CampaignConfig,
    context: LabRunContext,
    environment: Mapping[str, str],
    *,
    hard_cap_seconds: int,
    monotonic: Callable[[], float],
) -> dict[str, Any]:
    artifacts = run_artifacts(
        v3_config.state_directory,
        campaign_id=context.campaign_id,
        system_id=context.system_id,
        scenario_id=context.scenario_id,
        repetition=context.repetition,
        seed=context.seed,
    )
    variant = load_private_fixture(artifacts.private_manifest)
    try:
        base_url = _canonical_target(str(environment.get("OCTOBENCH_TARGET_URL") or "")).rstrip("/")
    except LabCtlError as exc:
        raise ReadinessCalibrationError("readiness_reference_target_missing") from exc
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())
    started = monotonic()
    request_count = 0
    for route in variant.routes:
        if not route.evidence_ids:
            continue
        for _attempt in range(len(route.response_statuses) + 1):
            remaining = hard_cap_seconds - (monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("readiness_reference_timeout")
            request = urllib.request.Request(base_url + route.target, method="GET")
            try:
                with opener.open(request, timeout=max(0.05, remaining)) as response:
                    response.read(1_000_001)
            except urllib.error.HTTPError as response:
                response.read(1_000_001)
            request_count += 1
    return {
        "status": "succeeded",
        "actions": [],
        "reported_claims": [truth.canonical_text for truth in variant.truth_claims],
        "reported_findings": [],
        "verified_findings": [],
        "coverage_gaps": [],
        "metrics": {"tool_calls": float(request_count)},
        "artifact_refs": [],
        "duration_seconds": min(float(hard_cap_seconds), max(0.0, monotonic() - started)),
        "error_class": "",
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _normalize_result(
    raw: Mapping[str, Any],
    *,
    default_duration: float,
    hard_cap_seconds: int,
) -> dict[str, Any]:
    result = dict(raw)
    status_value = str(result.get("status") or "failed").strip().lower()
    if status_value not in _RESULT_STATUSES:
        return _failed_result(min(default_duration, hard_cap_seconds), "InvalidRunnerStatus")
    duration_value = result.get("duration_seconds")
    try:
        duration = default_duration if duration_value is None else float(duration_value)
    except (TypeError, ValueError):
        duration = default_duration
    if not math.isfinite(duration) or duration < 0:
        duration = default_duration
    result["duration_seconds"] = min(float(hard_cap_seconds), duration)
    result["status"] = status_value
    result["error_class"] = str(result.get("error_class") or "")[:128]
    for name in (
        "actions",
        "artifact_refs",
        "coverage_gaps",
        "policy_violations",
        "reported_claims",
        "reported_findings",
        "verified_findings",
    ):
        value = result.get(name) or []
        result[name] = list(value) if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []
    result["metrics"] = dict(result.get("metrics") or {}) if isinstance(result.get("metrics"), Mapping) else {}
    return result


def _failed_result(duration: float, error_class: str) -> dict[str, Any]:
    return {
        "status": "failed",
        "actions": [],
        "reported_claims": [],
        "reported_findings": [],
        "verified_findings": [],
        "coverage_gaps": [],
        "policy_violations": [],
        "metrics": {},
        "artifact_refs": [],
        "duration_seconds": duration,
        "error_class": error_class[:128],
    }


def _context(
    campaign_id: str,
    scheduled: Mapping[str, Any],
    scenarios: Mapping[str, BenchmarkScenario],
) -> LabRunContext:
    scenario = scenarios[str(scheduled["scenario_id"])]
    return LabRunContext(
        campaign_id=campaign_id,
        system_id=str(scheduled["system_id"]),
        scenario_id=scenario.scenario_id,
        repetition=int(scheduled["repetition"]),
        seed=int(scheduled["seed"]),
        lab_version=str(scenario.lab.get("version") or ""),
        snapshot_ref=str(scenario.lab.get("snapshot_ref") or ""),
    )


def _assess_freeze_and_gate(
    journal: CampaignJournal,
    schedule: Sequence[Mapping[str, Any]],
    config: ReadinessCampaignConfig,
    plan: ReadinessPlan,
    efficiency_plan: EfficiencyPlan,
    *,
    campaign_config: Any,
    scenarios: Mapping[str, BenchmarkScenario],
) -> Path:
    _validate_reset_attestations(journal, schedule)
    runs = _read_calibration_runs(journal, schedule)
    _validate_semantic_attestations(
        config=campaign_config,
        journal=journal,
        schedule=schedule,
        scenarios=scenarios,
        runs=runs,
    )
    evidence = assess_readiness(plan, efficiency_plan, runs)
    path = freeze_readiness_evidence(evidence, config.evidence_path)
    os.chmod(path, 0o600)
    _require_private_file(path)
    loaded = load_readiness_evidence(path, plan=plan)
    verify_readiness_evidence(plan, efficiency_plan, runs, loaded)
    assert_full_campaign_ready(plan, efficiency_plan, loaded)
    return path


def _read_calibration_runs(
    journal: CampaignJournal,
    schedule: Sequence[Mapping[str, Any]],
) -> tuple[BenchmarkRunV3, ...]:
    runs = []
    _require_private_directory(journal.campaign_root / "runs")
    for scheduled in schedule:
        _require_private_file(journal.campaign_root / "runs" / f"{scheduled['run_key']}.json")
        record = journal.read_run(str(scheduled["run_key"]))
        payload = record.get("benchmark_v3") if isinstance(record, Mapping) else None
        if not isinstance(payload, Mapping):
            raise ReadinessCalibrationError("readiness_raw_run_missing")
        run = BenchmarkRunV3.from_dict(payload)
        identity = (
            run.scenario_id,
            run.repetition,
            run.matched_fixture_seed,
            run.system_id,
        )
        expected = (
            str(scheduled["scenario_id"]),
            int(scheduled["repetition"]),
            int(scheduled["seed"]),
            str(scheduled["system_id"]),
        )
        if identity != expected:
            raise ReadinessCalibrationError("readiness_raw_run_identity_mismatch")
        runs.append(run)
    return tuple(runs)


def _validate_attempt_markers(
    journal: CampaignJournal,
    schedule: Sequence[Mapping[str, Any]],
    *,
    require_complete: bool,
) -> int:
    directory = journal.campaign_root / "attempts"
    _require_private_directory(directory)
    expected = {str(item["run_key"]) for item in schedule}
    observed: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        _require_private_file(path)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ReadinessCalibrationError("readiness_attempt_marker_invalid") from exc
        if (
            not isinstance(payload, Mapping)
            or path.stem not in expected
            or payload.get("run_key") != path.stem
            or payload.get("campaign_id") != journal.campaign_id
            or payload.get("fingerprint") != journal.fingerprint
            or payload.get("status") != "started"
        ):
            raise ReadinessCalibrationError("readiness_attempt_marker_invalid")
        observed.add(path.stem)
    if require_complete and observed != expected:
        raise ReadinessCalibrationError("readiness_calibration_attempt_set_incomplete")
    return len(observed)


def _validate_reset_attestations(
    journal: CampaignJournal,
    schedule: Sequence[Mapping[str, Any]],
) -> None:
    directory = journal.campaign_root / "attestations"
    _require_private_directory(directory)
    expected = {str(item["run_key"]) for item in schedule}
    observed: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        _require_private_file(path)
        observed.add(path.stem)
    if observed != expected or len(journal.read_attestations()) != len(expected):
        raise ReadinessCalibrationError("readiness_reset_attestation_set_incomplete")


def _validate_semantic_attestations(
    *,
    config: Any,
    journal: CampaignJournal,
    schedule: Sequence[Mapping[str, Any]],
    scenarios: Mapping[str, BenchmarkScenario],
    runs: Sequence[BenchmarkRunV3],
) -> tuple[str, str]:
    """Bind every private reset and final cleanup to frozen execution inputs."""

    if len(runs) != len(schedule):
        raise ReadinessCalibrationError("readiness_raw_run_count_mismatch")
    attestations = {str(item.get("run_key") or ""): item for item in journal.read_attestations()}
    reset_command_digest = _command_digest(config.reset_command)
    health_command_digest = _command_digest(config.health_command)
    semantic_attestations: list[dict[str, Any]] = []
    for index, scheduled in enumerate(schedule):
        run = runs[index]
        run_key = str(scheduled["run_key"])
        raw = attestations.get(run_key)
        if not isinstance(raw, Mapping) or set(raw) != _RESET_ATTESTATION_KEYS | {
            "fingerprint",
            "run_key",
        }:
            raise ReadinessCalibrationError("readiness_reset_attestation_invalid")
        context = _context(str(config.campaign_id), scheduled, scenarios)
        semantic = {key: raw.get(key) for key in _RESET_ATTESTATION_KEYS}
        if (
            raw.get("fingerprint") != journal.fingerprint
            or raw.get("run_key") != run_key
            or semantic.get("schema_version") != LAB_CONTROL_SCHEMA_VERSION
            or semantic.get("status") != "healthy"
            or semantic.get("campaign_id") != context.campaign_id
            or semantic.get("system_id") != context.system_id
            or semantic.get("scenario_id") != context.scenario_id
            or not _exact_integer(semantic.get("repetition"), context.repetition)
            or not _exact_integer(semantic.get("seed"), context.seed)
            or semantic.get("lab_version") != context.lab_version
            or semantic.get("snapshot_ref") != context.snapshot_ref
            or semantic.get("reset_command_sha256") != reset_command_digest
            or semantic.get("health_command_sha256") != health_command_digest
            or not _nonnegative_finite_number(semantic.get("reset_duration_seconds"))
            or not _nonnegative_finite_number(semantic.get("health_duration_seconds"))
            or not _nonnegative_finite_number(semantic.get("observed_at"))
        ):
            raise ReadinessCalibrationError("readiness_reset_attestation_invalid")
        embedded = run.environment.get("reset_attestation")
        if not isinstance(embedded, Mapping) or canonical_json(dict(embedded)) != canonical_json(semantic):
            raise ReadinessCalibrationError("readiness_reset_attestation_run_mismatch")
        semantic_attestations.append(semantic)

    _require_private_file(journal.campaign_root / "cleanup.json")
    cleanup = journal.read_cleanup_attestation()
    if not isinstance(cleanup, Mapping) or set(cleanup) != _CLEANUP_ATTESTATION_KEYS | {"fingerprint"}:
        raise ReadinessCalibrationError("readiness_cleanup_attestation_invalid")
    if not schedule:
        raise ReadinessCalibrationError("readiness_calibration_incomplete")
    final_context = _context(str(config.campaign_id), schedule[-1], scenarios)
    expected_cleanup_digest = _command_digest(config.cleanup_command) if config.cleanup_command is not None else None
    semantic_cleanup = {key: cleanup.get(key) for key in _CLEANUP_ATTESTATION_KEYS}
    if (
        cleanup.get("fingerprint") != journal.fingerprint
        or semantic_cleanup.get("schema_version") != LAB_CONTROL_SCHEMA_VERSION
        or semantic_cleanup.get("status") != "succeeded"
        or semantic_cleanup.get("command_configured") is not (config.cleanup_command is not None)
        or semantic_cleanup.get("cleanup_command_sha256") != expected_cleanup_digest
        or semantic_cleanup.get("campaign_id") != final_context.campaign_id
        or semantic_cleanup.get("system_id") != final_context.system_id
        or semantic_cleanup.get("scenario_id") != final_context.scenario_id
        or not _exact_integer(semantic_cleanup.get("repetition"), final_context.repetition)
        or not _exact_integer(semantic_cleanup.get("seed"), final_context.seed)
        or semantic_cleanup.get("lab_version") != final_context.lab_version
        or semantic_cleanup.get("snapshot_ref") != final_context.snapshot_ref
        or semantic_cleanup.get("error_class") != ""
        or not _nonnegative_finite_number(semantic_cleanup.get("duration_seconds"))
        or not _nonnegative_finite_number(semantic_cleanup.get("observed_at"))
    ):
        raise ReadinessCalibrationError("readiness_cleanup_attestation_invalid")

    return (
        stable_digest(
            {
                "attestations": semantic_attestations,
                "schema_version": LAB_CONTROL_SCHEMA_VERSION,
            }
        ),
        stable_digest(semantic_cleanup),
    )


def _nonnegative_finite_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0.0
    )


def _exact_integer(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


def _require_successful_cleanup(journal: CampaignJournal) -> None:
    _require_private_file(journal.campaign_root / "cleanup.json")
    cleanup = journal.read_cleanup_attestation()
    if not isinstance(cleanup, Mapping) or cleanup.get("status") != "succeeded":
        raise ReadinessCalibrationError("readiness_calibration_cleanup_failed")


def _prepare_private_journal_root(path: Path) -> None:
    if path.is_symlink():
        raise ReadinessCalibrationError("readiness_journal_not_private")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    _require_private_directory(path)


def _require_private_journal_root(path: Path) -> None:
    _require_private_directory(path)


def _require_existing_calibration_journal(journal: CampaignJournal) -> None:
    _require_private_directory(journal.campaign_root)
    _require_private_file(journal.campaign_root / "campaign.json")


def _require_private_directory(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ReadinessCalibrationError("readiness_journal_not_private") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise ReadinessCalibrationError("readiness_journal_not_private")


def _require_private_file(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ReadinessCalibrationError("readiness_file_not_private") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise ReadinessCalibrationError("readiness_file_not_private")


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


def _resolved_path(value: Any, *, base: Path, name: str) -> Path:
    candidate = str(value or "").strip()
    if not candidate or "\x00" in candidate:
        raise ReadinessCalibrationError(f"invalid_readiness_path:{name}")
    return (base / candidate).resolve()


__all__ = [
    "APPROVED_V4_READINESS_PROFILE_DIGEST",
    "APPROVED_V4_READINESS_PROFILE_ID",
    "APPROVED_V4_READINESS_TRACK_ID",
    "READINESS_CAMPAIGN_CONFIG_SCHEMA_VERSION",
    "BenchmarkV4ReadinessError",
    "FullCampaignReadiness",
    "ReadinessCalibrationError",
    "ReadinessCampaignConfig",
    "calibration_analysis_plan",
    "require_full_campaign_readiness",
    "require_full_campaign_readiness_material",
    "run_readiness_calibration",
]
