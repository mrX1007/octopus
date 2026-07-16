"""Hermetic deterministic replays for the versioned benchmark catalog.

The built-in runner exercises OCTOPUS persistence, assessment, execution-result,
planner-fallback, and mission-resume components against recorded semantic input.
It never invokes a scanner, model provider, network service, or external tool.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from core.ai.fact_assessment import AssessmentStatus
from core.ai.fact_store import FactStore
from core.ai.mission_store import MissionStore
from core.ai.outcomes import TaskOutcome
from core.ai.planner import MissionPlanner
from core.execution.results import ExecutionResult, ExecutionStatus

from .schema import BenchmarkScenario

ReplayHandler = Callable[[BenchmarkScenario, Path], Mapping[str, Any]]


class BuiltinReplayRunner:
    """Run one catalog scenario through deterministic in-process components."""

    def __init__(self) -> None:
        self._handlers: dict[str, ReplayHandler] = {
            "service_discovery_verification": _service_discovery,
            "web_api_mapping": _web_api_mapping,
            "credential_discovery_safe_validation": _credential_validation,
            "verified_ssh_inventory": _ssh_inventory,
            "authorized_internal_discovery": _internal_discovery,
            "clean_negative": _clean_negative,
            "timeout_partial_result": _timeout_partial,
            "invalid_empty_llm": _invalid_llm_fallback,
            "crash_resume": _crash_resume,
            "contradictions": _contradictions,
        }

    def __call__(
        self,
        scenario: BenchmarkScenario,
        repetition: int,
        seed: int,
    ) -> Mapping[str, Any]:
        handler = self._handlers.get(scenario.category)
        if handler is None:
            raise ValueError(f"no built-in replay for category:{scenario.category}")
        started_at = time.monotonic()
        with TemporaryDirectory(prefix="octopus-benchmark-") as temporary:
            result = dict(handler(scenario, Path(temporary)))
        duration = max(0.0, time.monotonic() - started_at)

        actions = tuple(str(item) for item in result.get("actions") or ())
        if len(actions) > int(scenario.budgets["max_tools"]):
            raise ValueError("built-in replay exceeds scenario max_tools budget")
        if duration > float(scenario.budgets["max_seconds"]):
            raise ValueError("built-in replay exceeds scenario max_seconds budget")
        metrics = dict(result.get("metrics") or {})
        metrics.setdefault("component_checks", 1.0)
        metrics.setdefault("no_op_task_rate", 0.0)
        metrics.setdefault("repeated_task_rate", 0.0)
        result["metrics"] = metrics
        result.setdefault("status", "succeeded")
        result.setdefault("duration_seconds", duration)
        result.setdefault(
            "artifact_refs",
            (
                f"benchmark-replay://{scenario.scenario_id}/"
                f"{repetition}/{seed}",
            ),
        )
        output_bytes = len(
            json.dumps(result, sort_keys=True, default=str).encode("utf-8")
        )
        if output_bytes > int(scenario.budgets["max_output_bytes"]):
            raise ValueError("built-in replay exceeds scenario max_output_bytes budget")
        return result


@contextmanager
def _facts(path: Path) -> Iterator[FactStore]:
    store = FactStore(str(path / "facts.db"))
    try:
        yield store
    finally:
        store.secret_store.close()


def _result(
    *,
    actions: tuple[str, ...],
    findings: tuple[str, ...],
    verified: tuple[str, ...] = (),
    persisted_records: int,
    component_checks: int,
    coverage_gaps: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "status": "succeeded",
        "actions": actions,
        "reported_findings": findings,
        "verified_findings": verified,
        "coverage_gaps": coverage_gaps,
        "metrics": {
            "component_checks": float(component_checks),
            "evidence_completeness": 1.0,
            "persisted_records": float(persisted_records),
        },
    }


def _record_successful_execution(
    store: FactStore,
    *,
    scan_id: str,
    host: str,
    execution_id: str,
) -> None:
    """Persist provenance before facts or assessments consume an execution ID."""

    execution = ExecutionResult(
        status=ExecutionStatus.SUCCEEDED,
        request_id=f"request-{execution_id}",
        execution_id=execution_id,
        tool_name="deterministic_replay",
        stdout="recorded replay completed",
        exit_code=0,
    )
    store.add_command_result(
        scan_id,
        host,
        f"recorded-{execution_id}",
        "recorded replay only",
        hashlib.sha256(execution_id.encode()).hexdigest(),
        execution_result=execution,
        idempotency_key=f"{scan_id}:{execution_id}",
    )


def _service_discovery(scenario: BenchmarkScenario, root: Path) -> Mapping[str, Any]:
    with _facts(root) as store:
        _record_successful_execution(
            store,
            scan_id=scenario.scenario_id,
            host="replay-host",
            execution_id="exec-service",
        )
        service_ids = (
            store.add_fact(
                scenario.scenario_id,
                "replay-host",
                "service_status",
                "ssh:22:open",
                "fixture:service-discovery-v1",
                source_execution_ids=("exec-service",),
            ),
            store.add_fact(
                scenario.scenario_id,
                "replay-host",
                "service_status",
                "https:443:open",
                "fixture:service-discovery-v1",
                source_execution_ids=("exec-service",),
            ),
        )
        for fact_id in service_ids:
            store.assessments.assess_fact(
                fact_id,
                AssessmentStatus.VERIFIED,
                confidence=100,
                rule_id="benchmark.service.verified.v1",
                reason="Recorded verification confirmed the discovered service.",
                assessor="benchmark.builtin_replay",
                evidence_fact_ids=(fact_id,),
                source_execution_ids=("exec-service",),
            )
        facts = store.get_facts(scenario.scenario_id)
        commands = store.get_command_results(scenario.scenario_id)
    values = {
        str(item["value"])
        for item in facts
        if item.get("assessment_status") == AssessmentStatus.VERIFIED.value
    }
    findings = tuple(
        finding
        for value, finding in (
            ("ssh:22:open", "ssh_service"),
            ("https:443:open", "https_service"),
        )
        if value in values
    )
    return _result(
        actions=("replay_service_discovery", "verify_service"),
        findings=findings,
        verified=findings,
        persisted_records=len(facts) + len(commands),
        component_checks=2,
    )


def _web_api_mapping(scenario: BenchmarkScenario, root: Path) -> Mapping[str, Any]:
    with _facts(root) as store:
        store.add_fact(
            scenario.scenario_id,
            "replay-web",
            "web_endpoint",
            "https://replay.invalid/",
            "fixture:web-api-map-v1",
            source_execution_ids=("exec-web",),
        )
        store.add_fact(
            scenario.scenario_id,
            "replay-web",
            "api_route",
            "/api/v1/status",
            "fixture:web-api-map-v1",
            source_execution_ids=("exec-api",),
        )
        facts = store.get_facts(scenario.scenario_id)
    types = {str(item["type"]) for item in facts}
    findings = tuple(
        item for item in ("web_endpoint", "api_route") if item in types
    )
    return _result(
        actions=("replay_web_mapping", "replay_api_mapping"),
        findings=findings,
        persisted_records=len(facts),
        component_checks=2,
    )


def _credential_validation(
    scenario: BenchmarkScenario,
    root: Path,
) -> Mapping[str, Any]:
    plaintext = "benchmark-fixture-value"
    with _facts(root) as store:
        _record_successful_execution(
            store,
            scan_id=scenario.scenario_id,
            host="replay-auth",
            execution_id="exec-credential",
        )
        _record_successful_execution(
            store,
            scan_id=scenario.scenario_id,
            host="replay-auth",
            execution_id="exec-safe-validation",
        )
        credential_id = store.add_fact(
            scenario.scenario_id,
            "replay-auth",
            "credential",
            f"replay-user:{plaintext}",
            "fixture:credential-validation-v1",
            source_execution_ids=("exec-credential",),
        )
        authentication_id = store.add_fact(
            scenario.scenario_id,
            "replay-auth",
            "authentication_result",
            "replay-user:success",
            "fixture:credential-validation-v1",
            source_execution_ids=("exec-safe-validation",),
        )
        store.assessments.assess_fact(
            authentication_id,
            AssessmentStatus.VERIFIED,
            confidence=100,
            rule_id="benchmark.authentication.safe_validation.v1",
            reason="Recorded safe validation corroborates the credential reference.",
            assessor="benchmark.builtin_replay",
            evidence_fact_ids=(credential_id,),
            source_execution_ids=("exec-safe-validation",),
        )
        facts = store.get_facts(scenario.scenario_id)
        commands = store.get_command_results(scenario.scenario_id)
        authentication = store.assessments.current_for_fact(authentication_id)

    serialized = json.dumps(facts, sort_keys=True)
    credential_safe = plaintext not in serialized and "secret://" in serialized
    authentication_verified = bool(
        authentication and authentication.status is AssessmentStatus.VERIFIED
    )
    findings = tuple(
        finding
        for condition, finding in (
            (credential_safe, "credential_observed"),
            (authentication_verified, "authentication_verified"),
        )
        if condition
    )
    return _result(
        actions=("replay_credential_discovery", "safe_credential_validation"),
        findings=findings,
        verified=("authentication_verified",) if authentication_verified else (),
        persisted_records=len(facts) + len(commands),
        component_checks=3,
    )


def _ssh_inventory(scenario: BenchmarkScenario, root: Path) -> Mapping[str, Any]:
    with _facts(root) as store:
        for execution_id in ("exec-ssh", "exec-inventory"):
            _record_successful_execution(
                store,
                scan_id=scenario.scenario_id,
                host="replay-ssh",
                execution_id=execution_id,
            )
        access_id = store.add_fact(
            scenario.scenario_id,
            "replay-ssh",
            "system_access",
            "ssh:verified",
            "fixture:ssh-inventory-v1",
            source_execution_ids=("exec-ssh",),
        )
        store.assessments.assess_fact(
            access_id,
            AssessmentStatus.VERIFIED,
            confidence=100,
            rule_id="benchmark.ssh_access.verified.v1",
            reason="Recorded safe access validation confirmed SSH access.",
            assessor="benchmark.builtin_replay",
            evidence_fact_ids=(access_id,),
            source_execution_ids=("exec-ssh",),
        )
        store.add_fact(
            scenario.scenario_id,
            "replay-ssh",
            "host_inventory",
            "linux:x86_64",
            "fixture:ssh-inventory-v1",
            source_execution_ids=("exec-inventory",),
        )
        facts = store.get_facts(scenario.scenario_id)
        commands = store.get_command_results(scenario.scenario_id)
    types = {
        str(item["type"]): str(item.get("assessment_status") or "")
        for item in facts
    }
    findings = tuple(
        finding
        for fact_type, finding in (
            ("system_access", "ssh_access"),
            ("host_inventory", "host_inventory"),
        )
        if fact_type in types
        and (
            fact_type != "system_access"
            or types[fact_type] == AssessmentStatus.VERIFIED.value
        )
    )
    return _result(
        actions=("verify_ssh_access", "replay_bounded_inventory"),
        findings=findings,
        verified=("ssh_access",) if "ssh_access" in findings else (),
        persisted_records=len(facts) + len(commands),
        component_checks=2,
    )


def _internal_discovery(
    scenario: BenchmarkScenario,
    root: Path,
) -> Mapping[str, Any]:
    with _facts(root) as store:
        for execution_id in ("exec-internal-map", "exec-internal-service"):
            _record_successful_execution(
                store,
                scan_id=scenario.scenario_id,
                host="10.0.0.20",
                execution_id=execution_id,
            )
        store.add_fact(
            scenario.scenario_id,
            "10.0.0.20",
            "internal_host",
            "10.0.0.20",
            "fixture:internal-discovery-v1",
            source_execution_ids=("exec-internal-map",),
        )
        service_id = store.add_fact(
            scenario.scenario_id,
            "10.0.0.20",
            "internal_service",
            "http:8080:open",
            "fixture:internal-discovery-v1",
            source_execution_ids=("exec-internal-service",),
        )
        store.assessments.assess_fact(
            service_id,
            AssessmentStatus.VERIFIED,
            confidence=100,
            rule_id="benchmark.internal_service.verified.v1",
            reason="Recorded in-scope service verification confirmed the service.",
            assessor="benchmark.builtin_replay",
            evidence_fact_ids=(service_id,),
            source_execution_ids=("exec-internal-service",),
        )
        facts = store.get_facts(scenario.scenario_id)
        commands = store.get_command_results(scenario.scenario_id)
    types = {
        str(item["type"]): str(item.get("assessment_status") or "")
        for item in facts
    }
    findings = tuple(
        item
        for item in ("internal_host", "internal_service")
        if item in types
        and (
            item != "internal_service"
            or types[item] == AssessmentStatus.VERIFIED.value
        )
    )
    return _result(
        actions=("replay_internal_inventory", "verify_internal_service"),
        findings=findings,
        verified=("internal_service",) if "internal_service" in findings else (),
        persisted_records=len(facts) + len(commands),
        component_checks=2,
    )


def _clean_negative(scenario: BenchmarkScenario, root: Path) -> Mapping[str, Any]:
    with _facts(root) as store:
        execution = ExecutionResult(
            status=ExecutionStatus.SUCCEEDED,
            request_id="request-negative",
            execution_id="exec-negative",
            tool_name="recorded_negative_check",
            stdout="No matching observations in recorded fixture.",
            exit_code=0,
        )
        store.add_command_result(
            scenario.scenario_id,
            "replay-negative",
            "recorded-negative-check",
            "recorded replay only",
            hashlib.sha256(execution.stdout.encode()).hexdigest(),
            execution_result=execution,
            idempotency_key="clean-negative-v1",
        )
        commands = store.get_command_results(scenario.scenario_id)
        facts = store.get_facts(scenario.scenario_id)
    complete_negative = bool(
        len(commands) == 1
        and commands[0]["status"] == ExecutionStatus.SUCCEEDED.value
        and not facts
    )
    return _result(
        actions=("replay_negative_checks",),
        findings=(),
        persisted_records=len(commands),
        component_checks=1 if complete_negative else 0,
    )


def _timeout_partial(scenario: BenchmarkScenario, root: Path) -> Mapping[str, Any]:
    with _facts(root) as store:
        execution = ExecutionResult(
            status=ExecutionStatus.TIMEOUT,
            request_id="request-timeout",
            execution_id="exec-timeout",
            tool_name="recorded_partial_check",
            stdout="partial observation before timeout",
            stderr="recorded timeout",
            duration=20.0,
            error_class="timeout",
            partial=True,
        )
        store.add_command_result(
            scenario.scenario_id,
            "replay-timeout",
            "recorded-partial-check",
            "recorded replay only",
            hashlib.sha256(execution.stdout.encode()).hexdigest(),
            execution_result=execution,
            parsed_facts=1,
            new_facts=1,
            idempotency_key="timeout-partial-v1",
        )
        store.add_fact(
            scenario.scenario_id,
            "replay-timeout",
            "partial_observation",
            "service-banner-prefix",
            "fixture:timeout-partial-v1",
            source_execution_ids=(execution.execution_id,),
        )
        commands = store.get_command_results(scenario.scenario_id)
        facts = store.get_facts(scenario.scenario_id)
    partial_persisted = bool(
        commands
        and commands[0]["status"] == ExecutionStatus.TIMEOUT.value
        and commands[0]["partial"]
        and facts
    )
    findings = (
        ("partial_evidence", "coverage_gap") if partial_persisted else ()
    )
    result = _result(
        actions=("replay_partial_result", "record_coverage_gap"),
        findings=findings,
        persisted_records=len(commands) + len(facts),
        component_checks=2 if partial_persisted else 0,
        coverage_gaps=("recorded_execution_timeout",) if partial_persisted else (),
    )
    result["metrics"]["evidence_completeness"] = 0.5
    return result


def _invalid_llm_fallback(
    _scenario: BenchmarkScenario,
    _root: Path,
) -> Mapping[str, Any]:
    fallback = MissionPlanner()._fallback_logic("service_discovery")
    plan = fallback.get("plan") if isinstance(fallback, Mapping) else None
    valid_plan = bool(
        isinstance(plan, list)
        and 0 < len(plan) <= 3
        and all(
            isinstance(step, Mapping) and step.get("agent") and step.get("task")
            for step in plan
        )
    )
    findings = (
        ("fallback_used", "scan_continued_safely") if valid_plan else ()
    )
    return _result(
        actions=("replay_invalid_llm", "deterministic_fallback"),
        findings=findings,
        persisted_records=len(plan or ()),
        component_checks=2 if valid_plan else 0,
    )


def _crash_resume(scenario: BenchmarkScenario, root: Path) -> Mapping[str, Any]:
    database = root / "missions.db"
    crashed = MissionStore(str(database), owner_id="benchmark-owner-before-crash")
    mission = crashed.open_mission(scenario.scenario_id, "replay-mission")
    task = crashed.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
        scope="target:replay-mission",
        capability="service_discovery",
    )
    abandoned = crashed.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    crashed.close()

    recovery = MissionStore(str(database), owner_id="benchmark-owner-after-crash")
    reopened = recovery.open_mission(
        scenario.scenario_id,
        "replay-mission",
        recover=True,
    )
    recovered = recovery.snapshot(reopened.mission_id)
    interrupted = next(
        item for item in recovered.attempts if item.attempt_id == abandoned.attempt_id
    )
    retry = recovery.begin_attempt(
        reopened.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    recovery.complete_attempt(
        retry.attempt_id,
        TaskOutcome(
            agent="DiscoveryAgent",
            task="service_discovery",
            status="completed",
            reason="recorded_replay_completed",
            new_facts=1,
            parsed_facts=1,
            commands=({"command": "recorded replay", "failed": False},),
            duration=0.0,
        ),
        execution_ids=("exec-resumed",),
    )
    final = recovery.snapshot(reopened.mission_id)
    recovery.close()

    resumed = bool(
        reopened.run_count == 2
        and task.task_id == retry.task_id
        and interrupted.status == "interrupted"
        and retry.attempt_number == 2
    )
    completed_attempts = [item for item in final.attempts if item.status == "completed"]
    no_duplicate = len(final.attempts) == 2 and len(completed_attempts) == 1
    findings = tuple(
        finding
        for condition, finding in (
            (resumed, "mission_resumed"),
            (no_duplicate, "no_duplicate_execution"),
        )
        if condition
    )
    return _result(
        actions=("replay_mission_start", "inject_crash", "resume_mission"),
        findings=findings,
        persisted_records=len(final.tasks) + len(final.attempts),
        component_checks=2,
    )


def _contradictions(scenario: BenchmarkScenario, root: Path) -> Mapping[str, Any]:
    with _facts(root) as store:
        for execution_id in ("exec-positive", "exec-negative"):
            _record_successful_execution(
                store,
                scan_id=scenario.scenario_id,
                host="replay-evidence",
                execution_id=execution_id,
            )
        positive_id = store.add_fact(
            scenario.scenario_id,
            "replay-evidence",
            "benchmark_evidence",
            "positive-control-proof",
            "fixture:contradictions-v1",
            source_execution_ids=("exec-positive",),
        )
        candidate_id = store.add_fact(
            scenario.scenario_id,
            "replay-evidence",
            "vulnerability_candidate",
            "recorded-candidate:present",
            "fixture:contradictions-v1",
            source_execution_ids=("exec-positive",),
        )
        store.assessments.assess_fact(
            candidate_id,
            AssessmentStatus.VERIFIED,
            confidence=95,
            rule_id="benchmark.candidate.verified.v1",
            reason="Recorded positive control supported the candidate.",
            assessor="benchmark.builtin_replay",
            evidence_fact_ids=(positive_id,),
            source_execution_ids=("exec-positive",),
        )
        store.add_fact(
            scenario.scenario_id,
            "replay-evidence",
            "vulnerability_candidate",
            "recorded-candidate:absent",
            "fixture:contradictions-v1",
            source_execution_ids=("exec-negative",),
        )
        current = store.assessments.current_for_fact(candidate_id)
        history = store.assessments.history(candidate_id)
        commands = store.get_command_results(scenario.scenario_id)
    contradicted = bool(
        current
        and current.status is AssessmentStatus.CONTRADICTED
        and current.rule_id == "fact.contradicted.scoped_opposite.v1"
        and [item.status for item in history][-2:]
        == [AssessmentStatus.VERIFIED, AssessmentStatus.CONTRADICTED]
    )
    return _result(
        actions=(
            "replay_positive_evidence",
            "replay_negative_control",
            "assess_contradiction",
        ),
        findings=("candidate_contradicted",) if contradicted else (),
        persisted_records=3 + len(history) + len(commands),
        component_checks=2 if contradicted else 0,
    )


__all__ = ["BuiltinReplayRunner"]
