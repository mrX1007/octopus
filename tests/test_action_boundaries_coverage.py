"""Branch-complete contracts for action models, adapters, selection, and telemetry."""

from __future__ import annotations

import math
import sqlite3
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from core.actions import (
    ActionAdapter,
    ActionCleanupResult,
    ActionDescriptor,
    ActionExecutionReport,
    ActionKind,
    ActionLifecycle,
    ActionRequest,
    ActionRequirements,
    ActionVerificationResult,
    ActiveRiskClass,
    ApplicabilityResult,
    ExploitBaseAdapter,
    IngestionOutcome,
    KillchainActionAdapter,
    MetasploitActionAdapter,
    PluginActionAdapter,
    PolicyDenial,
    ProviderAttempt,
    ProviderCircuitBreaker,
    ProviderCircuitState,
    ProviderDecision,
    ProviderFallbackExecutor,
    ProviderRunResult,
    ProviderSelection,
    ProviderSelector,
    ProviderTelemetryEvent,
    ProviderTelemetryStore,
    ProviderTelemetrySummary,
    RegisteredToolAdapter,
    RetryClassifier,
    canonical_assessment_applicability,
    target_class,
)
from core.execution import ExecutionContext, ExecutionDecision, ExecutionResult, ExecutionStatus

pytestmark = [pytest.mark.contract, pytest.mark.security]


def automatic(target: str = "example.com") -> ExecutionContext:
    return ExecutionContext.automatic(
        target_scope=(target,) if target else (),
        actor="action-boundary-test",
        origin="test",
    )


def descriptor(
    action_id: str = "test:provider",
    *,
    active: bool = False,
    aliases: tuple[str, ...] = (),
) -> ActionDescriptor:
    return ActionDescriptor(
        action_id=action_id,
        name=action_id.replace(":", "_"),
        kind=ActionKind.REGISTERED_TOOL,
        provider="test",
        aliases=aliases,
        requirements=ActionRequirements(active=active),
    )


def report_with(
    result: ExecutionResult | None = None,
    *,
    check: ExecutionResult | None = None,
    denials: list[PolicyDenial] | None = None,
) -> ActionExecutionReport:
    return ActionExecutionReport(
        descriptor=descriptor(),
        lifecycle=ActionLifecycle(),
        check_result=check,
        execution_result=result,
        policy_denials=list(denials or ()),
    )


def telemetry_summary(**overrides: Any) -> ProviderTelemetrySummary:
    values: dict[str, Any] = {
        "provider_id": "test:provider",
        "capability": "discovery",
        "target_class": "dns",
    }
    values.update(overrides)
    return ProviderTelemetrySummary(**values)


def provider_decision(
    action_id: str = "test:provider",
    *,
    denial: PolicyDenial | None = None,
) -> ProviderDecision:
    return ProviderDecision(
        action_id=action_id,
        provider="test",
        score=10.0,
        rejected=denial is not None,
        reasons=("fixture",),
        telemetry=telemetry_summary(provider_id=action_id),
        dependency_available=True,
        scope_compatible=denial is None,
        active_risk=0.0,
        circuit_state="closed",
        policy_denial=denial,
    )


def provider_selection(
    *,
    ranked: tuple[ProviderDecision, ...] = (),
    rejected: tuple[ProviderDecision, ...] = (),
) -> ProviderSelection:
    return ProviderSelection(
        selection_id="selection_fixture",
        capability="discovery",
        target_class="dns",
        chosen_action_id=ranked[0].action_id if ranked else None,
        ranked=ranked,
        rejected=rejected,
    )


def test_action_models_serialize_commands_lifecycle_and_audit(monkeypatch):
    requirements = ActionRequirements(
        system_dependencies=("binary",),
        python_dependencies=("package",),
        capabilities=("network",),
        target_required=False,
        active=True,
        supports_check=True,
        supports_cleanup=True,
        positive_check_required=True,
    )
    action_descriptor = ActionDescriptor(
        action_id="tool:fixture",
        name="fixture",
        kind=ActionKind.REGISTERED_TOOL,
        provider="tests",
        category="recon",
        description="fixture descriptor",
        version="2",
        aliases=("alias",),
        requirements=requirements,
    )
    request = ActionRequest(
        target="example.com",
        execution_context=automatic(),
        arguments=("--safe",),
        parameters={"z": 1, "a": 2},
        command="fixture fallback",
        facts=({"type": "service"},),
        handle=object(),
        evidence_fact_ids=(3,),
        assessment_refs=("assessment-1",),
        source_execution_ids=("source-1",),
        provider_commands={" TOOL:FIXTURE ": "fixture provider"},
    )

    assert ActiveRiskClass.ACTIVE.score == 1.0
    assert ActiveRiskClass.READ_ONLY.score == 0.0
    assert requirements.to_dict()["system_dependencies"] == ["binary"]
    assert action_descriptor.to_dict()["kind"] == "registered_tool"
    assert request.provider_command_for("tool:fixture") == "fixture provider"
    assert request.provider_command_for("missing") == ""
    assert request.command_for("tool:fixture") == "fixture provider"
    assert request.command_for("missing") == "fixture fallback"
    assert request.audit_dict() == {
        "target": "example.com",
        "request_id": request.execution_context.request_id,
        "argument_count": 1,
        "parameter_names": ["a", "z"],
        "provider_command_count": 1,
        "fact_count": 1,
        "evidence_fact_ids": [3],
        "assessment_refs": ["assessment-1"],
        "source_execution_ids": ["source-1"],
        "has_handle": True,
    }

    applicability = ApplicabilityResult(False, ("reason",), ("dependency",))
    verification = ActionVerificationResult(
        True,
        "verified",
        evidence_fact_ids=(3,),
        assessment_refs=("assessment-1",),
        source_execution_ids=("source-1",),
    )
    cleanup = ActionCleanupResult(False, "cleanup failed")
    assert applicability.to_dict()["missing_requirements"] == ["dependency"]
    assert verification.to_dict()["verified"] is True
    assert cleanup.to_dict() == {"succeeded": False, "reason": "cleanup failed"}

    denial = PolicyDenial.create("", " Bad reason! : target detail", "x" * 300)
    assert denial.phase == "unknown"
    assert denial.reason_code == "bad_reason_"
    assert len(denial.decision_ref) == 256
    assert denial.to_dict()["reason_code"] == "bad_reason_"
    assert PolicyDenial.create("phase", "!!!").reason_code == "___"

    clock = iter((10.0, 11.0))
    monkeypatch.setattr("core.actions.models.time.time", lambda: next(clock))
    lifecycle = ActionLifecycle(created_at=1.0, updated_at=1.0)
    lifecycle.record("started", reason="fixture")
    assert lifecycle.events[0]["timestamp"] == 10.0
    lifecycle.events.extend({"event": "old"} for _ in range(63))
    lifecycle.record("bounded")
    assert len(lifecycle.events) == 64
    assert lifecycle.updated_at == 11.0
    assert lifecycle.to_dict()["events"][-1] == {"event": "old"}

    check_result = ExecutionResult(
        status=ExecutionStatus.FAILED,
        stdout="check secret",
        stderr="check stderr",
        error_class="CheckError",
        error_message="check detail",
    )
    execution_result = ExecutionResult(
        status=ExecutionStatus.SUCCEEDED,
        stdout="execution secret",
        stderr="execution stderr",
        error_class="ExecutionError",
        error_message="execution detail",
    )
    full_report = ActionExecutionReport(
        descriptor=action_descriptor,
        lifecycle=lifecycle,
        applicability=applicability,
        check_result=check_result,
        execution_result=execution_result,
        verification_result=verification,
        cleanup_result=cleanup,
        policy_decision_refs=["decision-1"],
        policy_denials=[denial],
    )
    payload = full_report.to_dict()
    assert payload["cleanup_result"]["succeeded"] is False
    audit = full_report.to_audit_dict()
    assert audit["check_result"]["stdout"] == ""
    assert audit["check_result"]["error"] == {"class": "CheckError", "message": ""}
    assert audit["execution_result"]["stderr"] == ""

    empty_report = ActionExecutionReport(action_descriptor, ActionLifecycle())
    assert empty_report.to_dict()["applicability"] is None
    assert empty_report.to_audit_dict()["execution_result"] is None


def test_canonical_assessments_filter_aliases_and_rank_statuses():
    facts = (
        {"type": "service", "value": "CVE-1"},
        {"type": "vulnerability", "value": "unrelated", "assessment_status": "verified"},
        {"type": "vulnerability", "value": "CVE-1", "assessment_status": "novel"},
        {"type": "verified_claim", "value": "CVE-1", "assessment_status": "verified"},
    )
    reasons, missing = canonical_assessment_applicability(facts, ("cve-1",))
    assert reasons == ("canonical_assessment:verified",)
    assert missing == ()
    assert canonical_assessment_applicability((), ()) == ((), ())
    assert canonical_assessment_applicability(
        ({"type": "vulnerability", "value": "anything"},),
    ) == (("canonical_assessment:observed",), ())

    unusable = (
        {
            "type": "vulnerability",
            "value": "CVE-1",
            "assessment_status": "contradicted",
        },
        {
            "type": "potential_vulnerability",
            "value": "CVE-1",
            "freshness_status": "stale",
        },
        {
            "type": "inferred_claim",
            "value": "CVE-1",
            "coverage_status": "degraded",
        },
    )
    assert canonical_assessment_applicability(unusable, ("cve-1",)) == (
        (),
        (
            "assessment:contradicted",
            "assessment:stale",
            "assessment:degraded_coverage",
        ),
    )


def tool_fixture(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "name": "fixture",
        "category": "recon",
        "description": "fixture",
        "aliases": ("fixture_alias",),
        "requires": (),
        "needs_target": True,
        "enabled": True,
        "is_available": lambda: True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_registered_tool_boundaries_and_killchain_contract():
    dispatched: list[str] = []
    adapter = RegisteredToolAdapter(
        tool_fixture(),
        lambda command, _context: dispatched.append(command) or "ok",
    )
    missing = adapter.applicability(ActionRequest("", automatic("")))
    assert missing.missing_requirements == ("target",)

    unavailable = RegisteredToolAdapter(
        tool_fixture(enabled=False, requires=("missing",), is_available=lambda: False),
        lambda *_args: None,
    )
    assert unavailable.applicability(ActionRequest("", automatic(""))).missing_requirements == (
        "target",
        "provider_disabled",
        "dependency:missing",
    )
    generic_unavailable = RegisteredToolAdapter(
        tool_fixture(is_available=lambda: False),
        lambda *_args: None,
    )
    assert generic_unavailable.applicability(
        ActionRequest("example.com", automatic())
    ).missing_requirements == ("provider_unavailable",)
    assert adapter.applicability(ActionRequest("example.com", automatic())).reasons == (
        "registered_tool_available",
    )

    by_id = ActionRequest(
        "example.com",
        automatic(),
        provider_commands={"tool:fixture": "fixture --by-id"},
    )
    assert adapter._command(by_id) == "fixture --by-id"
    by_name = ActionRequest(
        "example.com",
        automatic(),
        provider_commands={"fixture": "fixture_alias --by-name"},
    )
    assert adapter._command(by_name) == "fixture_alias --by-name"
    fallback = ActionRequest("example.com", automatic(), command="fixture example.com")
    assert adapter.execute(fallback) == "ok"
    assert dispatched == ["fixture example.com"]
    synthesized = ActionRequest("example.com", automatic(), arguments=("--safe", "two words"))
    assert adapter._command(synthesized) == "fixture example.com --safe 'two words'"

    targetless = RegisteredToolAdapter(
        tool_fixture(name="targetless", aliases=(), needs_target=False),
        lambda *_args: None,
    )
    assert targetless._command(ActionRequest("ignored", automatic(), arguments=("--flag",))) == (
        "targetless --flag"
    )
    with pytest.raises(ValueError, match="invalid_action_command_quoting"):
        adapter._command(ActionRequest("example.com", automatic(), command="fixture '"))
    with pytest.raises(ValueError, match="action_command_does_not_match_descriptor"):
        adapter._command(ActionRequest("example.com", automatic(), command="other command"))
    assert adapter.active_risk_class(
        ActionRequest("example.com", automatic(), command="fixture '"),
    ) is ActiveRiskClass.READ_ONLY

    killchain = KillchainActionAdapter(
        tool_fixture(name="killchain_fixture", aliases=()),
        lambda *_args: None,
    )
    assert killchain.descriptor.kind is ActionKind.KILLCHAIN
    with pytest.raises(ValueError, match="requires a killchain"):
        KillchainActionAdapter(tool_fixture(), lambda *_args: None)


def test_exploit_and_metasploit_adapter_boundaries(monkeypatch):
    exploit = SimpleNamespace(
        name="CVE fixture",
        cve="CVE-2026-1",
        description="fixture",
        supported_os=("linux",),
    )
    exploit_adapter = ExploitBaseAdapter(exploit)
    exploit_result = exploit_adapter.applicability(
        ActionRequest(
            "example.com",
            automatic(),
            parameters={"target_os": "windows"},
            handle=None,
        )
    )
    assert exploit_result.missing_requirements == ("provider_handle", "supported_os:linux")

    with pytest.raises(ValueError, match="Invalid Metasploit"):
        MetasploitActionAdapter("not a module")

    fake_msf = ModuleType("msf")
    fake_msf.run_msf_module = lambda *args, **kwargs: (args, kwargs)
    monkeypatch.setitem(sys.modules, "msf", fake_msf)
    assert MetasploitActionAdapter._default_runner("module", mode="check") == (
        ("module",),
        {"mode": "check"},
    )

    outputs = iter(
        (
            "msfconsole is not installed",
            "target does not appear to be vulnerable",
            "target appears to be vulnerable",
            "unknown response",
        )
    )
    adapter = MetasploitActionAdapter(
        "auxiliary/scanner/http/fixture",
        runner=lambda *_args, **_kwargs: next(outputs),
        dependency_check=lambda _name: True,
    )
    mapping_options = ActionRequest(
        "example.com",
        automatic(),
        parameters={"options": {"B": 2, "A": 1}},
    )
    assert adapter._options(mapping_options) == "RHOSTS=example.com A=1 B=2"
    assert adapter._options(
        ActionRequest(
            "example.com",
            automatic(),
            parameters={"options": "RHOST=other.example"},
        )
    ) == "RHOST=other.example"
    assert adapter._options(
        ActionRequest("", automatic(""), parameters={"options": "THREADS=2"})
    ) == "THREADS=2"

    unavailable = adapter.check(mapping_options)
    assert unavailable.result["status"] == "unavailable"
    assert unavailable.applicable is None
    assert adapter.check(mapping_options).applicable is False
    assert adapter.check(mapping_options).applicable is True
    assert adapter.check(mapping_options).applicable is None

    missing_dependency = MetasploitActionAdapter(
        "post/linux/gather/fixture",
        runner=lambda *_args, **_kwargs: "ok",
        dependency_check=lambda _name: False,
    )
    assert missing_dependency.applicability(mapping_options).missing_requirements == (
        "binary:msfconsole",
    )


class PluginManagerFixture:
    def __init__(self, *, plugin_type: str = "recon", validation: tuple[str, ...] = ()):
        self.plugin_type = plugin_type
        self.validation = validation
        self.calls: list[dict[str, Any]] = []

    def get_plugin(self, name: str):
        if name == "missing":
            return None
        return SimpleNamespace(
            plugin_type=self.plugin_type,
            description="fixture plugin",
            version="1",
            requires=("binary",),
            python_deps=("package",),
            capabilities=("network",),
        )

    def validate(self, _name: str):
        return self.validation

    def check(self, *_args, **_kwargs):
        return SimpleNamespace(vulnerable=True, details="details", evidence="evidence")

    def execute(self, _name: str, **kwargs: Any):
        self.calls.append(kwargs)
        return "executed"


def test_plugin_adapter_actions_execution_and_cleanup():
    with pytest.raises(KeyError, match="Unknown plugin"):
        PluginActionAdapter(PluginManagerFixture(), "missing")

    manager = PluginManagerFixture(validation=("dependency:missing",))
    adapter = PluginActionAdapter(manager, "fixture")
    applicability = adapter.applicability(ActionRequest("", automatic("")))
    assert applicability.missing_requirements == ("target", "dependency:missing")
    manager.validation = ()
    request = ActionRequest(
        "example.com",
        automatic(),
        parameters={"action": "custom", "timeout": 1, "flag": True},
    )
    assert adapter._action(request, "check") == "check"
    assert adapter._action(ActionRequest("example.com", automatic()), "execute") == "scan"
    assert adapter._action(request, "execute") == "custom"
    assert adapter.invocation(request, "check").registered_name == "plugin"
    assert adapter.check(request).applicable is True
    assert adapter.execute(request) == "executed"
    assert manager.calls[0]["action"] == "custom"
    assert "timeout" in manager.calls[0]
    assert manager.calls[0]["flag"] is True

    active_adapter = PluginActionAdapter(PluginManagerFixture(plugin_type="exploit"), "fixture")
    assert active_adapter._action(ActionRequest("example.com", automatic()), "execute") == "run"

    assert adapter.cleanup(request, None).succeeded is True
    failed = adapter.cleanup(
        request,
        ExecutionResult(stderr="provider cleanup failed: fixture"),
    )
    assert failed == ActionCleanupResult(False, "plugin_worker_cleanup_failed")
    assert adapter.cleanup(request, ExecutionResult(stdout="complete")).reason == (
        "plugin_worker_cleanup_succeeded"
    )


class BoundaryAdapter(ActionAdapter):
    def __init__(
        self,
        action_id: str,
        *,
        active: bool = False,
        aliases: tuple[str, ...] = (),
        risk_error: bool = False,
        applicability: ApplicabilityResult | None = None,
        applicability_error: bool = False,
        authorization: str = "allow",
    ) -> None:
        self.descriptor = descriptor(action_id, active=active, aliases=aliases)
        self.risk_error = risk_error
        self.applicability_result = applicability or ApplicabilityResult(True)
        self.applicability_error = applicability_error
        self.authorization = authorization

    def active_risk_class(self, request: ActionRequest, phase: str = "execute"):
        if self.risk_error:
            raise RuntimeError("risk fixture")
        return super().active_risk_class(request, phase)

    def applicability(self, request: ActionRequest) -> ApplicabilityResult:
        if self.applicability_error:
            raise RuntimeError("applicability fixture")
        return self.applicability_result

    def authorize(self, policy, request: ActionRequest, phase: str):
        del policy, phase
        if self.authorization == "error":
            raise RuntimeError("authorization fixture")
        return ExecutionDecision(
            allowed=self.authorization == "allow",
            reason="allowed" if self.authorization == "allow" else "scope denied: target",
            context=request.execution_context,
        )

    def invocation(self, request: ActionRequest, phase: str):
        return self.registered_invocation(f"fixture {request.target}", "fixture")

    def execute(self, request: ActionRequest):
        return {"status": "succeeded", "target": request.target}


class CircuitFixture:
    def __init__(self, states: dict[str, ProviderCircuitState]):
        self.states = states

    def evaluate(self, provider_id: str, *_args, **_kwargs) -> ProviderCircuitState:
        return self.states.get(provider_id, ProviderCircuitState("closed", True, "closed"))


def test_selector_exception_denial_duplicate_and_half_open_paths():
    from core.actions import ActionCatalog

    catalog = ActionCatalog()
    adapters = (
        BoundaryAdapter("test:active", active=True, aliases=("active-alias",), risk_error=True),
        BoundaryAdapter("test:risk-readonly", risk_error=True, applicability_error=True),
        BoundaryAdapter("test:auth-error", authorization="error"),
        BoundaryAdapter("test:denied", authorization="deny"),
        BoundaryAdapter(
            "test:not-applicable",
            applicability=ApplicabilityResult(False, missing_requirements=("fixture",)),
        ),
    )
    for adapter in adapters:
        catalog.register(adapter)
    telemetry = ProviderTelemetryStore(":memory:")
    selector = ProviderSelector(
        catalog,
        object(),
        telemetry,
        CircuitFixture({
            "test:active": ProviderCircuitState("half_open", True, "probe"),
        }),
    )
    selection = selector.select(
        "service discovery!",
        ActionRequest("example.com", automatic()),
        (
            "test:active",
            "active-alias",
            "test:risk-readonly",
            "test:auth-error",
            "test:denied",
            "test:not-applicable",
            "unknown name",
            "",
        ),
    )
    assert selection.chosen_action_id == "test:active"
    assert len(selection.ranked) == 1
    accepted = selection.ranked[0]
    assert accepted.active_risk_class is ActiveRiskClass.ACTIVE
    assert "circuit:half_open_penalty:-25.000" in accepted.reasons
    rejected = {item.action_id: item for item in selection.rejected}
    assert "applicability_error:RuntimeError" in rejected["test:risk-readonly"].reasons
    assert "authorization_error:RuntimeError" in rejected["test:auth-error"].reasons
    assert rejected["test:denied"].policy_denial.reason_code == "scope_denied"
    assert "not_applicable:fixture" in rejected["test:not-applicable"].reasons
    assert rejected["unknown:unknown_name"].reasons == ("unknown_action",)
    assert len(selection.to_dict()["rejected"]) == 5
    assert accepted.to_dict()["policy_denial"] is None
    assert rejected["test:denied"].to_dict()["policy_denial"]["phase"] == "selection"
    telemetry.close()


class RecentEventsFixture:
    def __init__(self, events: tuple[tuple[str, float], ...]):
        self.events = events

    def recent_events(self, *_args, **_kwargs):
        return self.events


def test_circuit_scoring_and_label_helpers(monkeypatch):
    closed = ProviderCircuitBreaker(
        RecentEventsFixture((("succeeded", 100.0),)),
        failure_threshold=1,
        cooldown_seconds=0,
    )
    assert closed.failure_threshold == 2
    assert closed.cooldown_seconds == 1.0
    assert closed.evaluate("provider", "capability", "dns").state == "closed"

    breaker = ProviderCircuitBreaker(
        RecentEventsFixture((("unavailable", 100.0), ("unavailable", 99.0))),
        failure_threshold=2,
        cooldown_seconds=10,
    )
    opened = breaker.evaluate("provider", "capability", "dns", now=105.0)
    assert opened.state == "open"
    assert opened.retry_after_seconds == 5.0
    assert breaker.evaluate("provider", "capability", "dns", now=111.0).state == "half_open"
    monkeypatch.setattr("core.actions.selection.time.time", lambda: 105.0)
    assert breaker.evaluate("provider", "capability", "dns").state == "open"

    no_samples_score, no_samples_reasons = ProviderSelector._score(telemetry_summary(), 1.0)
    assert no_samples_score == 40.0
    assert "telemetry:no_samples" in no_samples_reasons
    rich = telemetry_summary(
        samples=1,
        dependency_availability_rate=1.0,
        average_duration=30_000.0,
        timeout_rate=0.0,
        failure_rate=0.0,
        unavailable_rate=0.0,
        success_rate=10.0,
        useful_fact_yield=100.0,
        duplicate_yield_rate=0.0,
        parser_quality=1.0,
        scope_compatibility_rate=1.0,
    )
    assert ProviderSelector._score(rich, 0.0)[0] == 100.0
    bad = telemetry_summary(
        samples=1,
        average_duration=30_000.0,
        timeout_rate=10.0,
        failure_rate=10.0,
        unavailable_rate=10.0,
        duplicate_yield_rate=10.0,
    )
    assert ProviderSelector._score(bad, 1.0)[0] == -100.0
    assert ProviderSelector._label(" two words! ") == "two_words_"
    assert ProviderSelector._reason_code("") == "unknown"
    with pytest.raises(ValueError, match="must not be empty"):
        ProviderSelector._label("")


def test_ingestion_retry_and_run_result_projection():
    outcome = IngestionOutcome(parsed_facts=1)
    assert IngestionOutcome.from_value(outcome) is outcome
    assert IngestionOutcome.from_value("not a mapping") == IngestionOutcome()
    converted = IngestionOutcome.from_value({
        "parsed_facts": "5",
        "useful_facts": 0,
        "new_facts": 2,
        "duplicate_facts": -1,
        "parser_items": 0,
        "parser_errors": object(),
        "error": "fixture",
    })
    assert converted == IngestionOutcome(
        parsed_facts=5,
        useful_facts=2,
        duplicate_facts=0,
        parser_items=5,
        parser_errors=0,
        error="fixture",
    )
    direct = IngestionOutcome.from_value({
        "parsed_facts": 2_000_000,
        "useful_facts": 3,
        "parser_items": 4,
    })
    assert direct.parsed_facts == 1_000_000
    assert direct.to_dict()["parser_items"] == 4

    assert RetryClassifier.is_retryable(ExecutionResult(status=ExecutionStatus.SUCCEEDED)) is False
    assert RetryClassifier.is_retryable(
        ExecutionResult(status=ExecutionStatus.FAILED, metadata={"retryable": True})
    ) is True

    denial = PolicyDenial.create("selection", "denied")
    rejected_selection = provider_selection(
        rejected=(
            provider_decision("test:no-denial"),
            provider_decision(denial=denial),
        )
    )
    empty_run = ProviderRunResult(rejected_selection, (), None)
    assert empty_run.effective_result is None
    assert empty_run.policy_denial == denial
    assert empty_run.status is ExecutionStatus.BLOCKED
    assert empty_run.to_dict()["final_report"] is None

    final_denial = PolicyDenial.create("execute", "blocked")
    denied_report = report_with(
        ExecutionResult(status=ExecutionStatus.SUCCEEDED),
        denials=[final_denial],
    )
    denied_run = ProviderRunResult(provider_selection(), (), denied_report)
    assert denied_run.effective_result is None
    assert denied_run.policy_denial == final_denial

    checked = ExecutionResult(status=ExecutionStatus.PARTIAL)
    checked_report = report_with(check=checked)
    checked_attempt = ProviderAttempt(
        "test:provider",
        checked_report,
        outcome,
        retryable=False,
        fallback_taken=False,
        stop_reason="done",
    )
    checked_run = ProviderRunResult(
        rejected_selection,
        (checked_attempt,),
        checked_report,
        trace={"fixture": True},
    )
    assert checked_run.effective_result is checked
    assert checked_run.policy_denial is None
    assert checked_run.status is ExecutionStatus.PARTIAL
    assert checked_attempt.to_dict()["stop_reason"] == "done"
    assert checked_run.to_dict()["trace"] == {"fixture": True}

    execution = ExecutionResult(status=ExecutionStatus.SUCCEEDED)
    executed_run = ProviderRunResult(provider_selection(), (), report_with(execution))
    assert executed_run.effective_result is execution
    assert executed_run.status is ExecutionStatus.SUCCEEDED
    assert ProviderRunResult(provider_selection(), (), None).status is ExecutionStatus.UNAVAILABLE


class StaticSelector:
    def __init__(self, selection: ProviderSelection):
        self.selection = selection

    def select(self, *_args, **_kwargs) -> ProviderSelection:
        return self.selection


class StaticExecutor:
    def __init__(self, reports: list[ActionExecutionReport]):
        self.reports = reports

    def run(self, *_args, **_kwargs) -> ActionExecutionReport:
        return self.reports.pop(0)


class RecordingTelemetry:
    def __init__(self, error: Exception | None = None):
        self.error = error
        self.events: list[ProviderTelemetryEvent] = []

    def record(self, event: ProviderTelemetryEvent) -> bool:
        if self.error:
            raise self.error
        self.events.append(event)
        return True


def test_fallback_empty_last_retry_and_ingestion_error_boundaries():
    empty = ProviderFallbackExecutor(
        StaticSelector(provider_selection()),
        StaticExecutor([]),
        RecordingTelemetry(),
    )
    empty_run = empty.run("discovery", ActionRequest("example.com", automatic()), ())
    assert empty_run.attempts == ()
    assert empty_run.status is ExecutionStatus.UNAVAILABLE

    decision = provider_decision()
    timed_out = ExecutionResult(
        status=ExecutionStatus.TIMEOUT,
        execution_id="execution-1",
        duration=2.0,
    )
    telemetry = RecordingTelemetry()
    fallback = ProviderFallbackExecutor(
        StaticSelector(provider_selection(ranked=(decision,))),
        StaticExecutor([report_with(timed_out)]),
        telemetry,
    )
    run = fallback.run(
        "discovery",
        ActionRequest("example.com", automatic()),
        ("test:provider",),
        action_options={"verify": False},
    )
    assert run.attempts[0].stop_reason == "retryable_failure_no_provider_remaining"
    assert telemetry.events[0].status == "timeout"

    output = ExecutionResult(status=ExecutionStatus.TIMEOUT, stdout="partial", partial=True)
    assert ProviderFallbackExecutor._ingest(None, "provider", lambda *_args: {}) == IngestionOutcome()
    assert ProviderFallbackExecutor._ingest(output, "provider", None) == IngestionOutcome()
    assert ProviderFallbackExecutor._ingest(
        ExecutionResult(status=ExecutionStatus.TIMEOUT),
        "provider",
        lambda *_args: {},
    ) == IngestionOutcome()
    assert ProviderFallbackExecutor._ingest(
        output,
        "provider",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("fixture")),
    ).error == "ingest_error:RuntimeError"
    request = ActionRequest("example.com", automatic())
    assert ProviderFallbackExecutor._ingest_partial(None, "provider", request, lambda *_args: {}) == (
        IngestionOutcome()
    )
    assert ProviderFallbackExecutor._ingest_partial(output, "provider", request, None) == (
        IngestionOutcome()
    )
    assert ProviderFallbackExecutor._ingest_partial(
        output,
        "provider",
        request,
        lambda *_args: (_ for _ in ()).throw(ValueError("fixture")),
    ).error == "ingest_error:ValueError"

    broken = ProviderFallbackExecutor(
        StaticSelector(provider_selection()),
        StaticExecutor([]),
        RecordingTelemetry(ValueError("fixture")),
    )
    broken._record_telemetry(
        "discovery",
        "dns",
        decision,
        None,
        IngestionOutcome(error="fixture"),
        retryable=False,
        partial_output_ingested=False,
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        ("", "none"),
        ("https://example.com/path", "url_https_dns"),
        ("https://[::1]/", "url_https_ip6_private"),
        ("10.0.0.0/24", "network_4_private"),
        ("bad/24", "opaque"),
        ("example.com:443", "dns"),
        ("example.com:notaport", "dns"),
        ("localhost", "local"),
        ("example.com", "dns"),
        ("bad.name with-space", "opaque"),
        ("opaque", "opaque"),
    ),
)
def test_target_class_boundary_matrix(raw, expected):
    assert target_class(raw) == expected


def telemetry_event(index: int, **overrides: Any) -> ProviderTelemetryEvent:
    values: dict[str, Any] = {
        "provider_id": "provider fixture!",
        "capability": "service discovery",
        "target_class": "dns",
        "status": "succeeded",
        "dependency_available": True,
        "scope_compatible": True,
        "active_risk": 0.0,
        "duration": 0.0,
        "execution_id": f"execution-{index}",
        "observed_at": float(index),
    }
    values.update(overrides)
    return ProviderTelemetryEvent(**values)


def test_telemetry_validation_transactions_summary_and_bounds(tmp_path):
    assert ProviderTelemetryStore._label(" label with spaces! ", limit=8) == "label_wi"
    with pytest.raises(ValueError, match="must not be empty"):
        ProviderTelemetryStore._label("")
    assert ProviderTelemetryStore._count(object()) == 0
    assert ProviderTelemetryStore._count(-1) == 0
    assert ProviderTelemetryStore._count(2_000_000) == 1_000_000
    assert ProviderTelemetryStore._finite(object(), maximum=1.0) == 0.0
    assert ProviderTelemetryStore._finite(math.nan, maximum=1.0) == 0.0
    assert ProviderTelemetryStore._finite(-1, maximum=1.0) == 0.0
    assert ProviderTelemetryStore._finite(2, maximum=1.0) == 1.0

    store = ProviderTelemetryStore(":memory:", max_events_per_key=1, max_total_events=1)
    assert store.max_events_per_key == 5
    assert store.max_total_events == 5
    with pytest.raises(RuntimeError, match="rollback fixture"), store._connect() as conn:
        conn.execute("CREATE TABLE rollback_fixture(value INTEGER)")
        raise RuntimeError("rollback fixture")
    rows = (
        telemetry_event(1, useful_facts=0, duplicate_facts=0, parser_items=0),
        telemetry_event(
            2,
            status="failed",
            dependency_available=False,
            scope_compatible=False,
            active_risk=1.0,
            duration=2.0,
            useful_facts=2,
            duplicate_facts=2,
            parser_items=4,
            parser_errors=1,
        ),
        telemetry_event(3, status="timeout"),
        telemetry_event(4, status="unavailable"),
        telemetry_event(5),
        telemetry_event(6),
    )
    for event in rows:
        assert store.record(event) is True
    assert store.count() == 5
    assert store.record(rows[-1]) is False
    no_execution_id = telemetry_event(7, execution_id="", observed_at=7.0)
    assert store.record(no_execution_id) is True
    assert store.record(no_execution_id) is False
    summary = store.summary("provider fixture!", "service discovery", "dns")
    assert summary.samples == 5
    assert summary.failure_rate >= 0.0
    assert summary.to_dict()["provider_id"] == "provider_fixture_"
    assert store.summary("missing", "service discovery", "dns").samples == 0
    assert len(store.recent_events("provider fixture!", "service discovery", "dns", limit=0)) == 1
    assert len(store.recent_events("provider fixture!", "service discovery", "dns", limit=999)) == 5
    store.close()
    store.close()

    db_path = tmp_path / "telemetry.sqlite"
    file_store = ProviderTelemetryStore(str(db_path))
    assert file_store.record(telemetry_event(10)) is True
    file_store.close()

    unsupported_path = tmp_path / "unsupported.sqlite"
    conn = sqlite3.connect(unsupported_path)
    conn.execute(
        "CREATE TABLE provider_telemetry_schema(schema_version TEXT PRIMARY KEY, applied_at REAL NOT NULL)"
    )
    conn.execute(
        "INSERT INTO provider_telemetry_schema(schema_version, applied_at) VALUES (?, ?)",
        ("9.9", 0.0),
    )
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError, match="Unsupported provider-telemetry schema"):
        ProviderTelemetryStore(str(unsupported_path))
