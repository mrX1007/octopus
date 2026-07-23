"""Focused contracts for the read-only capability assessment facade."""

import json
from dataclasses import FrozenInstanceError

import pytest

from core.ai.capability_assessment import (
    STRATEGIC_TASKS,
    CapabilityAssessment,
    CapabilityResolver,
    FreshnessConfidenceSummary,
    ProviderAssessment,
)
from core.ai.command_scheduler import CommandScheduler
from core.ai.context_builder import ContextBuilder
from core.ai.llm_context import compact_context_for_llm
from core.ai.planner import MissionPlanCompiler
from core.execution import ExecutionContext

pytestmark = pytest.mark.contract

TARGET = "10.0.0.5"


class StubRegistry:
    """Minimal deterministic registry surface consumed by the resolver."""

    def __init__(self, statuses=None, profiles=None, aliases=None):
        self.statuses = statuses or {}
        self.profiles = profiles or {}
        self.aliases = aliases or {}
        self.status_requests = []

    def canonical_task(self, task):
        normalized = str(task or "").strip().lower().replace("-", "_").replace(" ", "_")
        return self.aliases.get(normalized, normalized)

    def task_profile(self, task):
        return dict(self.profiles.get(self.canonical_task(task), {"preconditions": []}))

    def get_provider_statuses_for_task(self, task):
        task = self.canonical_task(task)
        self.status_requests.append(task)
        return [dict(record) for record in self.statuses.get(task, ())]

    def get_commands_for_task(self, *_args, **_kwargs):
        raise AssertionError("capability resolution must not request executable commands")


class StubPolicyDecision:
    def __init__(self, allowed, reason):
        self.allowed = bool(allowed)
        self.reason = reason

    def to_dict(self):
        return {
            "action": "execute" if self.allowed else "deny",
            "reason": self.reason,
        }


class MutablePolicy:
    """Policy double whose decision can change between assessment and dispatch."""

    def __init__(self, allowed=True, reason="stub_authorized", denied_markers=()):
        self.allowed = allowed
        self.reason = reason
        self.denied_markers = tuple(denied_markers)
        self.calls = []

    def authorize_command(self, command, context):
        self.calls.append((command, context))
        denied_by_marker = any(marker in command for marker in self.denied_markers)
        allowed = bool(self.allowed and not denied_by_marker)
        reason = self.reason if not denied_by_marker else "marker_denied"
        return StubPolicyDecision(allowed, reason)


def _execution_context():
    return ExecutionContext.automatic(
        (TARGET,), actor="scan:phase3", origin="ai_pipeline"
    )


def _provider_record(provider="stub_provider", *, available=True, command=None, **extra):
    record = {
        "provider": provider,
        "available": available,
        "command_template": command or f"{provider} {{target}}",
    }
    record.update(extra)
    return record


def _assessment(
    *,
    capability="service_discovery",
    provider_availability="available",
    authorization_decision="allowed",
    authorization_reason="stub_authorized",
    missing_requirements=(),
    blocking_reasons=(),
):
    if provider_availability == "no_provider":
        providers = ()
    else:
        status = (
            "not_applicable"
            if provider_availability == "not_applicable"
            else provider_availability
        )
        providers = (
            ProviderAssessment(
                task=capability,
                provider="analysis_agent" if status == "not_applicable" else "stub_provider",
                status=status,
                authorization_decision=authorization_decision,
                authorization_reason=authorization_reason,
            ),
        )
    return CapabilityAssessment(
        capability=capability,
        target=TARGET,
        scope=(TARGET,),
        requested=True,
        providers=providers,
        provider_availability=provider_availability,
        authorization_decision=authorization_decision,
        authorization_reason=authorization_reason,
        evidence_state="confirmed_present",
        requirements=("services",),
        missing_requirements=tuple(missing_requirements),
        blocking_reasons=tuple(blocking_reasons),
        supporting_fact_ids=(3, 7),
        freshness_confidence=FreshnessConfidenceSummary(
            fact_count=2,
            oldest_observed_at=10.0,
            newest_observed_at=30.0,
            confidence_min=0.4,
            confidence_max=0.9,
            confidence_average=0.7,
        ),
    )


def _fully_satisfied_context(capability):
    return {
        "host": TARGET,
        "state": "root_access_confirmed",
        "services": ["http", "ssh"],
        "stage_gates": {
            "recon": True,
            "credentials": True,
            "root": True,
            "post_access_inventory": True,
            "persistence": True,
            "internal_recon": True,
            "exfiltration": True,
            "cleanup": True,
        },
        "automation_policy": {
            "auto_payload_generation": True,
            "auto_persistence": True,
            "auto_internal_recon": True,
            "auto_data_exfil": True,
            "auto_cleanup": True,
        },
        "target_model": {"access": {"ssh_authenticated": True, "root_confirmed": True}},
        "next_required_capability": capability,
    }


def test_assessment_models_are_immutable_and_serialize_every_contract_field():
    assessment = _assessment()

    expected = {
        "capability": "service_discovery",
        "target": TARGET,
        "scope": [TARGET],
        "requested": True,
        "providers": [
            {
                "task": "service_discovery",
                "provider": "stub_provider",
                "status": "available",
                "authorization_decision": "allowed",
                "authorization_reason": "stub_authorized",
            }
        ],
        "provider_availability": "available",
        "authorization_decision": "allowed",
        "authorization_reason": "stub_authorized",
        "evidence_state": "confirmed_present",
        "requirements": ["services"],
        "missing_requirements": [],
        "blocking_reasons": [],
        "supporting_fact_ids": [3, 7],
        "freshness_confidence": {
            "fact_count": 2,
            "oldest_observed_at": 10.0,
            "newest_observed_at": 30.0,
            "confidence_min": 0.4,
            "confidence_max": 0.9,
            "confidence_average": 0.7,
            "freshness": "not_assessed",
        },
        "hard_unavailable": False,
        "ready": True,
    }

    payload = assessment.to_dict()

    assert payload == expected
    assert json.loads(json.dumps(payload)) == expected
    with pytest.raises(FrozenInstanceError):
        assessment.capability = "changed"
    with pytest.raises(FrozenInstanceError):
        assessment.providers[0].status = "changed"
    with pytest.raises(FrozenInstanceError):
        assessment.freshness_confidence.fact_count = 99

    payload["providers"][0]["status"] = "changed"
    assert assessment.providers[0].status == "available"


@pytest.mark.parametrize(
    (
        "expected_availability",
        "records",
        "agent",
        "expected_authorization",
        "expected_provider_statuses",
        "expected_hard_unavailable",
    ),
    [
        ("available", [_provider_record()], "DiscoveryAgent", "allowed", ("available",), False),
        (
            "unavailable",
            [_provider_record(available=False)],
            "DiscoveryAgent",
            "unknown",
            ("unavailable",),
            True,
        ),
        ("no_provider", [], "DiscoveryAgent", "unknown", (), True),
        (
            "not_applicable",
            [],
            "AnalysisAgent",
            "not_applicable",
            ("not_applicable",),
            False,
        ),
    ],
)
def test_resolver_distinguishes_all_provider_availability_states(
    expected_availability,
    records,
    agent,
    expected_authorization,
    expected_provider_statuses,
    expected_hard_unavailable,
):
    capability = (
        "analyze_vulnerabilities"
        if expected_availability == "not_applicable"
        else "custom_capability"
    )
    registry = StubRegistry({capability: records})
    resolver = CapabilityResolver(registry, MutablePolicy())

    assessment = resolver.resolve(
        capability,
        target=TARGET,
        facts=[],
        context={},
        execution_context=_execution_context(),
        agent=agent,
    )

    assert assessment.provider_availability == expected_availability
    assert assessment.authorization_decision == expected_authorization
    assert tuple(provider.status for provider in assessment.providers) == (
        expected_provider_statuses
    )
    assert assessment.hard_unavailable is expected_hard_unavailable
    assert assessment.ready is (not expected_hard_unavailable)


@pytest.mark.parametrize(("capability", "expected_tasks"), tuple(STRATEGIC_TASKS.items()))
def test_strategic_capabilities_expand_to_their_concrete_task_mapping(
    capability, expected_tasks
):
    registry = StubRegistry(
        {
            task: [
                _provider_record(
                    f"provider_for_{task}", command=f"provider_for_{task} {{target}}"
                )
            ]
            for task in expected_tasks
        }
    )
    resolver = CapabilityResolver(registry, MutablePolicy())

    assessment = resolver.resolve(
        capability,
        target=TARGET,
        facts=[],
        context=_fully_satisfied_context(capability),
        execution_context=_execution_context(),
    )

    assert tuple(registry.status_requests) == expected_tasks
    if capability == "conclude":
        assert assessment.provider_availability == "not_applicable"
        assert tuple(provider.provider for provider in assessment.providers) == (
            "control_plane",
        )
    else:
        assert tuple(provider.task for provider in assessment.providers) == expected_tasks
        assert assessment.provider_availability == "available"
    assert assessment.requested is True


def test_supporting_fact_ids_and_observation_bounds_are_evidence_derived():
    registry = StubRegistry(
        {"vulnerability_assessment": [_provider_record("vuln_probe")]}
    )
    resolver = CapabilityResolver(registry, MutablePolicy())
    facts = [
        {
            "id": "7",
            "type": "port_open",
            "value": "80/tcp (http)",
            "timestamp": 999,
            "confidence": 0.99,
            "observations": [
                {"timestamp": "20", "confidence": "0.8"},
                {"timestamp": 10, "confidence": 0.4},
            ],
        },
        {
            "id": 3,
            "type": "web_endpoint",
            "value": "http://10.0.0.5/",
            "timestamp": 30,
            "confidence": 0.9,
        },
        {
            "id": 99,
            "type": "unrelated",
            "value": "does not establish a requirement",
            "timestamp": 1,
            "confidence": 0.1,
        },
    ]
    context = {
        "services": ["http"],
        "stage_gates": {"recon": True},
        "next_required_capability": "vulnerability_assessment",
    }

    assessment = resolver.resolve(
        "vulnerability_assessment",
        target=TARGET,
        facts=facts,
        context=context,
        execution_context=_execution_context(),
    )

    assert assessment.evidence_state == "confirmed_present"
    assert assessment.supporting_fact_ids == (3, 7)
    assert assessment.freshness_confidence == FreshnessConfidenceSummary(
        fact_count=2,
        oldest_observed_at=10.0,
        newest_observed_at=30.0,
        confidence_min=0.4,
        confidence_max=0.9,
        confidence_average=0.7,
    )


def test_missing_requirements_and_authorization_denial_have_distinct_blockers():
    registry = StubRegistry(
        {"establish_persistence": [_provider_record("stub_persistence")]}
    )
    resolver = CapabilityResolver(
        registry, MutablePolicy(allowed=False, reason="approval_revoked")
    )

    assessment = resolver.resolve(
        "persistence",
        target=TARGET,
        facts=[],
        context={
            "state": "initial_recon",
            "stage_gates": {"root": False},
            "automation_policy": {"auto_persistence": False},
        },
        execution_context=_execution_context(),
    )

    assert assessment.provider_availability == "available"
    assert assessment.authorization_decision == "denied"
    assert assessment.authorization_reason == "stub_persistence:approval_revoked"
    assert assessment.missing_requirements == (
        "stage:root",
        "access",
        "policy:auto_persistence",
    )
    assert assessment.blocking_reasons == (
        "authorization:denied:stub_persistence:approval_revoked",
        "requirement:missing:stage:root",
        "requirement:missing:access",
        "requirement:missing:policy:auto_persistence",
    )
    assert assessment.hard_unavailable is False
    assert assessment.ready is False


def test_resolver_reads_provider_metadata_without_invoking_provider_callable():
    provider_calls = []

    def provider_callable(*args, **kwargs):
        provider_calls.append((args, kwargs))
        raise AssertionError("provider execution escaped the read-only facade")

    registry = StubRegistry(
        {
            "read_only_check": [
                _provider_record("safe_probe", callable=provider_callable)
            ]
        }
    )
    resolver = CapabilityResolver(registry, MutablePolicy())

    assessment = resolver.resolve(
        "read_only_check",
        target=TARGET,
        facts=[],
        context={},
        execution_context=_execution_context(),
    )

    assert assessment.provider_availability == "available"
    assert provider_calls == []


def test_tool_registry_provider_description_expands_nested_tasks_read_only():
    from core.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()
    registry.task_map = {
        "outer_task": [("inner_task {target}", "inner_task")],
        "inner_task": [("leaf_probe {target}", "leaf_probe")],
    }
    registry._available_cache = {"leaf_probe": True}

    statuses = registry.get_provider_statuses_for_task("outer_task")

    assert statuses == [
        {
            "task": "outer_task",
            "provider": "leaf_probe",
            "command_template": "leaf_probe {target}",
            "available": True,
        }
    ]


def test_analysis_provider_exemption_requires_exact_agent_task_pair():
    registry = StubRegistry(
        {"service_discovery": [_provider_record("service_probe")]}
    )
    resolver = CapabilityResolver(registry, MutablePolicy())
    execution_context = _execution_context()

    exact = resolver.resolve(
        "analyze_vulnerabilities",
        target=TARGET,
        facts=[],
        context={},
        execution_context=execution_context,
        agent="AnalysisAgent",
    )
    unknown = resolver.resolve(
        "totally_unknown",
        target=TARGET,
        facts=[],
        context={},
        execution_context=execution_context,
        agent="AnalysisAgent",
    )
    mismatched_tool = resolver.resolve(
        "service_discovery",
        target=TARGET,
        facts=[],
        context={},
        execution_context=execution_context,
        agent="AnalysisAgent",
    )
    mismatched_analysis = resolver.resolve(
        "analyze_vulnerabilities",
        target=TARGET,
        facts=[],
        context={},
        execution_context=execution_context,
        agent="DiscoveryAgent",
    )

    assert exact.provider_availability == "not_applicable"
    assert unknown.provider_availability == "no_provider"
    assert mismatched_tool.provider_availability == "no_provider"
    assert mismatched_analysis.provider_availability == "no_provider"


def test_unknown_authorization_is_not_reported_as_ready():
    registry = StubRegistry(
        {"contextless_task": [_provider_record("contextless_probe")]}
    )
    resolver = CapabilityResolver(registry, MutablePolicy())

    assessment = resolver.resolve(
        "contextless_task",
        target=TARGET,
        facts=[],
        context={},
        execution_context=None,
    )

    assert assessment.provider_availability == "available"
    assert assessment.authorization_decision == "unknown"
    assert assessment.blocking_reasons == (
        "authorization:unknown:execution_context_not_supplied",
    )
    assert assessment.hard_unavailable is False
    assert assessment.ready is False


def test_supporting_fact_rules_cover_resolved_root_and_internal_recon_evidence():
    registry = StubRegistry(
        {
            "post_access_inventory": [_provider_record("inventory_probe")],
            "internal_stage_task": [_provider_record("internal_probe")],
        },
        profiles={
            "internal_stage_task": {"preconditions": ["stage:internal_recon"]},
        },
    )
    resolver = CapabilityResolver(registry, MutablePolicy())
    root = resolver.resolve(
        "post_access_inventory",
        target=TARGET,
        facts=[
            {
                "id": 41,
                "type": "exploit_success",
                "value": "pwnkit root shell",
                "timestamp": 10,
                "confidence": 90,
            },
        ],
        context={
            "state": "root_access_confirmed",
            "stage_gates": {"root": True},
            "target_model": {"access": {"root_confirmed": True}},
        },
        execution_context=_execution_context(),
    )
    internal = resolver.resolve(
        "internal_stage_task",
        target=TARGET,
        facts=[
            {
                "id": 42,
                "type": "service_status",
                "value": "network_recon_completed",
                "timestamp": 20,
                "confidence": 85,
            },
        ],
        context={"stage_gates": {"internal_recon": True}},
        execution_context=_execution_context(),
    )

    assert root.supporting_fact_ids == (41,)
    assert internal.supporting_fact_ids == (42,)


class StubFactStore:
    def __init__(self, facts=()):
        self.facts = [dict(fact) for fact in facts]
        self.calls = []

    def get_facts(self, scan_id, host):
        self.calls.append((scan_id, host))
        return [dict(fact) for fact in self.facts]


class StubStateResolver:
    def __init__(self, state=None):
        self.state = dict(state or {})
        self.calls = []

    def resolve_state(self, scan_id, host):
        self.calls.append((scan_id, host))
        return dict(self.state)


class RecordingCapabilityResolver:
    def __init__(self):
        self.calls = []
        self.results = []

    def resolve(self, capability, **kwargs):
        call = {"capability": capability, **kwargs}
        self.calls.append(call)
        execution_context = kwargs["execution_context"]
        result = CapabilityAssessment(
            capability=capability,
            target=kwargs["target"],
            scope=tuple(execution_context.target_scope) if execution_context else (),
            requested=bool(kwargs.get("requested")),
            providers=(
                ProviderAssessment(
                    task=capability,
                    provider="recording_provider",
                    status="available",
                    authorization_decision="allowed",
                    authorization_reason="recorded",
                ),
            ),
            provider_availability="available",
            authorization_decision="allowed",
            authorization_reason="recorded",
            evidence_state="unknown",
            requirements=(),
            missing_requirements=(),
            blocking_reasons=(),
            supporting_fact_ids=(),
            freshness_confidence=FreshnessConfidenceSummary(),
        )
        self.results.append(result)
        return result


def test_context_builder_exposes_assessment_with_exact_supplied_execution_context():
    capability_resolver = RecordingCapabilityResolver()

    def unused_factory(_scan_id, _host):
        raise AssertionError("factory must not replace an explicitly supplied context")

    builder = ContextBuilder(
        StubFactStore(),
        StubStateResolver(),
        capability_resolver,
        unused_factory,
    )
    supplied = _execution_context()

    context = builder.build_context("scan-supplied", TARGET, supplied)

    assert capability_resolver.calls[0]["execution_context"] is supplied
    assert capability_resolver.calls[0]["requested"] is True
    assert context["capability_assessment"] == capability_resolver.results[0].to_dict()


def test_context_builder_exposes_assessment_with_exact_factory_execution_context():
    capability_resolver = RecordingCapabilityResolver()
    factory_calls = []
    produced = ExecutionContext.automatic(
        (TARGET,), actor="factory:phase3", origin="factory"
    )

    def factory(scan_id, host):
        factory_calls.append((scan_id, host))
        return produced

    builder = ContextBuilder(
        StubFactStore(), StubStateResolver(), capability_resolver, factory
    )

    context = builder.build_context("scan-factory", TARGET)

    assert factory_calls == [("scan-factory", TARGET)]
    assert capability_resolver.calls[0]["execution_context"] is produced
    assert context["capability_assessment"] == capability_resolver.results[0].to_dict()


def test_compact_llm_context_retains_the_capability_assessment():
    assessment = _assessment().to_dict()

    compact = compact_context_for_llm(
        {
            "host": TARGET,
            "state": "recon_completed",
            "capability_assessment": assessment,
            "raw_noise": ["discard me"],
        },
        role="planner",
    )

    assert compact["capability_assessment"] == assessment
    assert "raw_noise" not in compact


def test_plan_compiler_rejects_only_hard_provider_failures():
    registry = StubRegistry(
        {
            "available_task": [_provider_record("available_tool")],
            "denied_task": [_provider_record("denied_tool")],
            "unavailable_task": [
                _provider_record("missing_tool", available=False)
            ],
        }
    )
    policy = MutablePolicy(denied_markers=("denied_tool",))
    resolver = CapabilityResolver(registry, policy)
    compiler = MissionPlanCompiler(resolver)
    execution_context = _execution_context()
    plan = [
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
        {"agent": "DiscoveryAgent", "task": "available_task", "note": "preserved"},
        {"agent": "VerificationAgent", "task": "denied_task"},
        {"agent": "DiscoveryAgent", "task": "unavailable_task"},
        {"agent": "DiscoveryAgent", "task": "no_provider_task"},
        {"agent": "AnalysisAgent", "task": "totally_unknown"},
        {"agent": "DiscoveryAgent", "task": "analyze_vulnerabilities"},
    ]

    denied_assessment = resolver.resolve(
        "denied_task",
        target=TARGET,
        facts=[],
        context={},
        execution_context=execution_context,
        agent="VerificationAgent",
    )
    compilation = compiler.compile(
        plan,
        target=TARGET,
        facts=[],
        context={},
        execution_context=execution_context,
    )

    assert denied_assessment.provider_availability == "available"
    assert denied_assessment.authorization_decision == "denied"
    assert compilation.plan == tuple(plan[:3])
    assert tuple(item["task"] for item in compilation.rejected) == (
        "unavailable_task",
        "no_provider_task",
        "totally_unknown",
        "analyze_vulnerabilities",
    )
    assert tuple(item["reason"] for item in compilation.rejected) == (
        "capability_unavailable",
        "capability_no_provider",
        "capability_no_provider",
        "capability_no_provider",
    )
    assert compilation.rejected[0]["blocking_reasons"] == ["provider:unavailable"]
    assert compilation.rejected[1]["blocking_reasons"] == ["provider:no_provider"]
    assert all(item["assessment"]["requested"] for item in compilation.rejected)


def test_scheduler_rechecks_policy_after_an_allowed_capability_assessment():
    registry = StubRegistry(
        {"policy_sensitive_task": [_provider_record("policy_probe")]}
    )
    policy = MutablePolicy(allowed=True, reason="initially_allowed")
    resolver = CapabilityResolver(registry, policy)
    execution_context = _execution_context()

    assessment = resolver.resolve(
        "policy_sensitive_task",
        target=TARGET,
        facts=[],
        context={},
        execution_context=execution_context,
    )
    policy.allowed = False
    policy.reason = "authorization_changed"
    decision = CommandScheduler(policy).decide(
        f"policy_probe {TARGET}",
        [],
        set(),
        execution_context=execution_context,
    )

    assert assessment.authorization_decision == "allowed"
    assert decision.action == "skip"
    assert decision.reason == "policy_denied:authorization_changed"
    assert len(policy.calls) == 2
    assert policy.calls[0][1] is execution_context
    assert policy.calls[1][1] is execution_context


def test_pipeline_composition_shares_registry_and_execution_policy(tmp_path):
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(str(tmp_path / "capability-composition.db"))

    assert pipeline.capability_resolver.tool_registry is pipeline.tool_registry
    assert (
        pipeline.capability_resolver.execution_policy
        is pipeline.command_scheduler.execution_policy
    )
    assert pipeline.context_builder.capability_resolver is pipeline.capability_resolver
    assert pipeline.plan_compiler.capability_resolver is pipeline.capability_resolver


def test_pipeline_optimizer_rejects_incompatible_analysis_task(tmp_path):
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(str(tmp_path / "capability-agent-vocabulary.db"))
    plan = pipeline._optimize_plan(
        [
            {"agent": "AnalysisAgent", "task": "totally_unknown"},
            {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
        ],
        "custom_goal",
        {"state": "recon_completed"},
    )

    assert plan == [
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]
