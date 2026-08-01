"""Branch-complete, read-only tests for capability assessment helpers."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from core.ai.capability_assessment import (
    CapabilityResolver,
    ProviderAssessment,
)
from core.execution import ExecutionContext

pytestmark = pytest.mark.contract


class RegistryDouble:
    def __init__(self, *, statuses=None, profiles=None, aliases=None):
        self.statuses = statuses or {}
        self.profiles = profiles or {}
        self.aliases = aliases or {}

    def canonical_task(self, task):
        return self.aliases.get(task, task)

    def task_profile(self, task):
        return self.profiles.get(task, {})

    def get_provider_statuses_for_task(self, task):
        return list(self.statuses.get(task, ()))


@dataclass
class Decision:
    allowed: bool
    reason: str


class PolicyDouble:
    def __init__(self, decisions=()):
        self.decisions = list(decisions)
        self.commands = []

    def authorize_command(self, command, context):
        self.commands.append((command, context))
        return self.decisions.pop(0) if self.decisions else Decision(False, "")


def _resolver(*, registry=None, policy=None):
    return CapabilityResolver(registry or RegistryDouble(), policy or PolicyDouble())


def _context():
    return ExecutionContext.automatic(("example.test",), actor="coverage", origin="tests")


@pytest.mark.parametrize(
    ("requirement", "context", "expected"),
    [
        ("stage:recon", {"stage_gates": {"recon": True}}, True),
        ("stage:recon", {}, False),
        ("policy:auto_cleanup", {"automation_policy": {"auto_cleanup": True}}, True),
        ("policy:auto_cleanup", {}, False),
        ("killchain:cleanup", {}, True),
        ("killchain:cleanup", {"killchain_policy": {"automated_stages": {"cleanup": False}}}, False),
        ("killchain:cleanup", {"killchain_policy": {"automated_stages": {"cleanup": True}}}, True),
        ("killchain:cleanup", {"killchain_policy": {"automated_stages": {}}}, True),
        ("services", {"services": ["smtp"]}, True),
        ("services", {}, False),
        ("web", {"services": ["http"]}, True),
        ("web", {"target_model": {"endpoints": [{"scheme": "http"}]}}, True),
        ("web", {"surface_states": {"web": "confirmed_present"}}, True),
        ("web", {}, False),
        ("tls", {"services": ["https"]}, True),
        ("tls", {"target_model": {"endpoints": ["bad", {"scheme": "https"}]}}, True),
        ("tls", {"target_model": {"endpoints": [{"scheme": "http"}]}}, False),
        ("tls", {}, False),
        ("domain", {"host": "example.test"}, True),
        ("domain", {"host": "10.0.0.1"}, False),
        ("ad_surface", {"services": ["ldap"]}, True),
        ("ad_surface", {"services": ["http"]}, False),
        ("smb", {"services": ["smb"]}, True),
        ("smb", {}, False),
        ("ssh", {"services": ["ssh"]}, True),
        ("ssh", {}, False),
        ("access", {"state": "root_access_confirmed"}, True),
        ("access", {"target_model": {"access": {"ssh_authenticated": True}}}, True),
        ("access", {"target_model": {"access": {"root_confirmed": True}}}, True),
        ("access", {}, False),
        ("internal_hosts", {"network_graph": {"nodes": ["n"]}}, True),
        ("internal_hosts", {"target_model": {"internal_graph": {"nodes": ["n"]}}}, True),
        ("internal_hosts", {}, False),
        ("internal_services", {"target_model": {"internal_services": ["ssh"]}}, True),
        ("internal_services", {}, False),
        ("unknown", {}, False),
    ],
)
def test_requirement_met_all_kinds(requirement, context, expected):
    assert _resolver().requirement_met(requirement, context) is expected


def test_missing_requirements_handles_empty_and_mixed_inputs():
    resolver = _resolver()
    assert resolver.missing_requirements(None, {}) == []
    assert resolver.missing_requirements(["services", "ssh", "unknown"], {"services": ["ssh"]}) == ["unknown"]


def test_capability_normalization_task_expansion_and_requirement_deduplication():
    registry = RegistryDouble(
        aliases={"friendly_task": "real_task"},
        profiles={"real_task": {"preconditions": ["services", "services", "web"]}},
    )
    resolver = _resolver(registry=registry)

    assert resolver._canonical_capability(" Friendly-Task ") == "real_task"
    assert resolver._canonical_capability(" CLEANUP ") == "cleanup"
    assert resolver._tasks_for_capability("") == ()
    assert resolver._tasks_for_capability("friendly_task") == ("real_task",)
    assert resolver._requirements_for("real_task", ("real_task",)) == (
        "services",
        "web",
    )


def test_provider_grouping_merges_availability_and_unique_templates():
    registry = RegistryDouble(
        statuses={
            "task": [
                {"provider": "p", "available": False, "command_template": ""},
                {"provider": "p", "available": True, "command_template": "probe {target}"},
                {"provider": "p", "available": False, "command_template": "probe {target}"},
            ]
        }
    )
    policy = PolicyDouble([Decision(True, "allowed")])
    providers = _resolver(registry=registry, policy=policy)._resolve_providers(
        "task", ("task",), "example.test", _context(), "DiscoveryAgent"
    )

    assert providers == (ProviderAssessment("task", "p", "available", "allowed", "allowed"),)
    assert len(policy.commands) == 1


def test_authorize_templates_covers_unformattable_empty_allowed_and_denied_paths():
    resolver = _resolver(policy=PolicyDouble())
    context = _context()
    assert resolver._authorize_templates(["{missing}", "{"], "host", context) == (
        "unknown",
        "provider_command_not_assessable",
    )

    policy = PolicyDouble([Decision(False, "one"), Decision(True, "two")])
    resolver = _resolver(policy=policy)
    assert resolver._authorize_templates(["first {target}", "second {target}"], "host", context) == (
        "allowed",
        "two",
    )

    policy = PolicyDouble([Decision(False, "same"), Decision(False, "same")])
    resolver = _resolver(policy=policy)
    assert resolver._authorize_templates(["a {target}", "b {target}"], "host", context) == (
        "denied",
        "same",
    )

    resolver = _resolver(policy=PolicyDouble([Decision(False, "")]))
    assert resolver._authorize_templates(["a {target}"], "host", context) == (
        "denied",
        "execution_policy_denied",
    )


def test_provider_and_authorization_aggregate_fallbacks():
    not_applicable = ProviderAssessment("t", "p", "not_applicable")
    denied = ProviderAssessment("t", "p", "available", "denied", "no")
    unknown = ProviderAssessment("t", "q", "available", "unknown", "why")

    assert CapabilityResolver._provider_availability("task", (not_applicable,), "") == "not_applicable"
    assert CapabilityResolver._aggregate_authorization((denied, unknown), "available") == (
        "unknown",
        "execution_context_not_supplied",
    )
    assert CapabilityResolver._blocking_reasons("available", "allowed", "ok", ("x", "x")) == ("requirement:missing:x",)


def test_requested_and_supporting_fact_selection_paths():
    resolver = _resolver(registry=RegistryDouble(aliases={"alias": "real"}))
    assert resolver._is_requested("real", {"next_required_capability": "alias"}) is True
    assert resolver._is_requested("credential_harvesting", {"next_required_capability": "test_credentials"}) is False
    assert resolver._is_requested("test_credentials", {"next_required_capability": "credential_harvesting"}) is True
    assert resolver._supporting_facts([], ("services",), ("services",)) == []
    facts = [
        {"type": "port_open", "value": "80/tcp http"},
        {"type": "note", "value": "unrelated"},
    ]
    assert resolver._supporting_facts(facts, ("services",), ()) == [facts[0]]


@pytest.mark.parametrize(
    ("requirement", "fact", "expected"),
    [
        ("policy:auto", {}, False),
        ("stage:recon", {"type": "port_open"}, False),
        ("stage:recon", {"type": "port_open", "value": "80/tcp (http)"}, True),
        ("stage:recon", {"type": "web_title"}, True),
        ("stage:recon", {"type": "note"}, False),
        ("stage:credentials", {"type": "credential"}, False),
        ("stage:credentials", {"type": "credential", "value": "ssh_login_success:user@host"}, True),
        ("stage:credentials", {"value": "login_success"}, False),
        ("stage:credentials", {}, False),
        ("stage:root", {"value": "uid=0"}, False),
        ("stage:root", {"type": "system_access", "value": "uid=0"}, True),
        ("stage:root", {"value": "root_access_confirmed"}, False),
        ("stage:root", {"type": "credential", "value": "ssh_login_success:root@host"}, True),
        ("stage:root", {"type": "exploit_success", "value": "pwnkit root shell"}, False),
        ("stage:root", {"type": "exploit_success", "value": "wordpress root shell"}, False),
        ("stage:root", {"type": "note", "value": "nothing"}, False),
        (
            "stage:post_access_inventory",
            {"type": "post_exploit_stage", "value": "post_access_inventory_completed"},
            True,
        ),
        ("stage:post_access_inventory", {"type": "post_exploit_stage", "value": "other"}, False),
        ("stage:post_access_inventory", {"type": "note", "value": "post_access_inventory_completed"}, False),
        ("stage:persistence", {"type": "persistence_status"}, False),
        ("stage:persistence", {"type": "persistence", "value": "mechanism_planted"}, True),
        ("stage:persistence", {"value": "mechanism_planted"}, False),
        ("stage:persistence", {}, False),
        ("stage:internal_recon", {"type": "internal_network"}, True),
        ("stage:internal_recon", {"value": "internal_network_recon_completed"}, False),
        ("stage:internal_recon", {"type": "service_status", "value": "network_recon_completed"}, True),
        ("stage:internal_recon", {"type": "service_status", "value": "other"}, False),
        ("stage:internal_recon", {}, False),
        ("stage:exfiltration", {"type": "data_exfiltration", "value": "completed"}, True),
        ("stage:exfiltration", {"type": "post_exploit_stage", "value": "data_exfiltration_completed"}, True),
        ("stage:exfiltration", {"type": "post_exploit_stage", "value": "other"}, False),
        ("stage:exfiltration", {"type": "note", "value": "data_exfiltration_completed"}, False),
        ("stage:cleanup", {"type": "cleanup_status", "value": "success"}, True),
        ("stage:cleanup", {"type": "cleanup_status", "value": "failed"}, False),
        ("stage:cleanup", {"type": "note", "value": "success"}, False),
        ("stage:unknown", {}, False),
        ("services", {"type": "port_open", "value": "80/tcp (http)"}, True),
        ("services", {"type": "web_link"}, True),
        ("services", {}, False),
        ("web", {"type": "web_title"}, True),
        ("web", {"type": "port_open", "value": "8080/tcp (tomcat)"}, True),
        ("web", {"type": "port_open", "value": "smtp"}, False),
        ("web", {"type": "note", "value": "http"}, False),
        ("tls", {"type": "web_endpoint", "value": "https://host"}, True),
        ("tls", {"type": "web_endpoint", "value": "http://host"}, False),
        ("tls", {"type": "port_open", "value": "443/tcp (ssl/http)"}, True),
        ("tls", {"type": "port_open", "value": "25/tcp (smtp)"}, False),
        ("tls", {"type": "note", "value": "https"}, False),
        ("domain", {"type": "domain"}, True),
        ("domain", {"type": "subdomain"}, True),
        ("domain", {"type": "dns_record"}, True),
        ("domain", {"type": "note"}, False),
        ("ad_surface", {"type": "port_open", "value": "445/tcp (microsoft-ds)"}, True),
        ("ad_surface", {"type": "port_open", "value": "80/tcp (http)"}, False),
        ("ad_surface", {"type": "note", "value": "smb"}, False),
        ("smb", {"type": "port_open", "value": "445/tcp (smb)"}, True),
        ("ssh", {"type": "port_open", "value": "22/tcp (ssh)"}, True),
        ("smb", {"type": "note", "value": "smb"}, False),
        ("ssh", {"type": "port_open", "value": "25/tcp (smtp)"}, False),
        ("access", {"type": "application_access"}, False),
        ("access", {"type": "application_access", "value": "session_confirmed"}, True),
        ("access", {"value": "login_success"}, False),
        ("access", {"type": "service_status", "value": "ssh_authenticated"}, True),
        ("access", {"value": "ssh_authenticated"}, False),
        ("access", {"type": "system_access", "value": "uid=0"}, True),
        ("access", {"value": "uid=0"}, False),
        ("access", {}, False),
        ("internal_hosts", {"type": "internal_host"}, True),
        ("internal_hosts", {"type": "internal_subnet"}, True),
        ("internal_hosts", {"type": "network_node"}, True),
        ("internal_hosts", {}, False),
        ("internal_services", {"type": "internal_service"}, True),
        (
            "internal_services",
            {"type": "service_status", "value": "internal_service_probe_completed:host"},
            True,
        ),
        ("internal_services", {"value": "internal_service_probe_completed:host"}, False),
        ("internal_services", {}, False),
        ("unknown", {}, False),
    ],
)
def test_fact_support_matrix(requirement, fact, expected):
    assert _resolver()._fact_supports_requirement(fact, requirement) is expected


def test_system_access_marker_and_fact_id_boundaries():
    resolver = _resolver()
    assert resolver._is_system_access_exploit_value("ordinary application issue") is False
    assert resolver._is_system_access_exploit_value("dirty pipe") is True
    assert resolver._supporting_fact_ids(
        [
            {},
            {"id": None},
            {"id": "bad"},
            {"id": []},
            {"id": -1},
            {"id": 0},
            {"id": "2"},
            {"id": 2},
        ]
    ) == (2,)


def test_freshness_confidence_handles_bad_samples_and_all_state_outcomes():
    resolver = _resolver()
    degraded = resolver._freshness_confidence(
        [
            {
                "freshness_status": "fresh",
                "coverage_status": "complete",
                "execution_status": "timeout",
                "observations": [
                    "ignored",
                    {"timestamp": "bad", "confidence": "bad"},
                    {"timestamp": [], "confidence": []},
                    {"timestamp": -1, "confidence": float("nan")},
                    {"timestamp": float("inf"), "confidence": 0.25},
                    {"timestamp": 5, "confidence": 0.75},
                ],
            }
        ]
    )
    assert degraded.freshness == "degraded"
    assert degraded.oldest_observed_at == 5
    assert degraded.confidence_average == 0.5

    stale = resolver._freshness_confidence([{"freshness_status": "stale", "timestamp": None, "confidence": None}])
    assert stale.freshness == "stale"
    assert stale.confidence_average is None
    assert (
        resolver._freshness_confidence([{"freshness_status": "fresh", "timestamp": 1, "confidence": 1}]).freshness
        == "fresh"
    )
    assert resolver._freshness_confidence([{"freshness_status": "unexpected"}]).freshness == "unknown"
    assert resolver._freshness_confidence([]).freshness == "not_assessed"


def test_evidence_state_covers_confirmed_absence_and_other_outcomes():
    resolver = _resolver()
    assert (
        resolver._evidence_state(
            {"target_model": {"surface_states": {"web": "confirmed_absent"}}},
            ("web",),
            ("web",),
            [],
        )
        == "confirmed_absent"
    )
    assert resolver._evidence_state({"surface_states": {"web": "unknown"}}, ("web",), ("web",), []) == "unknown"
    assert resolver._evidence_state({}, ("web",), (), [{"id": 1}]) == "confirmed_present"
    assert resolver._evidence_state({}, (), (), []) == "unknown"
