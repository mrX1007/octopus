"""Focused branch coverage for deterministic reporting helpers."""

from __future__ import annotations

import json

import pytest

from core.ai import reporting

pytestmark = pytest.mark.unit


def _assessment(status="verified", **extra):
    return {
        "assessment_id": f"assessment-{status}",
        "status": status,
        "reason": f"reason-{status}",
        "source_execution_ids": ["", "exec-1"],
        **extra,
    }


def test_finding_groups_cover_all_supported_and_rejected_fact_shapes():
    module = "exploit/linux/ssh/example"
    facts = [
        {"id": 1, "type": "exploit_candidate", "value": "not a candidate"},
        {
            "id": 2,
            "type": "exploit_candidate",
            "value": f"{module} on ssh:22 [OpenSSH]",
            "assessment": _assessment(),
        },
        {"id": 3, "type": "verification_command", "value": "not msf"},
        {
            "id": 4,
            "type": "verification_command",
            "value": f"msf_check host {module}",
        },
        {"id": 5, "type": "active_command", "value": "not msf"},
        {
            "id": 6,
            "type": "active_command",
            "value": "msf_run host auxiliary/scanner/ssh/ssh_login",
        },
        {
            "id": 7,
            "type": "active_command",
            "value": f"msf_run host {module}",
        },
        {
            "id": 8,
            "type": "vulnerability",
            "value": f"msf_check_positive:{module}",
            "assessment": _assessment(),
        },
        {
            "id": 9,
            "type": "vulnerability_endpoint",
            "value": "msf_check_positive:invalid",
        },
        {
            "id": 10,
            "type": "vulnerability_endpoint",
            "value": f"msf_check_positive:{module}:22",
            "assessment": _assessment(),
        },
        {
            "id": 11,
            "type": "exploit_success",
            "value": f"msf_session_opened:{module}",
            "assessment": _assessment(),
        },
        {"type": "port_open", "value": "22/tcp (ssh)"},
    ]

    groups = reporting.build_finding_groups(facts)

    assert len(groups) == 1
    assert groups[0]["module"] == module
    assert groups[0]["ports"] == ["22"]
    assert groups[0]["severity"] == "CRITICAL"
    assert groups[0]["active_commands"] == [f"msf_run host {module}"]


def test_contradicted_candidate_is_not_a_current_finding():
    groups = reporting.build_finding_groups(
        [
            {
                "id": 1,
                "type": "exploit_candidate",
                "value": "exploit/test on service:1 [v]",
                "assessment": _assessment("contradicted"),
            }
        ]
    )

    assert groups == []


@pytest.mark.parametrize(
    "invalidity",
    [
        {"freshness_status": "stale"},
        {"coverage_status": "degraded"},
        {"trust_level": "target_controlled"},
    ],
)
def test_non_current_candidate_cannot_create_finding_or_remediation(invalidity):
    fact = {
        "id": 1,
        "type": "exploit_candidate",
        "value": "exploit/test on service:1 [v]",
        **invalidity,
    }

    groups = reporting.build_finding_groups([fact])

    assert groups == []
    assert reporting.build_remediations(groups, [fact]) == []


def test_access_findings_cover_legacy_verified_and_rejected_assessments():
    assert reporting.build_access_findings([], {}) == []
    assert (
        reporting.build_access_findings(
            [
                {
                    "type": "system_access",
                    "value": "uid=0",
                    "assessment": _assessment("contradicted"),
                }
            ],
            {"root_access_confirmed": True},
        )
        == []
    )

    supporting = [
        {"type": "credential", "value": "ssh_login_success:root"},
        {"type": "service_status", "value": "ssh_authenticated"},
        {"type": "system_access", "value": "root_access_confirmed"},
        {"type": "verified_claim", "value": "root_access_confirmed"},
        {"type": "unrelated", "value": "root_access_confirmed"},
    ]
    finding = reporting.build_access_findings(
        supporting,
        {"root_access_confirmed": True},
    )[0]
    assert finding["evidence"] == [
        "credential: ssh_login_success:root",
        "system_access: root_access_confirmed",
    ]


def test_access_finding_collects_canonical_assessment_metadata():
    finding = reporting.build_access_findings(
        [
            {
                "type": "system_access",
                "value": "uid=0",
                "assessment": _assessment(),
            }
        ],
        {"root_access_confirmed": True},
    )[0]

    assert finding["assessment_refs"] == ["assessment-verified"]
    assert finding["source_execution_ids"] == ["exec-1"]


def test_coverage_summary_deduplicates_scopes_and_checked_results():
    def check(identifier, status, tool="probe", kind="kind", scope=None):
        return {
            "id": identifier,
            "type": "check_result",
            "value": json.dumps({"status": status, "tool": tool, "kind": kind, "scope": scope or {}}),
        }

    facts = [
        {"type": "check_result", "value": "{"},
        check(1, "timeout", scope={"host": "a"}),
        check(2, "timeout", tool="other"),
        check(3, "timeout", kind="other-kind"),
        check(4, "timeout", scope={"host": "b"}),
        check(5, "timeout", scope={"host": "b"}),
        check(6, "skipped", scope={"host": "a"}),
        check(7, "skipped", scope={"host": "a"}),
        check(8, "completed_empty", scope={"host": "b"}),
        check(9, "succeeded"),
        {"id": 10, "type": "service_status", "value": "tool_timeout:legacy"},
        {"id": 11, "type": "service_status", "value": "probe_failed"},
        {"id": 12, "type": "other", "value": "ignored"},
    ]

    summary = reporting.build_coverage_summary(facts)

    assert summary["confidence"] == "partial"
    assert len(summary["degraded"]) == 4
    assert len(summary["checked_but_not_confirmed"]) == 3
    probe = next(item for item in summary["degraded"] if item["tool"] == "probe" and item.get("kind") == "kind")
    assert probe["scopes"] == [{"host": "a"}, {"host": "b"}]


def test_attack_path_covers_every_stage_and_unconfirmed_variants():
    facts = [
        {"type": "credential", "value": "ssh_login_success:user@host"},
        {
            "type": "post_exploit_stage",
            "value": "post_access_inventory_completed",
        },
        {"type": "privesc_vector", "value": "sudo_rights_present"},
        {"type": "internal_host", "value": "10.0.0.8"},
    ]
    path = reporting.build_attack_path(facts, {"persistence_established": True})
    assert [step["stage"] for step in path] == [
        "Initial access",
        "Host inventory",
        "Privilege escalation",
        "Persistence",
        "Internal recon",
        "Cleanup",
    ]
    assert path[2]["status"] == "tested"
    assert path[3]["status"] == "completed"
    mention_only = reporting.build_attack_path(
        [{"type": "note", "value": "persistence candidate"}],
        {},
    )
    assert not any(step["stage"] == "Persistence" for step in mention_only)

    confirmed = reporting.build_attack_path(
        [{"type": "exploit_attempted"}],
        {
            "root_access_confirmed": True,
            "persistence_established": True,
            "internal_recon_completed": True,
            "cleanup_completed": True,
        },
    )
    assert any(step["stage"] == "Root access" for step in confirmed)
    assert any(step["stage"] == "Persistence" and step["status"] == "completed" for step in confirmed)


def test_risk_explanation_covers_noncritical_access_and_empty_case():
    assert "verified access" in reporting.build_risk_explanation(
        {"risk_level": "high"},
        [{}],
    )
    assert reporting.build_risk_explanation({"risk_level": "low"}, []) == ""


def test_remediations_cover_all_service_specific_and_fallback_paths():
    groups = [
        {"module": "redis_issue", "service": "other"},
        {"module": "finding", "service": "ssh"},
        {"module": "finding", "service": "cpanel"},
        {"module": "finding", "service": "web", "impact_confirmed": True},
        {"class": "generic", "service": ""},
    ]
    remediations = reporting.build_remediations(
        groups,
        [{"type": "service_status", "value": "tool_timeout:probe"}],
        access_findings=[{}],
    )

    assert len(remediations) == 7
    assert remediations[-1]["finding"] == "coverage_degraded"
    assert any(item["service"] == "unknown" for item in remediations)


def test_private_parsers_group_updates_and_service_fallbacks():
    assert reporting._parser_name_for_fact({"source": "replay:tool"}) == "replay_output_parser"
    assert reporting._parse_exploit_candidate(' {"module": "x"}') == {}
    assert reporting._parse_exploit_candidate("invalid") == {}
    assert reporting._parse_exploit_candidate("m on svc:1 [v]")["port"] == "1"
    assert reporting._parse_msf_endpoint("bad") == {}
    assert reporting._module_from_msf_command("") == ""
    assert reporting._active_module_allows_run("auxiliary/test") is False
    assert reporting._active_module_allows_run("exploit/test_login") is False
    assert reporting._active_module_allows_run("exploit/test") is True
    assert reporting._module_from_success("msf_session_opened:module") == "module"
    assert reporting._module_from_success("found cve-2026-1234") == "CVE-2026-1234"
    assert reporting._module_from_success("") == "exploit_success"

    groups = {}
    first = reporting._group_for_module(groups, "module", "unknown", [])
    assert reporting._group_for_module(groups, "module", "unknown", []) is first

    facts = [
        {"type": "other", "value": "ignored"},
        {"type": "port_open", "value": "malformed"},
        {"type": "port_open", "value": "80/tcp (http)"},
    ]
    assert reporting._service_for_module("custom", facts) == "http"
    assert reporting._service_for_module("custom", facts[:2]) == "unknown"
    assert reporting._service_for_module("redis/module", []) == "redis"
    assert reporting._service_for_port(facts, "80") == "http"
    assert reporting._service_for_port(facts, "443") == ""
