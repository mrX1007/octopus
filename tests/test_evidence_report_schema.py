"""Contract tests for the canonical evidence-backed report."""

from __future__ import annotations

import pytest

from core.ai.fact_store import FactStore
from core.ai.report_schema import (
    EVIDENCE_REPORT_SECTION_ORDER,
    build_evidence_report,
    validate_evidence_report,
)
from core.ai.reporting import build_coverage_summary, build_evidence_index
from core.ai.trace_report import TraceReporter

pytestmark = pytest.mark.contract


def _verified_fact(
    store: FactStore,
    fact_id: int,
    *,
    evidence_fact_ids: tuple[int, ...],
    execution_id: str,
    reason: str,
) -> None:
    store.assessments.assess_fact(
        fact_id,
        "verified",
        confidence=96,
        reason=reason,
        assessor="test.report_verifier",
        evidence_fact_ids=evidence_fact_ids,
        source_execution_ids=(execution_id,),
    )


def test_machine_report_separates_verified_vulnerability_candidate_and_access(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    scan_id = "scan-report"
    host = "10.0.0.5"
    check_id = store.add_fact(
        scan_id,
        host,
        "check_result",
        "positive control matched",
        "safe_verifier",
        source_execution_ids=("exec-check",),
    )
    vulnerability_id = store.add_fact(
        scan_id,
        host,
        "vulnerability",
        "CVE-2026-4242 verified by safe check",
        "safe_verifier",
        source_execution_ids=("exec-check",),
    )
    _verified_fact(
        store,
        vulnerability_id,
        evidence_fact_ids=(check_id,),
        execution_id="exec-check",
        reason="The positive control matched the exact endpoint.",
    )
    store.add_fact(
        scan_id,
        host,
        "potential_vulnerability",
        "CVE-2026-9999 version match only",
        "version_matcher",
        source_execution_ids=("exec-version",),
    )
    access_id = store.add_fact(
        scan_id,
        host,
        "system_access",
        "uid=0",
        "safe_access_check",
        source_execution_ids=("exec-access",),
    )
    _verified_fact(
        store,
        access_id,
        evidence_fact_ids=(access_id,),
        execution_id="exec-access",
        reason="The bounded identity check returned uid=0.",
    )

    report = TraceReporter(store).build(
        scan_id,
        host,
        context={"stage_gates": {"root": True}},
    )["machine_report"]
    sections = report["sections"]

    assert report["schema_version"] == "1.0"
    assert tuple(report["section_order"]) == EVIDENCE_REPORT_SECTION_ORDER
    assert len(sections["verified_vulnerabilities"]) == 1
    verified = sections["verified_vulnerabilities"][0]
    assert verified["status"] == "verified"
    assert verified["source_execution_ids"] == ["exec-check"]
    assert verified["assessment_reasons"] == [
        "The positive control matched the exact endpoint."
    ]
    assert {item["fact_id"] for item in verified["evidence_chain"]} == {
        check_id,
        vulnerability_id,
    }
    assert len(sections["access_findings"]) == 1
    assert sections["access_findings"][0]["kind"] == "root_access"
    assert all(
        item["kind"] != "system_access"
        for item in sections["verified_vulnerabilities"]
    )
    candidates = sections["hypotheses_candidates"]
    assert any("CVE-2026-9999" in item["detail"] for item in candidates)
    assert all(item["status"] != "verified" for item in candidates)
    assert validate_evidence_report(report) == ()


def test_machine_report_keeps_every_operational_section_distinct(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    scan_id = "scan-sections"
    host = "example.test"
    store.add_fact(scan_id, host, "web_security_note", "missing_hsts", "headers")
    store.add_fact(scan_id, host, "port_open", "443/tcp (https)", "discovery")
    store.add_fact(
        scan_id,
        host,
        "exploit_attempted",
        "safe verification attempt had no conclusive result",
        "verifier",
    )
    store.add_fact(
        scan_id,
        host,
        "service_status",
        "tool_timeout:nuclei_safe",
        "nuclei_safe",
    )
    store.add_fact(
        scan_id,
        host,
        "cleanup_outcome",
        "cleanup_succeeded",
        "action_adapter",
    )
    store.add_hypothesis(
        scan_id,
        host,
        "The API may accept anonymous access.",
        ["authenticated and anonymous comparison"],
        "analysis",
    )
    store.add_command_result(
        scan_id,
        host,
        "policy-blocked-check",
        "safe_check example.test",
        "a" * 64,
        status="blocked",
        policy_decision_ref="policy://sha256/example",
        execution_id="exec-blocked",
    )
    facts = store.get_facts(scan_id, host)
    coverage = build_coverage_summary(facts)

    report = build_evidence_report(
        scan_id,
        host,
        facts,
        evidence_index=build_evidence_index(facts),
        hypotheses=store.get_hypotheses(scan_id, host),
        command_results=store.get_command_results(scan_id, host),
        coverage=coverage,
        context={"coverage_gaps": ["authenticated_api_coverage_pending"]},
        state={"cleanup_completed": True},
        redact=store.redactor.redact_data,
    )
    sections = report["sections"]

    assert any(item["kind"] == "web_security_note" for item in sections["misconfigurations"])
    assert any(item["kind"] == "port_open" for item in sections["observations"])
    assert any(item["kind"] == "hypothesis" for item in sections["hypotheses_candidates"])
    assert any(item["kind"] == "exploit_attempted" for item in sections["attempted_unverified"])
    assert any(
        "authenticated_api_coverage_pending" in item["detail"]
        for item in sections["coverage_gaps"]
    )
    degraded = sections["policy_blocked_degraded_checks"]
    assert any(item["status"] == "timeout" for item in degraded)
    assert any(item["status"] == "blocked" for item in degraded)
    assert any(item["source_execution_ids"] == ["exec-blocked"] for item in degraded)
    assert {item["status"] for item in sections["cleanup_outcomes"]} >= {
        "succeeded"
    }


def test_contradiction_removes_previous_verified_classification(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    fact_id = store.add_fact(
        "scan",
        "host",
        "vulnerability",
        "CVE-2026-1111",
        "verifier",
        source_execution_ids=("exec-positive",),
    )
    _verified_fact(
        store,
        fact_id,
        evidence_fact_ids=(fact_id,),
        execution_id="exec-positive",
        reason="Initial positive result.",
    )
    store.assessments.assess_fact(
        fact_id,
        "contradicted",
        confidence=99,
        reason="A repeat check produced a reliable negative result.",
        assessor="test.report_verifier",
        evidence_fact_ids=(fact_id,),
        source_execution_ids=("exec-negative",),
    )
    facts = store.get_facts("scan", "host")

    report = build_evidence_report(
        "scan",
        "host",
        facts,
        evidence_index=build_evidence_index(facts),
        redact=store.redactor.redact_data,
    )

    assert report["sections"]["verified_vulnerabilities"] == []
    candidate = report["sections"]["hypotheses_candidates"][0]
    assert candidate["status"] == "contradicted"
    assert candidate["verification_gap"] == "current_assessment_contradicted"


def test_report_snapshot_is_deterministic_and_incomplete_verification_is_not_promoted():
    facts = [
        {
            "id": 7,
            "scan_id": "scan",
            "host": "host",
            "type": "vulnerability",
            "value": "CVE-2026-7000",
            "source": "parser",
            "timestamp": 10.0,
            "assessment_status": "verified",
            "assessment": {
                "assessment_id": "assessment-7",
                "status": "verified",
                "reason": "A check was positive, but execution provenance was lost.",
                "evidence_fact_ids": [7],
                "source_execution_ids": [],
            },
        }
    ]

    first = build_evidence_report("scan", "host", facts)
    second = build_evidence_report("scan", "host", facts)

    assert first == second
    assert first["sections"]["verified_vulnerabilities"] == []
    candidate = first["sections"]["hypotheses_candidates"][0]
    assert candidate["verification_gap"] == "missing_source_execution_ids"
    assert candidate["status"] == "candidate"


@pytest.mark.parametrize(
    ("freshness_status", "coverage_status", "expected_status"),
    [
        ("stale", "complete", "stale"),
        ("current", "degraded", "degraded"),
    ],
)
def test_historical_misconfiguration_is_not_reported_as_current_verified_state(
    freshness_status,
    coverage_status,
    expected_status,
):
    fact = {
        "id": 11,
        "scan_id": "scan",
        "host": "host",
        "type": "misconfiguration",
        "value": "anonymous_admin_enabled",
        "timestamp": 1.0,
        "freshness_status": freshness_status,
        "coverage_status": coverage_status,
        "assessment_status": "verified",
        "assessment": {
            "assessment_id": "assessment-11",
            "status": "verified",
            "reason": "The setting was directly observed.",
            "evidence_fact_ids": [11],
            "source_execution_ids": ["exec-11"],
        },
    }

    report = build_evidence_report("scan", "host", [fact])
    item = report["sections"]["misconfigurations"][0]

    assert item["assessment_status"] == "verified"
    assert item["status"] == expected_status
    assert report["summary"]["verified_items"] == 0
