"""Branch-complete hermetic tests for the canonical evidence report schema."""

from __future__ import annotations

import pytest

from core.ai import report_schema as schema

pytestmark = pytest.mark.contract


def _sections():
    return {name: [] for name in schema.EVIDENCE_REPORT_SECTION_ORDER}


def _seen():
    return {name: set() for name in schema.EVIDENCE_REPORT_SECTION_ORDER}


def test_build_skips_invalid_inputs_and_fails_closed_after_redaction():
    with pytest.raises(ValueError, match="Invalid evidence report"):
        schema.build_evidence_report(
            "scan",
            "target",
            [{"type": ""}],
            hypotheses=["not-a-mapping"],
            redact=lambda _report: {},
        )


def test_report_validator_all_structural_failures():
    assert schema.validate_evidence_report({"schema_version": "bad", "sections": []}) == (
        "unsupported_schema_version",
        "sections_not_mapping",
    )

    sections = _sections()
    sections["verified_vulnerabilities"] = [{"item_id": "v", "status": "candidate"}]
    sections["access_findings"] = "not-a-list"
    sections["misconfigurations"] = [{"item_id": f"item-{index}"} for index in range(schema._MAX_SECTION_ITEMS + 1)]
    sections["observations"] = [None, {}, {"item_id": "incomplete", "status": "verified"}]
    report = {
        "schema_version": "bad",
        "sections": sections,
        "evidence_index": {},
    }
    errors = schema.validate_evidence_report(report)
    assert "unsupported_schema_version" in errors
    assert "section_not_list:access_findings" in errors
    assert "section_unbounded:misconfigurations" in errors
    assert "invalid_item:observations" in errors
    assert "verified_item_incomplete:incomplete" in errors
    assert "unverified_vulnerability:v" in errors
    assert "evidence_index_not_list" in errors

    report["schema_version"] = schema.EVIDENCE_REPORT_SCHEMA_VERSION
    report["evidence_index"] = [{}] * (schema._MAX_EVIDENCE_ITEMS + 1)
    assert "evidence_index_unbounded" in schema.validate_evidence_report(report)


class DictReport:
    def to_dict(self):
        return {
            "descriptor": {"action_id": "action-1"},
            "lifecycle": {
                "attempt": "attempted",
                "verification": "failed",
                "cleanup": "succeeded",
            },
            "execution_result": {"execution_id": "exec-1"},
            "verification_result": {
                "reason": "not confirmed",
                "assessment_refs": ["assessment-1"],
                "evidence_fact_ids": [1, "2", "bad"],
            },
            "cleanup_result": {"reason": "removed"},
        }


def test_operational_collectors_cover_skip_and_emit_paths():
    sections = _sections()
    seen = _seen()
    schema._add_degraded_check_items(
        sections,
        seen,
        {"degraded": ["offline", {"status": "partial", "impact": "reduced"}]},
        [
            "not-a-mapping",
            {"status": "succeeded"},
            {
                "id": 1,
                "status": "timeout",
                "command": "bounded check",
                "execution_id": "exec-timeout",
                "policy_decision_ref": "policy-1",
                "timestamp": 4,
            },
        ],
        ["not-a-mapping", {"action": "run"}, {"action": "skip", "reason": "policy"}],
    )
    schema._add_action_report_items(
        sections,
        seen,
        [
            DictReport(),
            "not-a-report",
            {"descriptor": {}, "lifecycle": {}},
        ],
    )
    schema._add_state_cleanup_item(sections, seen, {})
    schema._add_state_cleanup_item(sections, seen, {"cleanup_completed": False})

    degraded = sections["policy_blocked_degraded_checks"]
    assert {item["status"] for item in degraded} >= {"offline", "partial", "timeout", "blocked"}
    attempted = sections["attempted_unverified"][0]
    assert attempted["source_execution_ids"] == ["exec-1"]
    assert [link["fact_id"] for link in attempted["evidence_chain"]] == [1, 2]
    assert {item["status"] for item in sections["cleanup_outcomes"]} == {
        "succeeded",
        "not_completed",
    }


@pytest.mark.parametrize(
    ("fact", "expected"),
    [
        ({"assessment_status": "contradicted"}, "current_assessment_contradicted"),
        ({"coverage_status": "degraded"}, "degraded_evidence_coverage"),
        ({"freshness_status": "stale"}, "stale_evidence"),
        ({"assessment_status": "inferred"}, "current_assessment_inferred"),
        ({"assessment_status": "verified"}, "missing_evidence_chain"),
        (
            {"id": 1, "assessment_status": "verified", "assessment": {}},
            "missing_assessment_reason",
        ),
        (
            {
                "id": 1,
                "assessment_status": "verified",
                "assessment": {"reason": "confirmed"},
            },
            "missing_source_execution_ids",
        ),
        (
            {
                "id": 1,
                "assessment_status": "verified",
                "assessment": {"reason": "confirmed", "source_execution_ids": ["exec"]},
            },
            "none",
        ),
    ],
)
def test_verification_gap_matrix(fact, expected):
    evidence = {1: {"evidence_id": "E-1", "evidence_ref": "evidence://fact/1"}}
    assert schema._verification_gap(fact, evidence) == expected


def test_access_root_cleanup_candidate_and_evidence_helpers():
    assert schema._is_access_fact("exploit_success", {}) is False
    assert schema._is_access_fact("credential", {"value": "ssh_login_success:user@host"}) is True
    assert schema._is_access_fact("credential", {"value": "found username"}) is False
    assert schema._is_access_fact("service_status", {"value": "ssh_authenticated"}) is True
    assert schema._is_access_fact("service_status", {"value": "authenticated_access:yes"}) is False
    assert schema._is_access_fact("verified_claim", {"value": "root_access_confirmed"}) is False
    assert schema._is_access_fact("verified_claim", {"value": "other"}) is False
    assert schema._is_access_fact("other", {}) is False
    assert schema._is_root_access_fact({"type": "system_access", "value": "uid=0"}) is True
    assert schema._is_root_access_fact({"type": "system_access", "value": "uid=0(root)"}) is False
    assert schema._is_root_access_fact({"value": "user"}) is False
    assert schema._is_cleanup_fact("observation", {"value": "cleanup"}) is False
    assert (
        schema._is_cleanup_fact(
            "cleanup_status",
            {"type": "cleanup_status", "value": "success"},
        )
        is True
    )
    assert schema._looks_like_cve_candidate("observation", {"value": "CVE-1"}) is False
    assert schema._looks_like_cve_candidate("finding", {"value": "CVE-2026-1"}) is True
    assert schema._looks_like_cve_candidate("finding", {"value": "version only"}) is False
    assert schema._evidence_ref({"type": "observation", "value": "x"}).startswith("evidence://sha256/")


def test_deduplication_reference_and_scalar_helpers():
    sections = _sections()
    seen = _seen()
    schema._append(sections, seen, "observations", {})
    item = {"item_id": "same"}
    schema._append(sections, seen, "observations", item)
    schema._append(sections, seen, "observations", item)
    assert sections["observations"] == [item]

    assert schema._dedupe_dicts(["bad", {"a": 1}, {"a": 1}, {"a": 2}]) == [
        {"a": 1},
        {"a": 2},
    ]
    assert schema._refs(None) == []
    assert schema._refs("one") == ["one"]
    assert schema._refs(["same", "same", "other"]) == ["same", "other"]
    assert len(schema._refs(range(schema._MAX_REFS + 10))) == schema._MAX_REFS
    assert schema._positive_ints(None) == []
    assert schema._positive_ints("2") == [2]
    assert schema._positive_ints([1, "1", "bad", -1]) == [1]
    assert schema._positive_int(object()) is None
    assert schema._number(object()) == 0.0
    assert schema._number(-4) == 0.0
    assert schema._text("é" * 20, 5).encode("utf-8") <= ("é" * 20).encode("utf-8")
    assert len(schema._text("x" * 20, 5).encode()) <= 5
