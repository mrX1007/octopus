"""Hermetic regression coverage for canonical report boundary failures."""

from __future__ import annotations

import copy
import math

import pytest

from core.ai import report_export, report_schema

pytestmark = pytest.mark.contract


def _observation_report(*, count: int = 1) -> dict:
    return report_schema.build_evidence_report(
        "scan-ci-report",
        "target.test",
        [
            {
                "id": index,
                "type": "port_open",
                "value": f"{442 + index}/tcp",
                "host": "target.test",
                "source": "fixture",
            }
            for index in range(1, count + 1)
        ],
    )


def _verified_report() -> dict:
    return report_schema.build_evidence_report(
        "scan-ci-verified",
        "target.test",
        [
            {
                "id": 1,
                "type": "vulnerability",
                "value": "Verified bounded fixture",
                "host": "target.test",
                "source": "fixture",
                "assessment": {
                    "assessment_id": "assessment-ci-1",
                    "status": "verified",
                    "reason": "The bounded fixture matched.",
                    "evidence_fact_ids": [1],
                    "source_execution_ids": ["execution-ci-1"],
                },
            }
        ],
    )


def _valid_legacy_adapter() -> dict[str, str]:
    return {
        "source_schema": "octopus-db-session-v1",
        "session_id": "7",
        "scan_date": "today",
        "status": "complete",
        "risk_level": "LOW",
        "analysis": "",
        "raw_output": "",
        "summary_id": "",
        "summary_session_id": "",
        "generated_at": "",
    }


def _observation_item(report: dict) -> dict:
    return report["sections"]["observations"][0]


def test_export_ingress_and_legacy_shape_rejection_edges():
    with pytest.raises(TypeError, match="mapping"):
        report_export.extract_machine_report([])
    with pytest.raises(TypeError, match="mapping"):
        report_export.legacy_session_to_machine_report([])
    with pytest.raises(report_export.MachineReportError, match="no history row"):
        report_export.legacy_session_to_machine_report({"history": None, "vulns": []})

    with pytest.raises(report_export.MachineReportError, match="both vulnerability aliases"):
        report_export.legacy_session_to_machine_report(
            {
                "history": (7, "target.test"),
                "vulns": [],
                "vulnerabilities": [],
            }
        )
    with pytest.raises(report_export.MachineReportError, match="history row exceeds"):
        report_export.legacy_session_to_machine_report(
            {"history": (7, "target.test", "today", "complete", "extra"), "vulns": []}
        )

    alias_report = report_export.legacy_session_to_machine_report(
        {
            "history": (7, "target.test"),
            "vulnerabilities": [],
            "fixes": [],
            "exploits": [],
            "summary": None,
        }
    )
    assert alias_report["legacy_adapter"]["session_id"] == "7"

    with pytest.raises(report_export.MachineReportError, match="summary row must"):
        report_export.legacy_session_to_machine_report(
            {"history": (7, "target.test"), "vulns": [], "summary": object()}
        )
    with pytest.raises(report_export.MachineReportError, match="summary row exceeds"):
        report_export.legacy_session_to_machine_report(
            {"history": (7, "target.test"), "vulns": [], "summary": tuple(range(7))}
        )

    repeated_fixes = [(index, 7, 99, "bounded remediation", "fixture") for index in range(65)]
    with pytest.raises(report_export.MachineReportError, match="per-finding remediation bound"):
        report_export.legacy_session_to_machine_report(
            {
                "history": (7, "target.test"),
                "vulns": [],
                "fixes": repeated_fixes,
                "exploits": [],
                "summary": None,
            }
        )


def test_export_post_sanitization_and_projection_fail_closed(monkeypatch):
    report = _observation_report()
    validation_results = iter([(), ("post_redaction_failure",)])
    monkeypatch.setattr(
        report_export,
        "validate_evidence_report",
        lambda _report: next(validation_results),
    )
    monkeypatch.setattr(report_export, "_sanitize_report_data", lambda value: value)

    with pytest.raises(report_export.MachineReportError, match="redacted machine_report"):
        report_export.extract_machine_report(report)

    monkeypatch.setattr(
        report_export,
        "validate_evidence_report",
        lambda _report: ("projection_failure",),
    )
    with pytest.raises(report_export.MachineReportError, match="invalid machine_report"):
        report_export.project_machine_report(report)


def test_legacy_adapter_validates_empty_built_items_and_its_output(monkeypatch):
    built = {
        "section_order": ["observations"],
        "sections": {"observations": [{"fact_ids": []}]},
    }
    monkeypatch.setattr(report_export, "build_evidence_report", lambda *_args, **_kwargs: copy.deepcopy(built))
    monkeypatch.setattr(report_export, "_sanitize_report_data", lambda value: value)
    monkeypatch.setattr(report_export, "validate_evidence_report", lambda _report: ("adapter_failure",))

    with pytest.raises(report_export.MachineReportError, match="legacy adapter produced invalid"):
        report_export.legacy_session_to_machine_report(
            {
                "history": (7, "target.test"),
                "vulns": [],
                "fixes": [],
                "exploits": [],
                "summary": None,
            }
        )


def test_legacy_row_cvss_and_secret_helpers_cover_closed_edges():
    assert report_export._legacy_rows(None, "rows", 1, 2) == []
    with pytest.raises(report_export.MachineReportError, match="must be a list"):
        report_export._legacy_rows(object(), "rows", 1, 2)
    with pytest.raises(report_export.MachineReportError, match="non-row"):
        report_export._legacy_rows([object()], "rows", 1, 2)
    with pytest.raises(report_export.MachineReportError, match="wider than supported"):
        report_export._legacy_rows([(1, 2, 3)], "rows", 1, 2)

    assert report_export._legacy_cvss(math.inf) is None
    assert report_export._legacy_cvss(11) is None
    assert report_export._legacy_cvss(object()) is None
    assert report_export._sanitize_report_value(("ordinary",), field="notes") == ("ordinary",)

    protected_password = report_export._sanitize_report_text("Abc123!", field="password")
    assert protected_password.startswith("[REDACTED secret://")
    assert report_export._looks_like_password("Abc123") is True

    protected_quoted = report_export._redacted_token("'Abc123!'", kind="fixture")
    assert protected_quoted.startswith("'[REDACTED secret://")
    assert protected_quoted.endswith("'")


def test_schema_build_routes_exact_cleanup_facts():
    report = report_schema.build_evidence_report(
        "scan-cleanup",
        "target.test",
        [
            {
                "id": 1,
                "type": "cleanup_action",
                "value": "completed",
                "host": "target.test",
                "source": "fixture",
            }
        ],
    )

    assert len(report["sections"]["cleanup_outcomes"]) == 1


def test_schema_top_level_item_and_evidence_validation_edges():
    assert report_schema.validate_evidence_report([]) == ("report_not_mapping",)

    report = _observation_report()
    report["report_id"] = "invalid"
    assert "invalid_report_id" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["section_order"] = []
    assert "section_order_mismatch" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["sections"]["extension"] = []
    assert "unexpected_section:extension" in report_schema.validate_evidence_report(report)

    report = _observation_report(count=2)
    observations = report["sections"]["observations"]
    observations[1]["item_id"] = observations[0]["item_id"]
    assert any(error.startswith("duplicate_item_id:") for error in report_schema.validate_evidence_report(report))

    report = _observation_report()
    report["evidence_index"].append(None)
    assert "invalid_evidence_record:1" in report_schema.validate_evidence_report(report)

    report = _observation_report(count=2)
    report["evidence_index"][1]["evidence_id"] = report["evidence_index"][0]["evidence_id"]
    assert any(error.startswith("duplicate_evidence_id:") for error in report_schema.validate_evidence_report(report))

    report = _verified_report()
    report["evidence_index"] = []
    assert any(
        error.startswith("verified_item_missing_evidence:") for error in report_schema.validate_evidence_report(report)
    )

    report = _verified_report()
    report["sections"]["verified_vulnerabilities"][0]["fact_ids"] = "not-a-list"
    assert any(error.startswith("not_list:") for error in report_schema.validate_evidence_report(report))

    report = _observation_report()
    item = _observation_item(report)
    item["extension"] = True
    assert any(error.startswith("unexpected_item_field:") for error in report_schema.validate_evidence_report(report))

    report = _observation_report()
    item = _observation_item(report)
    item["scope"]["extension"] = True
    assert any(
        error.startswith("item_scope_unexpected_field:") for error in report_schema.validate_evidence_report(report)
    )


def test_schema_evidence_chain_and_record_validation_edges():
    report = _observation_report()
    item = _observation_item(report)
    item["evidence_chain"] = [copy.deepcopy(item["evidence_chain"][0])] * (report_schema._MAX_CHAIN_ITEMS + 1)
    assert any(
        error.startswith("item_evidence_chain_unbounded:") for error in report_schema.validate_evidence_report(report)
    )

    report = _observation_report()
    _observation_item(report)["evidence_chain"] = [None]
    assert any(error.startswith("invalid_evidence_link:") for error in report_schema.validate_evidence_report(report))

    report = _observation_report()
    _observation_item(report)["evidence_chain"] = [{"fact_id": 1, "extension": True}]
    assert any(
        error.startswith("unexpected_evidence_link_field:") for error in report_schema.validate_evidence_report(report)
    )

    report = _observation_report()
    _observation_item(report)["evidence_chain"] = [{"fact_id": 0}]
    assert any(
        error.startswith("invalid_evidence_link_fact_id:") for error in report_schema.validate_evidence_report(report)
    )

    report = _observation_report()
    report["evidence_index"][0]["extension"] = True
    assert "unexpected_evidence_field:0:extension" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["evidence_index"][0]["fact_id"] = 0
    assert "invalid_evidence_fact_id:0" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["evidence_index"][0]["observations"] = {}
    assert "invalid_evidence_scalar:0:observations" in report_schema.validate_evidence_report(report)


def test_schema_summary_validation_edges():
    report = _observation_report()
    report["summary"]["extension"] = 0
    assert "summary_fields_mismatch" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["summary"]["section_counts"] = {}
    assert "summary_section_counts_invalid" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["summary"]["section_counts"]["observations"] = 99
    assert "summary_section_count_mismatch:observations" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["summary"]["verified_items"] = -1
    assert "summary_invalid_count:verified_items" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["sections"]["observations"] = "not-a-list"
    assert "section_not_list:observations" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["summary"]["evidence_completeness"] = None
    assert "summary_invalid_evidence_completeness" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["summary"]["evidence_completeness"] = 2.0
    assert "summary_invalid_evidence_completeness" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["summary"]["evidence_completeness"] = 0.5
    assert "summary_evidence_completeness_mismatch" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["summary"]["evidence_records"] = 0
    assert "summary_evidence_records_mismatch" in report_schema.validate_evidence_report(report)


def test_schema_truncation_and_legacy_validation_edges():
    report = _observation_report()
    report["truncation"]["section_items_omitted"] = {}
    assert "truncation_section_items_invalid" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["truncation"]["section_items_omitted"]["observations"] = -1
    assert "truncation_section_count_invalid:observations" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["truncation"]["evidence_items_omitted"] = -1
    assert "truncation_evidence_count_invalid" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["legacy_adapter"] = []
    assert "legacy_adapter_not_mapping" in report_schema.validate_evidence_report(report)

    report = _observation_report()
    report["legacy_adapter"] = _valid_legacy_adapter()
    report["legacy_adapter"]["source_schema"] = "unsupported"
    assert "legacy_adapter_source_schema_invalid" in report_schema.validate_evidence_report(report)

    def legacy_errors(value) -> tuple[str, ...]:
        legacy_report = _observation_report()
        legacy_report["legacy_adapter"] = _valid_legacy_adapter()
        _observation_item(legacy_report)["legacy_fields"] = value
        return report_schema.validate_evidence_report(legacy_report)

    assert any(error.startswith("legacy_fields_not_mapping:") for error in legacy_errors([]))
    assert any(error.startswith("legacy_fields_unexpected_field:") for error in legacy_errors({"extension": True}))
    assert any(error.startswith("legacy_fields_invalid_cvss:") for error in legacy_errors({"cvss_score": 11}))
    assert any(
        error.startswith("legacy_remediations_not_list:") for error in legacy_errors({"remediations": "invalid"})
    )
    valid_remediation = {"id": "1", "session_id": "7", "text": "fix", "source": "fixture"}
    assert any(
        error.startswith("legacy_remediations_unbounded:")
        for error in legacy_errors({"remediations": [valid_remediation] * (report_schema._MAX_REFS + 1)})
    )
    assert any(error.startswith("legacy_remediation_invalid:") for error in legacy_errors({"remediations": [{}]}))


def test_schema_list_text_scalar_and_access_helper_edges():
    report = _observation_report()
    _observation_item(report)["fact_ids"] = list(range(1, report_schema._MAX_REFS + 2))
    errors = report_schema.validate_evidence_report(report)
    assert any(error.startswith("unbounded_list:") for error in errors)

    report = _observation_report()
    _observation_item(report)["fact_ids"] = [0]
    errors = report_schema.validate_evidence_report(report)
    assert any(error.startswith("invalid_positive_int_list:") for error in errors)

    report = _observation_report()
    _observation_item(report)["sources"] = ["fixture"] * (report_schema._MAX_REFS + 1)
    errors = report_schema.validate_evidence_report(report)
    assert any(error.startswith("unbounded_list:") for error in errors)

    text_errors: list[str] = []
    report_schema._validate_text(text_errors, "required", "", 10, required=True)
    assert text_errors == ["text_empty:required"]
    assert report_schema._is_json_scalar(1.5) is True
    assert report_schema._is_json_scalar(math.inf) is False

    assert report_schema._is_access_fact(
        "application_access",
        {"value": "authenticated_access_confirmed"},
    )
    assert report_schema._is_access_fact("verified_access", {"value": "root_access_confirmed"})
    assert report_schema._is_root_access_fact({"type": "verified_access", "value": "root_access_confirmed"})
    assert report_schema._is_root_access_fact({"type": "credential", "value": "ssh_login_success:root@target.test:22"})
