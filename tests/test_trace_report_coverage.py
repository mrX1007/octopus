"""Focused branch coverage for trace report validation and text rendering."""

from __future__ import annotations

import pytest

from core.ai.evaluated_facts import EvaluatedFactSnapshot
from core.ai.fact_store import FactStore
from core.ai.trace_report import TraceReporter

pytestmark = pytest.mark.contract


def test_snapshot_validation_rejects_another_scan_and_target(tmp_path):
    reporter = TraceReporter(FactStore(str(tmp_path / "facts.db")))

    with pytest.raises(ValueError, match="different scan"):
        reporter._validate_evaluated_fact_snapshot(
            EvaluatedFactSnapshot.build("other-scan", "host", []),
            "scan",
            "host",
        )

    with pytest.raises(ValueError, match="does not cover"):
        reporter._validate_evaluated_fact_snapshot(
            EvaluatedFactSnapshot.build("scan", "other-host", []),
            "scan",
            "host",
        )


def test_text_report_renders_coverage_and_empty_human_sections(tmp_path):
    reporter = TraceReporter(FactStore(str(tmp_path / "facts.db")))

    text = reporter.to_text(
        {
            "scan_id": "scan",
            "target": "host",
            "summary": {},
            "coverage": {
                "confidence": "partial",
                "degraded": [
                    {
                        "tool": "probe",
                        "status": "timeout",
                        "impact": "coverage incomplete",
                    }
                ],
                "checked_but_not_confirmed": [{"status": "not_confirmed"}],
            },
            "evidence_index": [],
            "attack_path": [],
            "remediations": [],
            "fact_flow": [],
        }
    )

    assert "degraded: probe timeout - coverage incomplete" in text
    assert "checked: not_confirmed" in text
    assert text.count("  none") == 4


def test_llm_event_parser_skips_invalid_json_and_non_objects(tmp_path):
    reporter = TraceReporter(FactStore(str(tmp_path / "facts.db")))

    assert (
        reporter._llm_events(
            [
                {"type": "port_open", "value": "443/tcp"},
                {"type": "llm_health", "value": "{"},
                {"type": "llm_health", "value": "[]"},
            ]
        )
        == []
    )
