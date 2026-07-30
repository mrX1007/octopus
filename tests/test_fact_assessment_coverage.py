"""Focused branch coverage for the fact-assessment persistence boundary."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.ai.fact_assessment import (
    AssessmentStatus,
    FactAssessment,
    FreshnessPolicy,
)
from core.ai.fact_store import FactStore

pytestmark = pytest.mark.unit


def _assessment(**overrides):
    values = {
        "assessment_id": "fa_current",
        "fact_id": 1,
        "status": AssessmentStatus.OBSERVED,
        "confidence": 80,
        "rule_id": "fact.test.observed.v1",
        "reason": "observed",
        "assessor": "test",
        "evidence_fact_ids": (1,),
        "source_execution_ids": ("exec-a",),
        "supersedes_assessment_id": None,
        "created_at": 10.0,
    }
    values.update(overrides)
    return FactAssessment(**values)


class _Rows:
    def __init__(self, rows=(), row=None):
        self._rows = rows
        self._row = row

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._row


def test_freshness_policy_rejects_invalid_configuration_and_timestamps():
    with pytest.raises(ValueError, match="version"):
        FreshnessPolicy(policy_version=" ")
    with pytest.raises(ValueError, match="default_max_age_seconds"):
        FreshnessPolicy(default_max_age_seconds=0)
    with pytest.raises(ValueError, match="corroboration_window_seconds"):
        FreshnessPolicy(corroboration_window_seconds=float("inf"))
    with pytest.raises(ValueError, match="type bounds"):
        FreshnessPolicy(max_age_by_type=(("", 1.0),))

    policy = FreshnessPolicy()
    incomplete = policy.evaluate(
        "service",
        observed_at="bad",
        now=10,
        execution_statuses=("failed",),
    )
    missing = policy.evaluate("service", observed_at=None, now=10)

    assert incomplete.rule_id == "fact.coverage.incomplete_execution.v1"
    assert incomplete.observed_at is None
    assert missing.rule_id == "fact.freshness.timestamp_missing.v1"
    assert FreshnessPolicy._timestamp(object()) is None


def test_startup_rejects_an_unsupported_assessment_schema(tmp_path):
    db_path = tmp_path / "unsupported.db"
    store = FactStore(str(db_path))
    with store._get_conn() as conn:
        conn.execute(
            "INSERT INTO fact_assessment_schema(schema_version, applied_at) VALUES (?, ?)",
            ("99.0", 1.0),
        )

    with pytest.raises(RuntimeError, match=r"99\.0"):
        FactStore(str(db_path))


def test_startup_backfills_a_legacy_derived_fact_as_inferred(tmp_path):
    db_path = tmp_path / "backfill.db"
    store = FactStore(str(db_path))
    evidence_id = store.add_fact("scan", "host", "observation", "proof", "test")
    derived_id = store.add_fact(
        "scan",
        "host",
        "claim",
        "derived",
        "test",
        derived_from=(evidence_id,),
    )
    with store._get_conn() as conn:
        conn.execute("DELETE FROM fact_assessment_heads WHERE fact_id = ?", (derived_id,))
        conn.execute("DELETE FROM fact_assessments WHERE fact_id = ?", (derived_id,))

    migrated = FactStore(str(db_path)).assessments.current_for_fact(derived_id)

    assert migrated is not None
    assert migrated.status is AssessmentStatus.INFERRED
    assert migrated.evidence_fact_ids == (evidence_id,)


def test_existing_non_head_assessment_fields_are_redacted(tmp_path, monkeypatch):
    store = FactStore(str(tmp_path / "redact.db"))
    assessments = store.assessments
    monkeypatch.setattr(
        assessments,
        "redactor",
        SimpleNamespace(redact_text=lambda value, **_kwargs: f"safe:{value}"),
    )
    conn = MagicMock()

    def execute(sql, _params=()):
        if "SELECT fact_id, assessment_id" in sql:
            return _Rows([])
        if "SELECT assessment_id, reason, assessor" in sql:
            return _Rows([("old", "reason", "assessor")])
        if "SELECT assessment_id, ordinal, execution_id" in sql:
            return _Rows([("old", 0, "execution")])
        return _Rows()

    conn.execute.side_effect = execute

    assert assessments._redact_existing_rows(conn) == ()
    assert conn.execute.call_count == 5


def test_valid_derived_ids_rejects_bad_shapes_and_filters_by_scan(tmp_path):
    store = FactStore(str(tmp_path / "derived.db"))
    first = store.add_fact("scan", "host", "observation", "one", "test")
    second = store.add_fact("scan", "host", "observation", "two", "test")
    other = store.add_fact("other", "host", "observation", "three", "test")
    assessments = store.assessments

    with store._get_conn() as conn:
        assert assessments._valid_derived_ids(conn, first, "{") == ()
        assert assessments._valid_derived_ids(conn, first, "{}") == ()
        assert assessments._valid_derived_ids(conn, first, '["bad", 0]') == ()
        assert assessments._valid_derived_ids(conn, 999999, f"[{second}]") == ()
        assert assessments._valid_derived_ids(
            conn,
            first,
            f"[{other}, {second}, {second}]",
        ) == (second,)


@pytest.mark.parametrize(
    ("fact_type", "value", "expected"),
    [
        ("", "present", None),
        ("service", "", None),
        ("service", "confirmed_present:web", ("service:web", "positive")),
        ("service", "nonsense", None),
        ("---", "present", None),
        ("service", "present:---", None),
    ],
)
def test_scoped_claim_edge_cases(tmp_path, fact_type, value, expected):
    store = FactStore(str(tmp_path / "claim.db"))
    assert store.assessments._scoped_claim(fact_type, value) == expected


def test_automatic_rules_report_missing_fact_and_assessment(tmp_path):
    store = FactStore(str(tmp_path / "rules.db"))
    assessments = store.assessments
    fact_id = store.add_fact("scan", "host", "service", "present", "test")

    with store._get_conn() as conn:
        with pytest.raises(KeyError, match="Unknown fact_id"):
            assessments._apply_automatic_rules_in_connection(conn, 999999)
        conn.execute("DELETE FROM fact_assessment_heads WHERE fact_id = ?", (fact_id,))
        with pytest.raises(KeyError, match="Unassessed fact_id"):
            assessments._apply_automatic_rules_in_connection(conn, fact_id)


@pytest.mark.parametrize(
    ("observed_at", "candidates"),
    [
        ("bad", []),
        (10.0, [(2, "host", "service", "present", "bad")]),
        (10.0, [(2, "host", "service", "present", 10.0)]),
        (10.0, [(2, "host", "service", "nonsense", 9.0)]),
        (10.0, [(2, "host", "service", "different:present", 9.0)]),
    ],
)
def test_automatic_rule_candidate_guard_paths(
    tmp_path,
    monkeypatch,
    observed_at,
    candidates,
):
    store = FactStore(str(tmp_path / "candidate-guards.db"))
    assessments = store.assessments
    current = _assessment()
    conn = MagicMock()

    def execute(sql, _params=()):
        if "SELECT scan_id, host, type, value, timestamp" in sql:
            return _Rows(row=("scan", "host", "service", "present", observed_at))
        if "SELECT id, host, type, value, timestamp" in sql:
            return _Rows(candidates)
        raise AssertionError(sql)

    conn.execute.side_effect = execute
    monkeypatch.setattr(assessments, "_successful_execution_keys", lambda *_args: {"key"})
    monkeypatch.setattr(
        assessments,
        "_has_independent_observation_provenance",
        lambda *_args, **_kwargs: False,
    )

    assert assessments._apply_automatic_rules_in_connection(conn, 1, current) is current


def test_apply_rules_skips_an_impacted_fact_without_a_head(tmp_path, monkeypatch):
    store = FactStore(str(tmp_path / "headless.db"))
    assessments = store.assessments
    monkeypatch.setattr(
        assessments,
        "automatic_rule_fact_ids_for_execution_in_connection",
        lambda *_args, **_kwargs: (7,),
    )
    monkeypatch.setattr(assessments, "_current_in_connection", lambda *_args: None)

    assert (
        assessments.apply_automatic_rules_for_execution_in_connection(
            MagicMock(), execution_key="key", scan_id="scan", host="host"
        )
        == ()
    )


def test_automatic_rule_fact_ids_guard_paths(tmp_path):
    store = FactStore(str(tmp_path / "impacted.db"))
    assessments = store.assessments
    conn = MagicMock()

    assert (
        assessments.automatic_rule_fact_ids_for_execution_in_connection(
            conn, execution_key="", scan_id="scan", host="host"
        )
        == ()
    )
    conn.execute.return_value = _Rows([])
    assert (
        assessments.automatic_rule_fact_ids_for_execution_in_connection(
            conn, execution_key="missing", scan_id="scan", host="host"
        )
        == ()
    )

    conn.execute.side_effect = [
        _Rows([(1, "scan", "host", "service", "bad")]),
        _Rows([(1, "scan", "host", "service", 10.0)]),
        _Rows([(2, "host", "bad")]),
    ]
    assert (
        assessments.automatic_rule_fact_ids_for_execution_in_connection(
            conn, execution_key="bad-direct", scan_id="scan", host="host"
        )
        == ()
    )
    assert assessments.automatic_rule_fact_ids_for_execution_in_connection(
        conn, execution_key="bad-candidate", scan_id="scan", host="host"
    ) == (1,)


def test_corroboration_window_handles_initial_and_missing_previous(tmp_path):
    store = FactStore(str(tmp_path / "window.db"))
    assessments = store.assessments
    conn = MagicMock()

    assert assessments._corroboration_within_window(conn, _assessment()) is True
    conn.execute.return_value = _Rows(row=None)
    assert (
        assessments._corroboration_within_window(
            conn,
            replace(_assessment(), supersedes_assessment_id="missing"),
        )
        is False
    )


def test_assessment_validation_without_optional_hooks_or_evidence(tmp_path):
    store = FactStore(str(tmp_path / "validation.db"))
    assessments = store.assessments
    assessments._post_commit_hook = None
    assessments._transition_hook = None
    fact_id = store.add_fact("scan", "host", "observation", "value", "test")

    with pytest.raises(KeyError, match="Unknown fact_id"):
        assessments.assess_fact(
            999999,
            "observed",
            confidence=50,
            reason="reason",
            assessor="test",
        )
    with pytest.raises(ValueError, match="reason"):
        assessments.assess_fact(
            fact_id,
            "observed",
            confidence=50,
            reason="",
            assessor="test",
        )
    with pytest.raises(ValueError, match="assessor"):
        assessments.assess_fact(
            fact_id,
            "observed",
            confidence=50,
            reason="reason",
            assessor="",
        )

    assessment, created = assessments.assess_fact(
        fact_id,
        "inferred",
        confidence=50,
        reason="inference",
        assessor="test",
    )
    assert created is True
    assert assessment.evidence_fact_ids == ()


def test_changed_display_redaction_without_transition_hook(tmp_path):
    store = FactStore(str(tmp_path / "refresh.db"))
    fact_id = store.add_fact(
        "scan",
        "host",
        "observation",
        "value",
        "test",
        source_execution_ids=("exec-secret",),
    )
    assessments = store.assessments
    assessments._transition_hook = None
    assessments.secret_store.store("secret", kind="test")

    with store._get_conn() as conn:
        current = assessments._current_in_connection(conn, fact_id)
        assert current is not None
        refreshed = assessments._refresh_display_redaction(conn, current)

    assert refreshed.source_execution_ids[0] != "exec-secret"
    assert "[REDACTED" in refreshed.source_execution_ids[0]


def test_attach_batch_read_and_filtered_listing_paths(tmp_path):
    store = FactStore(str(tmp_path / "public-paths.db"))
    assessments = store.assessments
    fact_id = store.add_fact("scan", "host", "observation", "value", "test")

    with pytest.raises(KeyError, match="Unknown or unassessed"):
        assessments.attach_source_executions(999999, ("exec",))
    attached, created = assessments.attach_source_executions(fact_id, ("exec",))

    assert created is True
    assert attached.source_execution_ids == ("exec",)
    assert assessments.current_for_facts((fact_id, 0, "bad")) == {fact_id: attached}
    assert assessments.list_for_scan(
        "scan",
        host="host",
        status=AssessmentStatus.OBSERVED,
        current_only=False,
    )


@pytest.mark.parametrize(
    ("method", "args", "message"),
    [
        ("_rule_id", ("BAD RULE", AssessmentStatus.OBSERVED), "rule_id"),
        ("_status", ("missing",), "Unsupported"),
        ("_confidence", (True,), "confidence"),
        ("_confidence", (object(),), "confidence"),
        ("_confidence", (10.5,), "confidence"),
    ],
)
def test_scalar_validation_helpers(tmp_path, method, args, message):
    store = FactStore(str(tmp_path / "helpers.db"))
    with pytest.raises(ValueError, match=message):
        getattr(store.assessments, method)(*args)


def test_collection_and_bounded_text_helpers(tmp_path):
    assessments = FactStore(str(tmp_path / "collections.db")).assessments

    assert assessments._positive_ids(("bad", 0, 2, 2, 3)) == (2, 3)
    assert assessments._raw_texts((None, " ", "one", "one", "two")) == (
        "one",
        "two",
    )
    assert assessments._bounded("abc", 3) == "abc"
    assert assessments._bounded("éé", 3) == "é"
