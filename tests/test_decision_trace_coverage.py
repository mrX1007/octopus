"""Boundary and failure-path coverage for the durable decision trace."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

import pytest

import core.ai.decision_trace as trace_module
from core.ai.decision_trace import DecisionTraceStore, build_decision_metrics

pytestmark = pytest.mark.contract


class IdentityRedactor:
    def redact_data(self, value):
        return value

    def redact_text(self, value, *, kind):
        del kind
        return str(value or "")


def _store(path=":memory:", **kwargs):
    return DecisionTraceStore(path, redactor=IdentityRedactor(), **kwargs)


def test_memory_store_connection_lifecycle_and_rollback():
    store = _store(max_events_per_scope=-1, max_total_events=-1)
    assert store.max_events_per_scope == 5
    assert store.max_total_events == 5

    with pytest.raises(RuntimeError, match="rollback"), store._connect() as conn:
        conn.execute("CREATE TABLE rolled_back(value TEXT)")
        raise RuntimeError("rollback")

    assert store.count() == 0
    store.close()
    assert store._persistent_conn is None
    store.close()


def test_constructor_rejects_unknown_schema_version(tmp_path):
    path = tmp_path / "unsupported.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE decision_trace_schema (schema_version TEXT PRIMARY KEY, applied_at REAL NOT NULL)")
    conn.execute(
        "INSERT INTO decision_trace_schema(schema_version, applied_at) VALUES (?, ?)",
        ("999", 1.0),
    )
    conn.commit()
    conn.close()

    with pytest.raises(RuntimeError, match="999"):
        _store(str(path))


def test_large_payload_is_reduced_before_storage(tmp_path):
    store = _store(
        str(tmp_path / "large.db"),
        max_events_per_scope=50_000,
        max_total_events=2_000_000,
    )
    assert store.max_events_per_scope == 20_000
    assert store.max_total_events == 1_000_000
    large = {f"key-{index}": "x" * 4_096 for index in range(64)}
    event_id, created = store.record(
        {
            "event_type": "large",
            "scan_id": "scan",
            "expected_outcome": large,
            "actual_outcome": large,
            "rejected": [str(index) for index in range(20)],
        }
    )

    assert event_id.startswith("decision://sha256/")
    assert created is True
    stored = store.list_events()[0]
    assert stored["expected_outcome"] == {"truncated": True}
    assert stored["actual_outcome"] == {"truncated": True}
    assert len(stored["rejected"]) == 8


def test_list_and_count_filter_combinations_and_limits(tmp_path):
    store = _store(str(tmp_path / "filters.db"))
    for index, (scan, mission, event_type) in enumerate(
        [("s1", "m1", "one"), ("s1", "m2", "two"), ("s2", "m1", "two")],
        start=1,
    ):
        store.record(
            {
                "event_id": f"e-{index}",
                "scan_id": scan,
                "mission_id": mission,
                "event_type": event_type,
                "occurred_at": index,
            }
        )

    assert len(store.list_events()) == 3
    assert len(store.list_events(mission_id="m1", event_type="two", limit=99_999)) == 1
    assert len(store.list_events(scan_id="s1", mission_id="m1", limit=0)) == 1
    assert store.count() == 3
    assert store.count(mission_id="m1") == 2
    assert store.count(scan_id="s1", mission_id="m2") == 1


def test_count_defensively_handles_a_missing_database_row():
    store = _store()

    class ConnectionDouble:
        def execute(self, _query, _params):
            return self

        def fetchone(self):
            return None

    @contextmanager
    def connection_double():
        yield ConnectionDouble()

    store._connect = connection_double
    assert store.count() == 0


def test_normalization_handles_redactor_and_state_shape_boundaries():
    store = _store()
    store.redactor = type(
        "NonMappingRedactor",
        (),
        {
            "redact_data": lambda _self, _value: "not-a-mapping",
            "redact_text": lambda _self, value, *, kind: str(value or ""),
        },
    )()
    normalized = store._normalize_event({"event_type": "ignored"})
    assert normalized["event_type"] == "decision"
    assert normalized["scope_key"].startswith("decision-scope://sha256/")

    store.redactor = IdentityRedactor()
    normalized = store._normalize_event(
        {
            "event_type": "shape",
            "state_transition": "invalid",
            "state_from": "before",
            "state_to": "after",
        }
    )
    assert normalized["state_transition"] == {"from": "before", "to": "after"}


def test_text_and_rejection_collections_cover_deduplication_and_bounds():
    store = _store()
    assert store._text_list(None, "kind") == []
    assert store._text_list(b"bytes", "kind") == ["b'bytes'"]
    values = ["", "same", "same", *[f"v-{index}" for index in range(100)]]
    result = store._text_list(values, "kind")
    assert len(result) == 64
    assert result[0] == "same"

    assert store._rejected("bad") == []
    assert store._rejected(123) == []
    assert store._rejected({"action_id": "a", "reasons": ["why"]}) == [{"candidate": "a", "reason": "['why']"}]
    assert store._rejected(["plain"]) == [{"candidate": "", "reason": "plain"}]


def test_metrics_fallbacks_filters_and_empty_denominators():
    complete = {
        "type": "vulnerability_candidate",
        "timestamp": 4,
        "assessment": {
            "status": "verified",
            "reason": "checked",
            "evidence_fact_ids": [1],
            "source_execution_ids": ["run"],
        },
    }
    incomplete = {
        "type": "vulnerability",
        "timestamp": "bad",
        "assessment_status": "verified",
        "assessment": "invalid",
    }
    contradicted = {
        "type": "finding",
        "timestamp": 5,
        "assessment": {"status": "contradicted"},
    }
    internal = {"type": "check_result", "timestamp": 6}
    report = build_decision_metrics(
        [complete, incomplete, contradicted, internal, "ignored"],
        [
            {"status": "blocked", "new_facts": 50},
            {"status": "succeeded", "new_facts": 0, "parsed_facts": 0},
            "ignored",
        ],
        decision_events=[
            {
                "event_type": "goal_selection",
                "actual_outcome": {},
                "occurred_at": 3,
                "duration": "bad",
                "cost": "invalid",
            },
            {
                "event_type": "provider_selection",
                "fallback_count": 0,
                "retry_count": 0,
                "cost": {},
            },
            {
                "event_type": "mission_resume_outcome",
                "actual_outcome": {"status": "failed"},
            },
            "ignored",
        ],
        task_outcomes=[
            {"reason": "invalid_task"},
            {"reason": "ordinary"},
            "ignored",
        ],
    )

    assert report["counts"]["facts"] == 4
    assert report["counts"]["executed_commands"] == 1
    assert report["metrics"]["evidence_completeness"] == 0.5
    assert report["metrics"]["invalid_planner_rate"] == pytest.approx(1 / 3)
    assert report["metrics"]["fallback_rate"] == 0.0
    assert report["metrics"]["retry_rate"] == 0.0
    assert report["metrics"]["resume_success_rate"] == 0.0

    empty = build_decision_metrics([], [])
    assert empty["metrics"]["time_to_first_useful_evidence_seconds"] is None
    assert empty["metrics"]["duplicate_rate"] is None
    assert empty["metrics"]["evidence_completeness"] == 1.0


def test_private_value_helpers_cover_all_type_and_error_boundaries():
    assert trace_module._first_delay([{"timestamp": "bad"}], 1.0) is None
    assert trace_module._verified_fact_complete({"assessment": "bad"}) is False
    assert trace_module._assessment_status({"assessment": "bad"}) == "observed"

    nested = {"z": [[[[["too deep"]]]]], "a": True, "b": None}
    bounded = trace_module._bounded_value(nested)
    assert bounded["z"][0][0][0] == "[depth-bounded]"
    assert trace_module._bounded_value(1) == 1
    assert trace_module._bounded_value(1.5) == 1.5
    assert trace_module._bounded_value(float("inf")) == 0.0
    assert trace_module._bounded_value("x" * 5_000) == "x" * 4_096
    assert trace_module._bounded_text("é" * 10, 3) == "é"

    assert trace_module._positive_ints(None) == []
    assert trace_module._positive_ints("2") == [2]
    assert trace_module._positive_ints(["bad", [], -1, 0, 2, 2, 3]) == [2, 3]
    assert trace_module._bounded_count("bad") == 0
    assert trace_module._bounded_count(-1) == 0
    assert trace_module._bounded_count(2_000_000) == 1_000_000
    assert trace_module._nonnegative_float("bad") == 0.0
    assert trace_module._nonnegative_float(-1) == 0.0
    assert trace_module._nonnegative_float(float("nan")) == 0.0
    assert trace_module._nonnegative_float(1.5) == 1.5
    assert trace_module._positive_timestamp(0) is None
    assert trace_module._timestamp(0) > 0
