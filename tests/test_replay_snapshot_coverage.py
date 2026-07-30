"""Failure-path coverage for replay snapshot assertions."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.ai.replay_snapshot import ReplaySnapshot

pytestmark = pytest.mark.contract


class _FactStore:
    def get_facts(self, _scan_id, _target):
        return [{"type": "present", "value": "known-value"}]


def _snapshot() -> ReplaySnapshot:
    snapshot = ReplaySnapshot.__new__(ReplaySnapshot)
    snapshot.pipeline = SimpleNamespace(
        fact_store=_FactStore(),
        replay_outputs=lambda *_args: {
            "snapshot_actions": [{"command": "known-action host"}],
            "context": {"surface_states": {"web": "confirmed_absent"}},
        },
    )
    return snapshot


def test_replay_reports_every_missing_expectation():
    result = _snapshot().run(
        {
            "schema_version": "1.0",
            "scan_id": "scan",
            "target": "host",
            "expected_facts": [{"type": "missing", "value": "fact"}],
            "expected_fact_prefixes": [("present", "other-prefix")],
            "expected_actions": ["missing-action"],
            "expected_surface_states": {"web": "confirmed_present"},
        }
    )

    assert result["ok"] is False
    assert result["failures"] == [
        "missing_fact:missing:fact",
        "missing_fact_prefix:present:other-prefix",
        "missing_action:missing-action",
        "surface_state:web:expected=confirmed_present:actual=confirmed_absent",
    ]


def test_assert_ok_joins_failures():
    with pytest.raises(AssertionError, match="missing_action:absent"):
        _snapshot().assert_ok(
            {
                "scan_id": "scan",
                "target": "host",
                "expected_actions": ["absent"],
            }
        )


def test_expected_pair_rejects_invalid_shapes():
    snapshot = _snapshot()

    with pytest.raises(ValueError, match="Invalid expected fact"):
        snapshot._expected_pair(["only-one"])
