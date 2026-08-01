"""Complete edge-case coverage for evaluated fact snapshots."""

from __future__ import annotations

import copy

import pytest

import core.ai.evaluated_facts as evaluated_module
from core.ai.evaluated_facts import (
    EvaluatedFact,
    EvaluatedFactSnapshot,
    fact_is_decision_usable,
)

pytestmark = pytest.mark.contract


def _rich_facts():
    return [
        {
            "id": "1",
            "type": "service",
            "coverage_status": "complete",
            "freshness_status": "fresh",
            "freshness": {"evaluated_at": 10, "policy_version": "one"},
            "assessment": {
                "assessment_id": "a-1",
                "status": "verified",
                "source_execution_ids": ["exec-1", "", "exec-1"],
            },
            "observations": [
                "ignored",
                {},
                {
                    "source_identity": "TLS Sensor A",
                    "observation_method": "tls-handshake",
                },
                {"source": "nmap --safe", "observation_method": ""},
                {"source_identity": "", "observation_method": "manual"},
            ],
        },
        {
            "id": 2,
            "coverage_status": "complete",
            "freshness": {"evaluated_at": "bad", "policy_version": "two"},
            "assessment": "invalid",
            "sources": ["browser capture", "verify-check", ""],
            "source": "ssh inventory",
        },
        {
            "id": [],
            "coverage_status": "complete",
            "freshness": "invalid",
            "observations": [],
        },
    ]


def test_evaluated_fact_invalid_id_and_payload_round_trip():
    fact = EvaluatedFact.from_mapping(
        {
            "id": [],
            "assessment_id": "fallback-id",
            "assessment_status": " OBSERVED ",
            "freshness_status": " FRESH ",
            "coverage_status": " COMPLETE ",
            "opaque": object(),
        }
    )

    assert fact.fact_id is None
    assert fact.assessment_id == "fallback-id"
    assert fact.assessment_status == "observed"
    assert fact.freshness_status == "fresh"
    assert fact.coverage_status == "complete"
    assert fact.to_dict()["opaque"].startswith("<object object")


def test_snapshot_collects_mixed_policy_and_all_provenance_forms():
    snapshot = EvaluatedFactSnapshot.build(
        "scan",
        ["HOST.Example", "host.example"],
        [*_rich_facts(), "ignored"],
    )

    assert snapshot.canonical_scope == ("host.example",)
    assert snapshot.evaluated_at == 10
    assert snapshot.freshness_policy_version == "mixed"
    assert snapshot.coverage_status == "complete"
    assert snapshot.supporting_execution_ids == ("exec-1",)
    assert snapshot.source_identities == (
        "browser",
        "nmap",
        "ssh",
        "tls_sensor_a",
        "verify-check",
    )
    assert snapshot.observation_methods == (
        "application_observation",
        "authenticated_observation",
        "manual",
        "network_observation",
        "tls-handshake",
        "verification_check",
    )
    assert len(snapshot.historical_facts()) == 3
    assert len(snapshot.decision_facts()) == 3
    assert snapshot.to_context()["historical_fact_count"] == 3


def test_snapshot_coverage_policy_and_clock_outcomes(monkeypatch):
    monkeypatch.setattr(evaluated_module.time, "time", lambda: 55.0)
    degraded = EvaluatedFactSnapshot.build(
        "scan",
        "host",
        [{"coverage_status": "degraded", "freshness": {"policy_version": "one"}}],
    )
    assert degraded.coverage_status == "degraded"
    assert degraded.freshness_policy_version == "one"
    assert degraded.evaluated_at == 55

    unknown = EvaluatedFactSnapshot.build("scan", "host", [], evaluated_at=0)
    assert unknown.coverage_status == "unknown"
    assert unknown.freshness_policy_version == "unknown"
    assert unknown.evaluated_at == 0


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda payload: "not-an-object", "must be an object"),
        (lambda payload: {**payload, "schema_version": "999"}, "unsupported"),
        (lambda payload: {**payload, "canonical_scope": "host"}, "must be arrays"),
        (lambda payload: {**payload, "facts": ["bad"]}, "must be objects"),
        (lambda payload: {**payload, "snapshot_ref": ""}, "integrity check"),
        (lambda payload: {**payload, "snapshot_ref": "wrong"}, "integrity check"),
        (
            lambda payload: {**payload, "coverage_status": "tampered"},
            "derived metadata",
        ),
    ],
)
def test_payload_validation_rejects_each_invalid_shape(mutation, message):
    payload = EvaluatedFactSnapshot.build("scan", "host", [{"id": 1}], evaluated_at=12).to_payload()
    invalid = mutation(copy.deepcopy(payload))

    with pytest.raises(ValueError, match=message):
        EvaluatedFactSnapshot.from_payload(invalid)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("bad", None),
        ([], None),
        (-1, None),
        (float("inf"), None),
        (float("-inf"), None),
        (0, 0.0),
        (1.5, 1.5),
    ],
)
def test_finite_number_boundaries(value, expected):
    assert evaluated_module._finite_number(value) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("", ""),
        ("  NMAP --safe ", "nmap"),
        ("Odd!! Tool argument", "odd"),
    ],
)
def test_source_identity_normalization(source, expected):
    assert evaluated_module._source_identity(source) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("verify-check", "verification_check"),
        ("browser", "application_observation"),
        ("nmap", "network_observation"),
        ("ssh-session", "authenticated_observation"),
        ("human", "reported_observation"),
    ],
)
def test_observation_method_categories(source, expected):
    assert evaluated_module._observation_method(source) == expected


def test_provenance_token_empty_and_punctuation():
    assert evaluated_module._provenance_token(None) == ""
    assert evaluated_module._provenance_token(" TLS Sensor/A! ") == "tls_sensor/a"


@pytest.mark.parametrize("trust_level", ["target_controlled", "untrusted"])
def test_fact_with_only_non_trusted_observations_is_not_decision_usable(
    trust_level: str,
) -> None:
    fact = {
        "type": "system_access",
        "value": "root_access_confirmed",
        "observations": [{"trust_level": trust_level}],
    }

    assert fact_is_decision_usable(fact) is False
    snapshot = EvaluatedFactSnapshot.build("scan", "host", [fact])
    assert snapshot.historical_facts() == (fact,)
    assert snapshot.decision_facts() == ()
    assert snapshot.to_context()["assessment_heads"][0]["trust_level"] == trust_level


def test_trusted_observation_keeps_fact_usable_despite_untrusted_duplicate() -> None:
    fact = {
        "type": "system_access",
        "value": "root_access_confirmed",
        "observations": [
            {"trust_level": "target_controlled"},
            {"trust_level": "trusted"},
        ],
    }

    assert fact_is_decision_usable(fact) is True
    snapshot = EvaluatedFactSnapshot.build("scan", "host", [fact])
    assert len(snapshot.decision_facts()) == 1
    assert snapshot.to_context()["assessment_heads"][0]["trust_level"] == "trusted"


def test_known_untrusted_observation_method_fails_closed_without_explicit_level() -> None:
    fact = {
        "type": "credential",
        "value": "ssh_login_success:root@host",
        "observations": [{"observation_method": "target-controlled-stdout"}],
    }

    assert fact_is_decision_usable(fact) is False
