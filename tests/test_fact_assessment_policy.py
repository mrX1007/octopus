"""Versioned freshness and automatic fact-assessment rule contracts."""

import sqlite3
from types import SimpleNamespace

import pytest

from core.actions import ActionRequest, ExploitBaseAdapter, MetasploitActionAdapter
from core.ai.capability_assessment import CapabilityResolver
from core.ai.fact_assessment import (
    FACT_ASSESSMENT_SCHEMA_VERSION,
    AssessmentStatus,
    EvidenceCoverageStatus,
    FactFreshnessStatus,
    FreshnessPolicy,
)
from core.ai.fact_store import FactStore
from core.execution import ExecutionContext

pytestmark = pytest.mark.contract


def _automatic(target: str = "10.0.0.5") -> ExecutionContext:
    return ExecutionContext.automatic(
        actor="fact-assessment-test",
        origin="test",
        target_scope=(target,),
    )


def _record_execution(
    store: FactStore,
    execution_id: str,
    *,
    status: str = "succeeded",
    scan_id: str = "scan",
    host: str = "host",
) -> None:
    store.add_command_result(
        scan_id,
        host,
        f"probe:{execution_id}",
        f"probe {host}",
        f"{execution_id}:{status}",
        status=status,
        execution_id=execution_id,
    )


def test_versioned_freshness_policy_marks_old_facts_without_rewriting_confidence(tmp_path):
    policy = FreshnessPolicy(default_max_age_seconds=60.0)
    store = FactStore(
        str(tmp_path / "facts.db"),
        assessment_policy=policy,
        assessment_clock=lambda: 200.0,
    )
    fact_id = store.add_fact(
        "scan",
        "host",
        "service_version",
        "ssh:22:OpenSSH",
        "nmap",
        confidence=73,
        source_execution_ids=("exec-success",),
    )
    with store._get_conn() as conn:
        conn.execute("UPDATE facts SET timestamp = 100 WHERE id = ?", (fact_id,))
        conn.execute(
            "UPDATE fact_observations SET timestamp = 100 WHERE fact_id = ?",
            (fact_id,),
        )

    fact = store.get_facts("scan", "host")[0]

    assert fact["confidence"] == 73
    assert fact["freshness_status"] == FactFreshnessStatus.STALE.value
    assert fact["freshness"]["policy_version"] == policy.policy_version
    assert fact["freshness"]["rule_id"] == "fact.freshness.max_age.v1"


def test_v1_assessment_store_migrates_rule_ids_forward_on_restart(tmp_path):
    db_path = tmp_path / "legacy-facts.db"
    store = FactStore(str(db_path))
    fact_id = store.add_fact("scan", "host", "observation", "value", "legacy")
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE fact_assessments DROP COLUMN rule_id")
        conn.execute("DELETE FROM fact_assessment_schema")
        conn.execute(
            "INSERT INTO fact_assessment_schema(schema_version, applied_at) VALUES ('1.0', 1)"
        )
        conn.commit()

    migrated = FactStore(str(db_path))
    assessment = migrated.assessments.current_for_fact(fact_id)

    assert assessment is not None
    assert assessment.rule_id == "fact.assessment.legacy.v1"
    with sqlite3.connect(db_path) as conn:
        versions = {
            row[0]
            for row in conn.execute(
                "SELECT schema_version FROM fact_assessment_schema"
            ).fetchall()
        }
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(fact_assessments)").fetchall()
        }
    assert FACT_ASSESSMENT_SCHEMA_VERSION in versions
    assert "rule_id" in columns


def test_timeout_is_degraded_unknown_not_negative_evidence():
    policy = FreshnessPolicy(default_max_age_seconds=60.0)

    result = policy.evaluate(
        "service_version",
        observed_at=100.0,
        now=120.0,
        execution_statuses=("timeout",),
    )

    assert result.status is FactFreshnessStatus.UNKNOWN
    assert result.coverage is EvidenceCoverageStatus.DEGRADED
    assert result.rule_id == "fact.coverage.timeout.v1"
    summary = CapabilityResolver._freshness_confidence(
        [
            {
                "id": 1,
                "timestamp": 100.0,
                "confidence": 80,
                "freshness_status": result.status.value,
                "coverage_status": result.coverage.value,
            }
        ]
    )
    assert summary.freshness == "degraded"


def test_canonical_fact_coverage_uses_persisted_execution_status(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    fact_id = store.add_fact(
        "scan",
        "host",
        "service_version",
        "ssh:22:OpenSSH",
        "nmap",
        source_execution_ids=("exec-timeout",),
    )
    store.add_command_result(
        "scan",
        "host",
        "nmap",
        "nmap host",
        "0" * 64,
        status="timeout",
        execution_id="exec-timeout",
    )

    timed_out = store.get_facts("scan", "host")[0]
    assert timed_out["id"] == fact_id
    assert timed_out["freshness_status"] == "unknown"
    assert timed_out["coverage_status"] == "degraded"

    store.add_fact(
        "scan",
        "host",
        "service_version",
        "ssh:22:OpenSSH",
        "nmap",
        source_execution_ids=("exec-success",),
    )
    store.add_command_result(
        "scan",
        "host",
        "nmap",
        "nmap host",
        "1" * 64,
        status="succeeded",
        execution_id="exec-success",
    )

    recovered = store.get_facts("scan", "host")[0]
    assert recovered["freshness_status"] == "fresh"
    assert recovered["coverage_status"] == "complete"


@pytest.mark.parametrize(
    ("outcomes", "freshness", "coverage"),
    [
        (("succeeded", "timeout"), "unknown", "degraded"),
        (("timeout", "succeeded"), "fresh", "complete"),
    ],
)
def test_latest_execution_observation_controls_freshness_and_coverage(
    tmp_path,
    outcomes,
    freshness,
    coverage,
):
    store = FactStore(str(tmp_path / f"{'-'.join(outcomes)}.db"))
    store.add_fact(
        "scan",
        "host",
        "service_version",
        "ssh:22:OpenSSH",
        "nmap",
        source_execution_ids=("exec-first", "exec-second"),
    )
    _record_execution(store, "exec-first", status=outcomes[0])
    _record_execution(store, "exec-second", status=outcomes[1])

    fact = store.get_facts("scan", "host")[0]
    assert fact["freshness_status"] == freshness
    assert fact["coverage_status"] == coverage


def test_independent_execution_corroboration_promotes_same_scoped_fact(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    fact_id = store.add_fact(
        "scan",
        "host",
        "service_check",
        "ssh:confirmed_present",
        "probe-a",
        confidence=78,
        source_execution_ids=("exec-a",),
    )
    duplicate_id = store.add_fact(
        "scan",
        "host",
        "service_check",
        "ssh:confirmed_present",
        "probe-b",
        confidence=78,
        source_execution_ids=("exec-b",),
    )
    assert store.assessments.current_for_fact(fact_id).status is AssessmentStatus.OBSERVED

    _record_execution(store, "exec-a")
    _record_execution(store, "exec-b")

    assessment = store.assessments.current_for_fact(fact_id)

    assert duplicate_id == fact_id
    assert assessment is not None
    assert assessment.status is AssessmentStatus.VERIFIED
    assert assessment.rule_id == "fact.corroborated.independent_execution.v1"
    assert assessment.source_execution_ids == ("exec-a", "exec-b")
    assert store.get_facts("scan", "host")[0]["confidence"] == 78


def test_command_result_and_automatic_rules_share_one_transaction(tmp_path, monkeypatch):
    store = FactStore(str(tmp_path / "atomic-rules.db"))
    store.add_fact(
        "scan",
        "host",
        "service_check",
        "ssh:confirmed_present",
        "probe",
        source_execution_ids=("exec-a",),
    )

    def fail_rule_evaluation(*_args, **_kwargs):
        raise RuntimeError("rule evaluation failed")

    monkeypatch.setattr(
        store.assessments,
        "apply_automatic_rules_for_execution_in_connection",
        fail_rule_evaluation,
    )

    with pytest.raises(RuntimeError, match="rule evaluation failed"):
        _record_execution(store, "exec-a")

    assert store.get_command_results("scan", "host") == []


def test_independent_duplicate_outside_policy_window_is_not_corroboration(tmp_path):
    store = FactStore(
        str(tmp_path / "facts.db"),
        assessment_policy=FreshnessPolicy(corroboration_window_seconds=1.0),
    )
    fact_id = store.add_fact(
        "scan",
        "host",
        "service_check",
        "ssh:confirmed_present",
        "probe-a",
        source_execution_ids=("exec-a",),
    )
    with store._get_conn() as conn:
        conn.execute(
            "UPDATE fact_assessments SET created_at = created_at - 10 WHERE fact_id = ?",
            (fact_id,),
        )
    _record_execution(store, "exec-a")
    store.add_fact(
        "scan",
        "host",
        "service_check",
        "ssh:confirmed_present",
        "probe-b",
        source_execution_ids=("exec-b",),
    )
    _record_execution(store, "exec-b")

    assessment = store.assessments.current_for_fact(fact_id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.OBSERVED


@pytest.mark.parametrize("unsuccessful_status", ["failed", "timeout"])
def test_unsuccessful_persisted_execution_cannot_corroborate(
    tmp_path,
    unsuccessful_status,
):
    store = FactStore(str(tmp_path / f"corroboration-{unsuccessful_status}.db"))
    fact_id = store.add_fact(
        "scan",
        "host",
        "service_check",
        "ssh:confirmed_present",
        "probe-a",
        source_execution_ids=("exec-success",),
    )
    store.add_fact(
        "scan",
        "host",
        "service_check",
        "ssh:confirmed_present",
        "probe-b",
        source_execution_ids=("exec-unsuccessful",),
    )

    _record_execution(store, "exec-success")
    _record_execution(
        store,
        "exec-unsuccessful",
        status=unsuccessful_status,
    )

    assessment = store.assessments.current_for_fact(fact_id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.OBSERVED
    assert all(
        item.rule_id != "fact.corroborated.independent_execution.v1"
        for item in store.assessments.history(fact_id)
    )


def test_later_independent_opposite_assertion_contradicts_only_same_target_subject_and_time(
    tmp_path,
):
    policy = FreshnessPolicy(corroboration_window_seconds=300.0)
    store = FactStore(str(tmp_path / "facts.db"), assessment_policy=policy)
    positive_id = store.add_fact(
        "scan",
        "host-a",
        "surface_assertion",
        "web:confirmed_present",
        "probe-a",
        source_execution_ids=("exec-a",),
    )
    other_target_id = store.add_fact(
        "scan",
        "host-b",
        "surface_assertion",
        "web:confirmed_present",
        "probe-a",
        source_execution_ids=("exec-c",),
    )
    negative_id = store.add_fact(
        "scan",
        "host-a",
        "surface_assertion",
        "web:confirmed_absent",
        "probe-b",
        source_execution_ids=("exec-b",),
    )
    # Persist the later assertion first: re-evaluation when the older result
    # arrives must still apply the scoped contradiction atomically.
    _record_execution(store, "exec-b", host="host-a")
    _record_execution(store, "exec-c", host="host-b")
    _record_execution(store, "exec-a", host="host-a")

    contradicted = store.assessments.current_for_fact(positive_id)
    latest = store.assessments.current_for_fact(negative_id)
    other_target = store.assessments.current_for_fact(other_target_id)

    assert contradicted is not None
    assert contradicted.status is AssessmentStatus.CONTRADICTED
    assert contradicted.rule_id == "fact.contradicted.scoped_opposite.v1"
    assert contradicted.evidence_fact_ids == (negative_id,)
    assert contradicted.source_execution_ids == ("exec-a",)
    assert latest is not None and latest.status is AssessmentStatus.OBSERVED
    assert other_target is not None and other_target.status is AssessmentStatus.OBSERVED


@pytest.mark.parametrize("unsuccessful_status", ["failed", "timeout"])
def test_unsuccessful_persisted_execution_cannot_contradict(
    tmp_path,
    unsuccessful_status,
):
    store = FactStore(str(tmp_path / f"contradiction-{unsuccessful_status}.db"))
    positive_id = store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "web:confirmed_present",
        "probe-a",
        source_execution_ids=("exec-success",),
    )
    negative_id = store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "web:confirmed_absent",
        "probe-b",
        source_execution_ids=("exec-unsuccessful",),
    )

    _record_execution(store, "exec-success")
    _record_execution(
        store,
        "exec-unsuccessful",
        status=unsuccessful_status,
    )

    positive = store.assessments.current_for_fact(positive_id)
    negative = store.assessments.current_for_fact(negative_id)
    assert positive is not None and positive.status is AssessmentStatus.OBSERVED
    assert negative is not None and negative.status is AssessmentStatus.OBSERVED


def test_contradicted_duplicate_and_idempotent_attach_cannot_resurrect_fact(tmp_path):
    store = FactStore(str(tmp_path / "contradicted-idempotency.db"))
    positive_id = store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "web:confirmed_present",
        "probe-a",
        source_execution_ids=("exec-positive",),
    )
    negative_id = store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "web:confirmed_absent",
        "probe-b",
        source_execution_ids=("exec-negative",),
    )
    _record_execution(store, "exec-positive")
    _record_execution(store, "exec-negative")
    assert (
        store.assessments.current_for_fact(positive_id).status
        is AssessmentStatus.CONTRADICTED
    )

    duplicate_id = store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "web:confirmed_present",
        "probe-c",
        source_execution_ids=("exec-repeat",),
    )
    _record_execution(store, "exec-repeat")
    attached, _created = store.assessments.attach_source_executions(
        positive_id,
        ("exec-repeat",),
    )
    repeated_id = store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "web:confirmed_present",
        "probe-c",
        source_execution_ids=("exec-repeat",),
    )

    assert duplicate_id == repeated_id == positive_id
    assert attached.status is AssessmentStatus.CONTRADICTED
    assert (
        store.assessments.current_for_fact(positive_id).status
        is AssessmentStatus.CONTRADICTED
    )
    assert (
        store.assessments.current_for_fact(negative_id).status
        is AssessmentStatus.OBSERVED
    )
    assert all(
        item.status is not AssessmentStatus.VERIFIED
        for item in store.assessments.history(positive_id)
    )


def test_same_execution_or_expired_observation_is_not_independent_contradiction(tmp_path):
    policy = FreshnessPolicy(corroboration_window_seconds=1.0)
    store = FactStore(str(tmp_path / "facts.db"), assessment_policy=policy)
    first_id = store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "api:confirmed_present",
        "probe",
        source_execution_ids=("same-exec",),
    )
    store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "api:confirmed_absent",
        "probe",
        source_execution_ids=("same-exec",),
    )
    _record_execution(store, "same-exec")

    assert store.assessments.current_for_fact(first_id).status is AssessmentStatus.OBSERVED

    expired_store = FactStore(
        str(tmp_path / "expired.db"),
        assessment_policy=policy,
    )
    expired_id = expired_store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "api:confirmed_present",
        "probe-a",
        source_execution_ids=("exec-a",),
    )
    with expired_store._get_conn() as conn:
        conn.execute(
            "UPDATE facts SET timestamp = timestamp - 10 WHERE id = ?",
            (expired_id,),
        )
    expired_store.add_fact(
        "scan",
        "host",
        "surface_assertion",
        "api:confirmed_absent",
        "probe-b",
        source_execution_ids=("exec-b",),
    )
    _record_execution(expired_store, "exec-a")
    _record_execution(expired_store, "exec-b")

    assert (
        expired_store.assessments.current_for_fact(expired_id).status
        is AssessmentStatus.OBSERVED
    )


@pytest.mark.parametrize(
    ("fact", "expected_missing"),
    [
        (
            {
                "id": 1,
                "type": "potential_vulnerability",
                "value": "CVE-2026-1000",
                "assessment_status": "contradicted",
                "freshness_status": "fresh",
            },
            "assessment:contradicted",
        ),
        (
            {
                "id": 2,
                "type": "potential_vulnerability",
                "value": "CVE-2026-1000",
                "assessment_status": "observed",
                "freshness_status": "stale",
            },
            "assessment:stale",
        ),
        (
            {
                "id": 3,
                "type": "potential_vulnerability",
                "value": "CVE-2026-1000",
                "assessment_status": "observed",
                "freshness_status": "unknown",
                "coverage_status": "degraded",
            },
            "assessment:degraded_coverage",
        ),
    ],
)
def test_exploit_applicability_rejects_only_relevant_unusable_canonical_assessment(
    fact,
    expected_missing,
):
    exploit = SimpleNamespace(
        name="Example exploit",
        cve="CVE-2026-1000",
        description="fixture",
        supported_os=(),
    )
    adapter = ExploitBaseAdapter(exploit)
    request = ActionRequest(
        target="10.0.0.5",
        execution_context=_automatic(),
        handle=object(),
        facts=(fact,),
    )

    result = adapter.applicability(request)

    assert result.applicable is False
    assert expected_missing in result.missing_requirements


def test_exploit_applicability_accepts_fresh_non_contradicted_candidate():
    exploit = SimpleNamespace(
        name="Example exploit",
        cve="CVE-2026-1000",
        description="fixture",
        supported_os=(),
    )
    result = ExploitBaseAdapter(exploit).applicability(
        ActionRequest(
            target="10.0.0.5",
            execution_context=_automatic(),
            handle=object(),
            facts=(
                {
                    "id": 1,
                    "type": "potential_vulnerability",
                    "value": "CVE-2026-1000",
                    "assessment_status": "inferred",
                    "freshness_status": "fresh",
                    "coverage_status": "complete",
                },
            ),
        )
    )

    assert result.applicable is True
    assert "canonical_assessment:inferred" in result.reasons


def test_metasploit_exploit_applicability_consumes_matching_assessment():
    adapter = MetasploitActionAdapter(
        "exploit/test/example",
        dependency_check=lambda _name: True,
    )
    result = adapter.applicability(
        ActionRequest(
            target="10.0.0.5",
            execution_context=_automatic(),
            facts=(
                {
                    "id": 4,
                    "type": "vulnerability",
                    "value": "msf_check_positive:exploit/test/example",
                    "assessment_status": "contradicted",
                    "freshness_status": "fresh",
                },
            ),
        )
    )

    assert result.applicable is False
    assert "assessment:contradicted" in result.missing_requirements
