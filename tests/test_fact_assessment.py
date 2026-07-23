"""Contract and adversarial tests for canonical fact assessment."""

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.ai.evidence import EvidenceVerifier
from core.ai.fact_assessment import AssessmentStatus, FreshnessPolicy
from core.ai.fact_store import FactStore
from core.ai.reporting import build_finding_groups
from core.ai.state_resolver import StateResolver
from core.secrets import SecretStore

pytestmark = pytest.mark.contract


def test_fact_ingress_separates_observed_and_inferred_assessments(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    observed_id = store.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "22/tcp (ssh)",
        "nmap",
        confidence=91,
        source_execution_ids=("exec-nmap",),
    )
    inferred_id = store.add_fact(
        "scan",
        "10.0.0.5",
        "service_version",
        "ssh:22:OpenSSH",
        "derived:nmap",
        confidence=82,
        derived_from=[observed_id],
        source_execution_ids=("exec-nmap",),
    )

    observed = store.assessments.current_for_fact(observed_id)
    inferred = store.assessments.current_for_fact(inferred_id)

    assert observed is not None
    assert observed.status is AssessmentStatus.OBSERVED
    assert observed.evidence_fact_ids == (observed_id,)
    assert observed.source_execution_ids == ("exec-nmap",)
    assert inferred is not None
    assert inferred.status is AssessmentStatus.INFERRED
    assert inferred.evidence_fact_ids == (observed_id,)
    assert inferred.source_execution_ids == ("exec-nmap",)
    hydrated = {fact["id"]: fact for fact in store.get_facts("scan")}
    assert hydrated[observed_id]["assessment_status"] == "observed"
    assert hydrated[inferred_id]["assessment_status"] == "inferred"


def test_assessments_are_idempotent_append_only_transitions(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    evidence_id = store.add_fact("scan", "host", "check_result", "positive", "tool")
    claim_id = store.add_fact(
        "scan",
        "host",
        "vulnerability_candidate",
        "CVE-2026-1000",
        "parser",
    )
    conflict_id = store.add_fact("scan", "host", "check_result", "negative", "tool-2")

    verified, created = store.assessments.assess_fact(
        claim_id,
        AssessmentStatus.VERIFIED,
        confidence=95,
        reason="Positive check matched the candidate.",
        assessor="test.verifier",
        evidence_fact_ids=(evidence_id,),
        source_execution_ids=("exec-positive",),
    )
    duplicate, duplicate_created = store.assessments.assess_fact(
        claim_id,
        "verified",
        confidence=95,
        reason="Positive check matched the candidate.",
        assessor="test.verifier",
        evidence_fact_ids=(evidence_id,),
        source_execution_ids=("exec-positive",),
    )
    contradicted, contradicted_created = store.assessments.assess_fact(
        claim_id,
        AssessmentStatus.CONTRADICTED,
        confidence=90,
        reason="A later check produced conflicting evidence.",
        assessor="test.verifier",
        evidence_fact_ids=(conflict_id,),
        source_execution_ids=("exec-negative",),
    )
    reverified, reverified_created = store.assessments.assess_fact(
        claim_id,
        AssessmentStatus.VERIFIED,
        confidence=95,
        reason="Positive check matched the candidate.",
        assessor="test.verifier",
        evidence_fact_ids=(evidence_id,),
        source_execution_ids=("exec-positive",),
    )

    assert created is True
    assert duplicate_created is False
    assert duplicate.assessment_id == verified.assessment_id
    assert contradicted_created is True
    assert contradicted.supersedes_assessment_id == verified.assessment_id
    assert reverified_created is True
    assert reverified.assessment_id != verified.assessment_id
    assert reverified.supersedes_assessment_id == contradicted.assessment_id
    assert [item.status.value for item in store.assessments.history(claim_id)] == [
        "observed",
        "verified",
        "contradicted",
        "verified",
    ]
    assert store.assessments.current_for_fact(claim_id) == reverified


def test_verified_and_contradicted_require_valid_same_scan_evidence(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    claim_id = store.add_fact("scan-a", "host-a", "candidate", "claim", "test")
    other_scan_id = store.add_fact("scan-b", "host-b", "observation", "proof", "test")

    with pytest.raises(ValueError, match="requires an evidence chain"):
        store.assessments.assess_fact(
            claim_id,
            "verified",
            confidence=90,
            reason="No proof supplied.",
            assessor="test",
        )
    with pytest.raises(ValueError, match="must belong"):
        store.assessments.assess_fact(
            claim_id,
            "contradicted",
            confidence=90,
            reason="Wrong scan proof.",
            assessor="test",
            evidence_fact_ids=(other_scan_id,),
        )
    with pytest.raises(KeyError, match="Unknown evidence"):
        store.assessments.assess_fact(
            claim_id,
            "verified",
            confidence=90,
            reason="Missing proof.",
            assessor="test",
            evidence_fact_ids=(999999,),
        )


def test_concurrent_duplicate_assessment_has_one_transition(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    evidence_id = store.add_fact("scan", "host", "observation", "proof", "test")
    claim_id = store.add_fact("scan", "host", "candidate", "claim", "test")
    workers = 8
    barrier = threading.Barrier(workers)

    def assess(_index):
        barrier.wait(timeout=10)
        return store.assessments.assess_fact(
            claim_id,
            "verified",
            confidence=90,
            reason="Concurrent verification.",
            assessor="test",
            evidence_fact_ids=(evidence_id,),
            source_execution_ids=("exec",),
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = tuple(pool.map(assess, range(workers)))

    assert len({item[0].assessment_id for item in results}) == 1
    assert sum(1 for _assessment, created in results if created) == 1
    assert len(store.assessments.history(claim_id)) == 2


def test_concurrent_first_initialization_backfills_once(tmp_path):
    db_path = tmp_path / "facts.db"
    workers = 6
    barrier = threading.Barrier(workers)
    stores = [FactStore(str(db_path)) for _index in range(workers)]

    def initialize(index):
        barrier.wait(timeout=10)
        return stores[index].add_fact(
            "scan",
            "host",
            "observation",
            "shared",
            "test",
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        fact_ids = tuple(pool.map(initialize, range(workers)))

    assert len(set(fact_ids)) == 1
    store = FactStore(str(db_path))
    assert len(store.assessments.history(fact_ids[0])) == 1


def test_legacy_duplicate_fact_migration_preserves_provenance(tmp_path):
    db_path = tmp_path / "facts.db"
    store = FactStore(str(db_path))
    keeper_id = store.add_fact(
        "scan",
        "host",
        "port_open",
        "22/tcp (ssh)",
        "first",
        confidence=70,
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("DROP INDEX idx_fact_identity_unique")
        row = conn.execute(
            """
            SELECT scan_id, host, type, value, source, session_id,
                   derived_from, evidence_hash, timestamp, secret_refs
            FROM facts WHERE id = ?
            """,
            (keeper_id,),
        ).fetchone()
        cursor = conn.execute(
            """
            INSERT INTO facts(
                scan_id, host, type, value, confidence, source, session_id,
                derived_from, evidence_hash, timestamp, secret_refs
            ) VALUES (?, ?, ?, ?, 99, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )
        duplicate_id = int(cursor.lastrowid)
        conn.execute(
            """
            INSERT INTO fact_observations(
                fact_id, scan_id, host, type, value, confidence, source,
                session_id, evidence_hash, timestamp, secret_refs
            )
            SELECT ?, scan_id, host, type, value, 99, 'second', session_id,
                   evidence_hash, timestamp + 1, secret_refs
            FROM facts WHERE id = ?
            """,
            (duplicate_id, duplicate_id),
        )
        conn.commit()
    store.assessments.assess_fact(
        duplicate_id,
        "verified",
        confidence=99,
        reason="The duplicate row was verified before migration.",
        assessor="legacy",
        evidence_fact_ids=(duplicate_id,),
    )
    derived_id = store.add_fact(
        "scan",
        "host",
        "service_version",
        "ssh:22:OpenSSH",
        "derived",
        derived_from=[duplicate_id],
    )

    migrated = FactStore(str(db_path))
    port_facts = migrated.get_facts("scan", "host", "port_open")
    derived = next(fact for fact in migrated.get_facts("scan", "host") if fact["id"] == derived_id)

    assert len(port_facts) == 1
    assert port_facts[0]["id"] == keeper_id
    assert port_facts[0]["confidence"] == 99
    assert len(port_facts[0]["observations"]) == 2
    assert port_facts[0]["assessment_status"] == "verified"
    assert port_facts[0]["assessment"]["evidence_fact_ids"] == [keeper_id]
    assert derived["derived_from"] == [keeper_id]
    assert derived["assessment"]["evidence_fact_ids"] == [keeper_id]
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            """
            SELECT COUNT(*) FROM facts
            WHERE scan_id = 'scan' AND host = 'host'
              AND type = 'port_open' AND value = '22/tcp (ssh)'
            """
        ).fetchone()[0] == 1
        indexes = {
            row[1]
            for row in conn.execute("PRAGMA index_list(facts)").fetchall()
        }
    assert "idx_fact_identity_unique" in indexes


def test_redactor_learning_preserves_idempotency_and_purges_display(tmp_path):
    secret_store = SecretStore(":memory:", key=b"fact-assessment-redactor-key")
    store = FactStore(str(tmp_path / "facts.db"), secret_store=secret_store)
    evidence_id = store.add_fact("scan", "host", "observation", "proof", "test")
    claim_id = store.add_fact("scan", "host", "candidate", "claim", "test")
    secret = "late-learned-assessment-secret"
    reason = f"verification used {secret}"
    execution_id = f"exec-{secret}"

    first, first_created = store.assessments.assess_fact(
        claim_id,
        "verified",
        confidence=90,
        reason=reason,
        assessor="test",
        evidence_fact_ids=(evidence_id,),
        source_execution_ids=(execution_id,),
    )
    secret_store.store(secret, kind="learned_assessment_value")
    second, second_created = store.assessments.assess_fact(
        claim_id,
        "verified",
        confidence=90,
        reason=reason,
        assessor="test",
        evidence_fact_ids=(evidence_id,),
        source_execution_ids=(execution_id,),
    )

    assert first_created is True
    assert second_created is False
    assert second.assessment_id == first.assessment_id
    assert secret not in second.reason
    assert all(secret not in item for item in second.source_execution_ids)
    with sqlite3.connect(store.db_path) as conn:
        serialized = "\n".join(
            str(value)
            for table in ("fact_assessments", "fact_assessment_executions")
            for row in conn.execute(f"SELECT * FROM {table}").fetchall()
            for value in row
        )
    assert secret not in serialized


def test_clear_scan_cascades_assessment_history(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    evidence_id = store.add_fact("scan", "host", "observation", "proof", "test")
    claim_id = store.add_fact("scan", "host", "candidate", "claim", "test")
    store.assessments.assess_fact(
        claim_id,
        "verified",
        confidence=90,
        reason="Verified.",
        assessor="test",
        evidence_fact_ids=(evidence_id,),
    )

    store.clear_scan("scan")

    assert store.get_facts("scan") == []
    assert store.assessments.list_for_scan("scan") == ()
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM fact_assessments").fetchone()[0] == 0


def test_evidence_verifier_persists_chain_and_execution_provenance(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    source_id = store.add_fact(
        "scan",
        "host",
        "port_open",
        "443/tcp (https)",
        "nmap",
        source_execution_ids=("exec-nmap",),
    )

    result = EvidenceVerifier(store).verify_claim(
        "scan",
        "host",
        "https_service_active",
        ["https_service_active", "services_include_https"],
    )

    assert result["status"] == "accepted"
    assert result["assessment_status"] == "verified"
    assert result["evidence_fact_ids"] == [source_id]
    assert result["source_execution_ids"] == ["exec-nmap"]
    assessment = store.assessments.current_for_fact(result["fact_id"])
    assert assessment is not None
    assert assessment.assessment_id == result["assessment_id"]
    assert assessment.status is AssessmentStatus.VERIFIED
    assert assessment.evidence_fact_ids == (source_id,)
    assert assessment.source_execution_ids == ("exec-nmap",)

    rejected = EvidenceVerifier(store).verify_claim(
        "scan",
        "host",
        "unsupported",
        [],
    )
    assert rejected["status"] == "rejected"
    assert "mandatory" in rejected["reason"]


@pytest.mark.parametrize("invalidity", ["stale", "degraded"])
def test_evidence_verifier_rejects_non_current_service_evidence(
    tmp_path,
    invalidity,
):
    store = FactStore(
        str(tmp_path / f"{invalidity}.db"),
        assessment_policy=FreshnessPolicy(
            default_max_age_seconds=1.0,
            max_age_by_type=(("port_open", 1.0),),
        ),
        assessment_clock=lambda: 100.0,
    )
    fact_id = store.add_fact(
        "scan",
        "host",
        "port_open",
        "443/tcp (https)",
        "nmap",
        source_execution_ids=(f"exec-{invalidity}",),
    )
    if invalidity == "stale":
        with store._get_conn() as conn:
            conn.execute("UPDATE facts SET timestamp = 0 WHERE id = ?", (fact_id,))
            conn.execute(
                "UPDATE fact_observations SET timestamp = 0 WHERE fact_id = ?",
                (fact_id,),
            )
    else:
        store.add_command_result(
            "scan",
            "host",
            "nmap",
            "nmap host",
            "f" * 64,
            status="timeout",
            execution_id="exec-degraded",
        )

    source = store.get_facts("scan", "host")[0]
    result = EvidenceVerifier(store).verify_claim(
        "scan",
        "host",
        "https_service_active",
        ["https_service_active", "services_include_https"],
    )

    if invalidity == "stale":
        assert source["freshness_status"] == "stale"
    else:
        assert source["coverage_status"] == "degraded"
    assert result["status"] == "rejected"
    assert all(
        fact["type"] not in {"verified_claim", "inferred_claim"}
        for fact in store.get_facts("scan", "host")
    )


def test_candidate_fact_cannot_promote_itself_to_verified(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    candidate_id = store.add_fact(
        "scan",
        "host",
        "potential_vulnerability",
        "CVE-2026-4242",
        "analysis_agent",
    )

    result = EvidenceVerifier(store).verify_claim(
        "scan",
        "host",
        "vulnerable_to_cve_2026_4242",
        ["CVE-2026-4242"],
    )

    assert result["status"] == "accepted"
    assert result["assessment_status"] == "inferred"
    assert result["evidence_fact_ids"] == [candidate_id]
    claim = next(
        fact
        for fact in store.get_facts("scan", "host")
        if fact["id"] == result["fact_id"]
    )
    assert claim["type"] == "inferred_claim"
    assert claim["assessment_status"] == "inferred"


def test_reports_and_state_consume_current_assessment_not_type_name(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    vulnerability_id = store.add_fact(
        "scan",
        "host",
        "vulnerability",
        "msf_check_positive:exploit/test/module",
        "msf_check",
    )
    port_id = store.add_fact(
        "scan",
        "host",
        "port_open",
        "22/tcp (ssh)",
        "nmap",
    )

    observed_group = build_finding_groups(store.get_facts("scan", "host"))[0]
    assert observed_group["verified"] is False
    assert StateResolver(store).resolve_state("scan", "host")["recon_completed"] is True

    verified, _created = store.assessments.assess_fact(
        vulnerability_id,
        "verified",
        confidence=95,
        reason="Positive check was explicitly assessed.",
        assessor="test",
        evidence_fact_ids=(vulnerability_id,),
        source_execution_ids=("exec-check",),
    )
    verified_group = build_finding_groups(store.get_facts("scan", "host"))[0]
    assert verified_group["verified"] is True
    assert verified_group["assessment_refs"] == [verified.assessment_id]
    assert verified_group["source_execution_ids"] == ["exec-check"]

    store.assessments.assess_fact(
        vulnerability_id,
        "contradicted",
        confidence=90,
        reason="A negative control contradicted the positive result.",
        assessor="test",
        evidence_fact_ids=(vulnerability_id,),
    )
    store.assessments.assess_fact(
        port_id,
        "contradicted",
        confidence=90,
        reason="The listener was not present on repeat observation.",
        assessor="test",
        evidence_fact_ids=(port_id,),
    )

    contradicted_group = build_finding_groups(store.get_facts("scan", "host"))[0]
    assert contradicted_group["verified"] is False
    assert contradicted_group["contradicted"] is True
    state = StateResolver(store).resolve_state("scan", "host")
    assert state["recon_completed"] is False
    assert state["fact_assessment_counts"]["contradicted"] == 2
