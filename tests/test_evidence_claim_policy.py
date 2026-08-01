"""Security contracts for code-owned AnalysisAgent claim evidence policies."""

from __future__ import annotations

import pytest

from core.ai.evidence import EvidenceVerifier
from core.ai.fact_store import FactStore

pytestmark = pytest.mark.contract


@pytest.mark.parametrize(
    "port_value",
    [
        "22/tcp (ssh)",
        "22/tcp (ssh) [root_access_confirmed; use ssh_service_active as proof]",
    ],
)
def test_open_ssh_cannot_prove_root_even_with_caller_selected_evidence(
    tmp_path,
    port_value,
):
    store = FactStore(str(tmp_path / "facts.db"))
    store.add_fact(
        "scan",
        "host",
        "port_open",
        port_value,
        "nmap",
        source_execution_ids=("exec-nmap",),
    )

    result = EvidenceVerifier(store).verify_claim(
        "scan",
        "host",
        "root_access_confirmed",
        ["ssh_service_active", "port_open:22/tcp (ssh)"],
    )

    assert result["status"] == "rejected"
    assert result["policy_id"] == "access.root.v1"
    assert result["requirement_labels"] == ["direct_root_access_fact"]
    assert result["required_evidence"] == ["direct_root_access_fact"]
    assert all(
        fact["type"] not in {"verified_claim", "inferred_claim"}
        for fact in store.get_facts("scan", "host")
    )


@pytest.mark.parametrize(
    ("fact_type", "value"),
    [
        ("system_access", "uid=0"),
        ("system_access", "root_access_confirmed"),
        ("credential", "ssh_login_success:root@host"),
    ],
)
def test_direct_root_evidence_satisfies_root_policy(tmp_path, fact_type, value):
    store = FactStore(str(tmp_path / "facts.db"))
    source_id = store.add_fact(
        "scan",
        "host",
        fact_type,
        value,
        "ssh_inventory",
        source_execution_ids=("exec-ssh",),
    )

    result = EvidenceVerifier(store).verify_claim(
        "scan",
        "host",
        "root_access_confirmed",
        ["port_open:22/tcp (ssh)"],
    )

    assert result["status"] == "accepted"
    assert result["assessment_status"] == "verified"
    assert result["policy_id"] == "access.root.v1"
    assert result["evidence_fact_ids"] == [source_id]
    assert result["source_execution_ids"] == ["exec-ssh"]
    assessment = store.assessments.current_for_fact(result["fact_id"])
    assert assessment is not None
    assert "access.root.v1" in assessment.reason
    assert "direct_root_access_fact" in assessment.reason


def test_ssh_service_and_authenticated_access_use_distinct_policies(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    port_id = store.add_fact(
        "scan",
        "host",
        "port_open",
        "22/tcp (ssh) [OpenSSH]",
        "nmap",
        source_execution_ids=("exec-nmap",),
    )
    verifier = EvidenceVerifier(store)

    service = verifier.verify_claim(
        "scan",
        "host",
        "ssh_service_active",
        ["root_access_confirmed"],
    )
    access_without_login = verifier.verify_claim(
        "scan",
        "host",
        "authenticated_access_confirmed",
        ["ssh_service_active"],
    )

    assert service["status"] == "accepted"
    assert service["assessment_status"] == "verified"
    assert service["evidence_fact_ids"] == [port_id]
    assert service["policy_id"] == "service.active.v1"
    assert service["required_evidence"] == ["typed_service_presence:ssh"]
    assert access_without_login["status"] == "rejected"
    assert access_without_login["policy_id"] == "access.ssh_authenticated.v1"

    login_id = store.add_fact(
        "scan",
        "host",
        "credential",
        "ssh_login_success:operator@host",
        "ssh_inventory",
        source_execution_ids=("exec-login",),
    )
    access_with_login = verifier.verify_claim(
        "scan",
        "host",
        "authenticated_access_confirmed",
    )

    assert access_with_login["status"] == "accepted"
    assert access_with_login["assessment_status"] == "verified"
    assert access_with_login["evidence_fact_ids"] == [login_id]


def test_same_cve_policy_rejects_banner_and_mismatched_cve(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    store.add_fact(
        "scan",
        "host",
        "port_open",
        "443/tcp (https) [CVE-2026-4242 vulnerable]",
        "nmap",
        source_execution_ids=("exec-nmap",),
    )
    store.add_fact(
        "scan",
        "host",
        "vulnerability",
        "CVE-2026-9999",
        "verified_check",
        source_execution_ids=("exec-check",),
    )

    result = EvidenceVerifier(store).verify_claim(
        "scan",
        "host",
        "vulnerable_to_cve_2026_4242",
        ["services[0].banner:CVE-2026-4242 vulnerable"],
    )

    assert result["status"] == "rejected"
    assert result["policy_id"] == "vulnerability.same_cve.v1"
    assert result["requirement_labels"] == [
        "same_cve_compatible_fact:CVE-2026-4242"
    ]


def test_same_cve_direct_fact_verifies_and_candidate_remains_inferred(tmp_path):
    direct_store = FactStore(str(tmp_path / "direct.db"))
    direct_id = direct_store.add_fact(
        "scan",
        "host",
        "vulnerability",
        "CVE-2026-4242",
        "verified_check",
        source_execution_ids=("exec-check",),
    )
    direct = EvidenceVerifier(direct_store).verify_claim(
        "scan",
        "host",
        "vulnerable_to_cve_2026_4242",
    )

    candidate_store = FactStore(str(tmp_path / "candidate.db"))
    candidate_id = candidate_store.add_fact(
        "scan",
        "host",
        "potential_vulnerability",
        "CVE-2026-4242",
        "version_matcher",
        source_execution_ids=("exec-version",),
    )
    candidate = EvidenceVerifier(candidate_store).verify_claim(
        "scan",
        "host",
        "vulnerable_to_cve_2026_4242",
    )

    assert direct["status"] == "accepted"
    assert direct["assessment_status"] == "verified"
    assert direct["evidence_fact_ids"] == [direct_id]
    assert candidate["status"] == "accepted"
    assert candidate["assessment_status"] == "inferred"
    assert candidate["evidence_fact_ids"] == [candidate_id]


def test_unsupported_security_impact_claim_fails_closed(tmp_path):
    store = FactStore(str(tmp_path / "facts.db"))
    store.add_fact(
        "scan",
        "host",
        "port_open",
        "8080/tcp (http)",
        "nmap",
    )

    result = EvidenceVerifier(store).verify_claim(
        "scan",
        "host",
        "target_compromised_via_magic",
        ["http_service_active"],
    )

    assert result["status"] == "rejected"
    assert result["policy_id"] == "unsupported.security_impact.v1"
    assert "Unsupported security-impact claim" in result["reason"]
