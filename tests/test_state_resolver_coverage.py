"""Focused branch coverage for state inference edge cases."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

import pytest

from core.ai.state_resolver import StateResolver

pytestmark = pytest.mark.unit


class SnapshotStub:
    def __init__(
        self,
        facts: Iterable[dict[str, Any]],
        *,
        historical: Iterable[dict[str, Any]] | None = None,
        scope: tuple[str, ...] = ("example.test",),
    ) -> None:
        self._facts = tuple(facts)
        self._historical = tuple(historical) if historical is not None else self._facts
        self.canonical_scope = scope

    def historical_facts(self) -> tuple[dict[str, Any], ...]:
        return self._historical

    def decision_facts(self) -> tuple[dict[str, Any], ...]:
        return self._facts


class FactStoreStub:
    def __init__(self, facts: Iterable[dict[str, Any]]) -> None:
        self.facts = list(facts)
        self.calls: list[tuple[str, str]] = []

    def get_facts(self, scan_id: str, host: str) -> list[dict[str, Any]]:
        self.calls.append((scan_id, host))
        return list(self.facts)


def test_resolve_snapshot_handles_browser_and_verified_attack_stage_evidence() -> None:
    facts = [
        {"type": "port_open", "value": "443/tcp (https)", "session_id": "web"},
        {"type": "port_open", "value": "22/tcp (ssh)", "session_id": "chain"},
        {"type": "browser_rendered", "value": "https://example.test/home", "session_id": "web"},
        {"type": "browser_rendered", "value": "http://example.test/home", "session_id": "web"},
        {"type": "browser_rendered", "value": "render_complete", "session_id": "web"},
        {"type": "web_title", "value": "Example", "session_id": "web"},
        {
            "type": "vulnerability",
            "value": "CVE-2099-0001",
            "assessment_status": "verified",
            "session_id": "chain",
        },
        {
            "type": "credential",
            "value": "ssh_login_success:operator@example.test",
            "session_id": "chain",
        },
        {
            "type": "credential",
            "value": "ssh_login_success:root@example.test",
            "session_id": "root-login",
        },
        {"type": "exploit_success", "value": "pwnkit root shell", "session_id": "chain"},
        {"type": "system_access", "value": "uid=0", "session_id": "chain"},
        {
            "type": "post_exploit_stage",
            "value": "post_access_inventory_completed",
            "session_id": "chain",
        },
        {"type": "persistence", "value": "mechanism_planted", "session_id": "chain"},
        {"type": "internal_network", "value": "hosts_discovered:2", "session_id": "chain"},
        {
            "type": "service_status",
            "value": "network_recon_completed",
            "session_id": "chain",
        },
        {
            "type": "post_exploit_stage",
            "value": "internal_network_recon_completed",
            "session_id": "chain",
        },
        {
            "type": "post_exploit_stage",
            "value": "data_exfiltration_completed",
            "session_id": "chain",
        },
        {"type": "cleanup_action", "value": "success", "session_id": "chain"},
    ]

    state = StateResolver(None).resolve_snapshot(SnapshotStub(facts))

    assert state["target"] == "example.test"
    assert state["open_ports"] == ["22/tcp (ssh)", "443/tcp (https)", "80/tcp (http)"]
    assert state["recon_completed"] is True
    assert state["web_services_found"] is True
    assert state["vulnerabilities_found"] is True
    assert state["verified_vulnerabilities_found"] is True
    assert state["credentials_found"] is True
    assert state["root_access_confirmed"] is True
    assert state["post_access_inventory_completed"] is True
    assert state["persistence_established"] is True
    assert state["internal_recon_completed"] is True
    assert state["exfiltration_completed"] is True
    assert state["cleanup_completed"] is True


def test_resolve_snapshot_infers_default_port_for_non_browser_web_fact() -> None:
    snapshot = SnapshotStub(
        [{"type": "web_endpoint", "value": "https://example.test/login"}],
        scope=(),
    )

    state = StateResolver(None).resolve_snapshot(snapshot)

    assert state["target"] == ""
    assert state["recon_completed"] is True
    assert state["web_services_found"] is True
    assert state["open_ports"] == ["443/tcp (https)"]


def test_port_classification_uses_exact_parsed_port_and_service() -> None:
    state = StateResolver(None).resolve_snapshot(
        SnapshotStub(
            [
                {"type": "port_open", "value": "8222/tcp (unknown)"},
                {"type": "port_open", "value": "1800/tcp (unknown)"},
            ]
        )
    )

    assert state["recon_completed"] is True
    assert state["open_ports"] == ["1800/tcp (unknown)", "8222/tcp (unknown)"]
    assert state["ssh_service_found"] is False
    assert state["web_services_found"] is False


def test_explicit_https_alt_port_never_synthesizes_port_80() -> None:
    state = StateResolver(None).resolve_snapshot(
        SnapshotStub([{"type": "web_endpoint", "value": "https://example.test:8443/login"}])
    )

    assert state["web_services_found"] is True
    assert state["open_ports"] == ["8443/tcp (https)"]


def test_adversarial_substrings_do_not_advance_state() -> None:
    facts = [
        {"type": "observation", "value": "notice: not uid=0"},
        {"type": "noncredential", "value": "ssh_login_success:root@example.test"},
        {"type": "not_vulnerable", "value": "CVE-2099-0001 is absent"},
        {"type": "persistence_warning", "value": "mechanism_planted: absent"},
        {"type": "cleanup_hint", "value": "completed"},
    ]

    state = StateResolver(None).resolve_snapshot(SnapshotStub(facts))

    assert state["root_access_confirmed"] is False
    assert state["credentials_found"] is False
    assert state["vulnerabilities_found"] is False
    assert state["persistence_established"] is False
    assert state["cleanup_completed"] is False


@pytest.mark.parametrize(
    ("fact_type", "fact_value"),
    [
        ("system_access", "not uid=0"),
        ("system_access", "uid=0 denied"),
        ("credential", "ssh_login_success:root@example.test denied"),
    ],
)
def test_negated_or_extended_root_text_is_not_root(
    fact_type: str,
    fact_value: str,
) -> None:
    state = StateResolver(None).resolve_snapshot(SnapshotStub([{"type": fact_type, "value": fact_value}]))

    assert state["root_access_confirmed"] is False


def test_negated_system_exploit_text_does_not_correlate_to_root() -> None:
    state = StateResolver(None).resolve_snapshot(
        SnapshotStub(
            [
                {
                    "type": "credential",
                    "value": "ssh_login_success:operator@example.test",
                    "session_id": "chain",
                },
                {
                    "type": "exploit_success",
                    "value": "not pwnkit root shell",
                    "session_id": "chain",
                },
            ]
        )
    )

    assert state["credentials_found"] is True
    assert state["root_access_confirmed"] is False


@pytest.mark.parametrize(
    ("fact_type", "fact_value", "expected"),
    [
        ("post_exploit_stage", "data_exfiltration_completed", True),
        ("post_exploit_stage", "other_stage", False),
        ("data_exfiltration", "completed", True),
        ("data_exfiltration_status", "files_exfiltrated:2", True),
        ("data_exfiltration", "files_exfiltrated:not-a-number", False),
        ("data_exfiltration", "completed:archive.tar", True),
        ("artifact", "loot_collected", False),
    ],
)
def test_exfil_completion_variants(fact_type: str, fact_value: str, expected: bool) -> None:
    assert StateResolver(None)._is_exfil_completion(fact_type, fact_value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("cPanel root shell", False),
        ("ordinary application exploit", False),
        ("Dirty Pipe local privilege escalation", True),
    ],
)
def test_system_access_exploit_classification(value: str, expected: bool) -> None:
    assert StateResolver(None)._is_system_access_exploit(value) is expected


def test_get_state_for_llm_builds_snapshot_from_store() -> None:
    store = FactStoreStub([])
    resolver = StateResolver(store)

    serialized = resolver.get_state_for_llm("scan-empty", "EXAMPLE.TEST")
    state = json.loads(serialized)

    assert store.calls == [("scan-empty", "EXAMPLE.TEST")]
    assert serialized.startswith("{\n  ")
    assert state["target"] == "example.test"
    assert state["recon_completed"] is False
    assert state["fact_assessment_counts"] == {
        "observed": 0,
        "inferred": 0,
        "verified": 0,
        "contradicted": 0,
    }
