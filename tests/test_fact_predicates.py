"""Exact predicate and observation-trust contracts."""

from __future__ import annotations

import pytest

from core.ai.fact_predicates import (
    TARGET_CONTROLLED,
    TRUSTED,
    UNTRUSTED,
    aggregate_observation_trust,
    canonical_trust_level,
    confirms_cleanup,
    confirms_credentials,
    confirms_exfiltration,
    confirms_persistence,
    confirms_root,
    confirms_system_access_exploit,
    fact_is_decision_critical,
    fact_trust_level,
    is_vulnerability_fact,
    parse_port_open,
    web_fact_port,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("value", "method", "default", "expected"),
    [
        ("verified", "", TRUSTED, TRUSTED),
        ("unknown-label", "", TRUSTED, UNTRUSTED),
        (None, "target-controlled-stdout", TRUSTED, TARGET_CONTROLLED),
        (None, "untrusted-stdout", TRUSTED, UNTRUSTED),
        (None, "llm-extracted", TRUSTED, UNTRUSTED),
        (None, "tcp-connect", TRUSTED, TRUSTED),
        (None, "tcp-connect", "invalid-default", UNTRUSTED),
    ],
)
def test_canonical_trust_level_is_closed_set(
    value: object,
    method: str,
    default: str,
    expected: str,
) -> None:
    assert (
        canonical_trust_level(
            value,
            observation_method=method,
            default=default,
        )
        == expected
    )


def test_observation_trust_aggregation_boundaries() -> None:
    assert aggregate_observation_trust([]) == TRUSTED
    assert aggregate_observation_trust(["ignored"], default=UNTRUSTED) == UNTRUSTED
    assert aggregate_observation_trust([{"trust_level": UNTRUSTED}]) == UNTRUSTED
    assert (
        aggregate_observation_trust(
            [
                {"trust_level": UNTRUSTED},
                {"trust_level": TARGET_CONTROLLED},
            ]
        )
        == TARGET_CONTROLLED
    )
    assert fact_trust_level({"trust_level": "authoritative"}) == TRUSTED


@pytest.mark.parametrize(
    ("fact", "port", "protocol", "service", "is_web", "is_ssh"),
    [
        (
            {"type": "port_open", "value": "host:53/udp (dns) [banner]"},
            53,
            "udp",
            "dns",
            False,
            False,
        ),
        (
            {"type": "port_open", "value": "1234/tcp http"},
            1234,
            "tcp",
            "http",
            True,
            False,
        ),
        (
            {"type": "port_open", "value": "2222/tcp ssh"},
            2222,
            "tcp",
            "ssh",
            False,
            True,
        ),
        (
            {"type": "port_open", "value": "80/tcp"},
            80,
            "tcp",
            "",
            True,
            False,
        ),
    ],
)
def test_port_open_full_parser(
    fact: dict[str, str],
    port: int,
    protocol: str,
    service: str,
    is_web: bool,
    is_ssh: bool,
) -> None:
    parsed = parse_port_open(fact)

    assert parsed is not None
    assert (parsed.port, parsed.protocol, parsed.service) == (port, protocol, service)
    assert parsed.is_web is is_web
    assert parsed.is_ssh is is_ssh


@pytest.mark.parametrize(
    "fact",
    [
        {"type": "service", "value": "22/tcp (ssh)"},
        {"type": "port_open", "value": "not-a-port"},
        {"type": "port_open", "value": "0/tcp"},
        {"type": "port_open", "value": "65536/tcp"},
    ],
)
def test_port_open_rejects_wrong_type_or_non_full_match(fact: dict[str, str]) -> None:
    assert parse_port_open(fact) is None


@pytest.mark.parametrize(
    ("fact", "expected"),
    [
        ({"type": "service", "value": "https://host"}, None),
        ({"type": "web_endpoint", "value": ""}, None),
        ({"type": "web_endpoint", "value": "https://host:bad/"}, None),
        ({"type": "web_endpoint", "value": "ftp://host/path"}, None),
        ({"type": "web_endpoint", "value": "https:///path"}, None),
        (
            {"type": "web_endpoint", "value": '{"url": ["bad"], "port": "bad"}'},
            None,
        ),
        (
            {"type": "web_endpoint", "value": '{"url": "http://host/", "port": 0}'},
            "80/tcp (http)",
        ),
        (
            {"type": "web_endpoint", "value": '{"scheme": "https", "port": 8443}'},
            "8443/tcp (https)",
        ),
        (
            {"type": "web_endpoint", "value": '{"scheme": "http", "port": 8080}'},
            "8080/tcp (http)",
        ),
        (
            {"type": "web_endpoint", "value": '{"scheme": "custom", "port": 9001}'},
            "9001/tcp",
        ),
        (
            {"type": "web_endpoint", "value": '{"url": "https://host/path"}'},
            "443/tcp (https)",
        ),
    ],
)
def test_web_fact_port_parses_only_valid_urls_and_ports(
    fact: dict[str, str],
    expected: str | None,
) -> None:
    parsed = web_fact_port(fact)
    assert (parsed.rendered if parsed is not None else None) == expected


@pytest.mark.parametrize(
    ("predicate", "fact", "expected"),
    [
        (is_vulnerability_fact, {"type": "vulnerability", "value": "CVE-1"}, True),
        (is_vulnerability_fact, {"type": "not_vulnerable", "value": "CVE-1"}, False),
        (confirms_credentials, {"type": "credential", "value": "user:secret"}, True),
        (confirms_credentials, {"type": "credential", "value": ""}, False),
        (confirms_credentials, {"type": "noncredential", "value": "user:secret"}, False),
        (confirms_root, {"type": "system_access", "value": "uid=0"}, True),
        (confirms_root, {"type": "system_access", "value": "not uid=0"}, False),
        (
            confirms_root,
            {"type": "credential", "value": "ssh_login_success:root@host"},
            True,
        ),
        (confirms_root, {"type": "credential", "value": "root@host"}, False),
        (confirms_persistence, {"type": "persistence", "value": "ssh_key_injected"}, True),
        (confirms_persistence, {"type": "persistence", "value": "absent"}, False),
        (confirms_persistence, {"type": "note", "value": "ssh_key_injected"}, False),
        (confirms_cleanup, {"type": "cleanup_action", "value": "completed"}, True),
        (confirms_cleanup, {"type": "cleanup_action", "value": "failed"}, False),
        (confirms_cleanup, {"type": "cleanup_hint", "value": "completed"}, False),
        (
            confirms_exfiltration,
            {"type": "data_exfiltration", "value": "files_exfiltrated:0"},
            False,
        ),
    ],
)
def test_exact_fact_predicates(predicate, fact, expected: bool) -> None:
    assert predicate(fact) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CVE-2021-4034 PwnKit root access", True),
        ("Dirty Pipe local privilege escalation", True),
        ("not Dirty Pipe local privilege escalation", False),
        (None, False),
    ],
)
def test_system_access_exploit_is_a_full_match(value: object, expected: bool) -> None:
    assert confirms_system_access_exploit(value) is expected


@pytest.mark.parametrize(
    ("fact", "expected"),
    [
        ({"type": "application_access", "value": "authenticated"}, True),
        ({"type": "port_open", "value": "443/tcp"}, True),
        ({"type": "web_title", "value": "Title"}, True),
        ({"type": "vulnerability", "value": "CVE-1"}, True),
        ({"type": "credential", "value": "user:secret"}, True),
        ({"type": "system_access", "value": "uid=0"}, True),
        ({"type": "persistence", "value": "mechanism_planted"}, True),
        ({"type": "data_exfiltration", "value": "completed"}, True),
        ({"type": "cleanup_action", "value": "success"}, True),
        ({"type": "internal_network", "value": "hosts_discovered:1"}, True),
        (
            {"type": "post_exploit_stage", "value": "post_access_inventory_completed"},
            True,
        ),
        ({"type": "post_exploit_stage", "value": "other"}, False),
        ({"type": "service_status", "value": "ssh_authenticated"}, True),
        ({"type": "service_status", "value": "unknown"}, True),
        ({"type": "observation", "value": "uid=0"}, False),
    ],
)
def test_decision_critical_uses_exact_typed_predicates(
    fact: dict[str, str],
    expected: bool,
) -> None:
    assert fact_is_decision_critical(fact) is expected
