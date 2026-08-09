"""Complete behavioral coverage for legacy knowledge enrichment helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.credential_ranking import (
    KEY_AUTH_MARKER,
    best_credential,
    credential_rank_key,
    rank_credentials,
)
from core.knowledge.enricher import KnowledgeEnricher
from core.knowledge.models import EdgeType

pytestmark = pytest.mark.unit


class RecordingGraph:
    """Small graph boundary fake that preserves every enrichment argument."""

    def __init__(self, *, fail_service: bool = False) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []
        self.fail_service = fail_service

    def _record(self, name: str, args: tuple, kwargs: dict) -> None:
        self.calls.append((name, args, kwargs))

    def add_asset(self, target: str, **kwargs):
        self._record("add_asset", (target,), kwargs)
        return SimpleNamespace(node_id=f"asset:{target}")

    def add_service(self, target: str, port: int, **kwargs):
        self._record("add_service", (target, port), kwargs)
        if self.fail_service:
            raise RuntimeError("synthetic graph failure")
        return SimpleNamespace(node_id=f"svc:{target}:{port}")

    def add_credential(self, user: str, secret: str, **kwargs):
        self._record("add_credential", (user, secret), kwargs)
        return SimpleNamespace(node_id=f"credential:{user}")

    def link_credential_to_asset(self, *args, **kwargs):
        self._record("link_credential_to_asset", args, kwargs)

    def add_identity(self, username: str, **kwargs):
        self._record("add_identity", (username,), kwargs)
        return SimpleNamespace(node_id=f"identity:{username}")

    def add_vulnerability(self, vulnerability_id: str, **kwargs):
        self._record("add_vulnerability", (vulnerability_id,), kwargs)
        return SimpleNamespace(node_id=f"vulnerability:{vulnerability_id}")

    def link(self, *args, **kwargs):
        self._record("link", args, kwargs)


def _calls(graph: RecordingGraph, name: str):
    return [call for call in graph.calls if call[0] == name]


def test_enricher_routes_every_supported_fact_to_typed_graph_operations() -> None:
    graph = RecordingGraph()
    enricher = KnowledgeEnricher(graph)
    facts = [
        ("Port 22 OPEN (ssh)", "nmap"),
        ("Port 53 FILTERED (dns)", "nmap"),
        ("Port 25 CLOSED (smtp)", "nmap"),
        ("Port 22 version: OpenSSH 9.0", "nmap"),
        ("CREDENTIALS FOUND: ssh://admin:secret on port 22", "ssh"),
        ("SSH valid user confirmed: 'deploy'", "ssh-enum"),
        ("System user found: 'service' (UID 1001)", "passwd"),
        ("System login user: 'operator' (shell: /bin/bash)", "passwd"),
        ("TARGET IS ROOTED", "privesc"),
        ("NOPASSWD sudo: /usr/bin/find", "sudo"),
        ("Exploitable SUID binary: /usr/bin/find", "suid"),
        ("INTERNAL IP: 10.0.1.7", "route"),
        ("Cockpit web console detected", "http"),
        ("DB PASSWORD FOUND: database-secret", "mysql"),
        ("DB USER FOUND: reporting", "mysql"),
        ("SECRET KEY FOUND: api-secret", "secrets"),
        ("LATERAL: Compromised alice@10.0.2.8", "lateral"),
        ("PERSISTENCE: service installed", "persistence"),
        ("KILL CHAIN: exploitation complete", "pipeline"),
        ("HTTP header: Server: nginx/1.25", "curl"),
        ("HTTP header: X-Frame-Options: DENY", "curl"),
        ("unrecognized evidence", "fixture"),
    ]

    enricher.enrich_from_facts("10.0.0.5", facts)

    services = _calls(graph, "add_service")
    assert ("add_service", ("10.0.0.5", 22), {"service_name": "ssh"}) in services
    assert ("add_service", ("10.0.0.5", 53), {"service_name": "dns", "state": "filtered"}) in services
    assert ("add_service", ("10.0.0.5", 25), {"service_name": "smtp", "state": "closed"}) in services
    assert ("add_service", ("10.0.0.5", 22), {"version": "OpenSSH 9.0"}) in services
    assert ("add_service", ("10.0.0.5", 80), {"service_name": "http", "web_app": "cockpit"}) in services
    assert ("add_service", ("10.0.0.5", 80), {"service_name": "http", "version": "nginx/1.25"}) in services

    credentials = _calls(graph, "add_credential")
    assert (
        "add_credential",
        ("admin", "secret"),
        {"source": "ssh", "service": "ssh", "verified": True, "host": "10.0.0.5"},
    ) in credentials
    assert (
        "add_credential",
        ("root", "database-secret"),
        {"source": "mysql", "service": "mysql", "host": "10.0.0.5"},
    ) in credentials
    assert (
        "add_credential",
        ("api_key", "api-secret"),
        {"source": "secrets", "secret_type": "token", "host": "10.0.0.5"},
    ) in credentials

    identities = _calls(graph, "add_identity")
    assert ("add_identity", ("deploy",), {"identity_type": "local", "host": "10.0.0.5"}) in identities
    assert ("add_identity", ("service",), {"identity_type": "local", "host": "10.0.0.5", "uid": 1001}) in identities
    assert (
        "add_identity",
        ("operator",),
        {"identity_type": "local", "host": "10.0.0.5", "shell": "/bin/bash"},
    ) in identities
    assert ("add_identity", ("reporting",), {"identity_type": "service"}) in identities

    links = _calls(graph, "link")
    assert any(call[1][2] is EdgeType.HAS_IDENTITY and call[2] == {"source": "ssh-enum"} for call in links)
    assert any(call[1][2] is EdgeType.TRUSTS and call[2] == {"discovery": "route"} for call in links)
    assert any(call[1][2] is EdgeType.PIVOTS_TO and call[2] == {"method": "lateral_movement"} for call in links)
    assert enricher.get_processed_count() == len(facts)


@pytest.mark.parametrize(
    ("fact", "expected_app"),
    [
        ("WordPress CMS detected", "wordpress"),
        ("Zabbix web interface detected", "zabbix"),
        ("phpMyAdmin detected", "phpmyadmin"),
        ("Grafana dashboard detected", "grafana"),
        ("Jenkins CI detected", "jenkins"),
        ("Joomla CMS detected", "joomla"),
        ("Drupal CMS detected", "drupal"),
        ("Apache Tomcat detected", "tomcat"),
        ("Webmin panel detected", "webmin"),
        ("GitLab instance detected", "gitlab"),
        ("Cockpit web console detected", "cockpit"),
    ],
)
def test_enricher_maps_each_web_fingerprint(fact: str, expected_app: str) -> None:
    graph = RecordingGraph()
    KnowledgeEnricher(graph)._process_fact("example.test", fact, "http")

    assert _calls(graph, "add_service") == [
        ("add_service", ("example.test", 80), {"service_name": "http", "web_app": expected_app})
    ]


@pytest.mark.parametrize(
    "fact",
    [
        "CREDENTIALS FOUND: no-separator",
        "CREDENTIALS FOUND: :password",
        "CREDENTIALS FOUND: admin:",
        "CREDENTIALS FOUND: a:password",
    ],
)
def test_enricher_rejects_incomplete_or_ambiguous_credentials(fact: str) -> None:
    graph = RecordingGraph()
    KnowledgeEnricher(graph)._process_fact("10.0.0.5", fact, "fixture")

    assert _calls(graph, "add_credential") == []


def test_enricher_deduplicates_normalizes_untyped_facts_and_contains_errors(caplog) -> None:
    graph = RecordingGraph(fail_service=True)
    enricher = KnowledgeEnricher(graph)

    with caplog.at_level("DEBUG"):
        enricher.enrich_from_facts(
            "10.0.0.5",
            [
                ("Port 80 OPEN (http)", "nmap"),
                ("Port 80 OPEN (http)", "nmap"),
                "plain untyped fact",
                ("one-item tuple",),
            ],
        )

    assert len(_calls(graph, "add_service")) == 1
    assert enricher.get_processed_count() == 3
    assert "synthetic graph failure" in caplog.text


def test_credential_ranking_covers_every_supported_credential_class() -> None:
    credentials = [
        ("", ""),
        ("user", KEY_AUTH_MARKER),
        ("root", KEY_AUTH_MARKER),
        ("user", "password"),
        ("root", "password"),
    ]

    assert [credential_rank_key(item)[0] for item in credentials] == [5, 3, 2, 1, 0]
    assert rank_credentials(credentials) == list(reversed(credentials))
    assert best_credential(credentials) == ("root", "password")
    assert best_credential([]) == (None, None)
