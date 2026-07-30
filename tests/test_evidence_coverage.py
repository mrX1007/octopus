"""Hermetic branch coverage for the legacy evidence boundary."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.ai import evidence as evidence_module
from core.ai.evidence import (
    EvidenceVerifier,
    LLMExtractor,
    OutputParser,
    RegexParser,
    StructuredParser,
    WebEndpointParser,
)

pytestmark = pytest.mark.unit


def _pairs(facts: list[dict]) -> set[tuple[str, str]]:
    return {(str(fact["type"]), str(fact["value"])) for fact in facts}


def test_module_helpers_cover_invalid_values_timeouts_targets_and_scopes() -> None:
    assert evidence_module._is_internal_ip_value("10.0.0.1") is True
    assert evidence_module._is_internal_ip_value("not-an-ip") is False
    assert evidence_module._is_internal_subnet_value("192.168.1.9/24") is True
    assert evidence_module._is_internal_subnet_value("not-a-subnet") is False

    raw = """
[TIMEOUT] nuclei-safe killed after 10s
[!] TIMEOUT: tool
nikto timed out after 20s
[TIMEOUT] nuclei-safe killed after 10s
"""
    assert evidence_module._timeout_tool_labels(raw) == ["nuclei_safe", "nikto"]
    events = evidence_module._timeout_tool_events(raw)
    assert [event["tool"] for event in events] == [
        "nuclei_safe",
        "nikto",
        "nuclei_safe",
    ]

    assert evidence_module._canonical_scope_url("") == ""
    assert evidence_module._canonical_scope_url("EXAMPLE.COM/") == "example.com"
    assert evidence_module._canonical_scope_url("http:///missing-host/") == "http:///missing-host"
    assert evidence_module._canonical_scope_url("HTTP://Example.COM:80/path?x=1]") == (
        "http://example.com/path?x=1"
    )
    assert evidence_module._canonical_scope_url("https://Example.COM:8443/") == (
        "https://example.com:8443"
    )

    assert evidence_module._tool_target_from_output(
        "nuclei", "nuclei -u https://fallback.example", "[NUCLEI SAFE - https://first.example]"
    ) == "https://fallback.example"
    assert evidence_module._tool_target_from_output(
        "nikto", "nikto", "[NIKTO - https://nikto.example]"
    ) == "https://nikto.example"
    assert evidence_module._tool_target_from_output(
        "other", "other https://generic.example/path", ""
    ) == "https://generic.example/path"
    assert evidence_module._tool_target_from_output("other", "other", "") == ""
    timed = "[NUCLEI SAFE - https://before.example]\n[TIMEOUT] nuclei killed after 3s"
    assert evidence_module._tool_target_before_timeout("nuclei", "nuclei", timed, 40) == (
        "https://before.example"
    )
    assert evidence_module._tool_target_before_timeout(
        "nikto", "nikto https://whole.example", "[TIMEOUT] nikto killed", 0
    ) == "https://whole.example"

    endpoint = json.loads(
        evidence_module._check_result_fact(
            "nuclei", "completed", "https://EXAMPLE.com:443/", "session"
        )["value"]
    )
    host = json.loads(
        evidence_module._check_result_fact("custom", "timeout", "10.0.0.1", "session")[
            "value"
        ]
    )
    unknown = json.loads(
        evidence_module._check_result_fact("", "timeout", "", "session")["value"]
    )
    assert endpoint["scope"] == {"type": "endpoint", "value": "https://example.com"}
    assert host["scope"] == {"type": "host", "value": "10.0.0.1"}
    assert unknown["scope"] == {"type": "unknown", "value": "tool"}


class _Snapshot:
    def __init__(self, facts: list[dict]) -> None:
        self.facts = facts

    def decision_facts(self):
        return tuple(self.facts)


class _FallbackFactStore:
    def __init__(self) -> None:
        self.add_fact = MagicMock(return_value=71)

    @staticmethod
    def get_facts(_scan_id: str, _host: str) -> list[dict]:
        return []


def test_evidence_verifier_rejections_fallback_and_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _FallbackFactStore()
    projector = SimpleNamespace(project_fact_ids=MagicMock())
    verifier = EvidenceVerifier(store, assessment_store=None, graph_projector=projector)
    monkeypatch.setattr(
        evidence_module.EvaluatedFactSnapshot,
        "build",
        MagicMock(return_value=_Snapshot([])),
    )
    monkeypatch.setattr(verifier, "_build_evidence_terms", MagicMock(return_value={"derived"}))

    assert verifier.verify_claim("scan", "host", "", ["derived"])["status"] == "rejected"
    assert verifier.verify_claim("scan", "host", "claim", [])["status"] == "rejected"
    workflow = verifier.verify_claim("scan", "host", "Target is exposed", ["services"])
    assert workflow["status"] == "rejected"
    accepted = verifier.verify_claim("scan", "host", "Planning assessment", ["derived"])
    assert accepted["assessment_status"] == "inferred"
    assert accepted["fact_id"] == 71
    assert accepted["assessment_id"] is None
    store.add_fact.assert_called_once()
    projector.project_fact_ids.assert_called_once_with([71])


def test_evidence_verifier_verified_and_inferred_assessment_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = [
        {
            "id": 1,
            "type": "credential",
            "value": "ssh_login_success:alice@host",
            "confidence": 92,
            "source": "ssh",
            "assessment": {
                "status": "observed",
                "source_execution_ids": ["exec-1", "exec-shared"],
            },
        },
        {
            "id": 2,
            "type": "service_version",
            "value": "redis:6379:7.0",
            "confidence": 88,
            "source": "derived",
            "assessment": {
                "status": "inferred",
                "source_execution_ids": ["exec-shared", "exec-2"],
            },
        },
    ]
    monkeypatch.setattr(
        evidence_module.EvaluatedFactSnapshot,
        "build",
        MagicMock(return_value=_Snapshot(facts)),
    )
    assessment = SimpleNamespace(assessment_id="assessment-1")
    assessment_store = SimpleNamespace(assess_fact=MagicMock(return_value=(assessment, True)))
    fact_store = SimpleNamespace(
        assessments=assessment_store,
        get_facts=MagicMock(return_value=facts),
        add_fact_with_status=MagicMock(side_effect=[(81, True), (82, False)]),
    )
    verifier = EvidenceVerifier(fact_store)
    monkeypatch.setattr(
        verifier,
        "_build_evidence_terms",
        MagicMock(return_value={"ssh_access_confirmed", "redis_6379_7_0"}),
    )

    verified = verifier.verify_claim("scan", "host", "SSH is accessible", ["ssh_access_confirmed"])
    inferred = verifier.verify_claim("scan", "host", "Redis version observed", ["redis:6379:7.0"])
    assert verified["assessment_status"] == "verified"
    assert verified["source_execution_ids"] == ["exec-1", "exec-shared"]
    assert inferred["assessment_status"] == "inferred"
    assert inferred["evidence_fact_ids"] == [2]
    assert inferred["created"] is False
    assert assessment_store.assess_fact.call_count == 2


def test_evidence_verifier_term_and_hard_evidence_helpers() -> None:
    verifier = EvidenceVerifier(SimpleNamespace())
    facts = [
        {"id": None, "type": "port_open", "value": "22/tcp (ssh)"},
        {"id": "bad", "type": "port_open", "value": "22/tcp (ssh)"},
        {"id": 3, "type": "port_open", "value": "22/tcp (ssh)"},
    ]
    assert verifier._supporting_fact_ids("service:ssh", facts) == [3]
    terms = verifier._fact_evidence_terms(
        {"type": "system_access", "value": "root_access_confirmed"}
    )
    assert "ssh_access_confirmed" in terms
    assert verifier._fact_is_hard_evidence({"assessment_status": "verified"}) is True
    assert verifier._fact_is_hard_evidence({"assessment_status": "inferred"}) is False
    assert verifier._fact_is_hard_evidence(
        {"type": "vulnerability_candidate", "source": "scanner"}
    ) is False
    assert verifier._fact_is_hard_evidence(
        {"type": "observation", "source": "llm"}
    ) is False
    assert verifier._fact_is_hard_evidence(
        {"type": "observation", "source": "scanner"}
    ) is True
    assert verifier._workflow_marker_cannot_prove_claim("unknown", "status unknown") is False
    assert verifier._workflow_marker_cannot_prove_claim("unknown", "target vulnerable") is True

    aliases = verifier._requirement_alias_terms
    assert "coverage_gap_status_failed" in aliases("coverage_gaps[0].status: failed")
    assert "coverage_gap_check_nuclei" in aliases("coverage_gaps[0].check: nuclei")
    assert "service_version_nginx" in aliases("services[0].banner: nginx")
    assert "internal_service_port_5432" in aliases("internal_services[0].port: 5432")
    assert "security_findings_verified_value_cve_2026_1" in aliases(
        "security_findings.verified.value: CVE-2026-1"
    )
    assert "" in aliases("security_findings.verified.value: ''")


def test_evidence_verifier_builds_rich_context_terms_and_handles_context_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = {
        "state": "enumerating",
        "ports_count": 2,
        "services": ["ssh"],
        "open_questions": ["banner"],
        "stage_gates": {"exploit": True, "cleanup": False},
        "surface_states": {"ssh_access": "confirmed_present"},
        "typed_coverage_gaps": [
            "invalid",
            {"surface": "web", "check": "nuclei", "status": "pending", "meta": {}},
        ],
        "target_model": {
            "coverage": {
                "gaps": [{"status": "needed"}],
                "external_services": [
                    {"host": "example", "port": 443, "service": "https", "banner": "nginx"}
                ],
                "internal_services": [
                    {"host": "10.0.0.2", "port": 5432, "service": "postgresql"}
                ],
            },
            "services": [
                {"host": "example", "port": 22, "service": "ssh", "state": "open"}
            ],
            "internal_services": [
                {"host": "10.0.0.3", "port": 6379, "service": "redis", "banner": "7.0"}
            ],
            "security_findings": {
                "verified": ["invalid", {"value": "CVE-2026-1"}, {"value": ""}]
            },
        },
    }

    class Resolver:
        def __init__(self, _store) -> None:
            pass

    class Builder:
        def __init__(self, _store, _resolver) -> None:
            pass

        @staticmethod
        def build_context(_scan: str, _host: str) -> dict:
            return context

    monkeypatch.setattr("core.ai.state_resolver.StateResolver", Resolver)
    monkeypatch.setattr("core.ai.context_builder.ContextBuilder", Builder)
    verifier = EvidenceVerifier(SimpleNamespace())
    terms = verifier._build_evidence_terms(
        "scan",
        "host",
        [{"type": "credential", "value": "ssh_login_success:alice@host"}],
    )
    assert "coverage_gap_web_nuclei_pending" in terms
    assert "internal_service_10_0_0_3_6379_tcp_redis" in terms
    assert "cve_2026_1" in terms

    verifier._add_gap_evidence_terms(terms, "invalid", "coverage")  # type: ignore[arg-type]
    verifier._add_gap_evidence_terms(terms, {"meta": [1]}, "coverage")
    verifier._add_service_evidence_terms(terms, "invalid", "services")  # type: ignore[arg-type]
    verifier._add_service_evidence_terms(
        terms,
        {"host": "host", "port": 80, "service": "http", "banner": "server"},
        "services",
    )
    verifier._add_service_evidence_terms(
        terms,
        {"host": "10.0.0.1", "port": 80, "service": "http", "banner": "server"},
        "internal_services",
    )
    verifier._add_service_evidence_terms(
        terms, {"port": 80, "service": "http"}, "services"
    )
    verifier._add_service_evidence_terms(terms, {"banner": "only"}, "other")

    class BrokenBuilder(Builder):
        @staticmethod
        def build_context(_scan: str, _host: str) -> dict:
            raise RuntimeError("context unavailable")

    monkeypatch.setattr("core.ai.context_builder.ContextBuilder", BrokenBuilder)
    assert verifier._build_evidence_terms("scan", "host", []) == {"host_host", "host"}


def test_regex_parser_ports_timeouts_msf_and_exploit_boundaries() -> None:
    parser = RegexParser()
    initial = parser.parse(
        "custom",
        """
OCTOBENCH_V3_ABCDEFGHIJKLMNOP
22/tcp filtered ssh
80/tcp open http
81/tcp open http tcpwrapped
82/tcp open http Apache 2.4
Service Info: Host: web01
Web ports detected [80, 8443]
[TIMEOUT]
Shodan host: no information available for that IP
no HTTP(S) response
no common web wordlists found
CVE-2018-15473 - server patched
""",
        "session",
    )
    pairs = _pairs(initial)
    assert ("benchmark_observation", "OCTOBENCH_V3_ABCDEFGHIJKLMNOP") in pairs
    assert ("port_filtered", "22/tcp (ssh)") in pairs
    assert ("service_version", "http:82:Apache 2.4") in pairs
    assert ("service_status", "tool_timeout:custom") in pairs

    misc = parser.parse(
        "shodan ffuf",
        "No information available for that IP\nNo HTTP(S) response\nNo common web wordlists found",
        "session",
    )
    assert ("service_status", "external_intel_no_host_information:shodan") in _pairs(misc)
    assert ("service_status", "web_content_discovery_skipped:no_wordlist") in _pairs(misc)

    cases = (
        (
            "msf_check host auxiliary/scanner/ssh/ssh_login",
            "[+] 10.0.0.1:22 - Success: 'alice:secret'",
            "msf_login_check_success:auxiliary/scanner/ssh/ssh_login:22",
        ),
        ("msf_check host exploit/test", "Psych::SyntaxError traceback", "msf_check_error:exploit/test"),
        (
            "msf_check host exploit/test",
            "OptionValidateError failed to validate",
            "msf_check_invalid_options:exploit/test",
        ),
        (
            "msf_check host exploit/test",
            "The target does not appear to be vulnerable",
            "msf_check_not_vulnerable:exploit/test",
        ),
        (
            "msf_check host exploit/test RPORT=8080",
            "The target appears to be vulnerable",
            "msf_check_positive:exploit/test",
        ),
    )
    for tool, raw, expected in cases:
        assert any(fact["value"] == expected for fact in parser.parse(tool, raw, "session"))

    extra = parser.parse(
        "custom",
        """
MSF module 'missing/module' does NOT EXIST
[*] MSF Module: exploit/test
Meterpreter session 1 opened
[*] Attempting exploit via payload
CVE-2018-15473 - all users return valid
login success
""",
        "session",
    )
    extra_pairs = _pairs(extra)
    assert ("service_status", "msf_module_invalid:missing/module") in extra_pairs
    assert ("exploit_success", "msf_session_opened:exploit/test") in extra_pairs
    assert ("exploit_attempted", "payload") in extra_pairs
    assert ("credential", "login_success") in extra_pairs
    assert parser.parse("custom", "VULNERABLE cPanel", "session") == []
    assert parser.parse("custom", "VULNERABLE cPanel\nSession: :", "session") == []
    assert parser.parse(
        "custom",
        "[EXPLOIT CANDIDATE 1] ssh:22 OpenSSH -> informational/module",
        "session",
    )
    assert parser.parse(
        "msf_check host auxiliary/foo_login",
        "[+] 10.0.0.1:22 - Success: 'alice:secret'",
        "session",
    )
    assert parser.parse(
        "msf_check host exploit/test", "The target appears to be vulnerable", "session"
    )


def test_regex_parser_post_access_web_and_protocol_boundaries() -> None:
    parser = RegexParser()
    raw = """
SSH Post-Exploitation Analysis
SSH connected as alice@10.0.0.1
[+] Hostname
$ hostname
[not-a-host]
[+] Kernel
$ uname -a
[not-a-kernel]
inet 127.0.0.1/8
inet 10.0.0.5/24
inet 10.0.0.6
inet 10.0.0.7/2
inet 8.8.8.8
Listening Ports (2 internal services)
[22][ssh] host: x login: root password: secret
persistence planted success
CLEANUP STATUS: PARTIAL
+ OSVDB-1: issue
"""
    facts = parser.parse("nikto", raw, "session")
    pairs = _pairs(facts)
    assert ("service_status", "internal_services:2") in pairs
    assert ("credential", "root:secret (ssh port 22)") in pairs
    assert ("persistence", "mechanism_planted") in pairs
    assert ("cleanup", "partial") in pairs

    for status in ("SUCCESS", "FAILED"):
        assert parser.parse("custom", f"CLEANUP STATUS: {status}", "session")
    assert parser.parse("wpscan", "WordPress version 6.0\nVulnerability CVE-2026-1234", "s")
    assert parser.parse("wpscan", "No vulnerabilities identified", "s") == []
    assert ("service_status", "sqlmap_no_get_parameters_found") in _pairs(
        parser.parse("sqlmap", "no usable links found", "s")
    )
    assert ("service_status", "sqlmap_no_injection_found") in _pairs(
        parser.parse("sqlmap", "all tested parameters do not appear to be injectable", "s")
    )
    assert parser.parse("sqlmap", "neutral scan", "s") == []
    assert ("service_status", "jmx2rce_not_vulnerable") in _pairs(
        parser.parse("jmx2rce", "vulnerable but not accessible", "s")
    )

    crawl = parser.parse(
        "scrapling_crawl https://example.test/",
        """Title: Example
Forms (2):
  home -> /next
Links:
  /one
  https://example.test/two
""",
        "s",
    )
    assert ("service_status", "web_crawl_completed:https://example.test") in _pairs(crawl)
    assert parser.parse("crawl ", "Title: Empty command", "s")
    assert parser.parse("scrapling", "neutral", "s") == []

    ftp_allowed = parser.parse(
        "ftp_anonymous_check",
        "[FTP Anonymous Check - host:2121]\nBanner: FTP 1.0\nAnonymous login: allowed",
        "s",
    )
    ftp_denied = parser.parse("ftp_anonymous_check", "Anonymous login: denied", "s")
    ftp_failed = parser.parse("ftp_anonymous_check", "ftp probe failed", "s")
    assert ("vulnerability", "ftp_anonymous_login_allowed:host:2121") in _pairs(ftp_allowed)
    assert ("service_status", "ftp_anonymous_denied:21") in _pairs(ftp_denied)
    assert ("service_status", "ftp_probe_failed:21") in _pairs(ftp_failed)
    assert parser.parse("ftp_anonymous_check", "neutral", "s") == []

    smtp = parser.parse(
        "smtp_probe",
        "[SMTP Probe - host:2525]\nBanner: SMTP 1.0\nSTARTTLS: supported\nAUTH mechanisms: PLAIN LOGIN",
        "s",
    )
    smtp_failed = parser.parse("smtp probe", "smtp probe failed", "s")
    assert ("service_status", "smtp_probe_completed:2525") in _pairs(smtp)
    assert ("service_status", "smtp_probe_failed:25") in _pairs(smtp_failed)

    db = parser.parse(
        "db_inventory",
        "[DB Inventory - PostgreSQL host:5432]\nDB inventory completed: yes\nVersion: 14\nCurrent user: root\nDatabases (3):",
        "s",
    )
    db_failed = parser.parse("db inventory", "DB inventory failed", "s")
    assert ("database_inventory", "databases:postgresql:3") in _pairs(db)
    assert ("service_status", "db_inventory_failed:database:0") in _pairs(db_failed)
    assert parser.parse("db_inventory", "neutral", "s") == []

    stacks = parser.parse(
        "whatweb",
        "wordpress php node.js express nginx apache golang",
        "s",
    )
    assert len([fact for fact in stacks if fact["type"] == "app_stack"]) == 7
    assert parser.parse("whatweb", "unrecognized", "s") == []
    search = parser.parse(
        "searchsploit OpenSSH 8",
        "heading without pipe\nOpenSSH exploit | exploits/linux/123.py\nnot exploit | docs/readme.md",
        "s",
    )
    assert ("service_status", "searchsploit_queried:openssh_8") in _pairs(search)
    assert any(fact["type"] == "exploit_reference" for fact in search)
    assert parser.parse("searchsploit ", "no results", "s") == []
    assert parser.parse("killchain_exfil", "Files exfiltrated: 0", "s")


def test_regex_parser_family_security_and_code_scanner_boundaries() -> None:
    parser = RegexParser()
    tool = (
        "subfinder nuclei openapi_import graphql_check security_headers cors_check "
        "jwt_analyze js_route_extract burp_import gitleaks semgrep prowler"
    )
    raw = """
[header ignored]
https://Example.COM:8080/path [200] [Example Title] [nginx]
https://digits.test [12]
example.org 192.0.2.1:8443 [12]
[NUCLEI ignored]
{"template-id":"tpl","info":{"severity":"high","name":"Issue"},"matched-at":"https://target.test/x"}
{"template":"empty","severity":"low"}
{bad json
[classic] [http] [medium] https://target.test/y
POST /users/{id} auth=unknown_or_none
GET /health auth=bearer
__schema queryType
Server: nginx
Content-Security-Policy: default-src * 'unsafe-inline'
Set-Cookie: sid=value
Origin: https://origin.test
Access-Control-Allow-Origin: https://origin.test
Access-Control-Allow-Credentials: true
alg: HS256
kid: key-1
claims: sub=alice
Routes:
/api/users?id=1
/plain
URL https://proxy.test/path
ISSUE CORS weakness
ALERT informational
{"RuleID":"generic-api-key","File":"app.env","Verified":true}
{"RuleID":"unverified","File":"other.env","Verified":false}
api key leaked in plaintext
{"results":[{"check_id":"python.issue","path":"app.py","extra":{"severity":"ERROR"}}]}
{"Results":[{"Target":"image","Vulnerabilities":[{"Severity":"HIGH","VulnerabilityID":"CVE-1"}],"Misconfigurations":[{"Severity":"MEDIUM","ID":"CFG-1"}],"Secrets":[{"RuleID":"secret-1"}]}]}
{"results":{"failed_checks":[{"check_id":"CKV-1","file_path":"main.tf","severity":"HIGH"}]}}
{"Status":"FAIL","Severity":"HIGH","CheckID":"cloud-1","ResourceId":"bucket"}
{"Status":"PASS","CheckID":"cloud-2"}
"""
    facts = parser.parse(tool, raw, "session")
    types = {fact["type"] for fact in facts}
    for fact_type in (
        "asset_url",
        "asset_domain",
        "asset_ip",
        "asset_service",
        "nuclei_finding",
        "api_endpoint",
        "api_security_note",
        "web_security_note",
        "jwt_metadata",
        "js_route",
        "proxy_finding",
        "secret_finding",
        "code_finding",
        "cloud_finding",
    ):
        assert fact_type in types

    assert parser.parse("graphql_check", "not accessible", "s")
    assert parser.parse("graphql_check", "neutral", "s") == []
    assert parser.parse("security_headers", "", "s") == []
    assert parser.parse(
        "curl_headers",
        "Server: nginx\nLocation: /next\nX-Powered-By: PHP\nContent-Security-Policy: default-src self\nSet-Cookie: sid=v; HttpOnly; Secure; SameSite=Lax",
        "s",
    )
    assert parser.parse("cors_check", "Origin: x\nAccess-Control-Allow-Origin: y", "s")
    assert parser.parse("cors_check", "Access-Control-Allow-Credentials: true", "s")
    assert parser.parse("jwt_analyze", "alg: RS256", "s")
    assert parser.parse("jwt_analyze", "kid: key-only", "s")


def test_regex_parser_ad_credentials_browser_and_network_boundaries() -> None:
    parser = RegexParser()
    payload = parser.parse(
        "custom",
        """Python implant generated: /tmp/a.py
PowerShell stager generated: /tmp/a.ps1
Go implant: /tmp/a
C2: https://c2.test
SOCKS proxy started [+]
port forward started [+]
""",
        "s",
    )
    assert {fact["type"] for fact in payload} >= {"payload_artifact", "c2_profile", "pivot"}
    assert parser.parse("killchain_vuln_assess", "Total exploitable findings: 0", "s")
    assert parser.parse("killchain_vuln_assess", "Total exploitable findings: 2", "s")
    assert parser.parse("killchain_vuln_assess", "assessment started", "s") == []
    assert parser.parse("killchain_exploit", "Exploits attempted: 2 | Succeeded: 0", "s")
    assert parser.parse("killchain_exploit", "Exploits attempted: 2 | Succeeded: 1", "s")
    assert parser.parse("custom", "[!] Cleanup requires valid credentials", "s")
    assert parser.parse("enum4linux", "NT_STATUS_ACCESS_DENIED", "s")

    ad_raw = r"""
[AD Security Review]
(via ldap — 2 users)
(via ldap — 3 groups)
(via ldap — 4 computers)
(via ldap — 5 gpos)
Domain: example.test
Domain: unknown
Domain Admins adminCount=1
BloodHound data collected -> graph.zip
BloodHound file: another.zip
Shortest paths to Domain Admins: 2
Local admin paths: 3
High value targets: 4
User: alice@example.test
Minimum password length: 8
Minimum password length: 14
Password history length: 5
Maximum password age (days): 90
Lockout threshold: 0
Lockout threshold: 5
Delegation: constrained to service
Delegation:
unconstrained delegation
resource-based constrained delegation RBCD
ESC1: vulnerable template
ADCS vulnerable template enrollee supplies subject client authentication
GPO issue: writable policy
GenericAll on Domain Admins
"""
    ad = parser.parse("custom", ad_raw, "s")
    ad_types = {fact["type"] for fact in ad}
    assert ad_types >= {
        "ad_enumeration",
        "ad_users",
        "ad_domain",
        "ad_graph_data",
        "ad_attack_path",
        "ad_password_policy",
        "ad_gpo_issue",
        "ad_delegation",
        "ad_adcs_issue",
        "ad_acl_issue",
    }
    assert parser.parse("custom", "[AD users]\nDelegation:   \n", "s")

    kerberos = parser.parse(
        "custom",
        "1 AS-REP hash(es) extracted -> asrep.txt\n2 Kerberoast hash(es) extracted -> tgs.txt\nDCSync successful — 3 hash(es) extracted",
        "s",
    )
    assert {fact["type"] for fact in kerberos} >= {"kerberos_hashes", "domain_hash_dump"}
    assert parser.parse("custom", "$krb5asrep$", "s")
    assert parser.parse("custom", "$krb5tgs$", "s")
    assert parser.parse("custom", "DCSync successful", "s")

    pth = parser.parse(
        "custom",
        "[PASS-THE-HASH - alice@10.0.0.2]\nSMB authentication successful via PTH",
        "s",
    )
    assert ("lateral_access", "alice@10.0.0.2") in _pairs(pth)
    assert parser.parse("custom", "pass-the-hash", "s") == []
    remote = parser.parse("custom", "[PSEXEC - 10.0.0.2]\nUser: DOMAIN\\alice\npsexec successful", "s")
    fallback_remote = parser.parse("custom", "wmiexec successful", "s")
    assert any(fact["type"] == "remote_execution" for fact in remote + fallback_remote)

    cracked = parser.parse(
        "custom",
        "Hash cracker\nCrackable hashes: 2\nTotal hashes: 3\nCracked: 1\n + alice:secret",
        "s",
    )
    zero = parser.parse("custom", "Cracking results\nTotal hashes: 3\nCracked: 0\n + :empty", "s")
    assert ("credential", "cracked_credentials:1") in _pairs(cracked)
    assert all(fact["value"] != "cracked_credentials:0" for fact in zero)
    assert parser.parse("custom", "hash cracker started", "s") == []

    failed_browser = parser.parse(
        "browser_surface",
        "URL: https://fail.test\nrequests fallback failed",
        "s",
    )
    rendered_browser = parser.parse(
        "browser_surface",
        "URL: https://ok.test\nPage title: Login\nContent size: 10 bytes\nForms: 1\n input: password:pwd\n link: /next",
        "s",
    )
    assert any("web_fetch_failed" in fact["value"] for fact in failed_browser)
    assert ("browser_rendered", "https://ok.test") in _pairs(rendered_browser)
    assert parser.parse("browser_surface", "Page title: no URL", "s")

    osint = parser.parse(
        "custom",
        '[ShardX OSINT Search - query]\n"google": {"content_length": 12}\n"bing": {"error": "blocked"}',
        "s",
    )
    assert {fact["type"] for fact in osint} >= {"osint_query", "osint_result", "osint_status"}
    assert parser.parse("custom", "shardx osint search", "s") == []

    network = parser.parse(
        "network_recon",
        """Network discovery
Subnets: 10.0.0.0/24 127.0.0.0/8 invalid
 -> 10.0.0.2
 -> 10.0.0.0
 -> 8.8.8.8
Internal hosts discovered: 1
LATERAL MOVEMENT SUCCESS: alice@10.0.0.2
OPEN 10.0.0.2:22/tcp
OPEN 8.8.8.8:80/tcp (http)
Internal services discovered: 1
""",
        "s",
    )
    assert {fact["type"] for fact in network} >= {
        "internal_subnet",
        "internal_host",
        "internal_network",
        "lateral_access",
        "internal_service",
    }
    completed = parser.parse("network_recon", "[PIVOT]\n10.0.0.3", "s")
    assert ("service_status", "network_recon_completed") in _pairs(completed)


def test_structured_web_llm_and_output_parser_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    structured = StructuredParser()
    payload = {
        "facts": [
            {"type": "observation", "value": "one"},
            {"type": "", "value": "bad"},
            "bad",
        ],
        "cve": "CVE-2026-1",
        "plugin": "cpanel_auth_bypass",
        "success": True,
        "artifacts": ["artifact"],
        "sessions": [
            {"type": "web", "session": "token"},
            {"type": "web"},
            "bad",
        ],
    }
    facts = structured.parse("plugin", "prefix\n" + json.dumps(payload), "session")
    assert {fact["type"] for fact in facts} >= {
        "observation",
        "vulnerability",
        "plugin_result",
        "plugin_artifact",
        "credential",
    }
    assert structured.parse("plugin", '{"plugin":"x","success":false}', "session")
    assert structured.parse("plugin", "{bad}", "session") == []
    assert structured.parse("plugin", '{}\n--- plugin output ---\nignored', "session") == []

    web = WebEndpointParser()
    assert web._url_from_text("none") == ""
    assert web._tool_name_is_web_facing("") is False
    assert web._candidate_is_negative("anything", "not-a-url") is False
    assert web._candidate_is_negative(
        "web_fetch_failed:https://x.test", "https://x.test"
    ) is True
    assert web._candidate_is_negative(
        "requests fallback failed: x.test", "https://x.test"
    ) is True
    assert web._candidate_has_positive_signal("", "not-a-url") is False
    for signal in ("status: 200", "[201]", "title: yes"):
        assert web._candidate_has_positive_signal(
            f"x.test {signal}", "https://x.test"
        ) is True
    assert web._canonical_endpoint("") == ""
    assert web._canonical_endpoint("ftp://x.test") == ""
    assert web._canonical_endpoint("https://x.test/{bad}") == ""
    parsed = web.parse(
        "manual_recon https://x.test/path",
        "URL: https://x.test/path\nURL: https://x.test/path\nURL: invalid",
        "session",
    )
    assert len(parsed) == 1
    assert web.parse("manual_recon https://x.test", "connection failed", "session") == []
    positive = web.parse(
        "manual_recon https://x.test",
        "URL: https://x.test\nrequests fallback failed: x.test\nx.test status: 200",
        "session",
    )
    assert positive

    monkeypatch.setattr("core.ai.ollama_client.ask_ollama", lambda *_args, **_kwargs: '[!] error')
    extractor = LLMExtractor()
    assert extractor.parse("tool", "raw", "session") == []
    monkeypatch.setattr(
        "core.ai.ollama_client.ask_ollama",
        lambda *_args, **_kwargs: '{"facts":[{"type":"x","value":"y"}]}',
    )
    assert extractor.parse("tool", "raw", "session")[0]["type"] == "x"
    monkeypatch.setattr(
        "core.ai.ollama_client.ask_ollama",
        MagicMock(side_effect=RuntimeError("offline")),
    )
    assert extractor.parse("tool", "raw", "session") == []

    output = OutputParser()
    assert output._should_try_llm("tool", "short") is False
    assert output._should_try_llm("tool", "connection failed " * 10) is False
    assert output._should_try_llm("tool", "meaningful deterministic output " * 5) is True
    sanitized = output._sanitize_facts(
        [
            {},
            {"type": "port_open", "value": "invalid"},
            {"type": "password", "value": "secret"},
            {"type": "observation", "value": "unknown"},
            {"type": "observation", "value": "valid", "session_id": "s"},
            {"type": "observation", "value": "valid", "session_id": "s"},
        ]
    )
    assert sanitized == [{"type": "observation", "value": "valid", "session_id": "s"}]
    assert output._should_run_legacy_regex("nuclei", "") is False
    assert output._should_run_legacy_regex("custom", "[NUCLEI RESULTS]") is False

    output.family_pipeline.parse = MagicMock(return_value=[])
    output.web_endpoint_parser.parse = MagicMock(return_value=[])
    output.regex_parser.parse = MagicMock(return_value=[])
    output.structured_parser.parse = MagicMock(return_value=[])
    output.llm_extractor.parse = MagicMock(
        return_value=[{"type": "observation", "value": "llm", "session_id": "none"}]
    )
    assert output.parse_tool_output("custom", "meaningful output " * 10)[0]["value"] == "llm"

    timeout = output._parse_negative_status(
        "manual_recon",
        "[TIMEOUT]\n[NUCLEI SAFE - https://x.test]\n[TIMEOUT] nuclei killed after 1s",
        "session",
    )
    assert any(fact["type"] == "check_result" for fact in timeout)
    output._parse_negative_status("custom", "[TIMEOUT]", "session")
    output._parse_negative_status(
        "custom_tool args", "[TIMEOUT] nikto killed after 1s", "session"
    )
    complete = output._parse_negative_status(
        "nuclei nikto",
        "[NUCLEI COMPLETE - https://x.test]\n[NIKTO COMPLETE - host.test]",
        "session",
    )
    assert len([fact for fact in complete if fact["type"] == "check_result"]) == 2
    for raw, expected in (
        ("session_id: abc", "abc"),
        ("session = def", "def"),
        ("Session created -- SL# ghi", "ghi"),
        ("Scan ID: jkl", "jkl"),
        ("none", "none"),
    ):
        assert output._extract_session_id(raw) == expected
