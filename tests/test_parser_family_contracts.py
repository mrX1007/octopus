#!/usr/bin/env python3
"""Canonical parser-family and normalization contracts."""

import pytest

pytestmark = pytest.mark.contract

def test_pipeline_derives_normalized_endpoint_and_network_graph_facts():
    import json
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_pipeline_derived_{uuid.uuid4().hex}.db")
    scan_id = "scan-derived"
    host = "10.0.0.5"

    pipeline._store_fact(
        scan_id,
        host,
        {"type": "port_open", "value": "43117/tcp (ssl/http) [Golang net/http server]", "confidence": 100},
        "test",
    )
    pipeline._store_fact(
        scan_id,
        host,
        {"type": "internal_subnet", "value": "172.25.0.1/16", "confidence": 90},
        "ssh_inventory",
    )
    facts = pipeline.fact_store.get_facts(scan_id, host)
    pairs = {(fact["type"], fact["value"]) for fact in facts}
    endpoint_values = [json.loads(value) for ftype, value in pairs if ftype == "web_endpoint"]
    edge_values = [json.loads(value) for ftype, value in pairs if ftype == "network_edge"]

    assert any(endpoint["url"] == "https://10.0.0.5:43117/" for endpoint in endpoint_values)
    assert any(edge["type"] == "attached_subnet" and edge["to"] == "172.25.0.1/16" for edge in edge_values)


def test_runner_parses_web_scanner_target_flags_without_passing_flags_as_targets():
    import core.tools.exploit_tools
    import core.tools.recon_tools  # noqa: F401 - registers web scanner tools
    from core.tools.registry import get_tool
    from core.tools.runner import run_tool_by_command

    commands = {
        "nikto": "nikto -h http://10.0.0.5",
        "sqlmap": "sqlmap -u http://10.0.0.5/?id=1 --level=1",
        "wpscan": "wpscan --url http://10.0.0.5",
        "jmx2rce_scan": "jmx2rce_scan http://10.0.0.5:8080/manager",
    }
    captured = []
    old_funcs = {}

    def fake_url_tool(target, *args, **kwargs):
        captured.append(target)
        return "ok"

    try:
        for tool_name, command in commands.items():
            tool_def = get_tool(tool_name)
            old_funcs[tool_name] = tool_def.func
            tool_def.func = fake_url_tool
            result = run_tool_by_command(command)
            assert result == "ok"
    finally:
        for tool_name, old_func in old_funcs.items():
            get_tool(tool_name).func = old_func

    assert captured == [
        "http://10.0.0.5",
        "http://10.0.0.5/?id=1",
        "http://10.0.0.5",
        "http://10.0.0.5:8080/manager",
    ]


def test_exploit_selector_parses_compact_state_context():
    from core.exploits.selector import _extract_services

    recon_data = (
        'compact_state -> {"access":["root"],'
        '"open_ports":[{"port":22,"service":"ssh","banner":"OpenSSH 7.4"}],'
        '"internal_services":[{"host":"172.24.108.2","port":53,"service":"dns"}]}'
    )

    services = _extract_services(recon_data)

    assert {"port": "22", "service": "ssh", "version": "OpenSSH 7.4"} in services
    assert any(
        service.get("host") == "172.24.108.2"
        and service.get("port") == "53"
        and service.get("scope") == "internal"
        for service in services
    )


def test_parser_families_extract_without_legacy_dependency():
    from core.ai.parsers import ParserFamilyPipeline

    raw = """
80/tcp open http nginx
[API AUTH CHECK - https://app.example.com/api/users]
Anonymous status: 200
NOTE anonymous_accessible
Domain Name: CORP.LOCAL
ESC1: vulnerable template
"""

    facts = ParserFamilyPipeline().parse("nmap api_auth_check adcs_review", raw, "sess")
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("port_open", "80/tcp (http) [nginx]") in pairs
    assert ("api_security_note", "anonymous_accessible") in pairs
    assert ("ad_domain", "CORP.LOCAL") in pairs
    assert ("ad_adcs_issue", "ESC1:vulnerable template") in pairs


def test_authenticated_web_and_api_facts_are_normalized():
    from core.ai.evidence import OutputParser

    output = """
[SESSION PROFILE IMPORT - session.json]
Headers: 2
Cookies: 1
[AUTHENTICATED CRAWL - https://app.example.com/dashboard]
Status: 200
Title: Dashboard
Forms: 1
CSRF token observed: no
LINK https://app.example.com/api/users
[API AUTH CHECK - https://app.example.com/api/users]
Anonymous status: 200
NOTE anonymous_accessible
"""

    facts = OutputParser().parse_tool_output("session_profile_import authenticated_crawl api_auth_check", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("web_session", "profile_imported:headers=2:cookies=1") in pairs
    assert ("web_session", "authenticated_crawl_status:200") in pairs
    assert ("web_security_note", "csrf_token_not_observed_authenticated") in pairs
    assert ("web_link", "https://app.example.com/api/users") in pairs
    assert ("api_security_note", "anonymous_accessible") in pairs


def test_asm_parser_normalizes_dns_records_services_and_graph_edges():
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_asm_graph_{uuid.uuid4().hex}.db")
    scan_id = "scan-asm-graph"
    target = "example.com"
    result = pipeline.replay_outputs(scan_id, target, [{
        "tool": "httpx_probe dnsx tlsx naabu",
        "output": """
https://app.example.com [200] [Admin] [nginx,React]
app.example.com CNAME edge.example.net
app.example.com:443
SAN app.example.com api.example.com
""",
    }])

    model = result["context"]["target_model"]
    graph = result["context"]["asset_graph"]
    edge_types = {edge["type"] for edge in graph["edges"]}

    assert "app.example.com" in model["assets"]["domains"]
    assert any(value.startswith("cname:edge.example.net") for value in model["assets"]["dns_records"])
    assert "app.example.com:443/tcp" in model["assets"]["services"]
    assert "owns_service" in edge_types
    assert "has_dns_record" in edge_types or "has_tls_san" in edge_types


def test_family_parsers_cover_template_web_api_ad_code_cloud_secrets():
    from core.ai.parsers import ParserFamilyPipeline

    raw = """
{"template-id":"exposed-panel","info":{"severity":"medium","name":"Panel"},"matched-at":"https://app.example.com/admin"}
Content-Security-Policy: default-src * 'unsafe-inline'
Set-Cookie: sid=abc
alg: none
/api/users/{id}
GET /users/{id} auth=unknown_or_none
PATCH /users/{id} auth=unknown_or_none
Minimum password length: 8
Lockout threshold: 0
Unconstrained delegation: WEB01$
GenericAll -> CORP\\Helpdesk
{"RuleID":"generic-api-key","File":"app/.env","Verified":true}
{"results":[{"check_id":"python.lang.security.audit","path":"app.py","extra":{"severity":"HIGH"}}]}
{"Results":[{"Target":"requirements.txt","Vulnerabilities":[{"VulnerabilityID":"CVE-2025-0001","Severity":"CRITICAL"}]}]}
{"Status":"FAIL","Severity":"HIGH","CheckID":"s3_bucket_public_access","ResourceId":"bucket-1"}
"""

    facts = ParserFamilyPipeline().parse(
        "nuclei_safe security_headers_check jwt_analyze js_route_extract openapi_import ad_security_review gitleaks_scan semgrep_scan trivy_scan prowler_scan",
        raw,
        "sess",
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert any(ftype == "nuclei_finding" and value.startswith("medium:exposed-panel") for ftype, value in pairs)
    assert ("web_security_note", "weak_csp_policy") in pairs
    assert ("web_security_note", "cookie_missing_httponly:sid") in pairs
    assert ("jwt_metadata", "alg:none") in pairs
    assert ("api_security_note", "idor_candidate:GET:/users/{id}") in pairs
    assert ("api_security_note", "mass_assignment_candidate:PATCH:/users/{id}") in pairs
    assert ("ad_password_policy", "min_length:8") in pairs
    assert ("ad_gpo_issue", "account_lockout_disabled") in pairs
    assert ("ad_delegation", "WEB01$") in pairs
    assert ("ad_acl_issue", "GenericAll:CORP\\Helpdesk") in pairs
    assert ("secret_finding", "generic-api-key:app/.env:validated:rotation_required") in pairs
    assert ("code_finding", "high:python.lang.security.audit:app.py") in pairs
    assert ("code_finding", "critical:CVE-2025-0001:requirements.txt") in pairs
    assert ("cloud_finding", "high:s3_bucket_public_access:bucket-1") in pairs


def test_output_parser_skips_legacy_regex_for_family_owned_tools():
    from core.ai.evidence import OutputParser

    parser = OutputParser()

    def fail_legacy(*_args, **_kwargs):
        raise AssertionError("legacy RegexParser should not run for family-owned tools")

    parser.regex_parser.parse = fail_legacy
    facts = parser.parse_tool_output(
        "httpx_probe nuclei_safe security_headers_check openapi_import gitleaks_scan semgrep_scan prowler_scan ad_security_review",
        """
https://app.example.com [200] [Admin] [nginx]
{"template-id":"exposed-panel","info":{"severity":"medium"},"matched-at":"https://app.example.com/admin"}
Server: nginx
GET /users/{id} auth=unknown_or_none
{"RuleID":"generic-api-key","File":"app/.env","Verified":true}
{"results":[{"check_id":"python.lang.security.audit","path":"app.py","extra":{"severity":"HIGH"}}]}
{"Status":"FAIL","Severity":"HIGH","CheckID":"s3_bucket_public_access","ResourceId":"bucket-1"}
Shortest paths to Domain Admins: 1
""",
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("asset_url", "https://app.example.com") in pairs
    assert any(ftype == "nuclei_finding" for ftype, _value in pairs)
    assert ("web_server", "nginx") in pairs
    assert ("api_security_note", "idor_candidate:GET:/users/{id}") in pairs
    assert ("secret_finding", "generic-api-key:app/.env:validated:rotation_required") in pairs
    assert ("code_finding", "high:python.lang.security.audit:app.py") in pairs
    assert ("cloud_finding", "high:s3_bucket_public_access:bucket-1") in pairs
    assert ("ad_attack_path", "domain_admin_paths:1") in pairs


def test_output_parser_keeps_legacy_regex_for_legacy_killchain_outputs():
    from core.ai.evidence import OutputParser

    parser = OutputParser()
    facts = parser.parse_tool_output(
        "killchain_vuln_assess 10.0.0.5",
        "Total exploitable findings: 2",
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("stage_status", "vulnerability_assessment:findings:2") in pairs
