"""Focused branch fixtures for every first-party parser family."""

from __future__ import annotations

import json

import pytest

from core.ai.parsers import (
    ADParser,
    APIParser,
    ASMParser,
    CloudParser,
    CodeParser,
    MSFParser,
    NetworkGraphParser,
    NmapParser,
    PluginParser,
    SecretsParser,
    SSHParser,
    TemplateParser,
    WebParser,
)
from core.ai.parsers.common import BaseParser

pytestmark = pytest.mark.unit


def _pairs(facts: list[dict[str, object]]) -> set[tuple[object, object]]:
    return {(item["type"], item["value"]) for item in facts}


def test_ad_parser_ignores_empty_or_placeholder_matches() -> None:
    parser = ADParser()

    assert parser.parse("ad_enum", "Domain: unknown", "session") == []
    assert parser.parse("ad_enum", "User:   ", "session") == []
    assert parser.parse("ad_enum", "Delegation:   ", "session") == []


def test_api_parser_emits_each_api_auth_note_branch() -> None:
    output = "[API AUTH CHECK]\nNOTE possible_missing_auth\nNOTE auth_required"

    assert _pairs(APIParser().parse("api_auth_check", output, "session")) == {
        ("api_security_note", "possible_missing_auth"),
        ("api_security_note", "auth_required"),
    }


def test_asm_parser_does_not_treat_numeric_status_as_technology() -> None:
    facts = ASMParser().parse("httpx", "https://Example.TEST [200]", "session")

    assert ("http_status", "200:https://Example.TEST [200]") in _pairs(facts)
    assert not any(item["type"] == "technology" for item in facts)


def test_cloud_parser_skips_invalid_json_and_failed_check_without_identifier() -> None:
    output = '{not-json\n{"status":"fail","severity":"high","service":"s3"}'

    assert CloudParser().parse("prowler", output, "session") == []


def test_code_parser_handles_invalid_json_misconfiguration_and_checkov_shapes() -> None:
    trivy = {
        "Results": [
            {
                "Target": "image:latest",
                "Misconfigurations": [{"Severity": "HIGH", "ID": "CFG-001"}],
            }
        ]
    }
    checkov = {
        "results": {
            "failed_checks": [
                {
                    "bc_check_id": "BC_AWS_1",
                    "file_abs_path": "/src/main.tf",
                    "severity": "MEDIUM",
                }
            ]
        }
    }
    output = "\n".join(("{not-json", json.dumps(trivy), json.dumps(checkov)))

    assert _pairs(CodeParser().parse("trivy checkov", output, "session")) == {
        ("code_finding", "high:CFG-001:image:latest"),
        ("code_finding", "medium:BC_AWS_1:/src/main.tf"),
    }


def test_base_parser_default_is_empty() -> None:
    assert BaseParser().parse("tool", "output", "session") == []


def test_msf_parser_uses_default_ssh_service_and_records_uid_zero() -> None:
    output = "[+] 10.0.0.5:22 - Success: 'root:password'\nuid=0(root)"

    facts = MSFParser().parse("msf_run 10.0.0.5 auxiliary/login", output, "session")

    assert ("credential", "ssh_login_success:root@10.0.0.5") in _pairs(facts)
    assert ("system_access", "uid=0") in _pairs(facts)


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("OptionValidateError: RHOSTS is required", "msf_check_invalid_options:exploit/test"),
        ("The target does not appear to be vulnerable", "msf_check_not_vulnerable:exploit/test"),
    ],
)
def test_msf_parser_returns_explicit_negative_or_invalid_status(output: str, expected: str) -> None:
    facts = MSFParser().parse("msf_check 10.0.0.5 exploit/test", output, "session")

    assert ("service_status", expected) in _pairs(facts)


def test_msf_parser_positive_without_rport_and_opened_session() -> None:
    output = "The target appears to be vulnerable\nMeterpreter session 1 opened"

    facts = MSFParser().parse("msf_run 10.0.0.5 exploit/test", output, "session")

    assert ("vulnerability", "msf_check_positive:exploit/test") in _pairs(facts)
    assert ("exploit_success", "msf_session_opened:exploit/test") in _pairs(facts)
    assert not any(item["type"] == "vulnerability_endpoint" for item in facts)


def test_network_parser_rejects_invalid_ip_address() -> None:
    assert NetworkGraphParser()._is_internal_host("999.999.999.999") is False


def test_nmap_parser_handles_open_port_without_version() -> None:
    facts = NmapParser().parse("custom", "80/tcp open http\n", "session")

    assert _pairs(facts) == {("port_open", "80/tcp (http)")}


def test_plugin_parser_records_unavailable_tool() -> None:
    facts = PluginParser().parse("plugin cpanel_check", "tool_unavailable: not installed", "session")

    assert _pairs(facts) == {("tool_unavailable", "plugin")}


def test_secrets_parser_recovers_from_invalid_json_line() -> None:
    facts = SecretsParser().parse("gitleaks", "{broken api_key payload", "session")

    assert _pairs(facts) == {("secret_finding", "generic:{broken api_key payload:unvalidated:rotation_required")}


def test_ssh_parser_records_authentication_failure() -> None:
    facts = SSHParser().parse("ssh_session", "SSH connection failed: auth failed", "session")

    assert _pairs(facts) == {("service_status", "ssh_auth_failed:unknown")}


def test_template_parser_recovers_from_json_error_and_parses_text_finding() -> None:
    output = "{not-json\n[cve-test] [http] [high] https://example.test/path"

    facts = TemplateParser().parse("nuclei", output, "session")

    assert ("nuclei_finding", "info:unknown::unknown") in _pairs(facts)
    assert ("nuclei_finding", "high:cve-test:https://example.test/path") in _pairs(facts)


def test_web_parser_handles_invalid_endpoint_and_unavailable_content_tool() -> None:
    output = "http:///missing\nNo HTTP(S) response\nTool not found"

    facts = WebParser().parse("scrapling", output, "session")

    assert _pairs(facts) == {
        ("service_status", "web_content_discovery_skipped:no_http_response"),
        ("tool_unavailable", "scrapling"),
    }


def test_web_parser_accepts_fully_hardened_cookie() -> None:
    output = "Set-Cookie: sid=value; HttpOnly; Secure; SameSite=Lax"

    facts = WebParser().parse("curl_headers", output, "session")

    assert not any("cookie_missing_" in str(item["value"]) for item in facts)


def test_web_parser_does_not_flag_non_reflective_cors_origin() -> None:
    output = "Origin: https://origin.test\nAccess-Control-Allow-Origin: https://allowed.test"

    facts = WebParser().parse("cors_check", output, "session")

    assert ("web_security_note", "cors_allow_origin:https://allowed.test") in _pairs(facts)
    assert ("web_security_note", "cors_reflective_or_wildcard_origin") not in _pairs(facts)


def test_web_parser_empty_session_profile_and_authenticated_crawl_fields() -> None:
    output = "LINK https://example.test/plain\nalg: RS256\nkid: signing-key"
    tool = "session_profile_import authenticated_crawl jwt_analyze"

    facts = WebParser().parse(tool, output, "session")

    assert ("web_link", "https://example.test/plain") in _pairs(facts)
    assert ("jwt_metadata", "alg:RS256") in _pairs(facts)
    assert ("jwt_metadata", "kid:signing-key") in _pairs(facts)
    assert not any(item["type"] == "web_session" for item in facts)
    assert not any("jwt_review_required_alg" in str(item["value"]) for item in facts)


def test_web_parser_jwt_kid_without_algorithm() -> None:
    facts = WebParser().parse("jwt_analyze", "kid: key-only", "session")

    assert _pairs(facts) == {("jwt_metadata", "kid:key-only")}


def test_web_parser_plain_javascript_route_is_not_an_api_endpoint() -> None:
    facts = WebParser().parse("js_route_extract", "Routes:\n/plain", "session")

    assert _pairs(facts) == {("js_route", "/plain")}


def test_web_parser_proxy_import_skips_invalid_endpoint() -> None:
    output = "URL http:///missing\nISSUE Informational response"

    facts = WebParser().parse("burp_import", output, "session")

    assert ("asset_url", "http:///missing") in _pairs(facts)
    assert ("proxy_finding", "Informational response") in _pairs(facts)
    assert not any(item["type"] == "web_endpoint" for item in facts)
