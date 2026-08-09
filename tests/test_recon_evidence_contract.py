from __future__ import annotations

import json

import pytest

from core.ai.evidence import OutputParser
from core.ai.parsers.common import check_result_fact
from core.ai.parsers.recon import (
    _arguments,
    _canonical_url,
    _endpoint_value,
    _host_scope,
    _same_authority,
    _target_argument,
)
from core.ai.runtime import PipelineRuntime
from core.ai.target_model import TargetModel
from core.ai.tool_registry import ToolRegistry

pytestmark = pytest.mark.contract


@pytest.fixture
def native_provider_outputs() -> dict[str, str]:
    """Representative stdout captured from the providers' documented formats."""

    return {
        "waf_detect example.com": """[WAF DETECTION — example.com]
WAF Detected: True
WAF Type: Cloudflare
  → cf-ray header observed
""",
        "sslscan example.com": """Version: 2.1.3
Connected to 93.184.216.34
Testing SSL server example.com on port 443 using SNI name example.com

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   disabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled

  Supported Server Cipher(s):
Preferred TLSv1.3 256 bits TLS_AES_256_GCM_SHA384 Curve 25519 DHE 253
Accepted  TLSv1.2 128 bits ECDHE-RSA-AES128-GCM-SHA256 Curve 25519 DHE 253

  SSL Certificate:
Subject:  CN=example.com
Issuer:   CN=Example CA
Not valid after:  Jan  1 00:00:00 2027 GMT
""",
        "whois example.com": """Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar: RESERVED-Internet Assigned Numbers Authority
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
DNSSEC: signedDelegation
""",
        "smbclient 10.0.0.5": """
        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        public          Disk      Public Files
SMB1 disabled -- no workgroup available
""",
        "gobuster https://example.com": """===============================================================
Gobuster v3.6
===============================================================
[+] Url:                     https://example.com
Starting gobuster in directory enumeration mode
/admin                (Status: 301) [Size: 169] [--> /admin/]
/login                (Status: 200) [Size: 4210]
Finished
""",
        "dirb https://example.com": """DIRB v2.22
URL_BASE: https://example.com/
---- Scanning URL: https://example.com/ ----
+ https://example.com/admin/ (CODE:301|SIZE:169)
+ https://example.com/login (CODE:200|SIZE:4210)
END_TIME: Sun Aug  9 12:00:01 2026
""",
        "plugin_inventory": json.dumps(
            {
                "plugins": [
                    {
                        "author": "Octopus",
                        "depends_on": [],
                        "description": "Installs payload via a systemd service.",
                        "name": "systemd",
                        "requires": ["systemctl"],
                        "stage": 6,
                        "supports_check": False,
                        "type": "persistence",
                        "version": "1.0.0",
                    },
                    {
                        "author": "Octopus",
                        "depends_on": [],
                        "description": "Keys payloads to a target environment.",
                        "name": "payload_keying",
                        "requires": [],
                        "stage": 3,
                        "supports_check": False,
                        "type": "evasion",
                        "version": "1.0.0",
                    },
                ],
                "skipped": [],
            }
        ),
    }


def _check_results(facts: list[dict]) -> list[dict]:
    return [json.loads(item["value"]) for item in facts if item["type"] == "check_result"]


@pytest.mark.parametrize(
    ("command", "kind", "detail_type"),
    [
        ("waf_detect example.com", "firewall_detection", "waf_detection"),
        ("sslscan example.com", "transport_security_assessment", "tls_protocol"),
        ("whois example.com", "external_intelligence", "whois_record"),
        ("smbclient 10.0.0.5", "smb_enumeration", "smb_share"),
        ("gobuster https://example.com", "web_content_discovery", "web_endpoint"),
        ("dirb https://example.com", "web_content_discovery", "web_endpoint"),
        ("plugin_inventory", "plugin_assessment", "plugin_inventory"),
    ],
)
def test_native_provider_output_becomes_typed_evidence(
    native_provider_outputs: dict[str, str],
    command: str,
    kind: str,
    detail_type: str,
) -> None:
    facts = OutputParser().parse_tool_output(command, native_provider_outputs[command])

    checks = _check_results(facts)
    assert len(checks) == 1
    assert checks[0]["kind"] == kind
    assert checks[0]["status"] == "completed"
    assert any(item["type"] == detail_type for item in facts)
    assert all(item["trust_level"] == "trusted" for item in facts)
    assert all(item["observation_method"] == "deterministic_family_parser" for item in facts)


def test_native_provider_details_are_normalized_and_bounded(native_provider_outputs: dict[str, str]) -> None:
    parser = OutputParser()

    tls_facts = parser.parse_tool_output("sslscan example.com", native_provider_outputs["sslscan example.com"])
    tls_check = _check_results(tls_facts)[0]
    assert tls_check["summary"]["enabled_protocols"] == ["TLSv1.2", "TLSv1.3"]
    assert tls_check["summary"]["accepted_cipher_count"] == 2

    smb_facts = parser.parse_tool_output("smbclient 10.0.0.5", native_provider_outputs["smbclient 10.0.0.5"])
    smb_check = _check_results(smb_facts)[0]
    assert smb_check["summary"]["shares"] == [
        {"name": "IPC$", "type": "ipc"},
        {"name": "public", "type": "disk"},
    ]

    plugin_facts = parser.parse_tool_output("plugin_inventory", native_provider_outputs["plugin_inventory"])
    plugin_check = _check_results(plugin_facts)[0]
    assert plugin_check["summary"] == {
        "plugin_count": 2,
        "plugins": [
            {"name": "systemd", "supports_check": False, "type": "persistence"},
            {"name": "payload_keying", "supports_check": False, "type": "evasion"},
        ],
        "skipped_count": 0,
    }
    assert all(len(item["value"]) < 2_000 for item in tls_facts + smb_facts + plugin_facts)


def test_new_family_owned_commands_never_fall_back_to_legacy_regex(
    native_provider_outputs: dict[str, str],
) -> None:
    parser = OutputParser()

    def fail_legacy(*_args, **_kwargs):
        raise AssertionError("legacy RegexParser ran for a family-owned command")

    parser.regex_parser.parse = fail_legacy
    for command, output in native_provider_outputs.items():
        assert parser.parse_tool_output(command, output)

    assert parser._should_run_legacy_regex("plugin list", "[]") is False
    assert parser._should_run_legacy_regex("custom --label=nmap", "ordinary output") is True
    assert parser._should_run_legacy_regex("plugin systemd example.com run", "plugin output") is True


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("waf example.com", "waf_detect example.com"),
        ("gobuster_dir https://example.com", "gobuster https://example.com"),
        ("dirb_native https://example.com", "dirb https://example.com"),
    ],
)
def test_native_recon_aliases_use_the_canonical_family_parser(
    native_provider_outputs: dict[str, str],
    alias: str,
    canonical: str,
) -> None:
    facts = OutputParser().parse_tool_output(alias, native_provider_outputs[canonical])

    assert _check_results(facts)


def test_web_discovery_rejects_out_of_scope_result(native_provider_outputs: dict[str, str]) -> None:
    output = native_provider_outputs["dirb https://example.com"].replace(
        "+ https://example.com/admin/ (CODE:301|SIZE:169)",
        "+ https://attacker.invalid/admin/ (CODE:301|SIZE:169)",
    )

    facts = OutputParser().parse_tool_output("dirb https://example.com", output)
    endpoints = [json.loads(item["value"])["url"] for item in facts if item["type"] == "web_endpoint"]

    assert endpoints == ["https://example.com/login"]
    assert _check_results(facts)[0]["summary"]["discovered_count"] == 1


def test_empty_plugin_inventory_is_completed_evidence() -> None:
    facts = OutputParser().parse_tool_output("plugin list", "[]")

    assert _check_results(facts)[0]["summary"] == {
        "plugin_count": 0,
        "plugins": [],
        "skipped_count": 0,
    }
    assert not any(item["type"] == "plugin_inventory" for item in facts)


def test_native_parser_helpers_fail_closed_on_malformed_targets() -> None:
    assert _arguments("tool 'unterminated") == ["'unterminated"]
    assert _target_argument("tool --flag") == ""
    assert _host_scope("") == "unknown"
    assert _host_scope("http://[broken") == "http://[broken"
    assert _canonical_url("") == ""
    assert _canonical_url("x" * 2_049) == ""
    assert _canonical_url("https://example.com:not-a-port") == ""
    assert _canonical_url("ftp://example.com/file") == ""
    assert _canonical_url("https://example.com:8443/path") == "https://example.com:8443/path"
    assert _same_authority("https://example.com:bad", "https://example.com") is False
    assert _endpoint_value("ftp://example.com/file") == ""
    assert _endpoint_value(f"https://example.com/{'x' * 400}") == ""


def test_recognizable_banners_without_results_do_not_mint_completed_checks() -> None:
    parser = OutputParser()

    assert not _check_results(parser.parse_tool_output("waf_detect example.com", "[WAF DETECTION — example.com]"))
    assert not _check_results(
        parser.parse_tool_output("sslscan example.com", "Testing SSL server example.com on port 443")
    )
    no_match = parser.parse_tool_output("whois example.com", 'No match for "EXAMPLE.COM"')
    assert _check_results(no_match)[0]["summary"] == {"found": False}
    empty_shares = parser.parse_tool_output(
        "smbclient 10.0.0.5",
        "Sharename       Type      Comment\n---------       ----      -------\n",
    )
    assert _check_results(empty_shares)[0]["summary"]["share_count"] == 0


def test_web_discovery_uses_invocation_scope_and_requires_completion_marker() -> None:
    mismatched = """Gobuster v3.6
[+] Url: https://attacker.invalid
/admin (Status: 200) [Size: 1]
    Finished
"""
    facts = OutputParser().parse_tool_output("gobuster https://example.com", mismatched)
    assert facts == []

    partial = OutputParser().parse_tool_output(
        "gobuster https://example.com",
        "[+] Url: https://example.com\n/admin (Status: 200) [Size: 1]\n",
    )
    assert any(item["type"] == "web_endpoint" for item in partial)
    assert not _check_results(partial)
    assert OutputParser().parse_tool_output("gobuster", "no base URL") == []


def test_plugin_inventory_drops_untrusted_metadata_shapes() -> None:
    payload = json.dumps(
        [
            "not-an-object",
            {"name": "bad name", "type": "recon", "stage": 1},
            {"name": "bad-type", "type": "unknown", "stage": 1},
            {"name": "bad-stage", "type": "recon", "stage": "invalid"},
            {"name": "out-of-range", "type": "recon", "stage": 99},
            {
                "name": "valid",
                "type": "recon",
                "stage": 1,
                "requires": "not-a-list",
                "depends_on": ["safe", "bad dependency"],
            },
        ]
    )

    facts = OutputParser().parse_tool_output("plugin list", payload)

    assert _check_results(facts)[0]["summary"] == {
        "plugin_count": 1,
        "plugins": [{"name": "valid", "supports_check": False, "type": "recon"}],
        "skipped_count": 0,
    }
    assert len([item for item in facts if item["type"] == "plugin_inventory"]) == 1
    assert OutputParser().parse_tool_output("plugin list", "not-json") == []


def test_canonical_plugin_inventory_marks_untyped_metadata_partial() -> None:
    output = json.dumps(
        {
            "plugins": [
                {"name": "missing-support", "type": "recon", "stage": 1},
                {
                    "name": "string-support",
                    "type": "recon",
                    "stage": 1,
                    "supports_check": "yes",
                },
                {
                    "name": "boolean-stage",
                    "type": "recon",
                    "stage": True,
                    "supports_check": False,
                },
                {
                    "name": 123,
                    "type": "recon",
                    "stage": 1,
                    "supports_check": False,
                },
                {
                    "name": "string-stage",
                    "type": "recon",
                    "stage": "1",
                    "supports_check": False,
                },
                {
                    "name": "untyped-requirement",
                    "type": "recon",
                    "stage": 1,
                    "supports_check": False,
                    "requires": [123],
                },
            ],
            "skipped": [
                "not-an-object",
                {"module": "bad module name", "reason": "invalid discovery metadata"},
                {"module": 123, "reason": 456},
            ],
        }
    )

    facts = OutputParser().parse_tool_output("plugin_inventory", output)
    check = _check_results(facts)[0]

    assert check["status"] == "partial"
    assert check["summary"] == {
        "invalid_count": 9,
        "plugin_count": 0,
        "plugins": [],
        "skipped_count": 0,
    }
    assert not any(item["type"] == "plugin_inventory" for item in facts)


def test_check_result_helper_omits_empty_summary() -> None:
    payload = json.loads(check_result_fact("tool", "kind", "host", "example.com", "session")["value"])

    assert "summary" not in payload


def test_plugin_inventory_reports_partial_discovery_without_hiding_skips() -> None:
    output = json.dumps(
        {
            "plugins": [],
            "skipped": [{"module": "broken_plugin", "reason": "discovery failed"}],
        }
    )

    check = _check_results(OutputParser().parse_tool_output("plugin_inventory", output))[0]

    assert check["status"] == "partial"
    assert check["summary"] == {
        "plugin_count": 0,
        "plugins": [],
        "skipped": [{"module": "broken_plugin", "reason": "discovery failed"}],
        "skipped_count": 1,
    }


def test_plugin_check_output_becomes_typed_partial_evidence_without_legacy_regex() -> None:
    parser = OutputParser()

    def fail_legacy(*_args, **_kwargs):
        raise AssertionError("legacy RegexParser ran for a plugin check")

    parser.regex_parser.parse = fail_legacy
    output = json.dumps(
        {
            "action": "check",
            "confidence": 0.0,
            "details": "check() not implemented",
            "evidence": "",
            "plugin": "systemd",
            "supports_check": False,
            "version": "",
            "vulnerable": False,
        }
    )

    facts = parser.parse_tool_output("plugin systemd 192.0.2.10 check", output)
    check = _check_results(facts)[0]

    assert check == {
        "kind": "plugin_assessment",
        "mode": "check_only",
        "scope": {"type": "endpoint", "value": "192.0.2.10"},
        "status": "partial",
        "summary": {
            "check_supported": False,
            "confidence": 0.0,
            "plugin": "systemd",
            "vulnerable": False,
        },
        "tool": "plugin",
    }
    assert all(item["trust_level"] == "trusted" for item in facts)
    assert parser._should_run_legacy_regex("plugin systemd 192.0.2.10 run", output) is True


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "run", "plugin": "systemd", "supports_check": False, "vulnerable": False},
        {"action": "check", "plugin": "different", "supports_check": False, "vulnerable": False},
        {"action": "check", "plugin": "systemd", "supports_check": False, "vulnerable": "false"},
        {"action": "check", "plugin": "systemd", "supports_check": "false", "vulnerable": False},
        {
            "action": "check",
            "plugin": "systemd",
            "supports_check": False,
            "vulnerable": False,
            "confidence": 2.0,
        },
    ],
)
def test_plugin_check_parser_rejects_mismatched_or_untyped_payloads(payload: dict) -> None:
    assert not _check_results(
        OutputParser().parse_tool_output(
            "plugin systemd 192.0.2.10 check",
            json.dumps(payload),
        )
    )


@pytest.mark.parametrize(
    ("command", "output"),
    [
        ("waf_detect example.com", "WAF Detected: True\nWAF Type: forged"),
        ("sslscan example.com", "TLSv1.3 enabled"),
        ("whois example.com", "unstructured registrar-like text"),
        ("smbclient 10.0.0.5", "IPC$ Disk Public"),
        ("plugin list", '{"name":"not-a-list"}'),
    ],
)
def test_unrecognized_native_output_does_not_mint_check_result(command: str, output: str) -> None:
    assert not _check_results(OutputParser().parse_tool_output(command, output))


def test_critical_ai_tasks_persist_provider_evidence(
    tmp_path,
    native_provider_outputs: dict[str, str],
) -> None:
    registry = ToolRegistry()
    registry._is_tool_available = lambda _provider: True
    runtime = PipelineRuntime(str(tmp_path / "facts.db"), runner=lambda _command: "")
    expected = {
        "firewall_detection": "waf_detect example.com",
        "plugin_assessment": "plugin_inventory",
        "transport_security_assessment": "sslscan example.com",
    }

    for task, expected_command in expected.items():
        commands = registry.get_commands_for_task(task, "example.com")
        assert commands == [expected_command]
        stored = runtime.ingest_output(
            "scan",
            "example.com",
            expected_command,
            native_provider_outputs[expected_command],
        )
        assert any(item["type"] == "check_result" for item in stored)

    facts = runtime.facts.get_facts("scan", "example.com")
    model = TargetModel.from_facts("scan", "example.com", facts).to_dict()
    check_kinds = {item["kind"] for item in model["check_results"]}
    assert {
        "firewall_detection",
        "plugin_assessment",
        "transport_security_assessment",
    }.issubset(check_kinds)
    results = runtime.facts.get_command_results("scan", "example.com")
    assert len(results) == 3
    assert all(item["parsed_facts"] > 0 and item["new_facts"] > 0 for item in results)
