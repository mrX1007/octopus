"""Focused coverage for fail-closed evidence and reconnaissance branches."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.ai import evidence as evidence_module
from core.ai.evidence import EvidenceVerifier, OutputParser, StructuredParser
from core.ai.fact_predicates import TARGET_CONTROLLED, TRUSTED
from core.tools import recon_tools

pytestmark = pytest.mark.unit


class _Snapshot:
    def __init__(self, facts: list[dict]) -> None:
        self._facts = tuple(facts)

    def decision_facts(self) -> tuple[dict, ...]:
        return self._facts


def test_hard_evidence_policy_rejects_matching_inference_grade_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fact = {
        "id": 17,
        "type": "system_access",
        "value": "uid=0",
        "source_identity": "ssh_inventory",
        "confidence": 91,
        "assessment": {"status": "inferred"},
    }
    store = SimpleNamespace(get_facts=MagicMock(return_value=[fact]))
    monkeypatch.setattr(
        evidence_module.EvaluatedFactSnapshot,
        "build",
        MagicMock(return_value=_Snapshot([fact])),
    )

    result = EvidenceVerifier(store).verify_claim("scan", "host", "root_access_confirmed")

    assert result["status"] == "rejected"
    assert "requires direct hard evidence" in result["reason"]
    assert result["policy_id"] == "access.root.v1"


def test_evidence_term_helpers_cover_workflow_and_nonmatching_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = EvidenceVerifier(SimpleNamespace())

    assert (
        verifier._workflow_marker_cannot_prove_claim(
            "typed_coverage_gaps_status_pending",
            "coverage verification pending",
        )
        is False
    )
    assert (
        verifier._workflow_marker_cannot_prove_claim(
            "coverage_gaps_status_pending",
            "root access exposed",
        )
        is True
    )
    assert verifier._workflow_marker_cannot_prove_claim("service_ssh", "root access exposed") is False
    assert verifier._workflow_marker_cannot_prove_claim("service_pending", "verification pending") is False
    assert verifier._workflow_marker_cannot_prove_claim("service_needed", "routine observation") is False
    assert (
        verifier._requirement_supported(
            "services[0].banner: nginx",
            {"service_version_nginx"},
        )
        is True
    )
    assert verifier._requirement_supported("service:ssh", set()) is False
    assert (
        verifier._supporting_fact_ids(
            "service:ssh",
            [{"id": 9, "type": "port_open", "value": "443/tcp (https)"}],
        )
        == []
    )

    class BrokenBuilder:
        def __init__(self, _store, _resolver) -> None:
            pass

        @staticmethod
        def build_context(_scan_id: str, _host: str) -> dict:
            raise RuntimeError("derived context unavailable")

    monkeypatch.setattr("core.ai.context_builder.ContextBuilder", BrokenBuilder)
    terms = verifier._build_evidence_terms(
        "scan",
        "host",
        [
            {"type": "service_status", "value": "ssh_authenticated"},
            {"type": "system_access", "value": "root_access_confirmed"},
            {"type": "observation", "value": "no authority signal"},
        ],
    )
    assert "ssh_access_confirmed" in terms

    verifier._add_gap_evidence_terms(
        terms,
        {"surface": "web", "check": "nuclei", "status": "needed"},
        "typed_coverage_gaps",
    )
    assert "web_nuclei_needed" in terms
    assert "coverage_gap_web_nuclei_needed" in terms
    verifier._add_gap_evidence_terms(
        terms,
        {"surface": "web", "check": "", "status": "needed", "metadata": {}},
        "typed_coverage_gaps",
    )


def test_structured_plugin_envelope_covers_artifact_and_error_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = StructuredParser()
    envelope = json.dumps(
        {
            "plugin": "alpha.plugin",
            "success": False,
            "artifacts": ["", "report.json", {"kind": "summary"}],
        }
    )

    facts = parser.parse(
        "plugin alpha.plugin target.test scan",
        f"diagnostic prefix\n{envelope}\n--- plugin output ---\nuntrusted trailing text",
        "session-1",
    )

    assert [(fact["type"], fact["value"]) for fact in facts] == [
        ("plugin_result", "alpha.plugin:failed"),
        ("plugin_artifact", "report.json"),
        ("plugin_artifact", "{'kind': 'summary'}"),
    ]
    assert {fact["trust_level"] for fact in facts} == {TARGET_CONTROLLED}
    assert parser.parse(
        "plugin alpha.plugin target.test",
        '{"plugin":"alpha.plugin","success":true,"artifacts":"not-a-list"}',
        "session-2",
    ) == [
        {
            "type": "plugin_result",
            "value": "alpha.plugin:success",
            "confidence": 85,
            "session_id": "session-2",
            "trust_level": TARGET_CONTROLLED,
            "observation_method": "target_controlled_stdout",
        }
    ]
    assert parser.parse("plugin alpha.plugin target.test", "plain output", "session-3") == []
    assert (
        parser.parse(
            "plugin alpha.plugin target.test",
            '{"plugin":"other.plugin","success":true}',
            "session-3",
        )
        == []
    )
    assert parser.parse("plugin alpha.plugin target.test", "{invalid-json}", "session-3") == []

    real_json_loads = json.loads
    monkeypatch.setattr(json, "loads", lambda _text: [])
    assert parser.parse("plugin alpha.plugin target.test", "{}", "session-4") == []
    monkeypatch.setattr(json, "loads", real_json_loads)


@pytest.mark.parametrize(
    ("tool_name", "fact", "expected"),
    [
        ("ad_enum", {"type": "ad_computers", "value": "dc01"}, True),
        ("ssh_inventory", {"type": "container_runtime", "value": "docker"}, True),
        ("asrep_roast", {"type": "kerberos_hashes", "value": "hashes.txt"}, True),
        ("wmiexec", {"type": "lateral_access", "value": "administrator@host"}, True),
        ("network_recon", {"type": "internal_network", "value": "10.0.0.0/24"}, True),
        (
            "network_recon",
            {"type": "post_exploit_stage", "value": "internal_network_recon_completed"},
            True,
        ),
        ("ssh_session", {"type": "service_status", "value": "ssh_authenticated"}, True),
        (
            "network_recon",
            {"type": "service_status", "value": "internal_network_recon_completed"},
            True,
        ),
        ("searchsploit", {"type": "exploit_reference", "value": "CVE-2026-12345"}, True),
        ("curl_headers", {"type": "exploit_reference", "value": "CVE-2026-12345"}, False),
    ],
)
def test_tool_bound_fact_schema_tail(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    fact: dict,
    expected: bool,
) -> None:
    parser = OutputParser()
    monkeypatch.setattr(parser, "_tool_identity", lambda value: str(value).split()[0].casefold())

    assert parser._tool_can_emit_decision_fact(tool_name, fact) is expected


def test_tool_identity_and_fact_stamping_cover_alias_promotion_and_downgrade() -> None:
    parser = OutputParser()

    assert parser._tool_identity("jmx2rce scan host.test") == "jmx2rce_scan"

    promoted = parser._stamp_parser_facts(
        "manual_recon host.test",
        [{"type": "port_open", "value": "443/tcp (https)"}],
        observation_method="manual_recon_parser",
        default_trust=TARGET_CONTROLLED,
    )
    assert promoted == [
        {
            "type": "port_open",
            "value": "443/tcp (https)",
            "source_identity": "nmap",
            "trust_level": TRUSTED,
            "observation_method": "deterministic_manual_recon_port_parser",
        }
    ]

    downgraded = parser._stamp_parser_facts(
        "curl_headers https://host.test",
        [{"type": "system_access", "value": "uid=0"}],
        observation_method="regex_parser",
    )
    assert downgraded[0]["trust_level"] == TARGET_CONTROLLED
    assert downgraded[0]["observation_method"] == "target_controlled_stdout"

    observation = parser._stamp_parser_facts(
        "custom_tool host.test",
        [{"type": "observation", "value": "bounded metadata"}],
        observation_method="structured_parser",
    )
    assert observation[0]["trust_level"] == TRUSTED
    assert observation[0]["observation_method"] == "structured_parser"


def test_nmap_validation_and_scope_denials_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recon_tools, "get_tool_config", lambda _name: {})
    run_tool = MagicMock(side_effect=AssertionError("execution must remain blocked"))
    monkeypatch.setattr(recon_tools, "run_tool", run_tool)
    monkeypatch.setattr(
        recon_tools,
        "validate_registered_arguments",
        MagicMock(side_effect=ValueError("unsafe_nmap_arguments")),
    )

    invalid = recon_tools.run_nmap("scan.example", extra_flags=["-sV"])
    assert invalid == "[!] Execution denied: unsafe_nmap_arguments"

    monkeypatch.setattr(recon_tools, "validate_registered_arguments", MagicMock(return_value=()))
    monkeypatch.setattr(
        recon_tools,
        "authorize_final_registered_arguments",
        MagicMock(return_value=SimpleNamespace(allowed=False, reason="target_out_of_scope")),
    )
    denied = recon_tools.run_nmap("scan.example", extra_flags=["-sV"])
    assert denied == "[!] Execution denied: target_out_of_scope"
    run_tool.assert_not_called()


def test_rustscan_file_validation_and_scope_denials_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recon_tools,
        "get_tool_config",
        lambda name: {"timeout": 19, "default_flags": ["--", "-sV"]} if name == "rustscan" else {},
    )
    monkeypatch.setattr(recon_tools.Path, "is_file", lambda _path: True)
    assert recon_tools.run_rustscan("targets.txt") == "[!] Execution denied: ambiguous_rustscan_address_file"

    monkeypatch.setattr(recon_tools.Path, "is_file", lambda _path: False)
    validated = []

    def reject_arguments(name, arguments):
        validated.append((name, arguments))
        raise ValueError("unsupported_rustscan_indirection")

    monkeypatch.setattr(recon_tools, "validate_registered_arguments", reject_arguments)
    invalid = recon_tools.run_rustscan("scan.example")
    assert invalid == "[!] Execution denied: unsupported_rustscan_indirection"
    assert validated == [("rustscan", ("-a", "scan.example", "--no-config", "--", "-sV"))]

    monkeypatch.setattr(recon_tools, "validate_registered_arguments", MagicMock(return_value=()))
    monkeypatch.setattr(
        recon_tools,
        "authorize_final_registered_arguments",
        MagicMock(return_value=SimpleNamespace(allowed=False, reason="missing_target_scope")),
    )
    run_tool = MagicMock(side_effect=AssertionError("execution must remain blocked"))
    monkeypatch.setattr(recon_tools, "run_tool", run_tool)
    denied = recon_tools.run_rustscan("scan.example", extra_flags=["--no-config", "--", "-sV"])
    assert denied == "[!] Execution denied: missing_target_scope"
    run_tool.assert_not_called()


def test_curl_headers_rejects_unsafe_final_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recon_tools, "get_tool_config", lambda _name: {"timeout": 23})
    monkeypatch.setattr(recon_tools, "_url_candidates", lambda _target: ["https://host.test/path"])
    monkeypatch.setattr(
        recon_tools,
        "validate_registered_arguments",
        MagicMock(side_effect=ValueError("unsupported_curl_indirection:--proxy")),
    )
    run_tool = MagicMock(side_effect=AssertionError("execution must remain blocked"))
    monkeypatch.setattr(recon_tools, "run_tool", run_tool)

    result = recon_tools.run_curl_headers("host.test")

    assert result == "[!] Execution denied: unsupported_curl_indirection:--proxy"
    run_tool.assert_not_called()
