"""Small residual branches shared by AI helper modules."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.ai.exploit_applicability import assess_exploit_command
from core.ai.pipeline_telemetry import print_efficiency_report
from core.ai.risk_analysis import RiskAnalyzer
from core.ai.task_agents import AnalysisAgent, VerificationAgent

pytestmark = pytest.mark.unit


def test_efficiency_report_omits_empty_optional_sections():
    lines = []

    print_efficiency_report(
        "scan",
        "host",
        0,
        get_facts=lambda *_args: [],
        task_outcomes=[],
        total_new_facts=0,
        goal_trace=[],
        command_trace=[],
        emit=lines.append,
    )

    assert lines == [
        "[*] Efficiency report: tasks=0, new_facts=0, total_facts=0, failed=0, blocked=0, no_fact=0, elapsed=0.0s"
    ]


def test_risk_analysis_includes_delegation_and_acl_paths():
    paths = RiskAnalyzer(
        {
            "active_directory": {
                "delegation": [{"value": "unconstrained:server"}],
                "acl_issues": [{"value": "generic_all:user"}],
            }
        }
    ).ad_attack_paths()

    assert [(item["kind"], item["severity"]) for item in paths] == [
        ("delegation", "high"),
        ("acl", "high"),
    ]


def test_exploit_assessment_accepts_malformed_shell_and_empty_module():
    assert assess_exploit_command("msf_check 'unterminated", []).applicable is True
    empty_module = assess_exploit_command("msf_check host ''", [])
    assert empty_module.applicable is True
    assert empty_module.missing_requirements == ()


def test_analysis_exception_and_verification_delegation(capsys):
    context_builder = SimpleNamespace(build_context=lambda *_args: (_ for _ in ()).throw(RuntimeError("boom")))
    analysis = AnalysisAgent(None, context_builder)

    assert analysis.analyze("scan", "host") == {
        "hypotheses": [],
        "llm_status": "failed",
        "llm_error": "analysis_exception",
    }
    assert "AnalysisAgent Error: RuntimeError" in capsys.readouterr().out

    registry = SimpleNamespace(get_commands_for_task=lambda task, target: [f"{task}:{target}"])
    verifier = SimpleNamespace(verify_claim=lambda *args: {"verified": True, "args": args})
    verification = VerificationAgent(registry, verifier)

    assert verification.execute_task("verify", "host") == ["verify:host"]
    result = verification.verify_hypothesis(
        "scan",
        "host",
        "claim",
        ["evidence"],
    )
    assert result["verified"] is True
    assert result["args"] == ("scan", "host", "claim", ["evidence"])
