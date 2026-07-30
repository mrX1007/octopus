"""Focused result-shape and fallback coverage for the mission planner."""

from __future__ import annotations

import pytest

import core.ai.planner as planner_module
from core.ai.planner import MissionPlanner, PlanCompilation

pytestmark = pytest.mark.contract


def test_plan_compilation_serializes_detached_mappings():
    step = {"agent": "DiscoveryAgent", "task": "service_discovery"}
    rejection = {"task": "unknown", "reason": "capability_no_provider"}

    payload = PlanCompilation((step,), (rejection,)).to_dict()

    assert payload == {"plan": [step], "rejected": [rejection]}
    assert payload["plan"][0] is not step
    assert payload["rejected"][0] is not rejection


def test_planner_accepts_json_object(monkeypatch):
    monkeypatch.setattr(
        planner_module,
        "ask_ollama",
        lambda *_args, **_kwargs: '{"thought":"ok","plan":[]}',
    )

    result = MissionPlanner().create_plan("cleanup", {}, [])

    assert result == {"thought": "ok", "plan": [], "llm_status": "ok"}


def test_planner_error_contract_uses_goal_fallback(monkeypatch, capsys):
    monkeypatch.setattr(
        planner_module,
        "ask_ollama",
        lambda *_args, **_kwargs: "[!] provider unavailable",
    )

    result = MissionPlanner().create_plan(
        "service_discovery",
        {"state": "initial_recon"},
        ["old-task"] * 10,
    )

    assert result["llm_status"] == "failed"
    assert result["fallback"] is True
    assert result["llm_error"] == "[!] provider unavailable"
    assert result["plan"][0]["task"] == "service_discovery"
    assert "Planner LLM Error" in capsys.readouterr().out


def test_planner_rejects_scalar_json_and_uses_unknown_goal_fallback(
    monkeypatch,
):
    monkeypatch.setattr(
        planner_module,
        "ask_ollama",
        lambda *_args, **_kwargs: "42",
    )

    result = MissionPlanner().create_plan("unknown-goal", {}, [])

    assert result["plan"] == []
    assert result["thought"] == "fallback: unknown goal, concluding"
    assert result["llm_status"] == "failed"
    assert "returned int" in result["llm_error"]


@pytest.mark.parametrize(
    ("goal", "tasks"),
    [
        (
            "vulnerability_assessment",
            ["vulnerability_assessment", "web_application_mapping", "analyze_vulnerabilities"],
        ),
        ("credential_harvesting", ["credential_harvesting", "test_credentials"]),
        ("privilege_escalation", ["find_privesc_vectors", "exploit_privesc"]),
        ("post_access_inventory", ["post_access_inventory"]),
        ("persistence", ["establish_persistence"]),
        ("internal_reconnaissance", ["internal_network_recon"]),
        ("data_exfiltration", ["exfiltrate_data"]),
        ("cleanup", ["stealth_cleanup"]),
    ],
)
def test_every_named_fallback_has_the_expected_bounded_tasks(goal, tasks):
    result = MissionPlanner()._fallback_logic(goal)

    assert [step["task"] for step in result["plan"]] == tasks
    assert len(result["plan"]) <= 3
