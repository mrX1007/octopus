"""Focused branch coverage for deterministic director decisions."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.ai import director as director_module
from core.ai.director import DirectorLLM

pytestmark = pytest.mark.unit


def _context(state="initial_recon", **extra):
    return {
        "state": state,
        "services": [],
        "open_questions": [],
        "next_required_capability": "conclude",
        "automation_policy": {},
        **extra,
    }


def test_decide_goal_short_circuits_repeated_goal(monkeypatch):
    monkeypatch.setattr(
        director_module,
        "ask_ollama",
        lambda *_args, **_kwargs: pytest.fail("LLM must not be called"),
    )

    result = DirectorLLM().decide_goal(_context(), ["service_discovery"] * 3)

    assert result == {
        "thought": "Loop detected — same goal 3x",
        "goal": "conclude",
        "llm_status": "not_called",
    }


def test_decide_goal_error_contract_uses_fallback(monkeypatch):
    monkeypatch.setattr(
        director_module,
        "ask_ollama",
        lambda *_args, **_kwargs: "[!] adapter unavailable",
    )

    result = DirectorLLM().decide_goal(_context(), [])

    assert result["goal"] == "service_discovery"
    assert result["llm_status"] == "failed"
    assert result["fallback"] is True


def test_decide_goal_accepts_policy_override(monkeypatch):
    instance = DirectorLLM()
    instance.policy = SimpleNamespace(
        validate_goal=lambda *_args: {
            "goal": "service_discovery",
            "reason": "required",
        }
    )
    monkeypatch.setattr(
        director_module,
        "ask_ollama",
        lambda *_args, **_kwargs: '{"goal":"cleanup","thought":"try"}',
    )

    result = instance.decide_goal(_context(), [])

    assert result["goal"] == "service_discovery"
    assert "policy forced" in result["thought"]
    assert result["llm_status"] == "ok"


def test_decide_goal_applies_local_validation_override(monkeypatch):
    instance = DirectorLLM()
    instance.policy = SimpleNamespace(
        validate_goal=lambda goal, *_args: {"goal": goal, "reason": "allowed"}
    )
    instance._validate_goal = lambda *_args: "conclude"
    monkeypatch.setattr(
        director_module,
        "ask_ollama",
        lambda *_args, **_kwargs: '{"goal":"cleanup","thought":"try"}',
    )

    result = instance.decide_goal(_context(), ["conclude", "conclude", "conclude"])

    assert result["goal"] == "conclude"
    assert "overridden" in result["thought"]


def test_validate_goal_covers_specific_state_and_question_overrides():
    director = DirectorLLM()

    assert director._validate_goal(
        "service_discovery",
        _context("recon_completed", services=["ssh"]),
        [],
    ) == "vulnerability_assessment"
    assert director._validate_goal(
        "data_exfiltration",
        _context(
            "root_access_confirmed",
            open_questions=["internal_network_recon_pending", "data_exfiltration_pending"],
            automation_policy={"auto_data_exfil": True},
        ),
        [],
    ) == "internal_reconnaissance"
    assert director._validate_goal(
        "conclude",
        _context(
            "root_access_confirmed",
            open_questions=["post_access_inventory_needed"],
        ),
        [],
    ) == "post_access_inventory"
    assert director._validate_goal(
        "persistence",
        _context(
            "root_access_confirmed",
            automation_policy={"auto_persistence": True},
        ),
        [],
    ) == "conclude"
    assert director._validate_goal(
        "persistence",
        _context(
            "root_access_confirmed",
            open_questions=["persistence_needed"],
            automation_policy={"auto_persistence": True},
        ),
        [],
    ) == "persistence"
    assert director._validate_goal(
        "post_access_inventory",
        _context("root_access_confirmed"),
        [],
    ) == "conclude"


def test_killchain_and_automation_policy_can_disable_goals():
    director = DirectorLLM()

    assert director._goal_allowed_by_policy(
        "persistence",
        {
            "automation_policy": {"auto_persistence": True},
            "killchain_policy": {"automated_stages": {"persistence": False}},
        },
    ) is False
    assert director._goal_allowed_by_policy(
        "cleanup",
        {"automation_policy": {"auto_cleanup": True}},
    ) is True
    assert director._goal_allowed_by_policy("cleanup", {"automation_policy": {}}) is False


def test_next_chain_handles_unknown_skipped_and_exhausted_goals():
    director = DirectorLLM()

    assert director._next_in_chain("unknown", []) == "conclude"
    assert director._next_in_chain(
        "service_discovery",
        ["vulnerability_assessment"],
    ) == "credential_harvesting"
    assert director._next_in_chain("cleanup", ["conclude"]) == "conclude"


@pytest.mark.parametrize(
    ("state", "questions", "services", "history", "expected"),
    [
        ("initial_recon", [], [], [], "service_discovery"),
        ("recon_completed", ["vulnerabilities_unknown"], [], [], "vulnerability_assessment"),
        ("recon_completed", ["credential_unknown"], [], [], "credential_harvesting"),
        ("recon_completed", [], ["ssh"], [], "vulnerability_assessment"),
        ("recon_completed", [], [], [], "conclude"),
        ("vulnerabilities_found", ["service_discovery_needed"], [], [], "service_discovery"),
        ("vulnerabilities_found", ["verification_needed"], [], [], "vulnerability_assessment"),
        ("vulnerabilities_found", [], [], [], "credential_harvesting"),
        ("credentials_found", ["service_discovery_needed"], [], [], "service_discovery"),
        ("credentials_found", ["cpanel_session"], [], [], "vulnerability_assessment"),
        ("credentials_found", [], [], ["privilege_escalation"], "conclude"),
        ("credentials_found", ["privilege_escalation_path_unknown"], [], [], "privilege_escalation"),
        ("credentials_found", [], [], [], "vulnerability_assessment"),
        ("root_access_confirmed", ["post_access_inventory_needed"], [], [], "post_access_inventory"),
        ("root_access_confirmed", ["persistence_needed"], [], [], "persistence"),
        ("root_access_confirmed", ["internal_network_recon_pending"], [], [], "internal_reconnaissance"),
        ("root_access_confirmed", [], [], [], "conclude"),
        ("persistence_established", ["internal_network_recon_pending"], [], [], "internal_reconnaissance"),
        ("persistence_established", ["data_exfiltration_pending"], [], [], "data_exfiltration"),
        ("persistence_established", [], [], [], "conclude"),
        ("internal_recon_completed", ["data_exfiltration_pending"], [], [], "data_exfiltration"),
        ("internal_recon_completed", ["persistence_needed"], [], [], "persistence"),
        ("internal_recon_completed", [], [], [], "conclude"),
        ("exfiltration_completed", ["cleanup_needed"], [], [], "cleanup"),
        ("exfiltration_completed", [], [], [], "conclude"),
        ("cleanup_completed", [], [], [], "conclude"),
        ("unknown", [], [], [], "conclude"),
    ],
)
def test_fallback_state_machine_routes_every_outcome(
    state,
    questions,
    services,
    history,
    expected,
):
    result = DirectorLLM()._fallback_logic(
        _context(state, open_questions=questions, services=services),
        history,
    )
    assert result["goal"] == expected


def test_fallback_honors_explicit_required_capability_and_pick_deduplicates():
    director = DirectorLLM()
    result = director._fallback_logic(
        _context(
            "recon_completed",
            next_required_capability="credential_harvesting",
        ),
        [],
    )

    assert result["goal"] == "credential_harvesting"
    assert director._pick("cleanup", ["cleanup"], "reason")["goal"] == "conclude"
