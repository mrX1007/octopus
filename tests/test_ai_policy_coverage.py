"""Residual state-gate branches for deterministic AI policy."""

from __future__ import annotations

import pytest

from core.ai.policy import DeterministicPolicy

pytestmark = pytest.mark.unit


def test_goal_validation_enforces_required_and_nonrepeating_goals():
    policy = DeterministicPolicy()

    assert policy.validate_goal(
        "other",
        {"next_required_capability": "service_discovery"},
        [],
    ) == {
        "goal": "service_discovery",
        "reason": "state_gate_required:service_discovery",
    }
    assert policy.validate_goal("repeat", {}, ["repeat"]) == {
        "goal": "conclude",
        "reason": "goal_already_attempted_without_state_change",
    }


def test_plan_validation_filters_empty_duplicate_absent_and_state_blocked_steps():
    policy = DeterministicPolicy()
    shared = {"task": "service_discovery"}
    plan = [
        {},
        shared,
        dict(shared),
        {"task": "api_security_testing"},
        {"task": "establish_persistence"},
    ]
    context = {
        "state": "initial_recon",
        "target_model": {"surface_states": {"api": "confirmed_absent"}},
        "automation_policy": {"auto_persistence": True},
    }

    assert policy.validate_plan(plan, context) == [shared]


def test_killchain_stage_configuration_can_disable_a_mapped_task():
    policy = DeterministicPolicy()
    assert (
        policy._allowed_by_state(
            "vulnerability_assessment",
            {"killchain_policy": {"automated_stages": {"vuln_assess": False}}},
        )
        is False
    )
    assert (
        policy._allowed_by_state(
            "vulnerability_assessment",
            {"killchain_policy": {"automated_stages": {"vuln_assess": True}}},
        )
        is True
    )


@pytest.mark.parametrize(
    ("task", "state", "automation", "expected"),
    [
        ("establish_persistence", "initial_recon", True, False),
        ("establish_persistence", "root_access_confirmed", False, False),
        ("establish_persistence", "root_access_confirmed", True, True),
        ("internal_network_recon", "initial_recon", True, False),
        ("internal_network_recon", "root_access_confirmed", False, False),
        ("internal_network_recon", "root_access_confirmed", True, True),
        ("exfiltrate_data", "initial_recon", True, False),
        ("exfiltrate_data", "persistence_established", False, False),
        ("exfiltrate_data", "persistence_established", True, True),
        ("stealth_cleanup", "initial_recon", True, False),
        ("stealth_cleanup", "exfiltration_completed", False, False),
        ("stealth_cleanup", "exfiltration_completed", True, True),
    ],
)
def test_post_access_state_and_automation_flags_are_both_required(
    task,
    state,
    automation,
    expected,
):
    key = {
        "establish_persistence": "auto_persistence",
        "internal_network_recon": "auto_internal_recon",
        "exfiltrate_data": "auto_data_exfil",
        "stealth_cleanup": "auto_cleanup",
    }[task]

    assert (
        DeterministicPolicy()._allowed_by_state(
            task,
            {"state": state, "automation_policy": {key: automation}},
        )
        is expected
    )
