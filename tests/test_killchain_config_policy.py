"""Kill-chain configuration registry and final execution-gate contracts."""

import pytest

import config as runtime_config_module
from core.execution import (
    CAP_ACTIVE_TOOL,
    CAP_REGISTERED_TOOL,
    ExecutionContext,
    ExecutionPolicy,
    ToolInvocation,
)
from core.killchain.policy import (
    GOAL_STAGE_MAP,
    KILLCHAIN_STAGES,
    STAGE_REGISTRY,
    TASK_STAGE_MAP,
    TOOL_STAGE_MAP,
    killchain_enabled,
    normalize_stage,
    registered_tool_gate_reason,
    registered_tool_stage,
    stage_enabled,
)

pytestmark = pytest.mark.security


def _config(*, enabled=True, stage_overrides=None):
    stages = dict.fromkeys(KILLCHAIN_STAGES, True)
    stages.update(stage_overrides or {})
    return {
        "killchain": {"enabled": enabled, "stages": stages},
        "strategy": {"auto_killchain": True},
    }


def _approved_context():
    return ExecutionContext(
        actor="killchain-policy-test",
        origin="operator",
        capabilities=frozenset({CAP_REGISTERED_TOOL, CAP_ACTIVE_TOOL}),
        approved=True,
        approval_id="approved-policy-test",
    )


def _registered_invocation(*, executable, registered_name=None):
    return ToolInvocation(
        executable=executable,
        argv=(executable, "10.0.0.5"),
        raw_command=f"{executable} 10.0.0.5",
        registered_name=registered_name,
        targets=("10.0.0.5",),
    )


def test_stage_registry_is_the_single_source_for_public_stage_maps():
    assert tuple(spec.name for spec in STAGE_REGISTRY) == KILLCHAIN_STAGES
    assert KILLCHAIN_STAGES == (
        "vuln_assess",
        "exploitation",
        "privesc",
        "persistence",
        "lateral_movement",
        "data_exfil",
        "cleanup",
    )
    assert {
        task: spec.name
        for spec in STAGE_REGISTRY
        for task in spec.tasks
    } == TASK_STAGE_MAP
    assert {
        goal: spec.name
        for spec in STAGE_REGISTRY
        for goal in spec.goals
    } == GOAL_STAGE_MAP
    assert {
        tool: spec.name
        for spec in STAGE_REGISTRY
        for tool in spec.tools
    } == TOOL_STAGE_MAP
    assert runtime_config_module.KILLCHAIN_STAGE_KEYS == KILLCHAIN_STAGES
    assert tuple(runtime_config_module.DEFAULTS["killchain"]["stages"]) == KILLCHAIN_STAGES


@pytest.mark.parametrize(
    "alias,canonical",
    [
        (" AUTO_EXPLOIT ", "exploitation"),
        ("persist", "persistence"),
        ("lateral", "lateral_movement"),
        ("exfil", "data_exfil"),
        ("stealth_cleanup", "cleanup"),
    ],
)
def test_stage_aliases_normalize_to_registered_canonical_stage(alias, canonical):
    assert normalize_stage(alias) == canonical


@pytest.mark.parametrize(
    "tool_name,stage",
    [
        ("killchain_privesc", "privesc"),
        ("privesc", "privesc"),
        ("run_privesc", "privesc"),
        ("data_exfil", "data_exfil"),
        ("stealth_cleanup", "cleanup"),
    ],
)
def test_registered_tool_aliases_resolve_to_the_same_stage(tool_name, stage):
    assert registered_tool_stage(tool_name) == stage


@pytest.mark.parametrize(
    "malformed,master_enabled",
    [
        ([], False),
        ({}, False),
        ({"killchain": []}, False),
        ({"killchain": {"enabled": "true", "stages": {"privesc": True}}}, False),
        ({"killchain": {"enabled": True, "stages": []}}, True),
    ],
)
def test_missing_or_malformed_master_and_stage_config_fail_closed(
    malformed,
    master_enabled,
):
    assert killchain_enabled(malformed) is master_enabled
    assert not stage_enabled("privesc", malformed)
    assert registered_tool_gate_reason("killchain_privesc", malformed)


@pytest.mark.parametrize(
    "stages",
    [
        {},
        {"privesc": "true"},
        {"privilege_escalation": True},
    ],
)
def test_missing_mistyped_or_misspelled_stage_value_fails_closed(stages):
    malformed = {"killchain": {"enabled": True, "stages": stages}}

    assert not stage_enabled("privesc", malformed)
    assert registered_tool_gate_reason("privesc", malformed) == (
        "killchain_stage_disabled:privesc"
    )


def test_final_execution_policy_denies_disabled_stage_through_alias_dispatch(monkeypatch):
    monkeypatch.setattr(
        runtime_config_module,
        "CFG",
        _config(stage_overrides={"privesc": False}),
    )
    invocation = _registered_invocation(
        executable="privesc",
        registered_name="apparently_safe_registered_name",
    )

    decision = ExecutionPolicy().authorize_registered(invocation, _approved_context())

    assert not decision.allowed
    assert decision.reason == "killchain_stage_disabled:privesc"


def test_command_authorization_alias_cannot_bypass_disabled_stage(monkeypatch):
    monkeypatch.setattr(
        runtime_config_module,
        "CFG",
        _config(stage_overrides={"privesc": False}),
    )

    decision = ExecutionPolicy().authorize_command(
        "privesc 10.0.0.5",
        _approved_context(),
    )

    assert not decision.allowed
    assert decision.reason == "killchain_stage_disabled:privesc"


def test_final_execution_policy_denies_full_alias_when_master_is_off(monkeypatch):
    monkeypatch.setattr(runtime_config_module, "CFG", _config(enabled=False))
    invocation = _registered_invocation(executable="full_killchain")

    decision = ExecutionPolicy().authorize_registered(invocation, _approved_context())

    assert not decision.allowed
    assert decision.reason == "killchain_disabled"


def test_final_execution_policy_rejects_unknown_reserved_killchain_tool(monkeypatch):
    monkeypatch.setattr(runtime_config_module, "CFG", _config())
    invocation = _registered_invocation(executable="killchain_unregistered")

    decision = ExecutionPolicy().authorize_registered(invocation, _approved_context())

    assert not decision.allowed
    assert decision.reason == "killchain_unknown_tool:killchain_unregistered"


def test_enabled_approved_registered_alias_remains_authorized_without_dispatch(monkeypatch):
    monkeypatch.setattr(runtime_config_module, "CFG", _config())
    invocation = _registered_invocation(executable="privesc")

    decision = ExecutionPolicy().authorize_registered(invocation, _approved_context())

    assert decision.allowed
    assert decision.reason == "registered_tool_authorized"


def test_unregistered_name_fails_closed_even_when_killchain_is_disabled(monkeypatch):
    monkeypatch.setattr(runtime_config_module, "CFG", _config(enabled=False))
    invocation = _registered_invocation(executable="safe_fake_tool")
    context = ExecutionContext(
        actor="killchain-policy-test",
        origin="automation",
        capabilities=frozenset({CAP_REGISTERED_TOOL}),
    )

    decision = ExecutionPolicy().authorize_registered(invocation, context)

    assert not decision.allowed
    assert decision.reason == "unknown_registered_tool:safe_fake_tool"
