"""Residual validation and message branches for kill-chain policy."""

from __future__ import annotations

import builtins

import pytest

import core.killchain.policy as policy_module
from core.killchain.policy import (
    KILLCHAIN_STAGES,
    StageSpec,
    automated_stage_enabled,
    master_gate_message,
    policy_snapshot,
    stage_gate_message,
    stage_gate_reason,
)

pytestmark = pytest.mark.security


def _config(*, enabled=True, disabled_stage=""):
    stages = dict.fromkeys(KILLCHAIN_STAGES, True)
    if disabled_stage:
        stages[disabled_stage] = False
    return {
        "killchain": {"enabled": enabled, "stages": stages},
        "strategy": {"auto_killchain": True},
    }


def test_registry_derivation_rejects_ambiguous_public_names(monkeypatch):
    monkeypatch.setattr(
        policy_module,
        "STAGE_REGISTRY",
        (
            StageSpec(name="first", tasks=("duplicate",)),
            StageSpec(name="second", tasks=("duplicate",)),
        ),
    )

    with pytest.raises(RuntimeError, match="maps to both"):
        policy_module._derive_unique_map("tasks")


def test_runtime_config_import_failure_fails_closed(monkeypatch):
    real_import = builtins.__import__

    def fail_config_import(name, *args, **kwargs):
        if name == "config":
            raise ImportError("config unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_config_import)

    assert policy_module._runtime_config() == {}


def test_gate_reasons_and_messages_cover_every_public_outcome():
    enabled = _config()
    disabled = _config(enabled=False)
    stage_disabled = _config(disabled_stage="privesc")

    assert master_gate_message(enabled) == ""
    assert master_gate_message(disabled).startswith("[BLOCKED] killchain_disabled")
    assert stage_gate_reason("not-a-stage", enabled) == ("killchain_unknown_stage:not-a-stage")

    assert stage_gate_message("privesc", enabled) == ""
    assert stage_gate_message("privesc", disabled).startswith("[BLOCKED] killchain_disabled")
    assert stage_gate_message("not-a-stage", enabled) == ("[BLOCKED] killchain_unknown_stage:not-a-stage")
    assert stage_gate_message("privesc", stage_disabled) == ("[SKIPPED] killchain_stage_disabled:privesc")


def test_policy_snapshot_and_automation_master_are_explicit():
    enabled = _config()
    snapshot = policy_snapshot(enabled)

    assert snapshot["enabled"] is True
    assert snapshot["auto_killchain"] is True
    assert all(snapshot["stages"].values())
    assert all(snapshot["automated_stages"].values())
    assert automated_stage_enabled("privesc", enabled) is True
    assert (
        automated_stage_enabled(
            "privesc",
            {**enabled, "strategy": {"auto_killchain": False}},
        )
        is False
    )
    assert automated_stage_enabled("privesc", {**enabled, "strategy": []}) is False
