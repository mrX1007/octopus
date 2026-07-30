"""Focused branch coverage for the controlled follow-up mixin."""

from __future__ import annotations

import builtins

import pytest

from core.ai.pipeline_followups import PipelineFollowupsMixin

pytestmark = pytest.mark.contract


class _Harness(PipelineFollowupsMixin):
    def __init__(self):
        self.executed_post_access_commands = set()


def test_controlled_followup_aggregates_each_execution_result():
    pipeline = _Harness()
    pipeline._controlled_post_access_commands_from_facts = lambda *_args: [
        "first",
        "second",
    ]
    results = iter(
        [
            {
                "parsed_facts": 2,
                "new_facts": 1,
                "command_result": {"command": "first"},
                "facts": [{"id": 1}],
            },
            {
                "parsed_facts": 3,
                "new_facts": 2,
                "command_result": {"command": "second"},
                "facts": [{"id": 2}, {"id": 3}],
            },
        ]
    )
    pipeline._execute_pipeline_command = lambda *_args: next(results)

    assert pipeline._run_controlled_post_access_followups("scan", "host", []) == {
        "parsed_facts": 5,
        "new_facts": 3,
        "commands": [{"command": "first"}, {"command": "second"}],
        "facts": [{"id": 1}, {"id": 2}, {"id": 3}],
    }


def test_service_status_also_confirms_ssh_access():
    pipeline = _Harness()

    assert pipeline._facts_confirm_ssh_access([{"type": "service_status", "value": "SSH_AUTHENTICATED"}])


def test_configuration_import_failures_use_safe_defaults(monkeypatch):
    pipeline = _Harness()
    real_import = builtins.__import__

    def fail_config_import(name, *args, **kwargs):
        if name == "config":
            raise ImportError("config unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_config_import)

    assert pipeline._auto_ssh_inventory_enabled() is True
    assert pipeline._strategy_enabled("missing", default=True) is True
    assert pipeline._strategy_limit("missing", default=object()) is None
