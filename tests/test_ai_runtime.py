"""Tests for the canonical pipeline/dispatch/fact runtime boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.ai.command_scheduler import CommandDecision
from core.ai.fact_store import FactStore
from core.ai.runtime import PipelineRuntime
from core.execution import ExecutionContext, ExecutionStatus

pytestmark = pytest.mark.contract


class StubScheduler:
    def __init__(self, action: str = "execute"):
        self.action = action
        self.calls = []

    def decide(self, command, facts, executed_keys, execution_context=None):
        self.calls.append((command, list(facts), set(executed_keys), execution_context))
        return CommandDecision(command, f"key:{command}", self.action, "stub")


class StubParser:
    def parse_tool_output(self, command, output):
        return [
            {
                "type": "credential",
                "value": "alice:runtime-canary-password (cached)",
                "confidence": 91,
                "session_id": "session-1",
            },
            {"type": "service_status", "value": f"parsed:{command}:{output}"},
        ]


def runtime(tmp_path: Path, *, action: str = "execute"):
    calls = []

    def runner(command):
        calls.append(command)
        return f"output:{command}"

    instance = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=runner,
        scheduler=StubScheduler(action),
        parser=StubParser(),
    )
    return instance, calls


def execution_context():
    return ExecutionContext.automatic(
        target_scope=("example.com",),
        actor="runtime-test",
        origin="test",
    )


def test_runtime_owns_one_fact_parser_scheduler_and_reporter(tmp_path: Path):
    instance, _ = runtime(tmp_path)

    assert isinstance(instance.facts, FactStore)
    assert instance.reporter.fact_store is instance.facts
    assert instance.scheduler.calls == []


def test_decide_delegates_all_state_to_scheduler(tmp_path: Path):
    instance, _ = runtime(tmp_path)
    context = execution_context()
    facts = [{"type": "port_open", "value": "22/tcp"}]

    decision = instance.decide("nmap example.com", facts, {"old"}, context)

    assert decision.action == "execute"
    assert instance.scheduler.calls == [("nmap example.com", facts, {"old"}, context)]


def test_execute_binds_context_and_hides_raw_output_from_repr(tmp_path: Path):
    instance, calls = runtime(tmp_path)
    decision = CommandDecision(
        "tool example.com password=runtime-secret",
        "key",
        "execute",
        "allowed",
    )

    result = instance.execute(decision, execution_context())

    assert result.executed
    assert calls == [decision.command]
    assert result.output.startswith("output:tool example.com password=[REDACTED secret://")
    assert "runtime-secret" not in result.output
    assert "runtime-secret" not in result.audit_command
    assert "runtime-secret" not in repr(result)
    assert result.to_audit_dict()["output_bytes"] == len(result.output.encode())


def test_execute_skip_never_calls_runner(tmp_path: Path):
    instance, calls = runtime(tmp_path)
    decision = CommandDecision("blocked", "key", "skip", "policy")

    result = instance.execute(decision, execution_context())

    assert result.status is ExecutionStatus.BLOCKED
    assert result.executed is False
    assert result.output == ""
    assert result.request_id
    assert result.execution_id
    assert calls == []
    assert result.to_audit_dict()["output_bytes"] == 0


def test_dispatch_combines_decision_and_execution(tmp_path: Path):
    instance, calls = runtime(tmp_path)

    result = instance.dispatch("nmap example.com", [], set(), execution_context())

    assert result.executed
    assert calls == ["nmap example.com"]


def test_dispatch_respects_scheduler_skip(tmp_path: Path):
    instance, calls = runtime(tmp_path, action="skip")

    result = instance.dispatch("nmap example.com", [], set(), execution_context())

    assert not result.executed
    assert calls == []


def test_parse_and_ingest_use_one_parser_and_redacted_fact_store(tmp_path: Path):
    instance, _ = runtime(tmp_path)
    parsed = instance.parse_output("stub", "raw")

    stored = instance.ingest_output("scan", "host", "stub", "raw")
    facts = instance.facts.get_facts("scan", "host")

    assert len(parsed) == 2
    assert len(stored) == 2
    assert all(item["created"] for item in stored)
    assert stored[0]["value"].startswith("alice:secret://")
    assert stored[0]["secret_refs"]
    assert "runtime-canary-password" not in repr(stored)
    assert "runtime-canary-password" not in repr(facts)


def test_ingest_accepts_explicit_safe_source_and_deduplicates(tmp_path: Path):
    instance, _ = runtime(tmp_path)

    first = instance.ingest_output("scan", "host", "stub", "same", source="fixture")
    second = instance.ingest_output("scan", "host", "stub", "same", source="fixture")

    assert all(item["created"] for item in first)
    assert not any(item["created"] for item in second)
    assert {fact["source"] for fact in instance.facts.get_facts("scan", "host")} == {"fixture"}
