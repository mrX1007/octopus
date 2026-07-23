"""Production scheduler-to-action-catalog dispatch contracts."""

from __future__ import annotations

import json

import pytest

from core.ai.command_scheduler import CommandScheduler
from core.ai.runtime import PipelineRuntime
from core.execution import (
    CancellationContext,
    ExecutionContext,
    ExecutionDecision,
    ExecutionPolicy,
    ExecutionStatus,
)
from core.tools.registry import get_tool, tool

pytestmark = [pytest.mark.contract, pytest.mark.security]


def _register_fixture_tool() -> str:
    name = "typed_production_dispatch_fixture"
    if get_tool(name) is None:

        @tool(
            name=name,
            category="recon",
            description="Hermetic typed dispatch fixture.",
        )
        def fixture(_target: str) -> str:
            return "registry callable is not the compatibility dispatch seam"

    return name


def _register_fallback_tools() -> tuple[str, str]:
    names = (
        "typed_production_dispatch_a_primary",
        "typed_production_dispatch_b_secondary",
    )
    for name in names:
        if get_tool(name) is None:

            @tool(
                name=name,
                category="recon",
                description="Hermetic production fallback fixture.",
            )
            def fixture(_target: str) -> str:
                return "registry callable is not the compatibility dispatch seam"

    return names


def test_scheduler_carries_typed_invocation_and_runtime_uses_action_lifecycle(
    tmp_path,
) -> None:
    name = _register_fixture_tool()
    calls: list[str] = []
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda command: calls.append(command) or "fixture-output",
    )
    context = ExecutionContext.automatic(target_scope=("example.com",))
    command = f"{name} example.com"

    decision = runtime.decide(command, (), set(), context)
    result = runtime.execute(
        decision,
        context,
        facts=({"type": "host", "value": "example.com"},),
        capability="read_only_discovery",
    )

    assert decision.invocation is not None
    assert decision.invocation.registered_name == name
    assert calls == [command]
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.metadata["action_catalog"] is True
    assert result.metadata["capability"] == "read_only_discovery"
    assert result.metadata["provider_attempts"] == 1
    assert result.metadata["action_lifecycle"]["outcome"] == "succeeded"
    assert result.policy_decision_ref.startswith("policy://sha256/")


def test_runtime_reauthorizes_typed_invocation_after_scheduler_decision(
    tmp_path,
) -> None:
    name = _register_fixture_tool()
    calls: list[str] = []
    cancellation = CancellationContext()
    context = ExecutionContext.automatic(
        target_scope=("example.com",),
        cancellation=cancellation,
    )
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda command: calls.append(command) or "must-not-run",
    )
    decision = runtime.decide(f"{name} example.com", (), set(), context)
    assert decision.action == "execute"

    cancellation.cancel("operator_request")
    result = runtime.execute(decision, context, capability="read_only_discovery")

    assert result.status is ExecutionStatus.CANCELLED
    assert result.executed is False
    assert result.metadata["authorization_phase"] == "pre_execute"
    assert calls == []


def test_runtime_pre_execute_policy_denial_has_typed_blocked_semantics(
    tmp_path,
) -> None:
    name = _register_fixture_tool()

    class DenyAfterScheduling(ExecutionPolicy):
        def __init__(self) -> None:
            self.calls = 0

        def authorize_registered(self, invocation, context):
            self.calls += 1
            if self.calls == 1:
                return super().authorize_registered(invocation, context)
            return ExecutionDecision(
                allowed=False,
                reason="target_out_of_scope:must-not-persist.example",
                context=context,
                invocation=invocation,
            )

    policy = DenyAfterScheduling()
    calls: list[str] = []
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda command: calls.append(command) or "must-not-run",
        scheduler=CommandScheduler(policy),
    )
    context = ExecutionContext.automatic(target_scope=("example.com",))
    decision = runtime.decide(f"{name} example.com", (), set(), context)

    result = runtime.execute(decision, context, capability="read_only_discovery")

    assert result.status is ExecutionStatus.BLOCKED
    assert result.executed is False
    assert result.metadata["policy_denial"] == {
        "phase": "pre_execute",
        "reason_code": "target_out_of_scope",
        "decision_ref": result.policy_decision_ref,
    }
    assert "must-not-persist.example" not in json.dumps(result.to_dict())
    assert calls == []


def test_typed_invocation_raw_command_is_never_in_decision_audit_payload(
    tmp_path,
) -> None:
    name = _register_fixture_tool()
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda _command: "ok",
    )
    context = ExecutionContext.automatic(target_scope=("example.com",))
    secret = "fixture-secret-never-persist"
    decision = runtime.decide(
        f"{name} example.com password={secret}",
        (),
        set(),
        context,
    )

    serialized = json.dumps(decision.to_dict(), sort_keys=True)

    assert decision.invocation is not None
    assert secret not in serialized
    assert "invocation" not in decision.to_dict()


def test_production_dispatch_uses_safe_provider_fallback_after_partial_ingestion(
    tmp_path,
) -> None:
    primary, secondary = _register_fallback_tools()
    events: list[str] = []

    def runner(command: str):
        events.append(f"execute:{command}")
        if command.startswith(primary):
            return {
                "status": "timeout",
                "stdout": "partial discovery",
                "partial": True,
                "error_class": "TimeoutError",
            }
        return {"status": "succeeded", "stdout": "complete discovery"}

    runtime = PipelineRuntime(str(tmp_path / "facts.db"), runner=runner)
    context = ExecutionContext.automatic(target_scope=("example.com",))
    command = f"{primary} example.com"
    fallback_command = f"{secondary} example.com"
    decision = runtime.decide(command, (), set(), context)

    def ingest_partial(result, action_id: str, request):
        events.append(f"ingest:{action_id}:{request.command_for(action_id)}")
        assert result.status is ExecutionStatus.TIMEOUT
        return {"parsed_facts": 1, "new_facts": 1}

    result = runtime.execute(
        decision,
        context,
        capability="read_only_discovery",
        provider_commands=(command, fallback_command),
        partial_result_ingest=ingest_partial,
    )

    assert events == [
        f"execute:{command}",
        f"ingest:tool:{primary}:{command}",
        f"execute:{fallback_command}",
    ]
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.metadata["provider_attempts"] == 2
    assert result.metadata["provider_attempt_action_ids"] == [
        f"tool:{primary}",
        f"tool:{secondary}",
    ]
    assert result.metadata["provider_fallback_attempt_action_ids"] == [
        f"tool:{secondary}"
    ]
    assert result.metadata["provider_status"] == "succeeded"


def test_production_fallback_excludes_active_registry_alternatives(tmp_path) -> None:
    name = _register_fixture_tool()
    calls: list[str] = []
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda command: calls.append(command) or "complete",
    )
    context = ExecutionContext.automatic(target_scope=("example.com",))
    command = f"{name} example.com"
    decision = runtime.decide(command, (), set(), context)

    result = runtime.execute(
        decision,
        context,
        capability="read_only_discovery",
        provider_commands=(
            command,
            "msf_run example.com exploit/test/fixture",
        ),
    )

    assert result.status is ExecutionStatus.SUCCEEDED
    assert calls == [command]
    assert result.metadata["provider_attempts"] == 1
    assert result.metadata["provider_attempt_action_ids"] == [f"tool:{name}"]


def test_mission_pipeline_persists_partial_attempt_before_provider_fallback(
    tmp_path,
) -> None:
    from core.ai.pipeline import AIPipeline

    primary, secondary = _register_fallback_tools()
    command = f"{primary} example.com"
    fallback_command = f"{secondary} example.com"
    calls: list[str] = []

    def runner(raw_command: str):
        calls.append(raw_command)
        if raw_command == command:
            return {
                "status": "timeout",
                "stdout": "partial discovery",
                "partial": True,
                "error_class": "TimeoutError",
            }
        return {"status": "succeeded", "stdout": "complete discovery"}

    pipeline = AIPipeline(str(tmp_path / "pipeline.db"))
    pipeline.runtime._runner = runner
    pipeline.mission_id = "mission-production-fallback"
    pipeline._active_task_name = "service_discovery"

    result = pipeline._run_task_commands(
        "scan-production-fallback",
        "example.com",
        [command, fallback_command],
        fact_label="Fact",
    )

    persisted = pipeline.fact_store.get_command_results(
        "scan-production-fallback",
        "example.com",
    )
    assert calls == [command, fallback_command]
    assert pipeline.tools_run_count == 2
    assert result["commands"][0]["provider_partial_new_facts"] >= 1
    assert any(item["status"] == "timeout" and item["partial"] for item in persisted)
    assert any(item["status"] == "succeeded" for item in persisted)


def test_mission_pipeline_does_not_enable_fallback_for_active_task_profile(
    tmp_path,
) -> None:
    from core.ai.pipeline import AIPipeline

    primary, secondary = _register_fallback_tools()
    pipeline = AIPipeline(str(tmp_path / "active-task.db"))
    pipeline.mission_id = "mission-active-task"
    pipeline._active_task_name = "vulnerability_assessment"

    candidates = pipeline._task_provider_commands(
        f"{primary} example.com",
        [f"{primary} example.com", f"{secondary} example.com"],
        "scan-active-task",
        "example.com",
    )

    assert candidates == ()
