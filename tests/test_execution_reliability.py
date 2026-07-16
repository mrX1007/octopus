"""Cancellation, bounded processes, partial persistence, and idempotency."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.ai.command_scheduler import CommandDecision
from core.ai.fact_store import FactStore
from core.ai.pipeline import AIPipeline
from core.ai.runtime import PipelineRuntime
from core.execution import (
    CancellationContext,
    ExecutionCancelled,
    ExecutionContext,
    ExecutionPolicy,
    ExecutionStatus,
    ToolInvocation,
    bind_execution_context,
    cancellation_reason_code,
)
from core.tools.base import run_tool


def automatic(
    *,
    cancellation: CancellationContext | None = None,
    max_runtime_seconds: int = 5,
    max_output_bytes: int = 4096,
) -> ExecutionContext:
    return ExecutionContext.automatic(
        target_scope=("example.com",),
        actor="reliability-test",
        origin="test",
        max_runtime_seconds=max_runtime_seconds,
        max_output_bytes=max_output_bytes,
        cancellation=cancellation,
    )


def decision() -> CommandDecision:
    return CommandDecision(
        "nmap example.com",
        "reliability-key",
        "execute",
        "fixture",
    )


def test_cancellation_context_is_thread_safe_deadline_aware_and_secret_free():
    token = CancellationContext()
    assert token.cancel("token=must-not-survive") is True
    assert token.cancel("second") is False
    assert token.cancelled is True
    assert token.reason_code == "token"
    assert cancellation_reason_code("password=must-not-survive") == "password"
    assert cancellation_reason_code("   ") == "cancelled"
    assert "must-not-survive" not in repr(token.__dict__)
    with pytest.raises(ExecutionCancelled, match="token"):
        token.checkpoint()

    expired = CancellationContext.with_timeout(0)
    assert expired.cancelled is True
    assert expired.reason_code == "deadline_exceeded"


def test_cancelled_context_fails_policy_and_runtime_closed_without_calling_provider(tmp_path):
    token = CancellationContext()
    context = automatic(cancellation=token)
    token.cancel("operator_request")
    invocation = ToolInvocation(
        executable="nmap",
        argv=("nmap", "example.com"),
        raw_command="nmap example.com",
        registered_name="nmap",
        targets=("example.com",),
    )
    policy_result = ExecutionPolicy().authorize_registered(invocation, context)
    calls: list[str] = []
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda command: calls.append(command) or "unexpected",
    )

    result = runtime.execute(decision(), context)

    assert policy_result.allowed is False
    assert policy_result.reason == "execution_cancelled"
    assert result.status is ExecutionStatus.CANCELLED
    assert result.executed is False
    assert calls == []


def test_runtime_preserves_and_redacts_partial_output_from_typed_cancellation(tmp_path):
    def runner(_command: str):
        raise ExecutionCancelled(
            "token=runtime-secret",
            stdout="partial password=runtime-secret",
            stderr="diagnostic token=runtime-secret",
            returncode=-15,
        )

    runtime = PipelineRuntime(str(tmp_path / "facts.db"), runner=runner)
    result = runtime.execute(decision(), automatic())
    payload = json.dumps(result.to_dict())

    assert result.status is ExecutionStatus.CANCELLED
    assert result.partial is True
    assert result.exit_code == -15
    assert "partial" in result.stdout
    assert "runtime-secret" not in payload


@pytest.mark.platform
def test_legacy_runner_turns_unlimited_timeout_into_bounded_partial_output():
    context = automatic(max_runtime_seconds=1, max_output_bytes=4096)
    started = time.monotonic()
    with bind_execution_context(context):
        output = run_tool(
            [
                sys.executable,
                "-c",
                "import time; print('partial-before-timeout', flush=True); time.sleep(30)",
            ],
            timeout=0,
        )

    assert time.monotonic() - started < 5
    assert "partial-before-timeout" in output
    assert "[TIMEOUT]" in output


@pytest.mark.platform
def test_legacy_runner_bounds_output_bytes():
    context = automatic(max_runtime_seconds=5, max_output_bytes=1024)
    with bind_execution_context(context):
        output = run_tool(
            [sys.executable, "-c", "print('x' * 100000, flush=True)"],
            timeout=5,
        )

    assert len(output.encode("utf-8")) <= 1024
    assert "[OUTPUT LIMIT]" in output


def _process_is_live(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@pytest.mark.platform
def test_cooperative_cancellation_terminates_the_spawned_process_group():
    token = CancellationContext()
    context = automatic(
        cancellation=token,
        max_runtime_seconds=10,
        max_output_bytes=4096,
    )
    program = (
        "import subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        "print(f'child={child.pid}',flush=True); time.sleep(30)"
    )

    def execute():
        with bind_execution_context(context):
            return run_tool([sys.executable, "-c", program], timeout=10)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(execute)
        time.sleep(0.5)
        token.cancel("test_cancel")
        with pytest.raises(ExecutionCancelled) as caught:
            future.result(timeout=5)

    match = re.search(r"child=(\d+)", str(caught.value.stdout))
    assert match is not None
    child_pid = int(match.group(1))
    for _attempt in range(20):
        if not _process_is_live(child_pid):
            break
        time.sleep(0.1)
    assert not _process_is_live(child_pid)


def test_pipeline_persists_cancelled_partial_result_before_interrupting(tmp_path):
    db_path = tmp_path / "pipeline.db"
    pipeline = AIPipeline(str(db_path))
    pipeline.runtime.decide = lambda *_args, **_kwargs: decision()

    def runner(_command: str):
        raise ExecutionCancelled(
            "sigint",
            stdout="80/tcp open http password=partial-secret",
        )

    pipeline.runtime._runner = runner
    with pytest.raises(ExecutionCancelled, match="provider_cancelled"):
        pipeline._execute_pipeline_command(
            "cancel-scan",
            "example.com",
            "nmap example.com",
            "Fact",
            "[Running]",
        )

    rows = pipeline.fact_store.get_command_results("cancel-scan", "example.com")
    assert len(rows) == 1
    assert rows[0]["status"] == "cancelled"
    assert rows[0]["partial"] is True
    assert rows[0]["output_bytes"] > 0
    assert "partial-secret" not in json.dumps(rows)
    assert b"partial-secret" not in db_path.read_bytes()


def test_command_result_idempotency_key_is_hashed_and_at_most_once(tmp_path):
    db_path = tmp_path / "facts.db"
    store = FactStore(str(db_path))
    first_id, first_unique = store.add_command_result(
        "scan",
        "example.com",
        "key",
        "nmap example.com",
        "a" * 64,
        status="succeeded",
        idempotency_key="execution:token=do-not-store",
    )
    second_id, second_unique = store.add_command_result(
        "scan",
        "example.com",
        "key",
        "nmap example.com",
        "b" * 64,
        status="failed",
        idempotency_key="execution:token=do-not-store",
    )

    rows = store.get_command_results("scan", "example.com")
    assert first_id == second_id
    assert first_unique is True
    assert second_unique is False
    assert len(rows) == 1
    assert len(rows[0]["idempotency_key"]) == 64
    assert "do-not-store" not in json.dumps(rows)
    assert b"do-not-store" not in db_path.read_bytes()


def test_concurrent_command_result_idempotency_converges_on_one_row(tmp_path):
    store = FactStore(str(tmp_path / "concurrent.db"))

    def persist(index: int) -> int:
        result_id, _created = store.add_command_result(
            "scan",
            "example.com",
            "same-key",
            "nmap example.com",
            f"{index:064x}",
            status="succeeded",
            idempotency_key="execution:shared",
        )
        return result_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        result_ids = list(pool.map(persist, range(8)))

    assert len(set(result_ids)) == 1
    assert len(store.get_command_results("scan", "example.com")) == 1


def test_sigint_requests_cancellation_and_raises_for_normal_unwinding(monkeypatch):
    import core.execution as execution
    import octopus

    context = automatic()
    stopped: list[bool] = []

    class Supervisor:
        def stop(self):
            stopped.append(True)

    monkeypatch.setattr(execution, "current_execution_context", lambda: context)
    monkeypatch.setattr(octopus, "_current_sl_no", None)
    monkeypatch.setattr(octopus, "_supervisor", Supervisor())

    with pytest.raises(KeyboardInterrupt):
        octopus._sigint_handler(None, None)

    assert context.cancellation.cancelled is True
    assert context.cancellation.reason_code == "sigint"
    assert stopped == [True]
