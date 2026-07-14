"""Canonical execution-result and PipelineRuntime compatibility contracts."""

from __future__ import annotations

import asyncio
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from core.ai.command_scheduler import CommandDecision
from core.ai.fact_store import FactStore
from core.ai.runtime import DispatchResult, PipelineRuntime
from core.execution import (
    ExecutionContext,
    ExecutionResult,
    ExecutionStatus,
    adapt_execution_result,
)
from core.execution.results import MAX_ARTIFACT_BYTES, MAX_ARTIFACT_REFS, MAX_METADATA_BYTES
from core.killchain.exploits.base import ExploitResult
from core.plugins.base import PluginResult


@dataclass
class FirstToolResult:
    tool_name: str
    stdout: str
    stderr: str = ""
    exit_code: int = 0
    duration: float = 0.0


@dataclass
class SecondToolResult:
    tool_name: str
    command: str
    stdout: str
    stderr: str = ""
    exit_code: int = 0
    duration: float = 0.0
    timestamp: str = "fixture"


def _context(*, max_output_bytes: int = 1_000_000) -> ExecutionContext:
    return ExecutionContext.automatic(
        target_scope=("example.com",),
        actor="result-test",
        origin="test",
        max_output_bytes=max_output_bytes,
    )


def _decision(action: str = "execute") -> CommandDecision:
    return CommandDecision(
        "fixture_tool example.com",
        "fixture-key",
        action,
        "fixture decision",
        policy={"request_id": "policy-request", "allowed": action == "execute"},
    )


def _runtime(tmp_path: Path, runner, parser=None) -> PipelineRuntime:
    return PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=runner,
        fact_store=FactStore(str(tmp_path / "runtime-facts.db")),
        parser=parser,
    )


def test_execution_status_contract_is_complete() -> None:
    assert {status.value for status in ExecutionStatus} == {
        "succeeded",
        "failed",
        "timeout",
        "blocked",
        "partial",
        "unavailable",
        "cancelled",
    }


def test_legacy_string_adapter_is_canonical_json_and_compatible() -> None:
    result = adapt_execution_result(
        "hello",
        request_id="req-1",
        execution_id="exec-1",
        tool_name="fixture",
    )

    assert isinstance(result, ExecutionResult)
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.output == "hello"
    assert str(result) == "hello"
    assert result.executed is True
    assert result.request_id == "req-1"
    assert result.execution_id == "exec-1"
    assert result.tool_name == "fixture"
    assert json.loads(json.dumps(result.to_dict()))["schema_version"] == "1.0"


@pytest.mark.parametrize("result_type", [FirstToolResult, SecondToolResult])
def test_both_duck_typed_tool_results_preserve_execution_fields(result_type) -> None:
    kwargs = {
        "tool_name": "legacy",
        "stdout": "useful stdout",
        "stderr": "diagnostic",
        "exit_code": 7,
        "duration": 1.25,
    }
    if result_type is SecondToolResult:
        kwargs["command"] = "legacy example.com"
    result = adapt_execution_result(result_type(**kwargs), request_id="req", execution_id="exec")

    assert result.status is ExecutionStatus.FAILED
    assert result.tool_name == "legacy"
    assert result.stdout == "useful stdout"
    assert result.stderr == "diagnostic"
    assert result.exit_code == 7
    assert result.duration == 1.25


@pytest.mark.parametrize(
    ("stdout", "stderr", "expected_status", "expected_partial"),
    [
        (
            "[PARTIAL OUTPUT - 3 lines captured]\n[TIMEOUT] scanner killed after 30s",
            "",
            ExecutionStatus.TIMEOUT,
            True,
        ),
        ("[PARTIAL OUTPUT - output limit reached]", "", ExecutionStatus.PARTIAL, True),
        ("", "[!] Tool not found: scanner", ExecutionStatus.UNAVAILABLE, False),
        ("", "missing dependency: scanner", ExecutionStatus.UNAVAILABLE, False),
        ("", "scanner: no such file or directory", ExecutionStatus.UNAVAILABLE, False),
    ],
)
def test_duck_tool_result_uses_bounded_legacy_failure_markers_without_explicit_status(
    stdout: str,
    stderr: str,
    expected_status: ExecutionStatus,
    expected_partial: bool,
) -> None:
    result = adapt_execution_result(
        FirstToolResult("scanner", stdout, stderr, exit_code=-1),
        request_id="req",
        execution_id="exec",
    )

    assert result.status is expected_status
    assert result.partial is expected_partial


def test_explicit_status_is_not_overridden_by_legacy_markers() -> None:
    result = adapt_execution_result(
        {"status": "failed", "stdout": "[TIMEOUT] killed after 30s", "exit_code": -1},
        request_id="req",
        execution_id="exec",
        tool_name="scanner",
    )

    assert result.status is ExecutionStatus.FAILED


def test_plugin_and_exploit_adapters_keep_artifacts_and_redacted_metadata() -> None:
    def redact_text(value, **_kwargs):
        return str(value).replace("runtime-secret", "[REDACTED]")

    def redact_data(value, **_kwargs):
        if isinstance(value, dict):
            return {key: redact_data(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact_data(item) for item in value]
        return redact_text(value) if isinstance(value, str) else value

    plugin = PluginResult(
        success=True,
        output="password=runtime-secret",
        data={"nested": "runtime-secret", "token=runtime-secret": "safe value"},
        artifacts=["artifact.json"],
        credentials=[{"password": "runtime-secret"}],
    )
    plugin_result = adapt_execution_result(
        plugin,
        request_id="req-p",
        execution_id="exec-p",
        tool_name="plugin",
        redact_text=redact_text,
        redact_data=redact_data,
    )
    exploit_result = adapt_execution_result(
        ExploitResult(
            success=False,
            status="not_vulnerable",
            evidence="negative check",
            artifacts=["evidence.txt"],
        ),
        request_id="req-e",
        execution_id="exec-e",
        tool_name="exploit-check",
    )

    assert plugin_result.status is ExecutionStatus.SUCCEEDED
    assert plugin_result.artifact_refs == ("artifact.json",)
    assert "runtime-secret" not in json.dumps(plugin_result.to_dict())
    assert len(plugin_result.metadata["data"]) == 2
    assert exploit_result.status is ExecutionStatus.SUCCEEDED
    assert exploit_result.stdout == "negative check"
    assert exploit_result.artifact_refs == ("evidence.txt",)


def test_dict_adapter_is_json_safe_and_preserves_typed_status(tmp_path: Path) -> None:
    recursive = []
    recursive.append(recursive)
    result = adapt_execution_result(
        {
            "status": "unavailable",
            "output": "provider missing",
            "error": "binary not found",
            "artifacts": [tmp_path / "artifact"],
            "metadata": {
                "path": tmp_path,
                "set": {"a", "b"},
                "bytes": b"bytes",
                "recursive": recursive,
            },
        },
        request_id="req",
        execution_id="exec",
        tool_name="provider",
    )

    payload = result.to_dict()
    json.dumps(payload, allow_nan=False)
    assert result.status is ExecutionStatus.UNAVAILABLE
    assert payload["artifact_refs"] == [str(tmp_path / "artifact")]
    assert payload["metadata"]["recursive"] == ["<recursive>"]


def test_adapter_bounds_combined_utf8_output_and_marks_partial() -> None:
    result = adapt_execution_result(
        {"stdout": "é" * 100, "stderr": "diagnostic" * 20, "status": "succeeded"},
        request_id="req",
        execution_id="exec",
        tool_name="bounded",
        max_output_bytes=73,
    )

    assert len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")) <= 73
    assert result.status is ExecutionStatus.PARTIAL
    assert result.partial is True
    assert result.metadata["output_truncated"] is True


def test_adapter_bounds_metadata_and_artifact_references() -> None:
    result = adapt_execution_result(
        {
            "output": "ok",
            "artifacts": [f"/tmp/{index}/" + ("x" * 5000) for index in range(200)],
            "metadata": {"oversized": "m" * (MAX_METADATA_BYTES * 2)},
        },
        request_id="req",
        execution_id="exec",
        tool_name="bounded-metadata",
    )
    payload = result.to_dict()
    metadata_bytes = len(json.dumps(payload["metadata"], ensure_ascii=False).encode("utf-8"))
    artifact_bytes = len(
        json.dumps(result.artifact_refs, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )

    assert len(result.artifact_refs) <= MAX_ARTIFACT_REFS
    assert artifact_bytes <= MAX_ARTIFACT_BYTES
    assert metadata_bytes <= MAX_METADATA_BYTES
    assert result.metadata["metadata_truncated"] is True
    assert result.metadata["artifact_refs_truncated"] is True
    assert result.metadata["artifact_ref_count"] == 200


def test_runtime_skip_is_blocked_and_keeps_dispatch_compatibility(tmp_path: Path) -> None:
    calls = []
    runtime = _runtime(tmp_path, lambda command: calls.append(command))

    result = runtime.execute(_decision("skip"), _context())

    assert isinstance(result, DispatchResult)
    assert result.status is ExecutionStatus.BLOCKED
    assert result.executed is False
    assert result.output == ""
    assert result.request_id
    assert result.execution_id
    assert result.policy_decision_ref
    assert calls == []


def test_runtime_redacts_and_bounds_before_returning_result(tmp_path: Path) -> None:
    def runner(_command):
        return FirstToolResult(
            tool_name="fixture_tool",
            stdout="password=runtime-secret " + ("x" * 500),
            stderr="token=runtime-secret",
        )

    runtime = _runtime(tmp_path, runner)
    result = runtime.execute(_decision(), _context(max_output_bytes=96))
    payload = json.dumps(result.to_dict())

    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 96
    assert result.status is ExecutionStatus.PARTIAL
    assert "runtime-secret" not in payload
    assert "runtime-secret" not in repr(result)


def test_runtime_redacts_secret_bearing_metadata_keys(tmp_path: Path) -> None:
    runtime = _runtime(
        tmp_path,
        lambda _command: {
            "output": "ok",
            "metadata": {
                "token=runtime-secret": "first",
                "password=runtime-secret": "second",
            },
        },
    )

    result = runtime.execute(_decision(), _context())
    payload = json.dumps(result.to_dict())

    assert "runtime-secret" not in payload
    assert "runtime-secret" not in repr(result)
    assert len(result.metadata) == 2


def test_metadata_key_redaction_retains_colliding_entries_deterministically() -> None:
    def collapse_secret_keys(value, **_kwargs):
        return "[REDACTED KEY]" if "=" in str(value) else str(value)

    result = adapt_execution_result(
        {
            "output": "ok",
            "metadata": {
                "token=first-secret": "first",
                "password=second-secret": "second",
            },
        },
        request_id="req",
        execution_id="exec",
        tool_name="metadata",
        redact_text=collapse_secret_keys,
    )
    keys = sorted(result.metadata)
    payload = json.dumps(result.to_dict())

    assert len(keys) == 2
    assert keys[0] == "[REDACTED KEY]"
    assert keys[1].startswith("[REDACTED KEY]#")
    assert "first-secret" not in payload
    assert "second-secret" not in payload


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_executed"),
    [
        (TimeoutError("token=runtime-secret"), ExecutionStatus.TIMEOUT, True),
        (FileNotFoundError("password=runtime-secret"), ExecutionStatus.UNAVAILABLE, False),
        (RuntimeError("password=runtime-secret"), ExecutionStatus.FAILED, True),
        (asyncio.CancelledError("token=runtime-secret"), ExecutionStatus.CANCELLED, True),
    ],
)
def test_runtime_classifies_and_redacts_runner_exceptions(
    tmp_path: Path,
    error: BaseException,
    expected_status: ExecutionStatus,
    expected_executed: bool,
) -> None:
    def runner(_command):
        raise error

    result = _runtime(tmp_path, runner).execute(_decision(), _context())

    assert result.status is expected_status
    assert result.executed is expected_executed
    assert result.error_class == type(error).__name__
    assert "runtime-secret" not in result.error_message
    assert "runtime-secret" not in json.dumps(result.to_dict())


def test_runtime_timeout_preserves_bounded_partial_output(tmp_path: Path) -> None:
    def runner(_command):
        raise subprocess.TimeoutExpired(
            "fixture",
            2,
            output=b"partial password=runtime-secret",
            stderr=b"diagnostic",
        )

    result = _runtime(tmp_path, runner).execute(_decision(), _context(max_output_bytes=48))

    assert result.status is ExecutionStatus.TIMEOUT
    assert result.partial is True
    assert "partial" in result.stdout
    assert "runtime-secret" not in json.dumps(result.to_dict())


def test_parser_accepts_canonical_result_and_legacy_text_facade(tmp_path: Path) -> None:
    calls = []

    class Parser:
        def parse_tool_output(self, command, output):
            calls.append((command, output))
            return [{"type": "observation", "value": output}]

    runtime = _runtime(tmp_path, lambda _command: "canonical output", parser=Parser())
    result = runtime.execute(_decision(), _context())
    result_with_stderr = adapt_execution_result(
        {"stdout": "canonical stdout", "stderr": "canonical stderr"},
        request_id="req",
        execution_id="exec",
        tool_name="fixture",
    )

    assert runtime.parse_output("fixture", result)[0]["value"] == "canonical output"
    assert runtime.parse_output("fixture", result_with_stderr)[0]["value"] == (
        "canonical stdout\ncanonical stderr"
    )
    assert runtime.parse_output("fixture", "legacy output")[0]["value"] == "legacy output"
    assert calls == [
        ("fixture", "canonical output"),
        ("fixture", "canonical stdout\ncanonical stderr"),
        ("fixture", "legacy output"),
    ]


def test_pipeline_classification_and_parser_receive_canonical_result(tmp_path: Path) -> None:
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(str(tmp_path / "pipeline.db"))
    pipeline.runtime._runner = lambda _command: FirstToolResult(
        tool_name="nuclei_safe",
        stdout="[+] misleading legacy success marker",
        exit_code=7,
    )
    parser_calls = []

    def parse_output(command, output):
        parser_calls.append((command, output))
        return []

    pipeline.runtime.parse_output = parse_output
    result = pipeline._execute_pipeline_command(
        "scan",
        "10.0.0.5",
        "nuclei_safe http://10.0.0.5",
        "Fact",
        "[Running]",
    )

    assert result["command_result"]["failed"] is True
    assert result["command_result"]["check_status"] == "failed"
    assert len(parser_calls) == 1
    assert isinstance(parser_calls[0][1], ExecutionResult)
    assert parser_calls[0][1].exit_code == 7
