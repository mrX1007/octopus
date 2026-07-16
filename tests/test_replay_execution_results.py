"""Persistence and replay contracts for canonical execution results."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from core.ai.command_scheduler import CommandDecision
from core.ai.fact_store import FactStore
from core.ai.pipeline import AIPipeline
from core.ai.replay_snapshot import ReplaySnapshot
from core.ai.runtime import PipelineRuntime
from core.execution import ExecutionContext, ExecutionResult, adapt_execution_result

pytestmark = [pytest.mark.contract, pytest.mark.replay]

CANARY = "phase1c-secret-canary"


def _legacy_command_database(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE command_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host TEXT NOT NULL,
                command_key TEXT NOT NULL,
                command TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                output_bytes INTEGER NOT NULL DEFAULT 0,
                parsed_facts INTEGER NOT NULL DEFAULT 0,
                new_facts INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                timestamp REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO command_results (
                scan_id, host, command_key, command, output_hash, output_bytes,
                parsed_facts, new_facts, failed, timestamp
            ) VALUES ('legacy', 'host', 'key', 'nmap host', 'hash', 7, 0, 0, 1, 1)
            """
        )


def _quiet_pipeline(path: Path) -> AIPipeline:
    pipeline = AIPipeline(str(path))
    pipeline.context_builder.build_context = lambda _scan, target: {"target": target}
    pipeline.snapshot_actions = lambda _scan, _target: []
    return pipeline


def test_legacy_command_result_schema_migrates_in_place_with_safe_defaults(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    _legacy_command_database(db_path)

    store = FactStore(str(db_path))

    with sqlite3.connect(db_path) as conn:
        columns = {row[1]: row for row in conn.execute("PRAGMA table_info(command_results)")}
    assert {
        "schema_version",
        "status",
        "partial",
        "execution_id",
        "request_id",
        "policy_decision_ref",
        "exit_code",
        "duration",
        "stderr_bytes",
        "error_class",
        "artifact_count",
        "metadata_json",
    } <= set(columns)

    row = store.get_command_results("legacy", "host")[0]
    assert row["schema_version"] == "0"
    assert row["status"] == "failed"
    assert row["failed"] is True
    assert row["partial"] is False
    assert row["execution_id"] == ""
    assert row["request_id"] == ""
    assert row["policy_decision_ref"] == ""
    assert row["exit_code"] is None
    assert row["duration"] == 0.0
    assert row["stderr_bytes"] == 0
    assert row["error_class"] == ""
    assert row["artifact_count"] == 0
    assert row["metadata"] == {}


def test_manual_command_metadata_keys_and_hash_field_are_independently_protected(tmp_path: Path) -> None:
    db_path = tmp_path / "manual.db"
    store = FactStore(str(db_path))
    store.add_command_result(
        "scan",
        "host",
        "manual",
        "fixture host",
        CANARY,
        status="succeeded",
        metadata={
            f"token={CANARY}": CANARY,
            f"password={CANARY}": {"token": CANARY},
        },
    )

    row = store.get_command_results("scan", "host")[0]
    assert len(row["output_hash"]) == 64
    assert CANARY not in json.dumps(row)
    assert CANARY.encode() not in db_path.read_bytes()


def test_pipeline_persists_canonical_status_and_legacy_failed_projection(tmp_path: Path) -> None:
    pipeline = AIPipeline(str(tmp_path / "pipeline.db"))
    pipeline.runtime.decide = lambda command, _facts, _keys, _context, *_retry: CommandDecision(
        command,
        "fixture-key",
        "execute",
        "fixture decision",
    )
    pipeline.runtime._runner = lambda _command: {
        "schema_version": "1.0",
        "status": "timeout",
        "stderr": "bounded diagnostic",
        "exit_code": 124,
        "duration": 2.5,
        "partial": True,
        "error": {"class": "TimeoutExpired", "message": "deadline"},
        "metadata": {"provider": "fixture"},
    }

    result = pipeline._execute_pipeline_command(
        "scan",
        "10.0.0.5",
        "nmap 10.0.0.5",
        "Fact",
        "[Running]",
    )
    persisted = pipeline.fact_store.get_command_results("scan", "10.0.0.5")[0]

    assert result["command_result"]["failed"] is True
    assert persisted["schema_version"] == "1.0"
    assert persisted["status"] == "timeout"
    assert persisted["failed"] is True
    assert persisted["partial"] is True
    assert persisted["exit_code"] == 124
    assert persisted["duration"] == 2.5
    assert persisted["stderr_bytes"] == len(b"bounded diagnostic")
    assert persisted["error_class"] == "TimeoutExpired"
    assert persisted["metadata"] == {"provider": "fixture"}


def test_versioned_replay_keeps_statuses_ids_and_never_returns_or_persists_bodies(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "replay.db"
    pipeline = _quiet_pipeline(db_path)
    pipeline._execution_context = lambda _scan, target: ExecutionContext.automatic(
        target_scope=(target,),
        max_output_bytes=96,
    )
    parser_inputs: list[ExecutionResult] = []
    parse_output = pipeline.runtime.parse_output

    def observe_parser(command: str, result: str | ExecutionResult):
        assert isinstance(result, ExecutionResult)
        parser_inputs.append(result)
        return parse_output(command, result)

    pipeline.runtime.parse_output = observe_parser
    outputs = [
        {
            "tool": "nmap",
            "result": {
                "schema_version": "1.0",
                "status": "timeout",
                "request_id": "request-timeout",
                "execution_id": "execution-timeout",
                "stdout": "",
                "stderr": f"22/tcp open ssh OpenSSH password={CANARY}",
                "exit_code": 124,
                "duration": 1.5,
                "partial": True,
                "error": {"class": "TimeoutExpired", "message": f"token={CANARY}"},
                "metadata": {"token": CANARY, "nested": {"password": CANARY}},
                "artifact_refs": [f"/tmp/{CANARY}"],
            },
        },
        {
            "tool": "nmap",
            "schema_version": "1.0",
            "status": "partial",
            "request_id": "request-partial",
            "execution_id": "execution-partial",
            "stdout": "80/tcp open http nginx\n" + ("x" * 500),
            "partial": True,
        },
        {
            "tool": f"blocked --token {CANARY}",
            "result": {
                "schema_version": "1.0",
                "status": "blocked",
                "request_id": "request-blocked",
                "execution_id": "execution-blocked",
                "error": {"class": "ExecutionBlocked", "message": f"secret={CANARY}"},
            },
        },
    ]

    replay = pipeline.replay_outputs("scan", "10.0.0.5", outputs)
    persisted = pipeline.fact_store.get_command_results("scan", "10.0.0.5")

    assert [item["status"] for item in replay["execution_results"]] == [
        "timeout",
        "partial",
        "blocked",
    ]
    assert replay["replay_results"] == replay["execution_results"]
    assert [item["execution_id"] for item in replay["execution_results"]] == [
        "execution-timeout",
        "execution-partial",
        "execution-blocked",
    ]
    assert [item["failed"] for item in replay["execution_results"]] == [True, False, False]
    assert all("stdout" not in item and "stderr" not in item and "metadata" not in item for item in replay["execution_results"])
    assert [item["status"] for item in persisted] == ["timeout", "partial", "blocked"]
    assert persisted[0]["output_bytes"] == 0
    assert persisted[0]["stderr_bytes"] > 0
    assert persisted[0]["artifact_count"] == 1
    assert persisted[0]["error_class"] == "TimeoutExpired"
    assert len(parser_inputs[1].stdout.encode()) <= 96
    assert replay["parsed_facts"] > 0
    assert not any(fact["type"] in {"port_open", "service_version"} for fact in pipeline.fact_store.get_facts("scan", "10.0.0.5") if fact["source"].startswith("replay:nmap") and "22" in fact["value"])
    assert CANARY not in repr(replay)
    assert CANARY not in json.dumps(persisted)
    assert CANARY.encode() not in db_path.read_bytes()


def test_legacy_replay_is_equivalent_deterministic_and_keeps_append_history(tmp_path: Path) -> None:
    legacy = _quiet_pipeline(tmp_path / "legacy-replay.db")
    canonical = _quiet_pipeline(tmp_path / "canonical-replay.db")
    raw = "80/tcp open http nginx"

    first = legacy.replay_outputs("scan", "10.0.0.5", [{"tool": "nmap", "output": raw}])
    second = legacy.replay_outputs("scan", "10.0.0.5", [{"tool": "nmap", "output": raw}])
    canonical_result = canonical.replay_outputs(
        "scan",
        "10.0.0.5",
        [
            {
                "tool": "nmap",
                "result": {
                    "schema_version": "1.0",
                    "status": "succeeded",
                    "request_id": "provided-request",
                    "execution_id": "provided-execution",
                    "stdout": raw,
                },
            }
        ],
    )

    legacy_pairs = {
        (fact["type"], fact["value"])
        for fact in legacy.fact_store.get_facts("scan", "10.0.0.5")
    }
    canonical_pairs = {
        (fact["type"], fact["value"])
        for fact in canonical.fact_store.get_facts("scan", "10.0.0.5")
    }
    assert legacy_pairs == canonical_pairs
    assert first["new_facts"] > 0
    assert second["new_facts"] == 0
    assert first["execution_results"][0]["request_id"] == second["execution_results"][0]["request_id"]
    assert first["execution_results"][0]["execution_id"] == second["execution_results"][0]["execution_id"]
    assert first["execution_results"][0]["duplicate_output"] is False
    assert second["execution_results"][0]["duplicate_output"] is True
    assert len(legacy.fact_store.get_command_results("scan", "10.0.0.5")) == 2
    assert canonical_result["execution_results"][0]["request_id"] == "provided-request"
    assert canonical_result["execution_results"][0]["execution_id"] == "provided-execution"


def test_failed_stderr_is_audit_only_and_cannot_create_verified_service_facts(tmp_path: Path) -> None:
    store = FactStore(str(tmp_path / "facts.db"))
    runtime = PipelineRuntime(
        str(tmp_path / "runtime.db"),
        runner=lambda _command: "",
        fact_store=store,
    )
    result = adapt_execution_result(
        {
            "schema_version": "1.0",
            "status": "failed",
            "stdout": "",
            "stderr": "22/tcp open ssh OpenSSH 9.9",
            "exit_code": 2,
        },
        tool_name="nmap",
        redact_text=store.redactor.redact_text,
        redact_data=store.redactor.redact_data,
    )

    facts = runtime.parse_output("nmap 10.0.0.5", result)

    assert not any(fact["type"] in {"port_open", "service_version"} for fact in facts)


def test_replay_rejects_unknown_result_schema_major(tmp_path: Path) -> None:
    pipeline = _quiet_pipeline(tmp_path / "future.db")

    with pytest.raises(ValueError, match="Unsupported execution result schema"):
        pipeline.replay_outputs(
            "scan",
            "target",
            [{"tool": "fixture", "result": {"schema_version": "2.0", "status": "succeeded"}}],
        )


def test_replay_schema_preflight_prevents_partial_batch_persistence(tmp_path: Path) -> None:
    pipeline = _quiet_pipeline(tmp_path / "preflight.db")

    with pytest.raises(ValueError, match="Unsupported execution result schema"):
        pipeline.replay_outputs(
            "scan",
            "target",
            [
                {"tool": "nmap", "output": "80/tcp open http nginx"},
                {
                    "tool": "future",
                    "result": {"schema_version": "2.0", "status": "succeeded"},
                },
            ],
        )

    assert pipeline.fact_store.get_facts("scan", "target") == []
    assert pipeline.fact_store.get_command_results("scan", "target") == []


def test_replay_snapshot_schema_migration_is_explicit_and_future_major_fails(tmp_path: Path) -> None:
    snapshot = ReplaySnapshot(str(tmp_path / "snapshot.db"))
    snapshot.pipeline.snapshot_actions = lambda _scan, _target: []

    legacy = snapshot.run({"scan_id": "legacy", "target": "host", "outputs": []})
    current = snapshot.run(
        {"schema_version": "1.0", "scan_id": "current", "target": "host", "outputs": []}
    )

    assert legacy["schema_version"] == "1.0"
    assert legacy["input_schema_version"] == "0"
    assert legacy["migration"] == {"from": "0", "to": "1.0"}
    assert current["schema_version"] == "1.0"
    assert current["input_schema_version"] == "1.0"
    assert current["migration"] is None
    with pytest.raises(ValueError, match="Unsupported replay snapshot schema"):
        snapshot.run({"schema_version": "2.0", "scan_id": "future", "target": "host"})
