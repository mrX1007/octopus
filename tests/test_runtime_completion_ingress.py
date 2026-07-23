"""Contracts for the runtime-owned execution-completion ingress."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from core.ai.command_scheduler import CommandDecision
from core.ai.evaluated_facts import fact_is_decision_usable
from core.ai.fact_store import (
    CommandCompletionConflictError,
    CommandCompletionInProgressError,
    FactStore,
)
from core.ai.pipeline import AIPipeline
from core.ai.runtime import PipelineRuntime
from core.execution import ExecutionContext, ExecutionStatus, adapt_execution_result

pytestmark = [pytest.mark.contract, pytest.mark.replay]


class OneFactParser:
    def __init__(self):
        self.calls = 0

    def parse_tool_output(self, command, output):
        self.calls += 1
        return [
            {
                "type": "port_open",
                "value": "443/tcp (https)",
                "confidence": 90,
                "source_identity": "fixture-probe",
                "observation_method": "tls-handshake",
            }
        ]


def _execution(runtime: PipelineRuntime, execution_id: str = "exec-ingress"):
    return adapt_execution_result(
        {
            "schema_version": "1.0",
            "status": "succeeded",
            "stdout": "443/tcp open https",
            "request_id": "request-ingress",
            "execution_id": execution_id,
        },
        tool_name="probe",
        redact_text=runtime.facts.redactor.redact_text,
        redact_data=runtime.facts.redactor.redact_data,
    )


def test_compatibility_ingest_uses_canonical_timeout_completion_semantics(
    tmp_path: Path,
) -> None:
    runtime = PipelineRuntime(
        str(tmp_path / "compat-ingress.db"),
        runner=lambda _command: "",
        parser=OneFactParser(),
    )
    timeout = adapt_execution_result(
        {
            "schema_version": "1.0",
            "status": "timeout",
            "stdout": "443/tcp open https",
            "request_id": "request-compat-timeout",
            "execution_id": "exec-compat-timeout",
            "error_class": "TimeoutError",
        },
        tool_name="probe",
        redact_text=runtime.facts.redactor.redact_text,
        redact_data=runtime.facts.redactor.redact_data,
    )

    stored = runtime.ingest_output("scan", "host", "probe host", timeout)
    replayed = runtime.ingest_output("scan", "host", "probe host", timeout)
    facts = runtime.facts.get_facts("scan", "host")
    results = runtime.facts.get_command_results("scan", "host")

    assert len(stored) == len(replayed) == len(facts) == 1
    assert stored[0]["created"] is True
    assert replayed[0]["created"] is False
    assert len(results) == 1
    assert results[0]["status"] == "timeout"
    assert results[0]["parsed_facts"] == 1
    assert facts[0]["coverage_status"] == "degraded"
    assert facts[0]["freshness_status"] == "unknown"
    assert fact_is_decision_usable(facts[0]) is False
    assert facts[0]["assessment"]["source_execution_ids"] == [
        "exec-compat-timeout"
    ]


def test_completion_orders_evidence_result_projection_and_attempt_provenance(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda _command: "",
        parser=OneFactParser(),
    )
    mission = runtime.missions.open_mission("scan", "host")
    task = runtime.missions.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "probe",
    )
    attempt = runtime.missions.begin_attempt(
        mission.mission_id,
        task.agent,
        task.task,
        task_id=task.task_id,
    )
    events: list[str] = []
    add_fact = runtime.facts.add_fact_with_status
    add_result = runtime.facts.add_command_result
    project = runtime.project_fact_ids
    progress = runtime.missions.record_attempt_progress

    def record_fact(*args, **kwargs):
        events.append("fact")
        return add_fact(*args, **kwargs)

    def record_result(*args, **kwargs):
        events.append("result")
        return add_result(*args, **kwargs)

    def record_projection(*args, **kwargs):
        events.append("projection")
        return project(*args, **kwargs)

    def record_progress(*args, **kwargs):
        events.append("attempt")
        return progress(*args, **kwargs)

    monkeypatch.setattr(runtime.facts, "add_fact_with_status", record_fact)
    monkeypatch.setattr(runtime.facts, "add_command_result", record_result)
    monkeypatch.setattr(runtime, "project_fact_ids", record_projection)
    monkeypatch.setattr(runtime.missions, "record_attempt_progress", record_progress)

    completion = runtime.complete_execution(
        "scan",
        "host",
        "probe host",
        "probe host",
        _execution(runtime),
        derive_facts=lambda _host, _fact, _source: [
            {
                "type": "web_endpoint",
                "value": "https://host/",
                "confidence": 85,
            }
        ],
        attempt_id=attempt.attempt_id,
        idempotency_key="execution:exec-ingress",
        completion_fence=runtime.facts.capture_scan_completion_fence("scan"),
    )

    assert events == ["fact", "fact", "result", "projection", "attempt"]
    assert completion["new_facts"] == 2
    assert completion["parsed_facts"] == 1
    assert len(runtime.facts.get_command_results("scan", "host")) == 1
    stored_by_type = {
        fact["type"]: fact for fact in runtime.facts.get_facts("scan", "host")
    }
    for fact_type in ("port_open", "web_endpoint"):
        observation = stored_by_type[fact_type]["observations"][0]
        assert observation["source_identity"] == "fixture-probe"
        assert observation["observation_method"] == "tls-handshake"
    persisted_attempt = next(
        item
        for item in runtime.missions.snapshot(mission.mission_id).attempts
        if item.attempt_id == attempt.attempt_id
    )
    assert persisted_attempt.execution_ids == ("exec-ingress",)
    assert persisted_attempt.fact_ids == tuple(
        completion["command_result"]["fact_ids"]
    )


def test_completion_replay_is_idempotent_without_executing_a_tool(
    tmp_path: Path,
) -> None:
    runner_calls: list[str] = []
    parser = OneFactParser()
    after_facts_calls: list[tuple[dict, ...]] = []
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda command: runner_calls.append(command),
        parser=parser,
    )
    execution = _execution(runtime, "exec-replayed")

    first = runtime.complete_execution(
        "scan",
        "host",
        "probe host",
        "probe host",
        execution,
        idempotency_key="execution:exec-replayed",
        completion_fence=runtime.facts.capture_scan_completion_fence("scan"),
        after_facts=lambda facts: after_facts_calls.append(tuple(facts)),
    )
    first_fact = runtime.facts.get_facts("scan", "host")[0]
    replay_fact_id = first["command_result"]["fact_ids"][0]
    with runtime.facts._get_conn() as conn:
        runtime.facts._enqueue_assessment_projections_in_connection(
            conn,
            (replay_fact_id,),
        )
    assert runtime.facts.pending_assessment_projections() != []
    second = runtime.complete_execution(
        "scan",
        "host",
        "probe host",
        "probe host",
        execution,
        idempotency_key="execution:exec-replayed",
        completion_fence=runtime.facts.capture_scan_completion_fence("scan"),
        after_facts=lambda facts: after_facts_calls.append(tuple(facts)),
    )

    assert runner_calls == []
    assert parser.calls == 1
    assert len(after_facts_calls) == 1
    assert first["new_facts"] == 1
    assert second["new_facts"] == 0
    assert second["command_result"]["status"] == first["command_result"]["status"]
    assert second["command_result"]["output_hash"] == first["command_result"]["output_hash"]
    assert second["command_result"]["fact_ids"] == first["command_result"]["fact_ids"]
    assert runtime.facts.pending_assessment_projections() == []
    replayed_facts = runtime.facts.get_facts("scan", "host")
    assert len(replayed_facts) == 1
    assert len(replayed_facts[0]["observations"]) == 1
    assert replayed_facts[0]["timestamp"] == first_fact["timestamp"]
    assert len(runtime.facts.get_command_results("scan", "host")) == 1
    fact_id = first["command_result"]["fact_ids"][0]
    assert len(runtime.facts.assessments.history(fact_id)) == 1


def test_completion_replay_repairs_attempt_tail_without_replaying_evidence(
    tmp_path: Path,
) -> None:
    parser = OneFactParser()
    runtime = PipelineRuntime(
        str(tmp_path / "attempt-tail.db"),
        runner=lambda _command: "",
        parser=parser,
    )
    mission = runtime.missions.open_mission("scan", "host")
    task = runtime.missions.register_task(mission.mission_id, "DiscoveryAgent", "probe")
    attempt = runtime.missions.begin_attempt(
        mission.mission_id,
        task.agent,
        task.task,
        task_id=task.task_id,
    )
    execution = _execution(runtime, "exec-attempt-tail")
    first = runtime.complete_execution(
        "scan",
        "host",
        "probe host",
        "probe host",
        execution,
        idempotency_key="execution:exec-attempt-tail",
        completion_fence=runtime.facts.capture_scan_completion_fence("scan"),
    )

    replayed = runtime.complete_execution(
        "scan",
        "host",
        "probe host",
        "probe host",
        execution,
        attempt_id=attempt.attempt_id,
        idempotency_key="execution:exec-attempt-tail",
        completion_fence=runtime.facts.capture_scan_completion_fence("scan"),
    )

    persisted_attempt = next(
        item
        for item in runtime.missions.snapshot(mission.mission_id).attempts
        if item.attempt_id == attempt.attempt_id
    )
    assert parser.calls == 1
    assert replayed["new_facts"] == 0
    assert persisted_attempt.fact_ids == tuple(first["command_result"]["fact_ids"])
    assert persisted_attempt.execution_ids == ("exec-attempt-tail",)


@pytest.mark.parametrize("conflict", ["output", "status", "request", "scope"])
def test_completion_conflicts_fail_before_parser_facts_or_callbacks(
    tmp_path: Path,
    conflict: str,
) -> None:
    parser = OneFactParser()
    callbacks: list[tuple[dict, ...]] = []
    runtime = PipelineRuntime(
        str(tmp_path / f"{conflict}.db"),
        runner=lambda _command: "",
        parser=parser,
    )
    first = _execution(runtime, f"exec-{conflict}")
    runtime.complete_execution(
        "scan",
        "host",
        "probe host",
        "probe host",
        first,
        idempotency_key=f"execution:exec-{conflict}",
        completion_fence=runtime.facts.capture_scan_completion_fence("scan"),
        after_facts=lambda facts: callbacks.append(tuple(facts)),
    )
    replay = _execution(runtime, f"exec-{conflict}")
    scan_id, host = "scan", "host"
    if conflict == "output":
        replay.stdout = "8443/tcp open https"
    elif conflict == "status":
        replay.status = ExecutionStatus.FAILED
    elif conflict == "request":
        replay.request_id = "different-request-envelope"
    else:
        scan_id, host = "other-scan", "other-host"

    with pytest.raises(CommandCompletionConflictError):
        runtime.complete_execution(
            scan_id,
            host,
            "probe host",
            "probe host",
            replay,
            idempotency_key=f"execution:exec-{conflict}",
            completion_fence=runtime.facts.capture_scan_completion_fence(scan_id),
            after_facts=lambda facts: callbacks.append(tuple(facts)),
        )

    assert parser.calls == 1
    assert len(callbacks) == 1
    assert len(runtime.facts.get_facts("scan", "host")) == 1
    assert len(runtime.facts.get_command_results("scan", "host")) == 1
    if conflict == "scope":
        assert runtime.facts.get_facts(scan_id, host) == []
        assert runtime.facts.get_command_results(scan_id, host) == []


def test_abandoned_completion_claim_is_reclaimed_after_its_lease(
    tmp_path: Path,
) -> None:
    now = [100.0]
    store = FactStore(
        str(tmp_path / "claim-lease.db"),
        completion_clock=lambda: now[0],
        completion_lease_seconds=10.0,
    )
    claim_fields = {
        "scan_id": "scan",
        "host": "host",
        "command_key": "probe host",
        "command": "probe host",
        "output_hash": "a" * 64,
        "status": "succeeded",
        "failed": False,
        "partial": False,
        "execution_id": "exec-lease",
        "idempotency_key": "execution:exec-lease",
    }
    abandoned = store.claim_command_completion(**claim_fields)
    with pytest.raises(CommandCompletionInProgressError):
        store.claim_command_completion(**claim_fields)

    now[0] = 111.0
    recovered = store.claim_command_completion(**claim_fields)
    result_id, unique = store.add_command_result(
        "scan",
        "host",
        "probe host",
        "probe host",
        "a" * 64,
        status="succeeded",
        execution_id="exec-lease",
        idempotency_key="execution:exec-lease",
        completion_claim=recovered,
    )
    replayed = store.claim_command_completion(**claim_fields)

    assert abandoned.owner_token != recovered.owner_token
    assert unique is True
    assert replayed.replayed is True
    assert replayed.command_result_id == result_id


def test_stale_completion_owner_is_fenced_inside_fact_transaction(
    tmp_path: Path,
) -> None:
    now = [100.0]
    store = FactStore(
        str(tmp_path / "claim-fence.db"),
        completion_clock=lambda: now[0],
        completion_lease_seconds=10.0,
    )
    claim_fields = {
        "scan_id": "scan",
        "host": "host",
        "command_key": "probe host",
        "command": "probe host",
        "output_hash": "a" * 64,
        "status": "succeeded",
        "failed": False,
        "partial": False,
        "execution_id": "exec-fence",
        "idempotency_key": "execution:exec-fence",
    }
    stale = store.claim_command_completion(**claim_fields)
    now[0] = 111.0
    current = store.claim_command_completion(**claim_fields)

    with pytest.raises(CommandCompletionInProgressError):
        store.add_fact_with_status(
            "scan",
            "host",
            "observation",
            "stale-owner-write",
            "probe",
            completion_claim=stale,
        )

    assert store.get_facts("scan", "host") == []
    fact_id, created = store.add_fact_with_status(
        "scan",
        "host",
        "observation",
        "current-owner-write",
        "probe",
        completion_claim=current,
    )
    assert created is True
    assert fact_id > 0


def test_clear_scan_rejects_live_claim_and_fences_an_expired_owner(
    tmp_path: Path,
) -> None:
    now = [100.0]
    store = FactStore(
        str(tmp_path / "clear-fence.db"),
        completion_clock=lambda: now[0],
        completion_lease_seconds=10.0,
    )
    claim = store.claim_command_completion(
        scan_id="scan",
        host="host",
        command_key="probe host",
        command="probe host",
        output_hash="a" * 64,
        status="succeeded",
        failed=False,
        partial=False,
        execution_id="exec-clear",
        idempotency_key="execution:exec-clear",
    )

    with pytest.raises(CommandCompletionInProgressError):
        store.clear_scan("scan")

    now[0] = 111.0
    store.clear_scan("scan")
    with pytest.raises(CommandCompletionConflictError):
        store.add_fact_with_status(
            "scan",
            "host",
            "observation",
            "write-after-clear",
            "probe",
            completion_claim=claim,
        )
    assert store.get_facts("scan", "host") == []


def test_scan_generation_fences_claim_and_generation_only_fact_after_clear(
    tmp_path: Path,
) -> None:
    store = FactStore(str(tmp_path / "scan-generation.db"))
    fence = store.capture_scan_completion_fence("scan")

    assert fence.scan_generation == 0
    store.clear_scan("scan")
    assert store.scan_completion_generation("scan") == 1

    with pytest.raises(CommandCompletionConflictError):
        store.claim_command_completion(
            scan_id="scan",
            host="host",
            command_key="probe host",
            command="probe host",
            output_hash="a" * 64,
            status="succeeded",
            failed=False,
            partial=False,
            execution_id="exec-before-clear",
            idempotency_key="execution:exec-before-clear",
            scan_generation=fence.scan_generation,
        )
    with pytest.raises(CommandCompletionConflictError):
        store.add_fact_with_status(
            "scan",
            "host",
            "observation",
            "generation-only-write-after-clear",
            "probe",
            completion_claim=fence,
        )

    assert store.get_facts("scan", "host") == []
    assert store.get_command_results("scan", "host") == []
    with store._get_conn() as conn:
        assert conn.execute("SELECT 1 FROM command_completion_claims").fetchall() == []


def test_stale_generation_without_idempotency_fails_before_parser_or_callback(
    tmp_path: Path,
) -> None:
    parser = OneFactParser()
    callbacks: list[tuple[dict, ...]] = []
    runtime = PipelineRuntime(
        str(tmp_path / "no-idempotency-generation.db"),
        runner=lambda _command: "",
        parser=parser,
    )
    fence = runtime.facts.capture_scan_completion_fence("scan")
    runtime.facts.clear_scan("scan")

    with pytest.raises(CommandCompletionConflictError):
        runtime.complete_execution(
            "scan",
            "host",
            "probe host",
            "probe host",
            _execution(runtime, "exec-no-idempotency-fence"),
            completion_fence=fence,
            after_facts=lambda facts: callbacks.append(tuple(facts)),
        )

    assert parser.calls == 0
    assert callbacks == []
    assert runtime.facts.get_facts("scan", "host") == []
    assert runtime.facts.get_command_results("scan", "host") == []


def test_completion_without_a_bound_fence_fails_closed(
    tmp_path: Path,
) -> None:
    parser = OneFactParser()
    callbacks: list[tuple[dict, ...]] = []
    runtime = PipelineRuntime(
        str(tmp_path / "missing-generation-fence.db"),
        runner=lambda _command: "",
        parser=parser,
    )

    with pytest.raises(TypeError, match="completion_fence"):
        runtime.complete_execution(
            "scan",
            "host",
            "probe host",
            "probe host",
            _execution(runtime, "exec-missing-fence"),
            after_facts=lambda facts: callbacks.append(tuple(facts)),
        )

    assert parser.calls == 0
    assert callbacks == []
    assert runtime.facts.get_facts("scan", "host") == []
    assert runtime.facts.get_command_results("scan", "host") == []


def test_scan_generation_survives_reopen_and_each_clear_increments_it(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "durable-scan-generation.db"
    first = FactStore(str(db_path))
    before_first_clear = first.capture_scan_completion_fence("scan")
    first.clear_scan("scan")

    reopened = FactStore(str(db_path))
    before_second_clear = reopened.capture_scan_completion_fence("scan")
    reopened.clear_scan("scan")

    reopened_again = FactStore(str(db_path))
    assert before_first_clear.scan_generation == 0
    assert before_second_clear.scan_generation == 1
    assert reopened_again.scan_completion_generation("scan") == 2
    with reopened_again._get_conn() as conn:
        generation_row = conn.execute(
            "SELECT scan_key, generation FROM scan_completion_generations"
        ).fetchone()
    assert generation_row == (
        reopened_again._completion_scan_key("scan"),
        2,
    )
    assert generation_row[0] != "scan"


def test_generation_token_cannot_authorize_a_different_scan_fact(
    tmp_path: Path,
) -> None:
    store = FactStore(str(tmp_path / "wrong-scan-generation.db"))
    fence = store.capture_scan_completion_fence("scan-a")

    with pytest.raises(CommandCompletionConflictError):
        store.add_fact_with_status(
            "scan-b",
            "host",
            "observation",
            "wrong-scan-write",
            "probe",
            completion_claim=fence,
        )

    assert store.get_facts("scan-a") == []
    assert store.get_facts("scan-b") == []


def test_bound_generation_token_cannot_authorize_a_different_runtime_scan(
    tmp_path: Path,
) -> None:
    parser = OneFactParser()
    callbacks: list[tuple[dict, ...]] = []
    runtime = PipelineRuntime(
        str(tmp_path / "wrong-runtime-scan-generation.db"),
        runner=lambda _command: "",
        parser=parser,
    )
    fence = runtime.facts.capture_scan_completion_fence("scan-a")

    with pytest.raises(CommandCompletionConflictError):
        runtime.complete_execution(
            "scan-b",
            "host",
            "probe host",
            "probe host",
            _execution(runtime, "exec-wrong-runtime-scan"),
            completion_fence=fence,
            after_facts=lambda facts: callbacks.append(tuple(facts)),
        )

    assert parser.calls == 0
    assert callbacks == []
    assert runtime.facts.get_facts("scan-a") == []
    assert runtime.facts.get_facts("scan-b") == []


def test_clear_while_dispatch_is_blocked_fences_the_returned_execution(
    tmp_path: Path,
) -> None:
    pipeline = AIPipeline(str(tmp_path / "dispatch-clear.db"))
    pipeline.runtime.decide = (
        lambda command, _facts, _keys, _context, *_retry: CommandDecision(
            command,
            "probe host",
            "execute",
            "fixture",
        )
    )
    pipeline._execution_context = lambda _scan, _target: ExecutionContext.automatic(
        target_scope=("host",)
    )
    dispatch_entered = Event()
    dispatch_release = Event()
    execution = _execution(pipeline.runtime, "exec-returned-after-clear")

    def blocked_execute(_decision, _context):
        dispatch_entered.set()
        if not dispatch_release.wait(timeout=5):
            raise TimeoutError("test did not release blocked dispatch")
        return execution

    pipeline.runtime.execute = blocked_execute
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            pipeline._execute_pipeline_command,
            "scan",
            "host",
            "probe host",
            "Fact",
            "[Running]",
        )
        assert dispatch_entered.wait(timeout=5)
        assert pipeline.fact_store.get_facts("scan", "host") != []
        try:
            pipeline.fact_store.clear_scan("scan")
        finally:
            dispatch_release.set()
        with pytest.raises(CommandCompletionConflictError):
            future.result(timeout=5)

    assert pipeline.fact_store.scan_completion_generation("scan") == 1
    assert pipeline.fact_store.get_facts("scan", "host") == []
    assert pipeline.fact_store.get_command_results("scan", "host") == []
    with pipeline.fact_store._get_conn() as conn:
        assert conn.execute("SELECT 1 FROM command_completion_claims").fetchall() == []


def test_clear_during_replay_preparation_fences_the_whole_batch(
    tmp_path: Path,
) -> None:
    pipeline = AIPipeline(str(tmp_path / "replay-prepare-clear.db"))
    prepare_entered = Event()
    prepare_release = Event()
    prepare_entry = pipeline._prepare_replay_entry

    def blocked_prepare(entry):
        prepare_entered.set()
        if not prepare_release.wait(timeout=5):
            raise TimeoutError("test did not release replay preparation")
        return prepare_entry(entry)

    pipeline._prepare_replay_entry = blocked_prepare
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            pipeline.replay_outputs,
            "scan",
            "host",
            [{"tool": "nmap", "output": "443/tcp open https"}],
        )
        assert prepare_entered.wait(timeout=5)
        try:
            pipeline.fact_store.clear_scan("scan")
        finally:
            prepare_release.set()
        with pytest.raises(CommandCompletionConflictError):
            future.result(timeout=5)

    assert pipeline.fact_store.get_facts("scan", "host") == []
    assert pipeline.fact_store.get_command_results("scan", "host") == []


def test_clear_between_replay_entries_fences_the_remaining_batch(
    tmp_path: Path,
) -> None:
    pipeline = AIPipeline(str(tmp_path / "replay-batch-clear.db"))
    first_completed = Event()
    first_release = Event()
    complete_execution = pipeline.runtime.complete_execution
    completion_calls = 0

    def block_after_first_completion(*args, **kwargs):
        nonlocal completion_calls
        completion = complete_execution(*args, **kwargs)
        completion_calls += 1
        if completion_calls == 1:
            first_completed.set()
            if not first_release.wait(timeout=5):
                raise TimeoutError("test did not release first replay completion")
        return completion

    pipeline.runtime.complete_execution = block_after_first_completion
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            pipeline.replay_outputs,
            "scan",
            "host",
            [
                {"tool": "nmap", "output": "443/tcp open https"},
                {"tool": "nmap", "output": "80/tcp open http"},
            ],
        )
        assert first_completed.wait(timeout=5)
        assert pipeline.fact_store.get_command_results("scan", "host") != []
        try:
            pipeline.fact_store.clear_scan("scan")
        finally:
            first_release.set()
        with pytest.raises(CommandCompletionConflictError):
            future.result(timeout=5)

    assert completion_calls == 1
    assert pipeline.fact_store.get_facts("scan", "host") == []
    assert pipeline.fact_store.get_command_results("scan", "host") == []


def test_legacy_result_adoption_ignores_redacted_display_fields(
    tmp_path: Path,
) -> None:
    store = FactStore(str(tmp_path / "legacy-adoption.db"))
    secret = "legacy-command-secret"
    store.secret_store.store(secret, kind="test")
    command = f"probe --token={secret} host " + "x" * 20_000
    result_id, _unique = store.add_command_result(
        "scan",
        "host",
        "probe host",
        command,
        "a" * 64,
        status="succeeded",
        execution_id="exec-legacy-adoption",
        request_id=f"request-{secret}",
        policy_decision_ref=f"policy-{secret}",
        idempotency_key="execution:exec-legacy-adoption",
    )
    with store._get_conn() as conn:
        conn.execute("DELETE FROM command_completion_claims")
        conn.execute(
            "UPDATE command_results SET completion_fingerprint = '' WHERE id = ?",
            (result_id,),
        )

    claim_fields = {
        "scan_id": "scan",
        "host": "host",
        "command_key": "probe host",
        "command": command,
        "output_hash": "a" * 64,
        "status": "succeeded",
        "failed": False,
        "partial": False,
        "execution_id": "exec-legacy-adoption",
        "idempotency_key": "execution:exec-legacy-adoption",
        "request_id": f"request-{secret}",
        "policy_decision_ref": f"policy-{secret}",
    }
    with pytest.raises(CommandCompletionConflictError):
        store.claim_command_completion(
            **{
                **claim_fields,
                "command": "different probe command",
            }
        )
    adopted = store.claim_command_completion(**claim_fields)

    assert adopted.replayed is True
    assert adopted.command_result_id == result_id


def test_normalization_failure_releases_claim_before_evidence_writes(
    tmp_path: Path,
) -> None:
    runtime = PipelineRuntime(
        str(tmp_path / "normalization-failure.db"),
        runner=lambda _command: "",
        parser=OneFactParser(),
    )

    def fail_normalization(_host, _fact):
        raise RuntimeError("normalization failed")

    with pytest.raises(RuntimeError, match="normalization failed"):
        runtime.complete_execution(
            "scan",
            "host",
            "probe host",
            "probe host",
            _execution(runtime, "exec-normalization-failure"),
            normalize_fact=fail_normalization,
            idempotency_key="execution:exec-normalization-failure",
            completion_fence=runtime.facts.capture_scan_completion_fence("scan"),
        )

    assert runtime.facts.get_facts("scan", "host") == []
    with runtime.facts._get_conn() as conn:
        claims = conn.execute(
            "SELECT idempotency_key FROM command_completion_claims"
        ).fetchall()
    assert claims == []


def test_completion_persists_legacy_failure_projection_for_canonical_success(
    tmp_path: Path,
) -> None:
    runtime = PipelineRuntime(
        str(tmp_path / "legacy-failure.db"),
        runner=lambda _command: "",
        parser=OneFactParser(),
    )
    execution = adapt_execution_result(
        {
            "schema_version": "1.0",
            "status": "succeeded",
            "stdout": "[!] error: provider returned no usable output",
            "execution_id": "exec-error-shaped",
        },
        tool_name="legacy-provider",
        redact_text=runtime.facts.redactor.redact_text,
        redact_data=runtime.facts.redactor.redact_data,
    )

    completion = runtime.complete_execution(
        "scan",
        "host",
        "legacy-provider host",
        "legacy-provider host",
        execution,
        idempotency_key="execution:exec-error-shaped",
        completion_fence=runtime.facts.capture_scan_completion_fence("scan"),
    )

    persisted = runtime.facts.get_command_results("scan", "host")[0]
    assert completion["command_result"]["failed"] is True
    assert persisted["status"] == "succeeded"
    assert persisted["failed"] is True


def test_production_and_snapshot_replay_delegate_to_completion_ingress(
    tmp_path: Path,
    monkeypatch,
) -> None:
    pipeline = AIPipeline(str(tmp_path / "pipeline.db"))
    pipeline.runtime.decide = (
        lambda command, _facts, _keys, _context, *_retry: CommandDecision(
            command,
            "probe host",
            "execute",
            "fixture",
        )
    )
    pipeline.runtime._runner = lambda _command: "443/tcp open https"
    calls: list[str] = []
    complete = pipeline.runtime.complete_execution

    def observe_completion(*args, **kwargs):
        calls.append(str(kwargs.get("source") or args[3]))
        return complete(*args, **kwargs)

    monkeypatch.setattr(pipeline.runtime, "complete_execution", observe_completion)

    context = ExecutionContext.automatic(target_scope=("host",))
    pipeline._execution_context = lambda _scan, _target: context
    pipeline._execute_pipeline_command(
        "scan",
        "host",
        "probe host",
        "Fact",
        "[Running]",
    )
    pipeline.replay_outputs(
        "replay-scan",
        "host",
        [{"tool": "nmap", "output": "443/tcp open https"}],
    )

    assert calls == ["probe host", "replay:nmap"]


def test_pipeline_caller_handles_an_exact_completion_replay(tmp_path: Path) -> None:
    pipeline = AIPipeline(str(tmp_path / "pipeline-replay.db"))
    pipeline.runtime.decide = (
        lambda command, _facts, _keys, _context, *_retry: CommandDecision(
            command,
            "probe host",
            "execute",
            "fixture",
        )
    )
    execution = _execution(pipeline.runtime, "exec-pipeline-replay")
    pipeline.runtime.execute = lambda _decision, _context: execution
    context = ExecutionContext.automatic(target_scope=("host",))
    pipeline._execution_context = lambda _scan, _target: context
    parse_calls = 0
    parse_output = pipeline.runtime.parse_output

    def count_parse(command, result):
        nonlocal parse_calls
        parse_calls += 1
        return parse_output(command, result)

    pipeline.runtime.parse_output = count_parse

    first = pipeline._execute_pipeline_command(
        "scan",
        "host",
        "probe host",
        "Fact",
        "[Running]",
    )
    replayed = pipeline._execute_pipeline_command(
        "scan",
        "host",
        "probe host",
        "Fact",
        "[Running]",
    )

    assert parse_calls == 1
    assert replayed["new_facts"] == 0
    assert replayed["command_result"]["check_status"] == first["command_result"][
        "check_status"
    ]
    assert len(pipeline.fact_store.get_command_results("scan", "host")) == 1
