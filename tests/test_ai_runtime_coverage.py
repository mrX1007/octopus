"""Hermetic branch coverage for the canonical AI runtime boundary."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.actions import ActionRequest, ActiveRiskClass, PolicyDenial
from core.ai.command_scheduler import CommandDecision
from core.ai.fact_store import CommandCompletionClaim
from core.ai.runtime import PipelineRuntime
from core.execution import (
    ExecutionCancelled,
    ExecutionContext,
    ExecutionDecision,
    ExecutionResult,
    ExecutionStatus,
    ToolInvocation,
    adapt_execution_result,
)

pytestmark = pytest.mark.unit


class StubRedactor:
    def redact_text(self, value, **_kwargs):
        return str(value)

    def redact_data(self, value, **_kwargs):
        return value

    def redact_fact(self, _fact_type, value):
        refs = ("secret://fixture",) if "secret" in str(value) else ()
        return f"safe:{value}", refs


def bare_runtime() -> PipelineRuntime:
    instance = object.__new__(PipelineRuntime)
    instance.facts = SimpleNamespace(redactor=StubRedactor())
    return instance


def context(*, target_scope=("example.com",)) -> ExecutionContext:
    return ExecutionContext.automatic(
        target_scope=target_scope,
        actor="runtime-coverage",
        origin="test",
    )


def execution(*, execution_id="exec-coverage") -> ExecutionResult:
    return adapt_execution_result(
        {
            "schema_version": "1.0",
            "status": "succeeded",
            "stdout": "fixture output",
            "request_id": "request-coverage",
            "execution_id": execution_id,
        },
        tool_name="fixture",
    )


def invocation(name="fixture", *, targets=("example.com",)) -> ToolInvocation:
    return ToolInvocation(
        executable=name,
        argv=(name, "example.com"),
        raw_command=f"{name} example.com",
        registered_name=name,
        targets=targets,
    )


def test_cached_provider_helpers_and_path_special_cases() -> None:
    instance = bare_runtime()
    selector = SimpleNamespace(select=MagicMock(return_value="selection"))
    fallback = object()
    instance._provider_selector = selector
    instance._provider_fallback_executor = fallback
    request = ActionRequest(target="example.com", execution_context=context())

    assert instance.provider_selector is selector
    assert instance.provider_fallback_executor is fallback
    assert instance.select_provider("probe", request, ("fixture",)) == "selection"
    selector.select.assert_called_once_with("probe", request, ("fixture",))

    assert PipelineRuntime._knowledge_graph_path(":memory:") == ":memory:"
    assert PipelineRuntime._knowledge_graph_path("data/facts.db") == "data/knowledge.db"
    assert PipelineRuntime._knowledge_graph_path("facts") == "facts.knowledge.db"
    assert PipelineRuntime._provider_telemetry_path(":memory:") == ":memory:"
    assert (
        PipelineRuntime._provider_telemetry_path("data/facts.db")
        == "data/provider-telemetry.db"
    )
    assert PipelineRuntime._provider_telemetry_path("facts") == "facts.provider-telemetry.db"
    assert PipelineRuntime._decision_trace_path(":memory:") == ":memory:"
    assert PipelineRuntime._decision_trace_path("data/facts.db") == "data/decision-trace.db"
    assert PipelineRuntime._decision_trace_path("facts") == "facts.decision-trace.db"


def test_provider_decision_records_an_unattempted_result() -> None:
    instance = bare_runtime()
    store = SimpleNamespace(record=MagicMock())
    request = ActionRequest(target="example.com", execution_context=context())
    attempt = SimpleNamespace(
        report=SimpleNamespace(execution_result=None, check_result=None),
        ingestion=SimpleNamespace(useful_facts=0, duplicate_facts=0),
        retryable=False,
        fallback_taken=False,
    )
    result = SimpleNamespace(
        final_report=None,
        attempts=(attempt,),
        selection=SimpleNamespace(
            selection_id="selection",
            ranked=(),
            rejected=(),
            chosen_action_id=None,
        ),
    )

    instance._record_provider_decision(store, "probe", request, result)

    payload = store.record.call_args.args[0]
    assert payload["scan_id"] == ""
    assert payload["actual_outcome"]["status"] == "not_attempted"
    assert payload["duration"] == 0.0


def test_retry_decision_and_scheduler_policy_denial() -> None:
    instance = bare_runtime()
    scheduler = SimpleNamespace(decide=MagicMock(return_value="decision"))
    instance.scheduler = scheduler
    ctx = context()

    assert instance.decide("fixture", (), set(), ctx, ("retry-key",)) == "decision"
    assert scheduler.decide.call_args.kwargs["retry_command_keys"] == ("retry-key",)

    instance._runner = lambda _command: pytest.fail("denied command reached runner")
    denied = CommandDecision("fixture", "key", "skip", "policy_denied:scope_mismatch")
    result = instance.execute(denied, ctx)
    assert result.status is ExecutionStatus.BLOCKED
    assert result.metadata["policy_denial"]["reason_code"] == "scope_mismatch"


def test_authorized_invocation_without_final_typed_invocation_uses_legacy_runner() -> None:
    instance = bare_runtime()
    ctx = context()
    initial_invocation = invocation()
    instance.scheduler = SimpleNamespace(
        execution_policy=SimpleNamespace(
            authorize_command=lambda _command, _context: ExecutionDecision(
                True,
                "allowed",
                ctx,
                None,
            )
        )
    )
    instance._dispatch_runner = MagicMock(return_value="legacy result")
    decision = CommandDecision(
        initial_invocation.raw_command,
        "key",
        "execute",
        "allowed",
        invocation=initial_invocation,
    )

    result = instance.execute(decision, ctx)

    assert result.status is ExecutionStatus.SUCCEEDED
    instance._dispatch_runner.assert_called_once_with(decision.command, ctx)


def test_typed_execution_cancellation_is_normalized() -> None:
    instance = bare_runtime()
    instance._dispatch_runner = MagicMock(
        side_effect=ExecutionCancelled("operator_cancelled", stdout="partial")
    )

    result = instance.execute(
        CommandDecision("fixture", "key", "execute", "allowed"),
        context(),
    )

    assert result.status is ExecutionStatus.CANCELLED
    assert result.stdout == "partial"


@pytest.mark.parametrize(
    ("denial", "rejected", "expected_reason", "expected_class"),
    [
        (
            PolicyDenial.create("select", "scope_mismatch"),
            (),
            "scope_mismatch",
            "ExecutionBlocked",
        ),
        (None, (SimpleNamespace(reasons=("not_applicable",)),), "not_applicable", "ProviderUnavailable"),
        (None, (), "provider_unavailable", "ProviderUnavailable"),
    ],
)
def test_registered_action_normalizes_unavailable_runs(
    denial,
    rejected,
    expected_reason,
    expected_class,
) -> None:
    instance = bare_runtime()
    instance.scheduler = SimpleNamespace(command_key=lambda command: f"key:{command}")
    instance._registered_provider_candidates = lambda *_args, **_kwargs: (("primary",), {})
    selection = SimpleNamespace(
        chosen_action_id=None,
        capability="probe",
        selection_id="selection",
        rejected=rejected,
    )
    run = SimpleNamespace(
        final_report=None,
        effective_result=None,
        policy_denial=denial,
        selection=selection,
        attempts=(),
        status=(ExecutionStatus.BLOCKED if denial is not None else ExecutionStatus.UNAVAILABLE),
    )
    instance.execute_with_fallback = lambda *_args, **_kwargs: run
    instance._normalize_result = MagicMock(side_effect=lambda value, **_kwargs: value)

    result = instance._execute_registered_action(
        CommandDecision("fixture", "key", "execute", "allowed"),
        context(target_scope=()),
        invocation(targets=()),
        execution_id="execution",
        policy_ref="policy",
        facts=(),
        capability="",
        provider_commands=(),
        partial_result_ingest=None,
    )

    assert result["error_message"] == expected_reason
    assert result["error_class"] == expected_class


class StubAdapter:
    def __init__(self, risk, *, active=False):
        self.risk = risk
        self.descriptor = SimpleNamespace(
            requirements=SimpleNamespace(active=active),
        )

    def active_risk_class(self, _request, _phase):
        if isinstance(self.risk, BaseException):
            raise self.risk
        return self.risk


def resolved_action(name, risk, *, active=False):
    return SimpleNamespace(
        canonical_id=name,
        adapter=StubAdapter(risk, active=active),
    )


def test_registered_candidates_handle_unknown_and_active_primary() -> None:
    instance = bare_runtime()
    instance._action_catalog = SimpleNamespace(resolve=lambda _name: None)

    assert instance._registered_provider_candidates(
        invocation("unknown"),
        context(),
        target="example.com",
        facts=(),
        provider_commands=(),
    ) == (("unknown",), {})

    active = resolved_action("primary", RuntimeError("classification"), active=True)
    instance._action_catalog = SimpleNamespace(resolve=lambda _name: active)
    candidates, commands = instance._registered_provider_candidates(
        invocation("primary"),
        context(),
        target="example.com",
        facts=(),
        provider_commands=("alternative example.com",),
    )
    assert candidates == ("primary",)
    assert commands == {"primary": "primary example.com"}


def test_registered_candidates_filter_invalid_duplicate_and_active_alternatives() -> None:
    primary = resolved_action("primary", RuntimeError("classification"), active=False)
    duplicate = resolved_action("primary", ActiveRiskClass.READ_ONLY)
    active = resolved_action("active", RuntimeError("classification"), active=True)
    safe = resolved_action("safe", RuntimeError("classification"), active=False)
    resolved = {
        "primary": primary,
        "duplicate": duplicate,
        "active": active,
        "safe": safe,
    }
    alternative_names = {
        "missing-name example.com": None,
        "blank-name example.com": invocation("", targets=()),
        "unknown example.com": invocation("unknown"),
        "duplicate example.com": invocation("duplicate"),
        "active example.com": invocation("active"),
        "safe example.com": invocation("safe"),
    }
    policy = SimpleNamespace(
        authorize_command=lambda command, _context: SimpleNamespace(
            invocation=alternative_names[command]
        )
    )
    instance = bare_runtime()
    instance.scheduler = SimpleNamespace(execution_policy=policy)
    instance._action_catalog = SimpleNamespace(resolve=lambda name: resolved.get(name))
    raw_commands = (
        "",
        "primary example.com",
        *alternative_names,
    )

    candidates, commands = instance._registered_provider_candidates(
        invocation("primary"),
        context(),
        target="example.com",
        facts=({"type": "observation"},),
        provider_commands=raw_commands,
    )

    assert candidates == ("primary", "safe")
    assert commands == {
        "primary": "primary example.com",
        "safe": "safe example.com",
    }


def test_normalize_and_validate_all_schema_edges() -> None:
    instance = bare_runtime()
    long_identifier = "x" * 5000
    normalized = instance.normalize_result(
        {
            "schema_version": "1.0",
            "status": ExecutionStatus.SUCCEEDED,
            "stdout": "ok",
            "request_id": long_identifier,
            "execution_id": long_identifier,
            "policy_decision_ref": long_identifier,
        },
        tool_name=long_identifier,
    )
    assert len(normalized.request_id.encode()) == 4096
    assert len(normalized.execution_id.encode()) == 4096
    assert len(normalized.tool_name.encode()) == 4096
    assert len(normalized.policy_decision_ref.encode()) == 4096

    assert PipelineRuntime.validate_result_schema(execution()) == "1.0"
    assert PipelineRuntime.validate_result_schema({"schema_version": "1.0", "status": "failed"}) == "1.0"
    with pytest.raises(ValueError, match="Unsupported execution result schema"):
        PipelineRuntime.validate_result_schema({"schema_version": "2.0"})
    with pytest.raises(ValueError, match="Unsupported canonical execution status"):
        PipelineRuntime.validate_result_schema({"schema_version": "1.0", "status": "invented"})


def test_persist_completion_fact_redacts_derived_secrets() -> None:
    instance = bare_runtime()
    instance.facts = SimpleNamespace(
        redactor=StubRedactor(),
        add_fact_with_status=MagicMock(side_effect=[(1, True), (2, True), (3, False)]),
    )

    stored = instance._persist_completion_fact(
        "scan",
        "host",
        {"type": "observation", "value": "base"},
        "fixture",
        derived_facts=(
            {"type": "credential", "value": "derived-secret"},
            {"type": "observation", "value": "derived-safe"},
        ),
    )

    assert stored["fact_ids"] == [1, 2, 3]
    assert stored["derived_facts"][0]["secret_refs"] == ["secret://fixture"]
    assert "secret_refs" not in stored["derived_facts"][1]


def persisted_result():
    return {
        "command": "fixture",
        "failed": False,
        "schema_version": "1.0",
        "status": "succeeded",
        "partial": False,
        "execution_id": "execution",
        "request_id": "request",
        "policy_decision_ref": "policy",
        "error_class": "",
        "exit_code": 0,
        "duration": 1.0,
        "output_bytes": 2,
        "stderr_bytes": 0,
        "artifact_count": 0,
        "output_hash": "hash",
        "parsed_facts": 1,
    }


def test_replayed_completion_validates_storage_and_applies_fields() -> None:
    instance = bare_runtime()
    instance.facts = SimpleNamespace(
        get_command_result_by_id=MagicMock(return_value=None),
        get_facts_by_ids=MagicMock(return_value=[]),
    )
    with pytest.raises(RuntimeError, match="no command result"):
        instance._replayed_completion(
            CommandCompletionClaim(replayed=True),
            command_result_fields=None,
        )
    with pytest.raises(RuntimeError, match="no longer available"):
        instance._replayed_completion(
            CommandCompletionClaim(replayed=True, command_result_id=1),
            command_result_fields=None,
        )

    instance.facts.get_command_result_by_id.return_value = persisted_result()
    instance.facts.get_facts_by_ids.return_value = [{"type": "port_open", "value": "443/tcp"}]
    replayed = instance._replayed_completion(
        CommandCompletionClaim(replayed=True, command_result_id=1, fact_ids=(7, 7)),
        command_result_fields={"extra": "field"},
    )
    assert replayed["command_result"]["extra"] == "field"
    assert replayed["command_result"]["fact_ids"] == [7]
    without_fields = instance._replayed_completion(
        CommandCompletionClaim(replayed=True, command_result_id=1, fact_ids=(7,)),
        command_result_fields=None,
    )
    assert "extra" not in without_fields["command_result"]


def completion_runtime(claim: CommandCompletionClaim) -> PipelineRuntime:
    instance = bare_runtime()
    instance.parser = SimpleNamespace(parse_tool_output=lambda _command, _output: [])
    instance.missions = SimpleNamespace(record_attempt_progress=MagicMock())
    instance.facts = SimpleNamespace(
        redactor=StubRedactor(),
        claim_command_completion=MagicMock(return_value=claim),
        drain_assessment_projection_outbox=MagicMock(),
        release_command_completion_claim=MagicMock(),
        renew_command_completion_claim=MagicMock(),
        add_command_result=MagicMock(return_value=(1, True)),
    )
    return instance


def complete(instance: PipelineRuntime, **kwargs):
    return instance.complete_execution(
        "scan",
        "host",
        "key",
        "fixture",
        execution(),
        completion_fence=CommandCompletionClaim(scan_key="scan", scan_generation=1),
        **kwargs,
    )


def test_completion_requires_typed_result_and_fence() -> None:
    instance = bare_runtime()
    with pytest.raises(TypeError, match="requires an ExecutionResult"):
        instance.complete_execution(
            "scan",
            "host",
            "key",
            "fixture",
            object(),
            completion_fence=CommandCompletionClaim(),
        )
    with pytest.raises(TypeError, match="requires a bound completion_fence"):
        instance.complete_execution(
            "scan",
            "host",
            "key",
            "fixture",
            execution(),
            completion_fence=object(),
        )


@pytest.mark.parametrize("replayed", [False, True])
def test_completion_outbox_failure_releases_only_owned_claims(replayed) -> None:
    claim = CommandCompletionClaim(replayed=replayed)
    instance = completion_runtime(claim)
    instance.facts.drain_assessment_projection_outbox.side_effect = RuntimeError("outbox")

    with pytest.raises(RuntimeError, match="outbox"):
        complete(instance)

    assert instance.facts.release_command_completion_claim.call_count == int(not replayed)


def test_completion_replay_records_optional_attempt_progress() -> None:
    claim = CommandCompletionClaim(
        replayed=True,
        command_result_id=1,
        fact_ids=(7,),
    )
    instance = completion_runtime(claim)
    instance.facts.get_command_result_by_id = MagicMock(return_value=persisted_result())
    instance.facts.get_facts_by_ids = MagicMock(
        return_value=[{"type": "port_open", "value": "443/tcp"}]
    )

    replayed = complete(instance, attempt_id="attempt")
    assert replayed["new_facts"] == 0
    instance.missions.record_attempt_progress.assert_called_once_with(
        "attempt",
        fact_ids=(7,),
        execution_ids=("exec-coverage",),
    )

    instance.missions.record_attempt_progress.reset_mock()
    assert complete(instance)["command_result"]["duplicate_output"] is True
    instance.missions.record_attempt_progress.assert_not_called()


def test_completion_preparation_failure_releases_claim() -> None:
    instance = completion_runtime(CommandCompletionClaim())
    instance.parser.parse_tool_output = MagicMock(side_effect=ValueError("parse"))

    with pytest.raises(ValueError, match="parse"):
        complete(instance)

    instance.facts.release_command_completion_claim.assert_called_once()


def test_completion_handles_empty_and_deferred_graph_projection(caplog) -> None:
    instance = completion_runtime(CommandCompletionClaim())
    empty = complete(instance)
    assert empty["graph_projection"] == []

    instance.project_fact_ids = MagicMock(side_effect=RuntimeError("projection"))
    with caplog.at_level("WARNING", logger="octopus.runtime"):
        deferred = complete(instance, initial_fact_ids=(7,), attempt_id="attempt")
    assert deferred["graph_projection"] == []
    assert "Graph projection deferred" in caplog.text
    instance.missions.record_attempt_progress.assert_called_once_with(
        "attempt",
        fact_ids=(7,),
        execution_ids=("exec-coverage",),
    )


def test_ingest_output_handles_a_stored_fact_without_an_id() -> None:
    instance = bare_runtime()
    instance.scheduler = SimpleNamespace(command_key=lambda _command: "key")
    instance.facts = SimpleNamespace(
        redactor=StubRedactor(),
        capture_scan_completion_fence=lambda _scan_id: CommandCompletionClaim(),
    )
    instance.complete_execution = MagicMock(
        return_value={
            "graph_projection": ({"fact_id": 7, "status": "projected"},),
            "stored_base_facts": (
                {
                    "fact_ids": (),
                    "fact": {"type": "observation", "value": "safe"},
                    "created": True,
                },
            ),
        }
    )

    stored = instance.ingest_output("scan", "host", "fixture", execution())

    assert stored == [
        {
            "type": "observation",
            "value": "safe",
            "id": None,
            "created": True,
        }
    ]

    instance.complete_execution.return_value = {
        "graph_projection": (),
        "stored_base_facts": (),
        "facts": ({"type": "observation", "value": "replayed"},),
    }
    assert instance.ingest_output("scan", "host", "fixture", execution()) == [
        {"type": "observation", "value": "replayed", "created": False}
    ]
