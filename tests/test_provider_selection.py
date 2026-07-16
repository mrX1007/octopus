"""Provider telemetry, explainable selection, and fallback boundaries."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any

import pytest

from core.actions import (
    ActionAdapter,
    ActionCatalog,
    ActionDescriptor,
    ActionExecutor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    IngestionOutcome,
    ProviderCircuitBreaker,
    ProviderFallbackExecutor,
    ProviderSelector,
    ProviderTelemetryEvent,
    ProviderTelemetryStore,
    RetryClassifier,
    target_class,
)
from core.ai.runtime import PipelineRuntime
from core.execution import ExecutionContext, ExecutionPolicy, ExecutionStatus


def automatic(target: str = "example.com") -> ExecutionContext:
    return ExecutionContext.automatic(
        target_scope=(target,),
        actor="provider-test",
        origin="test",
    )


class SequenceAdapter(ActionAdapter):
    def __init__(
        self,
        action_id: str,
        results: list[Any],
        events: list[str],
        *,
        policy_name: str = "nmap",
        requirements: ActionRequirements | None = None,
    ) -> None:
        self.results = results
        self.events = events
        self.policy_name = policy_name
        self.execute_calls = 0
        self.descriptor = ActionDescriptor(
            action_id=action_id,
            name=action_id.replace(":", "_"),
            kind=ActionKind.REGISTERED_TOOL,
            provider=action_id.split(":", 1)[0],
            requirements=requirements or ActionRequirements(),
        )

    def invocation(self, request: ActionRequest, phase: str):
        return self.registered_invocation(
            f"{self.policy_name} {request.target}",
            self.policy_name,
        )

    def execute(self, request: ActionRequest) -> Any:
        self.execute_calls += 1
        self.events.append(f"execute:{self.descriptor.action_id}")
        return self.results.pop(0)


def provider_stack(*adapters: ActionAdapter):
    catalog = ActionCatalog()
    for adapter in adapters:
        catalog.register(adapter)
    policy = ExecutionPolicy()
    telemetry = ProviderTelemetryStore(":memory:")
    selector = ProviderSelector(catalog, policy, telemetry)
    executor = ActionExecutor(catalog, policy)
    return telemetry, selector, ProviderFallbackExecutor(selector, executor, telemetry)


def telemetry_event(
    provider_id: str,
    status: str,
    index: int,
    **overrides: Any,
) -> ProviderTelemetryEvent:
    values: dict[str, Any] = {
        "provider_id": provider_id,
        "capability": "service_discovery",
        "target_class": "dns",
        "status": status,
        "dependency_available": True,
        "scope_compatible": True,
        "active_risk": 0.0,
        "duration": float(index),
        "useful_facts": 2,
        "duplicate_facts": 0,
        "parser_items": 2,
        "parser_errors": 0,
        "execution_id": f"exec-{index}",
        "observed_at": float(index),
    }
    values.update(overrides)
    return ProviderTelemetryEvent(**values)


def test_target_classification_never_retains_the_raw_target():
    cases = {
        "https://example.com/private/path": "url_https_dns",
        "10.20.30.40": "ip4_private",
        "8.8.8.8": "ip4_public",
        "10.20.0.0/16": "network_4_private",
        "internal-host": "opaque",
    }

    for raw, expected in cases.items():
        classified = target_class(raw)
        assert classified == expected
        assert raw not in classified


def test_telemetry_is_idempotent_bounded_and_persistent(tmp_path):
    db_path = tmp_path / "provider-telemetry.db"
    store = ProviderTelemetryStore(
        str(db_path),
        max_events_per_key=5,
        max_total_events=20,
    )
    for index in range(1, 9):
        status = "timeout" if index % 2 else "succeeded"
        assert store.record(telemetry_event("test:a", status, index)) is True

    assert store.count() == 5
    assert store.record(telemetry_event("test:a", "timeout", 7, observed_at=99.0)) is False
    assert store.count() == 5
    summary = store.summary("test:a", "service_discovery", "dns")
    assert summary.samples == 5
    assert summary.timeout_rate == pytest.approx(2 / 5)
    assert summary.success_rate == pytest.approx(3 / 5)
    assert summary.useful_fact_yield == pytest.approx(2.0)
    assert summary.parser_quality == pytest.approx(1.0)
    store.close()

    reopened = ProviderTelemetryStore(str(db_path), max_events_per_key=5)
    assert reopened.count() == 5
    assert reopened.summary("test:a", "service_discovery", "dns").samples == 5
    reopened.close()


def test_selector_ranks_history_and_explains_every_rejection_without_execution():
    events: list[str] = []
    slow = SequenceAdapter("test:a", [{"status": "succeeded"}], events)
    useful = SequenceAdapter("test:b", [{"status": "succeeded"}], events)
    useful.descriptor = ActionDescriptor(
        action_id="test:b",
        name="test_b",
        kind=ActionKind.REGISTERED_TOOL,
        provider="test",
        aliases=("useful-alias",),
    )
    missing = SequenceAdapter(
        "test:missing",
        [{"status": "succeeded"}],
        events,
        requirements=ActionRequirements(
            system_dependencies=("octopus-definitely-missing-provider",),
        ),
    )
    active = SequenceAdapter(
        "test:active",
        [{"status": "succeeded"}],
        events,
        policy_name="msf_run",
        requirements=ActionRequirements(active=True),
    )
    telemetry, selector, _fallback = provider_stack(slow, useful, missing, active)
    for index in range(1, 5):
        telemetry.record(
            telemetry_event(
                "test:a",
                "timeout",
                index,
                useful_facts=0,
                duplicate_facts=2,
                parser_errors=2,
            )
        )
        telemetry.record(telemetry_event("test:b", "succeeded", index + 10))

    selection = selector.select(
        "service_discovery",
        ActionRequest("example.com", automatic()),
        [
            "test:a",
            "test:b",
            "useful-alias",
            "test:missing",
            "test:active",
            "unknown-provider",
        ],
    )

    assert selection.chosen_action_id == "test:b"
    assert [item.action_id for item in selection.ranked] == ["test:b", "test:a"]
    rejected = {item.action_id: item for item in selection.rejected}
    assert any(reason.startswith("not_applicable:binary:") for reason in rejected["test:missing"].reasons)
    assert "authorization:active_tool_requires_approval" in rejected["test:active"].reasons
    assert rejected["unknown:unknown-provider"].reasons == ("unknown_action",)
    assert events == []
    assert slow.execute_calls == useful.execute_calls == missing.execute_calls == active.execute_calls == 0
    serialized = json.dumps(selection.to_dict(), sort_keys=True)
    assert "example.com" not in serialized
    assert "telemetry:timeouts" in serialized


def test_scope_rejection_trace_retains_only_the_policy_reason_code():
    events: list[str] = []
    provider = SequenceAdapter("test:a", [{"status": "succeeded"}], events)
    _telemetry, selector, _fallback = provider_stack(provider)
    context = ExecutionContext.automatic(
        target_scope=("allowed.example",),
        actor="provider-test",
        origin="test",
    )

    selection = selector.select(
        "service_discovery",
        ActionRequest("private-target.example", context),
        ["test:a"],
    )

    assert selection.ranked == ()
    assert "authorization:target_out_of_scope" in selection.rejected[0].reasons
    assert "private-target.example" not in json.dumps(selection.to_dict())


def test_repeated_unavailable_results_open_then_half_open_the_provider_circuit():
    events: list[str] = []
    unavailable = SequenceAdapter("test:a", [{"status": "succeeded"}], events)
    healthy = SequenceAdapter("test:b", [{"status": "succeeded"}], events)
    telemetry, selector, _fallback = provider_stack(unavailable, healthy)
    observed = time.time()
    for index in range(3):
        telemetry.record(
            telemetry_event(
                "test:a",
                "unavailable",
                100 + index,
                dependency_available=False,
                observed_at=observed + index,
            )
        )

    selection = selector.select(
        "service_discovery",
        ActionRequest("example.com", automatic()),
        ["test:a", "test:b"],
    )

    rejected = {item.action_id: item for item in selection.rejected}
    assert selection.chosen_action_id == "test:b"
    assert rejected["test:a"].circuit_state == "open"
    assert "circuit:open:repeated_unavailable" in rejected["test:a"].reasons
    assert unavailable.execute_calls == 0

    breaker = ProviderCircuitBreaker(
        telemetry,
        failure_threshold=3,
        cooldown_seconds=10,
    )
    state = breaker.evaluate(
        "test:a",
        "service_discovery",
        "dns",
        now=observed + 30,
    )
    assert state.state == "half_open"
    assert state.allowed is True

    telemetry.record(
        telemetry_event(
            "test:a",
            "succeeded",
            200,
            observed_at=observed + 31,
        )
    )
    recovered = breaker.evaluate(
        "test:a",
        "service_discovery",
        "dns",
        now=observed + 31,
    )
    assert recovered.state == "closed"


def test_retryable_partial_output_is_ingested_before_fallback():
    events: list[str] = []
    first = SequenceAdapter(
        "test:a",
        [{
            "status": "timeout",
            "stdout": "partial discovery",
            "partial": True,
            "error_class": "TimeoutError",
        }],
        events,
    )
    second = SequenceAdapter(
        "test:b",
        [{"status": "succeeded", "stdout": "complete discovery"}],
        events,
    )
    telemetry, _selector, fallback = provider_stack(first, second)

    def ingest(result, action_id: str) -> Mapping[str, int]:
        events.append(f"ingest:{action_id}")
        return {
            "parsed_facts": 2,
            "useful_facts": 1,
            "duplicate_facts": 1,
            "parser_items": 2,
        }

    run = fallback.run(
        "service_discovery",
        ActionRequest("example.com", automatic()),
        ["test:a", "test:b"],
        ingest=ingest,
    )

    assert events == [
        "execute:test:a",
        "ingest:test:a",
        "execute:test:b",
        "ingest:test:b",
    ]
    assert [item.action_id for item in run.attempts] == ["test:a", "test:b"]
    assert run.attempts[0].retryable is True
    assert run.attempts[0].fallback_taken is True
    assert run.attempts[0].ingestion == IngestionOutcome(
        parsed_facts=2,
        useful_facts=1,
        duplicate_facts=1,
        parser_items=2,
    )
    assert run.attempts[1].report.execution_result.status is ExecutionStatus.SUCCEEDED
    assert run.trace["attempts"][0]["partial_output_ingested"] is True
    assert telemetry.summary("test:a", "service_discovery", "dns").timeout_rate == 1.0


@pytest.mark.parametrize(
    ("status", "error_class"),
    [
        ("partial", ""),
        ("blocked", "ExecutionBlocked"),
        ("cancelled", "CancelledError"),
        ("succeeded", ""),
        ("failed", "ValueError"),
    ],
)
def test_fallback_never_runs_for_terminal_or_untyped_failures(status, error_class):
    events: list[str] = []
    first = SequenceAdapter(
        "test:a",
        [{"status": status, "stdout": "terminal output", "error_class": error_class}],
        events,
    )
    second = SequenceAdapter("test:b", [{"status": "succeeded"}], events)
    _telemetry, _selector, fallback = provider_stack(first, second)

    run = fallback.run(
        "service_discovery",
        ActionRequest("example.com", automatic()),
        ["test:a", "test:b"],
        ingest=lambda _result, _action_id: IngestionOutcome(parsed_facts=1),
    )

    assert [item.action_id for item in run.attempts] == ["test:a"]
    assert run.attempts[0].retryable is False
    assert second.execute_calls == 0


def test_typed_temporary_failure_falls_back_but_uningested_partial_timeout_does_not():
    events: list[str] = []
    temporary = SequenceAdapter(
        "test:a",
        [{"status": "failed", "error_class": "TemporaryError"}],
        events,
    )
    succeeding = SequenceAdapter("test:b", [{"status": "succeeded"}], events)
    _telemetry, _selector, fallback = provider_stack(temporary, succeeding)

    run = fallback.run(
        "service_discovery",
        ActionRequest("example.com", automatic()),
        ["test:a", "test:b"],
    )
    assert [item.action_id for item in run.attempts] == ["test:a", "test:b"]

    events.clear()
    timeout = SequenceAdapter(
        "test:a",
        [{"status": "timeout", "stdout": "must persist", "partial": True}],
        events,
    )
    unused = SequenceAdapter("test:b", [{"status": "succeeded"}], events)
    _telemetry, _selector, fallback = provider_stack(timeout, unused)
    run = fallback.run(
        "service_discovery",
        ActionRequest("example.com", automatic()),
        ["test:a", "test:b"],
    )
    assert [item.action_id for item in run.attempts] == ["test:a"]
    assert run.attempts[0].stop_reason == "partial_output_not_ingested"
    assert run.trace["attempts"][0]["partial_output_ingested"] is False
    assert unused.execute_calls == 0


def test_retry_classifier_accepts_only_explicit_retry_contracts():
    events: list[str] = []
    adapter = SequenceAdapter("test:a", [], events)
    request = ActionRequest("example.com", automatic())
    timeout = adapter.normalize_result({"status": "timeout"}, request, phase="execute")
    unavailable = adapter.normalize_result({"status": "unavailable"}, request, phase="execute")
    temporary = adapter.normalize_result(
        {"status": "failed", "error_class": "TemporaryError"},
        request,
        phase="execute",
    )
    generic = adapter.normalize_result(
        {"status": "failed", "error_class": "RuntimeError"},
        request,
        phase="execute",
    )

    assert RetryClassifier.is_retryable(timeout) is True
    assert RetryClassifier.is_retryable(unavailable) is True
    assert RetryClassifier.is_retryable(temporary) is True
    assert RetryClassifier.is_retryable(generic) is False
    assert RetryClassifier.is_retryable(None) is False


def test_pipeline_runtime_exposes_selection_and_fallback_with_separate_db(tmp_path):
    calls: list[str] = []
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda command: calls.append(command) or "complete",
    )
    request = ActionRequest("example.com", automatic())

    selection = runtime.select_provider("web_mapping", request, ["waf_detect"])
    run = runtime.execute_with_fallback(
        "web_mapping",
        request,
        ["waf_detect"],
        ingest=lambda _result, _action_id: {"useful_facts": 1, "parser_items": 1},
    )

    assert selection.chosen_action_id == "tool:waf_detect"
    assert run.final_report is not None
    assert run.final_report.execution_result.status is ExecutionStatus.SUCCEEDED
    assert calls == ["waf_detect example.com"]
    assert (tmp_path / "facts.provider-telemetry.db").exists()
