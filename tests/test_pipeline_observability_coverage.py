"""Remaining retry and decision-branch coverage for pipeline observability."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.ai.mission_store import RetryErrorClass
from core.ai.pipeline_observability import PipelineObservabilityMixin

pytestmark = pytest.mark.contract


class _Recorder:
    def __init__(self):
        self.items = []

    def record(self, item):
        self.items.append(item)
        return item


class _Harness(PipelineObservabilityMixin):
    def __init__(self):
        self._active_task_attempt_id = None
        self._active_task_id = None
        self._active_task_name = ""
        self._active_task_agent = ""
        self._active_retry_command_keys = set()
        self.retry_scheduled_tasks = set()
        self.completed_tasks = set()
        self.task_outcome_store = _Recorder()
        self.decision_trace = _Recorder()
        self.command_scheduler = SimpleNamespace(command_key=lambda command: f"key:{command}" if command else "")
        self.goal_trace = []
        self.command_trace = []
        self.plan_rejections = []
        self.mission_id = "mission"
        self._current_scan_id = "scan"
        self._last_decision_state = "initial"
        self.consecutive_llm_failures = 0


@pytest.mark.parametrize(
    ("commands", "expected"),
    [
        ([], None),
        ([{"error": "HTTP 429"}], RetryErrorClass.RATE_LIMIT),
        ([{"error": "timed out"}], RetryErrorClass.TIMEOUT),
        ([{"error": "DNS temporary error"}], RetryErrorClass.TRANSIENT_NETWORK),
        ([{"error": "FileNotFound"}], RetryErrorClass.TOOL_UNAVAILABLE),
        ([{"error": "provider unavailable"}], RetryErrorClass.PROVIDER_UNAVAILABLE),
        ([{"error": "permanent failure"}], None),
    ],
)
def test_retry_error_taxonomy_covers_every_terminal_class(commands, expected):
    assert _Harness()._task_retry_error_class(commands) is expected


def test_retry_command_keys_skip_ineligible_entries_and_dedupe_matches():
    pipeline = _Harness()
    commands = [
        {"command": "skipped", "failed": True, "skipped": True, "error": "timeout"},
        {"command": "not-failed", "failed": False, "error": "timeout"},
        {"command": "wrong-class", "failed": True, "error": "permanent"},
        {"command": "", "failed": True, "error": "timeout"},
        {"command": "retry", "failed": True, "error": "timeout"},
        {"command": "retry", "failed": True, "error": "timeout"},
    ]

    assert pipeline._task_retry_command_keys(commands, RetryErrorClass.TIMEOUT) == ("key:retry",)


def test_failed_attempt_without_retry_records_terminal_rejection():
    pipeline = _Harness()
    pipeline._active_task_attempt_id = "attempt"
    pipeline._active_task_id = "task-id"
    pipeline._active_task_name = "service_discovery"
    pipeline._active_task_agent = "DiscoveryAgent"
    pipeline._active_retry_command_keys.add("old")
    pipeline.retry_scheduled_tasks.add("service_discovery")
    pipeline.mission_store = SimpleNamespace(
        complete_attempt_and_schedule_retry=lambda *_args, **_kwargs: SimpleNamespace(
            attempt=SimpleNamespace(outcome=None),
            retry_scheduled=False,
            retry_rejection="",
        )
    )

    recorded = pipeline._record_task_outcome(
        "DiscoveryAgent",
        "service_discovery",
        "failed",
        "command_failed",
        0,
        0,
        [
            {
                "command": "probe",
                "failed": True,
                "error": "timeout",
                "execution_id": "exec-1",
                "fact_ids": (2, 3),
            }
        ],
        1.0,
        fact_ids=(1, 2),
    )

    assert recorded.status == "failed"
    assert pipeline._active_task_attempt_id is None
    assert pipeline._active_retry_command_keys == set()
    assert pipeline.retry_scheduled_tasks == set()
    assert pipeline.decision_trace.items[-1]["event_type"] == "task_retry_rejected"
    assert pipeline.decision_trace.items[-1]["actual_outcome"]["reason"] == ("retry_not_scheduled")


def test_goal_trace_normalizes_empty_mapping_scalar_and_sequence_rejections():
    pipeline = _Harness()
    pipeline.plan_rejections = [{"reason": "provider_missing"}]

    pipeline._record_goal_trace(
        1,
        {"state": "recon", "supporting_fact_ids": [4]},
        {"goal": "", "rejected": {"reason": "empty_goal"}},
    )
    pipeline.plan_rejections = []
    pipeline._record_goal_trace(
        2,
        {"state": "analysis"},
        {"goal": "analyze", "llm_status": "failed", "rejected": 7},
    )
    pipeline._record_goal_trace(
        3,
        {"state": "fallback"},
        {
            "goal": "discover",
            "llm_status": "failed",
            "thought": "fallback policy",
            "rejected": "invalid",
        },
    )
    pipeline._record_goal_trace(
        4,
        {"state": "selected"},
        {"goal": "verify", "llm_status": "ok", "rejected": ()},
    )

    events = pipeline.decision_trace.items
    assert [event["actual_outcome"]["status"] for event in events] == [
        "empty",
        "invalid",
        "fallback",
        "selected",
    ]
    assert events[0]["rejected"] == [
        {"reason": "empty_goal"},
        {"reason": "provider_missing"},
    ]
    assert events[1]["rejected"] == [{"reason": "7"}]


def test_llm_failure_counter_handles_failure_success_and_neutral_status():
    pipeline = _Harness()

    pipeline._update_llm_failure_counter({"llm_status": "FAILED"})
    assert pipeline.consecutive_llm_failures == 1
    pipeline._update_llm_failure_counter({"llm_status": "ok"})
    assert pipeline.consecutive_llm_failures == 0
    pipeline._update_llm_failure_counter({"llm_status": "skipped"})
    assert pipeline.consecutive_llm_failures == 0


def test_blocked_stage_fact_wrapper_handles_empty_results():
    assert _Harness()._has_blocked_stage_fact([]) is False
