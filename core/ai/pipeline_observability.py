"""Task outcome persistence and bounded decision observability seams."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from core.ai.mission_store import (
    RetryErrorClass,
    TaskRecord,
)
from core.ai.outcomes import (
    TaskOutcome,
    classify_task_result,
    command_result_reason,
    has_blocked_stage_fact,
)
from core.ai.pipeline_telemetry import (
    append_command_trace,
    append_goal_trace,
    persist_llm_health,
    print_efficiency_report,
)
from core.ai.pipeline_types import PipelineMixinBase


class PipelineObservabilityMixin(PipelineMixinBase):
    def _classify_task_result(self, task_result: dict[str, Any]) -> str:
        return classify_task_result(task_result)

    def _command_result_reason(self, command_results: list[dict[str, Any]], parsed_facts: int, new_facts: int) -> str:
        return command_result_reason(command_results, parsed_facts, new_facts)

    def _has_blocked_stage_fact(self, command_results: list[dict[str, Any]]) -> bool:
        return has_blocked_stage_fact(command_results)

    def _record_task_outcome(
        self,
        agent: str,
        task: str,
        status: str,
        reason: str,
        new_facts: int,
        parsed_facts: int,
        commands: list[dict[str, Any]],
        duration: float,
        *,
        fact_ids: tuple[int, ...] = (),
    ):
        outcome = TaskOutcome(
            agent=agent,
            task=task,
            status=status,
            reason=reason,
            new_facts=new_facts,
            parsed_facts=parsed_facts,
            commands=tuple(commands),
            duration=duration,
        )
        retry_error = (
            self._task_retry_error_class(commands) if status == "failed" else None
        )
        retry_command_keys = (
            self._task_retry_command_keys(commands, retry_error)
            if retry_error is not None
            else ()
        )
        if self._active_task_attempt_id:
            execution_ids = tuple(
                str(command.get("execution_id"))
                for command in commands
                if command.get("execution_id")
            )
            command_fact_ids = tuple(
                fact_id
                for command in commands
                for fact_id in command.get("fact_ids", ())
            )
            completion = self.mission_store.complete_attempt_and_schedule_retry(
                self._active_task_attempt_id,
                outcome,
                execution_ids=execution_ids,
                fact_ids=tuple(dict.fromkeys((*fact_ids, *command_fact_ids))),
                retry_error_class=retry_error,
                retry_command_keys=retry_command_keys,
            )
            self._active_task_attempt_id = None
            self._active_task_name = ""
            self._active_task_agent = ""
            self._active_retry_command_keys.clear()
            if completion.attempt.outcome is not None:
                outcome = completion.attempt.outcome
            if completion.retry_scheduled and retry_error is not None:
                self._record_typed_task_retry(completion.task, retry_error)
            else:
                self.retry_scheduled_tasks.discard(task)
                if retry_error is not None:
                    self._record_typed_retry_rejection(
                        task,
                        retry_error,
                        completion.retry_rejection or "retry_not_scheduled",
                    )
        return self.task_outcome_store.record(outcome)

    def _task_retry_error_class(
        self,
        commands: Sequence[Mapping[str, Any]],
    ) -> RetryErrorClass | None:
        """Map final execution metadata to the stable mission retry taxonomy."""
        values = [
            " ".join(
                (
                    str(command.get("status") or ""),
                    str(command.get("error_class") or ""),
                    str(command.get("error") or ""),
                )
            ).lower()
            for command in commands
        ]
        if not values:
            return None
        joined = " ".join(values)
        if "rate_limit" in joined or "ratelimit" in joined or "429" in joined:
            return RetryErrorClass.RATE_LIMIT
        if "timeout" in joined or "timed out" in joined:
            return RetryErrorClass.TIMEOUT
        if any(
            marker in joined
            for marker in (
                "connectionerror",
                "connectionreset",
                "connection refused",
                "dns",
                "network",
                "temporaryerror",
                "transient",
            )
        ):
            return RetryErrorClass.TRANSIENT_NETWORK
        if "filenotfound" in joined or "tool_unavailable" in joined:
            return RetryErrorClass.TOOL_UNAVAILABLE
        if "unavailable" in joined:
            return RetryErrorClass.PROVIDER_UNAVAILABLE
        return None

    def _task_retry_command_keys(
        self,
        commands: Sequence[Mapping[str, Any]],
        error_class: RetryErrorClass,
    ) -> tuple[str, ...]:
        """Build the bounded command-key allowlist for one typed retry."""
        keys = []
        for command in commands:
            if command.get("skipped") or not command.get("failed"):
                continue
            if self._task_retry_error_class((command,)) is not error_class:
                continue
            key = self.command_scheduler.command_key(str(command.get("command") or ""))
            if key:
                keys.append(key)
        return tuple(dict.fromkeys(keys))

    def _record_typed_retry_rejection(
        self,
        task: str,
        error_class: RetryErrorClass,
        reason: str,
    ) -> None:
        self.decision_trace.record(
            {
                "event_id": (
                    f"task-retry-rejected:{self.mission_id}:{task}:"
                    f"{error_class.value}:{reason}"
                ),
                "event_type": "task_retry_rejected",
                "mission_id": self.mission_id,
                "scan_id": self._current_scan_id,
                "task": task,
                "candidates": [error_class.value],
                "rejected": [
                    {
                        "candidate": error_class.value,
                        "reason": reason,
                    }
                ],
                "actual_outcome": {
                    "status": "terminal",
                    "reason": reason,
                },
            }
        )

    def _record_typed_task_retry(
        self,
        scheduled: TaskRecord,
        error_class: RetryErrorClass,
    ) -> None:
        self.completed_tasks.discard(scheduled.task)
        self.retry_scheduled_tasks.add(scheduled.task)
        self.decision_trace.record(
            {
                "event_id": (
                    f"task-retry:{self.mission_id}:{scheduled.task_id}:"
                    f"{scheduled.retry_count}"
                ),
                "event_type": "task_retry_scheduled",
                "mission_id": self.mission_id,
                "scan_id": self._current_scan_id,
                "task_id": scheduled.task_id,
                "task": scheduled.task,
                "candidates": [error_class.value],
                "chosen_action": "retry",
                "capability_ref": scheduled.capability,
                "expected_outcome": {
                    "retry_budget": scheduled.retry_budget,
                },
                "actual_outcome": {
                    "status": scheduled.status,
                    "error_class": error_class.value,
                    "retry_count": scheduled.retry_count,
                },
                "retry_count": scheduled.retry_count,
                "state_transition": {"from": "failed", "to": "pending"},
            }
        )

    def _record_goal_trace(self, loop: int, context: dict[str, Any], decision: dict[str, Any]) -> None:
        append_goal_trace(self.goal_trace, loop, context, decision)
        current_state = str(context.get("state") or "")
        llm_status = str(decision.get("llm_status") or "").lower()
        fallback = bool(decision.get("fallback")) or "fallback" in str(
            decision.get("thought") or ""
        ).lower()
        chosen_goal = str(decision.get("goal") or "")
        if not chosen_goal:
            actual_status = "empty"
        elif llm_status == "failed":
            actual_status = "fallback" if fallback else "invalid"
        else:
            actual_status = "selected"
        rejected = decision.get("rejected") or []
        if isinstance(rejected, Mapping):
            rejected = [dict(rejected)]
        elif isinstance(rejected, (str, bytes)) or not isinstance(
            rejected, Sequence
        ):
            rejected = [{"reason": str(rejected)}]
        else:
            rejected = list(rejected)
        if self.plan_rejections:
            rejected = [*rejected, *self.plan_rejections[-16:]]
        self.decision_trace.record({
            "event_id": (
                f"goal:{self.mission_id or self._current_scan_id}:"
                f"{loop}:{len(self.goal_trace)}"
            ),
            "event_type": "goal_selection",
            "mission_id": self.mission_id or "",
            "scan_id": self._current_scan_id,
            "goal": chosen_goal,
            "candidates": decision.get("candidates") or [],
            "rejected": rejected,
            "chosen_action": chosen_goal,
            "capability_ref": str(context.get("next_required_capability") or ""),
            "policy_refs": decision.get("policy_refs") or [],
            "supporting_fact_ids": (
                decision.get("supporting_fact_ids")
                or context.get("supporting_fact_ids")
                or []
            ),
            "expected_outcome": {
                "next_required_capability": context.get("next_required_capability"),
                "open_questions": len(context.get("open_questions") or []),
            },
            "actual_outcome": {
                "status": actual_status,
                "llm_status": llm_status,
            },
            "cost": {
                "llm_calls": int(llm_status not in {"", "skipped"}),
                "estimated_units": float(llm_status not in {"", "skipped"}),
            },
            "state_transition": {
                "from": self._last_decision_state,
                "to": current_state,
            },
            "fallback_count": int(fallback),
        })
        self._last_decision_state = current_state

    def _record_llm_health(
        self,
        scan_id: str,
        target: str,
        role: str,
        result: dict[str, Any],
        loop: int,
    ) -> None:
        persist_llm_health(
            self._store_fact,
            scan_id,
            target,
            role,
            result,
            loop,
        )

    def _update_llm_failure_counter(self, result: dict[str, Any]) -> None:
        status = str((result or {}).get("llm_status", "")).strip().lower()
        if status == "failed":
            self.consecutive_llm_failures += 1
        elif status == "ok":
            self.consecutive_llm_failures = 0

    def _record_command_trace(
        self,
        decision: dict[str, Any],
        result: dict[str, Any] | None = None,
    ) -> None:
        append_command_trace(self.command_trace, decision, result)
        result = result or {}
        tool = self._command_tool_name(str(decision.get("command") or ""))
        skipped = decision.get("action") == "skip"
        execution_id = str(result.get("execution_id") or "")
        self.decision_trace.record({
            "event_id": (
                f"command:{execution_id}"
                if execution_id
                else (
                    f"command:{self.mission_id or self._current_scan_id}:"
                    f"{decision.get('key')}:{len(self.command_trace)}"
                )
            ),
            "event_type": "command_decision",
            "mission_id": self.mission_id or "",
            "scan_id": self._current_scan_id,
            "task_id": self._active_task_attempt_id or "",
            "task": self._active_task_name,
            "goal": str((self.goal_trace[-1] if self.goal_trace else {}).get("goal") or ""),
            "candidates": [tool] if tool else [],
            "rejected": (
                [{"candidate": tool, "reason": decision.get("reason") or "policy_skip"}]
                if skipped
                else []
            ),
            "chosen_action": "" if skipped else tool,
            "capability_ref": str(decision.get("prerequisite") or tool),
            "policy_refs": [result.get("policy_decision_ref")]
            if result.get("policy_decision_ref")
            else [],
            "supporting_fact_ids": result.get("fact_ids") or [],
            "expected_outcome": {
                "scheduler_action": decision.get("action"),
                "prerequisite": decision.get("prerequisite") or "",
            },
            "actual_outcome": {
                "status": result.get("status") or ("blocked" if skipped else "unknown"),
                "failed": bool(result.get("failed", False)),
                "parsed_facts": result.get("parsed_facts", 0),
                "new_facts": result.get("new_facts", 0),
                "duplicate_output": bool(result.get("duplicate_output", False)),
                "check_status": result.get("check_status") or "",
            },
            "duration": result.get("duration", 0.0),
            "cost": {
                "tool_calls": int(not skipped),
                "output_bytes": result.get("output_bytes", 0),
                "estimated_units": float(not skipped),
            },
            "state_transition": {
                "from": self._last_decision_state,
                "to": self._last_decision_state,
            },
        })

    def _print_stage_gates(self, context: dict[str, Any]):
        gates = context.get("stage_gates") or {}
        if not gates:
            return
        ordered = [
            "recon", "credentials", "root", "post_access_inventory",
            "persistence", "internal_recon", "exfiltration", "cleanup",
        ]
        gate_text = ", ".join(f"{name}={'yes' if gates.get(name) else 'no'}" for name in ordered)
        print(f"[*] Stage gates: {gate_text}; next={context.get('next_required_capability', 'conclude')}")

    def _print_efficiency_report(self, scan_id: str, target: str, elapsed: float):
        print_efficiency_report(
            scan_id,
            target,
            elapsed,
            get_facts=self.fact_store.get_facts,
            task_outcomes=self.task_outcomes,
            total_new_facts=self.total_new_facts,
            goal_trace=self.goal_trace,
            command_trace=self.command_trace,
        )


__all__ = ["PipelineObservabilityMixin"]
