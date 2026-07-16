"""Durable mission lifecycle seam for :class:`AIPipeline`.

The mixin owns no database connection or mutable state; it coordinates the
canonical MissionStore already composed by the pipeline and preserves the
legacy in-memory compatibility projections.
"""

from __future__ import annotations

import json
from typing import Any

from core.ai.mission_store import (
    MissionTaskDefinition,
    RetryErrorClass,
    TaskDependenciesIncomplete,
    TaskRetryPolicy,
)
from core.ai.pipeline_types import PipelineMixinBase


class PipelineMissionMixin(PipelineMixinBase):
    def _start_mission(self, scan_id: str, target: str):
        """Open or recover one durable mission and rebuild compatibility views."""
        previous = self.mission_store.get_mission_by_scan_id(scan_id)
        self._current_scan_id = str(scan_id)
        self._current_target = str(target)
        mission = self.mission_store.open_mission(scan_id, target, recover=True)
        self.mission_id = mission.mission_id
        self._mission_was_completed = mission.status == "completed"
        self._mission_was_resumed = bool(
            previous is not None and previous.status != "completed"
        )
        if self._mission_was_resumed:
            self.decision_trace.record({
                "event_id": f"resume-start:{mission.mission_id}:{mission.run_count}",
                "event_type": "mission_resume_started",
                "mission_id": mission.mission_id,
                "scan_id": scan_id,
                "expected_outcome": {"status": "succeeded"},
                "actual_outcome": {
                    "status": "started",
                    "previous_status": previous.status if previous else "unknown",
                    "run_count": mission.run_count,
                },
                "state_from": previous.status if previous else "unknown",
                "state_to": mission.status,
            })
        snapshot = self.mission_store.snapshot(mission.mission_id)

        for task_record in snapshot.tasks:
            if task_record.attempt_count:
                self.task_history.append(f"{task_record.agent}:{task_record.task}")
            if (
                task_record.retry_count > 0
                and task_record.status in {"pending", "interrupted"}
            ):
                self.retry_scheduled_tasks.add(task_record.task)
            if task_record.status == "blocked":
                self.blocked_tasks.add(task_record.task)
            elif task_record.status in {
                "completed",
                "failed",
                "no_new_facts",
                "skipped",
            }:
                self.completed_tasks.add(task_record.task)

        for attempt in snapshot.attempts:
            if attempt.outcome is None:
                continue
            self.task_outcome_store.record(attempt.outcome)
        facts = self.fact_store.get_facts(scan_id, target)
        command_results = self.fact_store.get_command_results(scan_id, target)
        self.total_new_facts = len(facts)
        durable_execution_ids = {
            execution_id
            for attempt in snapshot.attempts
            for execution_id in attempt.execution_ids
            if execution_id
        }
        durable_execution_ids.update(
            str(result.get("execution_id"))
            for result in command_results
            if result.get("execution_id")
        )
        durable_tool_count = len(durable_execution_ids) + sum(
            1 for result in command_results if not result.get("execution_id")
        )
        self.tools_run_count = max(self.tools_run_count, durable_tool_count)
        self.executed_command_keys.update(
            str(result.get("command_key"))
            for result in command_results
            if result.get("command_key")
        )
        for fact in facts:
            if fact.get("type") != "check_result":
                continue
            try:
                check = json.loads(str(fact.get("value") or ""))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(check, dict) and check.get("command_key"):
                self.executed_command_keys.add(str(check["command_key"]))
        return mission

    def _register_mission_plan(
        self,
        plan: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Atomically persist planner tasks and dependency edges before execution."""
        if not self.mission_id:
            return plan
        snapshot = self.mission_store.snapshot(self.mission_id)
        records_by_key = {
            (record.agent, record.task): record for record in snapshot.tasks
        }
        records_by_name = {record.task: record for record in snapshot.tasks}
        records_by_id = {record.task_id: record for record in snapshot.tasks}

        selected: list[tuple[str, str, dict[str, Any]]] = []
        selected_by_name: dict[str, tuple[str, str]] = {}
        for step in plan:
            agent = str(step.get("agent") or "")
            task = str(step.get("task") or "")
            if not agent or not task or task in selected_by_name:
                continue
            existing = records_by_name.get(task)
            effective = (
                (existing.agent, existing.task) if existing else (agent, task)
            )
            selected_by_name[task] = effective
            selected.append((effective[0], effective[1], step))

        available_by_name = {
            **{name: (record.agent, record.task) for name, record in records_by_name.items()},
            **selected_by_name,
        }
        available_by_key = {
            **{key: (record.agent, record.task) for key, record in records_by_key.items()},
            **{value: value for value in selected_by_name.values()},
        }
        dependencies_by_task: dict[str, list[tuple[str, str]]] = {}
        invalid_reasons: dict[str, list[str]] = {}
        for _, task, step in selected:
            raw_dependencies = step.get("depends_on") or ()
            if isinstance(raw_dependencies, str):
                raw_dependencies = (raw_dependencies,)
            existing = records_by_name.get(task)
            if not raw_dependencies and existing is not None:
                dependencies_by_task[task] = [
                    (records_by_id[dependency_id].agent, records_by_id[dependency_id].task)
                    for dependency_id in existing.depends_on
                    if dependency_id in records_by_id
                ]
                continue
            resolved_dependencies: list[tuple[str, str]] = []
            for dependency in raw_dependencies:
                dependency_text = str(dependency)
                dependency_identity = available_by_name.get(dependency_text)
                if dependency_identity is None and ":" in dependency_text:
                    dep_agent, dep_task = dependency_text.split(":", 1)
                    dependency_identity = available_by_key.get((dep_agent, dep_task))
                if dependency_identity is None:
                    invalid_reasons.setdefault(task, []).append(dependency_text)
                else:
                    resolved_dependencies.append(dependency_identity)
            dependencies_by_task[task] = resolved_dependencies

        changed = True
        while changed:
            changed = False
            for _, task, _ in selected:
                if task in invalid_reasons:
                    continue
                invalid_dependencies = [
                    dependency_task
                    for _, dependency_task in dependencies_by_task[task]
                    if dependency_task in invalid_reasons
                ]
                if invalid_dependencies:
                    invalid_reasons[task] = invalid_dependencies
                    changed = True

        definitions: list[MissionTaskDefinition] = []
        blocked_reasons: dict[tuple[str, str], str] = {}
        default_retry_policy = self._mission_task_retry_policy()
        for agent, task, step in selected:
            existing = records_by_name.get(task)
            scope = (
                existing.scope
                if existing is not None
                else self._mission_task_scope(step)
            )
            capability = (
                existing.capability
                if existing is not None
                else str(step.get("capability") or task)
            )
            retry_policy = (
                TaskRetryPolicy(
                    retry_budget=existing.retry_budget,
                    retryable_error_classes=existing.retryable_error_classes,
                )
                if existing is not None
                else default_retry_policy
            )
            if task in invalid_reasons:
                reason = "unknown_dependencies:" + ",".join(
                    sorted(dict.fromkeys(invalid_reasons[task]))
                )
                definitions.append(
                    MissionTaskDefinition(
                        agent=agent,
                        task=task,
                        scope=scope,
                        capability=capability,
                        retry_policy=TaskRetryPolicy(),
                    )
                )
                blocked_reasons[(agent, task)] = reason
            else:
                definitions.append(
                    MissionTaskDefinition(
                        agent=agent,
                        task=task,
                        depends_on=tuple(dependencies_by_task[task]),
                        scope=scope,
                        capability=capability,
                        retry_policy=retry_policy,
                    )
                )

        records = self.mission_store.register_plan(
            self.mission_id,
            definitions,
            blocked_reasons=blocked_reasons,
        )
        if blocked_reasons:
            persisted = self.mission_store.snapshot(self.mission_id)
            attempts_by_task_id = {
                attempt.task_id: attempt
                for attempt in persisted.attempts
                if attempt.status == "blocked"
            }
            for record in records:
                if record.status != "blocked":
                    continue
                self.blocked_tasks.add(record.task)
                attempt = attempts_by_task_id.get(record.task_id)
                if attempt is not None and attempt.outcome is not None:
                    self.task_outcome_store.record(attempt.outcome)
        return self._ordered_mission_plan([record.task for record in records])

    def _mission_task_scope(self, step: dict[str, Any]) -> str:
        raw_scope = step.get("scope")
        if raw_scope in (None, ""):
            return f"target:{self._current_target}"
        if isinstance(raw_scope, (dict, list, tuple)):
            return json.dumps(
                raw_scope,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        return str(raw_scope)

    def _mission_task_retry_policy(self) -> TaskRetryPolicy:
        from config import CFG

        mission_config = (
            ((CFG.get("strategy") or {}).get("mission") or {})
            if isinstance(CFG, dict)
            else {}
        )
        raw_budget = mission_config.get("task_retry_budget", 0)
        try:
            budget = int(raw_budget)
        except (TypeError, ValueError) as exc:
            raise ValueError("strategy.mission.task_retry_budget must be an integer") from exc
        raw_classes = mission_config.get("retryable_error_classes") or []
        if isinstance(raw_classes, (str, bytes)):
            raw_classes = [raw_classes]
        return TaskRetryPolicy(
            retry_budget=budget,
            retryable_error_classes=tuple(
                RetryErrorClass(str(item)) for item in raw_classes
            ),
        )

    def _max_state_replans(self) -> int:
        from config import CFG

        raw = (
            ((CFG.get("strategy") or {}).get("mission") or {}).get(
                "max_state_replans",
                0,
            )
            if isinstance(CFG, dict)
            else 0
        )
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("strategy.mission.max_state_replans must be an integer") from exc
        return max(0, min(value, 100))

    @staticmethod
    def _state_replan_signature(context: dict[str, Any]) -> str:
        stage_gates = context.get("stage_gates") or {}
        assessment_counts = context.get("fact_assessment_counts") or {}
        payload = {
            "state": str(context.get("state") or "unknown"),
            "next_required_capability": str(
                context.get("next_required_capability") or ""
            ),
            "stage_gates": {
                str(key): bool(value)
                for key, value in sorted(stage_gates.items())
            },
            "fact_assessment_counts": {
                str(key): int(value)
                for key, value in sorted(assessment_counts.items())
                if isinstance(value, int) and not isinstance(value, bool)
            },
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def _evaluate_state_change_replan(
        self,
        previous_context: dict[str, Any],
        scan_id: str,
        target: str,
    ) -> bool:
        """Record a bounded replan request after a material state transition."""
        current_context = self.context_builder.build_context(scan_id, target)
        previous_signature = self._state_replan_signature(previous_context)
        current_signature = self._state_replan_signature(current_context)
        if previous_signature == current_signature:
            return False
        transition_key = f"{previous_signature}->{current_signature}"
        if transition_key in self._state_replan_signatures:
            return False

        maximum = self._max_state_replans()
        if self._state_replan_count >= maximum:
            self.decision_trace.record(
                {
                    "event_id": (
                        f"state-replan-rejected:{self.mission_id or scan_id}:"
                        f"{self._state_replan_count}:{current_signature}"
                    ),
                    "event_type": "state_replan_rejected",
                    "mission_id": self.mission_id or "",
                    "scan_id": scan_id,
                    "chosen_action": "continue_bounded_plan",
                    "rejected": [
                        {
                            "candidate": "replan",
                            "reason": "state_replan_budget_exhausted",
                        }
                    ],
                    "expected_outcome": {"max_state_replans": maximum},
                    "actual_outcome": {
                        "state_replans": self._state_replan_count,
                    },
                    "state_transition": {
                        "from": str(previous_context.get("state") or "unknown"),
                        "to": str(current_context.get("state") or "unknown"),
                    },
                }
            )
            self._state_replan_signatures.add(transition_key)
            return False

        self._state_replan_count += 1
        self._state_replan_signatures.add(transition_key)
        self.decision_trace.record(
            {
                "event_id": (
                    f"state-replan:{self.mission_id or scan_id}:"
                    f"{self._state_replan_count}:{current_signature}"
                ),
                "event_type": "state_replan_requested",
                "mission_id": self.mission_id or "",
                "scan_id": scan_id,
                "candidates": ["continue_plan", "replan"],
                "chosen_action": "replan",
                "capability_ref": str(
                    current_context.get("next_required_capability") or ""
                ),
                "supporting_fact_ids": (
                    current_context.get("supporting_fact_ids") or []
                ),
                "expected_outcome": {
                    "max_state_replans": maximum,
                    "remaining": maximum - self._state_replan_count,
                },
                "actual_outcome": {
                    "status": "requested",
                    "state_replans": self._state_replan_count,
                },
                "state_transition": {
                    "from": str(previous_context.get("state") or "unknown"),
                    "to": str(current_context.get("state") or "unknown"),
                },
            }
        )
        return True

    def _ordered_mission_plan(
        self,
        task_names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        if not self.mission_id:
            return []
        snapshot = self.mission_store.snapshot(self.mission_id)
        records = list(snapshot.tasks)
        by_id = {record.task_id: record for record in records}
        if task_names is None:
            selected = {
                record.task_id
                for record in records
                if record.status in {"pending", "interrupted"}
            }
        else:
            requested = set(task_names)
            selected = {
                record.task_id for record in records if record.task in requested
            }
        # A task with live prerequisite work is deferred to a later durable
        # drain pass.  Terminally unsatisfied prerequisites remain selected so
        # ``begin_attempt`` can persist the dependent as blocked.
        deferred_dependency_statuses = {"pending", "running", "interrupted"}
        selected = {
            task_id
            for task_id in selected
            if not any(
                by_id[dependency_id].status in deferred_dependency_statuses
                for dependency_id in by_id[task_id].depends_on
                if dependency_id in by_id
            )
        }
        order = {record.task_id: index for index, record in enumerate(records)}
        indegree = {
            task_id: sum(
                1 for dependency_id in by_id[task_id].depends_on
                if dependency_id in selected
            )
            for task_id in selected
        }
        dependents: dict[str, list[str]] = {task_id: [] for task_id in selected}
        for task_id in selected:
            for dependency_id in by_id[task_id].depends_on:
                if dependency_id in selected:
                    dependents[dependency_id].append(task_id)
        ready = sorted(
            (task_id for task_id, count in indegree.items() if count == 0),
            key=order.__getitem__,
        )
        ordered: list[str] = []
        while ready:
            task_id = ready.pop(0)
            ordered.append(task_id)
            for dependent_id in sorted(dependents[task_id], key=order.__getitem__):
                indegree[dependent_id] -= 1
                if indegree[dependent_id] == 0:
                    ready.append(dependent_id)
                    ready.sort(key=order.__getitem__)
        if len(ordered) != len(selected):
            raise RuntimeError("persisted mission task dependency cycle")
        # Keep the public planner-step shape stable.  ``_register_mission_plan``
        # rehydrates scope, capability, dependencies, and retry policy from the
        # matched durable TaskRecord instead of recomputing them from config.
        return [
            {"agent": by_id[task_id].agent, "task": by_id[task_id].task}
            for task_id in ordered
        ]

    def _resumable_mission_plan(self) -> list[dict[str, Any]]:
        """Return unfinished durable work before consulting Director or Planner."""
        return self._ordered_mission_plan()

    def _block_registered_task(self, agent: str, task: str, reason: str):
        if not self.mission_id:
            return None
        attempt = self.mission_store.block_task(self.mission_id, agent, task, reason)
        self.blocked_tasks.add(task)
        if attempt.outcome is not None:
            self.task_outcome_store.record(attempt.outcome)
        return attempt

    def _persist_plan_rejection(self, agent: str, task: str, reason: str) -> None:
        if not self.mission_id or not agent or not task:
            return
        snapshot = self.mission_store.snapshot(self.mission_id)
        record = next((item for item in snapshot.tasks if item.task == task), None)
        if record is not None and record.status not in {"pending", "interrupted"}:
            if record.status == "blocked":
                self.blocked_tasks.add(record.task)
            return
        effective_agent = record.agent if record is not None else agent
        effective_task = record.task if record is not None else task
        records = self.mission_store.register_plan(
            self.mission_id,
            [
                MissionTaskDefinition(
                    agent=effective_agent,
                    task=effective_task,
                    scope=f"target:{self._current_target}",
                    capability=effective_task,
                )
            ],
            blocked_reasons={(effective_agent, effective_task): reason},
        )
        blocked = records[0]
        self.blocked_tasks.add(blocked.task)
        persisted = self.mission_store.snapshot(self.mission_id)
        attempt = next(
            (
                item for item in reversed(persisted.attempts)
                if item.task_id == blocked.task_id and item.status == "blocked"
            ),
            None,
        )
        if attempt is not None and attempt.outcome is not None:
            self.task_outcome_store.record(attempt.outcome)

    def _terminalize_compatibility_exhausted_tasks(
        self,
        plan: list[dict[str, Any]],
    ) -> None:
        """Prevent legacy in-memory exhaustion from stranding durable pending work."""
        if not self.mission_id:
            return
        snapshot = self.mission_store.snapshot(self.mission_id)
        by_name = {record.task: record for record in snapshot.tasks}
        for step in plan:
            task = str(step.get("task") or "")
            if not task or not self._task_exhausted(task):
                continue
            record = by_name.get(task)
            if record is None or record.status not in {"pending", "interrupted"}:
                continue
            if task in self.blocked_tasks:
                self._block_registered_task(
                    record.agent,
                    record.task,
                    "compatibility_state_blocked",
                )
                continue
            attempt = self.mission_store.skip_task(
                self.mission_id,
                record.agent,
                record.task,
                "compatibility_state_exhausted",
            )
            if attempt.outcome is not None:
                self.task_outcome_store.record(attempt.outcome)

    def _begin_task_attempt(self, agent: str, task: str):
        if not self.mission_id:
            return None
        if self._active_task_attempt_id:
            raise RuntimeError("a mission task attempt is already active")
        self._active_retry_command_keys.clear()
        try:
            attempt = self.mission_store.begin_attempt(self.mission_id, agent, task)
        except TaskDependenciesIncomplete as exc:
            if all(
                status in {"pending", "running", "interrupted"}
                for _, status in exc.incomplete
            ):
                return None
            details = ",".join(
                f"{task_id}:{status}" for task_id, status in exc.incomplete
            )
            return self._block_registered_task(
                agent,
                task,
                f"dependency_unsatisfied:{details}",
            )
        self._active_task_attempt_id = attempt.attempt_id
        self._active_task_name = str(task)
        self._active_task_agent = str(agent)
        self._active_retry_command_keys = set(
            self.mission_store.pending_retry_command_keys(
                self.mission_id,
                agent,
                task,
            )
        )
        return attempt

    def _interrupt_mission(self, reason: str) -> None:
        if self.mission_id and not self._mission_was_completed:
            interrupted = self.mission_store.interrupt_mission(self.mission_id, reason)
            if self._mission_was_resumed:
                self.decision_trace.record({
                    "event_id": (
                        f"resume-outcome:{self.mission_id}:{interrupted.run_count}"
                    ),
                    "event_type": "mission_resume_outcome",
                    "mission_id": self.mission_id,
                    "scan_id": self._current_scan_id,
                    "expected_outcome": {"status": "succeeded"},
                    "actual_outcome": {
                        "status": "interrupted",
                        "reason": reason,
                    },
                    "state_transition": {"from": "running", "to": "interrupted"},
                })
        self._active_task_attempt_id = None
        self._active_task_name = ""
        self._active_task_agent = ""
        self._active_retry_command_keys.clear()

    def _complete_mission(self, reason: str) -> None:
        if self.mission_id and not self._mission_was_completed:
            completed = self.mission_store.complete_mission(self.mission_id, reason)
            if self._mission_was_resumed:
                self.decision_trace.record({
                    "event_id": f"resume-outcome:{self.mission_id}:{completed.run_count}",
                    "event_type": "mission_resume_outcome",
                    "mission_id": self.mission_id,
                    "scan_id": self._current_scan_id,
                    "expected_outcome": {"status": "succeeded"},
                    "actual_outcome": {
                        "status": "succeeded",
                        "reason": reason,
                    },
                    "state_transition": {"from": "running", "to": "completed"},
                })
            self._mission_was_completed = True
        self._active_task_attempt_id = None
        self._active_task_name = ""
        self._active_task_agent = ""


__all__ = ["PipelineMissionMixin"]
