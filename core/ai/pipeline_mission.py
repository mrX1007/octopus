"""Durable mission lifecycle seam for :class:`AIPipeline`.

The mixin owns no database connection or mutable state; it coordinates the
canonical MissionStore already composed by the pipeline and preserves the
legacy in-memory compatibility projections.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from core.ai.mission_store import (
    TASK_DEFINITION_SCHEMA_VERSION,
    MissionTaskDefinition,
    RetryErrorClass,
    TaskBackoff,
    TaskDependenciesIncomplete,
    TaskDependencyRef,
    TaskRetryPolicy,
    TaskScope,
)
from core.ai.pipeline_types import PipelineMixinBase
from core.knowledge.identity import canonical_asset


class PipelineMissionMixin(PipelineMixinBase):
    def _start_mission(self, scan_id: str, target: str):
        """Open or recover one durable mission and rebuild compatibility views."""
        previous = self.mission_store.get_mission_by_scan_id(scan_id)
        self._current_scan_id = str(scan_id)
        self._current_target = str(target)
        mission = self.mission_store.open_mission(scan_id, target, recover=True)
        self.mission_id = mission.mission_id
        self._state_replan_count = mission.state_replan_count
        self._state_replan_signatures = set(mission.state_replan_signatures)
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
            if (
                isinstance(check, dict)
                and check.get("command_key")
                and str(check.get("status") or "").casefold() != "running"
            ):
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
        records_by_id = {record.task_id: record for record in snapshot.tasks}

        explicit_task_ids = [str(step.get("task_id") or "") for step in plan]
        if plan and all(explicit_task_ids):
            for step, task_id in zip(plan, explicit_task_ids):
                record = records_by_id.get(task_id)
                if record is None or (
                    record.agent != str(step.get("agent") or "")
                    or record.task != str(step.get("task") or "")
                ):
                    raise ValueError("ordered mission plan contains an unknown task_id")
            return self._ordered_mission_plan(task_ids=explicit_task_ids)

        selected: list[
            tuple[
                tuple[Any, ...],
                str,
                str,
                dict[str, Any],
                Any,
                TaskScope,
                str,
            ]
        ] = []
        selected_identities: set[tuple[Any, ...]] = set()
        for step in plan:
            agent = str(step.get("agent") or "")
            task = str(step.get("task") or "")
            if not agent or not task:
                continue
            requested_scope = self._mission_task_scope(step)
            requested_version = str(
                step.get("task_definition_version")
                or TASK_DEFINITION_SCHEMA_VERSION
            )
            requested_task_id = str(step.get("task_id") or "")
            identity: tuple[Any, ...]
            if requested_task_id:
                existing = records_by_id.get(requested_task_id)
                if existing is None or existing.task != task:
                    raise ValueError("mission plan contains an unknown task_id")
                identity = ("task_id", existing.task_id)
            else:
                candidates = [
                    record
                    for record in snapshot.tasks
                    if record.agent == agent
                    and record.task == task
                    and self._mission_task_scope_identity(record.task_scope)
                    == self._mission_task_scope_identity(requested_scope)
                    and record.task_definition_version == requested_version
                ]
                existing = candidates[0] if candidates else None
                identity = (
                    "definition",
                    agent,
                    task,
                    self._mission_task_scope_identity(requested_scope),
                    requested_version,
                )
            if identity in selected_identities:
                continue
            effective = (
                (existing.agent, existing.task) if existing else (agent, task)
            )
            selected_identities.add(identity)
            selected.append(
                (
                    identity,
                    effective[0],
                    effective[1],
                    step,
                    existing,
                    existing.task_scope if existing is not None else requested_scope,
                    (
                        existing.task_definition_version
                        if existing is not None
                        else requested_version
                    ),
                )
            )

        available_entries: dict[tuple[Any, ...], TaskDependencyRef] = {
            ("task_id", record.task_id): TaskDependencyRef(
                agent=record.agent,
                task=record.task,
                scope=record.task_scope,
                task_definition_version=record.task_definition_version,
                task_id=record.task_id,
            )
            for record in snapshot.tasks
        }
        for identity, agent, task, _, existing, scope, version in selected:
            token = (
                ("task_id", existing.task_id)
                if existing is not None
                else identity
            )
            available_entries[token] = TaskDependencyRef(
                agent=agent,
                task=task,
                scope=scope,
                task_definition_version=version,
                task_id=existing.task_id if existing is not None else "",
            )
        identities_by_name: dict[str, list[TaskDependencyRef]] = {}
        identities_by_key: dict[tuple[str, str], list[TaskDependencyRef]] = {}
        for reference in available_entries.values():
            identities_by_name.setdefault(reference.task, []).append(reference)
            identities_by_key.setdefault(
                (reference.agent, reference.task),
                [],
            ).append(reference)

        dependencies_by_identity: dict[
            tuple[Any, ...], list[TaskDependencyRef]
        ] = {}
        invalid_reasons: dict[tuple[Any, ...], list[str]] = {}
        for identity, _, _task, step, existing, scope, version in selected:
            raw_dependencies = step.get("depends_on") or ()
            if isinstance(raw_dependencies, str):
                raw_dependencies = (raw_dependencies,)
            if not raw_dependencies and existing is not None:
                dependencies_by_identity[identity] = [
                    TaskDependencyRef(
                        agent=records_by_id[dependency_id].agent,
                        task=records_by_id[dependency_id].task,
                        scope=records_by_id[dependency_id].task_scope,
                        task_definition_version=(
                            records_by_id[dependency_id].task_definition_version
                        ),
                        task_id=dependency_id,
                    )
                    for dependency_id in existing.depends_on
                    if dependency_id in records_by_id
                ]
                continue
            resolved_dependencies: list[TaskDependencyRef] = []

            def select_reference(
                candidates: list[TaskDependencyRef],
                *,
                current_scope: TaskScope = scope,
                current_version: str = version,
            ) -> TaskDependencyRef | None:
                if len(candidates) == 1:
                    return candidates[0]
                same_scope = [
                    candidate
                    for candidate in candidates
                    if isinstance(candidate.scope, TaskScope)
                    and self._mission_task_scope_identity(candidate.scope)
                    == self._mission_task_scope_identity(current_scope)
                ]
                same_definition = [
                    candidate
                    for candidate in same_scope
                    if (
                        candidate.task_definition_version
                        or TASK_DEFINITION_SCHEMA_VERSION
                    )
                    == current_version
                ]
                if len(same_definition) == 1:
                    return same_definition[0]
                if len(same_scope) == 1:
                    return same_scope[0]
                return None

            for dependency in raw_dependencies:
                dependency_text = str(dependency)
                dependency_identity: TaskDependencyRef | None
                if isinstance(dependency, TaskDependencyRef):
                    dependency_identity = dependency
                elif isinstance(dependency, dict):
                    raw_dependency_scope = dependency.get(
                        "task_scope",
                        dependency.get("scope"),
                    )
                    dependency_identity = TaskDependencyRef(
                        agent=str(dependency.get("agent") or ""),
                        task=str(dependency.get("task") or ""),
                        scope=(
                            self._mission_task_scope(
                                {"task_scope": raw_dependency_scope}
                            )
                            if raw_dependency_scope is not None
                            else None
                        ),
                        task_definition_version=(
                            str(dependency["task_definition_version"])
                            if dependency.get("task_definition_version") is not None
                            else None
                        ),
                        task_id=str(dependency.get("task_id") or ""),
                    )
                elif (
                    isinstance(dependency, (list, tuple))
                    and len(dependency) == 2
                ):
                    dep_agent, dep_task = dependency
                    dependency_identity = select_reference(
                        identities_by_key.get(
                            (str(dep_agent), str(dep_task)),
                            [],
                        )
                    )
                elif dependency_text in records_by_id:
                    dependency_identity = available_entries.get(
                        ("task_id", dependency_text)
                    )
                else:
                    dependency_identity = select_reference(
                        identities_by_name.get(dependency_text, [])
                    )
                    if dependency_identity is None and ":" in dependency_text:
                        dep_agent, dep_task = dependency_text.split(":", 1)
                        dependency_identity = select_reference(
                            identities_by_key.get((dep_agent, dep_task), [])
                        )
                if dependency_identity is None:
                    invalid_reasons.setdefault(identity, []).append(dependency_text)
                else:
                    resolved_dependencies.append(dependency_identity)
            dependencies_by_identity[identity] = resolved_dependencies

        selected_by_task_id = {
            existing.task_id: identity
            for identity, _, _, _, existing, _, _ in selected
            if existing is not None
        }
        selected_by_definition = {
            (
                agent,
                task,
                self._mission_task_scope_identity(scope),
                version,
            ): identity
            for identity, agent, task, _, _, scope, version in selected
        }

        def selected_dependency_identity(
            dependency: TaskDependencyRef,
        ) -> tuple[Any, ...] | None:
            if dependency.task_id:
                return selected_by_task_id.get(dependency.task_id)
            if not dependency.agent or not dependency.task or dependency.scope is None:
                return None
            dependency_scope = (
                dependency.scope
                if isinstance(dependency.scope, TaskScope)
                else self._mission_task_scope({"task_scope": dependency.scope})
            )
            return selected_by_definition.get(
                (
                    dependency.agent,
                    dependency.task,
                    self._mission_task_scope_identity(dependency_scope),
                    (
                        dependency.task_definition_version
                        or TASK_DEFINITION_SCHEMA_VERSION
                    ),
                )
            )

        changed = True
        while changed:
            changed = False
            for identity, _, _, _, _, _, _ in selected:
                if identity in invalid_reasons:
                    continue
                invalid_dependencies = [
                    dependency.task or dependency.task_id
                    for dependency in dependencies_by_identity[identity]
                    if selected_dependency_identity(dependency) in invalid_reasons
                ]
                if invalid_dependencies:
                    invalid_reasons[identity] = invalid_dependencies
                    changed = True

        definitions: list[MissionTaskDefinition] = []
        blocked_reasons_by_position: dict[int, str] = {}
        default_retry_policy = self._mission_task_retry_policy()
        for identity, agent, task, step, existing, scope, version in selected:
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
            if identity in invalid_reasons:
                reason = "unknown_dependencies:" + ",".join(
                    sorted(dict.fromkeys(invalid_reasons[identity]))
                )
                definitions.append(
                    MissionTaskDefinition(
                        agent=agent,
                        task=task,
                        scope=scope,
                        capability=capability,
                        capability_id=(
                            existing.capability_id
                            if existing is not None
                            else str(step.get("capability_id") or "")
                        ),
                        task_definition_version=(
                            existing.task_definition_version if existing is not None else version
                        ),
                        retry_policy=TaskRetryPolicy(),
                        not_before=(
                            existing.not_before
                            if existing is not None
                            else step.get("not_before")
                        ),
                        backoff=(
                            existing.backoff
                            if existing is not None
                            else self._mission_task_backoff(step)
                        ),
                        provider_circuit_ref=(
                            existing.provider_circuit_ref
                            if existing is not None
                            else str(step.get("provider_circuit_ref") or "")
                        ),
                        evaluated_snapshot_ref=(
                            existing.evaluated_snapshot_ref
                            if existing is not None
                            else str(
                                step.get("evaluated_snapshot_ref")
                                or step.get("evaluated_fact_snapshot_ref")
                                or ""
                            )
                        ),
                    )
                )
                blocked_reasons_by_position[len(definitions) - 1] = reason
            else:
                definitions.append(
                    MissionTaskDefinition(
                        agent=agent,
                        task=task,
                        depends_on=tuple(dependencies_by_identity[identity]),
                        scope=scope,
                        capability=capability,
                        capability_id=(
                            existing.capability_id
                            if existing is not None
                            else str(step.get("capability_id") or "")
                        ),
                        task_definition_version=(
                            existing.task_definition_version if existing is not None else version
                        ),
                        retry_policy=retry_policy,
                        not_before=(
                            existing.not_before
                            if existing is not None
                            else step.get("not_before")
                        ),
                        backoff=(
                            existing.backoff
                            if existing is not None
                            else self._mission_task_backoff(step)
                        ),
                        provider_circuit_ref=(
                            existing.provider_circuit_ref
                            if existing is not None
                            else str(step.get("provider_circuit_ref") or "")
                        ),
                        evaluated_snapshot_ref=(
                            existing.evaluated_snapshot_ref
                            if existing is not None
                            else str(
                                step.get("evaluated_snapshot_ref")
                                or step.get("evaluated_fact_snapshot_ref")
                                or ""
                            )
                        ),
                    )
                )

        records = list(
            self.mission_store.register_plan(
                self.mission_id,
                definitions,
                blocked_reasons_by_position=blocked_reasons_by_position,
            )
        )
        if blocked_reasons_by_position:
            persisted = self.mission_store.snapshot(self.mission_id)
            records_by_id = {record.task_id: record for record in persisted.tasks}
            records = [records_by_id[record.task_id] for record in records]
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
        return self._ordered_mission_plan(
            task_ids=[record.task_id for record in records]
        )

    def _mission_task_scope(self, step: dict[str, Any]) -> TaskScope:
        raw_scope = step.get("task_scope", step.get("scope"))
        if isinstance(raw_scope, TaskScope):
            return raw_scope
        raw_entity_ids = step.get("entity_ids") or step.get("canonical_entity_ids")
        if raw_entity_ids:
            values = (
                (raw_entity_ids,)
                if isinstance(raw_entity_ids, str)
                else tuple(raw_entity_ids)
            )
            return TaskScope(
                entity_ids=tuple(str(item) for item in values),
                legacy_scope=self._legacy_scope_text(raw_scope),
            )
        if raw_scope in (None, ""):
            legacy_scope = f"target:{self._current_target}"
            try:
                return TaskScope(
                    entity_ids=(canonical_asset(self._current_target).entity_id,),
                    legacy_scope=legacy_scope,
                )
            except (TypeError, ValueError):
                return TaskScope.from_legacy(legacy_scope)
        if isinstance(raw_scope, dict) and (
            raw_scope.get("entity_ids") or raw_scope.get("canonical_entity_ids")
        ):
            raw_ids = raw_scope.get("entity_ids") or raw_scope.get(
                "canonical_entity_ids"
            )
            values = (
                (raw_ids,)
                if isinstance(raw_ids, str)
                else tuple(raw_ids or ())
            )
            return TaskScope(
                entity_ids=tuple(str(item) for item in values),
                legacy_scope=str(raw_scope.get("legacy_scope") or ""),
                schema_version=str(
                    raw_scope.get("schema_version") or TaskScope().schema_version
                ),
            )
        return TaskScope.from_legacy(self._legacy_scope_text(raw_scope))

    @staticmethod
    def _mission_task_scope_identity(
        scope: TaskScope,
    ) -> tuple[str, tuple[str, ...], str]:
        """Mirror MissionStore identity while excluding typed-scope display aliases."""
        return (
            scope.schema_version,
            scope.entity_ids,
            "" if scope.entity_ids else scope.legacy_scope,
        )

    @staticmethod
    def _legacy_scope_text(raw_scope: Any) -> str:
        if isinstance(raw_scope, (dict, list, tuple)):
            return json.dumps(
                raw_scope,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        return str(raw_scope)

    @staticmethod
    def _mission_task_backoff(step: dict[str, Any]) -> TaskBackoff:
        raw = step.get("backoff")
        if raw is None:
            return TaskBackoff()
        if not isinstance(raw, TaskBackoff):
            raise ValueError("mission task backoff must be a TaskBackoff")
        return raw

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
        fact_assessments = context.get("fact_assessments") or {}
        assessment_counts = (
            fact_assessments.get("counts")
            if isinstance(fact_assessments, dict)
            else None
        ) or context.get("fact_assessment_counts") or {}
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

    @staticmethod
    def _state_replan_transition_signature(
        previous_signature: str,
        current_signature: str,
    ) -> str:
        payload = json.dumps(
            [previous_signature, current_signature],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()

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
        transition_key = self._state_replan_transition_signature(
            previous_signature,
            current_signature,
        )
        if transition_key in self._state_replan_signatures:
            return False

        maximum = self._max_state_replans()
        if self.mission_id:
            durable = self.mission_store.record_state_replan(
                self.mission_id,
                transition_key,
                maximum,
            )
            self._state_replan_count = durable.count
            self._state_replan_signatures = set(durable.signatures)
            if durable.reason == "duplicate_transition":
                return False
            requested = durable.requested
        elif self._state_replan_count >= maximum:
            requested = False
            self._state_replan_signatures.add(transition_key)
        else:
            requested = True
            self._state_replan_count += 1
            self._state_replan_signatures.add(transition_key)

        if not requested:
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
            return False

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
        *,
        task_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        if not self.mission_id:
            return []
        snapshot = self.mission_store.snapshot(self.mission_id)
        records = list(snapshot.tasks)
        by_id = {record.task_id: record for record in records}
        now = time.time()
        if task_names is None and task_ids is None:
            selected = {
                record.task_id
                for record in records
                if record.status in {"pending", "interrupted"}
                and (
                    record.not_before is None
                    or record.not_before <= now
                )
            }
        elif task_ids is not None:
            requested_ids = set(task_ids)
            selected = {
                record.task_id
                for record in records
                if record.task_id in requested_ids
                and (
                    record.not_before is None
                    or record.not_before <= now
                )
            }
        else:
            assert task_names is not None
            requested = set(task_names)
            selected = {
                record.task_id
                for record in records
                if record.task in requested
                and (
                    record.not_before is None
                    or record.not_before <= now
                )
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
        return [
            {
                "agent": by_id[task_id].agent,
                "task": by_id[task_id].task,
                "task_id": by_id[task_id].task_id,
                "task_scope": by_id[task_id].task_scope,
            }
            for task_id in ordered
        ]

    def _resumable_mission_plan(self) -> list[dict[str, Any]]:
        """Return unfinished durable work before consulting Director or Planner."""
        return self._ordered_mission_plan()

    def _next_deferred_mission_time(self) -> float | None:
        """Return the earliest future durable task gate without sleeping in-process."""
        if not self.mission_id:
            return None
        now = time.time()
        deferred = [
            record.not_before
            for record in self.mission_store.snapshot(self.mission_id).tasks
            if record.status in {"pending", "interrupted"}
            and record.not_before is not None
            and record.not_before > now
        ]
        return min(deferred) if deferred else None

    def _mission_plan_step_exhausted(self, step: dict[str, Any]) -> bool:
        """Prefer durable task identity over the legacy name-only projections."""
        task_id = str(step.get("task_id") or "")
        if self.mission_id and task_id:
            record = next(
                (
                    item
                    for item in self.mission_store.snapshot(self.mission_id).tasks
                    if item.task_id == task_id
                ),
                None,
            )
            if record is not None:
                return record.status not in {"pending", "interrupted"}
        return self._task_exhausted(str(step.get("task") or ""))

    def _block_registered_task(
        self,
        agent: str,
        task: str,
        reason: str,
        *,
        task_id: str | None = None,
        scope: TaskScope | str | None = None,
    ):
        if not self.mission_id:
            return None
        attempt = self.mission_store.block_task(
            self.mission_id,
            agent,
            task,
            reason,
            task_id=task_id,
            scope=scope,
        )
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
        by_id = {record.task_id: record for record in snapshot.tasks}
        records_by_name: dict[str, list[Any]] = {}
        for record in snapshot.tasks:
            records_by_name.setdefault(record.task, []).append(record)
        for step in plan:
            task = str(step.get("task") or "")
            if not task or not self._task_exhausted(task):
                continue
            task_id = str(step.get("task_id") or "")
            same_name_records = records_by_name.get(task, [])
            if task_id and len(same_name_records) > 1:
                # A legacy name-only completion marker cannot identify which
                # typed scope it intended to terminalize.
                continue
            record = by_id.get(task_id) if task_id else (
                same_name_records[0] if len(same_name_records) == 1 else None
            )
            if record is None or record.status not in {"pending", "interrupted"}:
                continue
            if task in self.blocked_tasks:
                self._block_registered_task(
                    record.agent,
                    record.task,
                    "compatibility_state_blocked",
                    task_id=record.task_id,
                )
                continue
            attempt = self.mission_store.skip_task(
                self.mission_id,
                record.agent,
                record.task,
                "compatibility_state_exhausted",
                task_id=record.task_id,
            )
            if attempt.outcome is not None:
                self.task_outcome_store.record(attempt.outcome)

    def _begin_task_attempt(
        self,
        agent: str,
        task: str,
        *,
        task_id: str | None = None,
        scope: TaskScope | str | None = None,
    ):
        if not self.mission_id:
            return None
        if self._active_task_attempt_id:
            raise RuntimeError("a mission task attempt is already active")
        self._active_retry_command_keys.clear()
        try:
            attempt = self.mission_store.begin_attempt(
                self.mission_id,
                agent,
                task,
                task_id=task_id,
                scope=scope,
            )
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
                task_id=task_id,
                scope=scope,
            )
        self._active_task_attempt_id = attempt.attempt_id
        self._active_task_id = attempt.task_id
        self._active_task_name = str(task)
        self._active_task_agent = str(agent)
        self._active_retry_command_keys = set(
            self.mission_store.pending_retry_command_keys(
                self.mission_id,
                agent,
                task,
                task_id=attempt.task_id,
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
        self._active_task_id = None
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
        self._active_task_id = None
        self._active_task_name = ""
        self._active_task_agent = ""


__all__ = ["PipelineMissionMixin"]
