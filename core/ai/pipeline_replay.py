"""Replay and read-only reporting facade for :class:`AIPipeline`.

The mixin deliberately owns no runtime state.  It keeps replay normalization
and snapshot/report queries out of the orchestration facade while preserving
the public methods and their legacy return shapes.
"""

from __future__ import annotations

import hashlib
from typing import Any

from core.ai.pipeline_types import PipelineMixinBase
from core.execution import ExecutionResult


class PipelineReplayMixin(PipelineMixinBase):
    def _prepare_replay_entry(
        self,
        entry: dict[str, Any],
    ) -> tuple[Any, str, bool, bool, str]:
        nested_result = entry.get("result")
        if nested_result is not None:
            payload: Any = nested_result
        elif any(
            key in entry
            for key in (
                "schema_version",
                "status",
                "stdout",
                "stderr",
                "exit_code",
                "partial",
                "error",
                "metadata",
            )
        ):
            payload = {
                key: value
                for key, value in entry.items()
                if key not in {"tool", "command", "result"}
            }
        else:
            payload = entry.get("output") or entry.get("raw_output") or ""

        if (
            isinstance(payload, dict)
            and "raw_output" in payload
            and "stdout" not in payload
            and "output" not in payload
        ):
            payload = dict(payload)
            payload["output"] = payload.pop("raw_output")

        payload_schema = self.runtime.validate_result_schema(payload)
        supplied_request_id = False
        supplied_execution_id = False
        payload_tool = ""
        if isinstance(payload, ExecutionResult):
            supplied_request_id = bool(payload.request_id)
            supplied_execution_id = bool(payload.execution_id)
            payload_tool = payload.tool_name
        elif isinstance(payload, dict):
            supplied_request_id = bool(payload.get("request_id"))
            supplied_execution_id = bool(payload.get("execution_id"))
            payload_tool = str(payload.get("tool_name") or "")
        return (
            payload,
            payload_schema,
            supplied_request_id,
            supplied_execution_id,
            payload_tool,
        )

    def replay_outputs(
        self,
        scan_id: str,
        target: str,
        outputs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Replay legacy or canonical outputs through the runtime boundary."""

        completion_fence = self.fact_store.capture_scan_completion_fence(scan_id)
        prepared = [self._prepare_replay_entry(entry) for entry in (outputs or [])]
        stored = 0
        parsed = 0
        execution_results: list[dict[str, Any]] = []
        execution_context = self._execution_context(scan_id, target)
        for index, (entry, prepared_entry) in enumerate(zip(outputs or [], prepared)):
            (
                payload,
                payload_schema,
                supplied_request_id,
                supplied_execution_id,
                payload_tool,
            ) = prepared_entry

            tool = str(
                entry.get("tool")
                or entry.get("command")
                or payload_tool
                or "replay"
            )
            canonical = self.runtime.normalize_result(
                payload,
                tool_name=tool,
                max_output_bytes=execution_context.max_output_bytes,
            )
            output_text = self._output_text(canonical)
            output_hash = self.runtime.output_fingerprint(output_text)
            identity_seed = "\0".join(
                (scan_id, target, str(index), canonical.tool_name, output_hash)
            ).encode("utf-8", "replace")
            identity = hashlib.sha256(identity_seed).hexdigest()
            if not supplied_request_id:
                canonical.request_id = f"replay-request-{identity[:32]}"
            if not supplied_execution_id:
                canonical.execution_id = f"replay-execution-{identity[32:]}"

            failed = self._command_failed(canonical, output_text)
            completion = self.runtime.complete_execution(
                scan_id,
                target,
                f"replay:{canonical.tool_name}",
                canonical.tool_name,
                canonical,
                source=f"replay:{canonical.tool_name}",
                normalize_fact=self._scope_normalized_fact,
                derive_facts=self._derived_facts_from_fact,
                failed=failed,
                completion_fence=completion_fence,
            )
            parsed += completion["parsed_facts"]
            stored += completion["new_facts"]
            command_result = completion["command_result"]
            execution_results.append(
                {
                    "schema_version": canonical.schema_version,
                    "input_schema_version": payload_schema,
                    "status": canonical.status.value,
                    "request_id": canonical.request_id,
                    "execution_id": canonical.execution_id,
                    "tool_name": canonical.tool_name,
                    "policy_decision_ref": canonical.policy_decision_ref,
                    "exit_code": canonical.exit_code,
                    "duration": canonical.duration,
                    "partial": canonical.partial,
                    "executed": canonical.executed,
                    "failed": failed,
                    "output_hash": output_hash,
                    "output_bytes": len(canonical.stdout.encode("utf-8", "ignore")),
                    "stderr_bytes": len(canonical.stderr.encode("utf-8", "ignore")),
                    "artifact_count": len(canonical.artifact_refs),
                    "parsed_facts": completion["parsed_facts"],
                    "new_facts": completion["new_facts"],
                    "duplicate_output": command_result["duplicate_output"],
                }
            )
        context = self.context_builder.build_context(scan_id, target)
        return {
            "schema_version": "1.0",
            "parsed_facts": parsed,
            "new_facts": stored,
            "context": context,
            "snapshot_actions": self.snapshot_actions(scan_id, target),
            "execution_results": execution_results,
            "replay_results": [dict(item) for item in execution_results],
        }

    def snapshot_actions(self, scan_id: str, target: str) -> list[dict[str, str]]:
        """Return deterministic next actions without executing them."""
        facts = self.fact_store.get_facts(scan_id, target)
        executed_fact_actions = set(self.executed_fact_action_commands)
        service_evidence_seen = set(self.service_intelligence_evidence_seen)
        try:
            commands = self._fact_driven_action_commands(scan_id, target, facts)
        finally:
            self.executed_fact_action_commands = executed_fact_actions
            self.service_intelligence_evidence_seen = service_evidence_seen
        decisions = []
        all_facts = self.fact_store.get_facts(scan_id, target)
        execution_context = self._execution_context(scan_id, target)
        for command in commands:
            decision = self.runtime.decide(
                command,
                all_facts,
                self.executed_command_keys,
                execution_context,
            )
            decisions.append(decision.to_dict())
        return decisions

    def trace_report(self, scan_id: str, target: str) -> dict[str, Any]:
        evaluated_fact_snapshot = (
            self.context_builder.build_evaluated_fact_snapshot(scan_id, target)
        )
        context = self.context_builder.build_context(
            scan_id,
            target,
            evaluated_fact_snapshot=evaluated_fact_snapshot,
        )
        return self.trace_reporter.build(
            scan_id,
            target,
            goal_trace=self.goal_trace,
            command_trace=self.command_trace,
            task_outcomes=self.task_outcomes,
            context=context,
            decision_events=self.decision_trace.list_events(
                scan_id=scan_id,
                limit=2_000,
            ),
            evaluated_fact_snapshot=evaluated_fact_snapshot,
        )

    def trace_report_text(self, scan_id: str, target: str) -> str:
        return self.trace_reporter.to_text(self.trace_report(scan_id, target))


__all__ = ["PipelineReplayMixin"]
