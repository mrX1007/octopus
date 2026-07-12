#!/usr/bin/env python3

import json
from typing import Any, Optional

from core.ai.fact_store import FactStore
from core.ai.reporting import (
    build_attack_path,
    build_coverage_summary,
    build_evidence_index,
    build_finding_groups,
    build_remediations,
)


class TraceReporter:
    """Build human-readable and JSON trace reports from facts and command results."""

    def __init__(self, fact_store: FactStore):
        self.fact_store = fact_store
        self.redactor = fact_store.redactor

    def build(
        self,
        scan_id: str,
        target: str,
        goal_trace: Optional[list[dict[str, Any]]] = None,
        command_trace: Optional[list[dict[str, Any]]] = None,
        task_outcomes: Optional[list[dict[str, Any]]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        facts = self.fact_store.get_facts(scan_id, target)
        command_results = self.fact_store.get_command_results(scan_id, target)
        context = context or {}
        llm_events = self._llm_events(facts)
        state = {
            "root_access_confirmed": bool((context.get("stage_gates") or {}).get("root")),
            "persistence_established": bool((context.get("stage_gates") or {}).get("persistence")),
            "internal_recon_completed": bool((context.get("stage_gates") or {}).get("internal_recon")),
            "cleanup_completed": bool((context.get("stage_gates") or {}).get("cleanup")),
        }
        finding_groups = build_finding_groups(facts, state)
        report = {
            "scan_id": scan_id,
            "target": target,
            "summary": self._summary(facts, command_results, goal_trace or [], command_trace or []),
            "surface_states": (context.get("target_model") or {}).get("surface_states")
                or (context.get("surface_states") or {}),
            "asset_graph_summary": (context.get("asset_graph") or {}).get("summary", {}),
            "evidence_index": build_evidence_index(facts),
            "finding_groups": finding_groups,
            "coverage": build_coverage_summary(facts),
            "attack_path": build_attack_path(facts, state),
            "remediations": build_remediations(finding_groups, facts),
            "llm_status": self._llm_status(goal_trace or [], task_outcomes or [], llm_events),
            "llm_events": llm_events,
            "goal_trace": goal_trace or [],
            "command_trace": command_trace or [],
            "task_outcomes": task_outcomes or [],
            "command_results": command_results,
            "fact_flow": self._fact_flow(facts),
        }
        return self.redactor.redact_data(report)

    def to_text(self, report: dict[str, Any]) -> str:
        report = self.redactor.redact_data(report)
        summary = report.get("summary") or {}
        lines = [
            "OCTOPUS trace report",
            f"scan_id: {report.get('scan_id')}",
            f"target: {report.get('target')}",
            "",
            "summary:",
            f"  facts: {summary.get('facts', 0)}",
            f"  fact_types: {summary.get('fact_types', 0)}",
            f"  commands: {summary.get('commands', 0)}",
            f"  duplicate_outputs: {summary.get('duplicate_outputs', 0)}",
            f"  skipped_commands: {summary.get('skipped_commands', 0)}",
            f"  goals: {summary.get('goals', 0)}",
            "",
            "surface_states:",
        ]
        for key, value in sorted((report.get("surface_states") or {}).items()):
            lines.append(f"  {key}: {value}")
        lines.append("")
        lines.append("asset_graph_summary:")
        for key, value in sorted((report.get("asset_graph_summary") or {}).items()):
            lines.append(f"  {key}: {value}")
        lines.append("")
        lines.append("coverage:")
        coverage = report.get("coverage") or {}
        lines.append(f"  confidence: {coverage.get('confidence', 'normal')}")
        for item in coverage.get("degraded", [])[:10]:
            lines.append(f"  degraded: {item.get('tool')} {item.get('status')} - {item.get('impact')}")
        for item in coverage.get("checked_but_not_confirmed", [])[:10]:
            lines.append(f"  checked: {item.get('status')}")
        lines.append("")
        lines.append("evidence_index:")
        human_evidence = self._human_evidence(report.get("evidence_index", []))
        for item in human_evidence[:20]:
            lines.append(
                f"  - {item.get('evidence_id')} {item.get('fact_type')} "
                f"tool={self._short(item.get('tool'), 80)} "
                f"parser={item.get('parsed_by')} confidence={item.get('confidence')}: "
                f"{self._short(item.get('fact_value'), 160)}"
            )
        if not human_evidence:
            lines.append("  none")
        lines.append("")
        lines.append("finding_groups:")
        for group in report.get("finding_groups", [])[:12]:
            lines.append(
                f"  - {group.get('module')} service={group.get('service')} ports={group.get('ports')} "
                f"candidate={group.get('candidate')} verified={group.get('verified')} "
                f"exploited={group.get('exploited')} impact={group.get('impact_confirmed')}"
            )
        lines.append("")
        lines.append("attack_path:")
        for idx, step in enumerate(report.get("attack_path", [])[:12], 1):
            lines.append(
                f"  {idx}. {step.get('stage')}: {step.get('status')} - "
                f"{self._short(step.get('detail'), 160)}"
            )
        if not report.get("attack_path"):
            lines.append("  none")
        lines.append("")
        lines.append("remediations:")
        for item in report.get("remediations", [])[:12]:
            lines.append(
                f"  - {item.get('service', 'unknown')}: "
                f"{self._short(item.get('recommendation'), 220)}"
            )
        if not report.get("remediations"):
            lines.append("  none")
        lines.append("")
        lines.append("llm_status:")
        llm_status = report.get("llm_status") or {}
        lines.append(f"  primary_response: {llm_status.get('primary_response', 'unknown')}")
        lines.append(f"  empty_response_events: {llm_status.get('empty_response_events', 0)}")
        lines.append(f"  fallback_policy_used: {llm_status.get('fallback_policy_used', False)}")
        lines.append(f"  scan_continued_safely: {llm_status.get('scan_continued_safely', True)}")
        for event in report.get("llm_events", [])[-10:]:
            lines.append(
                f"  event: loop={event.get('loop')} role={event.get('role')} "
                f"status={event.get('status')} fallback={event.get('fallback')}"
            )
        lines.append("")
        lines.append("commands:")
        for item in report.get("command_results", [])[-20:]:
            dup = " duplicate_output" if self._is_duplicate_output(item, report.get("command_results", [])) else ""
            failed = " failed" if item.get("failed") else ""
            lines.append(
                f"  - {item.get('command')} facts={item.get('new_facts')}/{item.get('parsed_facts')} "
                f"hash={str(item.get('output_hash', ''))[:12]}{dup}{failed}"
            )
        if report.get("goal_trace"):
            lines.append("")
            lines.append("goals:")
            for item in report.get("goal_trace", [])[-10:]:
                lines.append(
                    f"  - loop={item.get('loop')} state={item.get('state')} "
                    f"goal={item.get('goal')} required={item.get('next_required_capability')}"
                )
        lines.append("")
        lines.append("fact_flow:")
        human_flow = self._human_fact_flow(report.get("fact_flow", []))
        for item in human_flow[-30:]:
            lines.append(f"  - {item.get('type')} <- {', '.join(item.get('sources') or [])}: {item.get('value')}")
        if not human_flow:
            lines.append("  none")
        return "\n".join(lines)

    def to_json(self, report: dict[str, Any]) -> str:
        return json.dumps(self.redactor.redact_data(report), indent=2, sort_keys=True, default=str)

    def _summary(
        self,
        facts: list[dict[str, Any]],
        command_results: list[dict[str, Any]],
        goal_trace: list[dict[str, Any]],
        command_trace: list[dict[str, Any]],
    ) -> dict[str, int]:
        output_hashes: dict[Any, int] = {}
        for result in command_results:
            output_hashes[result.get("output_hash")] = output_hashes.get(result.get("output_hash"), 0) + 1
        return {
            "facts": len(facts),
            "fact_types": len({fact.get("type") for fact in facts}),
            "commands": len(command_results),
            "duplicate_outputs": sum(1 for count in output_hashes.values() if count > 1),
            "skipped_commands": len([item for item in command_trace if item.get("action") == "skip"]),
            "goals": len(goal_trace),
        }

    def _fact_flow(self, facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        flow = []
        for fact in facts:
            flow.append({
                "type": fact.get("type"),
                "value": fact.get("value"),
                "sources": fact.get("sources") or ([fact.get("source")] if fact.get("source") else []),
                "observations": len(fact.get("observations") or []),
                "confidence": fact.get("confidence", 100),
            })
        return flow

    def _human_evidence(self, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            item for item in evidence or []
            if self._is_human_fact_type(str(item.get("fact_type") or ""))
        ]

    def _human_fact_flow(self, flow: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            item for item in flow or []
            if self._is_human_fact_type(str(item.get("type") or ""))
        ]

    def _is_human_fact_type(self, fact_type: str) -> bool:
        return fact_type not in {"check_result", "llm_health", "network_node", "network_edge", "external_url"}

    def _llm_status(
        self,
        goal_trace: list[dict[str, Any]],
        task_outcomes: list[dict[str, Any]],
        llm_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        empty_events = [
            item for item in task_outcomes
            if item.get("agent") == "AnalysisAgent"
            and item.get("status") == "failed"
            and item.get("reason") == "analysis_returned_no_hypotheses"
        ]
        failed_events = [event for event in llm_events if event.get("status") == "failed"]
        fallback_events = [
            item for item in goal_trace
            if any(marker in str(item.get("thought", "")).lower() for marker in ("policy forced", "fallback"))
        ]
        fallback_events.extend(event for event in llm_events if event.get("fallback"))
        return {
            "primary_response": "failed" if failed_events else ("empty" if empty_events else "available_or_not_needed"),
            "empty_response_events": len(empty_events) + len([
                event for event in failed_events
                if "empty" in str(event.get("error", "")).lower() or "json" in str(event.get("error", "")).lower()
            ]),
            "fallback_policy_used": bool(fallback_events),
            "fallback_events": fallback_events[-5:],
            "scan_continued_safely": True,
        }

    def _llm_events(self, facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        events = []
        for fact in facts:
            if fact.get("type") != "llm_health":
                continue
            try:
                payload = json.loads(str(fact.get("value", "")))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            payload.setdefault("timestamp", fact.get("timestamp"))
            events.append(payload)
        return events

    def _is_duplicate_output(self, item: dict[str, Any], all_results: list[dict[str, Any]]) -> bool:
        output_hash = item.get("output_hash")
        return bool(output_hash and sum(1 for result in all_results if result.get("output_hash") == output_hash) > 1)

    def _short(self, value: Any, limit: int) -> str:
        return self.redactor.redact_text(value, kind="trace").replace("\n", " ")[:limit]
