#!/usr/bin/env python3

import json
from typing import Any, Dict, List

from core.ai.fact_store import FactStore


class TraceReporter:
    """Build human-readable and JSON trace reports from facts and command results."""

    def __init__(self, fact_store: FactStore):
        self.fact_store = fact_store

    def build(
        self,
        scan_id: str,
        target: str,
        goal_trace: List[Dict[str, Any]] = None,
        command_trace: List[Dict[str, Any]] = None,
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        facts = self.fact_store.get_facts(scan_id, target)
        command_results = self.fact_store.get_command_results(scan_id, target)
        return {
            "scan_id": scan_id,
            "target": target,
            "summary": self._summary(facts, command_results, goal_trace or [], command_trace or []),
            "surface_states": ((context or {}).get("target_model") or {}).get("surface_states")
                or ((context or {}).get("surface_states") or {}),
            "asset_graph_summary": ((context or {}).get("asset_graph") or {}).get("summary", {}),
            "goal_trace": goal_trace or [],
            "command_trace": command_trace or [],
            "command_results": command_results,
            "fact_flow": self._fact_flow(facts),
        }

    def to_text(self, report: Dict[str, Any]) -> str:
        summary = report.get("summary") or {}
        lines = [
            f"OCTOPUS trace report",
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
        for item in report.get("fact_flow", [])[-30:]:
            lines.append(f"  - {item.get('type')} <- {', '.join(item.get('sources') or [])}: {item.get('value')}")
        return "\n".join(lines)

    def to_json(self, report: Dict[str, Any]) -> str:
        return json.dumps(report, indent=2, sort_keys=True, default=str)

    def _summary(
        self,
        facts: List[Dict[str, Any]],
        command_results: List[Dict[str, Any]],
        goal_trace: List[Dict[str, Any]],
        command_trace: List[Dict[str, Any]],
    ) -> Dict[str, int]:
        output_hashes = {}
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

    def _fact_flow(self, facts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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

    def _is_duplicate_output(self, item: Dict[str, Any], all_results: List[Dict[str, Any]]) -> bool:
        output_hash = item.get("output_hash")
        return bool(output_hash and sum(1 for result in all_results if result.get("output_hash") == output_hash) > 1)
