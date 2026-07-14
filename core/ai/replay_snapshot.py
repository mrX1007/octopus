#!/usr/bin/env python3

import json
from typing import Any

from core.ai.pipeline import AIPipeline


class ReplaySnapshot:
    """Run raw outputs through the pipeline and assert expected facts/actions."""

    SCHEMA_VERSION = "1.0"
    LEGACY_SCHEMA_VERSION = "0"

    def __init__(self, db_path: str):
        self.pipeline = AIPipeline(db_path)

    def run(self, spec: dict[str, Any]) -> dict[str, Any]:
        input_schema_version = str(spec.get("schema_version") or self.LEGACY_SCHEMA_VERSION)
        if input_schema_version not in {self.LEGACY_SCHEMA_VERSION, self.SCHEMA_VERSION}:
            raise ValueError(
                "Unsupported replay snapshot schema "
                f"{input_schema_version!r}; supported: "
                f"{self.LEGACY_SCHEMA_VERSION}, {self.SCHEMA_VERSION}"
            )
        scan_id = spec["scan_id"]
        target = spec["target"]
        result = self.pipeline.replay_outputs(scan_id, target, spec.get("outputs", []))
        facts = self.pipeline.fact_store.get_facts(scan_id, target)
        fact_pairs = {(fact.get("type"), fact.get("value")) for fact in facts}
        actions = [item.get("command") for item in result.get("snapshot_actions", [])]
        context = result.get("context") or {}
        failures: list[str] = []

        for expected in spec.get("expected_facts", []):
            pair = self._expected_pair(expected)
            if pair not in fact_pairs:
                failures.append(f"missing_fact:{pair[0]}:{pair[1]}")

        for expected in spec.get("expected_fact_prefixes", []):
            ftype, prefix = self._expected_pair(expected)
            if not any(pair_type == ftype and str(value).startswith(prefix) for pair_type, value in fact_pairs):
                failures.append(f"missing_fact_prefix:{ftype}:{prefix}")

        for command in spec.get("expected_actions", []):
            if not any(str(action or "").startswith(command) for action in actions):
                failures.append(f"missing_action:{command}")

        surface_states = (context.get("target_model") or {}).get("surface_states") or context.get("surface_states") or {}
        for surface, expected_state in (spec.get("expected_surface_states") or {}).items():
            actual = surface_states.get(surface)
            if actual != expected_state:
                failures.append(f"surface_state:{surface}:expected={expected_state}:actual={actual}")

        return {
            "schema_version": self.SCHEMA_VERSION,
            "input_schema_version": input_schema_version,
            "migration": (
                {"from": self.LEGACY_SCHEMA_VERSION, "to": self.SCHEMA_VERSION}
                if input_schema_version == self.LEGACY_SCHEMA_VERSION
                else None
            ),
            "ok": not failures,
            "failures": failures,
            "result": result,
            "facts": facts,
            "actions": actions,
            "surface_states": surface_states,
        }

    def assert_ok(self, spec: dict[str, Any]) -> dict[str, Any]:
        result = self.run(spec)
        if not result["ok"]:
            raise AssertionError("; ".join(result["failures"]))
        return result

    def assert_file_ok(self, path: str) -> dict[str, Any]:
        with open(path, encoding="utf-8") as fh:
            spec = json.load(fh)
        return self.assert_ok(spec)

    def _expected_pair(self, expected: Any) -> tuple[str, str]:
        if isinstance(expected, dict):
            return str(expected.get("type")), str(expected.get("value"))
        if isinstance(expected, (list, tuple)) and len(expected) == 2:
            return str(expected[0]), str(expected[1])
        raise ValueError(f"Invalid expected fact: {expected!r}")
