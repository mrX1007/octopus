#!/usr/bin/env python3

from __future__ import annotations

import json
import re
from typing import Any

from .common import BaseParser, Fact, check_result_fact, fact, raw_lower, tool_identity, tool_lower

_SAFE_PLUGIN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SAFE_PLUGIN_TYPE = frozenset(
    {
        "auxiliary",
        "evasion",
        "exploit",
        "lateral",
        "osint",
        "persistence",
        "post",
        "recon",
    }
)


def _bounded(value: Any, limit: int = 160) -> str:
    return " ".join(str(value or "").split())[:limit]


class PluginParser(BaseParser):
    family = "plugin"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        inventory = self._parse_inventory(tool_name, raw_output, session_id)
        if inventory is not None:
            return inventory
        checked = self._parse_check(tool_name, raw_output, session_id)
        if checked is not None:
            return checked
        identity = tool_identity(tool_name)
        if identity not in {"plugin", "plugin_inventory"} and "plugin_result" not in raw_lower(raw_output):
            return []
        facts: list[Fact] = []
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", raw_output or "", re.IGNORECASE):
            facts.append(fact("potential_vulnerability", cve.upper(), 65, session_id))
        if "tool_unavailable" in raw_lower(raw_output) or "not installed" in raw_lower(raw_output):
            facts.append(fact("tool_unavailable", identity or "plugin", 80, session_id))
        return facts

    def _parse_inventory(
        self,
        tool_name: str,
        raw_output: str,
        session_id: str,
    ) -> list[Fact] | None:
        command = tool_lower(tool_name).split()
        identity = tool_identity(tool_name)
        is_inventory_action = identity == "plugin_inventory" or (
            identity == "plugin" and len(command) >= 2 and command[1] in {"list", "ls", "summary"}
        )
        if not is_inventory_action:
            return None
        try:
            payload = json.loads((raw_output or "").strip())
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        skipped: list[dict[str, str]] = []
        invalid_count = 0
        canonical_envelope = False
        if isinstance(payload, dict):
            canonical_envelope = True
            raw_plugins = payload.get("plugins")
            raw_skipped = payload.get("skipped", [])
            if not isinstance(raw_plugins, list) or not isinstance(raw_skipped, list):
                return []
            invalid_count += max(0, len(raw_skipped) - 256)
            for item in raw_skipped[:256]:
                if not isinstance(item, dict):
                    invalid_count += 1
                    continue
                raw_module = item.get("module")
                raw_reason = item.get("reason")
                if not isinstance(raw_module, str) or not isinstance(raw_reason, str):
                    invalid_count += 1
                    continue
                module = _bounded(raw_module, 128)
                reason = _bounded(raw_reason, 160)
                if _SAFE_PLUGIN_NAME.fullmatch(module) and reason:
                    skipped.append({"module": module, "reason": reason})
                else:
                    invalid_count += 1
            invalid_count += max(0, len(raw_plugins) - 256)
            payload = raw_plugins
        if not isinstance(payload, list):
            return []

        plugins: list[dict[str, Any]] = []
        for item in payload[:256]:
            if not isinstance(item, dict):
                invalid_count += int(canonical_envelope)
                continue
            raw_name = item.get("name")
            raw_type = item.get("type")
            if canonical_envelope and (not isinstance(raw_name, str) or not isinstance(raw_type, str)):
                invalid_count += 1
                continue
            name = _bounded(raw_name, 128)
            plugin_type = _bounded(raw_type, 32).casefold()
            if not _SAFE_PLUGIN_NAME.fullmatch(name) or plugin_type not in _SAFE_PLUGIN_TYPE:
                invalid_count += int(canonical_envelope)
                continue
            raw_stage = item.get("stage", 0)
            if isinstance(raw_stage, bool) or (canonical_envelope and not isinstance(raw_stage, int)):
                invalid_count += int(canonical_envelope)
                continue
            try:
                stage = int(raw_stage)
            except (TypeError, ValueError):
                stage = 0
            if not 1 <= stage <= 9:
                invalid_count += int(canonical_envelope)
                continue
            raw_supports_check = item.get("supports_check", False)
            if canonical_envelope and ("supports_check" not in item or not isinstance(raw_supports_check, bool)):
                invalid_count += 1
                continue
            raw_requires = item.get("requires", [])
            raw_depends_on = item.get("depends_on", [])
            if canonical_envelope and (
                not isinstance(raw_requires, list)
                or not all(isinstance(value, str) for value in raw_requires)
                or not isinstance(raw_depends_on, list)
                or not all(isinstance(value, str) for value in raw_depends_on)
            ):
                invalid_count += 1
                continue
            requires = (
                [
                    dependency
                    for raw_dependency in (raw_requires or [])[:32]
                    if _SAFE_PLUGIN_NAME.fullmatch(dependency := _bounded(raw_dependency, 128))
                ]
                if isinstance(raw_requires, list)
                else []
            )
            depends_on = (
                [
                    dependency
                    for raw_dependency in (raw_depends_on or [])[:32]
                    if _SAFE_PLUGIN_NAME.fullmatch(dependency := _bounded(raw_dependency, 128))
                ]
                if isinstance(raw_depends_on, list)
                else []
            )
            plugins.append(
                {
                    "depends_on": depends_on,
                    "name": name,
                    "requires": requires,
                    "stage": stage,
                    "supports_check": raw_supports_check if isinstance(raw_supports_check, bool) else False,
                    "type": plugin_type,
                    "version": _bounded(item.get("version"), 64),
                }
            )

        summary = {
            "plugin_count": len(plugins),
            "plugins": [
                {
                    "name": plugin["name"],
                    "supports_check": plugin["supports_check"],
                    "type": plugin["type"],
                }
                for plugin in plugins[:8]
            ],
            "skipped_count": len(skipped),
        }
        if invalid_count:
            summary["invalid_count"] = invalid_count
        if skipped:
            summary["skipped"] = skipped[:8]
        facts: list[Fact] = [
            check_result_fact(
                identity,
                "plugin_assessment",
                "unknown",
                "plugin_catalog",
                session_id,
                status="partial" if skipped or invalid_count else "completed",
                summary=summary,
                confidence=95,
            )
        ]
        facts.extend(
            fact(
                "plugin_inventory",
                json.dumps(
                    {
                        "name": plugin["name"],
                        "stage": plugin["stage"],
                        "supports_check": plugin["supports_check"],
                        "type": plugin["type"],
                        "version": plugin["version"],
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                90,
                session_id,
            )
            for plugin in plugins
        )
        return facts

    def _parse_check(
        self,
        tool_name: str,
        raw_output: str,
        session_id: str,
    ) -> list[Fact] | None:
        command = tool_lower(tool_name).split()
        identity = tool_identity(tool_name)
        if identity != "plugin" or len(command) < 3:
            return None
        requested_action = command[3] if len(command) >= 4 else "scan"
        if requested_action not in {"check", "scan"}:
            return None
        try:
            payload = json.loads((raw_output or "").strip())
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        if not isinstance(payload, dict) or str(payload.get("action") or "").casefold() != "check":
            return []

        plugin_name = _bounded(payload.get("plugin"), 128)
        if (
            not _SAFE_PLUGIN_NAME.fullmatch(plugin_name)
            or plugin_name.casefold() != command[1].casefold()
            or not isinstance(payload.get("supports_check"), bool)
            or not isinstance(payload.get("vulnerable"), bool)
        ):
            return []
        try:
            confidence = float(payload.get("confidence", 0.0))
        except (TypeError, ValueError):
            return []
        if not 0.0 <= confidence <= 1.0:
            return []

        details = _bounded(payload.get("details"), 160)
        supports_check = payload["supports_check"]
        completed = supports_check and details.casefold() != "check() not implemented"
        return [
            check_result_fact(
                identity,
                "plugin_assessment",
                "endpoint",
                _bounded(command[2], 256),
                session_id,
                status="completed" if completed else "partial",
                summary={
                    "check_supported": supports_check,
                    "confidence": confidence,
                    "plugin": plugin_name,
                    "vulnerable": payload["vulnerable"],
                },
                confidence=90,
            )
        ]
