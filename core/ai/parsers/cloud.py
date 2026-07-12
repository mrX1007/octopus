#!/usr/bin/env python3

import json

from .common import BaseParser, Fact, fact, tool_lower


class CloudParser(BaseParser):
    family = "cloud"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        if not any(marker in tool_lower(tool_name) for marker in ("prowler", "scoutsuite")):
            return []
        facts: list[Fact] = []
        for line in (raw_output or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            status = str(data.get("Status") or data.get("status") or "").lower()
            if status not in {"fail", "failed", "danger", "warning"}:
                continue
            severity = str(data.get("Severity") or data.get("severity") or "info").lower()
            check_id = data.get("CheckID") or data.get("check_id") or data.get("id") or ""
            resource = data.get("ResourceId") or data.get("resource_id") or data.get("ServiceName") or data.get("service") or ""
            if check_id:
                facts.append(fact("cloud_finding", f"{severity}:{check_id}:{resource}", 85, session_id))
        return facts
