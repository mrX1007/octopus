#!/usr/bin/env python3

import json
import re
from typing import List

from .common import BaseParser, Fact, fact, raw_lower, tool_lower


class TemplateParser(BaseParser):
    family = "template"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Fact]:
        if "nuclei" not in tool_lower(tool_name) and "[nuclei" not in raw_lower(raw_output):
            return []
        facts: List[Fact] = []
        for line in (raw_output or "").splitlines():
            line = line.strip()
            if not line or line.startswith("[NUCLEI"):
                continue
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                except Exception:
                    data = {}
                template = data.get("template-id") or data.get("template") or data.get("id") or "unknown"
                severity = str(data.get("info", {}).get("severity") or data.get("severity") or "info").lower()
                matched = data.get("matched-at") or data.get("host") or data.get("url") or ""
                name = data.get("info", {}).get("name") or template
                facts.append(fact("nuclei_finding", f"{severity}:{template}:{matched}:{name}", 90, session_id))
                if matched:
                    facts.append(fact("asset_url", str(matched).rstrip("/"), 85, session_id))
                continue
            match = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)", line)
            if match:
                template, _proto, severity, matched = match.groups()
                facts.append(fact("nuclei_finding", f"{severity.lower()}:{template}:{matched}", 85, session_id))
        return facts
