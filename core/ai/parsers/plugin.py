#!/usr/bin/env python3

import re
from typing import List

from .common import BaseParser, Fact, fact, raw_lower, tool_lower


class PluginParser(BaseParser):
    family = "plugin"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Fact]:
        if "plugin" not in tool_lower(tool_name) and "plugin_result" not in raw_lower(raw_output):
            return []
        facts: List[Fact] = []
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", raw_output or "", re.IGNORECASE):
            facts.append(fact("potential_vulnerability", cve.upper(), 65, session_id))
        if "tool_unavailable" in raw_lower(raw_output) or "not installed" in raw_lower(raw_output):
            tool = (tool_name or "plugin").split()[0]
            facts.append(fact("tool_unavailable", tool, 80, session_id))
        return facts
