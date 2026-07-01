#!/usr/bin/env python3

import re
from typing import List

from .common import BaseParser, Fact, fact, raw_lower, tool_lower


class SSHParser(BaseParser):
    family = "ssh"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Fact]:
        if "ssh" not in tool_lower(tool_name) and "ssh connected as" not in raw_lower(raw_output):
            return []
        facts: List[Fact] = []
        for match in re.finditer(r"SSH connected as\s+([^\s@]+)@([^\s:]+)", raw_output or "", re.IGNORECASE):
            user, host = match.groups()
            facts.append(fact("credential", f"ssh_login_success:{user}@{host}", 100, session_id))
            facts.append(fact("service_status", "ssh_authenticated", 100, session_id))
            facts.append(fact("port_open", "22/tcp (ssh)", 90, session_id))
        if "auth failed" in raw_lower(raw_output) or "ssh connection failed" in raw_lower(raw_output):
            facts.append(fact("service_status", "ssh_auth_failed:unknown", 85, session_id))
        return facts
