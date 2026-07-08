#!/usr/bin/env python3

import re
from typing import List

from .common import BaseParser, Fact, fact, tool_lower


class NmapParser(BaseParser):
    family = "nmap"
    port_line_re = re.compile(
        r"(?m)^\s*(?:\[[^\]\n]+\]\s*)?(\d+)/(tcp|udp)[ \t]+"
        r"(open|filtered)[ \t]+(\S+)(?:[ \t]+([^\n]+))?"
    )

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Fact]:
        if "nmap" not in tool_lower(tool_name) and "rustscan" not in tool_lower(tool_name):
            if not self.port_line_re.search(raw_output or ""):
                return []
        facts: List[Fact] = []
        for match in self.port_line_re.finditer(raw_output or ""):
            port, proto, state, service, version = match.groups()
            if state == "filtered":
                facts.append(fact("port_filtered", f"{port}/{proto} ({service})", 85, session_id))
                continue
            value = f"{port}/{proto} ({service})"
            if version:
                value += f" [{version.strip()[:60]}]"
            facts.append(fact("port_open", value, 100, session_id))
            if version and version.strip().lower() not in {"tcpwrapped", "unknown"}:
                facts.append(fact("service_version", f"{service}:{port}:{version.strip()[:120]}", 90, session_id))
        host_match = re.search(r"Service Info:\s*Host:\s*(\S+)", raw_output or "")
        if host_match:
            facts.append(fact("hostname", host_match.group(1), 100, session_id))
        return facts
