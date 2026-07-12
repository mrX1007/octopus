#!/usr/bin/env python3

import ipaddress
import re

from .common import BaseParser, Fact, fact, raw_lower, tool_lower


class NetworkGraphParser(BaseParser):
    family = "network_graph"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        if "network_recon" not in tool_lower(tool_name) and "network discovery" not in raw_lower(raw_output):
            return []
        facts: list[Fact] = []
        for subnet in re.findall(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168|169\.254)(?:\.\d{1,3}){2}/\d{1,2}\b", raw_output or ""):
            if self._is_internal_subnet(subnet):
                facts.append(fact("internal_subnet", subnet, 85, session_id))
        for host in re.findall(r"(?m)^\s*->\s*((?:\d{1,3}\.){3}\d{1,3})\s*$", raw_output or ""):
            if self._is_internal_host(host):
                facts.append(fact("internal_host", host, 80, session_id))
        if "internal hosts discovered" in raw_lower(raw_output):
            facts.append(fact("service_status", "network_recon_completed", 95, session_id))
        return facts

    def _is_internal_subnet(self, value: str) -> bool:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        return network.is_private or network.is_link_local

    def _is_internal_host(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if not (address.is_private or address.is_link_local):
            return False
        last_octet = int(value.rsplit(".", 1)[-1])
        return last_octet not in {0, 255}
