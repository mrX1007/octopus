#!/usr/bin/env python3

import re

from .common import BaseParser, Fact, fact, tool_lower


class ASMParser(BaseParser):
    family = "asm"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        tool = tool_lower(tool_name)
        if not any(marker in tool for marker in ("subfinder", "amass", "dnsx", "httpx", "naabu", "tlsx", "wayback", "gau")):
            return []
        facts: list[Fact] = []
        for line in (raw_output or "").splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            for url in re.findall(r"\bhttps?://[^\s\"'<>]+", line):
                facts.append(fact("asset_url", url.rstrip("/"), 85, session_id))
            for domain in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", line):
                facts.append(fact("asset_domain", domain.lower().strip("."), 85, session_id))
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
                facts.append(fact("asset_ip", ip, 85, session_id))
            cname = re.search(r"(?i)\bCNAME\b[:\s]+((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})", line)
            if cname:
                facts.append(fact("asset_dns_record", f"cname:{cname.group(1).lower().strip('.')}", 80, session_id))
            status_match = re.search(r"\[(\d{3})\]", line)
            if status_match and re.search(r"https?://", line):
                facts.append(fact("http_status", f"{status_match.group(1)}:{line[:180]}", 80, session_id))
            tech_match = re.search(r"\[([A-Za-z0-9_.+:/, -]{2,160})\]\s*$", line)
            if tech_match and re.search(r"https?://", line):
                tech = tech_match.group(1).strip()
                if not tech.isdigit():
                    facts.append(fact("technology", tech[:160], 75, session_id))
            service_match = re.search(r"((?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}):(\d{1,5})", line)
            if service_match:
                facts.append(fact("asset_service", f"{service_match.group(1).lower()}:{service_match.group(2)}/tcp", 80, session_id))
            if any(marker in tool for marker in ("tlsx", "tls_probe")):
                for san in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", line):
                    facts.append(fact("asset_dns_record", f"tls_san:{san.lower().strip('.')}", 75, session_id))
        return facts
