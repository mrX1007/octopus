#!/usr/bin/env python3
"""Low-authority observations from passive public-intelligence providers."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .common import BaseParser, Fact, fact, tool_lower

_TOOL_NAMES = frozenset({"cve_lookup", "search_cve", "search_web", "web_search"})
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class IntelligenceParser(BaseParser):
    """Record references without promoting search text to a vulnerability."""

    family = "intelligence"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        identity = tool_lower(tool_name).split(maxsplit=1)[0]
        if identity not in _TOOL_NAMES:
            return []

        facts: list[Fact] = []
        seen_urls = set()
        for match in _URL.finditer(raw_output or ""):
            candidate = match.group(0).rstrip(".,;:!?)]}")
            try:
                parsed = urlsplit(candidate)
                valid = parsed.scheme.casefold() in {"http", "https"} and bool(parsed.hostname)
            except ValueError:
                valid = False
            if not valid or candidate in seen_urls:
                continue
            seen_urls.add(candidate)
            facts.append(fact("external_reference", candidate, 45, session_id))
            if len(seen_urls) >= 50:
                break

        seen_cves = set()
        for match in _CVE.finditer(raw_output or ""):
            cve_id = match.group(0).upper()
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            facts.append(fact("external_cve_reference", cve_id, 50, session_id))
            if len(seen_cves) >= 50:
                break
        return facts


__all__ = ["IntelligenceParser"]
