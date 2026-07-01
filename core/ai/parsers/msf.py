#!/usr/bin/env python3

import re
from typing import List

from .common import BaseParser, Fact, fact, raw_lower, tool_lower


class MSFParser(BaseParser):
    family = "msf"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Fact]:
        tool = tool_lower(tool_name)
        raw = raw_lower(raw_output)
        if "msf" not in tool and "metasploit" not in raw and "msf::" not in raw:
            return []
        module_match = (
            re.search(r"\b(?:msf_check|msf_run)\s+\S+\s+(\S+)", tool_name or "", re.IGNORECASE)
            or re.search(r"(?im)^\s*\[\*\]\s*MSF Module:\s*(\S+)\s*$", raw_output or "")
        )
        module = module_match.group(1) if module_match else "unknown"
        if "optionvalidateerror" in raw or "failed to validate" in raw:
            return [fact("service_status", f"msf_check_invalid_options:{module}", 95, session_id)]
        if "does not appear to be vulnerable" in raw or "not exploitable" in raw:
            return [fact("service_status", f"msf_check_not_vulnerable:{module}", 90, session_id)]
        if "appears to be vulnerable" in raw or re.search(r"\bis vulnerable\b", raw):
            return [fact("vulnerability", f"msf_check_positive:{module}", 90, session_id)]
        return []
