#!/usr/bin/env python3

import re
from typing import List

from .common import BaseParser, Fact, fact, tool_lower


class APIParser(BaseParser):
    family = "api"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Fact]:
        tool = tool_lower(tool_name)
        raw = raw_output or ""
        facts: List[Fact] = []
        if "openapi_import" in tool:
            for match in re.finditer(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+auth=(\S+)", raw, re.MULTILINE):
                method, path, auth = match.groups()
                facts.append(fact("api_endpoint", f"{method}:{path}:auth={auth}", 90, session_id))
                if auth == "unknown_or_none":
                    facts.append(fact("api_security_note", f"auth_unknown_or_none:{method}:{path}", 75, session_id))
                if re.search(r"\b(?:id|user|account|tenant|order|invoice|customer)[_-]?(?:id)?\b", path, re.IGNORECASE) or re.search(r"\{[^}]*id[^}]*\}", path, re.IGNORECASE):
                    facts.append(fact("api_security_note", f"idor_candidate:{method}:{path}", 65, session_id))
                if method in {"PUT", "PATCH", "POST"} and auth == "unknown_or_none":
                    facts.append(fact("api_security_note", f"mass_assignment_candidate:{method}:{path}", 60, session_id))
        if "graphql" in tool and ("__schema" in raw or "queryType" in raw):
            facts.append(fact("api_endpoint", "POST:/graphql:graphql", 85, session_id))
            facts.append(fact("api_security_note", "graphql_introspection_enabled", 85, session_id))
        if "api_auth_check" in tool or "[api auth check" in raw.lower():
            if "NOTE possible_missing_auth" in raw:
                facts.append(fact("api_security_note", "possible_missing_auth", 80, session_id))
            if "NOTE anonymous_accessible" in raw:
                facts.append(fact("api_security_note", "anonymous_accessible", 75, session_id))
            if "NOTE auth_required" in raw:
                facts.append(fact("api_security_note", "auth_required", 85, session_id))
        return facts
