#!/usr/bin/env python3

import json
import re

from .common import BaseParser, Fact, fact, tool_lower


class SecretsParser(BaseParser):
    family = "secrets"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        if not any(marker in tool_lower(tool_name) for marker in ("gitleaks", "trufflehog")):
            return []
        facts: list[Fact] = []
        for line in (raw_output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            data = {}
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                except Exception:
                    data = {}
            secret_type = data.get("RuleID") or data.get("DetectorName") or data.get("SourceName") or ""
            location = data.get("File") or data.get("SourceID") or data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file") or ""
            if secret_type or location:
                verified = "validated" if data.get("Verified") is True else "unvalidated"
                facts.append(fact("secret_finding", f"{secret_type}:{location}:{verified}:rotation_required", 90 if verified == "validated" else 75, session_id))
            elif re.search(r"(?i)(api[_-]?key|secret|token|private key|password)", line):
                facts.append(fact("secret_finding", f"generic:{line[:220]}:unvalidated:rotation_required", 65, session_id))
        return facts
