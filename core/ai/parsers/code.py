#!/usr/bin/env python3

import json

from .common import BaseParser, Fact, fact, tool_lower


class CodeParser(BaseParser):
    family = "code"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        if not any(marker in tool_lower(tool_name) for marker in ("semgrep", "trivy", "checkov")):
            return []
        facts: list[Fact] = []
        for line in (raw_output or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            for result in data.get("results", [])[:500] if isinstance(data.get("results"), list) else []:
                check_id = result.get("check_id") or result.get("rule_id") or "semgrep"
                path = result.get("path") or result.get("extra", {}).get("path") or ""
                severity = str(result.get("extra", {}).get("severity") or result.get("severity") or "info").lower()
                facts.append(fact("code_finding", f"{severity}:{check_id}:{path}", 85, session_id))
            for result_group in data.get("Results", [])[:50]:
                target = result_group.get("Target", "")
                for vuln in result_group.get("Vulnerabilities", [])[:500]:
                    facts.append(fact("code_finding", f"{str(vuln.get('Severity', 'UNKNOWN')).lower()}:{vuln.get('VulnerabilityID')}:{target}", 85, session_id))
                for misconf in result_group.get("Misconfigurations", [])[:500]:
                    facts.append(fact("code_finding", f"{str(misconf.get('Severity', 'UNKNOWN')).lower()}:{misconf.get('ID')}:{target}", 85, session_id))
                for secret in result_group.get("Secrets", [])[:500]:
                    facts.append(fact("secret_finding", f"{secret.get('RuleID', 'trivy_secret')}:{target}:unvalidated:rotation_required", 80, session_id))
            failed_checks = data.get("results", {}).get("failed_checks", []) if isinstance(data.get("results"), dict) else []
            for failed in failed_checks[:500]:
                check_id = failed.get("check_id") or failed.get("bc_check_id") or "checkov"
                file_path = failed.get("file_path") or failed.get("file_abs_path") or ""
                severity = str(failed.get("severity") or "info").lower()
                facts.append(fact("code_finding", f"{severity}:{check_id}:{file_path}", 85, session_id))
        return facts
