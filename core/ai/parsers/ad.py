#!/usr/bin/env python3

import re

from .common import BaseParser, Fact, fact, tool_lower


class ADParser(BaseParser):
    family = "ad"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        if not any(marker in tool_lower(tool_name) for marker in ("ad_", "bloodhound", "gpo", "adcs", "kerberoast", "asrep")):
            return []
        facts: list[Fact] = []
        for match in re.finditer(r"\b(?:Domain Name|Domain|Workgroup)\s*[:=]\s*([A-Za-z0-9._-]{2,})", raw_output or "", re.IGNORECASE):
            domain = match.group(1).strip(".")
            if domain.lower() not in {"unknown", "none", "workgroup"}:
                facts.append(fact("ad_domain", domain[:120], 80, session_id))
        for match in re.finditer(r"(?im)\b(ESC\d+)\b[:\s-]+(.+)$", raw_output or ""):
            facts.append(fact("ad_adcs_issue", f"{match.group(1).upper()}:{match.group(2).strip()[:220]}", 85, session_id))
        for match in re.finditer(r"(?im)^(?:Shortest paths to Domain Admins|Attack paths):\s*(\d+)", raw_output or ""):
            facts.append(fact("ad_attack_path", f"domain_admin_paths:{match.group(1)}", 85, session_id))
        for match in re.finditer(r"(?im)^Local admin paths?:\s*(\d+)", raw_output or ""):
            facts.append(fact("ad_local_admin_path", f"count:{match.group(1)}", 85, session_id))
        for match in re.finditer(r"(?im)^High Value Targets:\s*(\d+)", raw_output or ""):
            facts.append(fact("ad_high_value_object", f"count:{match.group(1)}", 85, session_id))
        for match in re.finditer(r"(?im)^User:\s*(.+)$", raw_output or ""):
            value = match.group(1).strip()
            if value:
                facts.append(fact("ad_object", value[:180], 75, session_id))
        for match in re.finditer(r"(?im)^BloodHound data collected\s*->\s*(\S+)", raw_output or ""):
            facts.append(fact("ad_graph_data", match.group(1).strip(), 90, session_id))
        for key, pattern in (
            ("min_length", r"(?im)^Minimum password length:\s*(\d+)"),
            ("history_length", r"(?im)^Password history length:\s*(\d+)"),
            ("max_age_days", r"(?im)^Maximum password age(?: \(days\))?:\s*(\d+)"),
            ("lockout_threshold", r"(?im)^Lockout threshold:\s*(\d+)"),
        ):
            for match in re.finditer(pattern, raw_output or ""):
                facts.append(fact("ad_password_policy", f"{key}:{match.group(1)}", 85, session_id))
                if key == "min_length" and int(match.group(1)) < 12:
                    facts.append(fact("ad_gpo_issue", f"weak_password_min_length:{match.group(1)}", 75, session_id))
                if key == "lockout_threshold" and int(match.group(1)) == 0:
                    facts.append(fact("ad_gpo_issue", "account_lockout_disabled", 75, session_id))
        for match in re.finditer(r"(?im)^(?:Delegation|Unconstrained delegation|Constrained delegation|RBCD|Resource-Based Constrained Delegation):\s*(.+)$", raw_output or ""):
            value = re.sub(r"\s+", " ", match.group(1)).strip()
            if value:
                facts.append(fact("ad_delegation", value[:260], 85, session_id))
                if "unconstrained delegation" in match.group(0).lower():
                    facts.append(fact("ad_delegation", "unconstrained_delegation_present", 85, session_id))
        for match in re.finditer(r"(?im)^GPO issue:\s*(.+)$", raw_output or ""):
            facts.append(fact("ad_gpo_issue", match.group(1).strip()[:260], 80, session_id))
        for match in re.finditer(r"(?im)\b(GenericAll|GenericWrite|WriteDacl|WriteOwner|AddMember|DCSync|AllExtendedRights)\b.*?(?:->|on|to)\s*([A-Za-z0-9_.@\\/-]{2,180})", raw_output or ""):
            facts.append(fact("ad_acl_issue", f"{match.group(1)}:{match.group(2)}", 80, session_id))
        return facts
