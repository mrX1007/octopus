#!/usr/bin/env python3

import re

from .common import BaseParser, Fact, fact, raw_lower, tool_lower


class MSFParser(BaseParser):
    family = "msf"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        tool = tool_lower(tool_name)
        raw = raw_lower(raw_output)
        if "msf" not in tool and "metasploit" not in raw and "msf::" not in raw:
            return []
        module_match = (
            re.search(r"\b(?:msf_check|msf_run)\s+\S+\s+(\S+)", tool_name or "", re.IGNORECASE)
            or re.search(r"(?im)^\s*\[\*\]\s*MSF Module:\s*(\S+)\s*$", raw_output or "")
        )
        module = module_match.group(1) if module_match else "unknown"
        module_l = module.lower()
        facts: list[Fact] = []
        login_success = re.search(
            r"\[\+\]\s+([A-Za-z0-9_.:-]+):(\d{1,5})\s+-\s+Success:\s+'([^':\s]+):([^']+)'",
            raw_output or "",
            re.IGNORECASE,
        )
        if login_success and ("_login" in module_l or module_l.endswith("/login")):
            host, port, username, _password = login_success.groups()
            service = "ssh"
            service_match = re.search(r"/scanner/([^/]+)/", module, re.IGNORECASE)
            if service_match:
                service = service_match.group(1).lower()
            facts.extend([
                fact("service_status", f"msf_login_check_success:{module}:{port}", 95, session_id),
                fact("credential", f"{service}_login_success:{username}@{host}", 90, session_id),
                fact("service_status", "ssh_authenticated" if service == "ssh" else f"{service}_authenticated", 90, session_id),
                fact("port_open", f"{port}/tcp ({service})", 85, session_id),
            ])
            if "uid=0" in raw:
                facts.append(fact("system_access", "uid=0", 100, session_id))

        runtime_error = any(marker in raw for marker in (
            "psych/syntax_error",
            "/rubygems/errors.rb",
            "bundler/errors.rb",
            "msf unexpected error",
            "traceback",
            "stack trace",
        ))
        if runtime_error:
            facts.append(fact("service_status", f"msf_check_error:{module}", 90, session_id))
        if "optionvalidateerror" in raw or "failed to validate" in raw:
            facts.append(fact("service_status", f"msf_check_invalid_options:{module}", 95, session_id))
            return facts
        if "does not appear to be vulnerable" in raw or "not exploitable" in raw:
            facts.append(fact("service_status", f"msf_check_not_vulnerable:{module}", 90, session_id))
            return facts
        if (
            ("appears to be vulnerable" in raw or re.search(r"\bis vulnerable\b", raw))
            and not ("_login" in module_l or module_l.endswith("/login"))
        ):
            facts.append(fact("vulnerability", f"msf_check_positive:{module}", 90, session_id))
            facts.append(fact("msf_module", module, 90, session_id))
            rport_match = re.search(r"\bRPORT(?:S)?=(\d{1,5})\b", tool_name or "", re.IGNORECASE)
            if rport_match:
                facts.append(fact("vulnerability_endpoint", f"msf_check_positive:{module}:{rport_match.group(1)}", 90, session_id))
        if re.search(r"(?:meterpreter|command shell) session \d+ opened", raw_output or "", re.IGNORECASE):
            facts.append(fact("exploit_success", f"msf_session_opened:{module}", 100, session_id))
        return facts
