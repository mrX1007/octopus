#!/usr/bin/env python3

import re

# ANSI Colors
C_GREY   = "[90m"
C_RESET  = "[0m"
C_CYAN   = "[96m"
C_GREEN  = "[92m"
C_YELLOW = "[93m"
C_RED    = "[91m"
C_BLUE   = "[94m"
C_MAGENTA = "[95m"

# ─────────────────────────────────────────────
# PARSERS
# ─────────────────────────────────────────────

def _strip_markdown(text: str) -> str:
    """Strip markdown formatting (**, *, `) from parsed names."""
    return text.replace('**', '').replace('*', '').replace('`', '').strip()


# ─────────────────────────────────────────────
# EVIDENCE-FIRST VULNERABILITY BUILDER (v5.0)
# ─────────────────────────────────────────────

def build_vulns_from_facts(accumulated_facts: list) -> list:
    """
    Build CONFIRMED vulnerabilities from concrete facts.
    This is the ONLY way to create CONFIRMED vulns — LLM text cannot.
    
    Args:
        accumulated_facts: list of (fact_text, source_tool) tuples
    Returns:
        list of vuln dicts with confidence=CONFIRMED and evidence fields
    """
    vulns = []
    seen = set()

    for fact_text, source in accumulated_facts:
        ft_lower = fact_text.lower()

        # ── CREDENTIALS FOUND ────────────────────────────────
        if "credentials found:" in ft_lower and ":" in fact_text:
            # Extract user:pass from fact
            cred_part = fact_text.split("CREDENTIALS FOUND:")[-1].strip()
            # Handle formats: "user:pass", "ssh://user:pass on port 22"
            cred_clean = cred_part.split(" on ")[0].replace("ssh://", "").replace("ftp://", "")
            if ":" in cred_clean:
                user, pwd = cred_clean.split(":", 1)
                vuln_key = f"weak_creds_{user}"
                if vuln_key not in seen:
                    seen.add(vuln_key)
                    vulns.append({
                        "vuln_name": f"Weak Credentials ({user})",
                        "severity": "critical",
                        "confidence": "CONFIRMED",
                        "port": "22",
                        "service": "SSH",
                        "description": f"Valid credentials discovered via {source}: {user}:{pwd}",
                        "evidence_tool": source,
                        "evidence_snippet": fact_text,
                        "repro_cmd": f"ssh {user}@TARGET",
                        "fix": "Enforce strong password policy, disable password authentication in SSH",
                    })

        # ── DEFAULT CREDENTIALS ──────────────────────────────
        elif "default credentials confirmed" in ft_lower:
            vuln_key = "default_creds"
            if vuln_key not in seen:
                seen.add(vuln_key)
                vulns.append({
                    "vuln_name": "Default Credentials",
                    "severity": "critical",
                    "confidence": "CONFIRMED",
                    "port": "",
                    "service": "",
                    "description": f"Default credentials work — confirmed by {source}",
                    "evidence_tool": source,
                    "evidence_snippet": fact_text,
                    "repro_cmd": "Use default credentials to authenticate",
                    "fix": "Change default credentials immediately",
                })

        # ── NOPASSWD SUDO ────────────────────────────────────
        elif "nopasswd sudo" in ft_lower:
            vuln_key = "nopasswd_sudo"
            if vuln_key not in seen:
                seen.add(vuln_key)
                vulns.append({
                    "vuln_name": "NOPASSWD Sudo Privilege Escalation",
                    "severity": "high",
                    "confidence": "CONFIRMED",
                    "port": "22",
                    "service": "SSH",
                    "description": f"NOPASSWD sudo entries found — confirmed by {source}",
                    "evidence_tool": source,
                    "evidence_snippet": fact_text,
                    "repro_cmd": "sudo -l # check for NOPASSWD entries",
                    "fix": "Remove NOPASSWD from sudoers entries",
                })

        # ── EXPLOITABLE SUID ─────────────────────────────────
        elif "exploitable suid" in ft_lower:
            vuln_key = "suid_exploit"
            if vuln_key not in seen:
                seen.add(vuln_key)
                vulns.append({
                    "vuln_name": "Exploitable SUID Binaries",
                    "severity": "high",
                    "confidence": "CONFIRMED",
                    "port": "22",
                    "service": "SSH",
                    "description": f"Exploitable SUID binaries found — confirmed by {source}",
                    "evidence_tool": source,
                    "evidence_snippet": fact_text,
                    "repro_cmd": "find / -perm -4000 -type f 2>/dev/null",
                    "fix": "Remove unnecessary SUID bits",
                })

        # ── TARGET IS ROOTED ─────────────────────────────────
        elif "target is rooted" in ft_lower:
            vuln_key = "rooted"
            if vuln_key not in seen:
                seen.add(vuln_key)
                vulns.append({
                    "vuln_name": "Root Access Achieved",
                    "severity": "critical",
                    "confidence": "CONFIRMED",
                    "port": "22",
                    "service": "SSH",
                    "description": f"Full root access obtained — confirmed by {source}",
                    "evidence_tool": source,
                    "evidence_snippet": fact_text,
                    "repro_cmd": "id  # should show uid=0(root)",
                    "fix": "Full security audit required — system compromised",
                })

        # ── PORT OPEN (info-level) ───────────────────────────
        elif fact_text.startswith("Port ") and "OPEN" in fact_text:
            port_match = re.match(r'Port (\d+) OPEN \((\S+)\)', fact_text)
            if port_match:
                port, service = port_match.groups()
                vuln_key = f"open_port_{port}"
                if vuln_key not in seen:
                    seen.add(vuln_key)
                    vulns.append({
                        "vuln_name": f"Open Port {port} ({service})",
                        "severity": "info",
                        "confidence": "CONFIRMED",
                        "port": port,
                        "service": service,
                        "description": f"Port {port} is open running {service} — confirmed by {source}",
                        "evidence_tool": source,
                        "evidence_snippet": fact_text,
                        "repro_cmd": f"nmap -sV -p{port} TARGET",
                        "fix": "Review if this service needs to be exposed",
                    })

        # ── WEB APP DETECTED (with HTTP evidence) ────────────
        elif "detected" in ft_lower and any(kw in ft_lower for kw in [
            "wordpress", "gitlab", "tomcat", "jenkins", "zabbix",
            "phpmyadmin", "grafana", "joomla", "drupal", "webmin"
        ]):
            app_name = fact_text.split(" detected")[0].strip()
            vuln_key = f"webapp_{app_name.lower()}"
            if vuln_key not in seen:
                seen.add(vuln_key)
                vulns.append({
                    "vuln_name": f"Web Application: {app_name}",
                    "severity": "medium",
                    "confidence": "CONFIRMED",
                    "port": "80",
                    "service": "HTTP",
                    "description": f"{app_name} detected via HTTP response — confirmed by {source}",
                    "evidence_tool": source,
                    "evidence_snippet": fact_text,
                    "repro_cmd": f"curl -sI http://TARGET | grep -i '{app_name.split()[0].lower()}'",
                    "fix": f"Keep {app_name} updated, restrict access",
                })

        # ── SSH POST-EXPLOITATION ────────────────────────────
        elif "ssh post-exploitation" in ft_lower:
            vuln_key = "ssh_postexploit"
            if vuln_key not in seen:
                seen.add(vuln_key)
                vulns.append({
                    "vuln_name": "SSH Post-Exploitation Access",
                    "severity": "high",
                    "confidence": "CONFIRMED",
                    "port": "22",
                    "service": "SSH",
                    "description": f"Post-exploitation completed via SSH — {source}",
                    "evidence_tool": source,
                    "evidence_snippet": fact_text,
                    "repro_cmd": "ssh user@TARGET",
                    "fix": "Rotate SSH credentials, audit authorized_keys",
                })

        # ── VERSION INFO (possible, not confirmed exploit) ───
        elif "version:" in ft_lower and "port" in ft_lower:
            vuln_key = f"version_{fact_text[:40]}"
            if vuln_key not in seen:
                seen.add(vuln_key)
                vulns.append({
                    "vuln_name": f"Version Disclosure: {fact_text[:60]}",
                    "severity": "low",
                    "confidence": "POSSIBLE",
                    "port": "",
                    "service": "",
                    "description": fact_text,
                    "evidence_tool": source,
                    "evidence_snippet": fact_text,
                    "repro_cmd": "nmap -sV TARGET",
                    "fix": "Update services to latest versions, hide version banners",
                })

    return vulns


def parse_vulnerabilities(response: str, accumulated_facts: list = None) -> list:
    """Parse vulns from AI response. v4.2: adds confidence classification."""
    vulns = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # ── Format 1: Pipe-delimited (VULN: name | SEVERITY: level | ...) ──
        if line.startswith("VULN:"):
            vuln = {"vuln_name": "", "severity": "medium", "port": "", "service": "", "description": "", "fix": ""}
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"): vuln["vuln_name"] = _strip_markdown(part.replace("VULN:", ""))
                elif part.startswith("SEVERITY:"): vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("PORT:"): vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"): vuln["service"] = _strip_markdown(part.replace("SERVICE:", ""))
            j = i + 1
            while j < len(lines) and j <= i + 5:
                next_line = lines[j].strip()
                if next_line.startswith("VULN:") or next_line.startswith("EXPLOIT:"):
                    break
                if next_line.startswith("DESC:"): vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"): vuln["fix"] = next_line.replace("FIX:", "").strip()
                elif next_line.startswith("RESULT:"): vuln["_result"] = next_line.replace("RESULT:", "").strip()
                j += 1
            if vuln["vuln_name"]:
                vulns.append(vuln)

        # ── Format 2: Block format ([ VULN ] followed by Name:, Severity:, etc.) ──
        elif line in ("[ VULN ]", "[VULN]", "**VULN**", "VULN"):
            vuln = {"vuln_name": "", "severity": "medium", "port": "", "service": "", "description": "", "fix": ""}
            j = i + 1
            while j < len(lines) and j <= i + 15:
                nl = lines[j].strip()
                if not nl or nl.startswith("===") or nl.startswith("---"):
                    j += 1
                    continue
                if nl in ("[ VULN ]", "[VULN]", "[ EXPLOIT ]", "[EXPLOIT]", "VULN:", "EXPLOIT:"):
                    break
                nl_lower = nl.lower()
                # Match "Name : value" or "Name: value" patterns
                kv = re.match(r'^[\*\-\s]*(\w[\w\s]*?)\s*:\s*(.+)$', nl)
                if kv:
                    key = kv.group(1).strip().lower()
                    val = _strip_markdown(kv.group(2).strip())
                    if key in ("name", "vuln_name", "vulnerability"):
                        vuln["vuln_name"] = val
                    elif key in ("severity", "risk", "level"):
                        vuln["severity"] = val.lower()
                    elif key in ("port", "ports"):
                        vuln["port"] = val
                    elif key in ("service", "protocol"):
                        vuln["service"] = val
                    elif key in ("description", "desc", "details", "info"):
                        vuln["description"] = val
                    elif key in ("fix", "remediation", "recommendation", "mitigation"):
                        vuln["fix"] = val
                j += 1
            if vuln["vuln_name"]:
                vulns.append(vuln)
                i = j - 1  # Skip parsed lines

        i += 1

    # ── v4.2: CONFIDENCE CLASSIFICATION ──────────────────────────
    # Determine confidence based on actual evidence, not AI claims
    filtered_ports = set()
    if accumulated_facts:
        for f in accumulated_facts:
            f_text = f[0] if isinstance(f, tuple) else f
            m = re.search(r'Port (\d+) FILTERED', f_text)
            if m:
                filtered_ports.add(m.group(1))

    for vuln in vulns:
        desc_lower = vuln.get("description", "").lower()
        result_text = vuln.get("_result", "").lower()
        port = vuln.get("port", "")

        # v5.0: LLM-parsed vulns can NEVER be CONFIRMED.
        # Only build_vulns_from_facts() creates CONFIRMED vulns.
        # Max confidence for LLM vulns = POSSIBLE.

        # UNCONFIRMED: port is filtered/service unreachable
        if port in filtered_ports:
            vuln["confidence"] = "UNCONFIRMED"
            if vuln["severity"] in ("critical", "high"):
                vuln["severity"] = "info"
                vuln["description"] += " [DOWNGRADED: port is FILTERED, service unverified]"
        # UNCONFIRMED: description mentions partial/filtered/unreachable
        elif any(kw in desc_lower for kw in ["filtered", "partial", "unreachable",
                                              "unverified", "potential"]):
            vuln["confidence"] = "UNCONFIRMED"
            if vuln["severity"] in ("critical", "high"):
                vuln["severity"] = "info"
                vuln["description"] += " [DOWNGRADED: no tool evidence]"
        # UNCONFIRMED: hallucination markers
        elif any(kw in desc_lower for kw in ["detected", "appears", "likely",
                                              "may be", "could be", "possibly"]):
            vuln["confidence"] = "UNCONFIRMED"
        # POSSIBLE: has some tool context (version match, CVE reference)
        elif any(kw in desc_lower for kw in ["version", "cve-", "known vulnerability",
                                              "discovered via", "bruteforce"]):
            vuln["confidence"] = "POSSIBLE"
        elif any(kw in result_text for kw in ["success", "confirmed", "verified"]):
            vuln["confidence"] = "POSSIBLE"  # max for LLM, not CONFIRMED
        else:
            vuln["confidence"] = "UNCONFIRMED"

        # Clean up internal field
        vuln.pop("_result", None)

    return vulns


def parse_exploits(response: str) -> list:
    exploits = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # ── Format 1: Pipe-delimited ──
        if line.startswith("EXPLOIT:"):
            exploit = {"exploit_name": "", "tool_used": "", "payload": "", "result": "unknown", "notes": ""}
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"): exploit["exploit_name"] = _strip_markdown(part.replace("EXPLOIT:", ""))
                elif part.startswith("TOOL:"): exploit["tool_used"] = _strip_markdown(part.replace("TOOL:", ""))
                elif part.startswith("PAYLOAD:"): exploit["payload"] = part.replace("PAYLOAD:", "").strip()
            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = lines[j].strip()
                if next_line.startswith("VULN:") or next_line.startswith("EXPLOIT:"):
                    break
                if next_line.startswith("RESULT:"): exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"): exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1
            if exploit["exploit_name"]:
                exploits.append(exploit)

        # ── Format 2: Block format ──
        elif line in ("[ EXPLOIT ]", "[EXPLOIT]", "**EXPLOIT**", "EXPLOIT"):
            exploit = {"exploit_name": "", "tool_used": "", "payload": "", "result": "unknown", "notes": ""}
            j = i + 1
            while j < len(lines) and j <= i + 15:
                nl = lines[j].strip()
                if not nl or nl.startswith("===") or nl.startswith("---"):
                    j += 1
                    continue
                if nl in ("[ VULN ]", "[VULN]", "[ EXPLOIT ]", "[EXPLOIT]", "VULN:", "EXPLOIT:", "RISK_LEVEL:", "[ RISK_LEVEL ]"):
                    break
                kv = re.match(r'^[\*\-\s]*(\w[\w\s]*?)\s*:\s*(.+)$', nl)
                if kv:
                    key = kv.group(1).strip().lower()
                    val = _strip_markdown(kv.group(2).strip())
                    if key in ("name", "exploit_name", "exploit"):
                        exploit["exploit_name"] = val
                    elif key in ("tool", "tool used", "tool_used"):
                        exploit["tool_used"] = val
                    elif key in ("payload", "command"):
                        exploit["payload"] = val
                    elif key in ("result", "status", "outcome"):
                        exploit["result"] = val
                    elif key in ("notes", "details", "info"):
                        exploit["notes"] = val
                j += 1
            if exploit["exploit_name"]:
                exploits.append(exploit)
                i = j - 1

        i += 1
    return exploits


def parse_risk_level(response: str) -> str:
    # Format 1: RISK_LEVEL: CRITICAL
    match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    # Format 2: [ RISK_LEVEL ] followed by Assessment: MEDIUM
    match2 = re.search(r'\[\s*RISK_LEVEL\s*\].*?(?:Assessment|Level|Rating|Risk)\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE | re.DOTALL)
    if match2:
        return match2.group(1).upper()
    # Format 3: Standalone "Overall Risk: HIGH" or "Risk Level: MEDIUM"
    match3 = re.search(r'(?:overall\s+)?risk\s*(?:level|rating|assessment)?\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    if match3:
        return match3.group(1).upper()
    return "UNKNOWN"


def parse_summary(response: str) -> str:
    # Format 1: SUMMARY: text
    match = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    # Format 2: [ SUMMARY ] followed by text
    match2 = re.search(r'\[\s*SUMMARY\s*\]\s*\n\s*=*\s*\n?\s*(.+)', response, re.IGNORECASE)
    if match2:
        return match2.group(1).strip()
    return response[:500]

