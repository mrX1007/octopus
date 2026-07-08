#!/usr/bin/env python3
import re
from urllib.parse import urlparse, urlunparse

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
# SMART DEDUPLICATION (v3.0 — FUZZY MATCH)
# ─────────────────────────────────────────────

def _canonical_url_key(value: str) -> str:
    parsed = urlparse((value or "").strip().strip("'\""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return (value or "").strip().rstrip("/").lower()
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, "")).rstrip("/")


def _extract_nuclei_target(parts: list[str]) -> str:
    target_flags = {"-u", "-url", "-target"}
    value_flags = {
        "-severity", "-exclude-tags", "-tags", "-t", "-templates",
        "-timeout", "-retries", "-rl", "-rate-limit", "-c", "-bs",
        "-headless-bulk-size", "-page-timeout", "-proxy",
    }
    skip_next = False
    for idx, part in enumerate(parts[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        for flag in target_flags:
            if part.startswith(flag + "="):
                return _canonical_url_key(part.split("=", 1)[1])
        if part in target_flags and idx + 1 < len(parts):
            return _canonical_url_key(parts[idx + 1])
        if part in value_flags:
            skip_next = True
            continue
        if part.startswith("-"):
            continue
        if re.match(r"^https?://", part, re.IGNORECASE):
            return _canonical_url_key(part)
    return ""


def _normalize_for_dedup(call_type: str, cmd: str) -> str:
    """
    Normalize a command for deduplication.
    v3.2: Smart hydra dedup — all hydra commands targeting same service://IP
    collapse into one. Prevents 3 parallel hydra instances.
    """
    norm = cmd.strip()

    if call_type == "CMD":
        parts = norm.split()
        tool = parts[0].lower() if parts else ""

        if tool == "hydra":
            # Extract service://target — this is what matters for dedup
            # All hydra runs against ssh://1.2.3.4 are the same attack
            service_match = re.search(r'(ssh|ftp|http-\w+|mysql|rdp|smb|telnet)://([\d.]+)', norm)
            if service_match:
                return f"HYDRA:{service_match.group(1)}://{service_match.group(2)}"
            # Fallback: strip noise flags
            norm = re.sub(r'\s+-[vV]+\b', '', norm)
            norm = re.sub(r'\s+-S\b', '', norm)
            norm = re.sub(r'\s+-t\s+\d+', '', norm)
            norm = re.sub(r'\s+-s\s+\d+', '', norm)
            norm = norm.replace("sshs://", "ssh://")

        elif tool == "nmap":
            norm = re.sub(r'\s+-v+\b', '', norm)
            norm = re.sub(r'\s+-T\d', '', norm)
            norm = re.sub(r'\s+--open\b', '', norm)
        elif tool == "nuclei":
            target = _extract_nuclei_target(parts)
            if target:
                return f"NUCLEI:{target}"

    elif call_type == "TOOL":
        # Cross-dedup: "bruteforce ssh 1.2.3.4" matches "hydra ... ssh://1.2.3.4"
        parts = norm.split()
        if parts and parts[0].lower() in ("bruteforce", "bruteforce_ssh"):
            service = parts[1] if len(parts) > 1 else "ssh"
            target = parts[2] if len(parts) > 2 else parts[1] if len(parts) > 1 else ""
            if re.match(r'\d+\.\d+', target):
                return f"HYDRA:{service}://{target}"
        if parts and parts[0].lower() in {"nuclei", "nuclei_safe"}:
            target = _extract_nuclei_target(parts)
            if target:
                return f"NUCLEI:{target}"

    elif call_type == "MSF":
        # v4.2: MSF dedup — strip everything except module name + RHOSTS
        # So "exploit/foo | RHOSTS=X RPORT=Y PAYLOAD=Z" deduplicates with
        # "exploit/foo | RHOSTS=X" — same module, same target = same attack
        msf_module = norm.split('|')[0].strip() if '|' in norm else norm.strip()
        rhosts_match = re.search(r'RHOSTS\s*=\s*([\d.]+)', norm)
        rhosts = rhosts_match.group(1) if rhosts_match else ""
        return f"MSF:{msf_module}:{rhosts}"

    # Collapse whitespace
    norm = re.sub(r'\s+', ' ', norm).strip()
    return f"{call_type}:{norm}"


# ─────────────────────────────────────────────
# FACT EXTRACTOR (ENHANCED v3.0)
# ─────────────────────────────────────────────

def extract_facts_from_output(tool_name: str, output: str) -> list:
    """
    Parse real tool output and extract concrete intelligence facts.
    v5.0: Returns list of (fact_text, source_tool) tuples for provenance tracking.
    Facts are ONLY extracted from tool output — never from LLM text.
    """
    facts = []  # List of (fact_text, source_tool)
    # Derive source tool name from the command/tool_name
    source = tool_name.split()[0] if tool_name else "unknown"
    # Handle ToolResult objects
    if hasattr(output, 'tool_name') and hasattr(output, 'stdout'):
        source = output.tool_name or source
        output = output.stdout
    out_lower = output.lower()

    # v5.0: Helper to append facts as (text, source) tuples — with dedup
    _seen_facts = set()
    def _add(fact_text):
        if fact_text not in _seen_facts:
            _seen_facts.add(fact_text)
            facts.append((fact_text, source))

    # Nmap port facts (line-anchored to prevent cross-line mismatches)
    for match in re.finditer(r'^(\d+)/tcp\s+(open|filtered|closed)\s+(\S+)', output, re.MULTILINE):
        port, state, service = match.groups()
        if state == "open":
            _add(f"Port {port} OPEN ({service})")
        elif state == "filtered":
            _add(f"Port {port} FILTERED ({service})")
        elif state == "closed":
            _add(f"Port {port} CLOSED ({service})")

    # Nmap version facts (line-anchored, only match version info on same line)
    for match in re.finditer(r'^(\d+)/tcp\s+open\s+\S+\s+(.+?)$', output, re.MULTILINE):
        port, version_info = match.groups()
        version_clean = version_info.strip()
        # Skip if version_info looks like another port line (contains /tcp)
        if version_clean and '/tcp' not in version_clean:
            _add(f"Port {port} version: {version_clean[:80]}")

    # Nmap all-filtered detection
    if re.search(r'All \d+ scanned ports? .*(filtered|no-response)', output, re.IGNORECASE):
        _add("ALL SCANNED PORTS ARE FILTERED — host is heavily firewalled")

    # Vulnerability extraction (CVEs)
    for match in re.finditer(r'(CVE-\d{4}-\d{4,7})', output, re.IGNORECASE):
        _add(f"VULNERABILITY DETECTED: {match.group(1).upper()}")

    # Nmap host status
    if "host is up" in out_lower:
        latency_match = re.search(r'Host is up \(([^)]+)\)', output, re.IGNORECASE)
        if latency_match:
            _add(f"Host is UP (latency: {latency_match.group(1)})")

    # Server headers
    for match in re.finditer(r'(?:Server|X-Powered-By):\s*(.+)', output, re.IGNORECASE):
        _add(f"HTTP header: {match.group(0).strip()[:100]}")

    # Usernames from /etc/passwd style
    for match in re.finditer(r'^(\w+):x:(\d+):\d+:', output, re.MULTILINE):
        uname, uid = match.groups()
        if uname not in ("nobody", "daemon", "bin", "sys", "sync", "games", "man",
                          "lp", "mail", "news", "uucp", "proxy", "www-data", "backup",
                          "list", "irc", "gnats", "systemd", "messagebus", "sshd"):
            _add(f"System user found: '{uname}' (UID {uid})")

    # HTTP response codes from ffuf/dirb
    for match in re.finditer(r'\|\s*(\d{3})\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*(\S+)', output):
        code, path = match.groups()
        if code in ("200", "301", "302", "403"):
            _add(f"Web path found: {path} (HTTP {code})")

    # Hydra success
    if "[22]" in output and "login:" in out_lower:
        _add(f"SSH credentials found by Hydra: {output[output.find('[22]'):output.find('[22]')+100]}")

    # Generic hydra success pattern
    for match in re.finditer(r'\[(\d+)\]\[(\w+)\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)', output):
        port, svc, user, pwd = match.groups()
        _add(f"CREDENTIALS FOUND: {svc}://{user}:{pwd} on port {port}")

    # Connection failures worth noting
    if "timeout" in out_lower and ("connecting" in out_lower or "connection" in out_lower):
        _add(f"Connection timeout to target — service may be firewalled")
    if "connection refused" in out_lower:
        _add(f"Connection REFUSED — port is closed or service is down")

    # Tool failures worth noting
    if "hydra is not installed" in out_lower:
        _add("Hydra NOT available — bruteforce will fail. Skip [TOOL: bruteforce] calls.")
    if "ffuf is not installed" in out_lower:
        _add("ffuf NOT available — use [CMD: gobuster] or curl instead")
    if "msfconsole is not installed" in out_lower:
        _add("Metasploit NOT available — skip [MSF:] tags, use manual exploits")
    if "searchsploit is not installed" in out_lower or "not in PATH" in out_lower:
        _add("searchsploit NOT available — use [SEARCH:] instead for exploit lookup")

    # SMB enumeration
    if "NT_STATUS_HOST_UNREACHABLE" in output:
        _add("SMB is UNREACHABLE (NT_STATUS_HOST_UNREACHABLE)")
    if "NT_STATUS_CONNECTION_REFUSED" in output:
        _add("SMB connection REFUSED")
    if "NT_STATUS_ACCESS_DENIED" in output:
        _add("SMB access DENIED (auth required)")

    # Web availability
    if "seems to be down" in out_lower or "unable to connect" in out_lower:
        _add("Web service appears DOWN or unreachable")
    if "no route to host" in out_lower:
        _add("No route to host — network unreachable")
    # SSH user enumeration results
    # v4.2: Restrict to SSH enum context to prevent false positives from killchain output
    _SSH_USER_BLACKLIST = {
        'ssh', 'crontab', 'suid', 'sgid', 'docker', 'kernel', 'system',
        'network', 'listening', 'active', 'running', 'installed', 'web',
        'database', 'environment', 'history', 'interesting', 'shadow',
        'sudo', 'home', 'writable', 'user', 'hostname', 'os', 'info',
        '.bashrc', '.bash_history', '.ssh', '.profile', 'authorized_keys',
    }
    is_ssh_enum_output = any(kw in out_lower for kw in [
        'ssh user enum', 'cve-2018-15473', 'ssh_user_enum', 'user enumeration',
        'valid user', 'openssh'
    ])
    for match in re.finditer(r'VALID USER:\s*(\S+)', output):
        uname = match.group(1).strip('.,;:()[]')
        if uname.lower() not in _SSH_USER_BLACKLIST and len(uname) >= 2 and uname[0].isalpha():
            _add(f"SSH valid user confirmed: '{uname}'")
    # Also catch the formatted output from our ssh_user_enum tool
    # But ONLY in SSH enumeration context (not killchain ✓ marks)
    if is_ssh_enum_output:
        for match in re.finditer(r'\u2713\s+(\S+)', output):
            username = match.group(1).strip('.,;:()[]')
            if (username and len(username) < 32 and len(username) >= 2
                    and username.lower() not in _SSH_USER_BLACKLIST
                    and username[0].isalpha()):
                fact = f"SSH valid user confirmed: '{username}'"
                _add(fact)
    if "confirmed valid users" in out_lower:
        _add("SSH user enumeration completed — valid users found")

    # ── WEB APPLICATION DETECTION (v4.2 — evidence-based) ──────────
    # v4.2: ONLY detect web apps when there is REAL HTTP evidence.
    # The output must contain actual HTTP signatures (status codes, HTML,
    # tool output headers) — NOT just AI-generated text mentioning app names.
    _HTTP_EVIDENCE_MARKERS = [
        'http/', '200 ok', '301 moved', '302 found', '403 forbidden',
        '404 not found', '<html', '<body', '<head', '<title',
        'content-type:', 'server:', 'x-powered-by:',
        '[ whatweb', '[ nikto', '[ scrapling', '[ ffuf',
        'nikto_', 'wpscan', 'gobuster',
        'status_code', 'response_code',
    ]
    has_http_evidence = any(marker in out_lower for marker in _HTTP_EVIDENCE_MARKERS)

    if has_http_evidence:
        web_apps = {
            "zabbix": "Zabbix web interface detected",
            "phpmyadmin": "phpMyAdmin detected",
            "grafana": "Grafana dashboard detected",
            "jenkins": "Jenkins CI detected",
            "wordpress": "WordPress CMS detected",
            "wp-login": "WordPress CMS detected",
            "joomla": "Joomla CMS detected",
            "drupal": "Drupal CMS detected",
            "tomcat": "Apache Tomcat detected",
            "webmin": "Webmin panel detected",
            "nagios": "Nagios monitoring detected",
            "kibana": "Kibana dashboard detected",
            "swagger": "Swagger API documentation detected",
            "netdata": "Netdata monitoring detected",
            "gitlab": "GitLab instance detected",
            "roundcube": "Roundcube webmail detected",
            "cpanel": "cPanel detected",
            "plesk": "Plesk panel detected",
            "cockpit": "Cockpit web console detected",
        }
        for keyword, fact_text in web_apps.items():
            if keyword in out_lower:
                _add(fact_text)
                _add(f"AI: Detected {fact_text.split(' detected')[0]} — try [TOOL: bruteforce http-post-form TARGET] and [SEARCH: {fact_text.split(' detected')[0]} CVE RCE exploit]")

        # Login form detection — also requires HTTP evidence
        if any(kw in out_lower for kw in ["login form", "password field", "forms (", "type=\"password\""]):
            _add("Login form detected on web target")
            _add("AI: Login form found — use [TOOL: bruteforce http-post-form TARGET]")

    # ── CREDENTIAL DISCOVERY (v4.2 — fixed garbage parsing) ──────
    # v4.2: Validate credentials have real alphanumeric content, not just punctuation
    def _is_valid_cred(val: str) -> bool:
        """Check if a credential value is real (not garbage like ',' or ':')."""
        val = val.strip('\'".,;:()[]{}|\\/ ')
        return (len(val) >= 2 and any(c.isalnum() for c in val)
                and val.lower() not in ('user', 'username', 'password', 'pass',
                                         'login', 'name', 'field', 'value',
                                         'none', 'null', 'n/a', 'unknown'))

    # Catch SSH credentials from any source
    for match in re.finditer(r'(?:login|user(?:name)?)[:\s]+[\'"]?(\S+?)[\'"]?\s+(?:password|pass)[:\s]+[\'"]?(\S+?)[\'"]?', output, re.IGNORECASE):
        user, pwd = match.groups()
        user = user.strip('\'".,;:()[]')
        pwd = pwd.strip('\'".,;:()[]')
        if _is_valid_cred(user) and _is_valid_cred(pwd):
            fact = f"CREDENTIALS FOUND: {user}:{pwd}"
            _add(fact)
            _add(f"AI: Credentials found! IMMEDIATELY use [TOOL: ssh_session TARGET {user} {pwd}]")

    # Catch stealth bruteforce output: [+] VALID CREDENTIALS: user:pass
    for match in re.finditer(r'\[\+\]\s*(?:FOUND\s+)?(?:VALID\s+)?CREDENTIALS?\s*(?:FOUND)?:?\s*(\S+?):(\S+)', output, re.IGNORECASE):
        user, pwd = match.groups()
        user = user.strip('\'".,;:()[]')
        pwd = pwd.strip('\'".,;:()[]')
        if _is_valid_cred(user) and _is_valid_cred(pwd) and user not in ('FOUND', 'VALID'):
            fact = f"CREDENTIALS FOUND: {user}:{pwd}"
            _add(fact)
            _add(f"AI: Credentials found! IMMEDIATELY use [TOOL: ssh_session TARGET {user} {pwd}]")

    # DEFAULT CREDS found
    if "default creds work" in out_lower or "default creds found" in out_lower:
        _add("DEFAULT CREDENTIALS CONFIRMED — exploitation possible")

    # SSH post-exploitation results
    if "post-exploitation summary" in out_lower:
        _add("SSH post-exploitation analysis completed")
        if "root" in out_lower and "uid=0" in out_lower:
            _add("TARGET IS ROOTED — we have root access")
        if "nopasswd" in out_lower:
            _add("Privilege escalation vector found: NOPASSWD sudo")
        if "exploitable suid" in out_lower:
            _add("Privilege escalation vector found: exploitable SUID binaries")

        # v5.0: Extract shadow file access
        if "shadow file readable" in out_lower or "got shadow" in out_lower:
            _add("SHADOW FILE READABLE — password hashes available for cracking")
            # Count shadow users
            shadow_count = len(re.findall(r'→\s+\S+', output[output.lower().find("shadow"):] if "shadow" in out_lower else ""))
            if shadow_count:
                _add(f"SHADOW: {shadow_count} users with crackable password hashes")

        # v5.0: Extract internal IPs (from network interfaces)
        if "internal ips:" in out_lower:
            ip_section = output[output.lower().find("internal ips:"):]
            for ipm in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', ip_section[:200]):
                ip = ipm.group(1)
                if not ip.startswith("127."):
                    _add(f"INTERNAL IP: {ip} — reachable ONLY via ssh_exec (NOT from outside)")

        # v5.0: Extract login users count
        users_match = re.search(r'Login Users:\s+(.+?)(?:\n|$)', output)
        if users_match:
            users_str = users_match.group(1).strip()
            if users_str != 'none found':
                user_list = [u.strip() for u in users_str.split(',') if u.strip()]
                _add(f"LOGIN USERS FOUND: {', '.join(user_list[:10])} — try su/ssh with known passwords")

        # v5.0: Extract internal services
        svc_match = re.search(r'Internal Services:\s+(.+?)(?:\n|$)', output)
        if svc_match:
            svc_str = svc_match.group(1).strip()
            if svc_str != 'none':
                _add(f"INTERNAL SERVICES: ports {svc_str} — access via ssh_exec ONLY")

    # Exploit attempts tracking (for anti-loop)
    if any(kw in out_lower for kw in ["exploit", "payload", "shell", "injection", "rce"]):
        if any(kw in out_lower for kw in ["success", "found", "session", "[+]"]):
            _add("EXPLOITATION SUCCESSFUL — exploit yielded results")
        elif any(kw in out_lower for kw in ["failed", "error", "not vulnerable", "[-]"]):
            _add("Exploitation attempted — no success")

    # ── KILL CHAIN STAGE TRACKING (v4.2 — evidence-based) ──────
    # v4.2: Only report stages as completed/successful when there is
    # concrete evidence in the output, not just because the function ran.
    if "kill chain" in out_lower:
        if "vulnerability assessment" in out_lower:
            # Check if any actual vulns were found
            if "exploitable" in out_lower or "Total exploitable findings:" in output:
                vuln_match = re.search(r'Total exploitable findings:\s*(\d+)', output)
                count = int(vuln_match.group(1)) if vuln_match else 0
                if count > 0:
                    _add(f"KILL CHAIN: Vulnerability assessment — {count} exploitable findings")
                else:
                    _add("KILL CHAIN: Vulnerability assessment — no exploitable findings")
            else:
                _add("KILL CHAIN: Vulnerability assessment ran (no results)")

        if "exploitation" in out_lower and "kill chain" in out_lower:
            if "session" in out_lower or "shell" in out_lower or "[+]" in output:
                _add("KILL CHAIN: Exploitation stage — results obtained")
            else:
                _add("KILL CHAIN: Exploitation attempted — no shells/sessions")

        if "privilege escalation" in out_lower:
            if "privesc successful" in out_lower or "got root" in out_lower or "already root" in out_lower:
                _add("KILL CHAIN: PRIVILEGE ESCALATION SUCCESSFUL")
            elif "escalation vectors found" in out_lower:
                vec_match = re.search(r'VECTORS FOUND:\s*(\d+)', output)
                count = int(vec_match.group(1)) if vec_match else 0
                _add(f"KILL CHAIN: Privesc — {count} vectors found")
            else:
                # Count how many checks returned data vs empty
                dash_count = output.count('\u2014') + output.count('—')
                _add(f"KILL CHAIN: Privesc — no vectors found ({dash_count} checks empty)")

        if "persistence" in out_lower:
            if "ssh key injected" in out_lower or "ssh key injection" in out_lower:
                _add("KILL CHAIN: Persistence — SSH key injected")
            if "crontab persistence" in out_lower or "crontab reverse shell" in out_lower:
                _add("KILL CHAIN: Persistence — crontab set")
            if "suid shell" in out_lower and "created" in out_lower:
                _add("KILL CHAIN: Persistence — SUID shell created")
            planted_match = re.search(r'Persistence methods planted:\s*(\d+)', output)
            if planted_match:
                count = int(planted_match.group(1))
                if count == 0:
                    _add("KILL CHAIN: Persistence — FAILED (0 methods planted)")
            elif "persistence" in out_lower and not any(kw in out_lower for kw in ['injected', 'crontab', 'suid shell']):
                _add("KILL CHAIN: Persistence stage ran (no methods confirmed)")

        if "lateral movement" in out_lower:
            compromised_match = re.search(r'Hosts compromised.*?:\s*(\d+)', output)
            if compromised_match and int(compromised_match.group(1)) > 0:
                _add(f"KILL CHAIN: Lateral movement — {compromised_match.group(1)} hosts compromised")
            else:
                _add("KILL CHAIN: Lateral movement — no hosts compromised")

        if "data exfiltration" in out_lower:
            exfil_match = re.search(r'Files exfiltrated:\s*(\d+)', output)
            if exfil_match and int(exfil_match.group(1)) > 0:
                count = int(exfil_match.group(1))
                size_match = re.search(r'Total data:\s*([\d,]+)\s*bytes', output)
                size = size_match.group(1) if size_match else '?'
                _add(f"KILL CHAIN: Data exfil — {count} files ({size} bytes)")
            elif '[+] EXFIL:' in output:
                _add("KILL CHAIN: Data exfil — files extracted")
            else:
                _add("KILL CHAIN: Data exfil — FAILED (0 files extracted)")

    # SUID shell detection
    if ".mtr_shell" in output:
        _add("PERSISTENCE: Hidden SUID shell at /usr/local/share/.mtr_shell")

    # Exfiltrated files
    if "octopus_exfil" in output:
        _add("DATA EXFIL: Files saved to /tmp/octopus_exfil_*/")

    # Lateral compromised hosts
    for match in re.finditer(r'COMPROMISED:\s*(\S+)@(\S+)', output):
        _add(f"LATERAL: Compromised {match.group(1)}@{match.group(2)}")

    # Fail2ban/rate-limit tracking
    if "fail2ban" in out_lower or "rate-limit active" in out_lower or "all retry attempts exhausted" in out_lower:
        _add("BRUTEFORCE: Target has fail2ban/rate-limiting — brute is very slow")

    # ── MSF MODULE FAILURE TRACKING (v4.2) ────────────────────
    # Prevent endless retries of non-existent modules
    for match in re.finditer(r"MSF module '([^']+)' (?:does NOT EXIST|FAILED TO LOAD)", output):
        mod_name = match.group(1)
        fact = f"MSF MODULE UNAVAILABLE: {mod_name} — do NOT retry"
        _add(fact)

    # ── KILL CHAIN DATA EXTRACTION (v4.2) ─────────────────────
    # Extract actual discovered data from kill chain output so it persists in facts

    # Users from /etc/passwd (with login shells)
    for match in re.finditer(r'^([a-z_][a-z0-9_-]{0,30}):[^:]*:[^:]*:[^:]*:[^:]*:(/[^:\n]+)$', output, re.MULTILINE):
        uname, shell = match.groups()
        if shell not in ('/usr/sbin/nologin', '/bin/false', '/sbin/nologin', ''):
            if uname not in ('root', 'daemon', 'bin', 'sys', 'sync', 'games',
                             'man', 'lp', 'mail', 'news', 'nobody'):
                fact = f"System login user: '{uname}' (shell: {shell})"
                _add(fact)

    # SUID binaries (exploitable ones)
    # v6.0: Fixed regex — old pattern matched /etc/passwd lines like
    # "root:x:0:0:root:/root:/bin/bash" as "/root:/bin/bash" (SUID: bash).
    # New pattern requires path starts with / and contains NO colons.
    _EXPLOITABLE_SUIDS = {'nmap', 'vim', 'vi', 'find', 'bash', 'sh', 'python',
                          'python3', 'perl', 'ruby', 'node', 'php', 'nano',
                          'cp', 'mv', 'pkexec', 'env', 'awk', 'strace', 'ltrace',
                          'gdb', 'docker', 'mount', 'taskset', 'wget', 'less',
                          'more', 'man', 'ed', 'emacs', 'flock', 'ionice',
                          'ip', 'nice', 'time', 'timeout', 'xargs'}
    for match in re.finditer(r'^(/[^\s:]+/([^\s/:]+))\s*$', output, re.MULTILINE):
        full_path, binary = match.groups()
        if binary.lower() in _EXPLOITABLE_SUIDS:
            fact = f"Exploitable SUID binary: {full_path}"
            _add(fact)

    # NOPASSWD sudo entries
    for match in re.finditer(r'\(.*?\)\s+NOPASSWD:\s+(.+)', output):
        fact = f"NOPASSWD sudo: {match.group(1).strip()[:100]}"
        _add(fact)

    # Internal listening services (from ss -tlnp / netstat)
    for match in re.finditer(r'(?:127\.0\.0\.1|0\.0\.0\.0|:::?)(\d{2,5})\s', output):
        port = match.group(1)
        if port not in ('22',) and int(port) > 1:
            fact = f"Internal service listening on port {port}"
            _add(fact)

    # Interesting config/backup files found
    for match in re.finditer(r'(/\S+\.(?:conf|cfg|ini|env|bak|old|sql|key|pem))\s*$', output, re.MULTILINE):
        fpath = match.group(1)
        fact = f"Interesting file found: {fpath}"
        _add(fact)

    # Docker containers running
    if 'container id' in out_lower or 'docker' in out_lower:
        for match in re.finditer(r'([a-f0-9]{12})\s+\S+\s+.*?\s+(Up\s+\S+)', output):
            fact = f"Docker container running: {match.group(1)}"
            _add(fact)

    # Passwords found in config files
    for match in re.finditer(r'(?:password|passwd|pass|pwd|secret|token|api_key)\s*[=:]\s*[\'"]?([^\s\'"]{3,50})[\'"]?', output, re.IGNORECASE):
        pwd_val = match.group(1).strip()
        # Skip common non-password values
        if pwd_val.lower() not in ('password', 'changeme', 'none', 'null', 'xxx',
                                     '*', '!', 'disabled', 'locked'):
            fact = f"Password found in config: {pwd_val[:30]}"
            _add(fact)

    # ── v6.0: DATABASE CREDENTIALS from config file content ──────
    # Catch DB_PASSWORD, MYSQL_PASSWORD etc. from harvested config output
    _DB_PASS_PATTERN = re.compile(
        r'(?:DB_PASSWORD|DB_PASS|MYSQL_PASSWORD|MYSQL_ROOT_PASSWORD)\s*[=:]\s*[\'"]?([^\s\'"#;]{3,80})',
        re.IGNORECASE
    )
    _DB_USER_PATTERN = re.compile(
        r'(?:DB_USER|DB_USERNAME|MYSQL_USER)\s*[=:]\s*[\'"]?([^\s\'"#;]{2,50})',
        re.IGNORECASE
    )
    db_passwords = []
    db_users = []
    for m in _DB_PASS_PATTERN.finditer(output):
        val = m.group(1).strip("'\"")
        if val.lower() not in ('password', 'changeme', 'none', 'null', 'xxx', 'secret',
                                'your_password', 'root', 'example', 'pass', ''):
            db_passwords.append(val)
            _add(f"DB PASSWORD FOUND: {val[:40]}")
    for m in _DB_USER_PATTERN.finditer(output):
        val = m.group(1).strip("'\"")
        if val.lower() not in ('user', 'username', 'root', 'none', 'null', ''):
            db_users.append(val)
            _add(f"DB USER FOUND: {val}")

    # If we found DB creds, generate actionable AI hint
    if db_passwords:
        db_u = db_users[0] if db_users else 'root'
        db_p = db_passwords[0]
        _add(f"AI: Database credentials found ({db_u}:{db_p})! "
             f"Try: [TOOL: ssh_exec HOST USER PASS 'mysql -u {db_u} -p{db_p} -e \"SHOW DATABASES\"']")

    # ── v6.0: API/SECRET KEY extraction ──────────────────────────
    for m in re.finditer(
        r'(?:API_KEY|SECRET_KEY|APP_SECRET|JWT_SECRET|APP_KEY)\s*[=:]\s*[\'"]?([^\s\'"#;]{8,120})',
        output, re.IGNORECASE
    ):
        val = m.group(1).strip("'\"")
        if val.lower() not in ('your_secret_key', 'changeme', 'secret', 'example'):
            _add(f"SECRET KEY FOUND: {val[:50]}")

    # ── v6.0: Register discovered credentials in the cache ───────
    # This ensures bruteforce is skipped for targets with known creds
    if db_passwords:
        try:
            from tools import register_credential
            db_u = db_users[0] if db_users else 'root'
            register_credential('mysql', 'localhost', db_u, db_passwords[0])
        except ImportError:
            pass

    return facts


def _extract_open_ports(accumulated_facts: list) -> set:
    """Extract set of confirmed open ports from accumulated facts.
    v5.0: handles (text, source) tuples."""
    open_ports = set()
    for fact in accumulated_facts:
        fact_text = fact[0] if isinstance(fact, tuple) else fact
        match = re.match(r'Port (\d+) OPEN', fact_text)
        if match:
            open_ports.add(int(match.group(1)))
    return open_ports


def _extract_filtered_ports(accumulated_facts: list) -> set:
    """Extract set of confirmed filtered ports from accumulated facts.
    v5.0: handles (text, source) tuples."""
    filtered = set()
    for fact in accumulated_facts:
        fact_text = fact[0] if isinstance(fact, tuple) else fact
        match = re.match(r'Port (\d+) FILTERED', fact_text)
        if match:
            filtered.add(int(match.group(1)))
    return filtered


def _is_all_filtered(accumulated_facts: list) -> bool:
    """Check if all ports are filtered (heavily firewalled target).
    v5.0: handles (text, source) tuples."""
    for fact in accumulated_facts:
        fact_text = fact[0] if isinstance(fact, tuple) else fact
        if "ALL SCANNED PORTS ARE FILTERED" in fact_text:
            return True
    open_ports = _extract_open_ports(accumulated_facts)
    filtered_ports = _extract_filtered_ports(accumulated_facts)
    # If we've scanned and found only filtered, no open
    if filtered_ports and not open_ports:
        return True
    return False


def _port_is_accessible(cmd: str, accumulated_facts: list) -> bool:
    """
    Check if the target port in a command is known to be open.
    Returns True if port is open or unknown (give benefit of the doubt).
    Returns False if port is confirmed FILTERED or CLOSED.
    """
    open_ports = _extract_open_ports(accumulated_facts)
    filtered_ports = _extract_filtered_ports(accumulated_facts)

    # If we have no port data yet, allow the command
    if not open_ports and not filtered_ports:
        return True

    # Extract port from common command patterns
    # hydra ssh://IP → port 22
    # hydra ftp://IP → port 21
    # telnet IP PORT → explicit port
    # curl http://IP → port 80
    # curl https://IP → port 443
    parts = cmd.lower().split()

    service_ports = {
        "ssh": 22, "ftp": 21, "http": 80, "https": 443,
        "smb": 445, "mysql": 3306, "rdp": 3389, "smtp": 25
    }

    # Check for explicit port in URL patterns
    for part in parts:
        for svc, port in service_ports.items():
            if f"{svc}://" in part:
                if port in filtered_ports and port not in open_ports:
                    return False
                return True

    # Telnet/ssh/ftp with explicit port
    if parts and parts[0] in ("telnet", "ssh", "ftp"):
        # Check if target has any accessible ports
        for part in parts[1:]:
            if part.isdigit():
                port = int(part)
                if port in filtered_ports and port not in open_ports:
                    return False

    # curl/wget to http/https
    for part in parts:
        if part.startswith("http://"):
            if 80 in filtered_ports and 80 not in open_ports:
                return False
        elif part.startswith("https://"):
            if 443 in filtered_ports and 443 not in open_ports:
                return False

    return True  # Default: allow
