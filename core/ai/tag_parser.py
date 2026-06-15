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
# TAG EXTRACTION
# ─────────────────────────────────────────────

def extract_tags(response: str) -> list:
    """
    Extract [TOOL:], [CMD:], [SEARCH:], [SEARCHSPLOIT:], [MSF:], [ASK:] tags.
    CRITICAL: Strip <thought> blocks first to avoid extracting tags from reasoning text.
    v3.1: If no tags found, fallback to parsing commands from markdown tables,
    bullet points, and other formats the AI sometimes uses instead of proper tags.
    """
    # Remove <thought>...</thought> blocks
    clean = re.sub(r'<thought>.*?</thought>', '', response, flags=re.DOTALL)

    calls = []
    for match in re.findall(r'\[TOOL:\s*(.+?)\]', clean):
        calls.append(("TOOL", match.strip()))
    for match in re.findall(r'\[CMD:\s*(.+?)\]', clean):
        calls.append(("CMD", match.strip()))
    for match in re.findall(r'\[SEARCH:\s*(.+?)\]', clean):
        calls.append(("SEARCH", match.strip()))
    for match in re.findall(r'\[SEARCHSPLOIT:\s*(.+?)\]', clean):
        calls.append(("SEARCHSPLOIT", match.strip()))
    for match in re.findall(r'\[MSF:\s*(.+?)\]', clean):
        calls.append(("MSF", match.strip()))
    for match in re.findall(r'\[ASK:\s*(.+?)\]', clean):
        calls.append(("ASK", match.strip()))

    # ── FALLBACK #1: XML <tool_request> FORMAT ────────────────────────
    if not calls:
        calls = _parse_xml_tool_requests(clean)
        if calls:
            print(f"\n{C_YELLOW}  [!] AI used XML format. Extracted {len(calls)} commands from <tool_request> tags.{C_RESET}")

    # ── FALLBACK #2: MARKDOWN "Parameters:" SECTIONS ─────────────────
    # AI writes: **1. NMAP** ... **Parameters:** `-sC -sV -p- IP`
    if not calls:
        calls = _parse_markdown_parameters(clean)
        if calls:
            print(f"\n{C_YELLOW}  [!] AI used markdown Parameters format. Extracted {len(calls)} commands.{C_RESET}")

    # ── FALLBACK #3: COMMAND PATTERNS IN PROSE ───────────────────────
    # Catches: nmap -sV ..., hydra -L ..., nikto -h ...
    if not calls:
        calls = _fallback_extract_commands(clean)
        if calls:
            print(f"\n{C_YELLOW}  [!] AI used wrong format. Extracted {len(calls)} commands via fallback parser.{C_RESET}")

    # ── v6.0: HARD CAP on tool tags per response ──────────────────────
    MAX_TOOLS_PER_RESPONSE = 15
    if len(calls) > MAX_TOOLS_PER_RESPONSE:
        print(f"\n  {C_RED}[!] AI generated {len(calls)} commands — CAPPED to {MAX_TOOLS_PER_RESPONSE} "
              f"(dropped {len(calls) - MAX_TOOLS_PER_RESPONSE} hallucinatory commands){C_RESET}")
        calls = calls[:MAX_TOOLS_PER_RESPONSE]

    # v6.0: Deduplicate identical commands
    seen_cmds = set()
    deduped = []
    for tag_type, tag_cmd in calls:
        key = (tag_type, tag_cmd.lower().strip())
        if key not in seen_cmds:
            seen_cmds.add(key)
            deduped.append((tag_type, tag_cmd))
    if len(deduped) < len(calls):
        print(f"  [~] Deduplicated {len(calls) - len(deduped)} identical commands")
    calls = deduped

    # v7.0: Anti-hallucination validation
    validated = []
    for tag_type, tag_cmd in calls:
        rejection = _validate_tool_call(tag_type, tag_cmd)
        if rejection:
            print(f"  {C_YELLOW}[REJECT] {tag_cmd[:60]} — {rejection}{C_RESET}")
        else:
            validated.append((tag_type, tag_cmd))
    if len(validated) < len(calls):
        print(f"  [~] Rejected {len(calls) - len(validated)} invalid commands")
    calls = validated

    return calls


def _validate_tool_call(tag_type: str, cmd: str) -> str:
    """v7.0: Validate a tool call before execution.
    Returns rejection reason string, or empty string if valid."""
    import re as _re

    parts = cmd.strip().split()
    if not parts:
        return "empty command"

    cmd_lower = parts[0].lower()

    # Reject internal IP targeting from external tools
    _INTERNAL_PATTERNS = [
        _re.compile(r'(?:^|\s)10\.\d+\.\d+\.\d+'),
        _re.compile(r'(?:^|\s)172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+'),
        _re.compile(r'(?:^|\s)192\.168\.\d+\.\d+'),
    ]
    _EXTERNAL_TOOLS = {"nmap", "nikto", "enum4linux", "smbclient", "hydra",
                       "wpscan", "sqlmap", "masscan", "gobuster"}
    if cmd_lower in _EXTERNAL_TOOLS:
        for pattern in _INTERNAL_PATTERNS:
            if pattern.search(cmd):
                return "cannot target internal IPs from outside — use ssh_exec"

    # Reject web tools if targeting obviously non-web services
    _WEB_TOOLS = {"scrapling", "dirb_fuzz", "wpscan", "web_brute", "web_login_brute"}
    if cmd_lower in _WEB_TOOLS:
        # These should only run if target has HTTP ports
        # We can't fully validate here without state, but catch obvious errors
        pass

    # Reject clearly hallucinated version strings in searchsploit
    if tag_type == "SEARCHSPLOIT":
        # Catch version enumeration hallucinations: "openvpn 2.4.11", "openvpn 2.4.12", etc.
        version_match = _re.search(r'(\d+\.\d+\.(\d+))', cmd)
        if version_match:
            minor = int(version_match.group(2))
            if minor > 50:  # No real software has 50+ patch versions
                return f"hallucinated version number ({version_match.group(1)})"

    # Reject format_b_final_analysis (common hallucination)
    if "format_b" in cmd_lower or "final_analysis" in cmd_lower:
        return "not a real tool"

    return ""  # Valid


def _parse_markdown_parameters(text: str) -> list:
    """
    Parse markdown sections with 'Parameters:' fields.
    Format AI uses:
      **1. NMAP (Comprehensive Port Scan)**
      *   **Parameters:** `-sC -sV -p- -T4 --open 185.20.122.92`
    Also handles:
      **2. GOBUSTER**
      *   **Parameters:** `dir -u http://IP -w /path/wordlist.txt`
    """
    calls = []
    seen = set()

    # Clean markdown
    clean = text.replace('**', '').replace('`', '').replace('*', '')

    # Map known tool names
    tool_type_map = {
        "nmap": "TOOL", "masscan": "CMD", "nikto": "CMD",
        "sqlmap": "CMD", "wpscan": "CMD", "gobuster": "CMD",
        "ffuf": "CMD", "hydra": "CMD", "curl": "CMD",
        "nuclei": "CMD", "httpx": "CMD", "subfinder": "CMD",
        "dirb": "CMD", "dirb_fuzz": "TOOL", "bruteforce": "TOOL",
        "scrapling": "TOOL", "searchsploit": "SEARCHSPLOIT",
        "ssh_user_enum": "TOOL", "ssh-user-enum": "TOOL", "sshenum": "TOOL",
        "jmx2rce": "CMD", "nxc": "CMD", "crackmapexec": "CMD",
        "whatweb": "CMD", "sslscan": "CMD", "enum4linux": "CMD",
        "dig": "CMD", "whois": "CMD",
    }

    # Pattern 1: Section header with tool name + Parameters line
    # "1. NMAP (description)" ... "Parameters: -sC -sV ..."
    sections = re.split(r'\n\s*\d+\.\s+', clean)
    for section in sections:
        # Extract tool name from section header
        header_match = re.match(r'(\w+)', section.strip())
        if not header_match:
            continue
        tool_name = header_match.group(1).strip().lower()
        if tool_name not in tool_type_map:
            continue

        # Extract parameters
        param_match = re.search(r'Parameters?:\s*(.+?)(?:\n|$)', section, re.IGNORECASE)
        if not param_match:
            continue
        params = param_match.group(1).strip()
        params = re.sub(r'\s+', ' ', params).strip()

        if not params or len(params) < 3:
            continue

        # Build full command
        # If params already start with the tool name, don't duplicate
        if params.lower().startswith(tool_name):
            full_cmd = params
        else:
            full_cmd = f"{tool_name} {params}"

        key = full_cmd.lower()[:60]
        if key in seen:
            continue
        seen.add(key)

        call_type = tool_type_map.get(tool_name, "CMD")
        if call_type == "SEARCHSPLOIT":
            calls.append(("SEARCHSPLOIT", params))
        elif call_type == "TOOL":
            calls.append(("TOOL", full_cmd))
        else:
            calls.append(("CMD", full_cmd))

    return calls


def _parse_xml_tool_requests(text: str) -> list:
    """
    Parse <tool_request> XML blocks that the AI sometimes uses.
    Format: <tool_request><tool_name>nmap</tool_name><parameters>-sV -sC IP</parameters></tool_request>
    """
    calls = []
    seen = set()

    # Map tool names to call types
    tool_type_map = {
        "nmap": "TOOL", "masscan": "CMD", "nikto": "CMD",
        "sqlmap": "CMD", "wpscan": "CMD", "gobuster": "CMD",
        "ffuf": "CMD", "hydra": "CMD", "curl": "CMD",
        "enum4linux": "CMD", "smbclient": "CMD", "dig": "CMD",
        "whatweb": "CMD", "sslscan": "CMD", "jmx2rce": "CMD",
        "nuclei": "CMD", "nxc": "CMD", "httpx": "CMD",
        "dirb_fuzz": "TOOL", "bruteforce": "TOOL",
        "scrapling": "TOOL", "searchsploit": "SEARCHSPLOIT",
        "ssh_user_enum": "TOOL", "ssh-user-enum": "TOOL", "sshenum": "TOOL",
    }

    for match in re.finditer(
        r'<tool_request>\s*<tool_name>\s*(\w+)\s*</tool_name>\s*<parameters>\s*(.*?)\s*</parameters>',
        text, re.DOTALL
    ):
        tool_name = match.group(1).strip().lower()
        params = match.group(2).strip()
        # Clean params: collapse whitespace
        params = re.sub(r'\s+', ' ', params).strip()

        if not params:
            continue

        # Build full command
        full_cmd = f"{tool_name} {params}"
        key = full_cmd.lower()[:60]
        if key in seen:
            continue
        seen.add(key)

        call_type = tool_type_map.get(tool_name, "CMD")

        if call_type == "SEARCHSPLOIT":
            calls.append(("SEARCHSPLOIT", params))
        elif call_type == "TOOL":
            calls.append(("TOOL", full_cmd))
        else:
            calls.append(("CMD", full_cmd))

    return calls


def _fallback_extract_commands(text: str) -> list:
    """
    Fallback: extract tool commands from markdown tables, bullets, backtick blocks.
    Catches patterns like:
      - `nmap -sV -sC 1.2.3.4`
      - | nmap | ... | `-p- -sV 1.2.3.4` |
      - **nmap**: nmap -Pn -sT ... 
    """
    calls = []
    seen = set()

    # Remove markdown formatting
    clean = text.replace('**', '').replace('`', '').replace('*', '')

    # Patterns match tool + flags/args but stop at sentence-like prose
    tool_patterns = [
        (r'(?:^|\s)(nmap\s+(?:-\S+\s+)*\S+)', "TOOL"),
        (r'(?:^|\s)(masscan\s+\S+\s+(?:-\S+\s*)*)', "CMD"),
        (r'(?:^|\s)(hydra\s+(?:-\S+\s+)*\S+://\S+(?:\s+-\S+\s*)*)', "CMD"),
        (r'(?:^|\s)(nikto\s+-h\s+\S+(?:\s+-\S+\s*)*)', "CMD"),
        (r'(?:^|\s)(sqlmap\s+-u\s+\S+[^\n]{0,80})', "CMD"),
        (r'(?:^|\s)(wpscan\s+--url\s+\S+[^\n]{0,60})', "CMD"),
        (r'(?:^|\s)(gobuster\s+dir\s+[^\n]{10,100})', "CMD"),
        (r'(?:^|\s)(ffuf\s+-\S+[^\n]{10,100})', "CMD"),
        (r'(?:^|\s)(whatweb\s+\S+)', "CMD"),
        (r'(?:^|\s)(curl\s+(?:-\S+\s+)*\S+)', "CMD"),
        (r'(?:^|\s)(smbclient\s+(?:-\S+\s+)*\S+)', "CMD"),
        (r'(?:^|\s)(enum4linux\s+(?:-\S+\s+)*\S+)', "CMD"),
        (r'(?:^|\s)(dig\s+\S+[^\n]{0,40})', "CMD"),
        (r'(?:^|\s)(searchsploit\s+\S+[^\n]{0,40})', "SEARCHSPLOIT"),
        (r'(?:^|\s)(jmx2rce\s+\w+\s+(?:-\S+\s+)*\S+)', "CMD"),
        (r'(?:^|\s)(nuclei\s+(?:-\S+\s+)*\S+)', "CMD"),
        (r'(?:^|\s)(ssh_user_enum\s+\S+)', "TOOL"),
        (r'(?:^|\s)(bruteforce\s+\w+\s+\S+)', "TOOL"),
    ]

    for pattern, call_type in tool_patterns:
        for match in re.finditer(pattern, clean, re.MULTILINE | re.IGNORECASE):
            cmd = match.group(1).strip()
            # Clean up: remove trailing | and markdown noise
            cmd = re.sub(r'\s*\|.*$', '', cmd)
            cmd = cmd.rstrip('|').strip()
            # Remove trailing prose words (not flags, IPs, or paths)
            # Keep: -flag, IP addresses, /paths, protocol://
            parts = cmd.split()
            cleaned_parts = [parts[0]]  # tool name
            for p in parts[1:]:
                if (p.startswith('-') or p.startswith('/') or
                    re.match(r'\d+\.\d+', p) or '://' in p or
                    '=' in p or p.startswith('http') or
                    re.match(r'^[A-Z_]+$', p) or  # env vars
                    re.match(r'^[\d,]+$', p) or  # port lists
                    p in ('dir', 'scan', 'rce', 'read', 'cleanup')):  # subcommands
                    cleaned_parts.append(p)
                else:
                    break  # Stop at first prose word
            cmd = ' '.join(cleaned_parts)

            # Skip if it's just a tool name with no arguments
            if len(cmd.split()) < 2:
                continue
            # Dedup
            key = cmd.lower()[:50]
            if key not in seen:
                seen.add(key)
                if call_type == "SEARCHSPLOIT":
                    calls.append((call_type, cmd.replace("searchsploit", "").strip()))
                elif call_type == "TOOL" and cmd.startswith("nmap"):
                    calls.append(("TOOL", cmd))
                else:
                    calls.append((call_type, cmd))

    return calls


# ─────────────────────────────────────────────
# COMMAND VALIDATOR & FIXER (NEW v3.0)
# ─────────────────────────────────────────────

def _fix_hydra_args(cmd: str) -> str:
    """
    Fix common hydra mistakes AI makes:
    1. -L csv_values → create temp file
    2. -P csv_values → create temp file
    3. sshs:// → ssh://
    4. Missing -t threads
    """
    # Fix sshs:// → ssh://
    cmd = cmd.replace("sshs://", "ssh://")

    # Fix -L with comma-separated values (not a file path)
    match_L = re.search(r'-L\s+(\S+)', cmd)
    if match_L:
        val = match_L.group(1)
        if ',' in val and not val.startswith('/'):
            # It's comma-separated usernames, create a temp file
            users = val.split(',')
            users_file = "/tmp/octopus_users.txt"
            # Only create if the AI gave inline values
            try:
                with open(users_file, "w") as f:
                    f.write("\n".join(u.strip() for u in users) + "\n")
                cmd = cmd.replace(f"-L {val}", f"-L {users_file}")
                print(f"  {C_YELLOW}[FIX] Created user file from inline values: {users_file}{C_RESET}")
            except Exception:
                pass

    # Fix -P with comma-separated values (not a file path)
    match_P = re.search(r'-P\s+(\S+)', cmd)
    if match_P:
        val = match_P.group(1)
        if ',' in val and not val.startswith('/'):
            # It's comma-separated passwords, create a temp file
            passwords = val.split(',')
            pass_file = "/tmp/octopus_passwords.txt"
            try:
                with open(pass_file, "w") as f:
                    f.write("\n".join(p.strip() for p in passwords) + "\n")
                cmd = cmd.replace(f"-P {val}", f"-P {pass_file}")
                print(f"  {C_YELLOW}[FIX] Created password file from inline values: {pass_file}{C_RESET}")
            except Exception:
                pass

    # Fix -s flag without proper port (hydra -s expects a port number)
    # Remove bare -s flags that aren't followed by a number
    cmd = re.sub(r'\s-s\s+(?!\d)', ' ', cmd)

    # Always add -I (skip restore file warning — saves 10s)
    if " -I" not in cmd:
        cmd = cmd.replace("hydra ", "hydra -I ", 1)

    # Always add -f (stop on first valid password)
    if " -f" not in cmd:
        cmd += " -f"

    # Always add -e nsr (try null, same-as-login, reversed)
    if " -e " not in cmd:
        cmd += " -e nsr"

    return cmd


def _fix_nmap_args(cmd: str) -> str:
    """Ensure -Pn -sT are present in nmap commands."""
    if "-Pn" not in cmd:
        cmd = cmd.replace("nmap ", "nmap -Pn ", 1)
    if "-sT" not in cmd:
        cmd = cmd.replace("nmap ", "nmap -sT ", 1)
    return cmd


def validate_and_fix_cmd(call_type: str, cmd: str) -> str:
    """
    Validate and fix common AI command mistakes before execution.
    Returns the fixed command string.
    """
    if call_type != "CMD":
        return cmd

    parts = cmd.strip().split()
    if not parts:
        return cmd

    tool = parts[0].lower()

    # Fix hydra commands
    if tool == "hydra":
        cmd = _fix_hydra_args(cmd)

    # Fix nmap commands
    elif tool == "nmap":
        cmd = _fix_nmap_args(cmd)

    # Fix sqlmap commands (v3.2)
    elif tool == "sqlmap":
        # Strip --output-dir (AI adds this, sqlmap doesn't support it as expected)
        cmd = re.sub(r'\s+--output-dir\s+\S+', '', cmd)
        cmd = re.sub(r'\s+--output\s+\S+', '', cmd)
        # Ensure --batch is present
        if "--batch" not in cmd:
            cmd += " --batch"
        # Fix URL without path: sqlmap -u "http://IP" → sqlmap -u "http://IP/"
        url_match = re.search(r'-u\s+["\']?(https?://[^"\'?\s]+)["\']?', cmd)
        if url_match:
            url = url_match.group(1)
            # If URL is just http://IP or http://IP:PORT with no path
            url_stripped = url.replace("http://", "").replace("https://", "")
            if "/" not in url_stripped:
                # No path — append /
                fixed_url = url + "/"
                cmd = cmd.replace(url, fixed_url)
                print(f"  [FIX] sqlmap URL had no path, added '/': {fixed_url}")

    # Fix nikto commands (v3.2)
    elif tool == "nikto":
        # Strip -Format and -o output flags AI adds
        cmd = re.sub(r'\s+-Format\s+\S+', '', cmd)
        cmd = re.sub(r'\s+-o\s+\S+', '', cmd)
        cmd = re.sub(r'\s+--output\s+\S+', '', cmd)

    # Fix curl — add timeout if missing
    elif tool == "curl":
        if "--max-time" not in cmd and "--connect-timeout" not in cmd:
            cmd = cmd.replace("curl ", "curl --max-time 10 ", 1)

    # Fix telnet — dangerously long timeout if unchecked
    elif tool == "telnet":
        # telnet has no built-in timeout flag, handled by run_arbitrary_cmd
        pass

    return cmd
