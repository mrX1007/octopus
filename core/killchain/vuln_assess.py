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


def vuln_assess(target: str, recon_data: str = "") -> str:
    """
    Automated vulnerability assessment.
    - Extracts service versions from nmap/recon data
    - Runs searchsploit for each version
    - Runs nuclei if available
    - Returns prioritized vulnerability report
    """
    print(f"\n  {C_MAGENTA}[KILL CHAIN] Stage 1: Vulnerability Assessment — {target}{C_RESET}")
    output = f"[KILL CHAIN — VULNERABILITY ASSESSMENT — {target}]\n{'═' * 60}\n\n"

    # Extract service versions from recon data
    services = []
    # Pattern: PORT/tcp open SERVICE VERSION_INFO
    for match in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)\s+(.*?)$', recon_data, re.MULTILINE):
        port, service, version = match.groups()
        version = version.strip()
        if version and version != "tcpwrapped":
            services.append({"port": port, "service": service, "version": version})

    if not services:
        # Try to extract from other formats
        for match in re.finditer(r'Port (\d+) version: (.+)', recon_data):
            port, version = match.groups()
            services.append({"port": port, "service": "unknown", "version": version.strip()})

    if not services:
        output += "[!] No service versions found in recon data. Run nmap -sV first.\n"
        output += "AI: Run [TOOL: nmap -Pn -sT -sV -sC TARGET] to get service versions.\n"
        return output

    output += f"Detected {len(services)} services with versions:\n"
    for svc in services:
        output += f"  Port {svc['port']}: {svc['service']} — {svc['version']}\n"
    output += "\n"

    # Run searchsploit for each service version
    vuln_count = 0
    if shutil.which("searchsploit"):
        print(f"  {C_CYAN}[*] Running searchsploit for {len(services)} services...{C_RESET}")
        for svc in services:
            # Build search query from version info
            version_clean = svc["version"]
            # Extract key identifiers: "OpenSSH 7.6p1" → "OpenSSH 7.6"
            version_parts = version_clean.split()
            search_terms = []
            for p in version_parts[:3]:  # first 3 words
                p = p.strip("()")
                if p and not p.startswith("protocol") and not p.startswith("Ubuntu"):
                    search_terms.append(p)

            if not search_terms:
                continue

            query = " ".join(search_terms)
            print(f"    [*] searchsploit: {query}")
            try:
                result = subprocess.run(
                    ["searchsploit", "--color", query],
                    capture_output=True, text=True, timeout=30
                )
                sp_output = result.stdout.strip()
                if sp_output and "No Results" not in sp_output:
                    output += f"\n[SEARCHSPLOIT: {query}]\n{sp_output}\n"
                    vuln_count += 1
                    # Extract exploit paths
                    for line in sp_output.splitlines():
                        if "|" in line and ("exploits/" in line or "shellcodes/" in line):
                            parts = line.split("|")
                            if len(parts) >= 2:
                                exploit_name = parts[0].strip()
                                exploit_path = parts[-1].strip()
                                output += f"  → EXPLOITABLE: {exploit_name} ({exploit_path})\n"
            except Exception as e:
                output += f"  [!] searchsploit error for '{query}': {e}\n"
    else:
        output += "[!] searchsploit not installed — skipping exploit-db lookup.\n"

    # Run nuclei if available
    if shutil.which("nuclei"):
        print(f"  {C_CYAN}[*] Running nuclei template scan...{C_RESET}")
        try:
            result = subprocess.run(
                ["nuclei", "-target", target, "-severity", "critical,high,medium",
                 "-silent", "-timeout", "10", "-retries", "1", "-no-color"],
                capture_output=True, text=True, timeout=180
            )
            nuclei_out = result.stdout.strip()
            if nuclei_out:
                output += f"\n[NUCLEI RESULTS]\n{nuclei_out}\n"
                vuln_count += nuclei_out.count("\n") + 1
        except subprocess.TimeoutExpired:
            output += "\n[!] nuclei timed out after 180s\n"
        except Exception as e:
            output += f"\n[!] nuclei error: {e}\n"
    else:
        output += "\n[!] nuclei not installed — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"

    output += f"\n{'═' * 60}\n"
    output += f"Total exploitable findings: {vuln_count}\n"
    if vuln_count > 0:
        output += "AI: VULNERABILITIES FOUND. Proceed to exploitation stage.\n"
        output += "AI: Use [TOOL: killchain_exploit TARGET] or specific MSF modules.\n"
    else:
        output += "AI: No known exploits found. Try bruteforce, web fuzzing, or manual analysis.\n"

    return output


# ═══════════════════════════════════════════════
# STAGE 2: AUTOMATED EXPLOITATION
# ═══════════════════════════════════════════════

# Map common service versions to MSF modules
_VERSION_TO_MSF = {
    "vsftpd 2.3.4": "exploit/unix/ftp/vsftpd_234_backdoor",
    "proftpd 1.3.3": "exploit/unix/ftp/proftpd_133c_backdoor",
    "openssh": "auxiliary/scanner/ssh/ssh_login",
    "openssh 7.2": "auxiliary/scanner/ssh/ssh_enumusers",
    "openssh 7.6": "auxiliary/scanner/ssh/ssh_login",
    "openssh 7.4": "auxiliary/scanner/ssh/ssh_login",
    "openssh 8.": "auxiliary/scanner/ssh/ssh_login",
    "apache 2.4.49": "exploit/multi/http/apache_normalize_path_rce",
    "apache 2.4.50": "exploit/multi/http/apache_normalize_path_rce",
    "samba 3.0": "exploit/multi/samba/usermap_script",
    "samba 4.5": "exploit/linux/samba/is_known_pipename",
    "tomcat 8": "exploit/multi/http/tomcat_mgr_upload",
    "tomcat 9": "exploit/multi/http/tomcat_mgr_upload",
    "jenkins": "exploit/multi/http/jenkins_script_console",
    "webmin 1.9": "exploit/unix/webapp/webmin_show_cgi_exec",
    "php 5.": "exploit/multi/http/php_cgi_arg_injection",
    "drupal 7": "exploit/unix/webapp/drupal_drupalgeddon2",
    "drupal 8": "exploit/unix/webapp/drupal_drupalgeddon2",
    "wordpress": "auxiliary/scanner/http/wordpress_login_enum",
    "phpmyadmin": "exploit/multi/http/phpmyadmin_lfi_rce",
    "elasticsearch 1.": "exploit/multi/elasticsearch/script_mvel_rce",
    "redis": "exploit/linux/redis/redis_replication_cmd_exec",
    "mysql 5.": "auxiliary/scanner/mysql/mysql_login",
    "postgres": "auxiliary/scanner/postgres/postgres_login",
    "iis 6.0": "exploit/windows/iis/iis_webdav_scstoragepathfromurl",
    "shellshock": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "heartbleed": "auxiliary/scanner/ssl/openssl_heartbleed",
    "eternalblue": "exploit/windows/smb/ms17_010_eternalblue",
    "smb": "auxiliary/scanner/smb/smb_ms17_010",
}


