#!/usr/bin/env python3
"""
Active Directory enumeration module.

Provides functions to enumerate AD objects (users, groups, computers, GPOs)
against a Domain Controller.  Each function tries impacket first, then
falls back to ldap3, and finally to CLI tools (ldapsearch, enum4linux,
rpcclient).

Usage::

    from core.killchain.ad.enumeration import run_ad_enum
    result = run_ad_enum("10.10.10.100", creds={"user": "admin", "password": "P@ss", "domain": "CORP"})
"""

import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

# ── Logging ──────────────────────────────────────────────────────────────
logger = logging.getLogger("octopus.killchain.ad.enumeration")

# ── ANSI Colors ──────────────────────────────────────────────────────────
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_GREY = "\033[90m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_RESET = "\033[0m"

# ── Default LDAP constants ───────────────────────────────────────────────
LDAP_PORT = 389
LDAPS_PORT = 636
LDAP_TIMEOUT = 30
ENUM4LINUX_TIMEOUT = 120
BLOODHOUND_TIMEOUT = 300

# ── LDAP search filters ─────────────────────────────────────────────────
FILTER_USERS = "(&(objectCategory=person)(objectClass=user))"
FILTER_GROUPS = "(objectCategory=group)"
FILTER_COMPUTERS = "(objectCategory=computer)"
FILTER_GPO = "(objectClass=groupPolicyContainer)"
USER_ATTRS = ["sAMAccountName", "displayName", "memberOf", "mail",
              "userAccountControl", "lastLogon", "pwdLastSet",
              "description", "adminCount"]
GROUP_ATTRS = ["sAMAccountName", "member", "description", "adminCount"]
COMPUTER_ATTRS = ["sAMAccountName", "dNSHostName", "operatingSystem",
                  "operatingSystemVersion", "lastLogon"]
GPO_ATTRS = ["displayName", "gPCFileSysPath", "versionNumber",
             "gPCMachineExtensionNames"]


# ═══════════════════════════════════════════════════════════════════════════
# Helper: Credential normalization
# ═══════════════════════════════════════════════════════════════════════════

def _normalize_creds(creds: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Return a dict with guaranteed keys: user, password, domain, nthash."""
    defaults: Dict[str, str] = {
        "user": "",
        "password": "",
        "domain": "",
        "nthash": "",
    }
    if creds:
        defaults.update(creds)
    return defaults


def _build_base_dn(domain: str) -> str:
    """Convert ``CORP.LOCAL`` → ``DC=CORP,DC=LOCAL``."""
    if not domain:
        return ""
    return ",".join(f"DC={part}" for part in domain.upper().split("."))


# ═══════════════════════════════════════════════════════════════════════════
# Backend helpers
# ═══════════════════════════════════════════════════════════════════════════

def _ldap_search_impacket(
    target: str, base_dn: str, search_filter: str,
    attributes: List[str], creds: Dict[str, str],
) -> Optional[List[Dict[str, Any]]]:
    """Perform an LDAP search via impacket's ``ldap`` module.

    Returns a list of entry dicts or ``None`` on failure.
    """
    try:
        from impacket.ldap import ldap as impacket_ldap  # lazy import
        from impacket.ldap import ldapasn1 as ldapasn1
    except ImportError:
        logger.debug("impacket not available for LDAP search")
        return None

    try:
        ldap_url = f"ldap://{target}"
        conn = impacket_ldap.LDAPConnection(ldap_url, base_dn, target)

        if creds["nthash"]:
            conn.login(
                creds["user"], "", creds["domain"],
                lmhash="", nthash=creds["nthash"],
            )
        else:
            conn.login(creds["user"], creds["password"], creds["domain"])

        sc = impacket_ldap.SimplePagedResultsControl(size=1000)
        raw = conn.search(
            searchFilter=search_filter,
            attributes=attributes,
            searchControls=[sc],
        )

        results: List[Dict[str, Any]] = []
        for entry in raw:
            if not isinstance(entry, ldapasn1.SearchResultEntry):
                continue
            item: Dict[str, Any] = {}
            try:
                item["dn"] = str(entry["objectName"])
            except Exception as e:
                item["dn"] = ""
            for attr in entry["attributes"]:
                attr_type = str(attr["type"])
                vals = [str(v) for v in attr["vals"]]
                item[attr_type] = vals[0] if len(vals) == 1 else vals
            results.append(item)

        return results
    except Exception as exc:
        logger.warning("impacket LDAP search failed: %s", exc)
        return None


def _ldap_search_ldap3(
    target: str, base_dn: str, search_filter: str,
    attributes: List[str], creds: Dict[str, str],
) -> Optional[List[Dict[str, Any]]]:
    """Perform an LDAP search via the ``ldap3`` library.

    Returns a list of entry dicts or ``None`` on failure.
    """
    try:
        import ldap3  # lazy import
    except ImportError:
        logger.debug("ldap3 not available for LDAP search")
        return None

    try:
        server = ldap3.Server(target, port=LDAP_PORT, get_info=ldap3.ALL,
                              connect_timeout=LDAP_TIMEOUT)
        bind_user = (
            f"{creds['domain']}\\{creds['user']}" if creds["domain"]
            else creds["user"]
        )
        conn = ldap3.Connection(
            server, user=bind_user, password=creds["password"],
            authentication=ldap3.NTLM if creds["domain"] else ldap3.SIMPLE,
            auto_bind=True,
        )
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            paged_size=1000,
        )

        results: List[Dict[str, Any]] = []
        for entry in conn.entries:
            item: Dict[str, Any] = {"dn": str(entry.entry_dn)}
            for attr_name in attributes:
                try:
                    val = entry[attr_name].value
                    item[attr_name] = val
                except (ldap3.core.exceptions.LDAPKeyError, KeyError):
                    pass
            results.append(item)

        conn.unbind()
        return results
    except Exception as exc:
        logger.warning("ldap3 LDAP search failed: %s", exc)
        return None


def _run_cli(cmd: str, timeout: int = LDAP_TIMEOUT) -> str:
    """Run a CLI command and return stdout, or an error string."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout,
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


def _ldap_search_cli(
    target: str, base_dn: str, search_filter: str,
    attributes: List[str], creds: Dict[str, str],
) -> str:
    """Fall back to ``ldapsearch`` CLI tool.  Returns raw text output."""
    if not shutil.which("ldapsearch"):
        return "[!] ldapsearch not found in PATH"

    attr_str = " ".join(attributes)
    bind_dn = ""
    auth_args = ""
    if creds["user"] and creds["domain"]:
        bind_dn = f"{creds['user']}@{creds['domain']}"
        auth_args = f'-D "{bind_dn}" -w "{creds["password"]}"'
    elif creds["user"]:
        auth_args = f'-D "{creds["user"]}" -w "{creds["password"]}"'
    else:
        auth_args = "-x"  # anonymous bind

    cmd = (
        f'ldapsearch -H ldap://{target} -b "{base_dn}" '
        f'{auth_args} "{search_filter}" {attr_str}'
    )
    return _run_cli(cmd)


def _format_entries(entries: List[Dict[str, Any]], label: str) -> str:
    """Pretty-format a list of LDAP entry dicts for output."""
    if not entries:
        return f"  No {label} found.\n"
    lines: List[str] = []
    for entry in entries:
        name = entry.get("sAMAccountName", entry.get("displayName", entry.get("dn", "?")))
        detail_parts: List[str] = []
        for k, v in entry.items():
            if k in ("dn", "sAMAccountName"):
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v[:5])
            detail_parts.append(f"{k}={v}")
        details = " | ".join(detail_parts[:4])
        lines.append(f"  {name}  {C_GREY}({details}){C_RESET}")
    return "\n".join(lines) + "\n"


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def run_ad_enum(target: str, creds: Optional[Dict[str, str]] = None) -> str:
    """Run comprehensive AD enumeration against a Domain Controller.

    Executes ``ldapsearch``, ``enum4linux``, and ``rpcclient`` as
    available.  Also calls the individual ``enumerate_*`` helpers.

    Args:
        target: IP or hostname of the Domain Controller.
        creds: Optional dict with keys ``user``, ``password``, ``domain``.

    Returns:
        Formatted string with all enumeration results.
    """
    print(f"\n  {C_MAGENTA}[AD ENUM] Full AD enumeration — {target}{C_RESET}")
    creds = _normalize_creds(creds)
    output = f"[AD ENUMERATION — {target}]\n{'═' * 60}\n\n"

    # ── enum4linux ────────────────────────────────────────────────
    if shutil.which("enum4linux"):
        print(f"    {C_CYAN}[*] Running enum4linux...{C_RESET}")
        auth = ""
        if creds["user"]:
            auth = f'-u "{creds["user"]}" -p "{creds["password"]}"'
        e4l_result = _run_cli(
            f"enum4linux -a {auth} {target}", timeout=ENUM4LINUX_TIMEOUT,
        )
        output += f"[enum4linux]\n{e4l_result[:3000]}\n\n"
    else:
        output += "[!] enum4linux not in PATH — skipped\n\n"

    # ── rpcclient ─────────────────────────────────────────────────
    if shutil.which("rpcclient"):
        print(f"    {C_CYAN}[*] Running rpcclient queries...{C_RESET}")
        rpc_auth = f'-U "{creds["user"]}%{creds["password"]}"' if creds["user"] else "-N"
        for rpc_cmd in ("enumdomusers", "enumdomgroups", "querydominfo"):
            rpc_out = _run_cli(
                f'rpcclient {rpc_auth} {target} -c "{rpc_cmd}"',
                timeout=LDAP_TIMEOUT,
            )
            output += f"[rpcclient — {rpc_cmd}]\n{rpc_out[:1500]}\n\n"
    else:
        output += "[!] rpcclient not in PATH — skipped\n\n"

    # ── Detailed LDAP enumeration ─────────────────────────────────
    output += enumerate_users(target, creds)
    output += enumerate_groups(target, creds)
    output += enumerate_computers(target, creds)
    output += enumerate_gpo(target, creds)

    output += f"\n{'═' * 60}\n"
    output += "AI: AD enumeration complete. Review users, groups, and GPOs for attack paths.\n"
    return output


def enumerate_users(target: str, creds: Optional[Dict[str, str]] = None) -> str:
    """Pull user list from Active Directory.

    Tries impacket → ldap3 → ldapsearch CLI.

    Args:
        target: DC IP or hostname.
        creds: Credential dict with ``user``, ``password``, ``domain``.

    Returns:
        Formatted string listing AD users and key attributes.
    """
    creds = _normalize_creds(creds)
    base_dn = _build_base_dn(creds["domain"])
    print(f"    {C_CYAN}[*] Enumerating AD users...{C_RESET}")
    output = "\n[AD USERS]\n" + "-" * 40 + "\n"

    # Try impacket
    entries = _ldap_search_impacket(target, base_dn, FILTER_USERS, USER_ATTRS, creds)
    if entries is not None:
        output += f"  (via impacket — {len(entries)} users)\n"
        output += _format_entries(entries, "users")
        return output

    # Try ldap3
    entries = _ldap_search_ldap3(target, base_dn, FILTER_USERS, USER_ATTRS, creds)
    if entries is not None:
        output += f"  (via ldap3 — {len(entries)} users)\n"
        output += _format_entries(entries, "users")
        return output

    # Fall back to CLI
    output += "  (via ldapsearch CLI)\n"
    cli_out = _ldap_search_cli(target, base_dn, FILTER_USERS, USER_ATTRS, creds)
    output += f"{cli_out[:2000]}\n"
    return output


def enumerate_groups(target: str, creds: Optional[Dict[str, str]] = None) -> str:
    """Pull group memberships from Active Directory.

    Args:
        target: DC IP or hostname.
        creds: Credential dict.

    Returns:
        Formatted string listing AD groups and members.
    """
    creds = _normalize_creds(creds)
    base_dn = _build_base_dn(creds["domain"])
    print(f"    {C_CYAN}[*] Enumerating AD groups...{C_RESET}")
    output = "\n[AD GROUPS]\n" + "-" * 40 + "\n"

    entries = _ldap_search_impacket(target, base_dn, FILTER_GROUPS, GROUP_ATTRS, creds)
    if entries is not None:
        output += f"  (via impacket — {len(entries)} groups)\n"
        output += _format_entries(entries, "groups")
        return output

    entries = _ldap_search_ldap3(target, base_dn, FILTER_GROUPS, GROUP_ATTRS, creds)
    if entries is not None:
        output += f"  (via ldap3 — {len(entries)} groups)\n"
        output += _format_entries(entries, "groups")
        return output

    output += "  (via ldapsearch CLI)\n"
    cli_out = _ldap_search_cli(target, base_dn, FILTER_GROUPS, GROUP_ATTRS, creds)
    output += f"{cli_out[:2000]}\n"
    return output


def enumerate_computers(target: str, creds: Optional[Dict[str, str]] = None) -> str:
    """List domain-joined computers from Active Directory.

    Args:
        target: DC IP or hostname.
        creds: Credential dict.

    Returns:
        Formatted string listing domain computers.
    """
    creds = _normalize_creds(creds)
    base_dn = _build_base_dn(creds["domain"])
    print(f"    {C_CYAN}[*] Enumerating AD computers...{C_RESET}")
    output = "\n[AD COMPUTERS]\n" + "-" * 40 + "\n"

    entries = _ldap_search_impacket(target, base_dn, FILTER_COMPUTERS, COMPUTER_ATTRS, creds)
    if entries is not None:
        output += f"  (via impacket — {len(entries)} computers)\n"
        output += _format_entries(entries, "computers")
        return output

    entries = _ldap_search_ldap3(target, base_dn, FILTER_COMPUTERS, COMPUTER_ATTRS, creds)
    if entries is not None:
        output += f"  (via ldap3 — {len(entries)} computers)\n"
        output += _format_entries(entries, "computers")
        return output

    output += "  (via ldapsearch CLI)\n"
    cli_out = _ldap_search_cli(target, base_dn, FILTER_COMPUTERS, COMPUTER_ATTRS, creds)
    output += f"{cli_out[:2000]}\n"
    return output


def enumerate_gpo(target: str, creds: Optional[Dict[str, str]] = None) -> str:
    """List Group Policy Objects from Active Directory.

    Args:
        target: DC IP or hostname.
        creds: Credential dict.

    Returns:
        Formatted string listing GPOs.
    """
    creds = _normalize_creds(creds)
    base_dn = _build_base_dn(creds["domain"])
    print(f"    {C_CYAN}[*] Enumerating GPOs...{C_RESET}")
    output = "\n[GROUP POLICY OBJECTS]\n" + "-" * 40 + "\n"

    entries = _ldap_search_impacket(target, base_dn, FILTER_GPO, GPO_ATTRS, creds)
    if entries is not None:
        output += f"  (via impacket — {len(entries)} GPOs)\n"
        output += _format_entries(entries, "GPOs")
        return output

    entries = _ldap_search_ldap3(target, base_dn, FILTER_GPO, GPO_ATTRS, creds)
    if entries is not None:
        output += f"  (via ldap3 — {len(entries)} GPOs)\n"
        output += _format_entries(entries, "GPOs")
        return output

    output += "  (via ldapsearch CLI)\n"
    cli_out = _ldap_search_cli(target, base_dn, FILTER_GPO, GPO_ATTRS, creds)
    output += f"{cli_out[:2000]}\n"
    return output


def bloodhound_ingest(target: str, creds: Optional[Dict[str, str]] = None) -> str:
    """Run the BloodHound Python ingestor to collect AD relationship data.

    Tries the ``bloodhound`` Python package first, then falls back to
    ``bloodhound-python`` CLI.

    Args:
        target: DC IP or hostname.
        creds: Credential dict with ``user``, ``password``, ``domain``.

    Returns:
        Formatted string with ingestor results and output file paths.
    """
    creds = _normalize_creds(creds)
    print(f"    {C_RED}[*] Running BloodHound ingestor against {target}...{C_RESET}")
    output = "\n[BLOODHOUND INGEST]\n" + "-" * 40 + "\n"

    if not creds["user"] or not creds["domain"]:
        output += "  [!] BloodHound requires domain credentials (user, password, domain).\n"
        return output

    loot_dir = os.path.expanduser(f"~/OCTOPUS/loot/{target.replace('.', '_')}/bloodhound")
    os.makedirs(loot_dir, exist_ok=True)

    # ── Try Python module ─────────────────────────────────────────
    try:
        from bloodhound import BloodHound  # lazy import
        from bloodhound.ad.domain import AD as BH_AD

        logger.info("Using bloodhound Python module")
        ad = BH_AD(domain=creds["domain"], auth="", nameserver=target,
                    dns_tcp=False, dns_timeout=10)
        ad.dns_resolve(domain=creds["domain"])

        bh = BloodHound(ad)
        bh.connect(
            creds["user"], creds["password"], creds["domain"],
        )
        bh.run(
            collect=["group", "localadmin", "session", "trusts",
                     "objectprops", "acl", "dcom", "rdp", "psremote"],
            output_directory=loot_dir,
        )
        output += f"  [+] BloodHound data collected → {loot_dir}\n"
        # List generated files
        for fname in os.listdir(loot_dir):
            fpath = os.path.join(loot_dir, fname)
            fsize = os.path.getsize(fpath)
            output += f"    {fname} ({fsize} bytes)\n"
        return output
    except ImportError:
        logger.debug("bloodhound Python module not available")
    except Exception as exc:
        logger.warning("BloodHound Python module failed: %s", exc)
        output += f"  [!] Python ingestor error: {exc}\n"

    # ── Fall back to CLI ──────────────────────────────────────────
    bh_bin = shutil.which("bloodhound-python") or shutil.which("bloodhound.py")
    if bh_bin:
        cmd = (
            f'{bh_bin} -u "{creds["user"]}" -p "{creds["password"]}" '
            f'-d "{creds["domain"]}" -ns {target} '
            f'-c all --zip -op {loot_dir}'
        )
        cli_out = _run_cli(cmd, timeout=BLOODHOUND_TIMEOUT)
        output += f"  (via CLI: {bh_bin})\n{cli_out[:2000]}\n"
    else:
        output += "  [!] No BloodHound ingestor available (install bloodhound Python package)\n"

    return output
