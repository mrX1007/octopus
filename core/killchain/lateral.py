#!/usr/bin/env python3
"""Secret-safe internal network inventory and legacy C2 deployment boundary."""

from __future__ import annotations

import re
from typing import Any

from core.c2.protocol import C2_PROTOCOL_VERSION
from core.credentials import sanitize_credential_text
from core.execution.policy import normalize_host
from core.killchain.ssh_helpers import _ssh_connect, _ssh_exec


def deploy_c2_beacon(
    host: str,
    user: str,
    password: str,
    port: int = 22,
    callback_host: str = "",
) -> str:
    """Fail closed instead of transferring the incompatible legacy payload.

    Protocol-v11 artifacts are produced by the canonical local Go builder.  The
    historical helper mixed generation, credential handling, transfer,
    execution, and persistence, so it cannot safely be adapted in place.
    """

    del host, user, password, port
    if not callback_host:
        return "[!] C2 deployment blocked: explicit callback_host is required."
    try:
        callback_host = normalize_host(callback_host)
    except ValueError:
        return "[!] C2 deployment blocked: callback_host must be one host without URL syntax."
    return (
        "[!] Automatic remote C2 deployment is disabled. The incompatible legacy payload was removed.\n"
        f"[*] Generate a protocol v{C2_PROTOCOL_VERSION} artifact for {callback_host} with the canonical "
        "build_go_implant workflow, then use separately approved deployment tooling.\n"
    )


def _valid_neighbor(candidate: str, target: str) -> bool:
    return candidate not in {
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "127.0.1.1",
        target,
    }


def _clip_inventory(value: Any, limit: int = 4000) -> str:
    rendered = str(value or "").strip()
    if len(rendered) <= limit:
        return rendered
    return rendered[:limit].rstrip() + "\n[... truncated ...]"


def lateral_move(
    host: str,
    user: str,
    password: str,
    port: int = 22,
    extra_creds: list | None = None,
) -> str:
    """Collect local adjacency data without harvesting or replaying credentials.

    ``extra_creds`` remains only for source compatibility and is deliberately
    ignored.  Credential material is revealed solely to the immediate SSH
    authentication call and never copied into output or intermediate pools.
    """

    del extra_creds
    heading = f"[INTERNAL NETWORK INVENTORY — {user}@{host}:{port}]"
    client, error = _ssh_connect(host, user, password, port)
    if not client:
        safe_error = sanitize_credential_text(str(error or "SSH connection failed"), password)
        return f"{heading}\n[!] SSH connection failed: {safe_error}\n"

    discovered_hosts: set[str] = set()
    sections: list[tuple[str, str]] = []
    checks = (
        ("Neighbor table", "arp -an 2>/dev/null || ip neigh 2>/dev/null", 10),
        ("Static hosts", "cat /etc/hosts 2>/dev/null", 5),
        ("Routes", "ip -4 route show 2>/dev/null", 5),
        ("Local listening services", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", 8),
    )

    try:
        for label, command, timeout in checks:
            result = _ssh_exec(client, command, timeout=timeout)
            safe_result = sanitize_credential_text(_clip_inventory(result), password)
            sections.append((label, safe_result))
            if label in {"Neighbor table", "Static hosts", "Routes"}:
                for match in re.finditer(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", safe_result):
                    candidate = match.group(0)
                    if _valid_neighbor(candidate, host):
                        discovered_hosts.add(candidate)
    finally:
        client.close()

    lines = [heading]
    for label, result in sections:
        lines.extend(("", f"[{label}]", result or "(no output)"))
    lines.extend(
        (
            "",
            f"[DISCOVERED ADJACENT HOSTS: {len(discovered_hosts)}]",
            *(f"  - {candidate}" for candidate in sorted(discovered_hosts)),
            "",
            "[*] Credential harvesting and credential replay are disabled; no secret material was retained.",
        )
    )
    return sanitize_credential_text("\n".join(lines) + "\n", password)
