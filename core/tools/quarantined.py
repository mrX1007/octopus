"""Canonical inventory for source capabilities that are not safe to dispatch.

These providers already exist in the repository, but exposing them directly
would bypass the current typed credential, artifact, protocol, or policy
contracts. Registering them as disabled entries gives architecture and future
integration work one authoritative identity while the runtime fails closed.
"""

from __future__ import annotations

from collections.abc import Iterable

from core.tools.dependencies import resource
from core.tools.registry import tool

_QUARANTINE_REASON = "unsafe_provider_contract_not_mounted"
_ALIASES = {"pass_the_hash": ["pth"]}

_CAPABILITIES: tuple[tuple[str, str, str], ...] = (
    ("pivot_remote_forward", "core.killchain.pivot:setup_remote_forward", "core/killchain/pivot.py"),
    ("pivot_ssh_chain", "core.killchain.pivot:create_ssh_chain", "core/killchain/pivot.py"),
    ("pivot_proxy_scan", "core.killchain.pivot:scan_through_proxy", "core/killchain/pivot.py"),
    (
        "kerberos_extract_tickets",
        "core.killchain.ad.kerberos:extract_tickets",
        "core/killchain/ad/kerberos.py",
    ),
    (
        "kerberos_crack_tickets",
        "core.killchain.ad.kerberos:crack_tickets",
        "core/killchain/ad/kerberos.py",
    ),
    (
        "ad_pass_the_ticket",
        "core.killchain.ad.credential:pass_the_ticket",
        "core/killchain/ad/credential.py",
    ),
    ("pass_the_hash", "core.killchain.ad.credential:pass_the_hash", "core/killchain/ad/credential.py"),
    ("ad_dump_lsass", "core.killchain.ad.credential:dump_lsass", "core/killchain/ad/credential.py"),
    ("ad_sam_dump", "core.killchain.ad.credential:sam_dump", "core/killchain/ad/credential.py"),
    ("ad_smbexec", "core.killchain.ad.lateral:smbexec", "core/killchain/ad/lateral.py"),
    ("ad_winrm_exec", "core.killchain.ad.lateral:winrm_exec", "core/killchain/ad/lateral.py"),
    ("ad_dcom_exec", "core.killchain.ad.lateral:dcom_exec", "core/killchain/ad/lateral.py"),
    ("dns_c2_channel", "core.c2.channels.dns:DNSChannel", "core/c2/channels/dns.py"),
    ("payload_keying", "modules.evasion.payload_keying:PayloadKeying", "modules/evasion/payload_keying.py"),
)


def _register_capabilities(capabilities: Iterable[tuple[str, str, str]]) -> None:
    for name, provider_path, source_path in capabilities:

        @tool(
            name=name,
            aliases=_ALIASES.get(name),
            category="post",
            description="Quarantined source capability; canonical adapter contract is not complete.",
            dependencies=resource("", source_path),
            enabled=False,
            provider_path=provider_path,
            disabled_reason=_QUARANTINE_REASON,
        )
        def _disabled_provider(*_args: object, **_kwargs: object) -> str:
            return f"[!] Execution denied: {_QUARANTINE_REASON}"


_register_capabilities(_CAPABILITIES)

QUARANTINED_CAPABILITY_NAMES = tuple(item[0] for item in _CAPABILITIES)

__all__ = ["QUARANTINED_CAPABILITY_NAMES"]
