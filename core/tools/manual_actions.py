"""Manual-gated capability inventory with deliberately unmounted providers.

These identities are discoverable and policy-recognized, but they are not
quarantined provider implementations. Final policy requires an explicit
operator approval and then fails closed with ``provider_not_configured`` until
a separately reviewed provider mount exists.
"""

from __future__ import annotations

from collections.abc import Iterable

from core.tools.dependencies import resource
from core.tools.registry import tool

_PROVIDER_NOT_CONFIGURED = "provider_not_configured"
_ALIASES = {"pass_the_hash": ["pth"]}
_TARGET_OPTIONAL = {
    "c2_enroll",
    "kerberos_crack_tickets",
    "payload_keying",
}

_MANUAL_GATED_CAPABILITIES: tuple[tuple[str, str, str], ...] = (
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
    (
        "ad_remote_execution",
        "core.killchain.ad.lateral:remote_execution",
        "core/killchain/ad/lateral.py",
    ),
    ("dns_c2_channel", "core.c2.channels.dns:DNSChannel", "core/c2/channels/dns.py"),
    ("c2_enroll", "core.c2.enrollment:EnrollmentAuthority", "core/c2/enrollment.py"),
    ("c2_deploy", "core.c2.daemon:deploy", "core/c2/daemon.py"),
    ("c2_channel_create", "core.c2.daemon:create_channel", "core/c2/daemon.py"),
    ("c2_task", "core.c2.daemon:task_agent", "core/c2/daemon.py"),
    ("c2_cleanup", "core.c2.daemon:cleanup", "core/c2/daemon.py"),
    (
        "payload_keying",
        "modules.evasion.payload_keying:PayloadKeyingPlugin",
        "modules/evasion/payload_keying.py",
    ),
)


def _register_capabilities(capabilities: Iterable[tuple[str, str, str]]) -> None:
    for name, provider_path, source_path in capabilities:

        @tool(
            name=name,
            aliases=_ALIASES.get(name),
            category="post",
            description="Manual-gated canonical capability; provider is not mounted.",
            dependencies=resource("", source_path),
            needs_target=name not in _TARGET_OPTIONAL,
            enabled=False,
            provider_path=provider_path,
            disabled_reason=_PROVIDER_NOT_CONFIGURED,
        )
        def _unmounted_provider(target: str = "", *_args: object, **_kwargs: object) -> str:
            del target
            return f"[!] Execution denied: {_PROVIDER_NOT_CONFIGURED}"


_register_capabilities(_MANUAL_GATED_CAPABILITIES)

MANUAL_GATED_CAPABILITY_NAMES = tuple(item[0] for item in _MANUAL_GATED_CAPABILITIES)
QUARANTINED_CAPABILITY_NAMES: tuple[str, ...] = ()

__all__ = ["MANUAL_GATED_CAPABILITY_NAMES", "QUARANTINED_CAPABILITY_NAMES"]
