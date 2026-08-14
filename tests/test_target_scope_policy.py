"""Canonical target-scope normalization and matching tests."""

from __future__ import annotations

import pytest

from core.actions.target_scope import (
    NetworkProtocol,
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopePolicy,
    TargetScopeRule,
    TargetScopeSnapshot,
)

pytestmark = pytest.mark.unit


def test_target_scope_policy_requires_exact_fqdn() -> None:
    target = TargetScopeCanonicalizer.canonicalize("Sub.Target.COM.", role=TargetRole.PRIMARY)
    exact = TargetScopeRule(None, TargetKind.FQDN, "sub.target.com")
    assert TargetScopePolicy.evaluate((target,), TargetScopeSnapshot("2.0", 1, (exact,))).allowed

    parent = TargetScopeRule(None, TargetKind.FQDN, "target.com")
    assert not TargetScopePolicy.evaluate((target,), TargetScopeSnapshot("2.0", 1, (parent,))).allowed
    with pytest.raises(ValueError, match="CIDR"):
        TargetScopeRule(None, TargetKind.FQDN, "target.com", allow_containment=True)


def test_target_scope_policy_cidr_port_and_protocol() -> None:
    target = TargetScopeCanonicalizer.canonicalize(
        "10.0.0.5",
        role=TargetRole.PRIMARY,
        port=443,
        protocol=NetworkProtocol.HTTPS,
    )
    rule = TargetScopeRule(
        TargetRole.PRIMARY,
        TargetKind.CIDR,
        "10.0.0.0/24",
        port=443,
        protocol=NetworkProtocol.HTTPS,
        allow_containment=True,
    )
    assert TargetScopePolicy.evaluate((target,), TargetScopeSnapshot("2.0", 1, (rule,))).allowed
    wrong_port = TargetScopeRule(
        TargetRole.PRIMARY,
        TargetKind.CIDR,
        "10.0.0.0/24",
        port=80,
        protocol=NetworkProtocol.HTTPS,
        allow_containment=True,
    )
    assert not TargetScopePolicy.evaluate((target,), TargetScopeSnapshot("2.0", 1, (wrong_port,))).allowed


def test_ambiguous_target_is_rejected() -> None:
    with pytest.raises(ValueError, match="ambiguous"):
        TargetScopeCanonicalizer.canonicalize("not/a/host", role=TargetRole.PRIMARY)


def test_target_role_values_are_closed_and_single_owner() -> None:
    assert tuple(member.value for member in TargetRole) == (
        "primary",
        "destination",
        "hop",
        "listen",
        "callback",
        "resource_bound",
    )


def test_network_protocol_values_are_closed_and_single_owner() -> None:
    assert tuple(member.value for member in NetworkProtocol) == (
        "tcp",
        "udp",
        "dns",
        "http",
        "https",
        "ssh",
        "smb",
        "winrm",
        "dcom",
    )


def test_target_kind_values_are_closed_and_single_owner() -> None:
    assert tuple(member.value for member in TargetKind) == (
        "ipv4",
        "ipv6",
        "cidr",
        "fqdn",
        "host",
        "network_endpoint",
        "resource_bound_target",
    )
