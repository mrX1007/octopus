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


def test_target_scope_canonicalizer_and_model_validations() -> None:
    # Port validation
    with pytest.raises(ValueError, match=r"target port must be in 1\.\.65535"):
        TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY, port=0)

    with pytest.raises(ValueError, match=r"target port must be in 1\.\.65535"):
        TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY, port=True)  # type: ignore

    # Protocol validation
    with pytest.raises(ValueError, match="target protocol must be canonical"):
        TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY, protocol="ssh")  # type: ignore

    # Role validation
    with pytest.raises(ValueError, match="target role must be canonical"):
        TargetScopeCanonicalizer.canonicalize("10.0.0.1", role="invalid_role")  # type: ignore

    # Empty string validation
    with pytest.raises(ValueError, match="target must be a non-empty string"):
        TargetScopeCanonicalizer.canonicalize("   ", role=TargetRole.PRIMARY)

    # Resource bound
    rb_target = TargetScopeCanonicalizer.canonicalize(
        "session://123",
        role=TargetRole.RESOURCE_BOUND,
        resource_bound=True,
    )
    assert rb_target.kind == TargetKind.RESOURCE_BOUND_TARGET
    assert rb_target.normalized_value == "session://123"

    with pytest.raises(ValueError, match="resource-bound target must be an opaque reference"):
        TargetScopeCanonicalizer.canonicalize("not-a-uri", role=TargetRole.RESOURCE_BOUND, resource_bound=True)

    # IPv6
    ipv6_target = TargetScopeCanonicalizer.canonicalize("2001:db8::1", role=TargetRole.PRIMARY)
    assert ipv6_target.kind == TargetKind.IPV6

    # Invalid FQDNs
    with pytest.raises(ValueError, match="target FQDN is not valid IDNA"):
        TargetScopeCanonicalizer.canonicalize("bad..domain.com", role=TargetRole.PRIMARY)

    with pytest.raises(ValueError, match="target FQDN is not canonical"):
        TargetScopeCanonicalizer.canonicalize("-bad.domain.com", role=TargetRole.PRIMARY)

    # Host
    host_target = TargetScopeCanonicalizer.canonicalize("myhost", role=TargetRole.PRIMARY)
    assert host_target.kind == TargetKind.HOST

    # TargetScopeSnapshot validations
    rule = TargetScopeRule(None, TargetKind.IPV4, "10.0.0.1")
    with pytest.raises(ValueError, match="target scope schema version is unsupported"):
        TargetScopeSnapshot("1.0", 1, (rule,))

    with pytest.raises(ValueError, match="target scope revision must be positive"):
        TargetScopeSnapshot("2.0", 0, (rule,))

    with pytest.raises(ValueError, match="target scope contains duplicate rules"):
        TargetScopeSnapshot("2.0", 1, (rule, rule))

    # validate_targets compatibility wrapper error path
    dec = TargetScopePolicy.validate_targets(("10.0.0.1",), ("invalid:scope:uri",))
    assert dec.allowed is False
    assert dec.reason == "invalid_target_scope"

    # ExtractedActionTarget validations
    from core.actions.target_scope import ExtractedActionTarget

    with pytest.raises(ValueError, match="target role and kind must be canonical enums"):
        ExtractedActionTarget(role="not_a_role", kind=TargetKind.IPV4, normalized_value="10.0.0.1")  # type: ignore

    with pytest.raises(ValueError, match="target is not in canonical form"):
        ExtractedActionTarget(role=TargetRole.PRIMARY, kind=TargetKind.IPV4, normalized_value="10.0.0.1.")

    # TargetScopeRule validations
    with pytest.raises(ValueError, match="scope rule role must be canonical"):
        TargetScopeRule(role="not_a_role", kind=TargetKind.IPV4, normalized_value="10.0.0.1")  # type: ignore

    with pytest.raises(ValueError, match="scope rule kind/containment must be canonical"):
        TargetScopeRule(role=TargetRole.PRIMARY, kind="not_a_kind", normalized_value="10.0.0.1")  # type: ignore

    with pytest.raises(ValueError, match="scope rule target is not in canonical form"):
        TargetScopeRule(role=TargetRole.PRIMARY, kind=TargetKind.IPV4, normalized_value="example.com")

    # TargetScopeSnapshot rules not tuple
    with pytest.raises(ValueError, match="target scope rules must be an exact tuple"):
        TargetScopeSnapshot("2.0", 1, ("not_a_rule",))  # type: ignore

    # Role mismatch in _matches
    target_primary = TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY)
    rule_dest = TargetScopeRule(role=TargetRole.DESTINATION, kind=TargetKind.IPV4, normalized_value="10.0.0.1")
    assert TargetScopePolicy._matches(target_primary, rule_dest) is False
