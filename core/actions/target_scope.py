"""Canonical target models, normalization, and exact scope matching."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum


class TargetRole(str, Enum):
    PRIMARY = "primary"
    DESTINATION = "destination"
    HOP = "hop"
    LISTEN = "listen"
    CALLBACK = "callback"
    RESOURCE_BOUND = "resource_bound"


class TargetKind(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    FQDN = "fqdn"
    HOST = "host"
    NETWORK_ENDPOINT = "network_endpoint"
    RESOURCE_BOUND_TARGET = "resource_bound_target"


class NetworkProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    SMB = "smb"
    WINRM = "winrm"
    DCOM = "dcom"


@dataclass(frozen=True)
class ExtractedActionTarget:
    role: TargetRole
    kind: TargetKind
    normalized_value: str
    port: int | None = None
    protocol: NetworkProtocol | None = None

    def __post_init__(self) -> None:
        if type(self.role) is not TargetRole or type(self.kind) is not TargetKind:
            raise ValueError("target role and kind must be canonical enums")
        canonical = TargetScopeCanonicalizer.canonicalize(
            self.normalized_value,
            role=self.role,
            port=self.port,
            protocol=self.protocol,
            resource_bound=self.kind is TargetKind.RESOURCE_BOUND_TARGET,
        )
        if canonical != self:
            raise ValueError("target is not in canonical form")


def _new_canonical_target(
    *,
    role: TargetRole,
    kind: TargetKind,
    normalized_value: str,
    port: int | None,
    protocol: NetworkProtocol | None,
) -> ExtractedActionTarget:
    """Construct the value emitted by the sole canonicalizer without recursion."""

    instance = object.__new__(ExtractedActionTarget)
    object.__setattr__(instance, "role", role)
    object.__setattr__(instance, "kind", kind)
    object.__setattr__(instance, "normalized_value", normalized_value)
    object.__setattr__(instance, "port", port)
    object.__setattr__(instance, "protocol", protocol)
    return instance


@dataclass(frozen=True)
class TargetScopeRule:
    role: TargetRole | None
    kind: TargetKind
    normalized_value: str
    port: int | None = None
    protocol: NetworkProtocol | None = None
    allow_containment: bool = False

    def __post_init__(self) -> None:
        if self.role is not None and type(self.role) is not TargetRole:
            raise ValueError("scope rule role must be canonical")
        if type(self.kind) is not TargetKind or type(self.allow_containment) is not bool:
            raise ValueError("scope rule kind/containment must be canonical")
        canonical = TargetScopeCanonicalizer.canonicalize(
            self.normalized_value,
            role=self.role or TargetRole.PRIMARY,
            port=self.port,
            protocol=self.protocol,
            resource_bound=self.kind is TargetKind.RESOURCE_BOUND_TARGET,
        )
        if canonical.kind is not self.kind or canonical.normalized_value != self.normalized_value:
            raise ValueError("scope rule target is not in canonical form")
        if self.allow_containment and self.kind is not TargetKind.CIDR:
            raise ValueError("containment is supported only for canonical CIDR rules")


@dataclass(frozen=True)
class TargetScopeSnapshot:
    schema_version: str
    revision: int
    rules: tuple[TargetScopeRule, ...]

    def __post_init__(self) -> None:
        if self.schema_version != "2.0":
            raise ValueError("target scope schema version is unsupported")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("target scope revision must be positive")
        if type(self.rules) is not tuple or any(type(rule) is not TargetScopeRule for rule in self.rules):
            raise ValueError("target scope rules must be an exact tuple")
        if len(self.rules) != len(set(self.rules)):
            raise ValueError("target scope contains duplicate rules")


@dataclass(frozen=True)
class TargetScopeDecision:
    allowed: bool
    reason: str = ""


_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_REFERENCE_RE = re.compile(r"[a-z][a-z0-9-]*://[^\s\x00-\x1f]+\Z")


class TargetScopeCanonicalizer:
    @staticmethod
    def canonicalize(
        value: str,
        *,
        role: TargetRole,
        port: int | None = None,
        protocol: NetworkProtocol | None = None,
        resource_bound: bool = False,
    ) -> ExtractedActionTarget:
        if type(role) is not TargetRole:
            raise ValueError("target role must be canonical")
        if type(value) is not str or not value.strip():
            raise ValueError("target must be a non-empty string")
        normalized = value.strip()
        if isinstance(port, bool) or (port is not None and not 1 <= port <= 65535):
            raise ValueError("target port must be in 1..65535")
        if protocol is not None and type(protocol) is not NetworkProtocol:
            raise ValueError("target protocol must be canonical")

        if resource_bound or _REFERENCE_RE.fullmatch(normalized):
            if not _REFERENCE_RE.fullmatch(normalized):
                raise ValueError("resource-bound target must be an opaque reference")
            return _new_canonical_target(
                role=TargetRole.RESOURCE_BOUND if role is not TargetRole.RESOURCE_BOUND else role,
                kind=TargetKind.RESOURCE_BOUND_TARGET,
                normalized_value=normalized,
                port=port,
                protocol=protocol,
            )

        try:
            network = ipaddress.ip_network(normalized, strict=True)
        except ValueError:
            network = None
        if network is not None and "/" in normalized:
            return _new_canonical_target(
                role=role,
                kind=TargetKind.CIDR,
                normalized_value=network.with_prefixlen,
                port=port,
                protocol=protocol,
            )

        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            address = None
        if address is not None:
            kind = TargetKind.IPV4 if address.version == 4 else TargetKind.IPV6
            return _new_canonical_target(
                role=role,
                kind=kind,
                normalized_value=address.compressed,
                port=port,
                protocol=protocol,
            )

        if "." in normalized:
            try:
                ascii_name = normalized.rstrip(".").encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError("target FQDN is not valid IDNA") from exc
            labels = ascii_name.split(".")
            if len(ascii_name) > 253 or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(character.isalnum() or character == "-" for character in label)
                for label in labels
            ):
                raise ValueError("target FQDN is not canonical")
            return _new_canonical_target(
                role=role,
                kind=TargetKind.FQDN,
                normalized_value=ascii_name,
                port=port,
                protocol=protocol,
            )

        if not _HOST_RE.fullmatch(normalized):
            raise ValueError("target host is ambiguous")
        return _new_canonical_target(
            role=role,
            kind=TargetKind.HOST,
            normalized_value=normalized.casefold(),
            port=port,
            protocol=protocol,
        )


class TargetScopePolicy:
    @staticmethod
    def evaluate(
        targets: tuple[ExtractedActionTarget, ...],
        authorized_scope: TargetScopeSnapshot,
    ) -> TargetScopeDecision:
        if not authorized_scope.rules:
            return TargetScopeDecision(False, "empty_authorized_scope")
        for target in targets:
            if not any(TargetScopePolicy._matches(target, rule) for rule in authorized_scope.rules):
                return TargetScopeDecision(False, f"target_not_in_scope:{target.normalized_value}")
        return TargetScopeDecision(True, "target_in_scope")

    @staticmethod
    def _matches(target: ExtractedActionTarget, rule: TargetScopeRule) -> bool:
        if rule.role is not None and rule.role is not target.role:
            return False
        if rule.port != target.port or rule.protocol != target.protocol:
            return False
        if rule.kind is target.kind and rule.normalized_value == target.normalized_value:
            return True
        if not rule.allow_containment:
            return False
        if rule.kind is TargetKind.CIDR and target.kind in (TargetKind.IPV4, TargetKind.IPV6):
            try:
                return ipaddress.ip_address(target.normalized_value) in ipaddress.ip_network(
                    rule.normalized_value,
                    strict=True,
                )
            except ValueError:
                return False
        return False

    @staticmethod
    def validate_targets(
        targets: tuple[str, ...],
        authorized_scope: tuple[str, ...],
    ) -> TargetScopeDecision:
        """V1 compatibility wrapper using canonical exact FQDN/IP matching."""

        try:
            canonical_targets = tuple(
                TargetScopeCanonicalizer.canonicalize(target, role=TargetRole.PRIMARY) for target in targets
            )
            rules = tuple(
                TargetScopeRule(
                    role=None,
                    kind=canonical.kind,
                    normalized_value=canonical.normalized_value,
                )
                for canonical in (
                    TargetScopeCanonicalizer.canonicalize(scope, role=TargetRole.PRIMARY)
                    for scope in authorized_scope
                )
            )
        except ValueError:
            return TargetScopeDecision(False, "invalid_target_scope")
        return TargetScopePolicy.evaluate(canonical_targets, TargetScopeSnapshot("2.0", 1, rules))


__all__ = [
    "ExtractedActionTarget",
    "NetworkProtocol",
    "TargetKind",
    "TargetRole",
    "TargetScopeCanonicalizer",
    "TargetScopeDecision",
    "TargetScopePolicy",
    "TargetScopeRule",
    "TargetScopeSnapshot",
]
