"""Closed C2 transport configuration and routing catalog."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from typing_extensions import TypeAlias

if TYPE_CHECKING:
    from core.actions.input_contracts import C2ChannelCreateInputV2, DNSC2ChannelInputV2


class DNSRecordType(str, Enum):
    TXT = "TXT"
    A = "A"


class C2Transport(str, Enum):
    DNS = "dns"


@dataclass(frozen=True)
class DNSChannelConfig:
    domain: str
    record_type: DNSRecordType
    listen_address: str
    listen_port: int

    def __post_init__(self) -> None:
        domain = self.domain.strip().rstrip(".").lower()
        if not domain or len(domain) > 253:
            raise ValueError("domain must be a non-empty bounded DNS name")
        labels = domain.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        ):
            raise ValueError("domain is not canonical")
        try:
            canonical_address = str(ipaddress.ip_address(self.listen_address.strip()))
        except ValueError as exc:
            raise ValueError("listen_address must be an IP address") from exc
        if isinstance(self.listen_port, bool) or not 1 <= self.listen_port <= 65535:
            raise ValueError("listen_port must be an integer in 1..65535")
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "listen_address", canonical_address)


C2TransportConfig: TypeAlias = DNSChannelConfig


@dataclass(frozen=True)
class C2TransportRoute:
    transport: C2Transport
    child_action_id: str
    child_input_schema_id: str


@runtime_checkable
class C2TransportCatalog(Protocol):
    def require_route(self, transport: C2Transport) -> C2TransportRoute: ...

    def build_child_input(
        self,
        request: C2ChannelCreateInputV2,
        route: C2TransportRoute,
    ) -> DNSC2ChannelInputV2: ...


class StaticC2TransportCatalog:
    """Production closed router table for the sole supported DNS leaf."""

    _DNS_ROUTE = C2TransportRoute(
        transport=C2Transport.DNS,
        child_action_id="c2:dns_c2_channel",
        child_input_schema_id="octopus:input:dns_c2_channel:2.0",
    )

    def require_route(self, transport: C2Transport) -> C2TransportRoute:
        if transport is not C2Transport.DNS:
            raise ValueError(f"unsupported C2 transport: {transport!r}")
        return self._DNS_ROUTE

    def build_child_input(
        self,
        request: C2ChannelCreateInputV2,
        route: C2TransportRoute,
    ) -> DNSC2ChannelInputV2:
        from core.actions.input_contracts import DNSC2ChannelInputV2

        expected = self.require_route(request.transport)
        if route != expected:
            raise ValueError("C2 route/schema mismatch")
        if type(request.config) is not DNSChannelConfig:
            raise ValueError("C2 transport config variant mismatch")
        return DNSC2ChannelInputV2(target=request.target, config=request.config)


__all__ = [
    "C2Transport",
    "C2TransportCatalog",
    "C2TransportConfig",
    "C2TransportRoute",
    "DNSChannelConfig",
    "DNSRecordType",
    "StaticC2TransportCatalog",
]
