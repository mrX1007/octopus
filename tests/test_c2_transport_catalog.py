"""Tests for the closed DNS-only C2 transport catalog."""

from __future__ import annotations

import pytest

from core.actions.input_contracts import C2ChannelCreateInputV2
from core.c2.transport_catalog import (
    C2Transport,
    C2TransportCatalog,
    C2TransportConfig,
    DNSChannelConfig,
    DNSRecordType,
    StaticC2TransportCatalog,
)

pytestmark = pytest.mark.unit


def test_c2_transport_config_is_dns_only_until_new_leaf() -> None:
    assert C2TransportConfig is DNSChannelConfig
    assert tuple(C2Transport) == (C2Transport.DNS,)
    assert tuple(DNSRecordType) == (DNSRecordType.TXT, DNSRecordType.A)


def test_static_transport_catalog_builds_exact_dns_child() -> None:
    catalog = StaticC2TransportCatalog()
    assert isinstance(catalog, C2TransportCatalog)
    config = DNSChannelConfig("c2.example.test", DNSRecordType.TXT, "127.0.0.1", 5353)
    request = C2ChannelCreateInputV2("host.example.test", C2Transport.DNS, config)
    route = catalog.require_route(C2Transport.DNS)
    child = catalog.build_child_input(request, route)
    assert child.target == request.target
    assert child.config is config
    assert route.child_action_id == "c2:dns_c2_channel"


def test_dns_channel_config_rejects_invalid_endpoint() -> None:
    with pytest.raises(ValueError, match="domain"):
        DNSChannelConfig("", DNSRecordType.TXT, "127.0.0.1", 5353)
    with pytest.raises(ValueError, match="listen_address"):
        DNSChannelConfig("c2.example.test", DNSRecordType.TXT, "not-an-ip", 5353)
    with pytest.raises(ValueError, match="listen_port"):
        DNSChannelConfig("c2.example.test", DNSRecordType.TXT, "127.0.0.1", 0)


def test_unknown_transport_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported C2 transport"):
        StaticC2TransportCatalog().require_route("dns")  # type: ignore[arg-type]
