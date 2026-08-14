"""E2E tests for C2 channel create router."""

from __future__ import annotations

import pytest

from core.c2.channel_manager import ChannelCreateRouter, ChannelManager
from core.c2.channel_models import ChannelConfigV1, ChannelStateV1, ChannelTypeV1
from core.c2.channel_reconciler import ChannelReconciler

pytestmark = pytest.mark.unit


def test_channel_create_router_e2e_full_routing():
    mgr = ChannelManager()
    router = ChannelCreateRouter(mgr)

    cfg_http = ChannelConfigV1("c_http", ChannelTypeV1.HTTP, "http://c2.local", "m1")
    cfg_dns = ChannelConfigV1("c_dns", ChannelTypeV1.DNS, "dns.c2.local", "m1")
    cfg_socket = ChannelConfigV1("c_sock", ChannelTypeV1.SOCKET, "unix:///tmp/c2.sock", "m1")

    r1 = router.route_create(cfg_http)
    r2 = router.route_create(cfg_dns)
    r3 = router.route_create(cfg_socket)

    assert r1.state == ChannelStateV1.ACTIVE
    assert r2.state == ChannelStateV1.ACTIVE
    assert r3.state == ChannelStateV1.ACTIVE

    channels = mgr.list_channels(mission_id="m1")
    assert len(channels) == 3


def test_channel_create_router_reconciliation_integration():
    mgr = ChannelManager()
    router = ChannelCreateRouter(mgr)
    reconciler = ChannelReconciler(mgr)

    desired_configs = [
        ChannelConfigV1("c_http", ChannelTypeV1.HTTP, "http://c2.local", "m1"),
        ChannelConfigV1("c_dns", ChannelTypeV1.DNS, "dns.c2.local", "m1"),
    ]

    for cfg in desired_configs:
        router.route_create(cfg)

    report = reconciler.reconcile_channels(desired_configs)
    assert len(report.created_channels) == 0
    assert len(report.closed_channels) == 0
    assert len(report.unchanged_channels) == 2


def test_channel_create_router_traffic_recording():
    mgr = ChannelManager()
    router = ChannelCreateRouter(mgr)
    cfg = ChannelConfigV1("c_traffic", ChannelTypeV1.HTTP, "http://c2.local", "m1")

    rec = router.route_create(cfg)
    assert rec.bytes_sent == 0

    updated = mgr.record_traffic("c_traffic", bytes_sent=1024, bytes_received=2048)
    assert updated.bytes_sent == 1024
    assert updated.bytes_received == 2048
