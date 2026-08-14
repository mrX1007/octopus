"""Tests for ChannelCreateRouter."""

from __future__ import annotations

import pytest

from core.c2.channel_manager import ChannelCreateRouter, ChannelManager
from core.c2.channel_models import ChannelConfigV1, ChannelRecordV1, ChannelStateV1, ChannelTypeV1

pytestmark = pytest.mark.unit


class MockChannelProvider:
    def create_channel(self, config: ChannelConfigV1) -> ChannelRecordV1:
        return ChannelRecordV1(
            channel_id=config.channel_id,
            channel_type=config.channel_type,
            state=ChannelStateV1.ACTIVE,
            config_digest="custom_provider_digest",
            created_at=100.0,
            updated_at=100.0,
        )


def test_channel_create_router_default():
    mgr = ChannelManager()
    router = ChannelCreateRouter(mgr)
    cfg = ChannelConfigV1("c1", ChannelTypeV1.HTTP, "http://127.0.0.1:8080", "m1")

    rec = router.route_create(cfg)
    assert rec.channel_id == "c1"
    assert rec.state == ChannelStateV1.ACTIVE


def test_channel_create_router_custom_provider():
    mgr = ChannelManager()
    provider = MockChannelProvider()
    mgr.register_provider(ChannelTypeV1.DNS, provider)

    router = ChannelCreateRouter(mgr)
    cfg = ChannelConfigV1("c_dns", ChannelTypeV1.DNS, "dns.c2.local", "m1")

    rec = router.route_create(cfg)
    assert rec.config_digest == "custom_provider_digest"
