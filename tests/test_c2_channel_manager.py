"""Tests for ChannelManager."""
from __future__ import annotations

import pytest
from core.c2.channel_manager import ChannelManager
from core.c2.channel_models import (
    ChannelConfigV1,
    ChannelRecordV1,
    ChannelStateV1,
    ChannelTypeV1,
)

pytestmark = pytest.mark.unit


def test_channel_manager_create_and_get():
    mgr = ChannelManager()
    cfg = ChannelConfigV1(
        channel_id="chan_1",
        channel_type=ChannelTypeV1.HTTP,
        endpoint="http://127.0.0.1:8080",
        mission_id="m1",
    )

    rec = mgr.create_channel(cfg)
    assert isinstance(rec, ChannelRecordV1)
    assert rec.channel_id == "chan_1"
    assert rec.state == ChannelStateV1.ACTIVE
    assert rec.config_digest != ""

    fetched = mgr.get_channel("chan_1")
    assert fetched is not None
    assert fetched.channel_id == "chan_1"


def test_channel_manager_list_and_filter():
    mgr = ChannelManager()
    mgr.create_channel(ChannelConfigV1("c1", ChannelTypeV1.DNS, "dns.local", "m1"))
    mgr.create_channel(ChannelConfigV1("c2", ChannelTypeV1.HTTP, "http.local", "m1"))
    mgr.create_channel(ChannelConfigV1("c3", ChannelTypeV1.SOCKET, "sock.local", "m2"))

    all_channels = mgr.list_channels()
    assert len(all_channels) == 3

    m1_channels = mgr.list_channels(mission_id="m1")
    assert len(m1_channels) == 2
    assert {c.channel_id for c in m1_channels} == {"c1", "c2"}


def test_channel_manager_update_state_and_close():
    mgr = ChannelManager()
    mgr.create_channel(ChannelConfigV1("c1", ChannelTypeV1.DNS, "dns.local", "m1"))

    updated = mgr.update_channel_state("c1", ChannelStateV1.DEGRADED)
    assert updated.state == ChannelStateV1.DEGRADED

    assert mgr.close_channel("c1") is True
    assert mgr.get_channel("c1").state == ChannelStateV1.CLOSED
