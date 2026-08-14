"""Tests for ChannelReconciler."""
from __future__ import annotations

import pytest
from core.c2.channel_manager import ChannelManager
from core.c2.channel_reconciler import ChannelReconciler, ReconciliationReportV1
from core.c2.channel_models import ChannelConfigV1, ChannelTypeV1, ChannelStateV1

pytestmark = pytest.mark.unit


def test_channel_reconciler_create_missing():
    mgr = ChannelManager()
    reconciler = ChannelReconciler(mgr)

    desired = [
        ChannelConfigV1("c1", ChannelTypeV1.HTTP, "http://127.0.0.1:8080", "m1"),
        ChannelConfigV1("c2", ChannelTypeV1.DNS, "dns.c2.local", "m1"),
    ]

    report = reconciler.reconcile_channels(desired)
    assert isinstance(report, ReconciliationReportV1)
    assert set(report.created_channels) == {"c1", "c2"}
    assert len(mgr.list_channels()) == 2


def test_channel_reconciler_close_obsolete():
    mgr = ChannelManager()
    mgr.create_channel(ChannelConfigV1("c1", ChannelTypeV1.HTTP, "http://127.0.0.1:8080", "m1"))
    mgr.create_channel(ChannelConfigV1("c2", ChannelTypeV1.DNS, "dns.c2.local", "m1"))

    reconciler = ChannelReconciler(mgr)
    # Desired list only contains c1
    desired = [ChannelConfigV1("c1", ChannelTypeV1.HTTP, "http://127.0.0.1:8080", "m1")]

    report = reconciler.reconcile_channels(desired)
    assert "c2" in report.closed_channels
    assert mgr.get_channel("c2").state == ChannelStateV1.CLOSED


def test_channel_reconciler_degraded_probe_and_recovery():
    mgr = ChannelManager()
    healthy_channels = {"c1"}

    def custom_probe(config, record):
        return record.channel_id in healthy_channels

    reconciler = ChannelReconciler(mgr, probe_fn=custom_probe)

    cfg1 = ChannelConfigV1("c1", ChannelTypeV1.HTTP, "http://127.0.0.1:8080", "m1")
    cfg2 = ChannelConfigV1("c2", ChannelTypeV1.DNS, "dns.c2.local", "m1")
    mgr.create_channel(cfg1)
    mgr.create_channel(cfg2)

    report = reconciler.reconcile_channels([cfg1, cfg2])
    assert "c2" in report.degraded_channels
    assert mgr.get_channel("c2").state == ChannelStateV1.DEGRADED

    # Mark c2 healthy now and recover
    healthy_channels.add("c2")
    assert reconciler.recover_channel("c2") is True
    assert mgr.get_channel("c2").state == ChannelStateV1.ACTIVE
