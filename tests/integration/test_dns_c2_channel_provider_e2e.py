"""E2E tests for DNS C2 channel provider."""
from __future__ import annotations

import time
import pytest
from core.c2.channels.dns import DNSChannel, _b32_encode_safe, _b32_decode_safe
from core.c2.channel_manager import ChannelManager
from core.c2.channel_models import ChannelConfigV1, ChannelTypeV1, ChannelStateV1

pytestmark = pytest.mark.unit


def test_dns_channel_e2e_encode_send_receive():
    channel = DNSChannel(domain="c2dns.local", record_type="TXT")

    # Queue task for agent
    channel.queue_task(agent_id="agt_e2e", task_id="task_dns_1", command="whoami")

    # Receive task
    task = channel.receive_task(agent_id="agt_e2e")
    assert task is not None
    assert task["task_id"] == "task_dns_1"
    assert task["command"] == "whoami"


def test_dns_channel_e2e_data_chunking_reconstruction():
    channel = DNSChannel(domain="c2dns.local")
    original_data = b"Sensitive Exfiltration Payload Content " * 10

    labels = channel.encode_data(original_data)
    assert len(labels) > 0

    reconstructed = channel.decode_data(labels)
    assert reconstructed == original_data


def test_dns_channel_e2e_manager_integration():
    mgr = ChannelManager()
    cfg = ChannelConfigV1(
        channel_id="dns_chan_e2e",
        channel_type=ChannelTypeV1.DNS,
        endpoint="dns.c2.local",
        mission_id="m_dns_e2e",
        parameters={"domain": "c2dns.local", "record_type": "TXT"},
    )
    rec = mgr.create_channel(cfg)
    assert rec.state == ChannelStateV1.ACTIVE

    channel_instance = DNSChannel(domain=cfg.parameters["domain"], record_type=cfg.parameters["record_type"])
    channel_instance.queue_task("agent_1", "t1", "hostname")
    t = channel_instance.receive_task("agent_1")
    assert t["command"] == "hostname"
