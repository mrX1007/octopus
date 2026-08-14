"""Tests for DNS C2 channel provider and DNSChannel."""
from __future__ import annotations

import pytest
from core.c2.channels.dns import DNSChannel, _b32_encode_safe, _b32_decode_safe

pytestmark = pytest.mark.unit


def test_b32_safe_encode_decode():
    raw = b"Octopus C2 DNS Channel Payload 123"
    encoded = _b32_encode_safe(raw)
    assert "=" not in encoded
    assert encoded.islower()

    decoded = _b32_decode_safe(encoded)
    assert decoded == raw


def test_dns_channel_encode_decode_labels():
    channel = DNSChannel(domain="c2.local", record_type="TXT")
    data = b"Testing DNS Label Chunking Logic"
    labels = channel.encode_data(data)

    assert len(labels) > 0
    assert all(len(l) <= 63 for l in labels)

    reassembled = channel.decode_data(labels)
    assert reassembled == data


def test_dns_channel_beacon_and_queue_task():
    channel = DNSChannel(domain="c2.local")
    channel.queue_task("AGT-001", "t1", "whoami")

    task = channel.receive_task("AGT-001")
    assert task is not None
    assert task["task_id"] == "t1"
    assert task["command"] == "whoami"

    # Queue should now be empty
    assert channel.receive_task("AGT-001") is None


def test_dns_channel_invalid_record_type():
    with pytest.raises(ValueError, match="Unsupported record type"):
        DNSChannel(domain="c2.local", record_type="INVALID")
