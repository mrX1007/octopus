"""Unit tests for modules/evasion/payload_keying.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from modules.evasion.payload_keying import PayloadKeying, PayloadKeyingPlugin

pytestmark = pytest.mark.unit


def test_payload_keying_direct_methods():
    pk = PayloadKeying()
    payload = b"print('SECRET PAYLOAD')"

    # Hostname keying
    keyed_host = pk.key_to_hostname(payload, "TargetHost")
    assert keyed_host != payload
    key_host = pk._derive_key("targethost")
    assert pk._decrypt(keyed_host, key_host) == payload

    # MAC keying
    keyed_mac = pk.key_to_mac(payload, "00-11-22-33-44-55")
    assert keyed_mac != payload
    key_mac = pk._derive_key("00:11:22:33:44:55")
    assert pk._decrypt(keyed_mac, key_mac) == payload

    # User keying
    keyed_user = pk.key_to_user(payload, "Alice")
    assert keyed_user != payload
    key_user = pk._derive_key("alice")
    assert pk._decrypt(keyed_user, key_user) == payload

    # Machine ID keying
    keyed_mid = pk.key_to_machine_id(payload, "mid123")
    assert keyed_mid != payload
    key_mid = pk._derive_key("mid123")
    assert pk._decrypt(keyed_mid, key_mid) == payload

    # Multi keying
    keyed_multi = pk.key_to_multi(payload, "TargetHost", "Alice", "00-11-22-33-44-55")
    assert keyed_multi != payload
    key_multi = pk._derive_key("targethost|alice|00-11-22-33-44-55", salt="octopus_multi_v8")
    assert pk._decrypt(keyed_multi, key_multi) == payload


def test_generate_loader_all_sources():
    pk = PayloadKeying()
    payload = b"print('TEST')"
    keyed = pk.key_to_hostname(payload, "host")

    for src in ("hostname", "mac", "user", "machine_id", "multi", "unknown"):
        loader = pk.generate_loader(keyed, key_source=src)
        assert "PAYLOAD_B64" in loader
        assert "_derive_key" in loader


def test_key_payload_for_target():
    pk = PayloadKeying()
    payload = b"print('TARGET TEST')"

    # Multi
    k1, l1 = pk.key_payload_for_target(payload, {"hostname": "host", "username": "user", "mac": "00:11:22:33:44:55"})
    assert k1 != payload
    assert "octopus_multi_v8" in l1

    # Machine id
    k2, l2 = pk.key_payload_for_target(payload, {"machine_id": "mid123"})
    assert k2 != payload
    assert l2 != ""

    # Hostname only
    k3, l3 = pk.key_payload_for_target(payload, {"hostname": "host"})
    assert k3 != payload
    assert l3 != ""

    # User only
    k4, l4 = pk.key_payload_for_target(payload, {"username": "user"})
    assert k4 != payload
    assert l4 != ""

    # Empty target info
    k5, l5 = pk.key_payload_for_target(payload, {})
    assert k5 == payload
    assert l5 == ""


def test_payload_keying_plugin(tmp_path: Path):
    plugin = PayloadKeyingPlugin()

    # Missing payload
    assert plugin.run().success is False

    # Invalid target info type
    assert plugin.run(payload=b"test", target_info=123).success is False

    # JSON string target info
    out_file = tmp_path / "loader.py"
    res = plugin.run(
        payload="print('test')",
        target_info=json.dumps({"hostname": "target1"}),
        output_path=str(out_file),
    )
    assert res.success is True
    assert out_file.exists()
    assert "PAYLOAD_B64" in out_file.read_text()

    # Bad JSON target info fallback to empty
    res_bad_json = plugin.run(payload=b"test", target_info="{bad_json")
    assert res_bad_json.success is True
