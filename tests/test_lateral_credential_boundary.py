"""Secret-boundary contracts for internal inventory and legacy C2 removal."""

from __future__ import annotations

from typing import Any

import pytest

from core.c2.protocol import C2_PROTOCOL_VERSION
from core.killchain import lateral

pytestmark = [pytest.mark.contract, pytest.mark.security]

CANARY = "S3cr3t-PASS-canary"


class _Client:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_legacy_c2_deployment_is_fail_closed_before_ssh(monkeypatch) -> None:
    monkeypatch.setattr(
        lateral,
        "_ssh_connect",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not connect")),
    )

    missing = lateral.deploy_c2_beacon("target", "alice", CANARY)
    invalid = lateral.deploy_c2_beacon(
        "target",
        "alice",
        CANARY,
        callback_host="https://callback/path",
    )
    blocked = lateral.deploy_c2_beacon(
        "target",
        "alice",
        CANARY,
        callback_host="callback.example",
    )

    assert "explicit callback_host" in missing
    assert "one host" in invalid
    assert f"protocol v{C2_PROTOCOL_VERSION}" in blocked
    assert "build_go_implant" in blocked
    assert CANARY not in blocked


def test_lateral_inventory_never_harvests_replays_or_retains_credentials(monkeypatch) -> None:
    client = _Client()
    connections: list[tuple[Any, ...]] = []
    commands: list[str] = []

    def connect(*args: Any, **_kwargs: Any):
        connections.append(args)
        return client, ""

    def execute(_client: _Client, command: str, **_kwargs: Any) -> str:
        commands.append(command)
        if command.startswith("arp"):
            return "? (10.0.0.2) at 00:11:22:33:44:55"
        if command.startswith("cat /etc/hosts"):
            return "10.0.0.3 internal\n127.0.0.1 localhost"
        if command.startswith("ip -4 route"):
            return "10.0.0.0/24 dev eth0 src 10.0.0.4"
        return f"LISTEN service accidentally echoed {CANARY}"

    monkeypatch.setattr(lateral, "_ssh_connect", connect)
    monkeypatch.setattr(lateral, "_ssh_exec", execute)

    output = lateral.lateral_move(
        "10.0.0.1",
        "alice",
        CANARY,
        extra_creds=[{"user": "root", "password": "another-secret"}],
    )

    assert len(connections) == 1
    assert client.closed is True
    assert CANARY not in output
    assert "another-secret" not in output
    assert "[REDACTED]" in output
    assert "10.0.0.2" in output and "10.0.0.3" in output
    assert "Credential harvesting and credential replay are disabled" in output

    rendered = "\n".join(commands)
    assert CANARY not in rendered
    for forbidden in (
        "password",
        ".bash_history",
        "/proc/*/environ",
        "id_rsa",
        "id_ed25519",
        ".env",
        "/dev/tcp",
        "seq 1 254",
    ):
        assert forbidden not in rendered
