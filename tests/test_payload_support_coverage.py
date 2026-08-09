"""Hermetic contracts for payload preparation and delivery support modules."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from modules.evasion.payload_keying import PayloadKeying, PayloadKeyingPlugin
from modules.persistence.systemd import SystemdPersistence

pytestmark = [pytest.mark.unit, pytest.mark.security]


def test_payload_keying_round_trips_every_environment_source(monkeypatch) -> None:
    keying = PayloadKeying()
    monkeypatch.setattr("modules.evasion.payload_keying.os.urandom", lambda size: b"n" * size)
    payload = b"fixture payload"

    cases = [
        (keying.key_to_hostname(payload, " Host-A "), keying._derive_key("host-a")),
        (keying.key_to_mac(payload, "AA-BB-CC-DD-EE-FF"), keying._derive_key("aa:bb:cc:dd:ee:ff")),
        (keying.key_to_user(payload, " Admin "), keying._derive_key("admin")),
        (keying.key_to_machine_id(payload, " machine-id \n"), keying._derive_key("machine-id")),
        (
            keying.key_to_multi(payload, "Host-A", "Admin", "AA:BB"),
            keying._derive_key("host-a|admin|aa:bb", salt="octopus_multi_v8"),
        ),
    ]

    assert all(keying._decrypt(encrypted, key) == payload for encrypted, key in cases)


@pytest.mark.parametrize(
    ("source", "needle", "salt"),
    [
        ("hostname", "socket.gethostname", "octopus_v8"),
        ("mac", "uuid.getnode", "octopus_v8"),
        ("user", "getpass.getuser", "octopus_v8"),
        ("machine_id", "/etc/machine-id", "octopus_v8"),
        ("multi", "socket, getpass, uuid", "octopus_multi_v8"),
        ("unknown", "socket.gethostname", "octopus_v8"),
    ],
)
def test_payload_loader_selects_source_and_embeds_ciphertext(
    source: str,
    needle: str,
    salt: str,
) -> None:
    loader = PayloadKeying().generate_loader(b"encrypted-fixture", source)

    assert needle in loader
    assert f'salt="{salt}"' in loader
    assert base64.b64encode(b"encrypted-fixture").decode() in loader


@pytest.mark.parametrize(
    ("target_info", "expected_source"),
    [
        ({"hostname": "host", "username": "user", "mac": "aa:bb"}, "multi"),
        ({"machine_id": "machine"}, "machine_id"),
        ({"hostname": "host"}, "hostname"),
        ({"username": "user"}, "user"),
    ],
)
def test_payload_keying_strategy_uses_best_available_identity(
    monkeypatch,
    target_info: dict,
    expected_source: str,
) -> None:
    keying = PayloadKeying()
    calls = []
    monkeypatch.setattr(keying, "key_to_multi", lambda payload, *args: calls.append(("multi", args)) or b"multi")
    monkeypatch.setattr(
        keying, "key_to_machine_id", lambda payload, value: calls.append(("machine_id", value)) or b"machine"
    )
    monkeypatch.setattr(keying, "key_to_hostname", lambda payload, value: calls.append(("hostname", value)) or b"host")
    monkeypatch.setattr(keying, "key_to_user", lambda payload, value: calls.append(("user", value)) or b"user")
    monkeypatch.setattr(
        keying,
        "generate_loader",
        lambda payload, source: calls.append(("loader", payload, source)) or f"loader:{source}",
    )

    keyed, loader = keying.key_payload_for_target(b"payload", target_info)

    assert calls[0][0] == expected_source
    assert calls[-1][-1] == expected_source
    assert keyed and loader == f"loader:{expected_source}"


def test_payload_keying_without_target_data_is_explicitly_unkeyed(capsys) -> None:
    payload = b"payload"
    assert PayloadKeying().key_payload_for_target(payload, {}) == (payload, "")
    assert "payload will be unkeyed" in capsys.readouterr().out


def test_payload_keying_plugin_validates_inputs_and_writes_optional_loader(
    monkeypatch,
    tmp_path,
) -> None:
    plugin = PayloadKeyingPlugin()
    assert plugin.run().error == "payload bytes or string are required"
    assert plugin.run(payload=b"x", target_info=[]).error == "target_info must be a dict"

    monkeypatch.setattr(
        PayloadKeying,
        "key_payload_for_target",
        lambda self, payload, target_info: (b"keyed", "loader source"),
    )
    output = tmp_path / "loader.py"
    result = plugin.run(
        payload="plaintext",
        target_info={"hostname": "host"},
        output_path=str(output),
    )
    assert result.success is True
    assert result.data == {
        "payload_len": 9,
        "keyed_payload_len": 5,
        "loader_len": 13,
        "keyed_payload_b64": base64.b64encode(b"keyed").decode("ascii"),
    }
    assert result.artifacts == [str(output)]
    assert output.read_text(encoding="utf-8") == "loader source"

    bytes_result = plugin.run(payload=b"bytes", target_info={})
    assert bytes_result.success is True
    assert bytes_result.artifacts == []


class SSHClient:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_systemd_persistence_validates_serializable_ssh_credentials(monkeypatch) -> None:
    plugin = SystemdPersistence()
    for kwargs in (
        {},
        {"target": "host", "password": "secret"},
        {"target": "host", "username": "user"},
    ):
        assert "Requires target" in plugin.run(**kwargs).error

    import core.killchain.ssh_helpers as ssh_helpers

    monkeypatch.setattr(
        ssh_helpers,
        "_ssh_connect",
        lambda host, user, password, port: (None, "connection refused"),
    )
    failed = plugin.run(target="host", user="user", pwd="secret", port="2222")
    assert failed.error == "SSH connection failed: connection refused"


def test_systemd_persistence_writes_enables_starts_and_closes_owned_client(monkeypatch) -> None:
    import core.killchain.ssh_helpers as ssh_helpers

    plugin = SystemdPersistence()
    client = SSHClient()
    connects = []
    commands = []
    monkeypatch.setattr(
        ssh_helpers,
        "_ssh_connect",
        lambda host, user, password, port: (
            connects.append((host, user, password, port)) or client,
            None,
        ),
    )
    monkeypatch.setattr(
        ssh_helpers,
        "_ssh_exec",
        lambda selected_client, command: commands.append((selected_client, command)) or "written",
    )

    result = plugin.run(
        target="host",
        username="user",
        password="secret",
        payload_path="/opt/agent",
        service_name="fixture.service",
    )

    assert result.success is True
    assert result.output == "written"
    assert result.data == {
        "service": "fixture.service",
        "path": "/etc/systemd/system/fixture.service",
        "target": "host",
    }
    assert connects == [("host", "user", "secret", 22)]
    decoded_service = base64.b64decode(commands[0][1].split("'")[3]).decode()
    assert "ExecStart=/opt/agent" in decoded_service
    assert [command for _client, command in commands[1:]] == [
        "systemctl daemon-reload",
        "systemctl enable fixture.service",
        "systemctl start fixture.service",
    ]
    assert client.closed is True


def test_systemd_persistence_reuses_external_client_and_contains_execution_errors(monkeypatch) -> None:
    import core.killchain.ssh_helpers as ssh_helpers

    client = SSHClient()
    monkeypatch.setattr(
        ssh_helpers,
        "_ssh_exec",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("write failed")),
    )

    result = SystemdPersistence().run(target="host", ssh_client=client)

    assert result.success is False
    assert result.error == "write failed"
    assert client.closed is False


def test_legacy_payload_agent_is_removed() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    assert not (repository_root / "payloads" / "agent.py").exists()
