"""Contract coverage for payload generation and persistence primitives."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from modules.persistence.systemd import SystemdPersistence

pytestmark = pytest.mark.unit


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


@pytest.mark.unit
def test_systemd_persistence_with_credential_handle(monkeypatch) -> None:
    plugin = SystemdPersistence()
    client = SSHClient()

    ref = SimpleNamespace(
        handle="credential://default/ssh/10.0.0.1/admin",
        username="admin",
    )

    with patch("core.credentials.is_credential_handle", return_value=True):
        with patch("core.credentials.resolve_credential_handle", return_value=ref):
            with patch(
                "core.credentials.call_credential_provider",
                side_effect=lambda cred, fn: fn(SimpleNamespace(username="admin", password="pwd")),
            ):
                with patch("core.killchain.ssh_helpers._ssh_connect", return_value=(client, None)):
                    with patch("core.killchain.ssh_helpers._ssh_exec", return_value="written"):
                        res = plugin.run(target="10.0.0.1", credential_ref="credential://default/ssh/10.0.0.1/admin")
                        assert res.success is True


def test_legacy_payload_agent_is_removed() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    assert not (repository_root / "payloads" / "agent.py").exists()
