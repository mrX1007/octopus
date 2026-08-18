"""Security contracts for target-scoped, registry-only cleanup."""

from __future__ import annotations

from typing import Any

import pytest

from core.killchain import cleanup

pytestmark = [pytest.mark.contract, pytest.mark.security]


class _Client:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_cleanup_is_noop_without_registered_artifacts(monkeypatch) -> None:
    constructed: list[str] = []

    class Manager:
        def __init__(self, *, target_ip: str) -> None:
            constructed.append(target_ip)

        @staticmethod
        def get_pending_cleanups() -> list[dict[str, Any]]:
            return []

    monkeypatch.setattr(cleanup, "ArtifactManager", Manager)
    monkeypatch.setattr(
        cleanup,
        "_ssh_connect",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not connect")),
    )

    result = cleanup.stealth_cleanup("192.0.2.10", "alice", "credential")

    assert constructed == ["192.0.2.10"]
    assert "No registered artifacts" in result


def test_cleanup_ssh_connection_failed(monkeypatch) -> None:
    class Manager:
        def __init__(self, *, target_ip: str) -> None:
            pass

        @staticmethod
        def get_pending_cleanups() -> list[dict[str, Any]]:
            return [{"artifact_id": 1, "type": "file", "path": "/tmp/test"}]

    monkeypatch.setattr(cleanup, "ArtifactManager", Manager)
    monkeypatch.setattr(cleanup, "_ssh_connect", lambda *_args, **_kwargs: (None, "Connection timeout"))

    res = cleanup.stealth_cleanup("192.0.2.10", "alice", "credential")
    assert "SSH connection failed" in res


def test_cleanup_root_authorized_keys_and_edge_paths() -> None:
    cmd, desc = cleanup._artifact_command(
        {"artifact_id": 10, "type": "ssh_key", "marker": "root-key", "user": "root"}, "root"
    )
    assert "$HOME/.ssh/authorized_keys" in cmd

    # invalid user
    cmd2, desc2 = cleanup._artifact_command(
        {"artifact_id": 11, "type": "file", "path": "/tmp/a", "user": "invalid user!"}, "alice"
    )
    assert cmd2 == ""
    assert "invalid user" in desc2

    # invalid bashrc path
    cmd3, desc3 = cleanup._artifact_command(
        {"artifact_id": 12, "type": "file_line", "path": "/etc/profile", "marker": "m", "user": "alice"}, "alice"
    )
    assert cmd3 == ""


def test_cleanup_executes_only_exact_registered_records(monkeypatch) -> None:
    pending = [
        {
            "artifact_id": 1,
            "artifact_type": "file",
            "path": "/var/tmp/safe file;touch-not-run",
            "user": "alice",
        },
        {
            "artifact_id": 2,
            "artifact_type": "ssh_key",
            "marker": "octopus-key-marker",
            "user": "alice",
        },
        {
            "artifact_id": 3,
            "artifact_type": "cron",
            "marker": "octopus-persistence",
            "user": "alice",
        },
        {
            "artifact_id": 4,
            "artifact_type": "file_line",
            "path": "~/.bashrc",
            "marker": "octopus-persistence",
            "user": "alice",
        },
        {
            "artifact_id": 5,
            "artifact_type": "process",
            "marker": "4242",
            "user": "alice",
        },
        {
            "artifact_id": 6,
            "artifact_type": "file",
            "path": "/var/tmp/fails-cleanup",
            "user": "alice",
        },
        {
            "artifact_id": 7,
            "artifact_type": "unknown",
            "path": "/var/tmp/must-not-run",
            "user": "alice",
        },
        {
            "artifact_id": 8,
            "artifact_type": "file",
            "path": "/var/tmp/injected\nrm -f /etc/passwd",
            "user": "alice",
        },
    ]
    marked: list[int] = []
    manager_targets: list[str] = []

    class Manager:
        def __init__(self, *, target_ip: str) -> None:
            manager_targets.append(target_ip)

        @staticmethod
        def get_pending_cleanups() -> list[dict[str, Any]]:
            return pending

        @staticmethod
        def mark_cleaned_by_id(artifact_id: int) -> None:
            marked.append(artifact_id)

    client = _Client()
    commands: list[str] = []

    def ssh_exec(_client: _Client, command: str, **_kwargs: Any) -> str:
        commands.append(command)
        if "fails-cleanup" in command:
            return cleanup._FAILURE_SENTINEL
        return cleanup._SUCCESS_SENTINEL

    monkeypatch.setattr(cleanup, "ArtifactManager", Manager)
    monkeypatch.setattr(cleanup, "_ssh_connect", lambda *_args, **_kwargs: (client, ""))
    monkeypatch.setattr(cleanup, "_ssh_exec", ssh_exec)

    result = cleanup.stealth_cleanup("192.0.2.10", "alice", "credential")

    assert manager_targets == ["192.0.2.10"]
    assert marked == [1, 2, 3, 4, 5]
    assert client.closed is True
    assert "Still pending: 3" in result

    rendered = "\n".join(commands)
    assert "'/var/tmp/safe file;touch-not-run'" in rendered
    assert "/var/tmp/must-not-run" not in rendered
    assert "/etc/passwd" not in rendered
    for forbidden in (
        "/var/log",
        "journalctl",
        "history -c",
        ".bash_history",
        "find /home",
        "*.log",
        "octopus*",
    ):
        assert forbidden not in rendered


def test_artifact_command_rejects_cross_user_and_unstable_records() -> None:
    cross_user = {
        "artifact_id": 1,
        "artifact_type": "ssh_key",
        "marker": "marker",
        "user": "bob",
    }
    missing_id = {
        "artifact_type": "file",
        "path": "/var/tmp/example",
        "user": "alice",
    }

    assert cleanup._artifact_command(cross_user, "alice")[0] == ""
    assert cleanup._artifact_command(missing_id, "alice")[0] == ""
