from __future__ import annotations

import os
import runpy
import sqlite3
import subprocess
from pathlib import Path
from typing import ClassVar

import pytest

from core.opsec import artifact_mgr, network
from core.opsec.artifact_mgr import ArtifactManager

pytestmark = pytest.mark.contract


def test_artifact_manager_default_path_is_repository_data(monkeypatch: pytest.MonkeyPatch) -> None:
    initialized: list[str] = []
    monkeypatch.setattr(
        ArtifactManager,
        "_init_schema",
        lambda self: initialized.append(self.db_path),
    )

    manager = ArtifactManager(target_ip="example")

    expected = Path(artifact_mgr.__file__).resolve().parents[2] / "data" / "c2.db"
    assert Path(manager.db_path) == expected
    assert initialized == [str(expected)]


def test_artifact_manager_lifecycle_is_target_scoped(tmp_path: Path) -> None:
    database = tmp_path / "artifacts.sqlite"
    manager = ArtifactManager(str(database), target_ip="192.0.2.10")
    other = ArtifactManager(str(database), target_ip="192.0.2.11")

    manager.record_file("/tmp/report.txt", "temporary report")
    manager.record_ssh_key("alice", "octopus-key")
    manager.record_cron("root", "octopus-cron")
    manager.record_process(4242, "temporary worker")
    other.record_file("/tmp/other.txt", "different target")

    pending = manager.get_pending_cleanups()
    assert {item["artifact_type"] for item in pending} == {
        "file",
        "ssh_key",
        "cron",
        "process",
    }
    assert {item["target_ip"] for item in pending} == {"192.0.2.10"}
    assert next(item for item in pending if item["artifact_type"] == "process")["marker"] == "4242"

    filtered = manager.get_all_artifacts("192.0.2.10")
    assert len(filtered) == 4
    assert len(manager.get_all_artifacts()) == 5

    manager.mark_cleaned("/tmp/report.txt")
    manager.mark_cleaned("4242")
    assert {item["artifact_type"] for item in manager.get_pending_cleanups()} == {
        "ssh_key",
        "cron",
    }

    manager.mark_all_cleaned()
    assert manager.get_pending_cleanups() == []
    assert other.get_pending_cleanups()[0]["path"] == "/tmp/other.txt"


def test_artifact_manager_rolls_back_and_closes_on_error(tmp_path: Path) -> None:
    manager = ArtifactManager(str(tmp_path / "rollback.sqlite"), target_ip="local")
    captured: sqlite3.Connection | None = None

    with pytest.raises(RuntimeError, match="abort transaction"), manager._get_conn() as connection:
        captured = connection
        connection.execute(
            """
                INSERT INTO artifacts (target_ip, artifact_type, timestamp)
                VALUES ('local', 'file', 'now')
                """
        )
        raise RuntimeError("abort transaction")

    assert manager.get_all_artifacts() == []
    assert captured is not None
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        captured.execute("SELECT 1")


class _FakeGoTransport:
    instances: ClassVar[list[_FakeGoTransport]] = []

    def __init__(self, *, go_binary: str, browser: str, policy: object) -> None:
        self.go_binary = go_binary
        self.browser = browser
        self.policy = policy
        self.calls: list[tuple[object, ...]] = []
        self.instances.append(self)

    def request(self, *args: object) -> dict[str, object]:
        self.calls.append(args)
        return {"transport": "go"}


class _FakePythonTransport:
    instances: ClassVar[list[_FakePythonTransport]] = []

    def __init__(self, *, policy: object) -> None:
        self.policy = policy
        self.calls: list[tuple[object, ...]] = []
        self.instances.append(self)

    def request(self, *args: object) -> dict[str, object]:
        self.calls.append(args)
        return {"transport": "python"}


def test_opsec_client_selects_transport_and_encodes_body(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeGoTransport.instances.clear()
    _FakePythonTransport.instances.clear()
    policy = object()
    profiles: list[str] = []
    compile_calls: list[tuple[str, str]] = []
    exists = iter((False, True))

    monkeypatch.setattr(network, "get_profile", lambda name: profiles.append(name) or policy)
    monkeypatch.setattr(network, "GoTLSTransport", _FakeGoTransport)
    monkeypatch.setattr(network, "PythonTransport", _FakePythonTransport)
    monkeypatch.setattr(network.os.path, "exists", lambda _path: next(exists))
    monkeypatch.setattr(
        network.OpsecClient,
        "_compile_go_client",
        lambda _self, base, binary: compile_calls.append((base, binary)),
    )

    compiled = network.OpsecClient(profile="stealth", browser="firefox", use_go_tls=True)
    existing = network.OpsecClient(profile="browser", browser="chrome", use_go_tls=True)
    python_client = network.OpsecClient(profile="scraper", use_go_tls=False)

    assert compiled.request("POST", "https://example.invalid", {"X-Test": "1"}, "payload", ignored=True) == {
        "transport": "go"
    }
    assert existing.request("GET", "https://example.invalid") == {"transport": "go"}
    assert python_client.request("GET", "https://example.invalid") == {"transport": "python"}
    assert compiled.transport is _FakeGoTransport.instances[0]
    assert _FakeGoTransport.instances[0].calls == [("POST", "https://example.invalid", {"X-Test": "1"}, b"payload")]
    assert _FakeGoTransport.instances[1].calls == [("GET", "https://example.invalid", None, None)]
    assert _FakePythonTransport.instances[0].calls == [("GET", "https://example.invalid", None, None)]
    assert profiles == ["stealth", "browser", "scraper"]
    assert len(compile_calls) == 1
    assert compile_calls[0][1].endswith(os.path.join("core", "opsec", "ja3_client"))


def test_compile_go_client_reports_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def succeed(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", succeed)
    client = object.__new__(network.OpsecClient)
    client._compile_go_client(str(tmp_path), str(tmp_path / "ja3_client"))

    assert calls == [
        (
            ["go", "build", "-o", str(tmp_path / "ja3_client"), str(tmp_path / "ja3_client.go")],
            {"check": True, "cwd": str(tmp_path), "timeout": 180},
        )
    ]
    assert capsys.readouterr().out == "[*] Compiling Go JA3 client...\n"

    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("no go")))
    client._compile_go_client(str(tmp_path), str(tmp_path / "ja3_client"))
    output = capsys.readouterr().out
    assert "[*] Compiling Go JA3 client..." in output
    assert "[!] Failed to compile JA3 client: no go" in output


def test_network_script_reports_error_and_success_without_network(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from core.transport import base, profiles

    responses = iter(
        (
            {"error": "offline"},
            {"error": "", "status_code": 204, "body": "x" * 250},
        )
    )

    class ScriptTransport:
        def __init__(self, *, policy: object) -> None:
            self.policy = policy

        def request(self, *_args: object) -> dict[str, object]:
            return next(responses)

    monkeypatch.setattr(base, "PythonTransport", ScriptTransport)
    monkeypatch.setattr(profiles, "get_profile", lambda _name: object())
    script = Path(network.__file__).resolve()

    runpy.run_path(str(script), run_name="__main__")
    first = capsys.readouterr().out
    assert "[*] Testing OpsecClient with Python transport..." in first
    assert "Error: offline" in first

    runpy.run_path(str(script), run_name="__main__")
    second = capsys.readouterr().out
    assert "Status: 204" in second
    assert f"Body: {'x' * 200}" in second
