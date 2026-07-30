from __future__ import annotations

import logging
import os
import signal
import stat
import subprocess
import textwrap
import types
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

import pytest

from core.plugins import loader, protocol
from core.plugins.base import CheckResult, KillChainStage, PluginContext, PluginResult, PluginType
from core.plugins.events import PluginEventBus
from core.plugins.loader import PluginDescriptor, PluginManager, _WorkerReply
from core.plugins.protocol import WireError
from core.secrets import reset_default_secret_store_for_tests

pytestmark = pytest.mark.contract


@pytest.fixture(autouse=True)
def _isolated_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    reset_default_secret_store_for_tests()
    monkeypatch.setenv("OCTOPUS_SECRET_STORE", str(tmp_path / "loader-secrets.db"))
    yield
    reset_default_secret_store_for_tests()


def _bare_manager(*, event_bus: Any = None) -> PluginManager:
    manager = object.__new__(PluginManager)
    manager.modules_dir = "modules"
    manager.plugins = {}
    manager.skipped_plugins = {}
    manager.event_bus = event_bus if event_bus is not None else PluginEventBus()
    manager._conflicted_names = set()
    manager._descriptors_by_path = {}
    return manager


def _descriptor(name: str = "sample", **changes: Any) -> PluginDescriptor:
    values: dict[str, Any] = {
        "name": name,
        "path": f"/plugins/{name}.py",
        "root": "/plugins",
        "module": name,
    }
    values.update(changes)
    return PluginDescriptor(**values)


class _IdentityRedactor:
    def __init__(self) -> None:
        self.protected: list[tuple[Any, str]] = []
        self.redacted: list[tuple[Any, str | None]] = []

    def protect(self, value: Any, *, kind: str) -> str:
        self.protected.append((value, kind))
        return f"secret://{kind}/{len(self.protected)}"

    def redact_data(self, value: Any, *, field: str | None = None) -> Any:
        self.redacted.append((value, field))
        if is_dataclass(value) and not isinstance(value, type):
            return asdict(value)
        return value

    def redact_text(self, value: Any, *, kind: str) -> str:
        return "" if value is None else str(value)


class _FakeProcess:
    def __init__(
        self,
        outcomes: list[Any],
        *,
        returncode: int | None = 0,
        poll_result: int | None = None,
    ) -> None:
        self.outcomes = list(outcomes)
        self.returncode = returncode
        self.poll_result = poll_result
        self.pid = 4321
        self.communications: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.terminated = 0
        self.killed = 0

    def communicate(self, *args: Any, **kwargs: Any) -> tuple[bytes, bytes]:
        self.communications.append((args, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def poll(self) -> int | None:
        return self.poll_result

    def terminate(self) -> None:
        self.terminated += 1

    def kill(self) -> None:
        self.killed += 1


def _write_plugin(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.py"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def test_manager_initialization_descriptors_and_static_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    discoveries: list[str] = []
    monkeypatch.setattr(PluginManager, "discover", lambda self: discoveries.append(self.modules_dir))
    default = PluginManager("default-modules")
    custom_bus = PluginEventBus()
    custom = PluginManager("custom-modules", event_bus=custom_bus)

    assert isinstance(default.event_bus, PluginEventBus)
    assert custom.event_bus is custom_bus
    assert discoveries == ["default-modules", "custom-modules"]
    assert default.plugins == {}
    assert default.skipped_plugins == {}
    assert default._conflicted_names == set()
    assert default._descriptors_by_path == {}

    descriptor = PluginDescriptor("name", "/root/name.py", "/root", "name")
    assert descriptor.version == "0.0.0"
    assert descriptor.plugin_type == "auxiliary"
    assert descriptor.kill_chain_stage == 1
    assert descriptor.requires == []
    assert descriptor.depends_on == []
    assert _WorkerReply().payload == {}
    assert PluginManager._module_label("/root/example.plugin.py") == "example.plugin"
    assert PluginManager._worker_command() == [os.sys.executable, "-m", "core.plugins.worker"]
    assert Path(PluginManager._project_root()) == Path(loader.__file__).resolve().parents[2]


def test_real_worker_discovery_check_and_execution_are_hermetic(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins"
    _write_plugin(
        plugin_dir,
        "hermetic",
        """
        from core.plugins.base import CheckResult, OctopusPlugin, PluginResult

        class HermeticPlugin(OctopusPlugin):
            name = "hermetic"
            version = "2.0.0"

            def check(self, target, **kwargs):
                return CheckResult(vulnerable=target == "local.test", confidence=0.75)

            def run(self, **kwargs):
                return PluginResult(success=True, data={"echo": kwargs.get("value")})
        """,
    )

    manager = PluginManager(str(plugin_dir))
    assert manager.get_instance("hermetic") is manager.get_plugin("hermetic")
    assert manager.list_plugins()[0]["version"] == "2.0.0"
    assert manager.check("hermetic", "local.test", timeout=5).vulnerable is True
    assert manager.execute("hermetic", timeout=5, value="ok").data == {"echo": "ok"}


def test_safe_root_and_real_file_iteration_reject_symlinks(tmp_path: Path) -> None:
    manager = _bare_manager()
    root = tmp_path / "plugins"
    nested = root / "nested"
    nested.mkdir(parents=True)
    valid = _write_plugin(nested, "valid", "VALUE = 1")
    (root / "__init__.py").write_text("", encoding="utf-8")
    (root / "notes.txt").write_text("ignored", encoding="utf-8")
    outside = _write_plugin(tmp_path / "outside", "linked", "VALUE = 2")
    linked_file = root / "linked.py"
    linked_directory = root / "linked-dir"
    try:
        linked_file.symlink_to(outside)
        linked_directory.symlink_to(outside.parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")

    assert PluginManager._safe_root(str(root)) == str(root.resolve())
    assert PluginManager._safe_root(str(tmp_path / "missing")) is None
    discovered = list(manager._iter_plugin_files(str(root)))
    assert discovered == [(str(root.resolve()), str(valid.resolve()))]
    assert manager.skipped_plugins["linked"] == "symlinked plugin paths are not allowed"
    assert list(manager._iter_plugin_files(str(tmp_path / "missing"))) == []


@pytest.mark.parametrize("failure", (OSError("gone"), ValueError("invalid")))
def test_file_iteration_fails_closed_for_path_anomalies(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    manager = _bare_manager()
    root = "/safe"
    files = ["alias.py", "broken.py", "directory.py", "valid.py"]
    monkeypatch.setattr(manager, "_safe_root", lambda _path: root)
    monkeypatch.setattr(loader.os, "walk", lambda *_args, **_kwargs: [(root, [], files)])
    monkeypatch.setattr(loader.os.path, "islink", lambda _path: False)

    def realpath(path: str) -> str:
        return "/outside/alias.py" if path.endswith("alias.py") else path

    def lstat(path: str) -> types.SimpleNamespace:
        if path.endswith("broken.py"):
            raise failure
        mode = stat.S_IFDIR if path.endswith("directory.py") else stat.S_IFREG
        return types.SimpleNamespace(st_mode=mode)

    monkeypatch.setattr(loader.os.path, "realpath", realpath)
    monkeypatch.setattr(loader.os, "lstat", lstat)
    assert list(manager._iter_plugin_files(root)) == [(root, "/safe/valid.py")]
    assert manager.skipped_plugins == {
        "alias": "symlinked plugin paths are not allowed",
        "broken": "plugin path escapes its discovery root",
        "directory": "plugin path escapes its discovery root",
    }


def test_discover_uses_default_or_explicit_dirs_and_skips_known_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _bare_manager()
    manager.modules_dir = "default"
    manager._descriptors_by_path["/known.py"] = ["known"]
    seen_dirs: list[str] = []
    discovered: list[tuple[str, str]] = []

    def iter_files(search_dir: str):
        seen_dirs.append(search_dir)
        yield f"/{search_dir}", "/known.py"
        yield f"/{search_dir}", f"/{search_dir}.py"

    monkeypatch.setattr(manager, "_iter_plugin_files", iter_files)
    monkeypatch.setattr(manager, "_discover_file", lambda root, path: discovered.append((root, path)))
    manager.discover()
    manager.discover(["one", "two"])

    assert seen_dirs == ["default", "one", "two"]
    assert discovered == [
        ("/default", "/default.py"),
        ("/one", "/one.py"),
        ("/two", "/two.py"),
    ]


@pytest.mark.parametrize(
    ("reply", "expected", "logs"),
    (
        (_WorkerReply(timed_out=True), "discovery timed out after 15s", True),
        (_WorkerReply(error_type="ImportError"), "plugin discovery worker failed", False),
        (_WorkerReply(error="worker crashed", error_type="RuntimeError"), "worker crashed", True),
    ),
)
def test_discover_file_records_worker_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    reply: _WorkerReply,
    expected: str,
    logs: bool,
) -> None:
    manager = _bare_manager()
    monkeypatch.setattr(manager, "_invoke_worker", lambda *_args, **_kwargs: reply)

    with caplog.at_level(logging.DEBUG):
        manager._discover_file("/plugins", "/plugins/broken.py")

    assert manager.skipped_plugins["broken"] == expected
    assert manager._descriptors_by_path["/plugins/broken.py"] == []
    assert ("Failed to discover plugin" in caplog.text) is logs


def test_discover_file_rejects_invalid_response_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _bare_manager()
    replies = iter(
        (
            _WorkerReply(ok=True, payload={"plugins": {}}),
            _WorkerReply(ok=True, payload={"plugins": ["not-an-object"]}),
            _WorkerReply(ok=True, payload={"plugins": [{"name": "same"}, {"name": "same"}]}),
        )
    )
    monkeypatch.setattr(manager, "_invoke_worker", lambda *_args, **_kwargs: next(replies))

    manager._discover_file("/plugins", "/plugins/shape.py")
    manager._discover_file("/plugins", "/plugins/object.py")
    manager._discover_file("/plugins", "/plugins/duplicate.py")

    assert manager.skipped_plugins == {
        "shape": "invalid discovery response",
        "object": "plugin metadata must be an object",
        "duplicate": "duplicate plugin name 'same' in /plugins/duplicate.py",
    }


def test_discover_file_builds_and_registers_complete_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _bare_manager()
    payload = {
        "plugins": [
            {
                "name": "complete",
                "version": 3,
                "type": "recon",
                "stage": 2,
                "description": 7,
                "author": 8,
                "requires": ["nmap"],
                "depends_on": ["base"],
                "python_deps": ["package"],
                "capabilities": ["network"],
                "hooks": ["on_session_opened"],
            }
        ]
    }
    monkeypatch.setattr(manager, "_invoke_worker", lambda *_args, **_kwargs: _WorkerReply(ok=True, payload=payload))
    manager._discover_file("/plugins", "/plugins/complete.py")

    descriptor = manager.plugins["complete"]
    assert descriptor.version == "3"
    assert descriptor.plugin_type == "recon"
    assert descriptor.kill_chain_stage == 2
    assert descriptor.description == "7"
    assert descriptor.author == "8"
    assert descriptor.requires == ["nmap"]
    assert descriptor.depends_on == ["base"]
    assert descriptor.python_deps == ["package"]
    assert descriptor.capabilities == ["network"]
    assert descriptor.hooks == ["on_session_opened"]
    assert manager._descriptors_by_path["/plugins/complete.py"] == ["complete"]


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        ({"name": 7}, "invalid name"),
        ({"name": ""}, "invalid name"),
        ({"name": "base_plugin"}, "invalid name"),
        ({"name": "x", "stage": True}, "stage.*integer"),
        ({"name": "x", "stage": "one"}, "stage.*integer"),
        ({"name": "x", "type": 7}, "type.*string"),
        ({"name": "x", "requires": "nmap"}, "requires.*list"),
        ({"name": "x", "requires": ["nmap", 7]}, "requires.*contain strings"),
    ),
)
def test_descriptor_metadata_validation(raw: dict[str, Any], message: str) -> None:
    manager = _bare_manager()
    with pytest.raises(ValueError, match=message):
        manager._descriptor_from_payload(raw, "/root", "/root/x.py", "x")


def test_descriptor_registration_fails_closed_across_files() -> None:
    manager = _bare_manager()
    first = _descriptor("duplicate", path="/a.py", module="one")
    same_path = _descriptor("duplicate", path="/a.py", module="one-new", version="2")
    second = _descriptor("duplicate", path="/b.py", module="two")
    third = _descriptor("duplicate", path="/c.py", module="three")

    manager._register_descriptor(first)
    manager._register_descriptor(same_path)
    assert manager.plugins["duplicate"].version == "2"
    manager._register_descriptor(second)
    assert "duplicate" not in manager.plugins
    assert manager.skipped_plugins["two"] == "duplicate plugin name 'duplicate' (fail-closed)"
    assert manager.skipped_plugins["one-new"] == "duplicate plugin name 'duplicate' (fail-closed)"
    manager._register_descriptor(third)
    assert manager.skipped_plugins["three"] == "duplicate plugin name 'duplicate' (fail-closed)"


def test_worker_environment_keeps_only_allowlisted_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("OCTOPUS_OPERATOR_SECRET", "do-not-copy")
    environment = PluginManager._worker_environment()
    assert environment["LANG"] == "C.UTF-8"
    assert "OCTOPUS_OPERATOR_SECRET" not in environment
    assert environment["PYTHONPATH"] == PluginManager._project_root()
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["OCTOPUS_PLUGIN_WORKER"] == "1"


@pytest.mark.parametrize(
    ("method", "sig", "fallback"), (("term", signal.SIGTERM, "terminate"), ("kill", signal.SIGKILL, "kill"))
)
def test_process_group_helpers_cover_finished_posix_missing_and_nonposix(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    sig: signal.Signals,
    fallback: str,
) -> None:
    helper = PluginManager._terminate_process_group if method == "term" else PluginManager._kill_process_group
    finished = _FakeProcess([], poll_result=0)
    helper(finished)  # type: ignore[arg-type]

    calls: list[tuple[int, signal.Signals]] = []
    posix = types.SimpleNamespace(name="posix", killpg=lambda pid, selected: calls.append((pid, selected)))
    monkeypatch.setattr(loader, "os", posix)
    running = _FakeProcess([], poll_result=None)
    helper(running)  # type: ignore[arg-type]
    assert calls == [(4321, sig)]

    posix.killpg = lambda *_args: (_ for _ in ()).throw(ProcessLookupError())
    helper(_FakeProcess([], poll_result=None))  # type: ignore[arg-type]

    nonposix = types.SimpleNamespace(name="nt")
    monkeypatch.setattr(loader, "os", nonposix)
    fallback_process = _FakeProcess([], poll_result=None)
    helper(fallback_process)  # type: ignore[arg-type]
    expected_attribute = "terminated" if fallback == "terminate" else "killed"
    assert getattr(fallback_process, expected_attribute) == 1


def test_invoke_worker_handles_encoding_and_start_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _bare_manager()
    monkeypatch.setattr(loader, "dumps_message", lambda _request: (_ for _ in ()).throw(WireError("unsafe")))
    encoded = manager._invoke_worker({"bad": object()}, timeout=1)
    assert encoded.error == "unsafe"
    assert encoded.error_type == "WireError"

    monkeypatch.setattr(loader, "dumps_message", protocol.dumps_message)
    monkeypatch.setattr(
        loader.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cannot fork")),
    )
    started = manager._invoke_worker({"operation": "test"}, timeout=1)
    assert started.error == "cannot start plugin worker: cannot fork"
    assert started.error_type == "OSError"


@pytest.mark.parametrize(("stderr", "suffix"), ((b"", "response"), (b"fatal\n", "response: fatal")))
def test_invoke_worker_handles_empty_output(
    monkeypatch: pytest.MonkeyPatch,
    stderr: bytes,
    suffix: str,
) -> None:
    manager = _bare_manager()
    process = _FakeProcess([(b"", stderr)], returncode=9)
    monkeypatch.setattr(loader.subprocess, "Popen", lambda *_args, **_kwargs: process)
    reply = manager._invoke_worker({"operation": "test"}, timeout=0)
    assert reply.error.endswith(suffix)
    assert reply.error_type == "WorkerExitError"
    assert reply.stderr == stderr.decode().strip()
    assert process.communications[0][1]["timeout"] == 0.001


def test_invoke_worker_handles_timeout_and_escalation(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _bare_manager()
    expired = subprocess.TimeoutExpired("worker", 0.1)
    terminated = _FakeProcess([expired, (b"late", b"term")], returncode=-15)
    killed = _FakeProcess([expired, expired, (b"killed", b"kill")], returncode=-9)
    processes = iter((terminated, killed))
    monkeypatch.setattr(loader.subprocess, "Popen", lambda *_args, **_kwargs: next(processes))
    term_calls: list[_FakeProcess] = []
    kill_calls: list[_FakeProcess] = []
    monkeypatch.setattr(manager, "_terminate_process_group", term_calls.append)
    monkeypatch.setattr(manager, "_kill_process_group", kill_calls.append)

    first = manager._invoke_worker({"operation": "test"}, timeout=0.1)
    second = manager._invoke_worker({"operation": "test"}, timeout=0.1)
    assert first.timed_out and first.stdout == "late" and first.stderr == "term"
    assert second.timed_out and second.stdout == "killed" and second.stderr == "kill"
    assert term_calls == [terminated, killed]
    assert kill_calls == [killed]


def test_invoke_worker_validates_and_normalizes_worker_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _bare_manager()
    response_bytes = b"response"
    processes = iter(
        (
            _FakeProcess([(response_bytes, b"bad json")], returncode=1),
            _FakeProcess([(response_bytes, b"")]),
            _FakeProcess([(response_bytes, b"")]),
            _FakeProcess([(response_bytes, b"")], returncode=4),
        )
    )
    monkeypatch.setattr(loader.subprocess, "Popen", lambda *_args, **_kwargs: next(processes))
    responses = iter(
        (
            WireError("invalid response"),
            ["not", "an", "object"],
            {"ok": True, "payload": []},
            {
                "ok": 1,
                "payload": {"result": 7},
                "error": 9,
                "error_type": 10,
                "stdout": 11,
                "stderr": 12,
            },
        )
    )

    def load(_raw: bytes) -> Any:
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(loader, "loads_message", load)
    invalid_json = manager._invoke_worker({}, timeout=1)
    invalid_shape = manager._invoke_worker({}, timeout=1)
    empty_payload = manager._invoke_worker({}, timeout=1)
    valid = manager._invoke_worker({}, timeout=1)

    assert invalid_json.error == "invalid response" and invalid_json.stdout == "response"
    assert invalid_json.stderr == "bad json" and invalid_json.returncode == 1
    assert invalid_shape.error == "invalid worker response"
    assert empty_payload.ok and empty_payload.payload == {}
    assert valid == _WorkerReply(
        ok=True,
        payload={"result": 7},
        error="9",
        error_type="10",
        stdout="11",
        stderr="12",
        returncode=4,
    )


def test_invoke_worker_sets_nonposix_session_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _bare_manager()
    process = _FakeProcess([(protocol.dumps_message({"ok": True}), b"")])
    calls: list[dict[str, Any]] = []

    def popen(*_args: Any, **kwargs: Any) -> _FakeProcess:
        calls.append(kwargs)
        return process

    os_proxy = types.SimpleNamespace(name="nt", path=os.path, environ=os.environ)
    monkeypatch.setattr(loader, "os", os_proxy)
    monkeypatch.setattr(loader.subprocess, "Popen", popen)
    assert manager._invoke_worker({}, timeout="2").ok is True  # type: ignore[arg-type]
    assert calls[0]["start_new_session"] is False


def test_validation_reports_all_dependency_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _bare_manager()
    manager.plugins = {
        "dependency": _descriptor("dependency"),
        "valid": _descriptor(
            "valid",
            requires=["present", "missing-tool"],
            depends_on=["dependency", "missing-plugin"],
            python_deps=["present-pkg[extra]", "missing-pkg", "broken-pkg"],
        ),
        "clean": _descriptor("clean"),
    }
    monkeypatch.setattr(loader.shutil, "which", lambda tool: "/bin/tool" if tool == "present" else None)
    seen_imports: list[str] = []

    def find_spec(name: str):
        seen_imports.append(name)
        if name == "broken_pkg":
            raise ValueError("bad package")
        return object() if name == "present_pkg" else None

    monkeypatch.setattr(loader.importlib.util, "find_spec", find_spec)
    assert manager.validate("missing") == ["Plugin 'missing' not found"]
    assert manager.validate("valid") == [
        "Required system tool not found: missing-tool",
        "Required plugin not found: missing-plugin",
        "Required Python package not installed: missing-pkg",
        "Required Python package not installed: broken-pkg",
    ]
    assert seen_imports == ["present_pkg", "missing_pkg", "broken_pkg"]
    assert manager.validate_all() == {"valid": manager.validate("valid")}


def test_skipped_listing_context_and_captured_output_boundaries() -> None:
    manager = _bare_manager()
    manager.skipped_plugins = {"z": "last", "a": "first"}
    assert manager.list_skipped_plugins() == [
        {"module": "a", "reason": "first"},
        {"module": "z", "reason": "last"},
    ]

    assert manager._context_payload(None) == {
        "target": "",
        "campaign": "",
        "work_dir": "/tmp/octopus",
        "credentials": {},
        "config": {},
    }
    context = PluginContext(target="target", campaign="campaign", work_dir="/work")
    assert manager._context_payload(context)["target"] == "target"
    with pytest.raises(WireError, match="knowledge_graph"):
        manager._context_payload(PluginContext(knowledge_graph=object()))
    with pytest.raises(WireError, match="unsupported wire value"):
        manager._context_payload(PluginContext(config={"bad": object()}))

    assert manager._captured_output("", "", "") == ""
    assert manager._captured_output("base", "stdout\n", "stderr\n") == (
        "base\n--- plugin stdout ---\nstdout\n--- plugin stderr ---\nstderr"
    )


def test_input_secret_registration_covers_values_and_errors(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(loader, "is_secret_ref", lambda value: value == "secret://plugin/already")
    redactor = _IdentityRedactor()
    context = {
        "credentials": {
            "plain": "password",
            "bytes": b"bytes",
            "empty": "",
            "number": 7,
            "reference": "secret://plugin/already",
        },
        "config": {"token": "config"},
    }
    PluginManager._remember_input_secrets(redactor, context, {"password": "argument"})  # type: ignore[arg-type]
    assert redactor.protected == [
        ("password", "plugin_context_credential"),
        (b"bytes", "plugin_context_credential"),
    ]
    assert [field for _value, field in redactor.redacted] == ["plugin_arguments", "plugin_config"]

    class BrokenRedactor(_IdentityRedactor):
        def protect(self, value: Any, *, kind: str) -> str:
            raise OSError("store failed")

    with caplog.at_level(logging.DEBUG):
        PluginManager._remember_input_secrets(BrokenRedactor(), context, {})  # type: ignore[arg-type]
    assert "Unable to pre-register plugin input secrets" in caplog.text

    nondict = _IdentityRedactor()
    PluginManager._remember_input_secrets(nondict, {"credentials": [], "config": {}}, {})  # type: ignore[arg-type]
    assert nondict.protected == []


def test_safe_credentials_handles_scalar_identity_secret_and_empty_fields() -> None:
    redactor = _IdentityRedactor()
    credentials: list[Any] = [
        "plain-secret",
        b"bytes-secret",
        "",
        b"",
        7,
        {
            "username": "alice",
            "Pass Word": "hunter2",
            "empty": "",
            "metadata": {"verified": True},
            "!!!": "opaque",
        },
    ]
    safe = PluginManager._safe_credentials(redactor, credentials)  # type: ignore[arg-type]
    assert safe[:5] == [
        "secret://plugin_credential/1",
        "secret://plugin_credential/2",
        "",
        b"",
        7,
    ]
    assert safe[5]["username"] == "alice"
    assert safe[5]["Pass Word"].startswith("secret://plugin_credential_pass_word/")
    assert safe[5]["empty"] == ""
    assert safe[5]["metadata"] == {"verified": True}
    assert safe[5]["!!!"].startswith("secret://plugin_credential_value/")


def test_result_and_check_sanitizers_normalize_safe_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _bare_manager()
    redactor = _IdentityRedactor()
    monkeypatch.setattr(loader, "get_redactor", lambda: redactor)
    result = PluginResult(
        success=True,
        data={"value": 1},
        output="output",
        artifacts=["artifact"],
        credentials=[{"username": "alice", "password": "secret"}],
        sessions=[{"id": "one"}],
        error="",
    )
    safe = manager._sanitize_result(result)
    assert safe.success and safe.data == {"value": 1}
    assert safe.credentials[0]["username"] == "alice"
    assert str(safe.credentials[0]["password"]).startswith("secret://")
    assert manager._safe_error_result("failed", "captured") == PluginResult(
        success=False,
        error="failed",
        output="captured",
    )

    class EmptyRedactor(_IdentityRedactor):
        def redact_data(self, value: Any, *, field: str | None = None) -> Any:
            if isinstance(value, dict) and "success" in value:
                return {
                    "success": 0,
                    "data": None,
                    "output": None,
                    "artifacts": None,
                    "credentials": None,
                    "sessions": None,
                    "error": None,
                }
            if isinstance(value, CheckResult):
                return {"vulnerable": 0, "confidence": "bad", "details": None, "version": None, "evidence": None}
            return value

    monkeypatch.setattr(loader, "get_redactor", EmptyRedactor)
    assert manager._sanitize_result(PluginResult()).data == {}
    sanitized_check = manager._sanitize_check(CheckResult(vulnerable=True, confidence=0.5))
    assert sanitized_check == CheckResult(
        vulnerable=False,
        confidence=0.0,
        details="None",
        version="None",
        evidence="None",
    )


def test_execute_handles_lookup_validation_and_serialization_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _bare_manager()
    monkeypatch.setattr(loader, "get_redactor", _IdentityRedactor)
    missing = manager.execute("missing")
    assert "not found" in missing.error

    manager.plugins["plugin"] = _descriptor("plugin")
    monkeypatch.setattr(manager, "validate", lambda _name: ["missing dependency"])
    invalid = manager.execute("plugin")
    assert invalid.error == "Validation failed: missing dependency"

    monkeypatch.setattr(manager, "validate", lambda _name: [])
    context_error = manager.execute("plugin", context=PluginContext(knowledge_graph=object()))
    assert "Plugin input is not serializable" in context_error.error
    argument_error = manager.execute("plugin", unsupported=object())
    assert "Plugin input is not serializable" in argument_error.error


def test_execute_handles_timeout_crash_cleanup_events_credentials_and_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted: list[tuple[str, dict[str, Any], str]] = []

    class Bus:
        def emit(self, event_type: str, data: dict[str, Any], *, source: str) -> None:
            emitted.append((event_type, data, source))

    manager = _bare_manager(event_bus=Bus())
    manager.plugins["plugin"] = _descriptor("plugin")
    redactor = _IdentityRedactor()
    monkeypatch.setattr(loader, "get_redactor", lambda: redactor)
    monkeypatch.setattr(manager, "validate", lambda _name: [])
    applied: list[tuple[Any, str]] = []
    dispatched: list[tuple[str, Any]] = []
    monkeypatch.setattr(manager, "_apply_worker_events", lambda items, source: applied.append((items, source)))
    monkeypatch.setattr(manager, "_dispatch_to_plugins", lambda method, data: dispatched.append((method, data)))
    replies = iter(
        (
            _WorkerReply(timed_out=True, stdout="out", stderr="err"),
            _WorkerReply(error_type="", error="", stdout="crash-out"),
            _WorkerReply(
                ok=True,
                payload={
                    "result": {
                        "status": "success",
                        "data": "scalar",
                        "output": "base",
                        "credentials": [{"username": "alice", "password": "secret"}, "opaque"],
                        "sessions": [{"id": "session"}, "opaque-session"],
                    },
                    "cleanup_error": "cleanup-secret",
                    "events": [{"event_type": "custom", "data": {}}],
                },
                stdout="worker-out\n",
                stderr="worker-err\n",
            ),
            _WorkerReply(ok=True, payload={"result": PluginResult(success=True), "cleanup_error": ""}),
        )
    )
    monkeypatch.setattr(manager, "_invoke_worker", lambda *_args, **_kwargs: next(replies))

    timeout = manager.execute("plugin", timeout=1.5)
    crash = manager.execute("plugin")
    success = manager.execute("plugin", context=PluginContext(credentials={"password": "input"}))
    no_cleanup = manager.execute("plugin")

    assert "timed out after 1.5s" in timeout.error
    assert "plugin stdout" in timeout.output and "plugin stderr" in timeout.output
    assert crash.error == "Plugin 'plugin' crashed: plugin worker failed"
    assert success.success and success.data == {"value": "scalar"}
    assert "base" in success.output and "worker-out" in success.output and "cleanup failed" in success.output
    assert no_cleanup.success
    assert applied == [([{"event_type": "custom", "data": {}}], "plugin"), ([], "plugin")]
    assert [item[0] for item in emitted] == [
        "credential.found",
        "credential.found",
        "session.opened",
        "session.opened",
    ]
    assert [item[0] for item in dispatched] == [
        "on_credential_found",
        "on_credential_found",
        "on_session_opened",
        "on_session_opened",
    ]


def test_check_handles_lookup_validation_serialization_worker_and_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _bare_manager()
    monkeypatch.setattr(loader, "get_redactor", _IdentityRedactor)
    assert "not found" in manager.check("missing", "target").details

    manager.plugins["plugin"] = _descriptor("plugin")
    monkeypatch.setattr(manager, "validate", lambda _name: ["missing dependency"])
    assert manager.check("plugin", "target").details == "Validation failed: missing dependency"

    monkeypatch.setattr(manager, "validate", lambda _name: [])
    assert "not serializable" in manager.check("plugin", "target", bad=object()).details

    applied: list[tuple[Any, str]] = []
    monkeypatch.setattr(manager, "_apply_worker_events", lambda items, source: applied.append((items, source)))
    replies = iter(
        (
            _WorkerReply(timed_out=True),
            _WorkerReply(error_type="RuntimeError", error="boom"),
            _WorkerReply(
                ok=True,
                payload={
                    "result": {"vulnerable": True, "confidence": "0.9", "details": "ok"},
                    "events": ["event"],
                },
            ),
        )
    )
    requests: list[dict[str, Any]] = []

    def invoke(request: dict[str, Any], **_kwargs: Any) -> _WorkerReply:
        requests.append(request)
        return next(replies)

    monkeypatch.setattr(manager, "_invoke_worker", invoke)
    assert "timed out after 2s" in manager.check("plugin", "target", timeout=2).details
    assert manager.check("plugin", "target", timeout=3).details == "Check failed: RuntimeError: boom"
    success = manager.check("plugin", "target", timeout=4, mode="safe")
    assert success.vulnerable and success.confidence == 0.9
    assert requests[0]["kwargs"]["timeout"] == 2
    assert requests[2]["kwargs"] == {"mode": "safe", "timeout": 4}
    assert applied == [(["event"], "plugin")]


def test_check_and_result_normalization_shapes() -> None:
    check = CheckResult(vulnerable=True)
    assert PluginManager._normalize_check(check) is check
    assert PluginManager._normalize_check({"confidence": "bad"}).confidence == 0.0
    assert PluginManager._normalize_check(7) == CheckResult(vulnerable=True, details="7")

    manager = _bare_manager()
    result = PluginResult(success=True)
    assert manager._normalize_result(result) is result
    assert manager._normalize_result({"success": True, "data": {"value": 1}}).data == {"value": 1}
    by_status = manager._normalize_result(
        {
            "success": False,
            "status": "success",
            "data": [1, 2],
            "artifacts": None,
            "credentials": None,
            "sessions": None,
        }
    )
    assert by_status.success and by_status.data == {"value": [1, 2]}
    assert by_status.artifacts == [] and by_status.credentials == [] and by_status.sessions == []
    assert manager._normalize_result(0) == PluginResult(success=False, output="0")


def test_worker_events_validate_redact_and_wrap_data(monkeypatch: pytest.MonkeyPatch) -> None:
    emitted: list[tuple[str, dict[str, Any], str]] = []

    class Bus:
        def emit(self, event_type: str, data: dict[str, Any], *, source: str) -> None:
            emitted.append((event_type, data, source))

    manager = _bare_manager(event_bus=Bus())
    redactor = _IdentityRedactor()
    monkeypatch.setattr(loader, "get_redactor", lambda: redactor)
    manager._apply_worker_events("not-list", "default")
    manager._apply_worker_events(
        [
            "not-dict",
            {"event_type": "", "data": {}},
            {"event_type": "credential.found", "source": "", "data": {"password": "secret"}},
            {"event_type": "custom", "source": "worker", "data": [1, 2]},
        ],
        "default",
    )
    assert emitted[0][0] == "credential.found"
    assert emitted[0][2] == "default"
    assert str(emitted[0][1]["password"]).startswith("secret://")
    assert emitted[1] == ("custom", {"value": [1, 2]}, "worker")

    monkeypatch.setattr(manager, "_safe_credentials", lambda _redactor, _items: [])
    manager._apply_worker_events([{"event_type": "credential.found", "data": "secret"}], "default")
    assert emitted[-1] == ("credential.found", {}, "default")


def test_dispatch_to_plugin_hooks_handles_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _bare_manager()
    manager.plugins = {
        "skip": _descriptor("skip"),
        "good": _descriptor("good", hooks=["on_credential_found"]),
        "bad": _descriptor("bad", hooks=["on_credential_found"]),
    }
    replies = iter(
        (
            _WorkerReply(ok=True, payload={"events": ["event"]}),
            _WorkerReply(error="hook failed"),
        )
    )
    requests: list[dict[str, Any]] = []

    def invoke(request: dict[str, Any], **_kwargs: Any) -> _WorkerReply:
        requests.append(request)
        return next(replies)

    applied: list[tuple[Any, str]] = []
    monkeypatch.setattr(manager, "_invoke_worker", invoke)
    monkeypatch.setattr(manager, "_apply_worker_events", lambda items, source: applied.append((items, source)))
    with caplog.at_level(logging.DEBUG):
        manager._dispatch_to_plugins("on_credential_found", {"user": "alice"})
    assert [request["plugin"] for request in requests] == ["good", "bad"]
    assert applied == [(["event"], "good")]
    assert "Plugin bad event hook failed: hook failed" in caplog.text


def test_dependency_resolution_filters_and_listing() -> None:
    manager = _bare_manager()
    manager.plugins = {
        "base": _descriptor("base", plugin_type="recon", kill_chain_stage=1),
        "left": _descriptor("left", depends_on=["base"], plugin_type="exploit", kill_chain_stage=3),
        "right": _descriptor("right", depends_on=["base"], plugin_type="exploit", kill_chain_stage=3),
        "top": _descriptor("top", depends_on=["left", "right"], plugin_type="post", kill_chain_stage=4),
    }
    assert manager.resolve_dependencies(["top", "base"]) == ["base", "left", "right", "top"]
    assert manager.get_plugins_by_type(PluginType.EXPLOIT) == ["left", "right"]
    assert manager.get_plugins_by_type("post") == ["top"]  # type: ignore[arg-type]
    assert manager.get_plugins_for_stage(KillChainStage.EXPLOITATION) == ["left", "right"]
    assert manager.get_plugins_for_stage(4) == ["top"]  # type: ignore[arg-type]
    listed = manager.list_plugins()
    assert [item["name"] for item in listed] == ["base", "left", "right", "top"]
    listed[1]["depends_on"].append("mutation")
    assert manager.plugins["left"].depends_on == ["base"]

    with pytest.raises(ValueError, match="Required plugin not found: missing"):
        manager.resolve_dependencies(["missing"])
    manager.plugins["cycle-a"] = _descriptor("cycle-a", depends_on=["cycle-b"])
    manager.plugins["cycle-b"] = _descriptor("cycle-b", depends_on=["cycle-a"])
    with pytest.raises(ValueError, match="Circular dependency: cycle-a"):
        manager.resolve_dependencies(["cycle-a"])
