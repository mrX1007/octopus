from __future__ import annotations

import io
import os
import runpy
import sys
import tempfile
import types
from enum import Enum
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from core.plugins import protocol, worker
from core.plugins.base import CheckResult, KillChainStage, OctopusPlugin, PluginResult, PluginType
from core.plugins.events import PluginEventBus

pytestmark = pytest.mark.contract


def _plugin_class(module: ModuleType, class_name: str, plugin_name: str, **attributes: Any):
    namespace = {"__module__": module.__name__, "name": plugin_name, **attributes}
    plugin_class = type(class_name, (OctopusPlugin,), namespace)
    setattr(module, class_name, plugin_class)
    return plugin_class


class _BinaryEndpoint:
    def __init__(self, payload: bytes = b"") -> None:
        self.buffer = io.BytesIO(payload)


class _FakeCapture:
    stdout = "captured stdout"
    stderr = "captured stderr"

    def __enter__(self):
        return self

    def __exit__(self, *_args: Any) -> None:
        return None


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    request: Any,
    dispatch: Any,
) -> tuple[int, dict[str, Any]]:
    stdin = _BinaryEndpoint(protocol.dumps_message(request))
    stdout = _BinaryEndpoint()
    fake_sys = types.SimpleNamespace(stdin=stdin, stdout=stdout)
    monkeypatch.setattr(worker, "sys", fake_sys)
    monkeypatch.setattr(worker, "_FDCapture", _FakeCapture)
    if isinstance(dispatch, BaseException):
        monkeypatch.setattr(
            worker,
            "_dispatch",
            lambda _request: (_ for _ in ()).throw(dispatch),
        )
    else:
        monkeypatch.setattr(worker, "_dispatch", lambda _request: dispatch)
    status = worker.main()
    return status, protocol.loads_message(stdout.buffer.getvalue())


def test_fd_capture_collects_python_and_native_output(monkeypatch: pytest.MonkeyPatch) -> None:
    class FDStream:
        def __init__(self, descriptor: int) -> None:
            self.descriptor = descriptor

        def write(self, value: str) -> int:
            return os.write(self.descriptor, value.encode())

        def flush(self) -> None:
            return None

    streams = types.SimpleNamespace(stdout=FDStream(1), stderr=FDStream(2))
    monkeypatch.setattr(worker, "sys", streams)
    with worker._FDCapture() as capture:
        print("python stdout", file=streams.stdout, flush=True)
        print("python stderr", file=streams.stderr, flush=True)
        os.write(1, b"native stdout\n")
        os.write(2, b"native stderr\n")

    assert "python stdout" in capture.stdout
    assert "native stdout" in capture.stdout
    assert "python stderr" in capture.stderr
    assert "native stderr" in capture.stderr


def test_fd_capture_truncation_empty_exit_and_flush_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    with tempfile.TemporaryFile(mode="w+b") as handle:
        handle.write(b"abcdef")
        monkeypatch.setattr(worker, "_CAPTURE_LIMIT", 4)
        assert worker._FDCapture._read_capture(handle) == "abcd\n[... truncated 2 bytes ...]"

    with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
        capture = worker._FDCapture()
        capture._stdout_file = stdout_file
        capture._stderr_file = stderr_file
        assert capture.__exit__(None, None, None) is None
        assert capture.stdout == ""
        assert capture.stderr == ""

    class MissingFlush:
        pass

    class BrokenFlush:
        def __init__(self, failure: type[Exception]) -> None:
            self.failure = failure

        def flush(self) -> None:
            raise self.failure("cannot flush")

    worker._FDCapture._flush_stream(MissingFlush())
    for failure in (OSError, ValueError):
        worker._FDCapture._flush_stream(BrokenFlush(failure))


def test_validated_path_accepts_regular_python_file(tmp_path: Path) -> None:
    root = tmp_path / "plugins"
    root.mkdir()
    plugin = root / "valid.py"
    plugin.write_text("VALUE = 1", encoding="utf-8")
    assert worker._validated_path(str(root), str(plugin)) == (str(root.resolve()), str(plugin.resolve()))


def test_validated_path_rejects_escape_symlink_missing_and_non_python(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "plugins"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("VALUE = 1", encoding="utf-8")
    with pytest.raises(ValueError, match="escapes"):
        worker._validated_path(str(root), str(outside))

    inside = root / "inside.py"
    inside.write_text("VALUE = 2", encoding="utf-8")
    linked = root / "linked.py"
    try:
        linked.symlink_to(inside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError, match="symlinked"):
        worker._validated_path(str(root), str(linked))

    missing = root / "missing.py"
    with pytest.raises(ValueError, match="unavailable"):
        worker._validated_path(str(root), str(missing))

    directory = root / "directory.py"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular Python file"):
        worker._validated_path(str(root), str(directory))

    text = root / "plugin.txt"
    text.write_text("VALUE = 1", encoding="utf-8")
    with pytest.raises(ValueError, match="regular Python file"):
        worker._validated_path(str(root), str(text))

    monkeypatch.setattr(worker.os.path, "commonpath", lambda _paths: (_ for _ in ()).throw(ValueError("drive")))
    with pytest.raises(ValueError, match="escapes"):
        worker._validated_path(str(root), str(text))


def test_validated_path_rejects_islink_even_when_realpath_matches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "plugins"
    root.mkdir()
    plugin = root / "valid.py"
    plugin.write_text("VALUE = 1", encoding="utf-8")
    root_real = str(root.resolve())
    plugin_real = str(plugin.resolve())
    monkeypatch.setattr(
        worker.os.path,
        "realpath",
        lambda path: root_real if os.path.abspath(path) == str(root) else plugin_real,
    )
    monkeypatch.setattr(worker.os.path, "islink", lambda _path: True)
    with pytest.raises(ValueError, match="symlinked"):
        worker._validated_path(str(root), str(plugin))


def test_load_module_imports_unique_module_and_removes_failed_import(tmp_path: Path) -> None:
    root = tmp_path / "plugins"
    root.mkdir()
    valid = root / "valid.py"
    valid.write_text("VALUE = 42", encoding="utf-8")
    module, module_name = worker._load_module(str(root), str(valid))
    try:
        assert module.VALUE == 42
        assert sys.modules[module_name] is module
        assert module_name.startswith("_octopus_plugin_")
    finally:
        sys.modules.pop(module_name, None)

    broken = root / "broken.py"
    broken.write_text("raise RuntimeError('import failed')", encoding="utf-8")
    before = set(sys.modules)
    with pytest.raises(RuntimeError, match="import failed"):
        worker._load_module(str(root), str(broken))
    assert not [name for name in set(sys.modules) - before if name.startswith("_octopus_plugin_")]


@pytest.mark.parametrize("spec", (None, types.SimpleNamespace(loader=None)))
def test_load_module_rejects_missing_import_spec(
    monkeypatch: pytest.MonkeyPatch,
    spec: Any,
) -> None:
    monkeypatch.setattr(worker, "_validated_path", lambda _root, path: ("/root", path))
    monkeypatch.setattr(worker.importlib.util, "spec_from_file_location", lambda *_args: spec)
    with pytest.raises(ImportError, match="cannot create an import spec"):
        worker._load_module("/root", "/root/plugin.py")


def test_plugin_class_filtering_covers_imports_base_nonplugin_and_default_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = ModuleType("worker_filter_module")
    imported = type("Imported", (OctopusPlugin,), {"__module__": "elsewhere", "name": "imported"})
    nonplugin = type("NonPlugin", (), {"__module__": module.__name__})
    default_name = type("DefaultName", (OctopusPlugin,), {"__module__": module.__name__})
    valid = _plugin_class(module, "Valid", "valid")
    module.Imported = imported
    module.NonPlugin = nonplugin
    module.DefaultName = default_name
    module.OctopusPlugin = OctopusPlugin
    monkeypatch.setattr(OctopusPlugin, "__module__", module.__name__)

    assert worker._plugin_classes(module) == [valid]


def test_enum_metadata_and_plugin_selection_boundaries() -> None:
    class CustomEnum(Enum):
        VALUE = "custom"

    assert worker._enum_value(CustomEnum.VALUE, "default") == "custom"
    assert worker._enum_value(None, "default") == "default"
    assert worker._enum_value("plain", "default") == "plain"

    module = ModuleType("worker_metadata_module")

    def credential_hook(self, credential: Any) -> None:
        self.credential = credential

    complete = _plugin_class(
        module,
        "Complete",
        "complete",
        version=3,
        plugin_type=PluginType.EXPLOIT,
        kill_chain_stage=KillChainStage.EXPLOITATION,
        description=7,
        author=8,
        requires=["tool"],
        depends_on=["dependency"],
        python_deps=["package"],
        capabilities={"z", "a"},
        on_credential_found=credential_hook,
    )
    empty = _plugin_class(
        module,
        "Empty",
        "empty",
        requires=None,
        depends_on=None,
        python_deps=None,
        capabilities=None,
    )
    assert worker._metadata(complete) == {
        "name": "complete",
        "version": "3",
        "type": "exploit",
        "stage": 3,
        "description": "7",
        "author": "8",
        "requires": ["tool"],
        "depends_on": ["dependency"],
        "python_deps": ["package"],
        "capabilities": ["a", "z"],
        "hooks": ["on_credential_found"],
        "supports_check": False,
        "supports_run": False,
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    }
    assert worker._metadata(empty)["requires"] == []
    assert worker._metadata(empty)["capabilities"] == []
    checked = _plugin_class(module, "Checked", "checked", check=lambda *_args, **_kwargs: CheckResult())
    assert worker._metadata(checked)["supports_check"] is True
    assert worker._metadata(checked)["supports_run"] is False
    runnable = _plugin_class(module, "Runnable", "runnable", run=lambda *_args, **_kwargs: PluginResult(True))
    assert worker._metadata(runnable)["supports_run"] is True
    assert worker._select_plugin(module, "complete") is complete
    with pytest.raises(LookupError, match="Plugin 'missing' not found"):
        worker._select_plugin(module, "missing")

    duplicate = _plugin_class(module, "Duplicate", "complete")
    assert duplicate is not complete
    with pytest.raises(RuntimeError, match="duplicate plugin name"):
        worker._select_plugin(module, "complete")


def test_context_and_event_serialization_validate_payload_shape() -> None:
    bus = PluginEventBus()
    default = worker._context_from_payload({}, bus)
    assert default.target == ""
    assert default.work_dir == "/tmp/octopus"
    assert default.credentials == {}
    assert default.config == {}
    assert default.event_bus is bus

    populated = worker._context_from_payload(
        {
            "target": 7,
            "campaign": 8,
            "work_dir": 9,
            "credentials": {"user": "alice"},
            "config": {"enabled": True},
        },
        bus,
    )
    assert populated.target == "7"
    assert populated.campaign == "8"
    assert populated.work_dir == "9"
    assert populated.credentials == {"user": "alice"}
    assert populated.config == {"enabled": True}
    with pytest.raises(ValueError, match="unsupported context fields: extra, unknown"):
        worker._context_from_payload({"unknown": 1, "extra": 2}, bus)

    bus.emit("custom", {"value": 1}, source="plugin")
    serialized = worker._events(bus)
    assert serialized[0]["event_type"] == "custom"
    assert serialized[0]["data"] == {"value": 1}


def test_execute_lifecycle_setup_false_success_cleanup_error_and_events() -> None:
    module = ModuleType("worker_execute_module")
    lifecycle: list[str] = []

    def setup_false(self, context: Any) -> bool:
        lifecycle.append("setup-false")
        self._context = context
        return False

    def cleanup_false(self) -> None:
        lifecycle.append("cleanup-false")

    _plugin_class(
        module,
        "SetupFalse",
        "setup-false",
        setup=setup_false,
        cleanup=cleanup_false,
    )

    def setup_true(self, context: Any) -> bool:
        lifecycle.append("setup-true")
        self._context = context
        return True

    def run_success(self, **kwargs: Any) -> PluginResult:
        lifecycle.append("run")
        self.emit_event("custom", {"value": kwargs["value"]})
        return PluginResult(success=True, data=kwargs)

    def cleanup_error(self) -> None:
        lifecycle.append("cleanup-error")
        raise OSError("cleanup failed")

    _plugin_class(
        module,
        "Success",
        "success",
        setup=setup_true,
        run=run_success,
        cleanup=cleanup_error,
    )

    failed_setup = worker._execute(
        module,
        {"plugin": "setup-false", "context": {}, "kwargs": {}},
    )
    assert failed_setup["result"] == PluginResult(
        success=False,
        error="Plugin setup() returned False",
    )
    assert failed_setup["setup_complete"] is False
    assert failed_setup["cleanup_error"] == ""

    success = worker._execute(
        module,
        {
            "plugin": "success",
            "context": {"target": "local"},
            "kwargs": {"value": 7},
        },
    )
    assert success["result"] == PluginResult(success=True, data={"value": 7})
    assert success["setup_complete"] is True
    assert success["cleanup_error"] == "OSError: cleanup failed"
    assert success["events"][0]["event_type"] == "custom"
    assert lifecycle == ["setup-false", "cleanup-false", "setup-true", "run", "cleanup-error"]


@pytest.mark.parametrize(
    ("request_payload", "message"),
    (
        ({"plugin": "plugin", "context": [], "kwargs": {}}, "context must be a JSON object"),
        ({"plugin": "plugin", "context": {}, "kwargs": []}, "arguments must be a JSON object"),
    ),
)
def test_execute_rejects_non_object_context_and_arguments(
    request_payload: dict[str, Any],
    message: str,
) -> None:
    module = ModuleType("worker_execute_shape_module")
    _plugin_class(module, "Plugin", "plugin")
    with pytest.raises(ValueError, match=message):
        worker._execute(module, request_payload)


def test_execute_rejects_check_only_action_before_plugin_run() -> None:
    module = ModuleType("worker_execute_action_module")
    calls: list[str] = []

    def run(self, **_kwargs: Any) -> PluginResult:
        calls.append("run")
        return PluginResult(success=True)

    _plugin_class(module, "Plugin", "plugin", run=run)

    with pytest.raises(ValueError, match="requires action=run"):
        worker._execute(
            module,
            {
                "plugin": "plugin",
                "action": "scan",
                "context": {},
                "kwargs": {},
            },
        )

    assert calls == []


def test_execute_cleanup_runs_when_setup_or_run_raises() -> None:
    module = ModuleType("worker_execute_error_module")
    cleaned: list[str] = []

    def setup_error(self, _context: Any) -> bool:
        raise RuntimeError("setup failed")

    def run_error(self, **_kwargs: Any) -> PluginResult:
        raise RuntimeError("run failed")

    def cleanup(self) -> None:
        cleaned.append(self.name)

    _plugin_class(module, "SetupError", "setup-error", setup=setup_error, cleanup=cleanup)
    _plugin_class(module, "RunError", "run-error", run=run_error, cleanup=cleanup)

    with pytest.raises(RuntimeError, match="setup failed"):
        worker._execute(module, {"plugin": "setup-error", "context": {}, "kwargs": {}})
    with pytest.raises(RuntimeError, match="run failed"):
        worker._execute(module, {"plugin": "run-error", "context": {}, "kwargs": {}})
    assert cleaned == ["setup-error", "run-error"]


def test_check_normalizes_dataclass_dict_scalar_and_rejects_arguments() -> None:
    module = ModuleType("worker_check_module")

    def dataclass_check(self, target: str, **_kwargs: Any) -> CheckResult:
        return CheckResult(vulnerable=True, details=target)

    def dict_check(self, _target: str, **_kwargs: Any) -> dict[str, Any]:
        return {"vulnerable": True}

    def scalar_check(self, _target: str, **_kwargs: Any) -> str:
        return "yes"

    _plugin_class(module, "DataclassCheck", "dataclass", check=dataclass_check)
    _plugin_class(module, "DictCheck", "dict", check=dict_check)
    _plugin_class(module, "ScalarCheck", "scalar", check=scalar_check)

    dataclass_result = worker._check(module, {"plugin": "dataclass", "target": 7, "kwargs": {}})
    dict_result = worker._check(module, {"plugin": "dict", "kwargs": {}})
    scalar_result = worker._check(module, {"plugin": "scalar", "kwargs": {}})
    assert dataclass_result["result"] == CheckResult(vulnerable=True, details="7")
    assert dict_result["result"] == {"vulnerable": True}
    assert scalar_result["result"] == CheckResult(vulnerable=True, details="yes")
    with pytest.raises(ValueError, match="check arguments must be a JSON object"):
        worker._check(module, {"plugin": "scalar", "kwargs": []})


def test_event_dispatch_validates_hook_setup_cleanup_and_emitted_events() -> None:
    module = ModuleType("worker_event_module")
    calls: list[Any] = []

    def setup_false(self, context: Any) -> bool:
        self._context = context
        return False

    def hook(self, data: Any) -> None:
        calls.append(data)
        self.emit_event("hook.event", {"data": data})

    def cleanup(self) -> None:
        calls.append("cleanup")

    _plugin_class(module, "SetupFalse", "setup-false", setup=setup_false, on_credential_found=hook)
    _plugin_class(module, "Success", "success", on_credential_found=hook, cleanup=cleanup)

    with pytest.raises(ValueError, match="unsupported plugin event hook"):
        worker._event(module, {"plugin": "success", "method": "unsupported"})
    with pytest.raises(RuntimeError, match=r"setup.*False"):
        worker._event(
            module,
            {"plugin": "setup-false", "method": "on_credential_found", "data": {}},
        )

    result = worker._event(
        module,
        {"plugin": "success", "method": "on_credential_found", "data": {"user": "alice"}},
    )
    assert result["events"][0]["event_type"] == "hook.event"
    assert calls == [{"user": "alice"}, "cleanup"]


def test_event_cleanup_runs_when_hook_raises() -> None:
    module = ModuleType("worker_event_error_module")
    cleaned: list[bool] = []

    def hook_error(self, _data: Any) -> None:
        raise RuntimeError("hook failed")

    def cleanup(self) -> None:
        cleaned.append(True)

    _plugin_class(module, "Error", "error", on_session_opened=hook_error, cleanup=cleanup)
    with pytest.raises(RuntimeError, match="hook failed"):
        worker._event(
            module,
            {"plugin": "error", "method": "on_session_opened", "data": {}},
        )
    assert cleaned == [True]


def test_dispatch_runs_every_operation_and_always_unloads_module(tmp_path: Path) -> None:
    root = tmp_path / "plugins"
    root.mkdir()
    plugin = root / "direct.py"
    plugin.write_text(
        """
from core.plugins.base import CheckResult, OctopusPlugin, PluginResult

class DirectPlugin(OctopusPlugin):
    name = "direct"
    version = "1.0.0"

    def run(self, **kwargs):
        return PluginResult(success=True, data=kwargs)

    def check(self, target, **kwargs):
        return CheckResult(vulnerable=target == "local")

    def on_credential_found(self, credential):
        self.emit_event("credential.seen", credential)
        """,
        encoding="utf-8",
    )
    base = {"root": str(root), "path": str(plugin), "plugin": "direct"}
    discovered = worker._dispatch({**base, "operation": "discover"})
    executed = worker._dispatch({**base, "operation": "execute", "context": {}, "kwargs": {"value": 7}})
    checked = worker._dispatch({**base, "operation": "check", "target": "local", "kwargs": {}})
    event = worker._dispatch(
        {
            **base,
            "operation": "event",
            "method": "on_credential_found",
            "data": {"user": "alice"},
        }
    )
    assert discovered["plugins"][0]["name"] == "direct"
    assert executed["result"] == PluginResult(success=True, data={"value": 7})
    assert checked["result"].vulnerable is True
    assert event["events"][0]["event_type"] == "credential.seen"

    with pytest.raises(ValueError, match="unsupported worker operation"):
        worker._dispatch({**base, "operation": "unknown"})
    assert not [name for name in sys.modules if name.startswith("_octopus_plugin_")]


def test_error_response_is_structured() -> None:
    assert worker._error_response(RuntimeError("failed")) == {
        "ok": False,
        "error_type": "RuntimeError",
        "error": "failed",
    }


@pytest.mark.parametrize("raw", (b"not-json", protocol.dumps_message(["not", "object"])))
def test_main_rejects_invalid_or_non_object_request(
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
) -> None:
    stdin = _BinaryEndpoint(raw)
    stdout = _BinaryEndpoint()
    monkeypatch.setattr(worker, "sys", types.SimpleNamespace(stdin=stdin, stdout=stdout))
    assert worker.main() == 2
    response = protocol.loads_message(stdout.buffer.getvalue())
    assert response["ok"] is False
    assert response["error_type"] in {"WireError"}


def test_main_returns_success_and_structured_dispatch_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    success_status, success = _run_main(monkeypatch, {"operation": "test"}, {"value": 7})
    assert success_status == 0
    assert success == {
        "ok": True,
        "payload": {"value": 7},
        "stdout": "captured stdout",
        "stderr": "captured stderr",
    }

    failure_status, failure = _run_main(
        monkeypatch,
        {"operation": "test"},
        RuntimeError("dispatch failed"),
    )
    assert failure_status == 1
    assert failure["ok"] is False
    assert failure["error_type"] == "RuntimeError"
    assert failure["error"] == "dispatch failed"
    assert failure["stdout"] == "captured stdout"
    assert failure["stderr"] == "captured stderr"


def test_main_serialization_failure_returns_error_and_failure_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status, response = _run_main(
        monkeypatch,
        {"operation": "test"},
        {"unsupported": object()},
    )
    assert status == 1
    assert response["ok"] is False
    assert response["error_type"] == "WireError"
    assert "worker response is not JSON-serializable" in response["error"]
    assert response["stdout"] == "captured stdout"
    assert response["stderr"] == "captured stderr"


def test_module_guard_exits_with_main_status(monkeypatch: pytest.MonkeyPatch) -> None:
    stdin = _BinaryEndpoint(b"not-json")
    stdout = _BinaryEndpoint()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(worker.__file__, run_name="__main__")

    assert exc_info.value.code == 2
    response = protocol.loads_message(stdout.buffer.getvalue())
    assert response["ok"] is False
    assert response["error_type"] == "WireError"
