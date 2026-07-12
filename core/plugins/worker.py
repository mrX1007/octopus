#!/usr/bin/env python3
"""One-shot JSON worker for isolated class-based plugins.

This module is intentionally a tiny subprocess entry point.  It imports a
single plugin file, performs one operation, writes one JSON response, and
exits.  Plugin stdout/stderr are redirected at the file-descriptor level so
Python, native extensions, and child commands cannot corrupt the protocol.
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import os
import stat
import sys
import tempfile
from contextlib import AbstractContextManager, suppress
from dataclasses import asdict
from types import ModuleType
from typing import Any

from core.plugins.base import CheckResult, OctopusPlugin, PluginContext, PluginResult
from core.plugins.events import PluginEventBus
from core.plugins.protocol import WireError, dumps_message, loads_message

_CAPTURE_LIMIT = 256 * 1024
_HOOKS = (
    "on_credential_found",
    "on_session_opened",
    "on_vulnerability_confirmed",
)


class _FDCapture(AbstractContextManager):
    """Capture fd 1 and 2 without relying on Python-level stream wrappers."""

    def __init__(self) -> None:
        self.stdout = ""
        self.stderr = ""
        self._stdout_file: Any = None
        self._stderr_file: Any = None
        self._saved_stdout: int | None = None
        self._saved_stderr: int | None = None

    @staticmethod
    def _flush_stream(stream: Any) -> None:
        with suppress(AttributeError, OSError, ValueError):
            stream.flush()

    def __enter__(self) -> _FDCapture:
        self._flush_stream(sys.stdout)
        self._flush_stream(sys.stderr)
        self._stdout_file = tempfile.TemporaryFile(mode="w+b")
        self._stderr_file = tempfile.TemporaryFile(mode="w+b")
        self._saved_stdout = os.dup(1)
        self._saved_stderr = os.dup(2)
        os.dup2(self._stdout_file.fileno(), 1)
        os.dup2(self._stderr_file.fileno(), 2)
        return self

    @staticmethod
    def _read_capture(handle: Any) -> str:
        handle.flush()
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(0)
        raw = handle.read(_CAPTURE_LIMIT)
        text = raw.decode("utf-8", errors="replace")
        if size > _CAPTURE_LIMIT:
            text += f"\n[... truncated {size - _CAPTURE_LIMIT} bytes ...]"
        return text

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self._flush_stream(sys.stdout)
        self._flush_stream(sys.stderr)
        if self._saved_stdout is not None:
            os.dup2(self._saved_stdout, 1)
            os.close(self._saved_stdout)
        if self._saved_stderr is not None:
            os.dup2(self._saved_stderr, 2)
            os.close(self._saved_stderr)
        self.stdout = self._read_capture(self._stdout_file)
        self.stderr = self._read_capture(self._stderr_file)
        self._stdout_file.close()
        self._stderr_file.close()
        return None


def _validated_path(root: str, path: str) -> tuple[str, str]:
    root_real = os.path.realpath(os.path.abspath(root))
    path_abs = os.path.abspath(path)
    path_real = os.path.realpath(path_abs)
    try:
        contained = os.path.commonpath((root_real, path_real)) == root_real
    except ValueError:
        contained = False
    if not contained:
        raise ValueError("plugin path escapes its discovery root")
    if path_abs != path_real or os.path.islink(path_abs):
        raise ValueError("symlinked plugin paths are not allowed")
    try:
        mode = os.lstat(path_abs).st_mode
    except OSError as exc:
        raise ValueError(f"plugin file is unavailable: {exc}") from exc
    if not stat.S_ISREG(mode) or not path_abs.endswith(".py"):
        raise ValueError("plugin path must be a regular Python file")
    return root_real, path_abs


def _load_module(root: str, path: str) -> tuple[ModuleType, str]:
    _, safe_path = _validated_path(root, path)
    digest = hashlib.sha256(safe_path.encode("utf-8")).hexdigest()[:20]
    module_name = f"_octopus_plugin_{digest}_{os.getpid()}"
    spec = importlib.util.spec_from_file_location(module_name, safe_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot create an import spec for {safe_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module, module_name


def _plugin_classes(module: ModuleType) -> list[type[OctopusPlugin]]:
    classes: list[type[OctopusPlugin]] = []
    for _, candidate in inspect.getmembers(module, inspect.isclass):
        if candidate.__module__ != module.__name__:
            continue
        if candidate is OctopusPlugin or not issubclass(candidate, OctopusPlugin):
            continue
        if getattr(candidate, "name", "base_plugin") == "base_plugin":
            continue
        classes.append(candidate)
    return classes


def _enum_value(value: Any, default: Any) -> Any:
    return getattr(value, "value", default if value is None else value)


def _metadata(plugin_class: type[OctopusPlugin]) -> dict[str, Any]:
    return {
        "name": str(getattr(plugin_class, "name", "")),
        "version": str(getattr(plugin_class, "version", "0.0.0")),
        "type": _enum_value(getattr(plugin_class, "plugin_type", None), "auxiliary"),
        "stage": _enum_value(getattr(plugin_class, "kill_chain_stage", None), 1),
        "description": str(getattr(plugin_class, "description", "")),
        "author": str(getattr(plugin_class, "author", "")),
        "requires": list(getattr(plugin_class, "requires", []) or []),
        "depends_on": list(getattr(plugin_class, "depends_on", []) or []),
        "python_deps": list(getattr(plugin_class, "python_deps", []) or []),
        "capabilities": sorted(str(item) for item in (getattr(plugin_class, "capabilities", set()) or set())),
        "hooks": [name for name in _HOOKS if name in plugin_class.__dict__],
    }


def _select_plugin(module: ModuleType, plugin_name: str) -> type[OctopusPlugin]:
    matches = [candidate for candidate in _plugin_classes(module) if candidate.name == plugin_name]
    if not matches:
        raise LookupError(f"Plugin '{plugin_name}' not found in worker module")
    if len(matches) != 1:
        raise RuntimeError(f"duplicate plugin name '{plugin_name}' in worker module")
    return matches[0]


def _context_from_payload(payload: dict[str, Any], event_bus: PluginEventBus) -> PluginContext:
    allowed = {"target", "campaign", "work_dir", "credentials", "config"}
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError(f"unsupported context fields: {', '.join(sorted(unknown))}")
    context = PluginContext(
        target=str(payload.get("target", "")),
        campaign=str(payload.get("campaign", "")),
        work_dir=str(payload.get("work_dir", "/tmp/octopus")),
        credentials=dict(payload.get("credentials", {}) or {}),
        config=dict(payload.get("config", {}) or {}),
    )
    context.event_bus = event_bus
    return context


def _events(event_bus: PluginEventBus) -> list[dict[str, Any]]:
    return [asdict(event) for event in event_bus.history]


def _execute(module: ModuleType, request: dict[str, Any]) -> dict[str, Any]:
    plugin_name = str(request.get("plugin", ""))
    plugin_class = _select_plugin(module, plugin_name)
    instance = plugin_class()
    event_bus = PluginEventBus()
    context_payload = request.get("context", {})
    if not isinstance(context_payload, dict):
        raise ValueError("plugin context must be a JSON object")
    kwargs = request.get("kwargs", {})
    if not isinstance(kwargs, dict):
        raise ValueError("plugin arguments must be a JSON object")
    context = _context_from_payload(context_payload, event_bus)

    setup_complete = False
    cleanup_error = ""
    result: Any
    try:
        setup_complete = bool(instance.setup(context))
        if not setup_complete:
            result = PluginResult(success=False, error="Plugin setup() returned False")
        else:
            result = instance.run(**kwargs)
    finally:
        try:
            instance.cleanup()
        except BaseException as exc:
            cleanup_error = f"{type(exc).__name__}: {exc}"

    return {
        "result": result,
        "events": _events(event_bus),
        "cleanup_error": cleanup_error,
        "setup_complete": setup_complete,
    }


def _check(module: ModuleType, request: dict[str, Any]) -> dict[str, Any]:
    plugin_name = str(request.get("plugin", ""))
    plugin_class = _select_plugin(module, plugin_name)
    kwargs = request.get("kwargs", {})
    if not isinstance(kwargs, dict):
        raise ValueError("plugin check arguments must be a JSON object")
    result = plugin_class().check(str(request.get("target", "")), **kwargs)
    if isinstance(result, CheckResult):
        normalized: Any = result
    elif isinstance(result, dict):
        normalized = result
    else:
        normalized = CheckResult(vulnerable=bool(result), details=str(result))
    return {"result": normalized, "events": []}


def _event(module: ModuleType, request: dict[str, Any]) -> dict[str, Any]:
    plugin_name = str(request.get("plugin", ""))
    method = str(request.get("method", ""))
    if method not in _HOOKS:
        raise ValueError(f"unsupported plugin event hook: {method}")
    plugin_class = _select_plugin(module, plugin_name)
    event_bus = PluginEventBus()
    instance = plugin_class()
    context = _context_from_payload({}, event_bus)
    if not instance.setup(context):
        raise RuntimeError("Plugin setup() returned False during event dispatch")
    try:
        getattr(instance, method)(request.get("data"))
    finally:
        instance.cleanup()
    return {"events": _events(event_bus)}


def _dispatch(request: dict[str, Any]) -> dict[str, Any]:
    operation = str(request.get("operation", ""))
    root = str(request.get("root", ""))
    path = str(request.get("path", ""))
    module, module_name = _load_module(root, path)
    try:
        if operation == "discover":
            return {"plugins": [_metadata(plugin_class) for plugin_class in _plugin_classes(module)]}
        if operation == "execute":
            return _execute(module, request)
        if operation == "check":
            return _check(module, request)
        if operation == "event":
            return _event(module, request)
        raise ValueError(f"unsupported worker operation: {operation}")
    finally:
        sys.modules.pop(module_name, None)


def _error_response(exc: BaseException) -> dict[str, Any]:
    return {
        "ok": False,
        "error_type": type(exc).__name__,
        "error": str(exc),
    }


def main() -> int:
    try:
        request = loads_message(sys.stdin.buffer.read())
        if not isinstance(request, dict):
            raise WireError("worker request must be a JSON object")
    except BaseException as exc:
        sys.stdout.buffer.write(dumps_message(_error_response(exc)))
        sys.stdout.buffer.flush()
        return 2

    capture = _FDCapture()
    with capture:
        try:
            payload = _dispatch(request)
            response: dict[str, Any] = {"ok": True, "payload": payload}
        except BaseException as exc:
            response = _error_response(exc)

    response["stdout"] = capture.stdout
    response["stderr"] = capture.stderr
    try:
        encoded = dumps_message(response)
    except BaseException as exc:
        encoded = dumps_message({
            "ok": False,
            "error_type": type(exc).__name__,
            "error": f"worker response is not JSON-serializable: {exc}",
            "stdout": capture.stdout,
            "stderr": capture.stderr,
        })
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0 if response.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
