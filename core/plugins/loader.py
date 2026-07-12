#!/usr/bin/env python3
"""Process-isolated manager for class-based OCTOPUS plugins.

The parent process never imports a discovered plugin module.  Discovery,
checks, execution, and event hooks are one-shot JSON subprocess operations.
Only inert metadata descriptors live in this process.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from core.plugins.base import CheckResult, KillChainStage, PluginContext, PluginResult, PluginType
from core.plugins.events import PluginEventBus
from core.plugins.protocol import WireError, dumps_message, loads_message
from core.secrets import Redactor, get_redactor, is_secret_ref

_DISCOVERY_TIMEOUT = 15.0
_EVENT_TIMEOUT = 15.0
_TERM_GRACE = 1.0
_CREDENTIAL_IDENTITY_FIELDS = {
    "account",
    "domain",
    "host",
    "kind",
    "port",
    "protocol",
    "realm",
    "service",
    "source",
    "target",
    "type",
    "user",
    "username",
    "verified",
}


@dataclass(frozen=True)
class PluginDescriptor:
    """Inert metadata returned by discovery; it contains no executable code."""

    name: str
    path: str
    root: str
    module: str
    version: str = "0.0.0"
    plugin_type: str = PluginType.AUXILIARY.value
    kill_chain_stage: int = KillChainStage.RECON.value
    description: str = ""
    author: str = ""
    requires: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    python_deps: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    hooks: list[str] = field(default_factory=list)


@dataclass
class _WorkerReply:
    ok: bool = False
    payload: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    error_type: str = ""
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    returncode: int | None = None


class PluginManager:
    """Discover and invoke plugins exclusively through isolated processes."""

    def __init__(
        self,
        modules_dir: str = "modules/",
        event_bus: PluginEventBus | None = None,
    ) -> None:
        self.modules_dir = modules_dir
        self.plugins: dict[str, PluginDescriptor] = {}
        self.skipped_plugins: dict[str, str] = {}
        self.event_bus = event_bus or PluginEventBus()
        self._conflicted_names: set[str] = set()
        self._descriptors_by_path: dict[str, list[str]] = {}
        self.discover()

    @staticmethod
    def _module_label(path: str) -> str:
        return os.path.splitext(os.path.basename(path))[0]

    @staticmethod
    def _safe_root(path: str) -> str | None:
        root = os.path.realpath(os.path.abspath(os.path.expanduser(path)))
        return root if os.path.isdir(root) else None

    def _iter_plugin_files(self, search_dir: str) -> Iterable[tuple[str, str]]:
        root = self._safe_root(search_dir)
        if root is None:
            return
        for current, directories, files in os.walk(root, followlinks=False):
            directories[:] = sorted(
                directory
                for directory in directories
                if not os.path.islink(os.path.join(current, directory))
            )
            for filename in sorted(files):
                if not filename.endswith(".py") or filename.startswith("__"):
                    continue
                path = os.path.abspath(os.path.join(current, filename))
                module = self._module_label(path)
                if os.path.islink(path) or os.path.realpath(path) != path:
                    self.skipped_plugins[module] = "symlinked plugin paths are not allowed"
                    continue
                try:
                    mode = os.lstat(path).st_mode
                    contained = os.path.commonpath((root, os.path.realpath(path))) == root
                except (OSError, ValueError):
                    contained = False
                    mode = 0
                if not contained or not stat.S_ISREG(mode):
                    self.skipped_plugins[module] = "plugin path escapes its discovery root"
                    continue
                yield root, path

    def discover(self, dirs: list[str] | None = None) -> None:
        """Discover plugin metadata without importing plugin code in-process."""
        for search_dir in dirs or [self.modules_dir]:
            for root, path in self._iter_plugin_files(search_dir):
                if path in self._descriptors_by_path:
                    continue
                self._discover_file(root, path)

    def _discover_file(self, root: str, path: str) -> None:
        module = self._module_label(path)
        reply = self._invoke_worker(
            {"operation": "discover", "root": root, "path": path},
            timeout=_DISCOVERY_TIMEOUT,
        )
        if not reply.ok:
            if reply.timed_out:
                reason = f"discovery timed out after {_DISCOVERY_TIMEOUT:g}s"
            else:
                reason = reply.error or "plugin discovery worker failed"
            self.skipped_plugins[module] = reason
            if reply.error_type not in {"ImportError", "ModuleNotFoundError"}:
                logging.debug("Failed to discover plugin from %s: %s", path, reason)
            self._descriptors_by_path[path] = []
            return

        raw_plugins = reply.payload.get("plugins", [])
        if not isinstance(raw_plugins, list):
            self.skipped_plugins[module] = "invalid discovery response"
            self._descriptors_by_path[path] = []
            return

        discovered_names: list[str] = []
        descriptors: list[PluginDescriptor] = []
        try:
            for raw in raw_plugins:
                if not isinstance(raw, dict):
                    raise ValueError("plugin metadata must be an object")
                descriptor = self._descriptor_from_payload(raw, root, path, module)
                if descriptor.name in discovered_names:
                    raise ValueError(f"duplicate plugin name '{descriptor.name}' in {path}")
                discovered_names.append(descriptor.name)
                descriptors.append(descriptor)
        except (TypeError, ValueError) as exc:
            self.skipped_plugins[module] = str(exc)
            self._descriptors_by_path[path] = []
            return

        self._descriptors_by_path[path] = discovered_names
        for descriptor in descriptors:
            self._register_descriptor(descriptor)

    @staticmethod
    def _string_list(value: Any, field_name: str) -> list[str]:
        if not isinstance(value, list):
            raise ValueError(f"plugin metadata field '{field_name}' must be a list")
        if not all(isinstance(item, str) for item in value):
            raise ValueError(f"plugin metadata field '{field_name}' must contain strings")
        return list(value)

    def _descriptor_from_payload(
        self,
        raw: dict[str, Any],
        root: str,
        path: str,
        module: str,
    ) -> PluginDescriptor:
        name = raw.get("name")
        if not isinstance(name, str) or not name or name == "base_plugin":
            raise ValueError("plugin metadata contains an invalid name")
        stage = raw.get("stage", KillChainStage.RECON.value)
        if isinstance(stage, bool) or not isinstance(stage, int):
            raise ValueError("plugin metadata field 'stage' must be an integer")
        plugin_type = raw.get("type", PluginType.AUXILIARY.value)
        if not isinstance(plugin_type, str):
            raise ValueError("plugin metadata field 'type' must be a string")
        return PluginDescriptor(
            name=name,
            path=path,
            root=root,
            module=module,
            version=str(raw.get("version", "0.0.0")),
            plugin_type=plugin_type,
            kill_chain_stage=stage,
            description=str(raw.get("description", "")),
            author=str(raw.get("author", "")),
            requires=self._string_list(raw.get("requires", []), "requires"),
            depends_on=self._string_list(raw.get("depends_on", []), "depends_on"),
            python_deps=self._string_list(raw.get("python_deps", []), "python_deps"),
            capabilities=self._string_list(raw.get("capabilities", []), "capabilities"),
            hooks=self._string_list(raw.get("hooks", []), "hooks"),
        )

    def _register_descriptor(self, descriptor: PluginDescriptor) -> None:
        name = descriptor.name
        existing = self.plugins.get(name)
        if name in self._conflicted_names or (existing is not None and existing.path != descriptor.path):
            self._conflicted_names.add(name)
            self.plugins.pop(name, None)
            reason = f"duplicate plugin name '{name}' (fail-closed)"
            self.skipped_plugins[descriptor.module] = reason
            if existing is not None:
                self.skipped_plugins[existing.module] = reason
            return
        self.plugins[name] = descriptor
        logging.debug("Plugin discovered: %s v%s (%s)", name, descriptor.version, descriptor.path)

    @staticmethod
    def _worker_command() -> list[str]:
        return [sys.executable, "-m", "core.plugins.worker"]

    @staticmethod
    def _project_root() -> str:
        return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    @classmethod
    def _worker_environment(cls) -> dict[str, str]:
        """Build a minimal environment without inheriting operator secrets."""
        allowed = {
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "PATH",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
            "SYSTEMROOT",
            "TMPDIR",
            "TZ",
            "VIRTUAL_ENV",
        }
        environment = {key: value for key, value in os.environ.items() if key in allowed}
        environment["PYTHONPATH"] = cls._project_root()
        environment["PYTHONNOUSERSITE"] = "1"
        environment["OCTOPUS_PLUGIN_WORKER"] = "1"
        return environment

    @staticmethod
    def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
        else:
            process.terminate()

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                return
        else:
            process.kill()

    def _invoke_worker(self, request: dict[str, Any], timeout: float) -> _WorkerReply:
        try:
            encoded = dumps_message(request)
        except WireError as exc:
            return _WorkerReply(error=str(exc), error_type=type(exc).__name__)

        try:
            process = subprocess.Popen(
                self._worker_command(),
                cwd=self._project_root(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=(os.name == "posix"),
                close_fds=True,
                env=self._worker_environment(),
            )
        except OSError as exc:
            return _WorkerReply(error=f"cannot start plugin worker: {exc}", error_type=type(exc).__name__)

        timed_out = False
        try:
            stdout, stderr = process.communicate(encoded, timeout=max(0.001, float(timeout)))
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate_process_group(process)
            try:
                stdout, stderr = process.communicate(timeout=_TERM_GRACE)
            except subprocess.TimeoutExpired:
                self._kill_process_group(process)
                stdout, stderr = process.communicate()

        if timed_out:
            return _WorkerReply(
                error="plugin worker timed out",
                error_type="TimeoutError",
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                timed_out=True,
                returncode=process.returncode,
            )
        if not stdout:
            detail = stderr.decode("utf-8", errors="replace").strip()
            error = f"plugin worker exited with code {process.returncode} without a JSON response"
            if detail:
                error = f"{error}: {detail}"
            return _WorkerReply(
                error=error,
                error_type="WorkerExitError",
                stderr=detail,
                returncode=process.returncode,
            )

        try:
            response = loads_message(stdout)
        except WireError as exc:
            return _WorkerReply(
                error=str(exc),
                error_type=type(exc).__name__,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                returncode=process.returncode,
            )
        if not isinstance(response, dict):
            return _WorkerReply(error="invalid worker response", error_type="WireError")
        payload = response.get("payload", {})
        if not isinstance(payload, dict):
            payload = {}
        return _WorkerReply(
            ok=bool(response.get("ok")),
            payload=payload,
            error=str(response.get("error", "")),
            error_type=str(response.get("error_type", "")),
            stdout=str(response.get("stdout", "")),
            stderr=str(response.get("stderr", "")),
            returncode=process.returncode,
        )

    def get_plugin(self, name: str) -> PluginDescriptor | None:
        """Return a truthy inert descriptor for a discovered plugin."""
        return self.plugins.get(name)

    def get_instance(self, name: str) -> PluginDescriptor | None:
        """Compatibility alias; plugin instances only exist in workers."""
        return self.get_plugin(name)

    def validate(self, plugin_name: str) -> list[str]:
        """Validate declared dependencies using inert discovery metadata."""
        errors: list[str] = []
        descriptor = self.get_plugin(plugin_name)
        if descriptor is None:
            return [f"Plugin '{plugin_name}' not found"]
        for tool in descriptor.requires:
            if not shutil.which(tool):
                errors.append(f"Required system tool not found: {tool}")
        for dependency in descriptor.depends_on:
            if dependency not in self.plugins:
                errors.append(f"Required plugin not found: {dependency}")
        for package in descriptor.python_deps:
            import_name = package.split("[", 1)[0].replace("-", "_")
            try:
                available = importlib.util.find_spec(import_name) is not None
            except (ImportError, AttributeError, ValueError):
                available = False
            if not available:
                errors.append(f"Required Python package not installed: {package}")
        return errors

    def validate_all(self) -> dict[str, list[str]]:
        """Return only discovered plugins with validation failures."""
        invalid: dict[str, list[str]] = {}
        for plugin_name in sorted(self.plugins):
            errors = self.validate(plugin_name)
            if errors:
                invalid[plugin_name] = errors
        return invalid

    def list_skipped_plugins(self) -> list[dict[str, str]]:
        return [
            {"module": module, "reason": reason}
            for module, reason in sorted(self.skipped_plugins.items())
        ]

    @staticmethod
    def _context_payload(context: PluginContext | None) -> dict[str, Any]:
        current = context or PluginContext()
        if current.knowledge_graph is not None:
            raise WireError("PluginContext.knowledge_graph is not serializable")
        payload = {
            "target": current.target,
            "campaign": current.campaign,
            "work_dir": current.work_dir,
            "credentials": current.credentials,
            "config": current.config,
        }
        # Validate now so an unsupported object never reaches Popen.
        dumps_message(payload)
        return payload

    @staticmethod
    def _captured_output(base: str, stdout: str, stderr: str) -> str:
        sections: list[str] = []
        if base:
            sections.append(base)
        if stdout:
            sections.append(f"--- plugin stdout ---\n{stdout.rstrip()}")
        if stderr:
            sections.append(f"--- plugin stderr ---\n{stderr.rstrip()}")
        return "\n".join(sections)

    @staticmethod
    def _remember_input_secrets(
        redactor: Redactor,
        context_payload: dict[str, Any],
        kwargs: dict[str, Any],
    ) -> None:
        try:
            credentials = context_payload.get("credentials", {})
            if isinstance(credentials, dict):
                for value in credentials.values():
                    if isinstance(value, (str, bytes)) and value and not is_secret_ref(value):
                        redactor.protect(value, kind="plugin_context_credential")
            redactor.redact_data(kwargs, field="plugin_arguments")
            redactor.redact_data(context_payload.get("config", {}), field="plugin_config")
        except (OSError, TypeError, ValueError):
            logging.debug("Unable to pre-register plugin input secrets", exc_info=True)

    @staticmethod
    def _safe_credentials(redactor: Redactor, credentials: list[Any]) -> list[Any]:
        protected: list[Any] = []
        for credential in credentials:
            if isinstance(credential, (str, bytes)):
                if credential:
                    protected.append(redactor.protect(credential, kind="plugin_credential"))
                else:
                    protected.append(credential)
                continue
            if not isinstance(credential, dict):
                protected.append(redactor.redact_data(credential, field="credential"))
                continue
            safe: dict[str, Any] = {}
            for key, value in credential.items():
                normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
                if normalized in _CREDENTIAL_IDENTITY_FIELDS:
                    safe[key] = redactor.redact_data(value, field=normalized)
                elif isinstance(value, (str, bytes)) and value:
                    safe[key] = redactor.protect(value, kind=f"plugin_credential_{normalized or 'value'}")
                else:
                    safe[key] = redactor.redact_data(value, field=normalized or "credential")
            protected.append(safe)
        return protected

    def _sanitize_result(self, result: PluginResult) -> PluginResult:
        redactor = get_redactor()
        credentials = self._safe_credentials(redactor, list(result.credentials or []))
        safe = redactor.redact_data({
            "success": result.success,
            "data": result.data,
            "output": result.output,
            "artifacts": result.artifacts,
            "credentials": credentials,
            "sessions": result.sessions,
            "error": result.error,
        })
        return PluginResult(
            success=bool(safe.get("success")),
            data=dict(safe.get("data", {}) or {}),
            output=str(safe.get("output", "")),
            artifacts=list(safe.get("artifacts", []) or []),
            credentials=list(safe.get("credentials", []) or []),
            sessions=list(safe.get("sessions", []) or []),
            error=str(safe.get("error", "")),
        )

    def _safe_error_result(self, error: str, output: str = "") -> PluginResult:
        return self._sanitize_result(PluginResult(success=False, error=error, output=output))

    def execute(
        self,
        plugin_name: str,
        context: PluginContext | None = None,
        timeout: float = 120,
        **kwargs: Any,
    ) -> PluginResult:
        """Execute one plugin lifecycle in a fresh worker process."""
        descriptor = self.get_plugin(plugin_name)
        if descriptor is None:
            return self._safe_error_result(f"Plugin '{plugin_name}' not found")
        errors = self.validate(plugin_name)
        if errors:
            return self._safe_error_result(f"Validation failed: {'; '.join(errors)}")
        try:
            context_payload = self._context_payload(context)
            dumps_message(kwargs)
        except WireError as exc:
            return self._safe_error_result(f"Plugin input is not serializable: {exc}")

        redactor = get_redactor()
        self._remember_input_secrets(redactor, context_payload, kwargs)
        reply = self._invoke_worker(
            {
                "operation": "execute",
                "root": descriptor.root,
                "path": descriptor.path,
                "plugin": plugin_name,
                "context": context_payload,
                "kwargs": kwargs,
            },
            timeout=timeout,
        )
        captured = self._captured_output("", reply.stdout, reply.stderr)
        if reply.timed_out:
            return self._safe_error_result(
                f"Plugin '{plugin_name}' timed out after {timeout:g}s",
                captured,
            )
        if not reply.ok:
            detail = reply.error or "plugin worker failed"
            return self._safe_error_result(
                f"Plugin '{plugin_name}' crashed: {reply.error_type}: {detail}".replace(": :", ":"),
                captured,
            )

        result = self._normalize_result(reply.payload.get("result"))
        result.output = self._captured_output(result.output, reply.stdout, reply.stderr)
        cleanup_error = str(reply.payload.get("cleanup_error", ""))
        if cleanup_error:
            result.output = self._captured_output(
                result.output,
                "",
                f"cleanup failed: {cleanup_error}",
            )
        result = self._sanitize_result(result)
        self._apply_worker_events(reply.payload.get("events", []), plugin_name)

        for credential in result.credentials:
            event_data = credential if isinstance(credential, dict) else {"credential": credential}
            self.event_bus.emit("credential.found", event_data, source=plugin_name)
            self._dispatch_to_plugins("on_credential_found", event_data)
        for session in result.sessions:
            event_data = session if isinstance(session, dict) else {"session": session}
            self.event_bus.emit("session.opened", event_data, source=plugin_name)
            self._dispatch_to_plugins("on_session_opened", event_data)
        return result

    def check(
        self,
        plugin_name: str,
        target: str,
        timeout: float = 120,
        **kwargs: Any,
    ) -> CheckResult:
        """Run a plugin check in a fresh worker with a hard timeout."""
        descriptor = self.get_plugin(plugin_name)
        if descriptor is None:
            return self._sanitize_check(CheckResult(
                vulnerable=False,
                details=f"Plugin '{plugin_name}' not found",
            ))
        errors = self.validate(plugin_name)
        if errors:
            return self._sanitize_check(CheckResult(
                vulnerable=False,
                details=f"Validation failed: {'; '.join(errors)}",
            ))
        plugin_kwargs = dict(kwargs)
        plugin_kwargs.setdefault("timeout", timeout)
        try:
            dumps_message(plugin_kwargs)
        except WireError as exc:
            return self._sanitize_check(CheckResult(
                vulnerable=False,
                details=f"Plugin check input is not serializable: {exc}",
            ))
        get_redactor().redact_data(plugin_kwargs, field="plugin_check_arguments")
        reply = self._invoke_worker(
            {
                "operation": "check",
                "root": descriptor.root,
                "path": descriptor.path,
                "plugin": plugin_name,
                "target": target,
                "kwargs": plugin_kwargs,
            },
            timeout=timeout,
        )
        if reply.timed_out:
            return self._sanitize_check(CheckResult(
                vulnerable=False,
                details=f"Plugin '{plugin_name}' timed out after {timeout:g}s",
            ))
        if not reply.ok:
            return self._sanitize_check(CheckResult(
                vulnerable=False,
                details=f"Check failed: {reply.error_type}: {reply.error}",
            ))
        self._apply_worker_events(reply.payload.get("events", []), plugin_name)
        return self._sanitize_check(self._normalize_check(reply.payload.get("result")))

    @staticmethod
    def _normalize_check(result: Any) -> CheckResult:
        if isinstance(result, CheckResult):
            return result
        if isinstance(result, dict):
            try:
                confidence = float(result.get("confidence", 0.0))
            except (TypeError, ValueError):
                confidence = 0.0
            return CheckResult(
                vulnerable=bool(result.get("vulnerable", False)),
                confidence=confidence,
                details=str(result.get("details", "")),
                version=str(result.get("version", "")),
                evidence=str(result.get("evidence", "")),
            )
        return CheckResult(vulnerable=bool(result), details=str(result))

    @staticmethod
    def _sanitize_check(result: CheckResult) -> CheckResult:
        safe = get_redactor().redact_data(result)
        try:
            confidence = float(safe.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        return CheckResult(
            vulnerable=bool(safe.get("vulnerable", False)),
            confidence=confidence,
            details=str(safe.get("details", "")),
            version=str(safe.get("version", "")),
            evidence=str(safe.get("evidence", "")),
        )

    def _apply_worker_events(self, events: Any, default_source: str) -> None:
        if not isinstance(events, list):
            return
        redactor = get_redactor()
        for event in events:
            if not isinstance(event, dict):
                continue
            event_type = redactor.redact_text(event.get("event_type", ""), kind="plugin_event_type")
            if not event_type:
                continue
            source = redactor.redact_text(event.get("source", default_source), kind="plugin_event_source")
            data = event.get("data", {})
            if event_type == "credential.found":
                items = self._safe_credentials(redactor, [data])
                data = items[0] if items else {}
            else:
                data = redactor.redact_data(data, field="plugin_event")
            if not isinstance(data, dict):
                data = {"value": data}
            self.event_bus.emit(event_type, data, source=source or default_source)

    def _dispatch_to_plugins(self, method_name: str, data: Any) -> None:
        for descriptor in list(self.plugins.values()):
            if method_name not in descriptor.hooks:
                continue
            reply = self._invoke_worker(
                {
                    "operation": "event",
                    "root": descriptor.root,
                    "path": descriptor.path,
                    "plugin": descriptor.name,
                    "method": method_name,
                    "data": data,
                },
                timeout=_EVENT_TIMEOUT,
            )
            if reply.ok:
                self._apply_worker_events(reply.payload.get("events", []), descriptor.name)
            else:
                logging.debug("Plugin %s event hook failed: %s", descriptor.name, reply.error)

    def _normalize_result(self, result: Any) -> PluginResult:
        if isinstance(result, PluginResult):
            return result
        if isinstance(result, dict):
            success = bool(result.get("success")) or result.get("status") == "success"
            data = result.get("data", {})
            if not isinstance(data, dict):
                data = {"value": data}
            return PluginResult(
                success=success,
                data=data,
                output=str(result.get("output", "")),
                artifacts=list(result.get("artifacts", []) or []),
                credentials=list(result.get("credentials", []) or []),
                sessions=list(result.get("sessions", []) or []),
                error=str(result.get("error", "")),
            )
        return PluginResult(success=bool(result), output=str(result))

    def resolve_dependencies(self, target_plugins: list[str]) -> list[str]:
        ordered: list[str] = []
        visited: set[str] = set()
        visiting: set[str] = set()

        def dfs(plugin_name: str) -> None:
            if plugin_name in visiting:
                raise ValueError(f"Circular dependency: {plugin_name}")
            if plugin_name in visited:
                return
            descriptor = self.get_plugin(plugin_name)
            if descriptor is None:
                raise ValueError(f"Required plugin not found: {plugin_name}")
            visiting.add(plugin_name)
            for dependency in descriptor.depends_on:
                dfs(dependency)
            visiting.remove(plugin_name)
            visited.add(plugin_name)
            ordered.append(plugin_name)

        for plugin_name in target_plugins:
            dfs(plugin_name)
        return ordered

    def get_plugins_by_type(self, plugin_type: PluginType) -> list[str]:
        expected = plugin_type.value if isinstance(plugin_type, PluginType) else str(plugin_type)
        return [name for name, item in self.plugins.items() if item.plugin_type == expected]

    def get_plugins_for_stage(self, stage: KillChainStage) -> list[str]:
        expected = stage.value if isinstance(stage, KillChainStage) else int(stage)
        return [name for name, item in self.plugins.items() if item.kill_chain_stage == expected]

    def list_plugins(self) -> list[dict[str, Any]]:
        """Return the established public metadata shape from inert descriptors."""
        return [
            {
                "name": descriptor.name,
                "version": descriptor.version,
                "type": descriptor.plugin_type,
                "stage": descriptor.kill_chain_stage,
                "description": descriptor.description,
                "author": descriptor.author,
                "requires": list(descriptor.requires),
                "depends_on": list(descriptor.depends_on),
            }
            for descriptor in self.plugins.values()
        ]
