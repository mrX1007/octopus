"""Fail-closed reset and health controls for authorized benchmark labs."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LAB_CONTROL_SCHEMA_VERSION = "1.0"
_PRIVATE_DIAGNOSTIC_PATH_ENVIRONMENT = "OCTOPUS_BENCHMARK_LAB_DIAGNOSTIC_PATH"
_ALLOWED_PLACEHOLDERS = frozenset(
    {
        "campaign_id",
        "lab_version",
        "repetition",
        "scenario_id",
        "seed",
        "snapshot_ref",
        "system_id",
    }
)


class LabControlError(RuntimeError):
    """Base error whose message is a stable, non-sensitive code."""


class LabResetError(LabControlError):
    """A reset or health-check failed; the campaign must stop."""

    def __init__(
        self,
        code: str,
        *,
        diagnostic_path: str | Path | None = None,
    ) -> None:
        self.diagnostic_path = (
            Path(diagnostic_path) if diagnostic_path is not None else None
        )
        super().__init__(code)


@dataclass(frozen=True)
class LabCommand:
    argv: tuple[str, ...]
    working_directory: Path
    timeout_seconds: float = 300.0
    environment_passthrough: tuple[str, ...] = ()

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        base_directory: str | Path,
    ) -> LabCommand:
        if set(payload) - {
            "argv",
            "environment_passthrough",
            "timeout_seconds",
            "working_directory",
        }:
            raise LabControlError("unknown_lab_command_key")
        raw_argv = payload.get("argv")
        if not isinstance(raw_argv, Sequence) or isinstance(raw_argv, (str, bytes)):
            raise LabControlError("invalid_lab_command_argv")
        argv = tuple(str(item) for item in raw_argv)
        if not argv or len(argv) > 64 or any(not item or "\x00" in item for item in argv):
            raise LabControlError("invalid_lab_command_argv")
        _validate_placeholders(argv)
        raw_cwd = str(payload.get("working_directory") or ".")
        cwd = (Path(base_directory) / raw_cwd).resolve()
        try:
            timeout = float(payload.get("timeout_seconds", 300.0))
        except (TypeError, ValueError) as exc:
            raise LabControlError("invalid_lab_command_timeout") from exc
        if timeout <= 0 or timeout > 3600:
            raise LabControlError("invalid_lab_command_timeout")
        raw_environment = payload.get("environment_passthrough") or []
        if not isinstance(raw_environment, Sequence) or isinstance(
            raw_environment, (str, bytes)
        ):
            raise LabControlError("invalid_lab_environment_passthrough")
        environment: list[str] = []
        for item in raw_environment:
            name = str(item or "").strip()
            if not _valid_environment_name(name):
                raise LabControlError("invalid_lab_environment_passthrough")
            if name.startswith("OCTOPUS_BENCHMARK_"):
                raise LabControlError("reserved_lab_environment_name")
            if name not in environment:
                environment.append(name)
        return cls(
            argv=argv,
            working_directory=cwd,
            timeout_seconds=timeout,
            environment_passthrough=tuple(environment),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "working_directory": str(self.working_directory),
            "timeout_seconds": self.timeout_seconds,
            "environment_passthrough": list(self.environment_passthrough),
        }


@dataclass(frozen=True)
class LabRunContext:
    campaign_id: str
    system_id: str
    scenario_id: str
    repetition: int
    seed: int
    lab_version: str
    snapshot_ref: str

    def substitutions(self) -> dict[str, str]:
        return {
            "campaign_id": self.campaign_id,
            "system_id": self.system_id,
            "scenario_id": self.scenario_id,
            "repetition": str(self.repetition),
            "seed": str(self.seed),
            "lab_version": self.lab_version,
            "snapshot_ref": self.snapshot_ref,
        }


@dataclass(frozen=True)
class ResetAttestation:
    context: LabRunContext
    reset_duration_seconds: float
    health_duration_seconds: float
    reset_command_sha256: str
    health_command_sha256: str
    observed_at: float
    schema_version: str = LAB_CONTROL_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": "healthy",
            "campaign_id": self.context.campaign_id,
            "system_id": self.context.system_id,
            "scenario_id": self.context.scenario_id,
            "repetition": self.context.repetition,
            "seed": self.context.seed,
            "lab_version": self.context.lab_version,
            "snapshot_ref": self.context.snapshot_ref,
            "reset_duration_seconds": round(self.reset_duration_seconds, 6),
            "health_duration_seconds": round(self.health_duration_seconds, 6),
            "reset_command_sha256": self.reset_command_sha256,
            "health_command_sha256": self.health_command_sha256,
            "observed_at": self.observed_at,
        }


class CommandLabController:
    """Run trusted shell-free reset and health commands before an adapter run."""

    def __init__(
        self,
        reset: LabCommand,
        health: LabCommand,
        *,
        cleanup: LabCommand | None = None,
        environment: Mapping[str, str] | None = None,
        diagnostics_directory: str | Path | None = None,
        clock: Any = time.time,
        monotonic: Any = time.monotonic,
    ) -> None:
        self.reset_command = reset
        self.health_command = health
        self.cleanup_command = cleanup
        self.environment = {str(key): str(value) for key, value in (environment or {}).items()}
        self.diagnostics_directory = (
            Path(diagnostics_directory) if diagnostics_directory is not None else None
        )
        self.clock = clock
        self.monotonic = monotonic

    def reset_and_health(self, context: LabRunContext) -> ResetAttestation:
        reset_duration = self._run(self.reset_command, context, phase="reset")
        health_duration = self._run(self.health_command, context, phase="health")
        return ResetAttestation(
            context=context,
            reset_duration_seconds=reset_duration,
            health_duration_seconds=health_duration,
            reset_command_sha256=_command_digest(self.reset_command),
            health_command_sha256=_command_digest(self.health_command),
            observed_at=float(self.clock()),
        )

    def cleanup(self, context: LabRunContext) -> None:
        if self.cleanup_command is not None:
            self._run(self.cleanup_command, context, phase="cleanup")

    def _run(self, command: LabCommand, context: LabRunContext, *, phase: str) -> float:
        argv = _format_argv(command.argv, context.substitutions())
        environment = {
            name: self.environment[name]
            for name in command.environment_passthrough
            if name in self.environment
        }
        environment.setdefault("PATH", self.environment.get("PATH", os.defpath))
        environment.update(
            {
            "OCTOPUS_BENCHMARK_CAMPAIGN_ID": context.campaign_id,
            "OCTOPUS_BENCHMARK_SYSTEM_ID": context.system_id,
            "OCTOPUS_BENCHMARK_SCENARIO_ID": context.scenario_id,
            "OCTOPUS_BENCHMARK_REPETITION": str(context.repetition),
            "OCTOPUS_BENCHMARK_SEED": str(context.seed),
            "OCTOPUS_BENCHMARK_LAB_PHASE": phase,
            "OCTOPUS_BENCHMARK_LAB_VERSION": context.lab_version,
            "OCTOPUS_BENCHMARK_SNAPSHOT_REF": context.snapshot_ref,
            }
        )
        diagnostic_path = self._diagnostic_path(context, phase=phase)
        if diagnostic_path is not None:
            environment[_PRIVATE_DIAGNOSTIC_PATH_ENVIRONMENT] = str(diagnostic_path)
        started = self.monotonic()
        try:
            process = subprocess.Popen(
                argv,
                cwd=str(command.working_directory),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                start_new_session=os.name == "posix",
            )
        except (OSError, ValueError):
            raise _lab_reset_error(
                f"lab_{phase}_unavailable",
                diagnostic_path,
            ) from None
        try:
            return_code = process.wait(timeout=command.timeout_seconds)
        except subprocess.TimeoutExpired:
            _terminate_process(process)
            raise _lab_reset_error(
                f"lab_{phase}_timeout",
                diagnostic_path,
            ) from None
        except BaseException:
            # Reset/health/cleanup commands own a separate process group. An
            # operator interrupt must tear it down before the caller attempts
            # cleanup; otherwise a late reset can recreate the lab afterward.
            _terminate_process(process)
            raise
        if return_code != 0:
            raise _lab_reset_error(f"lab_{phase}_failed", diagnostic_path)
        return max(0.0, float(self.monotonic() - started))

    def _diagnostic_path(
        self,
        context: LabRunContext,
        *,
        phase: str,
    ) -> Path | None:
        if self.diagnostics_directory is None:
            return None
        directory = Path(os.path.abspath(self.diagnostics_directory))
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory_stat = os.lstat(directory)
            if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(
                directory_stat.st_mode
            ):
                return None
            os.chmod(directory, 0o700)
        except OSError:
            return None
        identity = json.dumps(
            {**context.substitutions(), "phase": phase},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(identity).hexdigest()
        return directory / f"lab-{phase}-{digest}.log"


def _lab_reset_error(code: str, diagnostic_path: Path | None) -> LabResetError:
    available_path: Path | None = None
    if diagnostic_path is not None:
        try:
            path_stat = os.lstat(diagnostic_path)
            if stat.S_ISREG(path_stat.st_mode) and not stat.S_ISLNK(path_stat.st_mode):
                available_path = diagnostic_path
        except OSError:
            pass
    return LabResetError(code, diagnostic_path=available_path)


def command_executable_available(command: LabCommand, environment: Mapping[str, str]) -> bool:
    """Check command availability without launching it."""

    if not command.working_directory.is_dir():
        return False
    executable = command.argv[0]
    if "{" in executable or "}" in executable:
        return False
    candidate = Path(executable)
    if candidate.is_absolute():
        return candidate.is_file() and os.access(candidate, os.X_OK)
    if "/" in executable:
        resolved = (command.working_directory / candidate).resolve()
        return resolved.is_file() and os.access(resolved, os.X_OK)
    return shutil.which(executable, path=environment.get("PATH", os.defpath)) is not None


def _format_argv(argv: Sequence[str], substitutions: Mapping[str, str]) -> list[str]:
    try:
        return [item.format_map(substitutions) for item in argv]
    except (KeyError, ValueError):
        raise LabResetError("lab_command_placeholder_error") from None


def _validate_placeholders(argv: Sequence[str]) -> None:
    import string

    for argument in argv:
        try:
            for _literal, field_name, format_spec, conversion in string.Formatter().parse(argument):
                if field_name is None:
                    continue
                if field_name not in _ALLOWED_PLACEHOLDERS or format_spec or conversion:
                    raise LabControlError("invalid_lab_command_placeholder")
        except ValueError:
            raise LabControlError("invalid_lab_command_placeholder") from None


def _command_digest(command: LabCommand) -> str:
    encoded = json.dumps(
        command.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _terminate_process(process: subprocess.Popen[Any]) -> None:
    if os.name == "posix":
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGTERM)
    elif process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait()


def _valid_environment_name(value: str) -> bool:
    return bool(value) and value.isascii() and (value[0].isalpha() or value[0] == "_") and all(
        character.isalnum() or character == "_" for character in value
    )


__all__ = [
    "LAB_CONTROL_SCHEMA_VERSION",
    "CommandLabController",
    "LabCommand",
    "LabControlError",
    "LabResetError",
    "LabRunContext",
    "ResetAttestation",
    "command_executable_available",
]
