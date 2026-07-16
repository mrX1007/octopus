"""Bounded, shell-free command runner for external benchmark systems."""

from __future__ import annotations

import json
import math
import os
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any

from ..schema import BenchmarkScenario
from .schema import SystemManifest

MAX_SCENARIO_BYTES = 2_000_000
MAX_EFFECTIVE_OUTPUT_BYTES = 16_000_000
MAX_EFFECTIVE_TIMEOUT_SECONDS = 3_600.0
_MAX_RESULT_ITEMS = 512
_MAX_RESULT_TEXT_BYTES = 4_096
_RESULT_IDENTIFIER = __import__("re").compile(r"^[a-z0-9][a-z0-9_.:-]{0,255}$")
_RESULT_STATUSES = frozenset({"succeeded", "failed", "timeout", "partial", "invalid"})


class SystemRunnerError(RuntimeError):
    """Base class whose message is always a stable, non-sensitive code."""

    error_code = "system_runner_error"

    def __init__(self) -> None:
        super().__init__(self.error_code)


class SystemUnavailableError(SystemRunnerError):
    """The configured adapter executable or working directory is unavailable."""

    error_code = "system_unavailable"


class SystemProtocolError(SystemRunnerError):
    """The adapter violated the bounded JSON result protocol."""

    error_code = "system_protocol_error"


class CommandSystemRunner:
    """Adapt a :class:`SystemManifest` to the benchmark harness callable API."""

    def __init__(
        self,
        manifest: SystemManifest,
        *,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
        temporary_directory: str | Path | None = None,
    ) -> None:
        self.manifest = manifest
        self.timeout_seconds = _positive_optional_number(timeout_seconds)
        self.max_output_bytes = _positive_optional_integer(max_output_bytes)
        self.temporary_directory = (
            Path(temporary_directory) if temporary_directory is not None else None
        )

    def __call__(
        self,
        scenario: BenchmarkScenario,
        repetition: int,
        seed: int,
    ) -> Mapping[str, Any]:
        timeout = self._effective_timeout(scenario)
        output_limit = self._effective_output_limit(scenario)
        max_tools = _positive_integer(scenario.budgets.get("max_tools"))
        started = time.monotonic()

        try:
            with tempfile.TemporaryDirectory(
                prefix="octopus-benchmark-adapter-",
                dir=self.temporary_directory,
            ) as temporary:
                root = Path(temporary)
                scenario_path = root / "scenario.json"
                output_path = root / "result.json"
                _write_scenario(scenario, scenario_path)
                argv = self._argv(
                    scenario_path=scenario_path,
                    output_path=output_path,
                    repetition=repetition,
                    seed=seed,
                )
                cwd = self._working_directory()
                environment = self._environment(
                    scenario=scenario,
                    scenario_path=scenario_path,
                    output_path=output_path,
                    repetition=repetition,
                    seed=seed,
                )
                try:
                    process = subprocess.Popen(
                        argv,
                        cwd=str(cwd),
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        shell=False,
                        start_new_session=os.name == "posix",
                    )
                except (OSError, ValueError):
                    raise SystemUnavailableError() from None

                return_code, log_bytes, timed_out, output_exceeded = _monitor_process(
                    process,
                    timeout_seconds=timeout,
                    output_limit=output_limit,
                )
                duration = max(0.0, time.monotonic() - started)
                if timed_out:
                    return _empty_result("timeout", duration)
                if output_exceeded:
                    raise SystemProtocolError()
                if return_code != 0:
                    return _empty_result("failed", duration)
                remaining_output = output_limit - log_bytes
                raw_result = _read_result(output_path, remaining_output)
                return _normalize_result(
                    raw_result,
                    max_tools=max_tools,
                    duration_seconds=duration,
                )
        except SystemRunnerError:
            raise
        except (OSError, ValueError):
            raise SystemUnavailableError() from None

    def public_metadata(self) -> dict[str, Any]:
        """Metadata suitable for aggregate publication, with no environment values."""

        return self.manifest.to_public_dict()

    def _effective_timeout(self, scenario: BenchmarkScenario) -> float:
        scenario_limit = float(_positive_number(scenario.budgets.get("max_seconds")))
        candidates = [scenario_limit, MAX_EFFECTIVE_TIMEOUT_SECONDS]
        if self.timeout_seconds is not None:
            candidates.append(self.timeout_seconds)
        return min(candidates)

    def _effective_output_limit(self, scenario: BenchmarkScenario) -> int:
        scenario_limit = _positive_integer(scenario.budgets.get("max_output_bytes"))
        candidates = [scenario_limit, MAX_EFFECTIVE_OUTPUT_BYTES]
        if self.max_output_bytes is not None:
            candidates.append(self.max_output_bytes)
        return min(candidates)

    def _working_directory(self) -> Path:
        base = (
            self.manifest.source_path.parent
            if self.manifest.source_path is not None
            else Path.cwd()
        ).resolve()
        candidate = (base / self.manifest.adapter.cwd).resolve()
        try:
            candidate.relative_to(base)
        except ValueError:
            raise SystemUnavailableError() from None
        if not candidate.is_dir():
            raise SystemUnavailableError()
        return candidate

    def _argv(
        self,
        *,
        scenario_path: Path,
        output_path: Path,
        repetition: int,
        seed: int,
    ) -> list[str]:
        substitutions = {
            "scenario_path": str(scenario_path),
            "output_path": str(output_path),
            "repetition": str(repetition),
            "seed": str(seed),
            "system_id": self.manifest.system_id,
        }
        try:
            argv = [item.format_map(substitutions) for item in self.manifest.adapter.argv]
        except (KeyError, ValueError):
            raise SystemProtocolError() from None
        if any(len(item.encode("utf-8", "replace")) > 16_384 for item in argv):
            raise SystemProtocolError()
        return argv

    def _environment(
        self,
        *,
        scenario: BenchmarkScenario,
        scenario_path: Path,
        output_path: Path,
        repetition: int,
        seed: int,
    ) -> dict[str, str]:
        environment = {
            name: os.environ[name]
            for name in self.manifest.adapter.env_passthrough
            if name in os.environ
        }
        environment.update(
            {
                "OCTOPUS_BENCHMARK_SCHEMA_VERSION": "1.0",
                "OCTOPUS_BENCHMARK_SYSTEM_ID": self.manifest.system_id,
                "OCTOPUS_BENCHMARK_TRACK": self.manifest.track,
                "OCTOPUS_BENCHMARK_EXECUTION_MODE": self.manifest.execution_mode,
                "OCTOPUS_BENCHMARK_SCENARIO_ID": scenario.scenario_id,
                "OCTOPUS_BENCHMARK_SCENARIO_PATH": str(scenario_path),
                "OCTOPUS_BENCHMARK_OUTPUT_PATH": str(output_path),
                "OCTOPUS_BENCHMARK_REPETITION": str(repetition),
                "OCTOPUS_BENCHMARK_SEED": str(seed),
            }
        )
        return environment


def _write_scenario(scenario: BenchmarkScenario, destination: Path) -> None:
    payload = (
        json.dumps(
            scenario.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_SCENARIO_BYTES:
        raise SystemProtocolError()
    destination.write_bytes(payload)


def _monitor_process(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
    output_limit: int,
) -> tuple[int, int, bool, bool]:
    stdout = process.stdout
    if stdout is None:
        _cleanup_process_tree(process)
        raise SystemUnavailableError()
    with suppress(AttributeError, OSError):
        os.set_blocking(stdout.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    captured = 0
    timed_out = False
    output_exceeded = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 and process.poll() is None:
                timed_out = True
                break
            events = selector.select(max(0.0, min(0.05, remaining)))
            for key, _mask in events:
                try:
                    chunk = os.read(key.fd, 65_536)
                except OSError:
                    chunk = b""
                if chunk:
                    captured += len(chunk)
                    if captured > output_limit:
                        output_exceeded = True
                        break
                else:
                    with suppress(KeyError, ValueError):
                        selector.unregister(key.fileobj)
            if output_exceeded:
                break
            if process.poll() is not None:
                # Drain bytes already available without waiting for descendants
                # that incorrectly inherited the adapter's output stream.
                for key in list(selector.get_map().values()):
                    try:
                        chunk = os.read(key.fd, 65_536)
                    except OSError:
                        chunk = b""
                    captured += len(chunk)
                    if captured > output_limit:
                        output_exceeded = True
                break
    finally:
        selector.close()
        stdout.close()
        _cleanup_process_tree(process)
    return process.returncode or 0, captured, timed_out, output_exceeded


def _cleanup_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        delivered = False
        try:
            os.killpg(process.pid, signal.SIGTERM)
            delivered = True
        except (ProcessLookupError, PermissionError):
            pass
        if delivered:
            time.sleep(0.02)
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
    elif process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            process.kill()
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _read_result(path: Path, remaining_output: int) -> Mapping[str, Any]:
    if remaining_output <= 0:
        raise SystemProtocolError()
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SystemProtocolError()
        if metadata.st_size <= 0 or metadata.st_size > remaining_output:
            raise SystemProtocolError()
        with path.open("rb") as result_file:
            payload = result_file.read(remaining_output + 1)
        if len(payload) > remaining_output:
            raise SystemProtocolError()
        decoded = json.loads(payload.decode("utf-8"))
    except SystemProtocolError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise SystemProtocolError() from None
    if not isinstance(decoded, Mapping):
        raise SystemProtocolError()
    return decoded


def _normalize_result(
    result: Mapping[str, Any],
    *,
    max_tools: int,
    duration_seconds: float,
) -> dict[str, Any]:
    status = str(result.get("status") or "succeeded").strip().lower()
    if status not in _RESULT_STATUSES:
        raise SystemProtocolError()
    actions = _identifier_list(result.get("actions") or [])
    if len(actions) > max_tools:
        raise SystemProtocolError()
    metrics = _metrics(result.get("metrics") or {})
    return {
        "status": status,
        "actions": actions,
        "reported_findings": _identifier_list(
            result.get("reported_findings") or []
        ),
        "verified_findings": _identifier_list(
            result.get("verified_findings") or []
        ),
        "coverage_gaps": _identifier_list(result.get("coverage_gaps") or []),
        "metrics": metrics,
        "artifact_refs": _text_list(result.get("artifact_refs") or []),
        "duration_seconds": duration_seconds,
    }


def _identifier_list(value: Any) -> list[str]:
    values = _sequence(value)
    if len(values) > _MAX_RESULT_ITEMS:
        raise SystemProtocolError()
    result: list[str] = []
    for item in values:
        candidate = str(item or "").strip().lower()
        if not _RESULT_IDENTIFIER.fullmatch(candidate):
            raise SystemProtocolError()
        result.append(candidate)
    return result


def _text_list(value: Any) -> list[str]:
    values = _sequence(value)
    if len(values) > _MAX_RESULT_ITEMS:
        raise SystemProtocolError()
    result: list[str] = []
    for item in values:
        candidate = str(item or "").strip()
        if (
            not candidate
            or "\x00" in candidate
            or len(candidate.encode("utf-8", "replace")) > _MAX_RESULT_TEXT_BYTES
        ):
            raise SystemProtocolError()
        result.append(candidate)
    return result


def _metrics(value: Any) -> dict[str, float]:
    if not isinstance(value, Mapping) or len(value) > _MAX_RESULT_ITEMS:
        raise SystemProtocolError()
    result: dict[str, float] = {}
    for key, raw in value.items():
        name = str(key or "").strip().lower()
        if not _RESULT_IDENTIFIER.fullmatch(name) or isinstance(raw, bool):
            raise SystemProtocolError()
        try:
            number = float(raw)
        except (TypeError, ValueError):
            raise SystemProtocolError() from None
        if not math.isfinite(number) or number < 0:
            raise SystemProtocolError()
        result[name] = number
    return result


def _sequence(value: Any) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise SystemProtocolError()
    return value


def _empty_result(status: str, duration_seconds: float) -> dict[str, Any]:
    return {
        "status": status,
        "actions": [],
        "reported_findings": [],
        "verified_findings": [],
        "coverage_gaps": [],
        "metrics": {},
        "artifact_refs": [],
        "duration_seconds": duration_seconds,
    }


def _positive_number(value: Any) -> float:
    if isinstance(value, bool):
        raise SystemProtocolError()
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise SystemProtocolError() from None
    if not math.isfinite(parsed) or parsed <= 0:
        raise SystemProtocolError()
    return parsed


def _positive_integer(value: Any) -> int:
    if isinstance(value, bool):
        raise SystemProtocolError()
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise SystemProtocolError() from None
    if parsed <= 0:
        raise SystemProtocolError()
    return parsed


def _positive_optional_number(value: Any) -> float | None:
    if value is None:
        return None
    return _positive_number(value)


def _positive_optional_integer(value: Any) -> int | None:
    if value is None:
        return None
    return _positive_integer(value)


__all__ = [
    "MAX_EFFECTIVE_OUTPUT_BYTES",
    "MAX_EFFECTIVE_TIMEOUT_SECONDS",
    "MAX_SCENARIO_BYTES",
    "CommandSystemRunner",
    "SystemProtocolError",
    "SystemRunnerError",
    "SystemUnavailableError",
]
