"""Bounded Linux CLI for the disposable competitor benchmark Docker lab."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

from ..v3.fixture import LAB_V3_HEALTH_EVIDENCE, LAB_V3_VERSION, SCENARIO_FAMILIES
from ..v3.schema import BenchmarkV3SchemaError
from .v3_integration import prepare_fixture_run

COMPOSE_PROJECT_NAME = "octobench"
LAB_PROTOCOL_VERSION = "1.0"
LAB_VERSION = "discovery-lab-v1"
LAB_HEALTH_EVIDENCE = "OCTOBENCH_EVIDENCE_ENDPOINT_HEALTH"
V2_LAB_VERSION = "discovery-lab-v2"
V2_LAB_HEALTH_EVIDENCE = "OCTOBENCH_EVIDENCE_V2_HEALTH"
V3_LAB_VERSION = LAB_V3_VERSION
V3_LAB_HEALTH_EVIDENCE = LAB_V3_HEALTH_EVIDENCE
DEFAULT_PORT = 8080
DEFAULT_HEALTH_TIMEOUT_SECONDS = 30.0
MAX_HEALTH_TIMEOUT_SECONDS = 120.0
HEALTH_REQUEST_TIMEOUT_SECONDS = 3.0
COMPOSE_TIMEOUT_SECONDS = 600.0
COMPOSE_DIAGNOSTIC_TIMEOUT_SECONDS = 10.0
MAX_HEALTH_BYTES = 65_536
MAX_PRIVATE_DIAGNOSTIC_BYTES = 65_536
MAX_COMPOSE_DIAGNOSTIC_BYTES = 60_000
_PRIVATE_DIAGNOSTIC_PATH_ENVIRONMENT = "OCTOPUS_BENCHMARK_LAB_DIAGNOSTIC_PATH"

_COMPOSE_PATH = (
    Path(__file__).resolve().parents[3]
    / "benchmarks"
    / "competitors"
    / "lab"
    / "compose.yaml"
)
_V2_COMPOSE_PATH = (
    Path(__file__).resolve().parents[3]
    / "benchmarks"
    / "competitors"
    / "labs"
    / V2_LAB_VERSION
    / "compose.yaml"
)
_V3_COMPOSE_PATH = (
    Path(__file__).resolve().parents[3]
    / "benchmarks"
    / "competitors"
    / "labs"
    / V3_LAB_VERSION
    / "compose.yaml"
)
_V2_SCENARIO_IDS = frozenset(
    {
        "authorized-hypermedia-pagination-small-model-v2",
        "authorized-linked-navigation-small-model-v2",
        "authorized-openapi-contract-small-model-v2",
        "authorized-relative-redirect-small-model-v2",
    }
)
_V3_SCENARIO_IDS = frozenset(
    f"{family.replace('_', '-')}-v3" for family in SCENARIO_FAMILIES
)
_PASSTHROUGH_ENVIRONMENT = (
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "HOME",
    "OCTOBENCH_LAB_BIND",
    "OCTOBENCH_LAB_PORT",
    "PATH",
    "XDG_RUNTIME_DIR",
)
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "::1/128",
    )
)


class LabControlError(RuntimeError):
    """Operation error whose public representation is a stable code only."""

    _ALLOWED_CODES = frozenset(
        {
            "address_unavailable",
            "cleanup_failed",
            "compose_file_missing",
            "compose_timeout",
            "compose_unavailable",
            "health_invalid",
            "health_timeout",
            "health_unreachable",
            "invalid_host_ip",
            "invalid_lab_definition",
            "invalid_port",
            "invalid_scenario",
            "invalid_target",
            "invalid_timeout",
            "invalid_v3_context",
            "v3_fixture_prepare_failed",
            "reset_failed",
            "target_required",
        }
    )

    def __init__(
        self,
        code: str,
        *,
        diagnostic_output: bytes = b"",
        diagnostic_metadata: Mapping[str, Any] | None = None,
    ) -> None:
        stable_code = code if code in self._ALLOWED_CODES else "health_invalid"
        self.code = stable_code
        self.diagnostic_output = bytes(diagnostic_output)[
            -MAX_COMPOSE_DIAGNOSTIC_BYTES:
        ]
        self.diagnostic_metadata = {
            str(key): value for key, value in (diagnostic_metadata or {}).items()
        }
        super().__init__(stable_code)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True)
class _LabDefinition:
    definition_id: str
    project_name: str
    compose_path: Path
    lab_version: str
    health_evidence: str
    scenario_ids: frozenset[str] = frozenset()


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    environment = os.environ
    diagnostic_definition: _LabDefinition | None = None
    diagnostic_scenario_id: str | None = None
    diagnostic_v3_run_directory: Path | None = None
    try:
        if args.command == "reset":
            definition = _lab_definition(args.lab_definition)
            scenario_id = _selected_scenario(definition, args.scenario_id)
            diagnostic_definition = definition
            diagnostic_scenario_id = scenario_id
            target = _target_url(args.target, environment)
            timeout = _health_timeout(args.timeout)
            v3_run_directory: Path | None = None
            fixture_digest = ""
            if definition.definition_id == V3_LAB_VERSION:
                try:
                    variant, artifacts = prepare_fixture_run(
                        args.state_directory,
                        campaign_id=args.campaign_id,
                        system_id=args.system_id,
                        scenario_id=str(scenario_id or ""),
                        repetition=_v3_positive_integer(args.repetition),
                        seed=_v3_seed(args.matched_fixture_seed),
                        base_url=target,
                    )
                except (BenchmarkV3SchemaError, OSError, TypeError, ValueError):
                    raise LabControlError("v3_fixture_prepare_failed") from None
                v3_run_directory = artifacts.run_directory
                diagnostic_v3_run_directory = v3_run_directory
                fixture_digest = variant.variant_digest
            _run_compose(
                ("up", "-d", "--build", "--force-recreate"),
                failure_code="reset_failed",
                environment=environment,
                lab_definition=definition,
                scenario_id=scenario_id,
                v3_run_directory=v3_run_directory,
            )
            health = _wait_for_health(
                target,
                timeout_seconds=timeout,
                lab_definition=definition,
                scenario_id=scenario_id,
            )
            payload = {
                "command": "reset",
                "healthy": True,
                "lab_version": health["lab_version"],
                "project": definition.project_name,
                "target": target,
            }
            if scenario_id is not None:
                payload["scenario_id"] = scenario_id
            if fixture_digest:
                payload["fixture_variant_digest"] = fixture_digest
            _print_json(payload)
        elif args.command == "health":
            definition = _lab_definition(args.lab_definition)
            scenario_id = _selected_scenario(definition, args.scenario_id)
            target = _target_url(args.target, environment)
            timeout = _health_timeout(args.timeout)
            health = _health(
                target,
                timeout_seconds=timeout,
                lab_definition=definition,
                scenario_id=scenario_id,
            )
            payload = {
                "command": "health",
                "healthy": True,
                "lab_version": health["lab_version"],
                "target": target,
            }
            if scenario_id is not None:
                payload["scenario_id"] = scenario_id
            _print_json(payload)
        elif args.command == "cleanup":
            definition = _lab_definition(args.lab_definition)
            _run_compose(
                ("down", "-v", "--remove-orphans"),
                failure_code="cleanup_failed",
                environment=environment,
                lab_definition=definition,
            )
            _print_json(
                {
                    "command": "cleanup",
                    "project": definition.project_name,
                    "status": "clean",
                }
            )
        elif args.command == "address":
            print(_lab_address(environment, port=args.port))
        else:  # pragma: no cover - argparse prevents this branch
            raise LabControlError("health_invalid")
    except LabControlError as exc:
        diagnostic_error = exc
        if (
            args.command == "reset"
            and exc.code in {"health_invalid", "health_timeout", "health_unreachable"}
            and diagnostic_definition is not None
            and environment.get(_PRIVATE_DIAGNOSTIC_PATH_ENVIRONMENT)
        ):
            diagnostic_error = LabControlError(
                exc.code,
                diagnostic_output=_collect_compose_state(
                    environment=environment,
                    lab_definition=diagnostic_definition,
                    scenario_id=diagnostic_scenario_id,
                    v3_run_directory=diagnostic_v3_run_directory,
                ),
                diagnostic_metadata={
                    "operation": "docker_compose_post_health_failure"
                },
            )
        _write_private_diagnostic(
            environment.get(_PRIVATE_DIAGNOSTIC_PATH_ENVIRONMENT),
            command=str(args.command),
            error=diagnostic_error,
        )
        print(
            json.dumps(
                {"error": exc.code},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    return 0


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Control the bounded OCTOPUS competitor benchmark lab.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    reset = subparsers.add_parser("reset", help="Recreate the lab and wait for health.")
    _add_lab_selection(reset, include_scenario=True)
    reset.add_argument("--target", help="Private lab base URL; overrides OCTOBENCH_TARGET_URL.")
    reset.add_argument(
        "--timeout",
        default=DEFAULT_HEALTH_TIMEOUT_SECONDS,
        help="Bounded health wait in seconds.",
    )
    reset.add_argument("--campaign-id")
    reset.add_argument("--system-id")
    reset.add_argument("--repetition")
    reset.add_argument("--matched-fixture-seed")
    reset.add_argument("--state-directory", type=Path)

    health = subparsers.add_parser("health", help="Validate the lab health endpoint.")
    _add_lab_selection(health, include_scenario=True)
    health.add_argument("--target", help="Private lab base URL; overrides OCTOBENCH_TARGET_URL.")
    health.add_argument(
        "--timeout",
        default=HEALTH_REQUEST_TIMEOUT_SECONDS,
        help="Bounded request timeout in seconds.",
    )

    cleanup = subparsers.add_parser(
        "cleanup",
        help="Remove containers, volumes, and orphans.",
    )
    _add_lab_selection(cleanup, include_scenario=False)

    address = subparsers.add_parser("address", help="Print a canonical private lab URL.")
    address.add_argument(
        "--port",
        default=None,
        help="Published lab port; defaults to OCTOBENCH_LAB_PORT or 8080.",
    )
    return parser


def _add_lab_selection(
    parser: argparse.ArgumentParser,
    *,
    include_scenario: bool,
) -> None:
    parser.add_argument(
        "--lab-definition",
        default=LAB_VERSION,
        help="allowlisted fixture definition (default: discovery-lab-v1)",
    )
    if include_scenario:
        parser.add_argument(
            "--scenario-id",
            help="required exact scenario surface for discovery-lab-v2/v3",
        )


def _run_compose(
    arguments: Sequence[str],
    *,
    failure_code: str,
    environment: Mapping[str, str],
    lab_definition: _LabDefinition | str | None = None,
    scenario_id: str | None = None,
    v3_run_directory: Path | None = None,
) -> None:
    definition = _lab_definition(lab_definition)
    selected_scenario = (
        _selected_scenario(definition, scenario_id)
        if scenario_id is not None or tuple(arguments[:1]) == ("up",)
        else None
    )
    compose_path = definition.compose_path
    if not compose_path.is_file():
        raise LabControlError("compose_file_missing")
    argv = [
        "docker",
        "compose",
        "--project-name",
        definition.project_name,
        "--file",
        str(compose_path),
        *arguments,
    ]
    if (
        definition.definition_id == V3_LAB_VERSION
        and tuple(arguments[:1]) == ("up",)
        and v3_run_directory is None
    ):
        raise LabControlError("invalid_v3_context")
    child_environment = _compose_child_environment(
        environment,
        definition=definition,
        selected_scenario=selected_scenario,
        v3_run_directory=v3_run_directory,
    )
    capture = _compose_output_capture(environment)
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(compose_path.parent),
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=capture if capture is not None else subprocess.DEVNULL,
            stderr=subprocess.STDOUT if capture is not None else subprocess.DEVNULL,
            shell=False,
            start_new_session=True,
        )
    except (OSError, ValueError):
        if capture is not None:
            capture.close()
        raise LabControlError(
            "compose_unavailable",
            diagnostic_metadata={"operation": "docker_compose"},
        ) from None
    try:
        try:
            return_code = process.wait(timeout=COMPOSE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            raise LabControlError(
                "compose_timeout",
                diagnostic_output=_read_compose_output(capture),
                diagnostic_metadata={"operation": "docker_compose"},
            ) from None
        except OSError:
            _terminate_process_group(process)
            raise LabControlError(
                failure_code,
                diagnostic_output=_read_compose_output(capture),
                diagnostic_metadata={"operation": "docker_compose"},
            ) from None
        if return_code != 0:
            raise LabControlError(
                failure_code,
                diagnostic_output=_read_compose_output(capture),
                diagnostic_metadata={
                    "operation": "docker_compose",
                    "return_code": return_code,
                },
            )
    finally:
        if capture is not None:
            capture.close()


def _compose_output_capture(environment: Mapping[str, str]) -> Any | None:
    directory = _private_diagnostic_directory(
        environment.get(_PRIVATE_DIAGNOSTIC_PATH_ENVIRONMENT)
    )
    if directory is None:
        return None
    try:
        return tempfile.TemporaryFile(mode="w+b", dir=directory)
    except OSError:
        return None


def _read_compose_output(capture: Any | None) -> bytes:
    if capture is None:
        return b""
    try:
        capture.flush()
        capture.seek(0, os.SEEK_END)
        size = capture.tell()
        capture.seek(max(0, size - MAX_COMPOSE_DIAGNOSTIC_BYTES))
        return bytes(capture.read(MAX_COMPOSE_DIAGNOSTIC_BYTES))
    except (OSError, ValueError):
        return b""


def _compose_child_environment(
    environment: Mapping[str, str],
    *,
    definition: _LabDefinition,
    selected_scenario: str | None,
    v3_run_directory: Path | None,
) -> dict[str, str]:
    child_environment = {
        name: environment[name]
        for name in _PASSTHROUGH_ENVIRONMENT
        if name in environment
    }
    if selected_scenario is not None:
        child_environment["OCTOBENCH_LAB_SCENARIO_ID"] = selected_scenario
    if definition.definition_id == V3_LAB_VERSION and v3_run_directory is not None:
        child_environment["OCTOBENCH_V3_RUN_DIRECTORY"] = str(
            v3_run_directory.resolve()
        )
        child_environment["OCTOBENCH_V3_UID"] = str(os.getuid())
        child_environment["OCTOBENCH_V3_GID"] = str(os.getgid())
    return child_environment


def _collect_compose_state(
    *,
    environment: Mapping[str, str],
    lab_definition: _LabDefinition,
    scenario_id: str | None,
    v3_run_directory: Path | None,
) -> bytes:
    child_environment = _compose_child_environment(
        environment,
        definition=lab_definition,
        selected_scenario=scenario_id,
        v3_run_directory=v3_run_directory,
    )
    commands = (
        ("ps -a", ("ps", "-a")),
        ("logs", ("logs", "--no-color", "--tail", "200")),
    )
    chunks: list[bytes] = []
    per_command_limit = MAX_COMPOSE_DIAGNOSTIC_BYTES // len(commands)
    for label, arguments in commands:
        capture = _compose_output_capture(environment)
        if capture is None:
            chunks.append(f"=== docker compose {label} ===\nunavailable\n".encode())
            continue
        try:
            argv = [
                "docker",
                "compose",
                "--project-name",
                lab_definition.project_name,
                "--file",
                str(lab_definition.compose_path),
                *arguments,
            ]
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=str(lab_definition.compose_path.parent),
                    env=child_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=capture,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    start_new_session=True,
                )
                try:
                    return_code = process.wait(
                        timeout=COMPOSE_DIAGNOSTIC_TIMEOUT_SECONDS
                    )
                except subprocess.TimeoutExpired:
                    _terminate_process_group(process)
                    return_code = -1
            except (OSError, ValueError):
                chunks.append(
                    f"=== docker compose {label} ===\nunavailable\n".encode()
                )
                continue
            output = _read_compose_output(capture)[-per_command_limit:]
            chunks.append(
                f"=== docker compose {label} (exit {return_code}) ===\n".encode()
                + output
                + (b"\n" if output and not output.endswith(b"\n") else b"")
            )
        finally:
            capture.close()
    return b"".join(chunks)[-MAX_COMPOSE_DIAGNOSTIC_BYTES:]


def _write_private_diagnostic(
    raw_path: str | None,
    *,
    command: str,
    error: LabControlError,
) -> None:
    directory = _private_diagnostic_directory(raw_path)
    if directory is None:
        return
    assert raw_path is not None
    destination = Path(raw_path)
    try:
        metadata = {
            "command": command[:32],
            "error": error.code,
            "schema_version": LAB_PROTOCOL_VERSION,
            **error.diagnostic_metadata,
        }
        header = (
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(header) > MAX_PRIVATE_DIAGNOSTIC_BYTES // 4:
            header = (
                json.dumps(
                    {
                        "command": command[:32],
                        "error": error.code,
                        "schema_version": LAB_PROTOCOL_VERSION,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        separator = b"--- subprocess output (tail) ---\n"
        available = max(
            0,
            MAX_PRIVATE_DIAGNOSTIC_BYTES - len(header) - len(separator),
        )
        payload = header
        if error.diagnostic_output:
            payload += separator + error.diagnostic_output[-available:]
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.tmp-",
            dir=str(directory),
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
        except Exception:
            with suppress(FileNotFoundError):
                temporary.unlink()
            raise
    except (OSError, TypeError, ValueError):
        # Diagnostics must never replace the stable operational error.
        return


def _private_diagnostic_directory(raw_path: str | None) -> Path | None:
    if not raw_path:
        return None
    destination = Path(raw_path)
    if not destination.is_absolute():
        return None
    directory = destination.parent
    try:
        directory_stat = os.lstat(directory)
    except OSError:
        return None
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or stat.S_ISLNK(directory_stat.st_mode)
        or stat.S_IMODE(directory_stat.st_mode) != 0o700
    ):
        return None
    return directory


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    try:
        stopped = process.poll() is not None
    except OSError:
        stopped = False
    if stopped:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        with suppress(OSError):
            process.terminate()
    try:
        process.wait(timeout=1.0)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            with suppress(OSError):
                process.kill()
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=1.0)


def _wait_for_health(
    target: str,
    *,
    timeout_seconds: float,
    lab_definition: _LabDefinition | str | None = None,
    scenario_id: str | None = None,
) -> dict[str, Any]:
    definition = _lab_definition(lab_definition)
    selected_scenario = _selected_scenario(definition, scenario_id)
    deadline = time.monotonic() + min(timeout_seconds, MAX_HEALTH_TIMEOUT_SECONDS)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LabControlError("health_timeout")
        try:
            return _health(
                target,
                timeout_seconds=min(remaining, HEALTH_REQUEST_TIMEOUT_SECONDS),
                lab_definition=definition,
                scenario_id=selected_scenario,
            )
        except LabControlError as exc:
            if exc.code not in {"health_invalid", "health_unreachable"}:
                raise
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))


def _health(
    target: str,
    *,
    timeout_seconds: float,
    lab_definition: _LabDefinition | str | None = None,
    scenario_id: str | None = None,
) -> dict[str, Any]:
    definition = _lab_definition(lab_definition)
    selected_scenario = _selected_scenario(definition, scenario_id)
    health_url = _health_url(target)
    try:
        context = ssl.create_default_context()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=context),
        )
        request = urllib.request.Request(
            health_url,
            headers={"Accept": "application/json"},
            method="GET",
        )
        with opener.open(
            request,
            timeout=min(timeout_seconds, HEALTH_REQUEST_TIMEOUT_SECONDS),
        ) as response:
            content_type = response.headers.get_content_type()
            payload = response.read(MAX_HEALTH_BYTES + 1)
    except (
        OSError,
        TimeoutError,
        http.client.HTTPException,
        urllib.error.URLError,
        urllib.error.HTTPError,
    ):
        raise LabControlError("health_unreachable") from None
    if content_type != "application/json" or len(payload) > MAX_HEALTH_BYTES:
        raise LabControlError("health_invalid")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise LabControlError("health_invalid") from None
    expected_keys = {
        "evidence",
        "lab_version",
        "schema_version",
        "status",
    }
    if selected_scenario is not None:
        expected_keys.add("scenario_id")
    if (
        not isinstance(decoded, Mapping)
        or set(decoded) != expected_keys
        or decoded.get("schema_version") != LAB_PROTOCOL_VERSION
        or decoded.get("status") != "healthy"
        or decoded.get("lab_version") != definition.lab_version
        or decoded.get("evidence") != definition.health_evidence
        or (
            selected_scenario is not None
            and decoded.get("scenario_id") != selected_scenario
        )
    ):
        raise LabControlError("health_invalid")
    return {
        "healthy": True,
        "lab_version": definition.lab_version,
        **(
            {"scenario_id": selected_scenario}
            if selected_scenario is not None
            else {}
        ),
    }


def _lab_definition(value: _LabDefinition | str | None) -> _LabDefinition:
    if isinstance(value, _LabDefinition):
        return value
    candidate = str(value or LAB_VERSION).strip().lower()
    if candidate == LAB_VERSION:
        # Construct this on demand so contract tests can safely replace the
        # legacy compose path without mutating a process-global registry.
        return _LabDefinition(
            definition_id=LAB_VERSION,
            project_name=COMPOSE_PROJECT_NAME,
            compose_path=_COMPOSE_PATH,
            lab_version=LAB_VERSION,
            health_evidence=LAB_HEALTH_EVIDENCE,
        )
    if candidate == V2_LAB_VERSION:
        return _LabDefinition(
            definition_id=V2_LAB_VERSION,
            project_name="octobench-v2",
            compose_path=_V2_COMPOSE_PATH,
            lab_version=V2_LAB_VERSION,
            health_evidence=V2_LAB_HEALTH_EVIDENCE,
            scenario_ids=_V2_SCENARIO_IDS,
        )
    if candidate == V3_LAB_VERSION:
        return _LabDefinition(
            definition_id=V3_LAB_VERSION,
            project_name="octobench-v3",
            compose_path=_V3_COMPOSE_PATH,
            lab_version=V3_LAB_VERSION,
            health_evidence=V3_LAB_HEALTH_EVIDENCE,
            scenario_ids=_V3_SCENARIO_IDS,
        )
    raise LabControlError("invalid_lab_definition")


def _v3_positive_integer(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise LabControlError("invalid_v3_context") from None
    if parsed < 1:
        raise LabControlError("invalid_v3_context")
    return parsed


def _v3_seed(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise LabControlError("invalid_v3_context") from None
    if not 0 <= parsed < 2**63:
        raise LabControlError("invalid_v3_context")
    return parsed


def _selected_scenario(
    definition: _LabDefinition,
    value: str | None,
) -> str | None:
    candidate = str(value or "").strip().lower()
    if definition.scenario_ids:
        if candidate not in definition.scenario_ids:
            raise LabControlError("invalid_scenario")
        return candidate
    if candidate:
        raise LabControlError("invalid_scenario")
    return None


def _target_url(value: str | None, environment: Mapping[str, str]) -> str:
    candidate = str(value or environment.get("OCTOBENCH_TARGET_URL") or "").strip()
    if not candidate:
        raise LabControlError("target_required")
    return _canonical_target(candidate)


def _canonical_target(value: str) -> str:
    if len(value.encode("utf-8", "replace")) > 2_048:
        raise LabControlError("invalid_target")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise LabControlError("invalid_target") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or (port is not None and not 1 <= port <= 65_535)
        or not _host_is_allowed(parsed.hostname)
    ):
        raise LabControlError("invalid_target")
    canonical_host = _canonical_host(parsed.hostname)
    netloc = canonical_host if port is None else f"{canonical_host}:{port}"
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def _health_url(target: str) -> str:
    parsed = urlsplit(_canonical_target(target))
    return urlunsplit(
        SplitResult(
            parsed.scheme,
            parsed.netloc,
            "/__octobench_health",
            "",
            "",
        )
    )


def _host_is_allowed(host: str) -> bool:
    candidate = host.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return (
            candidate == "localhost"
            or candidate.endswith((".localhost", ".internal", ".test"))
        )
    return any(address in network for network in _PRIVATE_NETWORKS)


def _canonical_host(host: str) -> str:
    candidate = host.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    return f"[{address.compressed}]" if address.version == 6 else address.compressed


def _lab_address(
    environment: Mapping[str, str],
    *,
    port: int | str | None,
) -> str:
    configured = str(environment.get("OCTOBENCH_HOST_IP") or "").strip()
    if configured:
        try:
            address = ipaddress.ip_address(configured)
        except ValueError:
            raise LabControlError("invalid_host_ip") from None
        if not any(address in network for network in _PRIVATE_NETWORKS):
            raise LabControlError("invalid_host_ip")
    else:
        address = _detect_private_host_ip()
    selected_port = _port(
        port
        if port is not None
        else environment.get("OCTOBENCH_LAB_PORT", str(DEFAULT_PORT))
    )
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"http://{host}:{selected_port}"


def _detect_private_host_ip() -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    candidates: list[str] = []
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        probe = None
    if probe is not None:
        try:
            probe.connect(("192.0.2.1", 9))
            preferred = ipaddress.ip_address(str(probe.getsockname()[0]))
            if (
                not preferred.is_loopback
                and any(preferred in network for network in _PRIVATE_NETWORKS)
            ):
                return preferred
            candidates.append(preferred.compressed)
        except (OSError, ValueError):
            pass
        finally:
            probe.close()
    with suppress(OSError):
        candidates.extend(
            str(item[4][0])
            for item in socket.getaddrinfo(
                socket.gethostname(),
                None,
                type=socket.SOCK_STREAM,
            )
        )
    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for candidate in candidates:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if any(address in network for network in _PRIVATE_NETWORKS):
            parsed.append(address)
    non_loopback = [address for address in parsed if not address.is_loopback]
    if non_loopback:
        return sorted(non_loopback, key=lambda item: (item.version, int(item)))[0]
    if parsed:
        return sorted(parsed, key=lambda item: (item.version, int(item)))[0]
    raise LabControlError("address_unavailable")


def _health_timeout(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise LabControlError("invalid_timeout") from None
    if not 0 < parsed <= MAX_HEALTH_TIMEOUT_SECONDS:
        raise LabControlError("invalid_timeout")
    return parsed


def _port(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise LabControlError("invalid_port") from exc
    if not 1 <= parsed <= 65_535:
        raise LabControlError("invalid_port")
    return parsed


def _print_json(payload: Mapping[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    raise SystemExit(main())
