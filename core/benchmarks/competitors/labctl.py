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
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

COMPOSE_PROJECT_NAME = "octobench"
LAB_PROTOCOL_VERSION = "1.0"
LAB_VERSION = "discovery-lab-v1"
LAB_HEALTH_EVIDENCE = "OCTOBENCH_EVIDENCE_ENDPOINT_HEALTH"
DEFAULT_PORT = 8080
DEFAULT_HEALTH_TIMEOUT_SECONDS = 30.0
MAX_HEALTH_TIMEOUT_SECONDS = 120.0
HEALTH_REQUEST_TIMEOUT_SECONDS = 3.0
COMPOSE_TIMEOUT_SECONDS = 600.0
MAX_HEALTH_BYTES = 65_536

_COMPOSE_PATH = (
    Path(__file__).resolve().parents[3]
    / "benchmarks"
    / "competitors"
    / "lab"
    / "compose.yaml"
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
            "invalid_port",
            "invalid_target",
            "invalid_timeout",
            "reset_failed",
            "target_required",
        }
    )

    def __init__(self, code: str) -> None:
        stable_code = code if code in self._ALLOWED_CODES else "health_invalid"
        self.code = stable_code
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


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    environment = os.environ
    try:
        if args.command == "reset":
            target = _target_url(args.target, environment)
            timeout = _health_timeout(args.timeout)
            _run_compose(
                ("up", "-d", "--build", "--force-recreate"),
                failure_code="reset_failed",
                environment=environment,
            )
            health = _wait_for_health(target, timeout_seconds=timeout)
            _print_json(
                {
                    "command": "reset",
                    "healthy": True,
                    "lab_version": health["lab_version"],
                    "project": COMPOSE_PROJECT_NAME,
                    "target": target,
                }
            )
        elif args.command == "health":
            target = _target_url(args.target, environment)
            timeout = _health_timeout(args.timeout)
            health = _health(target, timeout_seconds=timeout)
            _print_json(
                {
                    "command": "health",
                    "healthy": True,
                    "lab_version": health["lab_version"],
                    "target": target,
                }
            )
        elif args.command == "cleanup":
            _run_compose(
                ("down", "-v", "--remove-orphans"),
                failure_code="cleanup_failed",
                environment=environment,
            )
            _print_json(
                {
                    "command": "cleanup",
                    "project": COMPOSE_PROJECT_NAME,
                    "status": "clean",
                }
            )
        elif args.command == "address":
            print(_lab_address(environment, port=args.port))
        else:  # pragma: no cover - argparse prevents this branch
            raise LabControlError("health_invalid")
    except LabControlError as exc:
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
    reset.add_argument("--target", help="Private lab base URL; overrides OCTOBENCH_TARGET_URL.")
    reset.add_argument(
        "--timeout",
        default=DEFAULT_HEALTH_TIMEOUT_SECONDS,
        help="Bounded health wait in seconds.",
    )

    health = subparsers.add_parser("health", help="Validate the lab health endpoint.")
    health.add_argument("--target", help="Private lab base URL; overrides OCTOBENCH_TARGET_URL.")
    health.add_argument(
        "--timeout",
        default=HEALTH_REQUEST_TIMEOUT_SECONDS,
        help="Bounded request timeout in seconds.",
    )

    subparsers.add_parser("cleanup", help="Remove containers, volumes, and orphans.")

    address = subparsers.add_parser("address", help="Print a canonical private lab URL.")
    address.add_argument(
        "--port",
        default=None,
        help="Published lab port; defaults to OCTOBENCH_LAB_PORT or 8080.",
    )
    return parser


def _run_compose(
    arguments: Sequence[str],
    *,
    failure_code: str,
    environment: Mapping[str, str],
) -> None:
    if not _COMPOSE_PATH.is_file():
        raise LabControlError("compose_file_missing")
    argv = [
        "docker",
        "compose",
        "--project-name",
        COMPOSE_PROJECT_NAME,
        "--file",
        str(_COMPOSE_PATH),
        *arguments,
    ]
    child_environment = {
        name: environment[name]
        for name in _PASSTHROUGH_ENVIRONMENT
        if name in environment
    }
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(_COMPOSE_PATH.parent),
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            start_new_session=True,
        )
    except (OSError, ValueError):
        raise LabControlError("compose_unavailable") from None
    try:
        return_code = process.wait(timeout=COMPOSE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _terminate_process_group(process)
        raise LabControlError("compose_timeout") from None
    except OSError:
        _terminate_process_group(process)
        raise LabControlError(failure_code) from None
    if return_code != 0:
        raise LabControlError(failure_code)


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


def _wait_for_health(target: str, *, timeout_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + min(timeout_seconds, MAX_HEALTH_TIMEOUT_SECONDS)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LabControlError("health_timeout")
        try:
            return _health(
                target,
                timeout_seconds=min(remaining, HEALTH_REQUEST_TIMEOUT_SECONDS),
            )
        except LabControlError as exc:
            if exc.code not in {"health_invalid", "health_unreachable"}:
                raise
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))


def _health(target: str, *, timeout_seconds: float) -> dict[str, Any]:
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
    if (
        not isinstance(decoded, Mapping)
        or set(decoded) != {
            "evidence",
            "lab_version",
            "schema_version",
            "status",
        }
        or decoded.get("schema_version") != LAB_PROTOCOL_VERSION
        or decoded.get("status") != "healthy"
        or decoded.get("lab_version") != LAB_VERSION
        or decoded.get("evidence") != LAB_HEALTH_EVIDENCE
    ):
        raise LabControlError("health_invalid")
    return {
        "healthy": True,
        "lab_version": LAB_VERSION,
    }


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
            candidates.append(str(probe.getsockname()[0]))
        except OSError:
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
