"""Bounded Docker competitor-lab control contract tests."""

from __future__ import annotations

import ipaddress
import json
import ssl
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from core.benchmarks.competitors import labctl

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


class _Headers:
    def __init__(self, content_type: str = "application/json") -> None:
        self.content_type = content_type

    def get_content_type(self) -> str:
        return self.content_type


class _Response:
    def __init__(self, payload: bytes, content_type: str = "application/json") -> None:
        self.payload = payload
        self.headers = _Headers(content_type)

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def read(self, count: int) -> bytes:
        return self.payload[:count]


class _SuccessfulProcess:
    pid = 12345

    def wait(self, *, timeout: float) -> int:
        assert timeout == labctl.COMPOSE_TIMEOUT_SECONDS
        return 0


def _compose_process_factory(calls: list[tuple[list[str], dict[str, Any]]]):
    def factory(argv: list[str], **kwargs: Any) -> _SuccessfulProcess:
        calls.append((argv, kwargs))
        return _SuccessfulProcess()

    return factory


def test_reset_uses_fixed_shell_free_compose_project_then_bounded_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n", encoding="utf-8")
    calls: list[tuple[list[str], dict[str, Any]]] = []
    health_calls: list[tuple[str, float]] = []
    monkeypatch.setattr(labctl, "_COMPOSE_PATH", compose)
    monkeypatch.setattr(
        labctl.subprocess,
        "Popen",
        _compose_process_factory(calls),
    )

    def healthy(
        target: str,
        *,
        timeout_seconds: float,
        lab_definition: Any,
        scenario_id: str | None,
    ) -> dict[str, Any]:
        health_calls.append((target, timeout_seconds))
        assert lab_definition.lab_version == "discovery-lab-v1"
        assert scenario_id is None
        return {"healthy": True, "lab_version": "discovery-lab-v1"}

    monkeypatch.setattr(labctl, "_wait_for_health", healthy)

    exit_code = labctl.main(
        ["reset", "--target", "http://127.0.0.1:8080", "--timeout", "7"]
    )

    output = json.loads(capsys.readouterr().out)
    argv, options = calls[0]
    assert exit_code == 0
    assert argv == [
        "docker",
        "compose",
        "--project-name",
        "octobench",
        "--file",
        str(compose),
        "up",
        "-d",
        "--build",
        "--force-recreate",
    ]
    assert options["shell"] is False
    assert options["stdout"] is subprocess.DEVNULL
    assert options["stderr"] is subprocess.DEVNULL
    assert options["start_new_session"] is True
    assert health_calls == [("http://127.0.0.1:8080", 7.0)]
    assert output == {
        "command": "reset",
        "healthy": True,
        "lab_version": "discovery-lab-v1",
        "project": "octobench",
        "target": "http://127.0.0.1:8080",
    }


def test_cleanup_uses_bounded_compose_down_without_raw_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n", encoding="utf-8")
    calls: list[tuple[list[str], dict[str, Any]]] = []
    monkeypatch.setattr(labctl, "_COMPOSE_PATH", compose)
    monkeypatch.setattr(
        labctl.subprocess,
        "Popen",
        _compose_process_factory(calls),
    )

    assert labctl.main(["cleanup"]) == 0

    output = json.loads(capsys.readouterr().out)
    assert calls[0][0][-3:] == ["down", "-v", "--remove-orphans"]
    assert output == {
        "command": "cleanup",
        "project": "octobench",
        "status": "clean",
    }


def test_v2_reset_uses_allowlisted_compose_and_attests_exact_scenario(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n", encoding="utf-8")
    calls: list[tuple[list[str], dict[str, Any]]] = []
    health_calls: list[tuple[str, str]] = []
    scenario_id = "authorized-hypermedia-pagination-small-model-v2"
    monkeypatch.setattr(labctl, "_V2_COMPOSE_PATH", compose)
    monkeypatch.setattr(
        labctl.subprocess,
        "Popen",
        _compose_process_factory(calls),
    )

    def healthy(
        target: str,
        *,
        timeout_seconds: float,
        lab_definition: Any,
        scenario_id: str | None,
    ) -> dict[str, Any]:
        assert timeout_seconds == 8.0
        assert scenario_id is not None
        health_calls.append((target, scenario_id))
        return {
            "healthy": True,
            "lab_version": lab_definition.lab_version,
            "scenario_id": scenario_id,
        }

    monkeypatch.setattr(labctl, "_wait_for_health", healthy)

    assert labctl.main(
        [
            "reset",
            "--lab-definition",
            "discovery-lab-v2",
            "--scenario-id",
            scenario_id,
            "--target",
            "http://127.0.0.1:8080",
            "--timeout",
            "8",
        ]
    ) == 0

    argv, options = calls[0]
    assert argv == [
        "docker",
        "compose",
        "--project-name",
        "octobench-v2",
        "--file",
        str(compose),
        "up",
        "-d",
        "--build",
        "--force-recreate",
    ]
    assert options["env"]["OCTOBENCH_LAB_SCENARIO_ID"] == scenario_id
    assert health_calls == [("http://127.0.0.1:8080", scenario_id)]
    assert json.loads(capsys.readouterr().out) == {
        "command": "reset",
        "healthy": True,
        "lab_version": "discovery-lab-v2",
        "project": "octobench-v2",
        "scenario_id": scenario_id,
        "target": "http://127.0.0.1:8080",
    }


def test_v2_health_rejects_wrong_scenario_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = "authorized-linked-navigation-small-model-v2"

    class Opener:
        def open(self, *_args: Any, **_kwargs: Any) -> _Response:
            return _Response(
                json.dumps(
                    {
                        "evidence": "OCTOBENCH_EVIDENCE_V2_HEALTH",
                        "lab_version": "discovery-lab-v2",
                        "scenario_id": "authorized-openapi-contract-small-model-v2",
                        "schema_version": "1.0",
                        "status": "healthy",
                    }
                ).encode()
            )

    monkeypatch.setattr(
        labctl.urllib.request,
        "build_opener",
        lambda *_handlers: Opener(),
    )

    with pytest.raises(labctl.LabControlError, match=r"^health_invalid$"):
        labctl._health(
            "http://127.0.0.1:8080",
            timeout_seconds=3,
            lab_definition="discovery-lab-v2",
            scenario_id=requested,
        )


def test_v2_health_accepts_exact_scenario_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = "authorized-linked-navigation-small-model-v2"

    class Opener:
        def open(self, *_args: Any, **_kwargs: Any) -> _Response:
            return _Response(
                json.dumps(
                    {
                        "evidence": "OCTOBENCH_EVIDENCE_V2_HEALTH",
                        "lab_version": "discovery-lab-v2",
                        "scenario_id": requested,
                        "schema_version": "1.0",
                        "status": "healthy",
                    }
                ).encode()
            )

    monkeypatch.setattr(
        labctl.urllib.request,
        "build_opener",
        lambda *_handlers: Opener(),
    )

    assert labctl._health(
        "http://127.0.0.1:8080",
        timeout_seconds=3,
        lab_definition="discovery-lab-v2",
        scenario_id=requested,
    ) == {
        "healthy": True,
        "lab_version": "discovery-lab-v2",
        "scenario_id": requested,
    }


@pytest.mark.parametrize(
    ("arguments", "error"),
    [
        (
            ["cleanup", "--lab-definition", "../../compose.yaml"],
            "invalid_lab_definition",
        ),
        (
            [
                "health",
                "--lab-definition",
                "discovery-lab-v2",
                "--target",
                "http://127.0.0.1:8080",
            ],
            "invalid_scenario",
        ),
        (
            [
                "health",
                "--lab-definition",
                "discovery-lab-v1",
                "--scenario-id",
                "authorized-linked-navigation-small-model-v2",
                "--target",
                "http://127.0.0.1:8080",
            ],
            "invalid_scenario",
        ),
    ],
)
def test_lab_definition_and_scenario_selection_fail_closed(
    arguments: list[str],
    error: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert labctl.main(arguments) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {"error": error}


def test_health_disables_proxies_redirects_and_verifies_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_handlers: list[Any] = []
    captured_request: list[tuple[urllib.request.Request, float]] = []

    class Opener:
        def open(
            self,
            request: urllib.request.Request,
            *,
            timeout: float,
        ) -> _Response:
            captured_request.append((request, timeout))
            return _Response(
                b'{"evidence":"OCTOBENCH_EVIDENCE_ENDPOINT_HEALTH",'
                b'"lab_version":"discovery-lab-v1","schema_version":"1.0",'
                b'"status":"healthy"}'
            )

    def build_opener(*handlers: Any) -> Opener:
        captured_handlers.extend(handlers)
        return Opener()

    monkeypatch.setattr(labctl.urllib.request, "build_opener", build_opener)

    result = labctl._health("https://lab.internal:8443", timeout_seconds=9)

    proxy_handler = next(
        item
        for item in captured_handlers
        if isinstance(item, urllib.request.ProxyHandler)
    )
    tls_handler = next(
        item
        for item in captured_handlers
        if isinstance(item, urllib.request.HTTPSHandler)
    )
    assert proxy_handler.proxies == {}
    assert any(isinstance(item, labctl._NoRedirectHandler) for item in captured_handlers)
    assert tls_handler._context.verify_mode == ssl.CERT_REQUIRED
    assert tls_handler._context.check_hostname is True
    assert captured_request[0][0].full_url == (
        "https://lab.internal:8443/__octobench_health"
    )
    assert captured_request[0][0].get_method() == "GET"
    assert captured_request[0][1] == labctl.HEALTH_REQUEST_TIMEOUT_SECONDS
    assert result == {"healthy": True, "lab_version": "discovery-lab-v1"}


@pytest.mark.parametrize(
    "target",
    [
        "http://8.8.8.8:8080",
        "https://example.com",
        "http://user:password@127.0.0.1",
        "http://127.0.0.1/path",
        "http://127.0.0.1?query=value",
        "file:///tmp/lab",
    ],
)
def test_health_rejects_non_private_or_ambiguous_targets(target: str) -> None:
    with pytest.raises(labctl.LabControlError, match=r"^invalid_target$"):
        labctl._canonical_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:8080",
        "http://10.2.3.4",
        "https://172.16.2.3:8443",
        "http://192.168.1.8",
        "https://fixture.internal",
        "http://fixture.test",
        "http://localhost:8080",
    ],
)
def test_health_accepts_only_explicit_local_lab_address_classes(target: str) -> None:
    assert labctl._canonical_target(target) == target


def test_network_and_protocol_failures_emit_only_stable_error_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sensitive_detail = "secret endpoint diagnostic"

    class Opener:
        def open(self, *_args: Any, **_kwargs: Any) -> _Response:
            raise urllib.error.URLError(sensitive_detail)

    monkeypatch.setattr(
        labctl.urllib.request,
        "build_opener",
        lambda *_handlers: Opener(),
    )

    exit_code = labctl.main(
        ["health", "--target", "http://127.0.0.1:8080"]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert json.loads(captured.err) == {"error": "health_unreachable"}
    assert sensitive_detail not in captured.err


def test_subprocess_failures_emit_only_stable_error_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n", encoding="utf-8")
    sensitive_detail = "secret Docker diagnostic"
    monkeypatch.setattr(labctl, "_COMPOSE_PATH", compose)

    def unavailable(*_args: Any, **_kwargs: Any) -> _SuccessfulProcess:
        raise OSError(sensitive_detail)

    monkeypatch.setattr(labctl.subprocess, "Popen", unavailable)

    assert labctl.main(["cleanup"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {"error": "compose_unavailable"}
    assert sensitive_detail not in captured.err


def test_address_uses_validated_environment_or_detected_private_ip(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("OCTOBENCH_HOST_IP", "192.168.40.2")
    monkeypatch.setenv("OCTOBENCH_LAB_PORT", "9080")

    assert labctl.main(["address"]) == 0
    assert capsys.readouterr().out == "http://192.168.40.2:9080\n"

    monkeypatch.delenv("OCTOBENCH_HOST_IP")
    monkeypatch.setattr(
        labctl,
        "_detect_private_host_ip",
        lambda: ipaddress.ip_address("10.20.30.40"),
    )
    assert labctl.main(["address", "--port", "8081"]) == 0
    assert capsys.readouterr().out == "http://10.20.30.40:8081\n"


def test_address_rejects_public_override_with_stable_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("OCTOBENCH_HOST_IP", "8.8.8.8")

    assert labctl.main(["address"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {"error": "invalid_host_ip"}


@pytest.mark.parametrize(
    ("arguments", "error"),
    [
        (["address", "--port", "70000"], "invalid_port"),
        (
            ["health", "--target", "http://127.0.0.1", "--timeout", "nan"],
            "invalid_timeout",
        ),
    ],
)
def test_numeric_cli_bounds_use_stable_error_codes(
    arguments: list[str],
    error: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("OCTOBENCH_HOST_IP", "127.0.0.1")

    assert labctl.main(arguments) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {"error": error}
