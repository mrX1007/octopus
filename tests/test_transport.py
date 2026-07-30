"""Hermetic contracts for transport policies and client adapters."""

from __future__ import annotations

import builtins
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

import core.transport.base as transport_module
from core.transport.base import GoTLSTransport, PythonTransport, TrafficPolicy, Transport
from core.transport.profiles import (
    browser_profile,
    get_profile,
    scraper_profile,
    stealth_profile,
    updater_profile,
)

pytestmark = pytest.mark.unit


class ScriptedTransport(Transport):
    """Transport double whose outcomes are supplied by each test."""

    def __init__(self, outcomes: list[Any], policy: Any = None) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[Any, ...]] = []
        super().__init__(policy)

    def _do_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        self.calls.append((method, url, headers, body, timeout))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class StubPolicy:
    def __init__(self, *, initial_delay: float, retry_delays: tuple[float, ...]) -> None:
        self.initial_delay = initial_delay
        self.retry_delays = retry_delays
        self.max_retries = len(retry_delays)
        self.retry_attempts: list[int] = []

    def pre_request_delay(self) -> float:
        return self.initial_delay

    def retry_delay(self, attempt: int) -> float:
        self.retry_attempts.append(attempt)
        return self.retry_delays[attempt]


def test_traffic_policy_shapes_bursts_retries_and_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = iter((100.0, 105.0))

    def uniform(low: float, high: float) -> float:
        if (low, high) == (0, 0.5):
            return 0.25
        if (low, high) == (-0.5, 0.5):
            return 0.2
        return 1.5

    monkeypatch.setattr(transport_module, "time", SimpleNamespace(time=lambda: next(clock)))
    monkeypatch.setattr(transport_module, "random", SimpleNamespace(uniform=uniform))
    policy = TrafficPolicy(
        min_jitter=1.0,
        max_jitter=2.0,
        burst_size=2,
        burst_cooldown=10.0,
        chunk_size=3,
        retry_base=1.0,
        retry_max=4.0,
        retry_jitter=0.5,
    )

    assert policy.pre_request_delay() == 1.5
    assert policy.pre_request_delay() == 1.5
    assert policy.pre_request_delay() == 1.5
    assert policy.pre_request_delay() == 5.25
    assert policy.retry_delay(0) == 1.2
    assert policy.retry_delay(10) == 4.2

    monkeypatch.setattr(
        transport_module,
        "random",
        SimpleNamespace(uniform=lambda _low, _high: -10.0),
    )
    assert policy.retry_delay(0) == 0.1
    assert policy.chunk_data(b"ab") == [b"ab"]
    assert policy.chunk_data(b"abcdefg") == [b"abc", b"def", b"g"]


def test_transport_request_returns_success_and_retries_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(transport_module, "time", SimpleNamespace(sleep=sleeps.append))

    immediate_policy = StubPolicy(initial_delay=0.0, retry_delays=())
    success = ScriptedTransport(
        [
            {"status_code": 200, "headers": {}, "body": "ok"},
            {"error": "", "status_code": 204, "headers": {}, "body": ""},
        ],
        immediate_policy,
    )
    assert success.request("GET", "https://example.invalid")["status_code"] == 200
    assert success.request("POST", "https://example.invalid")["status_code"] == 204

    retry_policy = StubPolicy(initial_delay=0.5, retry_delays=(1.0, 2.0))
    exhausted = ScriptedTransport(
        [
            {"error": "temporary"},
            RuntimeError("adapter exploded"),
            {"error": "permanent"},
        ],
        retry_policy,
    )
    result = exhausted.request(
        "PUT",
        "https://example.invalid/item",
        {"X-Test": "yes"},
        b"payload",
        4.0,
    )

    assert result == {"error": "permanent", "status_code": 0, "headers": {}, "body": ""}
    assert retry_policy.retry_attempts == [0, 1]
    assert sleeps == [0.5, 1.0, 2.0]
    assert len(exhausted.calls) == 3

    defaulted = ScriptedTransport([])
    assert isinstance(defaulted.policy, TrafficPolicy)


def test_transport_temp_files_are_tracked_and_cleanup_is_best_effort(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = ScriptedTransport([])
    removable = transport._create_temp_file("first")
    blocked = transport._create_temp_file("second")
    missing = str(tmp_path / "already-missing.tmp")
    transport._temp_files.append(missing)
    assert Path(removable).read_text(encoding="utf-8") == "first"
    assert Path(blocked).read_text(encoding="utf-8") == "second"

    real_remove = os.remove

    def remove(path: str) -> None:
        if path == blocked:
            raise OSError("simulated cleanup race")
        real_remove(path)

    monkeypatch.setattr(transport_module.os, "remove", remove)
    transport.cleanup()

    assert not Path(removable).exists()
    assert Path(blocked).exists()
    assert transport._temp_files == []
    transport.cleanup()
    real_remove(blocked)


def test_python_transport_maps_success_timeout_dependency_and_other_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_requests = ModuleType("requests")

    class RequestTimeout(Exception):
        pass

    calls: list[dict[str, Any]] = []

    def successful_request(**kwargs: Any) -> Any:
        calls.append(kwargs)
        return SimpleNamespace(status_code=201, headers={"X-Test": "ok"}, text="created")

    fake_requests.Timeout = RequestTimeout
    fake_requests.request = successful_request
    monkeypatch.setitem(sys.modules, "requests", fake_requests)
    transport = PythonTransport()

    success = transport._do_request("POST", "https://example.invalid", body=b"body", timeout=2.0)
    assert success == {"status_code": 201, "headers": {"X-Test": "ok"}, "body": "created"}
    assert calls == [
        {
            "method": "POST",
            "url": "https://example.invalid",
            "headers": {},
            "data": b"body",
            "timeout": 2.0,
            "verify": True,
        }
    ]

    def timeout_request(**_kwargs: Any) -> Any:
        raise RequestTimeout

    fake_requests.request = timeout_request
    assert transport._do_request("GET", "https://example.invalid", {"A": "B"})["error"] == ("Request timed out")

    def broken_request(**_kwargs: Any) -> Any:
        raise RuntimeError("socket closed")

    fake_requests.request = broken_request
    assert transport._do_request("GET", "https://example.invalid")["error"] == "socket closed"

    real_import = builtins.__import__

    def import_without_requests(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "requests":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(builtins, "__import__", import_without_requests)
        unavailable = transport._do_request("GET", "https://example.invalid")
    assert unavailable == {
        "error": "requests library not installed",
        "status_code": 0,
        "headers": {},
        "body": "",
    }


def test_go_tls_transport_serializes_requests_and_maps_adapter_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcomes: list[Any] = [
        SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"status_code": 200, "headers": {}, "body": "ok"}),
            stderr="",
        ),
        SimpleNamespace(returncode=9, stdout="", stderr="bad certificate"),
        subprocess.TimeoutExpired("ja3_client", 3.0),
        SimpleNamespace(returncode=0, stdout="not-json", stderr=""),
        FileNotFoundError("missing"),
    ]
    serialized: list[dict[str, Any]] = []

    def run(command: list[str], **kwargs: Any) -> Any:
        assert command[0] == "/test/ja3_client"
        assert command[1] == "-in"
        serialized.append(json.loads(Path(command[2]).read_text(encoding="utf-8")))
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(subprocess, "run", run)
    transport = GoTLSTransport(go_binary="/test/ja3_client", browser="firefox")

    assert transport._do_request("get", "https://example.invalid") == {
        "status_code": 200,
        "headers": {},
        "body": "ok",
    }
    failed = transport._do_request(
        "post",
        "https://example.invalid",
        {"Content-Type": "text/plain"},
        b"hello",
    )
    assert failed["error"] == "Go client failed: bad certificate"
    assert transport._do_request("get", "https://example.invalid", timeout=3.0)["error"] == ("Request timed out")
    assert transport._do_request("get", "https://example.invalid")["error"] == ("Invalid JSON from Go client")
    assert transport._do_request("get", "https://example.invalid")["error"] == ("Go binary not found: /test/ja3_client")
    assert serialized[0] == {
        "method": "GET",
        "url": "https://example.invalid",
        "headers": {},
        "body": "",
        "browser": "firefox",
    }
    assert serialized[1]["method"] == "POST"
    assert serialized[1]["headers"] == {"Content-Type": "text/plain"}
    assert serialized[1]["body"] == "hello"
    assert transport._temp_files == []

    default_binary = GoTLSTransport()
    assert default_binary.go_binary.endswith("core/opsec/ja3_client")


@pytest.mark.parametrize(
    ("factory", "expected"),
    (
        (
            updater_profile,
            ("updater", 30.0, 120.0, 3, 10.0, 16384, 2.0, 60.0, 3.0, 2),
        ),
        (
            browser_profile,
            ("browser", 0.05, 0.5, 6, 15.0, 4096, 0.5, 10.0, 0.3, 3),
        ),
        (
            scraper_profile,
            ("scraper", 2.0, 8.0, 10, 3.0, 8192, 1.0, 15.0, 1.0, 5),
        ),
        (
            stealth_profile,
            ("stealth", 60.0, 300.0, 1, 600.0, 2048, 30.0, 120.0, 10.0, 1),
        ),
    ),
)
def test_named_profiles_expose_the_documented_policy(
    factory: Any,
    expected: tuple[Any, ...],
) -> None:
    profile = factory()
    assert (
        profile.profile_name,
        profile.min_jitter,
        profile.max_jitter,
        profile.burst_size,
        profile.burst_cooldown,
        profile.chunk_size,
        profile.retry_base,
        profile.retry_max,
        profile.retry_jitter,
        profile.max_retries,
    ) == expected


def test_profile_lookup_uses_named_factory_and_safe_fallback() -> None:
    assert get_profile("browser").profile_name == "browser"
    assert get_profile("unknown-profile").profile_name == "updater"
