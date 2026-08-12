"""Hermetic branch contracts for action-adapter handle and denial helpers."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

import core.actions.adapters as action_adapters
from core.actions.adapters import (
    ExploitBaseAdapter,
    PluginActionAdapter,
    RegisteredToolAdapter,
    bind_provider_handle,
)
from core.actions.models import ActionRequest
from core.execution import ExecutionContext, ExecutionDecision, ToolInvocation

pytestmark = [pytest.mark.unit, pytest.mark.contract, pytest.mark.security]


class _FakeGaiError(OSError):
    pass


class _FakeSocket:
    def __init__(self, peer: Any = ("203.0.113.10", 22), *, peer_error: bool = False) -> None:
        self.peer = peer
        self.peer_error = peer_error

    def getpeername(self) -> Any:
        if self.peer_error:
            raise OSError("fixture socket is not connected")
        return self.peer


class _FakeTransport:
    def __init__(self, sock: Any) -> None:
        self.sock = sock


class _FakeSSHClient:
    def __init__(self, transport: _FakeTransport) -> None:
        self.transport = transport

    def get_transport(self) -> _FakeTransport:
        return self.transport


def _socket_module(getaddrinfo: Any) -> SimpleNamespace:
    return SimpleNamespace(
        socket=_FakeSocket,
        SOCK_STREAM=1,
        gaierror=_FakeGaiError,
        getaddrinfo=getaddrinfo,
    )


def _context(*scope: str) -> ExecutionContext:
    return ExecutionContext.automatic(
        target_scope=tuple(scope),
        actor="action-adapter-helper-test",
        origin="test",
    )


def _request(
    target: str = "example.test",
    *,
    context: ExecutionContext | None = None,
    handle: Any = None,
    parameters: dict[str, Any] | None = None,
) -> ActionRequest:
    return ActionRequest(
        target=target,
        execution_context=context or _context(target),
        handle=handle,
        parameters=parameters or {},
    )


def test_trusted_handle_peer_accepts_only_concrete_socket_or_paramiko_transports(monkeypatch) -> None:
    monkeypatch.setattr(
        action_adapters,
        "socket",
        _socket_module(lambda *_args, **_kwargs: ()),
    )
    paramiko = SimpleNamespace(SSHClient=_FakeSSHClient, Transport=_FakeTransport)
    monkeypatch.setattr(action_adapters, "import_module", lambda name: paramiko)

    sock = _FakeSocket(("203.0.113.10", 22))
    transport = _FakeTransport(sock)

    assert action_adapters._trusted_handle_peer(sock) == "203.0.113.10"
    assert action_adapters._trusted_handle_peer(_FakeSocket("203.0.113.11")) == "203.0.113.11"
    assert action_adapters._trusted_handle_peer(_FakeSSHClient(transport)) == "203.0.113.10"
    assert action_adapters._trusted_handle_peer(transport) == "203.0.113.10"
    assert action_adapters._trusted_handle_peer(_FakeTransport(object())) == ""
    assert action_adapters._trusted_handle_peer(object()) == ""
    assert action_adapters._trusted_handle_peer(_FakeSocket(peer_error=True)) == ""


@pytest.mark.parametrize("exception", [ImportError("missing"), TypeError("invalid type")])
def test_trusted_handle_peer_fails_closed_when_transport_types_cannot_be_loaded(monkeypatch, exception) -> None:
    monkeypatch.setattr(
        action_adapters,
        "socket",
        _socket_module(lambda *_args, **_kwargs: ()),
    )

    def fail_import(_name: str) -> Any:
        raise exception

    monkeypatch.setattr(action_adapters, "import_module", fail_import)

    assert action_adapters._trusted_handle_peer(SimpleNamespace(getpeername=lambda: ("203.0.113.99", 22))) == ""


def test_bind_provider_handle_rejects_scope_before_peer_or_dns(monkeypatch) -> None:
    def unexpected(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("peer and DNS helpers must not run after scope denial")

    monkeypatch.setattr(action_adapters, "_trusted_handle_peer", unexpected)
    monkeypatch.setattr(action_adapters, "socket", _socket_module(unexpected))

    with pytest.raises(ValueError, match=r"^target_out_of_scope:denied\.test$"):
        bind_provider_handle(object(), "denied.test", _context("allowed.test"))


def test_bind_provider_handle_rejects_unresolved_peer_before_dns(monkeypatch) -> None:
    def unexpected_dns(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("DNS must not run for an unresolved peer")

    monkeypatch.setattr(action_adapters, "_trusted_handle_peer", lambda _handle: "")
    monkeypatch.setattr(action_adapters, "socket", _socket_module(unexpected_dns))

    with pytest.raises(ValueError, match=r"^provider_handle_peer_unresolved$"):
        bind_provider_handle(object(), "example.test", _context("example.test"))


def test_bind_provider_handle_maps_dns_failure_and_rejects_peer_mismatch(monkeypatch) -> None:
    monkeypatch.setattr(action_adapters, "_trusted_handle_peer", lambda _handle: "203.0.113.10")

    def unresolved(*_args: Any, **_kwargs: Any) -> Any:
        raise _FakeGaiError("fixture DNS failure")

    monkeypatch.setattr(action_adapters, "socket", _socket_module(unresolved))
    with pytest.raises(ValueError, match=r"^provider_handle_target_unresolved$"):
        bind_provider_handle(object(), "example.test", _context("example.test"))

    def resolved_other(*_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        return ((None, None, None, None, ("203.0.113.11", 0)),)

    monkeypatch.setattr(action_adapters, "socket", _socket_module(resolved_other))
    with pytest.raises(ValueError, match=r"^provider_handle_target_mismatch$"):
        bind_provider_handle(object(), "example.test", _context("example.test"))


def test_bind_and_request_handle_binding_enforce_request_target_and_live_peer(monkeypatch) -> None:
    def resolved(host: str, port: Any, *, type: int) -> tuple[Any, ...]:
        assert (host, port, type) == ("example.test", None, 1)
        return ((None, None, None, None, ("203.0.113.10", 0)),)

    monkeypatch.setattr(action_adapters, "socket", _socket_module(resolved))
    context = _context("example.test")
    sock = _FakeSocket(("203.0.113.10", 22))
    binding = bind_provider_handle(sock, "example.test", context)

    assert binding.connected_peer == "203.0.113.10"
    assert binding.request_id == context.request_id
    assert action_adapters._request_handle_binding(_request(context=context, handle=binding)) is binding
    assert action_adapters._request_handle_binding(_request(context=context, handle=object())) is None
    assert (
        action_adapters._request_handle_binding(
            _request(context=context, handle=replace(binding, request_id="another-request"))
        )
        is None
    )
    assert action_adapters._request_handle_binding(_request("other.test", context=context, handle=binding)) is None

    sock.peer = ("203.0.113.12", 22)
    assert action_adapters._request_handle_binding(_request(context=context, handle=binding)) is None


def _registered_tool() -> SimpleNamespace:
    return SimpleNamespace(
        name="fixture_network_tool",
        category="recon",
        description="Hermetic registered-tool fixture.",
        aliases=(),
        requires=(),
        needs_target=True,
        enabled=True,
        is_available=lambda: True,
    )


@pytest.mark.parametrize(
    ("target", "invocation_targets"),
    [("", ("example.test",)), ("example.test", ())],
)
def test_registered_adapter_denies_missing_explicit_or_parsed_target(
    monkeypatch,
    target: str,
    invocation_targets: tuple[str, ...],
) -> None:
    adapter = RegisteredToolAdapter(
        _registered_tool(),
        lambda *_args, **_kwargs: pytest.fail("dispatch must not run during authorization"),
    )
    request = _request(target, context=_context("example.test"))
    invocation = ToolInvocation(
        executable="fixture_network_tool",
        argv=("fixture_network_tool",),
        registered_name="fixture_network_tool",
        targets=invocation_targets,
    )
    policy = SimpleNamespace(
        authorize_command=lambda _command, _context: ExecutionDecision(True, "allowed", _context, invocation)
    )
    monkeypatch.setattr(action_adapters, "registered_tool_uses_network_scope", lambda _name: True)

    decision = adapter.authorize(policy, request, "execute")

    assert decision.allowed is False
    assert decision.reason == "missing_explicit_target"
    assert decision.invocation is invocation


class _ExploitSpy:
    name = "Hermetic exploit fixture"
    cve = "CVE-2099-0001"
    description = "Must never reach provider methods in these tests."
    supported_os: tuple[str, ...] = ()

    @staticmethod
    def check_vulnerable(_handle: Any) -> Any:
        raise AssertionError("exploit check provider must not run")

    @staticmethod
    def run(_handle: Any) -> Any:
        raise AssertionError("exploit run provider must not run")

    @staticmethod
    def normalize_check_result(_value: Any) -> Any:
        raise AssertionError("exploit check normalization must not run")

    @staticmethod
    def normalize_run_result(_value: Any) -> Any:
        raise AssertionError("exploit run normalization must not run")


def test_exploit_adapter_denies_unbound_handle_before_policy_or_provider() -> None:
    adapter = ExploitBaseAdapter(_ExploitSpy())
    request = _request(handle=object())
    policy = SimpleNamespace(
        authorize_registered=lambda *_args, **_kwargs: pytest.fail("policy must not run without a bound handle")
    )

    decision = adapter.authorize(policy, request, "execute")

    assert decision.allowed is False
    assert decision.reason == "provider_handle_binding_required"

    with pytest.raises(ValueError, match=r"^provider_handle_binding_required$"):
        adapter.check(request)
    with pytest.raises(ValueError, match=r"^provider_handle_binding_required$"):
        adapter.execute(request)


class _PluginManagerSpy:
    def __init__(self, *, supports_check: bool) -> None:
        self.descriptor = SimpleNamespace(
            plugin_type="recon",
            description="Hermetic plugin fixture.",
            version="1",
            requires=(),
            python_deps=(),
            capabilities=(),
            supports_check=supports_check,
            supports_run=True,
            input_schema={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
        )

    def get_plugin(self, _name: str) -> SimpleNamespace:
        return self.descriptor

    @staticmethod
    def validate(_name: str) -> tuple[Any, ...]:
        return ()

    @staticmethod
    def check(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("plugin check provider must not run")

    @staticmethod
    def execute(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("plugin execute provider must not run")


def test_plugin_adapter_direct_check_and_internal_action_guards_never_call_provider(monkeypatch) -> None:
    unsupported = PluginActionAdapter(_PluginManagerSpy(supports_check=False), "fixture")
    request = _request(parameters={})
    with pytest.raises(ValueError, match=r"^plugin_check_unsupported$"):
        unsupported.check(request)

    invariant_guard = PluginActionAdapter(_PluginManagerSpy(supports_check=True), "fixture")
    monkeypatch.setattr(invariant_guard, "_action", lambda _request, _phase: "cleanup")
    with pytest.raises(ValueError, match=r"^plugin_action_not_executable$"):
        invariant_guard.execute(request)
