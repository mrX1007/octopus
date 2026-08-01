"""Coverage for provider-handle and adapter target-binding hardening."""

from __future__ import annotations

import socket
import sys
from dataclasses import replace
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

import core
import core.actions.adapters as adapter_module
from core.actions import (
    ActionRequest,
    ExploitBaseAdapter,
    RegisteredToolAdapter,
    bind_provider_handle,
)
from core.execution import (
    ExecutionContext,
    ExecutionDecision,
    ExecutionPolicy,
    ToolInvocation,
)

pytestmark = [pytest.mark.unit, pytest.mark.security]


class _PeerSocket(socket.socket):
    """Concrete socket whose peer result is deterministic without network I/O."""

    def __init__(self, peer: Any):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.peer = peer

    def getpeername(self):
        return self.peer


def _approved(*targets: str) -> ExecutionContext:
    return ExecutionContext.operator(
        actor="adapter-hardening-test",
        approval_id="adapter-hardening-approval",
        target_scope=tuple(targets),
        allow_active_tools=True,
    )


def _network_tool() -> SimpleNamespace:
    def fixture_network(target: str) -> str:
        return target

    return SimpleNamespace(
        name="fixture_network",
        aliases=(),
        category="recon",
        description="fixture network provider",
        requires=(),
        needs_target=True,
        enabled=True,
        is_available=lambda: True,
        func=fixture_network,
    )


def _install_tool_registry(
    monkeypatch: pytest.MonkeyPatch,
    tool: SimpleNamespace,
) -> None:
    tools_package = ModuleType("core.tools")
    tools_package.__path__ = []
    registry = ModuleType("core.tools.registry")
    registry.get_tool = lambda name: tool if name == tool.name else None
    tools_package.registry = registry
    monkeypatch.setitem(sys.modules, "core.tools", tools_package)
    monkeypatch.setitem(sys.modules, "core.tools.registry", registry)
    monkeypatch.setattr(core, "tools", tools_package, raising=False)


def test_trusted_handle_peer_covers_socket_paramiko_and_failure_paths(monkeypatch):
    import paramiko

    with _PeerSocket(("127.0.0.1", 22)) as handle:
        assert adapter_module._trusted_handle_peer(handle) == "127.0.0.1"

        transport = paramiko.Transport(handle)
        client = paramiko.SSHClient()
        client._transport = transport
        assert adapter_module._trusted_handle_peer(client) == "127.0.0.1"
        assert adapter_module._trusted_handle_peer(transport) == "127.0.0.1"
        transport.close()

    assert adapter_module._trusted_handle_peer(paramiko.SSHClient()) == ""
    assert adapter_module._trusted_handle_peer(object()) == ""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as disconnected:
        assert adapter_module._trusted_handle_peer(disconnected) == ""
    with _PeerSocket(" 192.0.2.10 ") as scalar_peer:
        assert adapter_module._trusted_handle_peer(scalar_peer) == "192.0.2.10"
    with _PeerSocket("") as empty_peer:
        assert adapter_module._trusted_handle_peer(empty_peer) == ""

    with monkeypatch.context() as missing_paramiko:
        missing_paramiko.setitem(sys.modules, "paramiko", None)
        assert adapter_module._trusted_handle_peer(object()) == ""


def test_bind_provider_handle_enforces_scope_peer_and_dns(monkeypatch):
    with _PeerSocket(("127.0.0.1", 2222)) as handle:
        with pytest.raises(ValueError, match="target_out_of_scope"):
            bind_provider_handle(handle, "outside.test", _approved("inside.test"))

        with (
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as disconnected,
            pytest.raises(ValueError, match="provider_handle_peer_unresolved"),
        ):
            bind_provider_handle(disconnected, "127.0.0.1", _approved("127.0.0.1"))

        context = _approved("127.0.0.1")
        binding = bind_provider_handle(handle, "127.0.0.1", context)
        assert binding.handle is handle
        assert binding.connected_peer == "127.0.0.1"
        assert binding.requested_target == "127.0.0.1"
        assert binding.request_id == context.request_id

        def unresolved(*_args, **_kwargs):
            raise socket.gaierror("fixture lookup failure")

        monkeypatch.setattr(adapter_module.socket, "getaddrinfo", unresolved)
        with pytest.raises(ValueError, match="provider_handle_target_unresolved"):
            bind_provider_handle(handle, "https://127.0.0.1/path", context)

        monkeypatch.setattr(
            adapter_module.socket,
            "getaddrinfo",
            lambda *_args, **_kwargs: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.9", 0)),
            ],
        )
        with pytest.raises(ValueError, match="provider_handle_target_mismatch"):
            bind_provider_handle(handle, "https://127.0.0.1/path", context)

        monkeypatch.setattr(
            adapter_module.socket,
            "getaddrinfo",
            lambda *_args, **_kwargs: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ()),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            ],
        )
        url_binding = bind_provider_handle(handle, "https://127.0.0.1/path", context)
        assert url_binding.connected_peer == "127.0.0.1"


def test_request_binding_is_request_target_and_live_peer_specific():
    context = _approved("127.0.0.1")
    with _PeerSocket(("127.0.0.1", 2222)) as handle:
        binding = bind_provider_handle(handle, "127.0.0.1", context)
        request = ActionRequest("127.0.0.1", context, handle=binding)

        assert adapter_module._request_handle_binding(request) is binding
        assert adapter_module._request_handle_binding(replace(request, handle=handle)) is None
        assert (
            adapter_module._request_handle_binding(
                replace(request, execution_context=_approved("127.0.0.1")),
            )
            is None
        )
        assert adapter_module._request_handle_binding(replace(request, target="127.0.0.2")) is None
        assert (
            adapter_module._request_handle_binding(
                replace(request, handle=replace(binding, connected_peer="203.0.113.9")),
            )
            is None
        )


def test_registered_adapter_binds_explicit_target_to_authorized_invocation(monkeypatch):
    tool = _network_tool()
    _install_tool_registry(monkeypatch, tool)
    adapter = RegisteredToolAdapter(tool, lambda *_args: None)
    context = _approved("inside.test", "outside.test")

    matching = adapter.authorize(
        ExecutionPolicy(),
        ActionRequest("inside.test", context, command="fixture_network inside.test"),
        "execute",
    )
    assert matching.allowed is True

    mismatch = adapter.authorize(
        ExecutionPolicy(),
        ActionRequest("inside.test", context, command="fixture_network outside.test"),
        "execute",
    )
    assert mismatch.allowed is False
    assert mismatch.reason == "action_target_mismatch"

    class AllowedWithoutInvocation:
        @staticmethod
        def authorize_command(_command, execution_context):
            return ExecutionDecision(True, "fixture_allowed", execution_context)

    targetless_tool = _network_tool()
    targetless_tool.name = "fixture_targetless"
    targetless_tool.needs_target = False
    targetless = RegisteredToolAdapter(targetless_tool, lambda *_args: None)
    targetless_decision = targetless.authorize(
        AllowedWithoutInvocation(),
        ActionRequest("", context),
        "execute",
    )
    assert targetless_decision.allowed is True

    missing = adapter.authorize(
        AllowedWithoutInvocation(),
        ActionRequest("inside.test", context),
        "execute",
    )
    assert missing.allowed is False
    assert missing.reason == "missing_explicit_target"

    class AllowedWithoutTargets:
        @staticmethod
        def authorize_command(command, execution_context):
            invocation = ToolInvocation(
                executable=tool.name,
                argv=tuple(command.split()),
                registered_name=tool.name,
                targets=(),
            )
            return ExecutionDecision(True, "fixture_allowed", execution_context, invocation)

    missing = adapter.authorize(
        AllowedWithoutTargets(),
        ActionRequest("inside.test", context),
        "execute",
    )
    assert missing.allowed is False
    assert missing.reason == "missing_explicit_target"


class _FixtureExploit:
    name = "Adapter hardening fixture"
    cve = "CVE-2099-4242"
    supported_os = ("linux",)

    def __init__(self):
        self.handles: list[Any] = []

    def check_vulnerable(self, client):
        self.handles.append(client)
        return True, "bound handle check"

    def run(self, client):
        self.handles.append(client)
        return True, "bound handle execution"

    def normalize_check_result(self, result):
        success, evidence = result
        return SimpleNamespace(
            success=success,
            evidence=evidence,
            output=evidence,
            status="vulnerable" if success else "not_vulnerable",
        )

    def normalize_run_result(self, result):
        success, output = result
        return SimpleNamespace(success=success, output=output)


def test_exploit_adapter_uses_a_real_bound_handle_for_all_lifecycle_paths():
    context = _approved("127.0.0.1")
    with _PeerSocket(("127.0.0.1", 2222)) as handle:
        binding = bind_provider_handle(handle, "127.0.0.1", context)
        request = ActionRequest(
            "127.0.0.1",
            context,
            parameters={"target_os": "linux"},
            handle=binding,
        )
        exploit = _FixtureExploit()
        adapter = ExploitBaseAdapter(exploit)

        applicability = adapter.applicability(request)
        assert applicability.applicable is True
        assert applicability.reasons == ("exploit_contract_applicable",)

        class AllowPolicy:
            def __init__(self):
                self.invocations: list[ToolInvocation] = []

            def authorize_registered(self, invocation, execution_context):
                self.invocations.append(invocation)
                return ExecutionDecision(
                    True,
                    "fixture_allowed",
                    execution_context,
                    invocation,
                )

        policy = AllowPolicy()
        decision = adapter.authorize(policy, request, "check")
        assert decision.allowed is True
        assert policy.invocations[0].registered_name == "killchain_vuln_assess"
        assert adapter.invocation(request, "execute").registered_name == "killchain_privesc"

        checked = adapter.check(request)
        executed = adapter.execute(request)
        assert checked.applicable is True
        assert checked.reason == "bound handle check"
        assert executed.success is True
        assert exploit.handles == [handle, handle]

        unbound = replace(request, handle=handle)
        denial = adapter.authorize(policy, unbound, "execute")
        assert denial.allowed is False
        assert denial.reason == "provider_handle_binding_required"
        with pytest.raises(ValueError, match="provider_handle_binding_required"):
            adapter.check(unbound)
