"""Residual cancellation and optional-registry policy branches."""

from __future__ import annotations

import builtins

import pytest

from core.execution import (
    CancellationContext,
    ExecutionContext,
    ExecutionPolicy,
    ToolInvocation,
)

pytestmark = pytest.mark.security


def _cancelled_context() -> ExecutionContext:
    cancellation = CancellationContext()
    cancellation.cancel("test_cancelled")
    return ExecutionContext.automatic(cancellation=cancellation)


def test_every_policy_entrypoint_stops_at_cancellation():
    policy = ExecutionPolicy()
    context = _cancelled_context()
    invocation = ToolInvocation(
        executable="nmap",
        argv=("nmap", "10.0.0.5"),
        raw_command="nmap 10.0.0.5",
        registered_name="nmap",
        targets=("10.0.0.5",),
    )

    assert policy.authorize_registered(invocation, context).reason == "execution_cancelled"
    assert policy.authorize_direct(invocation, context).reason == "execution_cancelled"
    assert policy.authorize_shell("echo ok", context).reason == "execution_cancelled"
    assert policy.authorize_python_repl("print(1)", context).reason == ("execution_cancelled")
    assert policy.authorize_command("nmap 10.0.0.5", context).reason == ("execution_cancelled")


def test_registered_authorization_fails_closed_when_registry_import_fails(
    monkeypatch,
):
    policy = ExecutionPolicy()
    context = ExecutionContext.automatic()
    invocation = ToolInvocation(
        executable="nmap",
        argv=("nmap",),
        raw_command="nmap",
        registered_name="nmap",
    )
    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "core.tools":
            raise ImportError("registry unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    assert policy.authorize_registered(invocation, context).reason == ("registered_tool_registry_unavailable")
