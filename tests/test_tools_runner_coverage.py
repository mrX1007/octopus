"""Hermetic statement and branch coverage for :mod:`core.tools.runner`."""

from __future__ import annotations

import builtins
import contextlib
import runpy
import signal
import subprocess
import sys
import threading
import time
import types
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import mock_open

import pytest

from core.credentials import CredentialRef
from core.execution import (
    ExecutionCancelled,
    ExecutionContext,
    ToolInvocation,
    bind_execution_context,
    current_execution_context,
)
from core.tools import runner
from core.tools.base import ToolResult

pytestmark = pytest.mark.unit


def _decision(
    allowed: bool,
    *,
    reason: str = "denied",
    invocation: ToolInvocation | None = None,
):
    return SimpleNamespace(allowed=allowed, reason=reason, invocation=invocation)


class _Policy:
    def __init__(
        self,
        *,
        registered: bool = True,
        command: bool = True,
        shell: bool = True,
        repl: bool = True,
        invocation: ToolInvocation | None = None,
    ) -> None:
        self.registered = registered
        self.command = command
        self.shell = shell
        self.repl = repl
        self.invocation = invocation

    def authorize_registered(self, invocation, _context):
        return _decision(
            self.registered,
            reason="registered_denied",
            invocation=invocation,
        )

    def authorize_command(self, _command, _context):
        return _decision(
            self.command,
            reason="command_denied",
            invocation=self.invocation,
        )

    def authorize_shell(self, _command, _context):
        return _decision(
            self.shell,
            reason="shell_denied",
            invocation=self.invocation,
        )

    def authorize_python_repl(self, _code, _context):
        return _decision(self.repl, reason="repl_denied")


def _tool_def(
    name: str,
    func=lambda target: f"ok:{target}",
    *,
    available: bool = True,
    requires: list[str] | None = None,
):
    return SimpleNamespace(
        name=name,
        func=func,
        requires=[] if requires is None else requires,
        is_available=lambda: available,
    )


class _ImmediateFuture:
    def __init__(self, func, args, kwargs) -> None:
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.cancelled = False

    def result(self):
        return self.func(*self.args, **self.kwargs)

    def cancel(self):
        self.cancelled = True
        return True


class _ImmediateExecutor:
    def __init__(self, *, max_workers: int) -> None:
        self.max_workers = max_workers

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def submit(self, func, *args, **kwargs):
        return _ImmediateFuture(func, args, kwargs)


def _patch_immediate_futures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner.concurrent.futures,
        "ThreadPoolExecutor",
        _ImmediateExecutor,
    )
    monkeypatch.setattr(
        runner.concurrent.futures,
        "as_completed",
        lambda futures: list(futures),
    )
    monkeypatch.setattr(runner, "effective_parallel_workers", lambda value: value)


def test_registered_extended_tool_all_outcomes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools import registry

    def explode(_target):
        raise RuntimeError("boom")

    tools = {
        "unavailable": _tool_def("unavailable", available=False, requires=["dep"]),
        "nodeps": _tool_def("nodeps", available=False),
        "denied": _tool_def("denied"),
        "success": _tool_def("success"),
        "explode": _tool_def("explode", explode),
    }
    monkeypatch.setattr(registry, "get_tool", tools.get)
    monkeypatch.setattr(
        runner,
        "_catalog_tool_definition",
        lambda name: (tools.get(name), "" if tools.get(name) else "not_registered"),
    )
    results: dict[str, str] = {}
    plan: list[str] = []

    runner._run_registered_extended_tool(results, plan, "missing", "target")
    runner._run_registered_extended_tool(results, plan, "unavailable", "target")
    runner._run_registered_extended_tool(results, plan, "nodeps", "target")
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(registered=False))
    runner._run_registered_extended_tool(results, plan, "denied", "target")
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    runner._run_registered_extended_tool(results, plan, "success", "target", "label")
    runner._run_registered_extended_tool(results, plan, "explode", "target")

    assert "not_registered" in results["missing"]
    assert "unavailable dependency: dep" in results["unavailable"]
    assert "unavailable dependency: dependency" in results["nodeps"]
    assert "Execution denied" in results["denied"]
    assert results["label"] == "ok:target"
    assert "boom" in results["explode"]


def test_registered_extended_tools_concurrent_all_outcomes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools import registry

    def explode(_target):
        raise RuntimeError("future boom")

    tools = {
        "unavailable": _tool_def("unavailable", available=False, requires=["dep"]),
        "nodeps": _tool_def("nodeps", available=False),
        "denied": _tool_def("denied"),
        "success": _tool_def("success", lambda _target: "complete output"),
        "explode": _tool_def("explode", explode),
    }
    monkeypatch.setattr(registry, "get_tool", tools.get)
    monkeypatch.setattr(
        runner,
        "_catalog_tool_definition",
        lambda name: (tools.get(name), "" if tools.get(name) else "not_registered"),
    )
    _patch_immediate_futures(monkeypatch)
    results: dict[str, str] = {}
    plan: list[str] = []

    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(registered=False))
    runner._run_registered_extended_tools_concurrent(
        results,
        plan,
        [
            ("missing", "target", "missing_label"),
            ("unavailable", "target", "unavailable_label"),
            ("nodeps", "target", ""),
            ("denied", "target", "denied_label"),
        ],
    )
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    runner._run_registered_extended_tools_concurrent(
        results,
        plan,
        [
            ("success", "target", "success_label"),
            ("explode", "target", "explode_label"),
        ],
        max_workers=2,
    )

    assert results["success_label"] == "complete output"
    assert "future boom" in results["explode_label"]
    assert any(line.startswith("complete success_label") for line in plan)


def test_registered_concurrent_worker_preserves_context_and_bounds_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools.registry import get_tool

    seen_contexts: list[ExecutionContext] = []
    tool_def = get_tool("nmap")
    assert tool_def is not None
    monkeypatch.setattr(tool_def, "requires", [])

    def provider(_target, extra_flags=None):
        del extra_flags
        seen_contexts.append(current_execution_context())
        return "x" * 4096

    monkeypatch.setattr(tool_def, "func", provider)
    context = ExecutionContext.operator(
        actor="worker-context-test",
        approval_id="worker-context-test",
        target_scope=("example.test",),
        max_output_bytes=1024,
    )
    results: dict[str, str] = {}
    with bind_execution_context(context):
        runner._run_registered_extended_tools_concurrent(
            results,
            [],
            [("nmap", "example.test", "nmap")],
            max_workers=1,
        )

    assert seen_contexts == [context]
    assert "OUTPUT LIMIT" in results["nmap"]
    assert len(str(results["nmap"]).encode()) <= context.max_output_bytes


def test_registered_concurrent_cancellation_stops_pending_stubbed_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def cancelled(_target):
        calls.append("cancelled")
        raise ExecutionCancelled("unit_cancel")

    def pending(_target):
        calls.append("pending")
        return "unexpected"

    tools = {
        "cancelled": _tool_def("cancelled", cancelled),
        "pending": _tool_def("pending", pending),
    }
    monkeypatch.setattr(
        runner,
        "_catalog_tool_definition",
        lambda name: (tools[name], ""),
    )
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    _patch_immediate_futures(monkeypatch)

    with pytest.raises(ExecutionCancelled, match="unit_cancel"):
        runner._run_registered_extended_tools_concurrent(
            {},
            [],
            [
                ("cancelled", "example.test", "cancelled"),
                ("pending", "example.test", "pending"),
            ],
            max_workers=2,
        )

    assert calls == ["cancelled"]


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("[TIMEOUT]", "timeout"),
        ("killed after 1s", "timeout"),
        ("timed out after 1s", "timeout"),
        ("tool skipped: reason", "skipped"),
        ("tool not applicable", "skipped"),
        ("not_applicable", "skipped"),
        ("[!] failed", "error"),
        ("tool error: failed", "error"),
        ("", "empty"),
        (None, "empty"),
        ("done", "complete"),
    ],
)
def test_tool_result_status(output, expected: str) -> None:
    assert runner._tool_result_status(output) == expected


def test_web_url_and_result_helpers_cover_all_signals() -> None:
    assert runner._web_result_suffix("https://EXAMPLE.test:8443/a?b=1") == "https_example_test_8443_a_b_1"
    assert runner._parsed_web_url(" example.test ").scheme == "http"
    assert runner._parsed_web_url("https://example.test").scheme == "https"
    assert runner._web_host_port("https://EXAMPLE.test") == ("example.test", 443)
    assert runner._web_host_port("example.test:8080") == ("example.test", 8080)
    assert runner._web_surface_group("http://example.test") == ("example.test", "default")
    assert runner._web_surface_group("http://example.test:8080") == ("example.test", "8080")
    assert runner._prefer_web_representative(["http://example.test", "https://example.test"]) == "https://example.test"

    url = "http://example.test"
    suffix = runner._web_result_suffix(url)
    assert (
        runner._web_result_text(
            {f"one_{suffix}": "a", f"two_{suffix}": "", f"three_{suffix}": 3},
            url,
            ("one", "two", "three"),
        )
        == "a\n3"
    )

    assert not runner._web_endpoint_alive({}, url)
    for negative in (
        "connection refused",
        "failed to connect",
        "could not resolve",
        "operation timed out",
        "timed out",
        "ssl: wrong_version_number",
    ):
        assert not runner._web_endpoint_alive({f"whatweb_{suffix}": negative}, url)
    for positive in (
        "HTTP/1.1 200 OK",
        "[200 OK]",
        "Server: nginx",
        "HTTPServer[nginx]",
        "<html>",
    ):
        assert runner._web_endpoint_alive({f"whatweb_{suffix}": positive}, url)
    assert not runner._web_endpoint_alive({f"whatweb_{suffix}": "unknown"}, url)

    fingerprint = runner._web_fingerprint(
        {
            f"curl_headers_{suffix}": "HTTP/1.1 200 OK\nServer: Nginx\nLocation: /next",
            f"whatweb_{suffix}": "HTTPServer[Nginx] Title[ Home ] X-Powered-By[PHP] PoweredBy[Python]",
        },
        url,
    )
    assert "http/1.1 200 ok" in fingerprint
    assert "nginx" in fingerprint
    assert "home" in fingerprint


def test_distinct_and_contextual_web_plans_cover_duplicates_and_applicability() -> None:
    urls = [
        "http://example.test",
        "https://example.test",
        "http://example.test:8080",
        "http://example.test:8081?item=1",
    ]
    results: dict[str, str] = {}
    for url in urls[:2]:
        suffix = runner._web_result_suffix(url)
        results[f"curl_headers_{suffix}"] = "HTTP/1.1 200 OK\nServer: nginx"
    suffix_8080 = runner._web_result_suffix(urls[2])
    results[f"whatweb_{suffix_8080}"] = "connection refused"
    suffix_query = runner._web_result_suffix(urls[3])
    results[f"whatweb_{suffix_query}"] = "WordPress wp-content"

    selected, skipped = runner._plan_distinct_web_targets(urls, results)
    assert "https://example.test" in selected
    assert skipped["http://example.test"] == "https://example.test"
    assert "http://example.test:8080" in selected

    plan: list[str] = []
    jobs = runner._plan_contextual_web_jobs(urls, results, plan)
    assert any(tool == "wpscan" for tool, _target, _key in jobs)
    assert not any(tool == "sqlmap" for tool, _target, _key in jobs)
    assert any(
        line.startswith("gated sqlmap_") and "requires explicit tool selection/approval" in line for line in plan
    )
    assert any("not_applicable:no_wordpress_signal" in line for line in plan)
    assert any("not_applicable:no_input_surface" in line for line in plan)
    assert any("duplicate_surface" in line for line in plan)
    assert any(line.startswith("web_contextual_targets:") for line in plan)

    assert runner._web_has_input_surface(
        {f"scrapling_{suffix_8080}": '<form method="post"><input name="x">'},
        urls[2],
    )
    assert runner._web_has_input_surface(
        {f"katana_crawl_{suffix_8080}": "http://example.test/a?q=x"},
        urls[2],
    )


def test_web_planning_edge_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    urls = ["http://example.test/a", "http://example.test/b"]
    monkeypatch.setattr(runner, "_web_endpoint_alive", lambda _results, _url: True)
    monkeypatch.setattr(runner, "_web_fingerprint", lambda _results, url: url)
    monkeypatch.setattr(runner, "_prefer_web_representative", lambda _urls: "shared")
    selected, _skipped = runner._plan_distinct_web_targets(urls, {})
    assert selected == ["shared"]

    monkeypatch.setattr(
        runner,
        "_web_endpoint_alive",
        lambda _results, url: url.startswith("https://"),
    )
    monkeypatch.setattr(runner, "_web_fingerprint", lambda _results, _url: "same")
    monkeypatch.setattr(runner, "_prefer_web_representative", lambda candidates: candidates[0])
    selected, skipped = runner._plan_distinct_web_targets(
        ["http://example.test", "https://example.test"],
        {},
    )
    assert selected == ["https://example.test"]
    assert skipped["http://example.test"] == "https://example.test"

    plan: list[str] = []
    assert runner._plan_contextual_web_jobs([], {}, plan) == []
    assert plan == []


def test_exhaustive_coverage_web_domain_and_service_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    direct: list[tuple[str, str]] = []
    concurrent_jobs: list[list[tuple[str, str, str]]] = []
    monkeypatch.setattr(runner, "_target_looks_domain", lambda _target: True)
    monkeypatch.setattr(runner, "_detect_web_ports_from_nmap", lambda _output: [])
    monkeypatch.setattr(runner, "_web_urls_from_ports", lambda target, ports: [f"http://{target}:{ports[0]}"])
    monkeypatch.setattr(runner, "_nmap_has_any_open_port", lambda *_args: True)
    monkeypatch.setattr(
        runner,
        "_run_registered_extended_tool",
        lambda _results, _plan, tool, target, result_key=None: direct.append((tool, target)),
    )
    monkeypatch.setattr(
        runner,
        "_run_registered_extended_tools_concurrent",
        lambda _results, _plan, jobs, max_workers=6: concurrent_jobs.append(jobs),
    )
    monkeypatch.setattr(
        runner,
        "_plan_contextual_web_jobs",
        lambda urls, _results, _plan: [("context", urls[0], "key")],
    )
    results = {
        "nmap": "21 25 389 5432",
        "curl_headers": "HTTP/1.1 200 OK",
        "whatweb": "",
    }

    assert runner._run_exhaustive_applicable_coverage("example.test", results) is results
    assert ("subfinder", "example.test") in direct
    assert ("ftp_anonymous_check", "example.test") in direct
    assert ("smtp_probe", "example.test") in direct
    assert ("db_inventory", "example.test") in direct
    assert ("ad_enum", "example.test") in direct
    assert len(concurrent_jobs) == 2
    assert "ports=80" in results["x_mode_plan"]


def test_exhaustive_coverage_no_web_or_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    direct: list[str] = []
    monkeypatch.setattr(runner, "_target_looks_domain", lambda _target: False)
    monkeypatch.setattr(runner, "_detect_web_ports_from_nmap", lambda _output: [])
    monkeypatch.setattr(runner, "_nmap_has_any_open_port", lambda *_args: False)
    monkeypatch.setattr(
        runner,
        "_run_registered_extended_tool",
        lambda _results, _plan, tool, _target, result_key=None: direct.append(tool),
    )
    results: dict[str, str] = {}

    runner._run_exhaustive_applicable_coverage("10.0.0.1", results)

    assert direct == ["httpx_probe", "naabu", "tlsx"]
    assert "web_deep_tools: not_applicable" in results["x_mode_plan"]
    assert "target_is_ip" in results["x_mode_plan"]


def test_single_tool_and_basic_dispatch_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = ExecutionContext.automatic(max_output_bytes=8)
    from core.tools.registry import get_tool

    tool_def = get_tool("nmap")
    assert tool_def is not None
    canonical_calls: list[str] = []

    def provider(target, extra_flags=None):
        del extra_flags
        canonical_calls.append(target)
        return "value:" + target

    monkeypatch.setattr(tool_def, "func", provider)
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    rogue_calls: list[str] = []
    monkeypatch.setitem(
        runner.TOOLS_MENU,
        "1",
        ("web login brute", lambda target: rogue_calls.append(target) or "rogue"),
    )
    runner.run_single_tool(
        "1",
        "target",
        context,
    )
    assert canonical_calls == ["target"]
    assert rogue_calls == []

    monkeypatch.setitem(runner.TOOLS_MENU, "1", ("nmap", provider))
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(registered=False))
    assert "registered_denied" in runner.run_single_tool("1", "target", context)

    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "config denied")
    assert runner.run_single_tool("1", "target", context) == "config denied"
    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "")
    assert "OUTPUT LIMIT" in runner.run_single_tool("1", "target", context)
    assert "Unknown tool key" in runner.run_single_tool("missing", "target", context)

    assert "FIXTURE OUTPUT" in runner.format_recon_for_llm({"fixture": " value "})
    assert "structured" in runner.format_recon_for_llm({"fixture": ToolResult(stdout=" structured ")})
    assert runner.format_recon_for_llm({}) == ""
    assert runner._execution_context_or_current(context) is context
    monkeypatch.setattr(runner, "current_execution_context", lambda: context)
    assert runner._execution_context_or_current() is context
    assert runner._execution_denied("reason", "request") == "[!] Execution denied: reason (request_id=request)"


def test_disabled_registered_provider_fails_closed_at_menu_and_command_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools.registry import get_tool

    calls: list[str] = []
    tool_def = get_tool("nmap")
    assert tool_def is not None
    monkeypatch.setattr(tool_def, "enabled", False)
    monkeypatch.setattr(
        tool_def,
        "func",
        lambda target, extra_flags=None: calls.append(target) or "unexpected",
    )
    context = ExecutionContext.operator(
        actor="disabled-provider-test",
        approval_id="disabled-provider-test",
        target_scope=("example.test",),
    )

    menu_result = runner.run_single_tool("1", "example.test", context)
    command_result = runner.run_tool_by_command("nmap example.test", context)

    assert "provider_disabled" in menu_result
    assert "provider_disabled" in command_result
    assert calls == []


def test_catalog_resolution_failures_are_explicit_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import core.actions as actions
    import core.tools.registry as registry

    tool_def = registry.get_tool("nmap")
    assert tool_def is not None

    monkeypatch.setattr(registry, "get_tool", lambda _name: None)
    assert runner._catalog_tool_definition("missing") == (None, "not_registered")

    monkeypatch.setattr(registry, "get_tool", lambda _name: tool_def)
    monkeypatch.setattr(registry, "list_tools", lambda: [tool_def])

    def fail_catalog(*_args, **_kwargs):
        raise RuntimeError("catalog unavailable")

    monkeypatch.setattr(actions, "build_action_catalog", fail_catalog)
    assert runner._catalog_tool_definition("nmap") == (
        None,
        "action_catalog_error:RuntimeError",
    )

    monkeypatch.setattr(
        actions,
        "build_action_catalog",
        lambda *_args, **_kwargs: SimpleNamespace(resolve=lambda _name: None),
    )
    assert runner._catalog_tool_definition("nmap") == (
        None,
        "action_catalog_unresolved",
    )

    mismatched = SimpleNamespace(
        adapter=SimpleNamespace(descriptor=SimpleNamespace(name="other")),
    )
    monkeypatch.setattr(
        actions,
        "build_action_catalog",
        lambda *_args, **_kwargs: SimpleNamespace(
            resolve=lambda _name: mismatched,
        ),
    )
    assert runner._catalog_tool_definition("nmap") == (
        None,
        "action_catalog_identity_mismatch",
    )

    context = ExecutionContext.automatic(
        ("example.test",),
        actor="catalog-failure-test",
    )
    monkeypatch.setattr(
        runner,
        "_catalog_tool_definition",
        lambda _name: (None, "fixture_catalog_denial"),
    )
    denied = runner._run_catalog_command("nmap", ["example.test"], context)
    assert "fixture_catalog_denial" in denied


def test_registered_provider_exception_is_redacted_and_output_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools.registry import get_tool

    tool_def = get_tool("nmap")
    assert tool_def is not None

    def provider(_target, extra_flags=None):
        del extra_flags
        raise RuntimeError("password=octopus-secret-value --token octopus-token-value " + "x" * 4096)

    monkeypatch.setattr(tool_def, "func", provider)
    context = ExecutionContext.operator(
        actor="provider-error-test",
        approval_id="provider-error-test",
        target_scope=("example.test",),
        max_output_bytes=1024,
    )

    result = runner.run_tool_by_command("nmap example.test", context)
    rendered = str(result)

    assert "octopus-secret-value" not in rendered
    assert "octopus-token-value" not in rendered
    assert "[REDACTED]" in rendered
    assert "OUTPUT LIMIT" in rendered
    assert len(rendered.encode()) <= context.max_output_bytes


def test_configured_denial_redaction_truncation_and_bounded_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.killchain import policy

    monkeypatch.setattr(policy, "master_gate_message", lambda: "master")
    monkeypatch.setattr(policy, "TOOL_STAGE_MAP", {"known": "stage"})
    monkeypatch.setattr(policy, "stage_gate_message", lambda stage: f"stage:{stage}")
    assert runner._configured_killchain_denial("killchain_full") == "master"
    assert runner._configured_killchain_denial("known") == "stage:stage"
    assert runner._configured_killchain_denial("other") == ""
    assert "[REDACTED]" in runner._redact_command("tool password=secret")
    assert runner._truncate_output_text("ok", 2) == "ok"
    assert "OUTPUT LIMIT" in runner._truncate_output_text("ééé", 1)

    context = ExecutionContext.automatic(max_output_bytes=4)
    result = ToolResult(command="tool password=secret", stdout="abcdef", stderr="ghijkl")
    assert runner._bounded_tool_result(result, context) is result
    assert "[REDACTED]" in result.command
    assert "OUTPUT LIMIT" in result.stdout
    assert "OUTPUT LIMIT" in result.stderr
    assert "OUTPUT LIMIT" in runner._bounded_tool_result("abcdef", context)


def test_bound_network_targets_handles_signatures_and_deduplication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def provider(target, host="", url=""):
        return target, host, url

    assert set(
        runner._bound_network_targets(
            provider,
            ["one"],
            {"host": "one", "url": "two"},
        )
    ) == {"one", "two"}
    assert runner._bound_network_targets(provider, [None], {"host": ""}) == ()
    monkeypatch.setattr(
        runner.inspect,
        "signature",
        lambda _func: (_ for _ in ()).throw(TypeError("signature")),
    )
    assert runner._bound_network_targets(provider, [], {}) == ()


def test_python_repl_is_policy_gated_and_uses_fake_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        allow_python_repl=True,
    )
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(repl=False))
    assert "repl_denied" in runner.run_python_repl("print(1)", context)

    calls: list[tuple[Any, dict[str, Any]]] = []
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    monkeypatch.setattr(
        runner,
        "_execute_process",
        lambda command, **kwargs: calls.append((command, kwargs)) or ToolResult(stdout="repl output"),
    )
    assert runner.run_python_repl("print(1)", context) == "repl output"
    assert calls[0][0][:2] == [sys.executable, "-I"]


def test_tool_command_rejects_bad_empty_fake_and_unknown_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools import registry

    monkeypatch.setattr(registry, "get_tool", lambda _name: None)
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(command=False))
    context = ExecutionContext.automatic()

    assert "invalid_quoting" in runner.run_tool_by_command("tool 'unterminated", context)
    assert runner.run_tool_by_command("  ", context) == "[!] Empty command."
    assert "TARGET" in runner.run_tool_by_command("metasploit_scan", context)
    assert "1.2.3.4" in runner.run_tool_by_command("metasploit_scan 1.2.3.4", context)
    assert "example.test" in runner.run_tool_by_command(
        "metasploit_scan http://example.test:8080/path",
        context,
    )
    assert "http:" in runner.run_tool_by_command(
        "metasploit_scan 'http://[invalid'",
        context,
    )
    assert "NOT a real tool" in runner.run_tool_by_command("metasploit_scan /path", context)
    assert "command_denied" in runner.run_tool_by_command("unknown target", context)


def test_tool_command_supports_two_word_alias_and_outer_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools import registry

    calls: list[tuple[Any, ...]] = []

    def provider(target="default"):
        calls.append((target,))
        return "ok"

    tool = _tool_def("two_word", provider)
    monkeypatch.setattr(
        registry,
        "get_tool",
        lambda name: tool if name == "two word" else None,
    )
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "")
    assert runner.run_tool_by_command("two word target") == "ok"
    assert calls == [("target",)]

    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "configured")
    assert runner.run_tool_by_command("two word target") == "configured"
    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "")
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(registered=False))
    assert "registered_denied" in runner.run_tool_by_command("two word target")

    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    tool.func = lambda _target: (_ for _ in ()).throw(RuntimeError("provider boom"))
    assert "provider boom" in runner.run_tool_by_command("two word target")


def test_tool_command_inner_parser_handles_quoting_and_empty_parts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools import registry

    tool = _tool_def("fixture", lambda: "ok")
    monkeypatch.setattr(registry, "get_tool", lambda _name: tool)
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "")
    original_split = runner.shlex.split

    outcomes = iter([["fixture"], ValueError("inner quoting")])

    def split_error(*_args, **_kwargs):
        value = next(outcomes)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(runner.shlex, "split", split_error)
    assert runner.run_tool_by_command("fixture") == "ok"

    outcomes = iter([["fixture"], []])
    assert runner.run_tool_by_command("fixture") == "ok"
    monkeypatch.setattr(runner.shlex, "split", original_split)


def test_tool_command_nmap_rustscan_and_searchsploit_parser_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools import registry

    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def nmap(target="default", extra_flags=None):
        calls.append(("nmap", (target, extra_flags), {}))
        return "nmap-ok"

    def searchsploit(query="default"):
        calls.append(("searchsploit", (query,), {}))
        return "search-ok"

    def rustscan(target="default", extra_flags=None):
        calls.append(("rustscan", (target, extra_flags), {}))
        return "rustscan-ok"

    tools = {
        "nmap": _tool_def("nmap", nmap),
        "rustscan": _tool_def("rustscan", rustscan),
        "searchsploit": _tool_def("searchsploit", searchsploit),
    }
    monkeypatch.setattr(registry, "get_tool", tools.get)
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "")

    assert runner.run_tool_by_command("nmap -oX out --ports=80 -sV 10.0.0.1") == "nmap-ok"
    assert calls[-1][1] == ("10.0.0.1", ["-sV"])
    assert runner.run_tool_by_command("nmap 10.0.0.1") == "nmap-ok"
    assert calls[-1][1] == ("10.0.0.1", None)
    assert runner.run_tool_by_command("nmap -oX") == "nmap-ok"
    assert calls[-1][1] == ("default", None)

    assert runner.run_tool_by_command("rustscan -a 10.0.0.1 -- -sV") == "rustscan-ok"
    assert calls[-1][1] == ("10.0.0.1", ["--", "-sV"])
    assert runner.run_tool_by_command("rustscan --addresses=10.0.0.2") == "rustscan-ok"
    assert calls[-1][1] == ("10.0.0.2", None)
    assert runner.run_tool_by_command("rustscan -a 10.0.0.1 --addresses 10.0.0.2") == "rustscan-ok"
    assert calls[-1][1] == ("10.0.0.1", None)
    assert runner.run_tool_by_command("rustscan -a 10.0.0.1 --addresses=10.0.0.2") == "rustscan-ok"
    assert calls[-1][1] == ("10.0.0.1", None)
    assert runner.run_tool_by_command("rustscan 10.0.0.3") == "rustscan-ok"
    assert calls[-1][1] == ("10.0.0.3", None)
    assert runner.run_tool_by_command("rustscan --") == "rustscan-ok"
    assert calls[-1][1] == ("default", None)

    assert runner.run_tool_by_command("searchsploit -s ssh --service nginx --exclude ignored CVE 2024") == "search-ok"
    assert calls[-1][1] == ("ssh nginx CVE 2024",)
    assert runner.run_tool_by_command("searchsploit -p ignored term") == "search-ok"


def test_tool_command_curl_enum_and_url_preservation_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools import registry

    calls: list[tuple[str, Any]] = []

    def curl_headers(url="default"):
        calls.append(("curl", url))
        return "curl-ok"

    def enum4linux(target="default"):
        calls.append(("enum", target))
        return "enum-ok"

    def scrapling(url="default"):
        calls.append(("scrapling", url))
        return "scrape-ok"

    tools = {
        "curl": _tool_def("curl_headers", curl_headers),
        "enum": _tool_def("enum4linux", enum4linux),
        "scrape": _tool_def("scrapling", scrapling),
    }
    monkeypatch.setattr(registry, "get_tool", tools.get)
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "")

    runner.run_tool_by_command("curl -H value -s https://example.test/a?q=1")
    runner.run_tool_by_command("curl -s example.test")
    runner.run_tool_by_command("curl --silent")
    runner.run_tool_by_command("enum -a --shares 10.0.0.1")
    runner.run_tool_by_command("scrape https://example.test/path?q=1")

    assert ("curl", "https://example.test/a?q=1") in calls
    assert ("curl", "example.test") in calls
    assert ("curl", "--silent") in calls
    assert ("enum", "10.0.0.1") in calls
    assert ("scrapling", "https://example.test/path?q=1") in calls


@pytest.mark.parametrize(
    ("tool_name", "command", "expected"),
    [
        ("nuclei_safe", "tool -u=https://a.test", "https://a.test"),
        ("nuclei_safe", "tool -url https://b.test", "https://b.test"),
        ("nuclei_safe", "tool -severity high -silent https://c.test", "https://c.test"),
        ("nuclei_safe", "tool -silent target.test", "target.test"),
        ("nuclei_safe", "tool -silent", "-silent"),
        ("nikto", "tool -h https://a.test", "https://a.test"),
        ("nikto", "tool --host=https://b.test", "https://b.test"),
        ("nikto", "tool -output out https://c.test", "https://c.test"),
        ("nikto", "tool -silent", "-silent"),
        ("sqlmap", "tool -u https://a.test", "https://a.test"),
        ("sqlmap", "tool --url=https://b.test", "https://b.test"),
        ("sqlmap", "tool --data x https://c.test", "https://c.test"),
        ("sqlmap", "tool --batch", "--batch"),
        ("wpscan", "tool --url https://a.test", "https://a.test"),
        ("wpscan", "tool --url=https://b.test", "https://b.test"),
        ("wpscan", "tool --api-token x https://c.test", "https://c.test"),
        ("wpscan", "tool --random-user-agent", "--random-user-agent"),
    ],
)
def test_tool_command_scanner_parser_branches(
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    command: str,
    expected: str,
) -> None:
    from core.tools import registry

    seen: list[str] = []

    def provider(url="default"):
        seen.append(url)
        return "ok"

    monkeypatch.setattr(registry, "get_tool", lambda _name: _tool_def(tool_name, provider))
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "")
    assert runner.run_tool_by_command(command) == "ok"
    assert seen == [expected]


def test_tool_command_generic_parameter_categories_and_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.tools import registry

    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def target_tool(target="target-default"):
        calls.append(("target", (target,), {}))
        return "ok"

    def query_tool(query="query-default"):
        calls.append(("query", (query,), {}))
        return "ok"

    def flags_tool(extra_flags=None):
        calls.append(("flags", (extra_flags,), {}))
        return "ok"

    def user_tool(user="user-default"):
        calls.append(("user", (user,), {}))
        return "ok"

    def misc_tool(misc="misc-default"):
        calls.append(("misc", (misc,), {}))
        return "ok"

    def no_params():
        calls.append(("none", (), {}))
        return "ok"

    tools = {
        "target": _tool_def("generic", target_tool),
        "query": _tool_def("generic", query_tool),
        "flags": _tool_def("generic", flags_tool),
        "user": _tool_def("generic", user_tool),
        "misc": _tool_def("generic", misc_tool),
        "none": _tool_def("generic", no_params),
    }
    monkeypatch.setattr(registry, "get_tool", tools.get)
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    monkeypatch.setattr(runner, "_configured_killchain_denial", lambda _name: "")

    for name in ("target", "query", "flags", "user", "misc"):
        assert runner.run_tool_by_command(name) == "ok"
    assert runner.run_tool_by_command("target one") == "ok"
    assert runner.run_tool_by_command("query one two") == "ok"
    assert runner.run_tool_by_command("flags one two") == "ok"
    assert runner.run_tool_by_command("user one") == "ok"
    assert runner.run_tool_by_command("misc one") == "ok"
    assert "Error executing tool" in runner.run_tool_by_command("none extra values")
    assert ("target", ("1.2.3.4",), {}) not in calls
    assert runner.run_tool_by_command("target 1.2.3.4:80") == "ok"
    assert calls[-1][1] == ("1.2.3.4",)

    def all_defaults(query="query", extra_flags=None, user="user", misc="misc"):
        calls.append(("defaults", (query, extra_flags, user, misc), {}))
        return "ok"

    tools["defaults"] = _tool_def("generic", all_defaults)
    assert runner.run_tool_by_command("defaults") == "ok"
    assert calls[-1][1] == ("query", None, "user", "misc")

    def required_query(query, misc="misc"):
        return query, misc

    def required_flags(extra_flags, misc="misc"):
        return extra_flags, misc

    def required_user(user, misc="misc"):
        return user, misc

    tools.update(
        {
            "required_query": _tool_def("generic", required_query),
            "required_flags": _tool_def("generic", required_flags),
            "required_user": _tool_def("generic", required_user),
        }
    )
    for name in ("required_query", "required_flags", "required_user"):
        assert "Error executing tool" in runner.run_tool_by_command(name)


def test_interactive_all_and_manual_choices_are_fully_stubbed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner,
        "_run_registered_default_recon",
        lambda target: {"nmap": f"recon:{target}"},
    )
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "a")
    assert "recon:10.0.0.1" in runner.interactive_tool_run("10.0.0.1")

    choices = iter(["fixture missing"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(choices))
    monkeypatch.setitem(runner.TOOLS_MENU, "fixture", ("fixture", lambda _target: "unused"))
    monkeypatch.setattr(runner, "run_single_tool", lambda key, target, context: f"ran:{key}:{target}:{context.actor}")
    output = runner.interactive_tool_run("10.0.0.1")
    assert "ran:fixture:10.0.0.1:interactive_cli" in output
    assert "MISSING" not in output


@pytest.mark.parametrize("vuln_outcome", ["success", "import_error", "error"])
def test_interactive_x_mode_vulnerability_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    vuln_outcome: str,
) -> None:
    import core.killchain

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "x")
    monkeypatch.setattr(
        runner,
        "_run_registered_default_recon",
        lambda _target: {"nmap": "base"},
    )
    monkeypatch.setattr(
        runner,
        "_run_exhaustive_applicable_coverage",
        lambda _target, results: {**results, "x_mode_plan": "plan"},
    )
    original_import = builtins.__import__
    if vuln_outcome == "success":
        monkeypatch.setattr(core.killchain, "vuln_assess", lambda target, _blob: f"vuln:{target}")
    elif vuln_outcome == "error":
        monkeypatch.setattr(
            core.killchain,
            "vuln_assess",
            lambda *_args: (_ for _ in ()).throw(RuntimeError("vuln boom")),
        )
    else:

        def fail_killchain_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "core.killchain" and "vuln_assess" in fromlist:
                raise ImportError("missing killchain")
            return original_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", fail_killchain_import)

    output = runner.interactive_tool_run("10.0.0.1")

    if vuln_outcome == "success":
        assert "vuln:10.0.0.1" in output
    elif vuln_outcome == "error":
        assert "vuln boom" in output
    else:
        assert "missing killchain" in output


def test_interactive_n_mode_rich_surfaces_and_registry_layers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import core.killchain

    _patch_immediate_futures(monkeypatch)
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "n")
    monkeypatch.setattr(
        runner,
        "_run_registered_default_recon",
        lambda _target: {
            "nmap": "21/tcp open ftp\n22/tcp open ssh\n80/tcp open http\n389/tcp open ldap",
            "curl_headers": "HTTP/1.1 200 OK\nServer: nginx",
            "whatweb": "nginx",
        },
    )
    monkeypatch.setattr(runner, "_detect_web_ports_from_nmap", lambda _output: ["80", "8443"])
    monkeypatch.setattr(
        runner,
        "_web_urls_from_ports",
        lambda target, _ports: [f"http://{target}", f"https://{target}:8443"],
    )
    monkeypatch.setattr(runner, "_target_looks_domain", lambda _target: True)
    monkeypatch.setattr(runner, "_nmap_has_any_open_port", lambda *_args: True)
    calls: list[tuple[Any, ...]] = []

    def fake_concurrent(results, plan, jobs, max_workers=6):
        del max_workers
        for tool_name, job_target, result_key in jobs:
            calls.append((tool_name, job_target))
            results[result_key] = f"{tool_name}:{job_target}"
            plan.append(f"run {result_key}: {tool_name} {job_target}")

    monkeypatch.setattr(
        runner,
        "_run_registered_extended_tools_concurrent",
        fake_concurrent,
    )

    def fake_web(name):
        return lambda target: calls.append((name, target)) or f"{name}:{target}"

    monkeypatch.setattr(runner, "run_wpscan", fake_web("wpscan"))
    monkeypatch.setattr(runner, "run_sqlmap", fake_web("sqlmap"))
    monkeypatch.setattr(runner, "run_nikto", fake_web("nikto"))
    monkeypatch.setattr(runner, "run_web_login_bruteforce", fake_web("web_login"))
    monkeypatch.setattr(runner, "run_scrapling_fetch", fake_web("scrapling"))
    monkeypatch.setattr(runner, "run_ssh_user_enum", lambda target: f"VALID USER\n✓ alice\n{target}")

    def bruteforce(service, target, **kwargs):
        calls.append(("bruteforce", service, target, kwargs))
        return f"brute:{service}"

    monkeypatch.setattr(runner, "run_bruteforce", bruteforce)
    monkeypatch.setattr(
        runner,
        "_run_registered_extended_tool",
        lambda _results, plan, tool, target, result_key=None: plan.append(f"extended:{result_key or tool}:{target}"),
    )
    monkeypatch.setattr(core.killchain, "vuln_assess", lambda target, _blob: f"vuln:{target}")

    output = runner.interactive_tool_run("example.test")

    assert "gated ssh_user_enum" in output
    assert "gated ssh_bruteforce" in output
    assert "gated ftp_bruteforce" in output
    assert "gated sqlmap" in output
    assert not any(call[0] == "sqlmap" for call in calls)
    assert "ftp_surface: present" in output
    assert "extended:subfinder:example.test" in output
    assert "extended:ad_enum:example.test" in output
    assert any(call[:2] == ("scrapling", "http://example.test") for call in calls)
    assert any(call[:2] == ("scrapling", "https://example.test:8443") for call in calls)


def test_interactive_n_mode_no_surfaces_and_import_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_immediate_futures(monkeypatch)
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "n")
    monkeypatch.setattr(runner, "_run_registered_default_recon", lambda _target: {})
    monkeypatch.setattr(runner, "_detect_web_ports_from_nmap", lambda _output: [])
    monkeypatch.setattr(runner, "_target_looks_domain", lambda _target: False)
    monkeypatch.setattr(runner, "_nmap_has_any_open_port", lambda *_args: False)
    monkeypatch.setattr(
        runner,
        "_run_registered_extended_tool",
        lambda _results, plan, tool, _target, result_key=None: plan.append(f"extended:{tool}"),
    )
    original_import = builtins.__import__

    def fail_killchain_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.killchain" and "vuln_assess" in fromlist:
            raise ImportError("missing")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_killchain_import)

    output = runner.interactive_tool_run("10.0.0.1")

    assert "web_surface: not_detected" in output
    assert "web_deep_tools: not_applicable" in output
    assert "ad_security_review: not_applicable" in output
    assert "missing" in output


def test_interactive_n_mode_unreliable_errors_and_default_web_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import core.killchain

    _patch_immediate_futures(monkeypatch)
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "n")
    monkeypatch.setattr(
        runner,
        "_run_registered_default_recon",
        lambda _target: {
            "nmap": "22/tcp open ssh",
            "curl_headers": "HTTP/1.1 200 OK",
        },
    )
    monkeypatch.setattr(runner, "_detect_web_ports_from_nmap", lambda _output: [])
    monkeypatch.setattr(runner, "_web_urls_from_ports", lambda target, ports: [f"http://{target}:{ports[0]}"])
    monkeypatch.setattr(runner, "_target_looks_domain", lambda _target: False)
    monkeypatch.setattr(runner, "_nmap_has_any_open_port", lambda *_args: False)

    def fake_concurrent(results, _plan, jobs, max_workers=6):
        del max_workers
        for tool_name, _job_target, result_key in jobs:
            results[result_key] = "[!] wpscan boom" if tool_name == "wpscan" else tool_name

    monkeypatch.setattr(
        runner,
        "_run_registered_extended_tools_concurrent",
        fake_concurrent,
    )
    monkeypatch.setattr(runner, "run_wpscan", lambda _target: (_ for _ in ()).throw(RuntimeError("wpscan boom")))
    monkeypatch.setattr(runner, "run_sqlmap", lambda _target: "sqlmap")
    monkeypatch.setattr(runner, "run_nikto", lambda _target: "nikto")
    monkeypatch.setattr(runner, "run_web_login_bruteforce", lambda _target: "login")
    monkeypatch.setattr(runner, "run_scrapling_fetch", lambda _target: "scrape")
    monkeypatch.setattr(runner, "run_ssh_user_enum", lambda _target: "UNRELIABLE")
    monkeypatch.setattr(
        runner,
        "run_bruteforce",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("brute boom")),
    )
    monkeypatch.setattr(runner, "_run_registered_extended_tool", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        core.killchain,
        "vuln_assess",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("vuln boom")),
    )

    output = runner.interactive_tool_run("10.0.0.1")

    assert "wpscan boom" in output
    assert "gated ssh_bruteforce" in output
    assert "vuln boom" in output
    assert "ports=80" in output


def test_interactive_n_mode_ssh_enum_without_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import core.killchain

    _patch_immediate_futures(monkeypatch)
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "n")
    monkeypatch.setattr(
        runner,
        "_run_registered_default_recon",
        lambda _target: {"nmap": "22/tcp open ssh"},
    )
    monkeypatch.setattr(runner, "_detect_web_ports_from_nmap", lambda _output: [])
    monkeypatch.setattr(runner, "_target_looks_domain", lambda _target: False)
    monkeypatch.setattr(runner, "_nmap_has_any_open_port", lambda *_args: False)
    monkeypatch.setattr(runner, "run_ssh_user_enum", lambda _target: "unknown enum response")
    monkeypatch.setattr(runner, "run_bruteforce", lambda *_args, **_kwargs: "bruteforce")
    monkeypatch.setattr(runner, "_run_registered_extended_tool", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(core.killchain, "vuln_assess", lambda *_args: "vuln")

    output = runner.interactive_tool_run("10.0.0.1")

    assert "gated ssh_user_enum" in output
    assert "unknown enum response" not in output


class _ProcessPipe:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = deque(outcomes)
        self.closed = False

    def read(self, _size: int):
        outcome = self.outcomes.popleft() if self.outcomes else b""
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def close(self) -> None:
        self.closed = True


class _Process:
    def __init__(
        self,
        *,
        stdout: _ProcessPipe | None = None,
        returncode: int | None = 0,
        poll_result: int | None = None,
        waits: list[Any] | None = None,
    ) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.poll_result = poll_result
        self.waits = deque(waits or [])
        self.pid = 4242
        self.calls: list[Any] = []

    def poll(self):
        self.calls.append("poll")
        return self.poll_result

    def terminate(self) -> None:
        self.calls.append("terminate")

    def kill(self) -> None:
        self.calls.append("kill")

    def wait(self, *, timeout: float):
        self.calls.append(("wait", timeout))
        if self.waits:
            outcome = self.waits.popleft()
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        return self.returncode


class _SyncThread:
    def __init__(self, *, target, daemon: bool) -> None:
        self.target = target
        self.daemon = daemon
        self.joins: list[float] = []

    def start(self) -> None:
        self.target()

    def is_alive(self) -> bool:
        return False

    def join(self, *, timeout: float) -> None:
        self.joins.append(timeout)


class _IdleThread:
    alive_values: tuple[bool, ...] = ()

    def __init__(self, *, target, daemon: bool) -> None:
        self.target = target
        self.daemon = daemon
        self.values = deque(self.alive_values)
        self.joins: list[float] = []

    def start(self) -> None:
        return None

    def is_alive(self) -> bool:
        return self.values.popleft() if self.values else False

    def join(self, *, timeout: float) -> None:
        self.joins.append(timeout)


def _patch_execute_runtime(
    monkeypatch: pytest.MonkeyPatch,
    process: _Process,
    *,
    thread_class: type = _SyncThread,
    times: list[float] | None = None,
) -> list[tuple[Any, dict[str, Any]]]:
    popen_calls: list[tuple[Any, dict[str, Any]]] = []

    def fake_popen(command, **kwargs):
        popen_calls.append((command, kwargs))
        return process

    values = deque(times or [0.0])
    monkeypatch.setattr(runner.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(threading, "Thread", thread_class)
    monkeypatch.setattr(time, "monotonic", lambda: values.popleft() if values else 0.0)
    return popen_calls


def test_terminate_process_group_all_platform_and_failure_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    done = _Process(poll_result=0)
    runner._terminate_process_group(done)
    assert done.calls == ["poll"]

    signals: list[tuple[int, signal.Signals]] = []
    posix = _Process(poll_result=None)
    monkeypatch.setattr(runner.os, "name", "posix")
    monkeypatch.setattr(runner.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    runner._terminate_process_group(posix, grace_seconds=-1)
    assert signals == [(posix.pid, signal.SIGTERM)]

    timed = _Process(
        poll_result=None,
        waits=[subprocess.TimeoutExpired("tool", 0), None],
    )

    def failing_killpg(_pid, sig):
        if sig == signal.SIGTERM:
            raise PermissionError
        raise ProcessLookupError

    monkeypatch.setattr(runner.os, "killpg", failing_killpg)
    runner._terminate_process_group(timed)
    assert "terminate" in timed.calls
    assert "kill" in timed.calls

    non_posix = _Process(
        poll_result=None,
        waits=[subprocess.TimeoutExpired("tool", 0)],
    )
    monkeypatch.setattr(runner.os, "name", "nt")
    runner._terminate_process_group(non_posix)
    assert "terminate" in non_posix.calls
    assert "kill" in non_posix.calls


def test_execute_process_normal_nuclei_output_limit_and_empty_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[_Process] = []
    monkeypatch.setattr(runner, "_terminate_process_group", terminated.append)
    context = ExecutionContext.automatic(max_runtime_seconds=20, max_output_bytes=100)

    pipe = _ProcessPipe([b"host: open password=secret\n", b""])
    process = _Process(stdout=pipe, returncode=0)
    calls = _patch_execute_runtime(monkeypatch, process, times=[0, 1, 2])
    result = runner._execute_process(
        ["tool", "password=secret"],
        context=context,
        tool="tool",
        timeout=10,
        shell=False,
        display_command="tool password=secret",
    )
    assert result.exit_code == 0
    assert "host: open" in result.stdout
    assert "secret" not in result.command
    assert calls[0][1]["shell"] is False
    assert pipe.closed

    monkeypatch.setattr(
        runner,
        "_nuclei_live_summary",
        lambda line: "summary" if "finding" in line else "",
    )
    nuclei_pipe = _ProcessPipe([b"quiet\nfinding\n", b""])
    nuclei = _Process(stdout=nuclei_pipe, returncode=0)
    _patch_execute_runtime(monkeypatch, nuclei, times=[0, 1, 2])
    assert (
        "finding"
        in runner._execute_process(
            ["nuclei"],
            context=context,
            tool="nuclei",
            timeout=10,
            shell=False,
            display_command="nuclei",
        ).stdout
    )

    limited_context = ExecutionContext.automatic(max_runtime_seconds=20, max_output_bytes=3)
    limited = _Process(stdout=_ProcessPipe([b"abcdef"]), returncode=0)
    _patch_execute_runtime(monkeypatch, limited, times=[0, 1])
    limited_result = runner._execute_process(
        ["tool"],
        context=limited_context,
        tool="tool",
        timeout=10,
        shell=False,
        display_command="tool",
    )
    assert limited_result.exit_code == -1
    assert "OUTPUT LIMIT" in limited_result.stdout
    assert limited in terminated

    zero_context = ExecutionContext.automatic(max_runtime_seconds=20, max_output_bytes=0)
    zero = _Process(stdout=_ProcessPipe([b"x"]), returncode=1)
    _patch_execute_runtime(monkeypatch, zero, times=[0, 1])
    assert (
        "OUTPUT LIMIT"
        in runner._execute_process(
            ["tool"],
            context=zero_context,
            tool="tool",
            timeout=10,
            shell=False,
            display_command="tool",
        ).stdout
    )

    no_stdout = _Process(stdout=None, returncode=None)
    _patch_execute_runtime(monkeypatch, no_stdout, times=[0, 1])
    no_output_result = runner._execute_process(
        ["tool"],
        context=context,
        tool="tool",
        timeout=10,
        shell=False,
        display_command="tool",
    )
    assert no_output_result.exit_code == -1
    assert "returned no output" in no_output_result.stdout


def test_execute_process_wait_timeout_and_reader_loop_states(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[_Process] = []
    monkeypatch.setattr(runner, "_terminate_process_group", terminated.append)
    context = ExecutionContext.automatic(max_runtime_seconds=10, max_output_bytes=100)

    waiting = _Process(
        stdout=_ProcessPipe([b""]),
        returncode=0,
        waits=[subprocess.TimeoutExpired("tool", 5), None],
    )
    _patch_execute_runtime(monkeypatch, waiting, times=[0, 1])
    assert (
        runner._execute_process(
            ["tool"],
            context=context,
            tool="tool",
            timeout=10,
            shell=False,
            display_command="tool",
        ).exit_code
        == 0
    )
    assert waiting in terminated

    class HeartbeatThread(_IdleThread):
        alive_values = (True, True, False)

    heartbeat = _Process(stdout=_ProcessPipe([]), returncode=0)
    heartbeat_context = ExecutionContext.automatic(
        max_runtime_seconds=100,
        max_output_bytes=100,
    )
    _patch_execute_runtime(
        monkeypatch,
        heartbeat,
        thread_class=HeartbeatThread,
        times=[0, 30, 31],
    )
    heartbeat_result = runner._execute_process(
        ["tool"],
        context=heartbeat_context,
        tool="tool",
        timeout=100,
        shell=False,
        display_command="tool",
    )
    assert "returned no output" in heartbeat_result.stdout

    class QuietLoopThread(_IdleThread):
        alive_values = (True, True, False)

    quiet = _Process(stdout=_ProcessPipe([]), returncode=0)
    _patch_execute_runtime(
        monkeypatch,
        quiet,
        thread_class=QuietLoopThread,
        times=[0, 1, 2],
    )
    quiet_result = runner._execute_process(
        ["tool"],
        context=heartbeat_context,
        tool="tool",
        timeout=100,
        shell=False,
        display_command="tool",
    )
    assert "returned no output" in quiet_result.stdout

    class TimeoutThread(_IdleThread):
        alive_values = (True,)

    timeout_process = _Process(stdout=_ProcessPipe([]), returncode=0)
    _patch_execute_runtime(
        monkeypatch,
        timeout_process,
        thread_class=TimeoutThread,
        times=[0, 20, 21],
    )
    timeout_result = runner._execute_process(
        ["tool"],
        context=context,
        tool="tool",
        timeout=2,
        shell=False,
        display_command="tool",
    )
    assert timeout_result.exit_code == -1
    assert "TIMEOUT" in timeout_result.stdout


def test_execute_process_cancellation_and_keyboard_interrupt_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated: list[_Process] = []
    monkeypatch.setattr(runner, "_terminate_process_group", terminated.append)

    class CancelThread(_IdleThread):
        alive_values = (True,)

    context = ExecutionContext.automatic(max_runtime_seconds=10, max_output_bytes=100)
    context.cancellation.cancel("user_cancelled")
    process = _Process(stdout=_ProcessPipe([]), returncode=7)
    _patch_execute_runtime(monkeypatch, process, thread_class=CancelThread, times=[0, 1, 2])
    with pytest.raises(ExecutionCancelled) as cancelled:
        runner._execute_process(
            ["tool"],
            context=context,
            tool="tool",
            timeout=10,
            shell=False,
            display_command="tool",
        )
    assert cancelled.value.reason_code == "user_cancelled"
    assert process in terminated

    before = ExecutionContext.automatic()
    monkeypatch.setattr(
        runner.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(time, "monotonic", lambda: 0.0)
    with pytest.raises(ExecutionCancelled) as interrupted:
        runner._execute_process(
            ["tool"],
            context=before,
            tool="tool",
            timeout=10,
            shell=False,
            display_command="tool",
        )
    assert interrupted.value.returncode is None

    after = ExecutionContext.automatic()
    interrupted_process = _Process(
        stdout=_ProcessPipe([b"partial", KeyboardInterrupt()]),
        returncode=9,
    )
    _patch_execute_runtime(monkeypatch, interrupted_process, times=[0, 1])
    with pytest.raises(ExecutionCancelled) as interrupted_after:
        runner._execute_process(
            ["tool"],
            context=after,
            tool="tool",
            timeout=10,
            shell=False,
            display_command="tool",
        )
    assert interrupted_after.value.stdout == "partial"
    assert interrupted_after.value.returncode == 9


def test_execute_process_platform_exceptions_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = ExecutionContext.automatic()
    monkeypatch.setattr(time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(
        runner.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("password=secret")),
    )
    failed = runner._execute_process(
        ["tool"],
        context=context,
        tool="tool",
        timeout=10,
        shell=False,
        display_command="tool password=secret",
    )
    assert failed.exit_code == -1
    assert "secret" not in failed.stdout

    terminated: list[_Process] = []
    monkeypatch.setattr(runner, "_terminate_process_group", terminated.append)
    process = _Process(stdout=_ProcessPipe([OSError("read failed")]), returncode=1)
    _patch_execute_runtime(monkeypatch, process, times=[0, 1])
    read_failed = runner._execute_process(
        ["tool"],
        context=context,
        tool="tool",
        timeout=10,
        shell=False,
        display_command="tool",
    )
    assert "read failed" in read_failed.stdout
    assert process in terminated


def test_tool_timeout_managed_shell_and_arbitrary_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        allow_shell=True,
        max_runtime_seconds=50,
    )
    monkeypatch.setattr(runner, "get_tool_config", lambda _name: {"timeout": "40"})
    assert runner._tool_timeout("nuclei", context) == 40
    assert runner._tool_timeout("rustscan", context) == 50
    assert runner._tool_timeout("other", context) == 50
    monkeypatch.setattr(
        runner,
        "get_tool_config",
        lambda _name: (_ for _ in ()).throw(RuntimeError("config")),
    )
    assert runner._tool_timeout("nuclei", context) == 50

    executed: list[tuple[Any, dict[str, Any]]] = []
    monkeypatch.setattr(
        runner,
        "_execute_process",
        lambda command, **kwargs: executed.append((command, kwargs)) or ToolResult(stdout="executed"),
    )
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(shell=False))
    denied = runner.run_managed_shell("printf ok", context)
    assert denied.exit_code == -1
    assert "shell_denied" in denied.stdout

    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy())
    assert runner.run_managed_shell("printf ok", context).stdout == "executed"
    assert executed[-1][1]["tool"] == "shell"
    shell_invocation = ToolInvocation(
        executable="sh",
        argv=("sh",),
        uses_shell=True,
    )
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(invocation=shell_invocation))
    runner.run_managed_shell("printf ok", context)
    assert executed[-1][1]["tool"] == "sh"

    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(command=False))
    assert "command_denied" in runner.run_arbitrary_cmd("anything", context)
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(invocation=None))
    assert "missing_typed_invocation" in runner.run_arbitrary_cmd("anything", context)

    monkeypatch.setattr(runner, "run_managed_shell", lambda command, ctx: f"shell:{command}:{ctx.actor}")
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(invocation=shell_invocation))
    assert runner.run_arbitrary_cmd("printf ok", context).startswith("shell:printf ok")

    registered = ToolInvocation(
        executable="nmap",
        argv=("nmap", "target"),
        registered_name="nmap",
    )
    monkeypatch.setattr(runner, "run_tool_by_command", lambda command, ctx: f"registered:{command}:{ctx.actor}")
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(invocation=registered))
    assert runner.run_arbitrary_cmd("nmap target", context).startswith("registered:nmap")

    direct = ToolInvocation(executable="rustscan", argv=("rustscan", "target"))
    monkeypatch.setattr(runner, "_EXECUTION_POLICY", _Policy(invocation=direct))
    direct_result = runner.run_arbitrary_cmd("rustscan target", context)
    assert "unregistered_direct_execution_disabled" in direct_result


def _credential(
    *,
    service: str = "ldap",
    username: str = "DOMAIN\\alice",
    port: int = 0,
) -> CredentialRef:
    return CredentialRef(
        handle="credential://fixture",
        service=service,
        target="10.0.0.1",
        username=username,
        port=port,
    )


@contextlib.contextmanager
def _material_for(credential: CredentialRef, password: str = "secret"):
    yield SimpleNamespace(username=credential.username, password=password)


def test_provider_identity_and_credential_execution_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert runner._provider_identity(" DOMAIN\\alice ") == ("alice", "DOMAIN")
    assert runner._provider_identity("alice@example.test") == ("alice", "example.test")
    assert runner._provider_identity(" alice ") == ("alice", "")
    assert runner._provider_identity(None) == ("", "")
    with runner._credential_dict_for_execution(None) as missing:
        assert missing is None

    monkeypatch.setattr(runner, "credential_material_for_execution", _material_for)
    ldap = _credential()
    retained: dict[str, Any]
    with runner._credential_dict_for_execution(ldap) as provider:
        assert provider is not None
        retained = provider
        assert provider["user"] == "alice"
        assert provider["domain"] == "DOMAIN"
        assert provider["port"] == 389
        assert provider["password"] == "secret"
    assert retained["password"] == ""

    ssh = _credential(service="ssh", username="bob", port=0)
    with runner._credential_dict_for_execution(ssh) as provider:
        assert provider["port"] == 22
    explicit = _credential(service="ssh", username="bob", port=2222)
    with runner._credential_dict_for_execution(explicit) as provider:
        assert provider["port"] == 2222


def _install_ad_modules(monkeypatch: pytest.MonkeyPatch, calls: list[Any]) -> None:
    enumeration = types.ModuleType("core.killchain.ad.enumeration")
    enumeration.run_ad_enum = lambda target, creds=None: calls.append(("enum", target, creds)) or "enum-ok"
    kerberos = types.ModuleType("core.killchain.ad.kerberos")
    kerberos.asrep_roast = lambda target, creds=None: calls.append(("asrep", target, creds)) or "asrep-ok"
    kerberos.kerberoast = lambda target, creds: calls.append(("kerb", target, creds)) or "kerb-ok"
    credential = types.ModuleType("core.killchain.ad.credential")
    credential.dcsync = lambda target, creds: calls.append(("dcsync", target, creds)) or "dcsync-ok"
    credential.pass_the_hash = lambda target, user, nthash, domain="": (
        calls.append(("pth", target, user, nthash, domain)) or "pth-ok"
    )
    lateral = types.ModuleType("core.killchain.ad.lateral")
    lateral.psexec = lambda target, creds: calls.append(("psexec", target, creds)) or "psexec-ok"
    lateral.wmiexec = lambda target, creds: calls.append(("wmiexec", target, creds)) or "wmiexec-ok"
    monkeypatch.setitem(sys.modules, enumeration.__name__, enumeration)
    monkeypatch.setitem(sys.modules, kerberos.__name__, kerberos)
    monkeypatch.setitem(sys.modules, credential.__name__, credential)
    monkeypatch.setitem(sys.modules, lateral.__name__, lateral)


def test_ad_tool_success_missing_credentials_and_unknown_actions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Any] = []
    _install_ad_modules(monkeypatch, calls)
    monkeypatch.setattr(runner, "credential_material_for_execution", _material_for)
    credential = _credential()
    monkeypatch.setattr(runner, "get_best_credential_ref", lambda *_args: credential)
    inputs = iter(["", "abc123"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(inputs))

    assert runner._run_ad_tool("enum", "target") == "enum-ok"
    assert runner._run_ad_tool("asrep", "target") == "asrep-ok"
    assert runner._run_ad_tool("kerberoast", "target") == "kerb-ok"
    assert runner._run_ad_tool("dcsync", "target") == "dcsync-ok"
    assert "requires an NT hash" in runner._run_ad_tool("pth", "target")
    assert runner._run_ad_tool("pth", "target") == "pth-ok"
    assert runner._run_ad_tool("psexec", "target") == "psexec-ok"
    assert runner._run_ad_tool("wmiexec", "target") == "wmiexec-ok"
    assert "Unknown AD action" in runner._run_ad_tool("unknown", "target")
    assert any(item[0] == "pth" and item[2:4] == ("alice", "abc123") for item in calls)

    monkeypatch.setattr(runner, "get_best_credential_ref", lambda *_args: None)
    assert "requires valid domain credentials" in runner._run_ad_tool("kerberoast", "target")
    assert "domain admin" in runner._run_ad_tool("dcsync", "target")
    assert "valid credentials" in runner._run_ad_tool("psexec", "target")
    assert "valid credentials" in runner._run_ad_tool("wmiexec", "target")


def test_ad_tool_ssh_fallback_import_and_runtime_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Any] = []
    _install_ad_modules(monkeypatch, calls)
    monkeypatch.setattr(runner, "credential_material_for_execution", _material_for)
    ssh = _credential(service="ssh", username="bob@example.test")
    monkeypatch.setattr(
        runner,
        "get_best_credential_ref",
        lambda _target, service: None if service == "ldap" else ssh,
    )
    assert runner._run_ad_tool("enum", "target") == "enum-ok"

    original_import = builtins.__import__

    def fail_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.killchain.ad.enumeration":
            raise ImportError("missing ad")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_import)
    assert "dependency missing" in runner._run_ad_tool("enum", "target")
    monkeypatch.setattr(builtins, "__import__", original_import)
    monkeypatch.setattr(
        runner,
        "get_best_credential_ref",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("credential store")),
    )
    assert "failed (RuntimeError)" in runner._run_ad_tool("enum", "target")


class _SSHClient:
    def __init__(self, *, connect_error: BaseException | None = None) -> None:
        self.connect_error = connect_error
        self.calls: list[Any] = []
        self.closed = False

    def set_missing_host_key_policy(self, policy) -> None:
        self.calls.append(("policy", policy))

    def connect(self, target: str, **kwargs: Any) -> None:
        self.calls.append(("connect", target, kwargs))
        if self.connect_error is not None:
            raise self.connect_error

    def close(self) -> None:
        self.closed = True


def _install_pivot_modules(
    monkeypatch: pytest.MonkeyPatch,
    ssh: _SSHClient,
    calls: list[Any],
) -> None:
    paramiko = types.ModuleType("paramiko")
    paramiko.SSHClient = lambda: ssh
    paramiko.AutoAddPolicy = lambda: "auto-policy"
    pivot = types.ModuleType("core.killchain.pivot")
    pivot.setup_socks_proxy = lambda client, local_port: calls.append(("socks", client, local_port)) or "socks-ok"
    pivot.setup_local_forward = lambda client, local, remote_host, remote: (
        calls.append(("forward", client, local, remote_host, remote)) or "forward-ok"
    )
    pivot.get_network_info = lambda client: calls.append(("netinfo", client)) or "netinfo-ok"
    monkeypatch.setitem(sys.modules, "paramiko", paramiko)
    monkeypatch.setitem(sys.modules, "core.killchain.pivot", pivot)


def test_pivot_tool_all_actions_are_fully_fake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Any] = []
    ssh = _SSHClient()
    _install_pivot_modules(monkeypatch, ssh, calls)
    credential = _credential(service="ssh", username="alice", port=0)
    monkeypatch.setattr(runner, "get_best_credential_ref", lambda *_args: credential)
    monkeypatch.setattr(runner, "credential_material_for_execution", _material_for)

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "")
    assert runner._run_pivot_tool("socks", "target") == "socks-ok"
    assert calls[-1][2] == 1080

    forward_inputs = iter(["9000", "internal.test", "443"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(forward_inputs))
    assert runner._run_pivot_tool("forward", "target") == "forward-ok"
    assert calls[-1][2:] == (9000, "internal.test", 443)

    assert runner._run_pivot_tool("netinfo", "target") == "netinfo-ok"
    assert "Unknown pivot action" in runner._run_pivot_tool("unknown", "target")
    assert ssh.closed
    connect = next(item for item in ssh.calls if item[0] == "connect")
    assert connect[2]["port"] == 22
    assert connect[2]["password"] == "secret"

    explicit_ssh = _SSHClient()
    _install_pivot_modules(monkeypatch, explicit_ssh, calls)
    explicit = _credential(service="ssh", username="alice", port=2222)
    monkeypatch.setattr(runner, "get_best_credential_ref", lambda *_args: explicit)
    assert runner._run_pivot_tool("netinfo", "target") == "netinfo-ok"
    assert next(item for item in explicit_ssh.calls if item[0] == "connect")[2]["port"] == 2222


def test_pivot_tool_missing_dependency_credentials_and_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "get_best_credential_ref", lambda *_args: None)
    assert "requires SSH credentials" in runner._run_pivot_tool("socks", "target")

    credential = _credential(service="ssh")
    monkeypatch.setattr(runner, "get_best_credential_ref", lambda *_args: credential)
    original_import = builtins.__import__

    def fail_paramiko(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "paramiko":
            raise ImportError("missing paramiko")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_paramiko)
    assert "paramiko not installed" in runner._run_pivot_tool("socks", "target")
    monkeypatch.setattr(builtins, "__import__", original_import)

    failing = _SSHClient(connect_error=RuntimeError("connect failed"))
    _install_pivot_modules(monkeypatch, failing, [])
    monkeypatch.setattr(runner, "credential_material_for_execution", _material_for)
    assert "failed (RuntimeError)" in runner._run_pivot_tool("socks", "target")


def _install_c2_modules(monkeypatch: pytest.MonkeyPatch, calls: list[Any]) -> None:
    builder = types.ModuleType("core.c2.builder")
    builder.build_implant = lambda **kwargs: calls.append(("go", kwargs)) or "go-ok"
    python_implant = types.ModuleType("core.c2.implants.python_implant")
    python_implant.generate_python_implant = lambda **kwargs: calls.append(("python", kwargs)) or "print('implant')"
    powershell = types.ModuleType("core.c2.implants.powershell_stager")
    powershell.generate_ps_encoded = lambda url: calls.append(("ps-encoded", url)) or "encoded-code"
    powershell.generate_ps_stager = lambda url, method: calls.append(("ps-iex", url, method)) or "iex-code"
    dns = types.ModuleType("core.c2.channels.dns")

    class DNSChannel:
        def __init__(self, domain: str) -> None:
            calls.append(("dns", domain))

    dns.DNSChannel = DNSChannel
    monkeypatch.setitem(sys.modules, builder.__name__, builder)
    monkeypatch.setitem(sys.modules, python_implant.__name__, python_implant)
    monkeypatch.setitem(sys.modules, powershell.__name__, powershell)
    monkeypatch.setitem(sys.modules, dns.__name__, dns)


def test_c2_build_all_types_without_writing_real_artifacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Any] = []
    _install_c2_modules(monkeypatch, calls)
    opened = mock_open()
    monkeypatch.setattr(builtins, "open", opened)
    monkeypatch.setattr(runner.os, "makedirs", lambda *_args, **_kwargs: None)

    inputs = iter(["", "", ""])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(inputs))
    assert runner._run_c2_build("go", "10.0.0.1") == "go-ok"
    assert calls[-1][1] == {
        "c2_urls": ["http://127.0.0.1:8443"],
        "os_target": "linux",
        "arch_target": "amd64",
    }

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "https://c2.test")
    python_result = runner._run_c2_build("python", "10.0.0.1")
    assert "Python implant generated" in python_result
    assert opened().write.called

    ps_inputs = iter(["https://c2.test", "encoded"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(ps_inputs))
    assert "PowerShell stager generated" in runner._run_c2_build("powershell", "10.0.0.1")
    assert ("ps-encoded", "https://c2.test") in calls

    ps_default = iter(["", ""])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(ps_default))
    runner._run_c2_build("powershell", "10.0.0.1")
    assert ("ps-iex", "http://127.0.0.1:8443", "iex") in calls

    dns_blank = iter(["", ""])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(dns_blank))
    assert "requires a domain" in runner._run_c2_build("dns", "target")
    dns_value = iter(["https://c2.test", "c2.example.test"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(dns_value))
    assert "configured for: c2.example.test" in runner._run_c2_build("dns", "target")
    assert ("dns", "c2.example.test") in calls

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "https://c2.test")
    assert "Unknown build type" in runner._run_c2_build("unknown", "target")


def test_c2_build_import_and_runtime_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__
    monkeypatch.setattr(builtins, "input", lambda _prompt="": "https://c2.test")

    def fail_builder(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.c2.builder":
            raise ImportError("missing builder")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_builder)
    assert "dependency missing" in runner._run_c2_build("go", "target")
    monkeypatch.setattr(builtins, "__import__", original_import)
    monkeypatch.setattr(
        builtins,
        "input",
        lambda _prompt="": (_ for _ in ()).throw(RuntimeError("input failed")),
    )
    assert "C2 build failed: input failed" in runner._run_c2_build("go", "target")


def test_module_main_guard_uses_stubbed_registered_recon(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from core.tools.registry import get_tool

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "example.test")
    for tool_name in runner._DEFAULT_RECON_TOOL_NAMES:
        tool_def = get_tool(tool_name)
        assert tool_def is not None
        monkeypatch.setattr(tool_def, "requires", [])
        monkeypatch.setattr(
            tool_def,
            "func",
            lambda target, _name=tool_name: f"{_name}:{target}",
        )

    runpy.run_path(str(Path(runner.__file__)), run_name="__main__")

    output = capsys.readouterr().out
    assert "NMAP OUTPUT" in output
    assert "nmap:example.test" in output
