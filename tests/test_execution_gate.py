"""Regression tests for the typed execution and managed-shell boundary."""

import pytest

pytestmark = pytest.mark.security


def test_unknown_tool_fails_closed_without_running_binary(monkeypatch):
    import subprocess

    from core.tools.runner import run_tool_by_command

    called = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: called.append(args))

    result = run_tool_by_command("octopus_not_a_real_tool --version")

    assert "Execution denied" in result
    assert "unknown_tool:octopus_not_a_real_tool" in result
    assert called == []


def test_automatic_shell_syntax_is_denied():
    from core.execution import ExecutionContext
    from core.tools.runner import run_arbitrary_cmd

    context = ExecutionContext.automatic(
        ("127.0.0.1",), actor="test-ai", origin="ai_pipeline"
    )

    result = run_arbitrary_cmd("printf octopus | tr a-z A-Z", context)

    assert "Execution denied" in str(result)
    assert "shell_origin_not_interactive" in str(result)


def test_managed_shell_requires_explicit_approval():
    from core.execution import CAP_MANAGED_SHELL, ExecutionContext
    from core.tools.runner import run_managed_shell

    context = ExecutionContext(
        actor="operator",
        origin="operator",
        capabilities=frozenset({CAP_MANAGED_SHELL}),
        approved=False,
    )

    result = run_managed_shell("printf octopus", context)

    assert result.exit_code == -1
    assert "shell_requires_approval" in result.stdout


def test_approved_managed_shell_keeps_pipeline_support():
    from core.execution import ExecutionContext
    from core.tools.runner import run_managed_shell

    context = ExecutionContext.operator(
        actor="test-operator",
        approval_id="approval-test-1",
        allow_shell=True,
        max_runtime_seconds=10,
        max_output_bytes=4096,
    )

    result = run_managed_shell("printf octopus | tr a-z A-Z", context)

    assert result.exit_code == 0
    assert result.stdout == "OCTOPUS"


def test_managed_shell_enforces_scope_across_shell_separators():
    from core.execution import ExecutionContext
    from core.tools.runner import run_managed_shell

    context = ExecutionContext.operator(
        actor="test-operator",
        approval_id="approval-test-scope",
        target_scope=("10.0.0.5",),
        allow_shell=True,
    )

    result = run_managed_shell("printf ok; curl http://10.0.0.6", context)

    assert result.exit_code == -1
    assert "target_out_of_scope:http://10.0.0.6" in result.stdout


def test_managed_shell_requires_separate_destructive_capability():
    from core.execution import ExecutionContext
    from core.tools.runner import run_managed_shell

    context = ExecutionContext.operator(
        actor="test-operator",
        approval_id="approval-test-safe-shell",
        allow_shell=True,
    )

    result = run_managed_shell("/bin/rm /tmp/octopus-never-created", context)

    assert result.exit_code == -1
    assert "destructive_shell_requires_capability" in result.stdout


def test_managed_shell_enforces_output_and_time_limits():
    from core.execution import ExecutionContext
    from core.tools.runner import run_managed_shell

    output_context = ExecutionContext.operator(
        actor="test-operator",
        approval_id="approval-test-output-limit",
        allow_shell=True,
        max_runtime_seconds=10,
        max_output_bytes=1024,
    )
    timeout_context = ExecutionContext.operator(
        actor="test-operator",
        approval_id="approval-test-time-limit",
        allow_shell=True,
        max_runtime_seconds=1,
        max_output_bytes=1024,
    )

    limited = run_managed_shell("python3 -c \"print('x' * 5000)\"", output_context)
    timed_out = run_managed_shell("sleep 2", timeout_context)

    assert limited.exit_code != 0
    assert "OUTPUT LIMIT" in limited.stdout
    assert len(limited.stdout.encode("utf-8")) <= 1024
    assert timed_out.exit_code != 0
    assert "TIMEOUT" in timed_out.stdout
    assert timed_out.duration < 2


def test_registered_tool_is_bound_to_execution_target_scope():
    import core.tools.recon_tools  # noqa: F401 - registers nmap
    from core.execution import ExecutionContext
    from core.tools.registry import get_tool
    from core.tools.runner import run_tool_by_command

    tool_def = get_tool("nmap")
    old_func = tool_def.func
    calls = []

    def fake_nmap(target, extra_flags=None):
        calls.append((target, extra_flags))
        return "ok"

    tool_def.func = fake_nmap
    try:
        context = ExecutionContext.automatic(
            ("10.0.0.5",), actor="scan:test", origin="ai_pipeline"
        )
        denied = run_tool_by_command("nmap -sV 10.0.0.6", context)
        allowed = run_tool_by_command("nmap -sV 10.0.0.5", context)
    finally:
        tool_def.func = old_func

    assert "target_out_of_scope:10.0.0.6" in denied
    assert allowed == "ok"
    assert calls == [("10.0.0.5", ["-sV"])]


def test_target_metacharacters_do_not_reach_registered_tool():
    import core.tools.recon_tools  # noqa: F401 - registers nmap
    from core.execution import ExecutionContext
    from core.tools.registry import get_tool
    from core.tools.runner import run_tool_by_command

    tool_def = get_tool("nmap")
    old_func = tool_def.func
    called = []

    def fake_nmap(target, extra_flags=None):
        called.append((target, extra_flags))
        return "unsafe"

    tool_def.func = fake_nmap
    try:
        context = ExecutionContext.automatic(
            ("10.0.0.5",), actor="scan:test", origin="ai_pipeline"
        )
        result = run_tool_by_command("nmap '10.0.0.5;touch'", context)
    finally:
        tool_def.func = old_func

    assert "invalid_target" in result
    assert called == []


def test_url_query_is_passed_as_one_typed_argument_not_shell_syntax():
    import core.tools.recon_tools  # noqa: F401 - registers curl_headers
    from core.execution import ExecutionContext
    from core.tools.registry import get_tool
    from core.tools.runner import run_tool_by_command

    tool_def = get_tool("curl_headers")
    old_func = tool_def.func
    captured = []
    tool_def.func = lambda target: captured.append(target) or "ok"
    try:
        context = ExecutionContext.automatic(
            ("app.example.com",), actor="scan:test", origin="ai_pipeline"
        )
        result = run_tool_by_command(
            "curl_headers 'https://app.example.com/?x=1&y=2'", context
        )
    finally:
        tool_def.func = old_func

    assert result == "ok"
    assert captured == ["https://app.example.com/?x=1&y=2"]


def test_registered_dispatch_preserves_ipv6_target():
    import core.tools.recon_tools  # noqa: F401 - registers nmap
    from core.execution import ExecutionContext
    from core.tools.registry import get_tool
    from core.tools.runner import run_tool_by_command

    tool_def = get_tool("nmap")
    old_func = tool_def.func
    captured = []

    def fake_nmap(target, extra_flags=None):
        captured.append(target)
        return "ok"

    tool_def.func = fake_nmap
    try:
        context = ExecutionContext.automatic(
            ("2001:db8::1",), actor="scan:test", origin="ai_pipeline"
        )
        result = run_tool_by_command("nmap 2001:db8::1", context)
    finally:
        tool_def.func = old_func

    assert result == "ok"
    assert captured == ["2001:db8::1"]


def test_registered_dispatch_extracts_targets_from_legacy_cli_flags():
    import core.tools.recon_tools  # noqa: F401 - registers tools
    from core.execution import ExecutionContext
    from core.tools.registry import get_tool
    from core.tools.runner import run_tool_by_command

    captured = []
    curl_def = get_tool("curl_headers")
    enum_def = get_tool("enum4linux")
    old_curl = curl_def.func
    old_enum = enum_def.func
    curl_def.func = lambda target: captured.append(("curl", target)) or "curl-ok"
    enum_def.func = lambda target: captured.append(("enum", target)) or "enum-ok"
    try:
        context = ExecutionContext.automatic(
            ("10.0.0.5",), actor="scan:test", origin="ai_pipeline"
        )
        curl_result = run_tool_by_command("curl -sL http://10.0.0.5/login", context)
        enum_result = run_tool_by_command("enum4linux -a 10.0.0.5", context)
    finally:
        curl_def.func = old_curl
        enum_def.func = old_enum

    assert curl_result == "curl-ok"
    assert enum_result == "enum-ok"
    assert captured == [
        ("curl", "http://10.0.0.5/login"),
        ("enum", "10.0.0.5"),
    ]


def test_active_registered_tool_needs_capability_and_approval():
    import core.tools.post_tools  # noqa: F401 - registers killchain tool
    from core.execution import ExecutionContext
    from core.tools.registry import get_tool
    from core.tools.runner import run_tool_by_command

    tool_def = get_tool("killchain_privesc")
    old_func = tool_def.func
    calls = []
    tool_def.func = lambda target_ip, user=None, pwd=None: calls.append(target_ip) or "ok"
    try:
        automatic = ExecutionContext.automatic(
            ("10.0.0.5",), actor="scan:test", origin="ai_pipeline"
        )
        operator = ExecutionContext.operator(
            actor="test-operator",
            approval_id="approval-active-1",
            target_scope=("10.0.0.5",),
            allow_active_tools=True,
        )
        denied = run_tool_by_command("killchain_privesc 10.0.0.5", automatic)
        allowed = run_tool_by_command("killchain_privesc 10.0.0.5", operator)
    finally:
        tool_def.func = old_func

    assert "active_tool_requires_approval" in denied
    assert allowed == "ok"
    assert calls == ["10.0.0.5"]


def test_ai_cannot_bypass_active_gate_through_numeric_menu():
    import core.tools.runner as runner

    old_entry = runner.TOOLS_MENU["20"]
    calls = []
    runner.TOOLS_MENU["20"] = (
        "auto exploit",
        lambda target: calls.append(target) or "unsafe",
    )
    try:
        denied = runner.run_single_tool("20", "10.0.0.5")
    finally:
        runner.TOOLS_MENU["20"] = old_entry

    assert "active_tool_requires_approval" in denied
    assert calls == []


def test_scheduler_records_auditable_policy_denial():
    from core.ai.command_scheduler import CommandScheduler
    from core.execution import ExecutionContext

    context = ExecutionContext.automatic(
        ("10.0.0.5",), actor="scan:test", origin="ai_pipeline"
    )

    decision = CommandScheduler().decide(
        "nmap 10.0.0.6", [], set(), execution_context=context
    )
    payload = decision.to_dict()

    assert decision.action == "skip"
    assert decision.reason == "policy_denied:target_out_of_scope:10.0.0.6"
    assert payload["policy"]["action"] == "deny"
    assert payload["policy"]["actor"] == "scan:test"
    assert payload["policy"]["origin"] == "ai_pipeline"
    assert payload["policy"]["request_id"] == context.request_id


def test_scheduler_audit_redacts_positional_and_named_secrets():
    from core.ai.command_scheduler import CommandDecision

    positional = CommandDecision(
        "ssh_session 10.0.0.5 admin super-secret", "key", "execute", "test"
    ).to_dict()
    named = CommandDecision(
        "msf_check 10.0.0.5 module PASSWORD=super-secret API_KEY=key-value",
        "key",
        "execute",
        "test",
    ).to_dict()

    assert "super-secret" not in positional["command"]
    assert "super-secret" not in named["command"]
    assert "key-value" not in named["command"]
    assert "[REDACTED]" in positional["command"]
    assert "[REDACTED]" in named["command"]


def test_invalid_scope_fails_closed_instead_of_crashing_policy():
    from core.ai.command_scheduler import CommandScheduler
    from core.execution import ExecutionContext

    context = ExecutionContext.automatic(
        ("/tmp/not-a-network-scope",), actor="scan:test", origin="ai_pipeline"
    )

    decision = CommandScheduler().decide(
        "nmap 10.0.0.5", [], set(), execution_context=context
    )

    assert decision.action == "skip"
    assert decision.reason == "policy_denied:target_out_of_scope:10.0.0.5"


def test_python_repl_is_no_longer_available_to_automatic_callers():
    from core.tools.runner import run_python_repl

    result = run_python_repl("print('should-not-run')")

    assert "Execution denied" in result
    assert "python_repl_origin_not_interactive" in result


def test_pipeline_persists_redacted_command_metadata():
    import uuid

    import core.ai.pipeline as pipeline_module
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_module.run_arbitrary_cmd
    pipeline_module.run_arbitrary_cmd = lambda _command: "[*] Check completed safely"
    try:
        pipeline = AIPipeline(f"/tmp/octopus_redaction_{uuid.uuid4().hex}.db")
        result = pipeline._execute_pipeline_command(
            "scan-redaction",
            "10.0.0.5",
            "msf_check 10.0.0.5 module PASSWORD=super-secret",
            "Fact",
            "[Running]",
        )
    finally:
        pipeline_module.run_arbitrary_cmd = old_runner

    serialized = str(result) + str(pipeline.command_trace)
    assert "super-secret" not in serialized
    assert "PASSWORD=[REDACTED]" in serialized
