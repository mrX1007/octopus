"""Branch-level tests for execution context, parsing, and authorization policy."""

import pytest

from core.execution import (
    CAP_ACTIVE_TOOL,
    CAP_DESTRUCTIVE_SHELL,
    CAP_DIRECT_BINARY,
    CAP_MANAGED_SHELL,
    CAP_PYTHON_REPL,
    CAP_REGISTERED_TOOL,
    ExecutionContext,
    ExecutionPolicy,
    ToolInvocation,
    bind_execution_context,
    current_execution_context,
    redact_sensitive_command,
    validate_target,
)
from core.execution.policy import (
    InvalidInvocation,
    _scope_matches,
    extract_network_targets,
    parse_invocation,
)

pytestmark = pytest.mark.security


def _context(*capabilities, scope=(), approved=False, origin="automation", **limits):
    return ExecutionContext(
        actor="policy-test",
        origin=origin,
        target_scope=tuple(scope),
        capabilities=frozenset(capabilities),
        approved=approved,
        approval_id="approval-test" if approved else "",
        **limits,
    )


def _invocation(name="nmap", targets=("10.0.0.5",), argv=None):
    argv = tuple(argv or (name, *targets))
    return ToolInvocation(
        executable=name,
        argv=argv,
        raw_command=" ".join(argv),
        registered_name=name,
        targets=tuple(targets),
    )


def test_operator_context_builds_all_explicit_capabilities_and_binds():
    context = ExecutionContext.operator(
        actor="operator-test",
        approval_id="approval-all",
        target_scope=("10.0.0.5",),
        allow_active_tools=True,
        allow_shell=True,
        allow_destructive_shell=True,
        allow_python_repl=True,
    )

    assert context.approved
    assert context.has(CAP_REGISTERED_TOOL)
    assert context.has(CAP_DIRECT_BINARY)
    assert context.has(CAP_ACTIVE_TOOL)
    assert context.has(CAP_MANAGED_SHELL)
    assert context.has(CAP_DESTRUCTIVE_SHELL)
    assert context.has(CAP_PYTHON_REPL)
    with bind_execution_context(context) as bound:
        assert bound is context
        assert current_execution_context() is context
    assert current_execution_context().origin == "legacy_automation"


def test_redactor_handles_json_flags_and_malformed_shell_text():
    value = redact_sensitive_command(
        'tool --token value {"password": "json-value"} API_KEY=named-value'
    )

    assert "value" not in value.replace("[REDACTED]", "")
    assert value.count("[REDACTED]") == 3
    assert redact_sensitive_command("tool 'unterminated PASSWORD=value").endswith(
        "PASSWORD=[REDACTED]"
    )


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.5",
        "10.0.0.0/24",
        "2001:db8::1",
        "https://app.example.com:8443/path?q=1",
        "localhost",
        "host.internal:443",
    ],
)
def test_validate_target_accepts_supported_forms(target):
    assert validate_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "",
        "host name",
        "gopher://example.com",
        "http://user:pass@example.com",
        "http://example.com:invalid",
        "http://",
        "-invalid.example.com",
        "host\nname",
        "x" * 2049,
    ],
)
def test_validate_target_rejects_ambiguous_or_unsafe_forms(target):
    assert not validate_target(target)


def test_target_helpers_reject_invalid_idn_empty_scope_and_non_cidr_path():
    assert not validate_target("http://\ud800.example")
    assert not _scope_matches("10.0.0.5", "")
    assert extract_network_targets(["path/not-a-cidr"]) == ()
    assert extract_network_targets(["10.0.0.0/24", "example.com:8443"]) == (
        "10.0.0.0/24",
        "example.com:8443",
    )


def test_scope_matching_supports_wildcards_cidrs_networks_and_ports():
    assert _scope_matches("api.example.com", "*.example.com")
    assert not _scope_matches("example.com", "*.example.com")
    assert _scope_matches("10.0.0.9", "10.0.0.0/24")
    assert not _scope_matches("host.example", "10.0.0.0/24")
    assert _scope_matches("10.0.0.0/24", "10.0.0.0/24")
    assert not _scope_matches("10.0.0.0/24", "10.0.0.5")
    assert _scope_matches("https://example.com:8443/a", "example.com:8443")
    assert not _scope_matches("https://example.com:443/a", "example.com:8443")
    assert not _scope_matches("other.example", "example.com")


@pytest.mark.parametrize(
    "command,reason",
    [
        ("", "empty_command"),
        ("x" * 65_537, "command_too_long"),
        ("echo\x00x", "nul_byte"),
        ("echo 'unterminated", "invalid_quoting"),
        ("/bin/echo ok", "executable_path_not_allowed"),
        (". ok", "executable_path_not_allowed"),
    ],
)
def test_parse_invocation_rejects_untyped_commands(command, reason):
    with pytest.raises(InvalidInvocation, match=reason):
        parse_invocation(command)


def test_parse_invocation_marks_shell_and_extracts_unique_targets():
    invocation = parse_invocation(
        "tool https://example.com/a https://example.com/a 10.0.0.5 | next"
    )

    assert invocation.uses_shell
    assert invocation.targets == ("https://example.com/a", "10.0.0.5")
    assert parse_invocation("/bin/echo ok", allow_executable_path=True).executable == "/bin/echo"


def test_parse_invocation_rejects_empty_tokenization(monkeypatch):
    import core.execution.policy as policy_module

    monkeypatch.setattr(policy_module.shlex, "split", lambda *_args, **_kwargs: [])

    with pytest.raises(InvalidInvocation, match="empty_command"):
        parse_invocation("nonempty")


def test_registered_policy_covers_limits_capabilities_special_actions_and_local_tools():
    policy = ExecutionPolicy()
    normal = _invocation()

    assert policy.authorize_registered(
        normal, _context(CAP_REGISTERED_TOOL, max_runtime_seconds=0)
    ).reason == "invalid_resource_limits"
    assert policy.authorize_registered(normal, _context()).reason == "missing_capability:registered_tool"
    assert policy.authorize_registered(
        _invocation(targets=("bad target",)), _context(CAP_REGISTERED_TOOL)
    ).reason.startswith("invalid_target:")

    cpanel_scan = _invocation(
        "cpanel_exploit",
        argv=("cpanel_exploit", "10.0.0.5", "scan"),
    )
    cpanel_cmd = _invocation(
        "cpanel_exploit",
        argv=("cpanel_exploit", "10.0.0.5", "cmd"),
    )
    plugin_scan = _invocation(
        "plugin",
        argv=("plugin", "demo", "10.0.0.5", "scan"),
    )
    plugin_exploit = _invocation(
        "plugin",
        argv=("plugin", "demo", "10.0.0.5", "exploit"),
    )
    automatic = _context(CAP_REGISTERED_TOOL, scope=("10.0.0.5",))

    assert policy.authorize_registered(cpanel_scan, automatic).allowed
    assert policy.authorize_registered(cpanel_cmd, automatic).reason == "active_tool_requires_approval"
    assert policy.authorize_registered(plugin_scan, automatic).allowed
    assert policy.authorize_registered(plugin_exploit, automatic).reason == "active_tool_requires_approval"
    assert policy.authorize_registered(
        _invocation("prowler_scan", targets=("not a network target",)), automatic
    ).allowed


def test_direct_policy_is_allowlisted_scoped_and_capability_gated():
    policy = ExecutionPolicy()
    invocation = ToolInvocation(
        executable="rustscan",
        argv=("rustscan", "-a", "10.0.0.5"),
        raw_command="rustscan -a 10.0.0.5",
        targets=("10.0.0.5",),
    )

    assert policy.authorize_direct(
        invocation, _context(CAP_DIRECT_BINARY, max_output_bytes=1)
    ).reason == "invalid_resource_limits"
    assert policy.authorize_direct(invocation, _context()).reason == "missing_capability:direct_binary"
    assert policy.authorize_direct(
        invocation, _context(CAP_DIRECT_BINARY, scope=("10.0.0.6",))
    ).reason.startswith("target_out_of_scope:")
    assert policy.authorize_direct(
        invocation, _context(CAP_DIRECT_BINARY, scope=("10.0.0.5",))
    ).allowed
    unknown = ToolInvocation("unknown", ("unknown",), "unknown")
    assert policy.authorize_direct(
        unknown, _context(CAP_DIRECT_BINARY)
    ).reason == "unknown_tool:unknown"


def test_shell_policy_covers_every_authority_gate_without_execution():
    policy = ExecutionPolicy()

    assert policy.authorize_shell("echo 'unterminated", _context()).reason == "invalid_quoting"
    assert policy.authorize_shell(
        "echo ok", _context(CAP_MANAGED_SHELL, origin="operator", max_runtime_seconds=0)
    ).reason == "invalid_resource_limits"
    assert policy.authorize_shell(
        "echo ok", _context(CAP_MANAGED_SHELL)
    ).reason == "shell_origin_not_interactive"
    assert policy.authorize_shell(
        "echo ok", _context(origin="operator")
    ).reason == "missing_capability:managed_shell"
    assert policy.authorize_shell(
        "echo ok", _context(CAP_MANAGED_SHELL, origin="operator")
    ).reason == "shell_requires_approval"
    destructive = _context(
        CAP_MANAGED_SHELL,
        CAP_DESTRUCTIVE_SHELL,
        origin="operator",
        approved=True,
    )
    assert policy.authorize_shell("/bin/rm /tmp/example", destructive).allowed


def test_shell_policy_falls_back_when_shell_target_lexer_fails(monkeypatch):
    import core.execution.policy as policy_module

    original_shlex = policy_module.shlex.shlex
    calls = []

    def fail_second_lexer(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise ValueError("lexer failure")
        return original_shlex(*args, **kwargs)

    monkeypatch.setattr(policy_module.shlex, "shlex", fail_second_lexer)
    context = _context(CAP_MANAGED_SHELL, origin="operator", approved=True)

    assert policy_module.ExecutionPolicy().authorize_shell("echo ok", context).allowed


def test_python_repl_policy_covers_every_authority_gate():
    policy = ExecutionPolicy()

    assert policy.authorize_python_repl(
        "print(1)", _context(CAP_PYTHON_REPL, origin="operator", max_output_bytes=1)
    ).reason == "invalid_resource_limits"
    assert policy.authorize_python_repl(
        "print(1)", _context(CAP_PYTHON_REPL)
    ).reason == "python_repl_origin_not_interactive"
    assert policy.authorize_python_repl(
        "print(1)", _context(origin="operator")
    ).reason == "missing_capability:python_repl"
    assert policy.authorize_python_repl(
        "print(1)", _context(CAP_PYTHON_REPL, origin="operator")
    ).reason == "python_repl_requires_approval"
    assert policy.authorize_python_repl(
        "print(1)", _context(CAP_PYTHON_REPL, origin="operator", approved=True)
    ).allowed


def test_command_policy_routes_registered_direct_shell_and_parse_failures():
    policy = ExecutionPolicy()
    automatic = _context(
        CAP_REGISTERED_TOOL,
        CAP_DIRECT_BINARY,
        scope=("10.0.0.5",),
    )

    assert policy.authorize_command("echo 'unterminated", automatic).reason == "invalid_quoting"
    assert policy.authorize_command("nmap 10.0.0.5", automatic).allowed
    assert policy.authorize_command("rustscan -a 10.0.0.5", automatic).allowed
    assert policy.authorize_command("unknown", automatic).reason == "unknown_tool:unknown"
    assert policy.authorize_command(
        "unknown | next", automatic
    ).reason == "shell_origin_not_interactive"
    assert policy.authorize_command("jmx2rce scan 10.0.0.5", automatic).allowed


def test_command_policy_fails_closed_when_tool_registry_import_is_unavailable(monkeypatch):
    import builtins

    policy = ExecutionPolicy()
    context = _context(CAP_DIRECT_BINARY)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "core.tools":
            raise ImportError("tool registry unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    assert policy.authorize_command("unknown", context).reason == "unknown_tool:unknown"
