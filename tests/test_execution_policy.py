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
    contains_sensitive_command_material,
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
    value = redact_sensitive_command('tool --token value {"password": "json-value"} API_KEY=named-value')

    assert "value" not in value.replace("[REDACTED]", "")
    assert value.count("[REDACTED]") == 3
    assert redact_sensitive_command("tool 'unterminated PASSWORD=value").endswith("PASSWORD=[REDACTED]")


@pytest.mark.parametrize(
    "command",
    [
        "PASSWORD=canary command",
        "curl --user alice:canary https://example.test",
        "docker login --password-stdin registry.example.test",
        "mysql -pcanary database",
        "redis-cli -a canary ping",
        "ssh -i /tmp/private-key alice@example.test",
        "sshpass -p canary ssh alice@example.test",
        "tool --token canary",
        "tool secret://opaque-reference",
        "https://alice:canary@example.test/path",
        "printf '-----BEGIN PRIVATE KEY-----'",
    ],
)
def test_sensitive_command_detector_rejects_shell_credential_forms(command):
    assert contains_sensitive_command_material(command)


@pytest.mark.parametrize(
    "command",
    [
        "curl --head https://example.test",
        "docker run -p 8080:80 example/image",
        "echo password rotation required",
        "mysql --host database.example.test",
        "ssh alice@example.test",
    ],
)
def test_sensitive_command_detector_preserves_secret_free_shell_forms(command):
    assert not contains_sensitive_command_material(command)


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
    invocation = parse_invocation("tool https://example.com/a https://example.com/a 10.0.0.5 | next")

    assert invocation.uses_shell
    assert invocation.targets == ("https://example.com/a", "10.0.0.5")
    assert parse_invocation("/bin/echo ok", allow_executable_path=True).executable == "/bin/echo"


def test_registered_single_label_target_is_bound_by_callable_contract_and_scoped():
    policy = ExecutionPolicy()
    in_scope = _context(CAP_REGISTERED_TOOL, scope=("intranet",))
    out_of_scope = _context(CAP_REGISTERED_TOOL, scope=("approved.example",))

    allowed = policy.authorize_command("nmap intranet", in_scope)
    denied = policy.authorize_command("nmap intranet", out_of_scope)

    assert allowed.allowed is True
    assert allowed.invocation is not None
    assert allowed.invocation.targets == ("intranet",)
    assert denied.allowed is False
    assert denied.reason == "target_out_of_scope:intranet"
    assert denied.invocation is not None
    assert denied.invocation.targets == ("intranet",)


def test_registered_signature_target_cannot_be_shadowed_by_network_like_argument():
    policy = ExecutionPolicy()
    context = _context(
        CAP_REGISTERED_TOOL,
        CAP_ACTIVE_TOOL,
        scope=("approved.example",),
        approved=True,
    )

    decision = policy.authorize_command(
        "bruteforce approved.example intranet",
        context,
    )

    assert decision.allowed is False
    assert decision.reason == "target_out_of_scope:intranet"
    assert decision.invocation is not None
    assert decision.invocation.targets == ("intranet",)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("nmap -Pn approved.example intranet", "intranet"),
        ("rustscan -a intranet", "intranet"),
        ("curl_headers -H approved.example https://intranet", "https://intranet"),
        ("nikto -output approved.example -h intranet", "intranet"),
        ("sqlmap --proxy approved.example -u http://intranet", "http://intranet"),
        ("wpscan --api-token approved.example --url http://intranet", "http://intranet"),
    ],
)
def test_registered_flag_grammars_authorize_the_dispatched_target(command, expected):
    policy = ExecutionPolicy()
    context = _context(CAP_REGISTERED_TOOL, scope=("approved.example",))

    decision = policy.authorize_command(command, context)

    assert decision.allowed is False
    assert decision.reason == f"target_out_of_scope:{expected}"
    assert decision.invocation is not None
    assert decision.invocation.targets[0] == expected


def test_registered_network_tool_without_a_typed_target_fails_closed():
    policy = ExecutionPolicy()
    context = _context(CAP_REGISTERED_TOOL, scope=("intranet",))

    command_decision = policy.authorize_command("nmap", context)
    direct_decision = policy.authorize_registered(
        _invocation("nmap", targets=(), argv=("nmap",)),
        context,
    )

    assert command_decision.reason == "missing_explicit_target"
    assert direct_decision.reason == "missing_explicit_target"


def test_registered_network_tool_requires_nonempty_scope_and_checks_secondary_host():
    policy = ExecutionPolicy()
    no_scope = _context(CAP_REGISTERED_TOOL)

    assert policy.authorize_command("nmap intranet", no_scope).reason == ("missing_target_scope")

    scoped = _context(
        CAP_REGISTERED_TOOL,
        CAP_ACTIVE_TOOL,
        scope=("approved.example",),
        approved=True,
    )
    decision = policy.authorize_command(
        "port_forward approved.example 8080 intranet 80",
        scoped,
    )

    assert decision.allowed is False
    assert decision.reason == "target_out_of_scope:intranet"
    assert decision.invocation is not None
    assert decision.invocation.targets == ("approved.example", "intranet")


@pytest.mark.parametrize(
    "command",
    [
        "nmap outside.example inside.example",
        "rustscan -a inside.example -- outside.example",
        "msf_check inside.example exploit/example RHOSTS=outside.example",
    ],
)
def test_registered_options_cannot_smuggle_secondary_targets(command):
    policy = ExecutionPolicy()
    context = _context(
        CAP_REGISTERED_TOOL,
        CAP_ACTIVE_TOOL,
        scope=("inside.example",),
        approved=True,
    )

    decision = policy.authorize_command(command, context)

    assert decision.allowed is False
    assert decision.reason == "target_out_of_scope:outside.example"


@pytest.mark.parametrize(
    "command",
    [
        "build_go_implant https://c2.example:9443",
        "build_python_implant https://c2.example:9443",
        "build_ps_stager https://c2.example:9443",
        "shodan outside.example",
    ],
)
def test_nonstandard_network_parameters_require_explicit_scope(command):
    decision = ExecutionPolicy().authorize_command(
        command,
        _context(CAP_REGISTERED_TOOL, CAP_ACTIVE_TOOL, approved=True),
    )

    assert decision.allowed is False
    assert decision.reason == "missing_target_scope"


def test_parse_invocation_rejects_empty_tokenization(monkeypatch):
    import core.execution.policy as policy_module

    monkeypatch.setattr(policy_module.shlex, "split", lambda *_args, **_kwargs: [])

    with pytest.raises(InvalidInvocation, match="empty_command"):
        parse_invocation("nonempty")


def test_registered_policy_covers_limits_capabilities_special_actions_and_local_tools():
    policy = ExecutionPolicy()
    normal = _invocation()

    assert (
        policy.authorize_registered(normal, _context(CAP_REGISTERED_TOOL, max_runtime_seconds=0)).reason
        == "invalid_resource_limits"
    )
    assert policy.authorize_registered(normal, _context()).reason == "missing_capability:registered_tool"
    assert policy.authorize_registered(
        _invocation(targets=("bad target",)), _context(CAP_REGISTERED_TOOL)
    ).reason.startswith("invalid_nmap_target:")

    plugin_scan = _invocation(
        "plugin",
        argv=("plugin", "demo", "10.0.0.5", "scan"),
    )
    plugin_run = _invocation(
        "plugin",
        argv=("plugin", "demo", "10.0.0.5", "run"),
    )
    sqlmap = _invocation("sqlmap")
    automatic = _context(CAP_REGISTERED_TOOL, scope=("10.0.0.5",))

    assert policy.authorize_registered(plugin_scan, automatic).allowed
    assert policy.authorize_registered(plugin_run, automatic).reason == "active_tool_requires_approval"
    assert policy.authorize_registered(sqlmap, automatic).reason == "active_tool_requires_approval"
    assert policy.authorize_registered(
        sqlmap,
        _context(
            CAP_REGISTERED_TOOL,
            CAP_ACTIVE_TOOL,
            scope=("10.0.0.5",),
            approved=True,
        ),
    ).allowed
    assert policy.authorize_registered(
        _invocation("prowler_scan", targets=("not a network target",)), automatic
    ).allowed


@pytest.mark.parametrize("gateway", ["plugin", "run_plugin", "octopus_plugin"])
def test_plugin_inventory_gateway_is_targetless_read_only(gateway: str) -> None:
    invocation = ToolInvocation(
        executable=gateway,
        argv=(gateway, "list"),
        raw_command=f"{gateway} list",
        registered_name="plugin",
        targets=(),
    )

    decision = ExecutionPolicy().authorize_registered(
        invocation,
        _context(CAP_REGISTERED_TOOL),
    )

    assert decision.allowed is True
    assert decision.reason == "registered_tool_authorized"
    assert decision.invocation is not None
    assert decision.invocation.targets == ()


def test_registered_policy_rejects_forged_and_mismatched_registry_identity():
    policy = ExecutionPolicy()
    context = _context(CAP_REGISTERED_TOOL)
    unknown = _invocation("totally_fake_registered_tool", targets=())
    mismatched = ToolInvocation(
        executable="nmap",
        argv=("nmap", "10.0.0.5"),
        raw_command="nmap 10.0.0.5",
        registered_name="whois",
        targets=("10.0.0.5",),
    )

    assert policy.authorize_registered(unknown, context).reason == (
        "unknown_registered_tool:totally_fake_registered_tool"
    )
    assert policy.authorize_registered(mismatched, context).reason == ("registered_tool_mismatch")


def test_direct_policy_is_disabled_and_capability_gated():
    policy = ExecutionPolicy()
    invocation = ToolInvocation(
        executable="rustscan",
        argv=("rustscan", "-a", "10.0.0.5"),
        raw_command="rustscan -a 10.0.0.5",
        targets=("10.0.0.5",),
    )

    assert (
        policy.authorize_direct(invocation, _context(CAP_DIRECT_BINARY, max_output_bytes=1)).reason
        == "invalid_resource_limits"
    )
    assert policy.authorize_direct(invocation, _context()).reason == "missing_capability:direct_binary"
    assert (
        policy.authorize_direct(invocation, _context(CAP_DIRECT_BINARY, scope=("10.0.0.5",))).reason
        == "unknown_tool:rustscan"
    )
    unknown = ToolInvocation("unknown", ("unknown",), "unknown")
    assert policy.authorize_direct(unknown, _context(CAP_DIRECT_BINARY)).reason == "unknown_tool:unknown"


def test_shell_policy_covers_every_authority_gate_without_execution():
    policy = ExecutionPolicy()

    assert policy.authorize_shell("echo 'unterminated", _context()).reason == "invalid_quoting"
    assert (
        policy.authorize_shell("echo ok", _context(CAP_MANAGED_SHELL, origin="operator", max_runtime_seconds=0)).reason
        == "invalid_resource_limits"
    )
    assert policy.authorize_shell("echo ok", _context(CAP_MANAGED_SHELL)).reason == "shell_origin_not_interactive"
    assert policy.authorize_shell("echo ok", _context(origin="operator")).reason == "missing_capability:managed_shell"
    assert (
        policy.authorize_shell("echo ok", _context(CAP_MANAGED_SHELL, origin="operator")).reason
        == "shell_requires_approval"
    )
    destructive = _context(
        CAP_MANAGED_SHELL,
        CAP_DESTRUCTIVE_SHELL,
        origin="operator",
        approved=True,
    )
    assert policy.authorize_shell("/bin/rm /tmp/example", destructive).allowed


def test_shell_policy_denies_credentials_before_the_managed_shell_boundary():
    policy = ExecutionPolicy()
    context = _context(CAP_MANAGED_SHELL, origin="operator", approved=True)

    decision = policy.authorize_shell(
        "curl --user alice:credential-canary https://example.test",
        context,
    )

    assert not decision.allowed
    assert decision.reason == "credential_material_forbidden_in_managed_shell"
    assert "credential-canary" not in str(decision.to_dict())


def test_shell_policy_fails_closed_when_shell_target_lexer_fails(monkeypatch):
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

    decision = policy_module.ExecutionPolicy().authorize_shell("echo ok", context)

    assert not decision.allowed
    assert decision.reason == "invalid_remote_command_quoting"


def test_python_repl_policy_covers_every_authority_gate():
    policy = ExecutionPolicy()

    assert (
        policy.authorize_python_repl(
            "print(1)", _context(CAP_PYTHON_REPL, origin="operator", max_output_bytes=1)
        ).reason
        == "invalid_resource_limits"
    )
    assert (
        policy.authorize_python_repl("print(1)", _context(CAP_PYTHON_REPL)).reason
        == "python_repl_origin_not_interactive"
    )
    assert (
        policy.authorize_python_repl("print(1)", _context(origin="operator")).reason == "missing_capability:python_repl"
    )
    assert (
        policy.authorize_python_repl("print(1)", _context(CAP_PYTHON_REPL, origin="operator")).reason
        == "python_repl_requires_approval"
    )
    assert policy.authorize_python_repl("print(1)", _context(CAP_PYTHON_REPL, origin="operator", approved=True)).allowed


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
    assert policy.authorize_command(
        "rustscan -a 10.0.0.5",
        _context(CAP_REGISTERED_TOOL, scope=("10.0.0.5",)),
    ).allowed
    assert policy.authorize_command("unknown", automatic).reason == "unknown_tool:unknown"
    assert policy.authorize_command("unknown | next", automatic).reason == "shell_origin_not_interactive"
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
