"""Residual branch coverage for fail-closed execution-policy hardening."""

from __future__ import annotations

import builtins
import operator
from types import SimpleNamespace

import pytest

import core.execution.policy as policy_module
from core.execution import CAP_REGISTERED_TOOL, ExecutionContext, ExecutionPolicy, ToolInvocation
from core.execution.policy import (
    InvalidInvocation,
    _command_text_network_targets,
    _declared_network_targets,
    _network_parameter_positions,
    _registered_tool_uses_network_scope,
    _scope_matches,
    _special_registered_targets,
    authorize_final_registered_arguments,
    bind_msf_target_options,
    normalize_host,
    registered_tool_network_parameter_names,
    registered_tool_uses_network_scope,
    remote_command_is_code_owned,
    targets_equivalent,
    validate_host,
    validate_msf_options,
    validate_registered_arguments,
)

pytestmark = [pytest.mark.unit, pytest.mark.security]


def _context(*scope: str) -> ExecutionContext:
    return ExecutionContext(
        actor="policy-hardening-coverage",
        origin="automation",
        target_scope=scope,
        capabilities=frozenset({CAP_REGISTERED_TOOL}),
    )


def test_registry_introspection_covers_typed_local_and_opaque_providers() -> None:
    def typed_provider(target: str, query: str = "") -> None:
        del target, query

    def local_provider(query: str, *, target: str = "") -> None:
        del query, target

    typed = SimpleNamespace(name="typed", func=typed_provider, needs_target=True)
    local = SimpleNamespace(name="local", func=local_provider, needs_target=True)
    opaque = SimpleNamespace(name="opaque", func=operator.attrgetter("peer"), needs_target=True)
    missing_callable = SimpleNamespace(name="opaque", func=None, needs_target=True)
    explicitly_local = SimpleNamespace(name="prowler_scan", func=typed_provider, needs_target=True)

    assert _network_parameter_positions(typed) == (0,)
    assert _network_parameter_positions(local) == ()
    assert _network_parameter_positions(opaque) == ()
    assert _registered_tool_uses_network_scope(typed) is True
    assert _registered_tool_uses_network_scope(local) is False
    assert _registered_tool_uses_network_scope(opaque) is True
    assert _registered_tool_uses_network_scope(missing_callable) is True
    assert _registered_tool_uses_network_scope(explicitly_local) is False

    def two_endpoints(target: str, callback_host: str) -> None:
        del target, callback_host

    endpoint_tool = SimpleNamespace(name="two_endpoints", func=two_endpoints, needs_target=True)
    assert _declared_network_targets(endpoint_tool, ("two_endpoints", "inside", "inside"), 1) == ("inside",)
    assert _declared_network_targets(endpoint_tool, ("two_endpoints", "inside"), 1) == ("inside",)


def test_registry_introspection_wrappers_fail_closed_and_report_typed_names(monkeypatch) -> None:
    assert registered_tool_uses_network_scope("nmap") is True
    assert registered_tool_uses_network_scope("prowler_scan") is False
    assert registered_tool_uses_network_scope("not-a-registered-tool") is True
    assert "target" in registered_tool_network_parameter_names("nmap")
    assert registered_tool_network_parameter_names("prowler_scan") == frozenset()
    assert registered_tool_network_parameter_names("not-a-registered-tool") == frozenset()

    real_import = builtins.__import__

    def reject_tool_registry(name, *args, **kwargs):
        if name == "core.tools":
            raise ImportError("registry unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_tool_registry)
    assert registered_tool_uses_network_scope("nmap") is True
    assert registered_tool_network_parameter_names("nmap") == frozenset()


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        (("-iL", "targets.txt", "inside"), "unsupported_nmap_indirect_target:-iL"),
        (("-Doutside", "inside"), "unsupported_nmap_indirect_target:-Doutside"),
        (("--script-args", "newtargets=outside", "inside"), "unsupported_nmap_newtargets"),
        (("--script-args=newtargets=outside", "inside"), "unsupported_nmap_newtargets"),
        (("--datadir=/tmp/nmap", "inside"), "unsupported_nmap_script_args"),
        (("--script-args", "fixture=value", "inside"), "unsupported_nmap_script_args"),
        (("--script", "custom", "inside"), "unsupported_nmap_script_source"),
        (("--script=custom", "inside"), "unsupported_nmap_script_source"),
        (("--script",), "unsupported_nmap_script_source"),
        (("bad target",), "invalid_nmap_target:bad target"),
    ],
)
def test_nmap_special_target_parser_rejects_indirection(arguments, reason) -> None:
    with pytest.raises(InvalidInvocation, match=reason):
        _special_registered_targets("nmap", arguments)


def test_nmap_special_target_parser_covers_output_values_deduplication_and_empty_input() -> None:
    arguments = (
        "--script",
        "vuln",
        "-p",
        "443",
        "-oX",
        "report.xml",
        "--output=xml",
        "ignored",
        "--ports=80",
        "first.example",
        "first.example",
        "last.example",
    )

    assert _special_registered_targets("nmap", arguments) == ("last.example", "first.example")
    assert _special_registered_targets("nmap", ("-Pn",)) == ()
    assert validate_registered_arguments(" NMAP ", ("inside", "outside")) == ("outside", "inside")
    assert validate_registered_arguments("unknown", ("inside",)) == ()


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        (("--resolver", "outside", "inside"), "unsupported_rustscan_indirection:--resolver"),
        (("-cconfig.toml", "inside"), "unsupported_rustscan_indirection:-cconfig.toml"),
    ],
)
def test_rustscan_special_target_parser_rejects_indirection(arguments, reason) -> None:
    with pytest.raises(InvalidInvocation, match=reason):
        _special_registered_targets("rustscan", arguments)


def test_rustscan_special_target_parser_covers_address_fallback_and_forwarded_targets() -> None:
    assert _special_registered_targets("rustscan", ("-a", "inside", "-a", "outside")) == ("inside",)
    assert _special_registered_targets("rustscan", ("--addresses=inside",)) == ("inside",)
    assert _special_registered_targets(
        "rustscan",
        ("--addresses=inside", "--addresses=outside"),
    ) == ("inside",)
    assert _special_registered_targets("rustscan", ("-p", "80", "fallback")) == ("fallback",)
    assert _special_registered_targets(
        "rustscan",
        ("-a", "inside", "--", "-p", "80", "outside", "inside"),
    ) == ("inside", "outside")
    assert _special_registered_targets("rustscan", ("--", "-Pn")) == ()
    assert _special_registered_targets("rustscan", ("--addresses=bad target",)) == ()


def test_msf_special_target_parser_covers_validation_secondary_targets_and_defence_in_depth(monkeypatch) -> None:
    assert _special_registered_targets(
        "msf_run",
        ("inside", "exploit/example", "RHOSTS=inside,outside"),
    ) == ("inside", "outside")
    assert _special_registered_targets(
        "msf_check",
        ("", "auxiliary/example", "RHOSTS", "outside"),
    ) == ("outside",)

    with pytest.raises(InvalidInvocation, match="unbound_msf_option:COMMAND"):
        _special_registered_targets("msf_run", ("inside", "exploit/example", "COMMAND=id"))

    monkeypatch.setattr(policy_module, "validate_msf_options", lambda _options: ("LHOST=outside",))
    with pytest.raises(InvalidInvocation, match="unbound_msf_option:LHOST"):
        _special_registered_targets("msf_run", ("inside", "exploit/example"))


def test_callback_build_and_browser_targets_cover_all_endpoint_shapes() -> None:
    assert _special_registered_targets(
        "killchain_persist",
        ("inside", "user", "password", "callback"),
    ) == ("inside", "callback")
    assert _special_registered_targets(
        "killchain_persist",
        ("inside", "user", "password", "inside"),
    ) == ("inside",)
    assert _special_registered_targets("build_go_implant", ()) == ()
    assert _special_registered_targets("build_python_implant", ("https://inside/path",)) == ("https://inside/path",)

    with pytest.raises(InvalidInvocation, match="multiple_c2_targets_not_supported"):
        _special_registered_targets("build_ps_stager", ("https://inside,https://outside",))
    with pytest.raises(InvalidInvocation, match="invalid_c2_target"):
        _special_registered_targets("build_ps_stager", ("ftp://inside",))
    with pytest.raises(InvalidInvocation, match="invalid_browser_protocol"):
        _special_registered_targets("browser_surface_analysis", ("inside", "ftp"))
    with pytest.raises(InvalidInvocation, match="invalid_browser_port"):
        _special_registered_targets("browser_surface_analysis", ("inside", "https", "not-a-port"))
    with pytest.raises(InvalidInvocation, match="invalid_browser_port"):
        _special_registered_targets("browser_surface_analysis", ("inside", "https", "65536"))
    with pytest.raises(InvalidInvocation, match="invalid_browser_target"):
        _special_registered_targets("browser_surface_analysis", ("bad target", "https"))

    assert _special_registered_targets("browser_surface_analysis", ("inside",)) == ("https://inside",)
    assert _special_registered_targets("browser_surface_analysis", ("inside", "http", "8080")) == (
        "http://inside:8080",
    )
    assert _special_registered_targets(
        "browser_surface_analysis",
        ("https://inside/path", "https", "443"),
    ) == ("https://inside/path",)


def test_cpanel_and_remote_command_targets_preserve_code_owned_operations() -> None:
    assert _special_registered_targets("cpanel_exploit", ()) == ()
    assert _special_registered_targets("cpanel_exploit", ("inside", "scan")) == ("inside",)
    assert _special_registered_targets("cpanel_exploit", ("inside", "cmd", "whoami")) == ("inside",)
    assert _special_registered_targets("ssh_exec", ("inside",)) == ("inside",)
    assert _special_registered_targets("ssh_exec", ("inside", "user", "password", "whoami")) == ("inside",)
    assert _special_registered_targets("ssh_exec", ("bad target",)) == ()
    assert _special_registered_targets("jmx2rce_rce", ("inside", "")) == ("inside",)
    assert remote_command_is_code_owned("jmx2rce_rce", "") is True

    with pytest.raises(InvalidInvocation, match="unsupported_cpanel_action"):
        _special_registered_targets("cpanel_exploit", ("inside", "delete"))
    with pytest.raises(InvalidInvocation, match="unapproved_remote_command:cpanel_exploit"):
        _special_registered_targets("cpanel_exploit", ("inside", "cmd", "curl outside"))
    with pytest.raises(InvalidInvocation, match="unapproved_remote_command:ssh_exec"):
        _special_registered_targets("ssh_exec", ("inside", "user", "password", "curl outside"))


@pytest.mark.parametrize(
    "arguments",
    [
        ("-L", "https://inside"),
        ("-K", "config", "https://inside"),
        ("-x", "proxy", "https://inside"),
        ("--proxy-http", "proxy", "https://inside"),
        ("--socks5", "proxy", "https://inside"),
        ("-KL", "config", "https://inside"),
    ],
)
def test_curl_header_target_parser_rejects_every_indirection_form(arguments) -> None:
    with pytest.raises(InvalidInvocation, match="unsupported_curl_indirection"):
        _special_registered_targets("curl_headers", arguments)


def test_curl_header_target_parser_skips_flag_values_and_handles_targetless_calls() -> None:
    assert _special_registered_targets(
        "curl_headers",
        ("-A", "agent", "-H", "X-Test: fixture", "--max-time", "2", "https://inside"),
    ) == ("https://inside",)
    assert _special_registered_targets("curl_headers", ("inside",)) == ("inside",)
    assert _special_registered_targets("curl_headers", ("-I",)) == ()


def test_nuclei_and_flag_contracts_cover_assignments_values_fallbacks_and_empty_targets() -> None:
    assert _special_registered_targets("nuclei_safe", ("-u=https://inside",)) == ("https://inside",)
    assert _special_registered_targets("nuclei_safe", ("-url", "https://inside")) == ("https://inside",)
    assert _special_registered_targets(
        "nuclei_safe",
        ("-severity", "high", "-silent", "https://inside"),
    ) == ("https://inside",)
    assert _special_registered_targets("nuclei_safe", ("inside",)) == ("inside",)
    assert _special_registered_targets("nuclei_safe", ("-silent",)) == ()

    assert _special_registered_targets("nikto", ("-h", "inside")) == ("inside",)
    assert _special_registered_targets("sqlmap", ("--url=https://inside",)) == ("https://inside",)
    assert _special_registered_targets(
        "wpscan",
        ("--api-token", "secret", "--url", "https://inside"),
    ) == ("https://inside",)
    assert _special_registered_targets("nikto", ("inside",)) == ("inside",)
    assert _special_registered_targets("wpscan", ("--no-banner",)) == ()
    assert _special_registered_targets("unknown", ("inside",)) is None
    assert _special_registered_targets("enum4linux", ("-a", "inside")) == ("inside",)
    assert _special_registered_targets("enum4linux", ()) == ()


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        ("RHOSTS=inside;CMD=id", "unsafe_msf_option_syntax"),
        ("RHOSTS='inside", "invalid_msf_options_quoting"),
        ("CMD=id", "unbound_msf_option:CMD"),
        ("SESSION=1", "unbound_msf_option:SESSION"),
        ("LHOST=outside", "unbound_msf_option:LHOST"),
        ("PROXIES=http:outside", "unbound_msf_option:PROXIES"),
        ("PAYLOAD=generic/shell_reverse_tcp", "unbound_msf_reverse_payload"),
    ],
)
def test_msf_option_validation_rejects_opaque_and_callback_inputs(options, reason) -> None:
    with pytest.raises(ValueError, match=reason):
        validate_msf_options(options)


def test_host_and_msf_binding_helpers_cover_success_failure_and_separate_remote_values() -> None:
    assert normalize_host("Example.COM.") == "example.com"
    with pytest.raises(ValueError, match="invalid_hostname"):
        normalize_host("bad_host")
    with pytest.raises(ValueError, match="invalid_host"):
        normalize_host("bad host")
    with pytest.raises(ValueError, match="host_port_not_allowed"):
        normalize_host("inside:443")
    assert validate_host("inside") is True
    assert validate_host("https://inside") is False
    assert targets_equivalent("https://inside:443/path", "inside:443") is True
    assert targets_equivalent("bad target", "inside") is False

    assert validate_msf_options("=ignored RHOSTS=inside RPORT=443") == (
        "=ignored",
        "RHOSTS=inside",
        "RPORT=443",
    )
    assert bind_msf_target_options("RHOST outside RPORT=443", "inside") == "RHOSTS=inside RPORT=443"
    assert (
        bind_msf_target_options(
            "RHOST=outside RHOSTS=outside PAYLOAD=generic/shell_bind_tcp",
            "inside",
        )
        == "RHOSTS=inside PAYLOAD=generic/shell_bind_tcp"
    )
    with pytest.raises(ValueError, match="invalid_msf_target"):
        bind_msf_target_options("RPORT=443", "bad target")


def test_scope_and_target_gate_cover_invalid_values_and_invalid_scope_entries() -> None:
    with pytest.raises(ValueError):
        _scope_matches("bad target", "inside")
    assert _scope_matches("inside", "") is False
    assert _scope_matches("hostname", "10.0.0.0/24") is False

    policy = ExecutionPolicy()
    assert policy._targets_allowed(("bad target",), _context("inside")) == (False, "invalid_target:bad target")
    assert policy._targets_allowed(("inside",), _context("bad target", "inside")) == (True, "target_authorized")


def test_shell_network_parser_covers_wrappers_segments_proxies_and_single_target_clients() -> None:
    assert _command_text_network_targets("NAME=value") == ()
    assert _command_text_network_targets("echo https://inert.example") == ()
    assert _command_text_network_targets(
        "; env MODE=test sudo /usr/bin/curl --proxy proxy.example -H 'X-Test: value' https://inside "
        "https://second | command ping -c 1 outside"
    ) == ("proxy.example", "https://inside", "https://second", "outside")
    assert _command_text_network_targets("curl --proxy=https://proxy.example https://inside") == (
        "https://proxy.example",
        "https://inside",
    )
    assert _command_text_network_targets("ssh user@inside ignored.example") == ("inside",)
    assert _command_text_network_targets("curl https://inside https://inside") == ("https://inside",)
    assert _command_text_network_targets("curl --silent 'bad target' https://inside") == ("https://inside",)


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ("curl $TARGET", "unresolved_network_variable"),
        ("curl 'unterminated", "invalid_remote_command_quoting"),
        ("curl -H fixture", "unresolved_network_target:curl"),
        ("curl --proxy 'bad target'", "unresolved_network_target:curl"),
    ],
)
def test_shell_network_parser_rejects_unresolved_or_indirect_targets(command, reason) -> None:
    with pytest.raises(InvalidInvocation, match=reason):
        _command_text_network_targets(command)


def test_registered_authorization_covers_two_token_alias_and_declared_target_rebuild() -> None:
    policy = ExecutionPolicy()
    context = _context("inside")
    two_token = ToolInvocation(
        executable="jmx2rce",
        argv=("jmx2rce", "scan", "inside"),
        raw_command="jmx2rce scan inside",
        registered_name="jmx2rce_scan",
        targets=("inside",),
    )
    rebuilt = ToolInvocation(
        executable="nmap",
        argv=("nmap", "inside"),
        raw_command="nmap inside",
        registered_name="nmap",
    )

    assert policy.authorize_registered(two_token, context).allowed is True
    rebuilt_decision = policy.authorize_registered(rebuilt, context)
    assert rebuilt_decision.allowed is True
    assert rebuilt_decision.invocation is not None
    assert rebuilt_decision.invocation.targets == ("inside",)

    missing_two_token_alias = ToolInvocation(
        executable="not-a-tool",
        argv=("not-a-tool", "still-not-a-tool"),
        raw_command="not-a-tool still-not-a-tool",
        registered_name="nmap",
    )
    assert policy.authorize_registered(missing_two_token_alias, context).reason == "registered_tool_mismatch"


def test_command_authorization_covers_local_typed_and_legacy_uninspectable_registry_paths(monkeypatch) -> None:
    policy = ExecutionPolicy()
    assert policy.authorize_command("prowler_scan account", _context()).allowed is True
    assert policy.authorize_command("nmap inside", _context("inside")).allowed is True

    legacy = SimpleNamespace(name="legacy_provider", func=None, needs_target=True)

    def fake_get_tool(name):
        return legacy if name in {"legacy", "legacy_provider"} else None

    monkeypatch.setattr("core.tools.registry.get_tool", fake_get_tool)
    decision = policy.authorize_command("legacy https://inside", _context("https://inside"))

    assert decision.allowed is True
    assert decision.invocation is not None
    assert decision.invocation.targets == ("https://inside",)
    assert _declared_network_targets(legacy, ("legacy", "https://inside"), 1) == ()


def test_shell_and_final_registered_authorization_cover_remaining_decision_edges() -> None:
    policy = ExecutionPolicy()
    shell_context = ExecutionContext.operator(
        actor="policy-hardening-shell",
        approval_id="policy-hardening-approval",
        target_scope=("inside",),
        allow_shell=True,
    )

    assert policy.authorize_shell("rm fixture", shell_context).reason == "destructive_shell_requires_capability"
    assert policy.authorize_shell("curl https://outside", shell_context).reason == (
        "target_out_of_scope:https://outside"
    )
    assert authorize_final_registered_arguments("nmap", ("inside",), _context("inside")).allowed is True
