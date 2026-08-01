"""Adversarial contracts for endpoints hidden behind provider arguments."""

from types import SimpleNamespace

import pytest

import core.tools  # noqa: F401 - register built-in providers
from core.actions import ActionRequest, ExploitBaseAdapter, PluginActionAdapter
from core.execution import ExecutionContext, ExecutionPolicy

pytestmark = [pytest.mark.contract, pytest.mark.security]

INSIDE = "inside"


def _approved(*scope: str) -> ExecutionContext:
    return ExecutionContext.operator(
        actor="scope-indirection-test",
        approval_id="scope-indirection-approval",
        target_scope=scope or (INSIDE,),
        allow_active_tools=True,
        allow_shell=True,
    )


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ("nmap -iL targets.txt inside", "unsupported_nmap_indirect_target:-iL"),
        ("nmap --script=/tmp/evil.nse inside", "unsupported_nmap_script_source"),
        ("nmap --datadir=/tmp/evil inside", "unsupported_nmap_script_args"),
        (
            "nmap --script-args http-open-proxy.url=http://outside inside",
            "unsupported_nmap_script_args",
        ),
        (
            "rustscan -a inside --config-path evil.toml",
            "unsupported_rustscan_indirection:--config-path",
        ),
        (
            "rustscan -a inside -- --script=/tmp/evil.nse",
            "unsupported_nmap_script_source",
        ),
        ("curl_headers -L http://inside", "unsupported_curl_indirection:-L"),
        ("curl_headers -K evil.conf http://inside", "unsupported_curl_indirection:-K"),
        (
            "curl_headers --connect-to inside:80:outside:80 http://inside",
            "unsupported_curl_indirection:--connect-to",
        ),
        (
            "msf_run inside exploit/test AutoRunScript=multi_console_command",
            "unbound_msf_option:AUTORUNSCRIPT",
        ),
        (
            "msf_run inside exploit/test COMMANDS='curl http://outside'",
            "unbound_msf_option:COMMANDS",
        ),
        (
            "build_python_implant http://inside/path,https://outside 60",
            "multiple_c2_targets_not_supported",
        ),
        (
            "cpanel_exploit inside cmd 'curl https://outside'",
            "unapproved_remote_command:cpanel_exploit",
        ),
        (
            "browser_surface_analysis inside https 80@outside",
            "invalid_browser_port",
        ),
    ],
)
def test_indirect_provider_endpoints_fail_closed(command: str, reason: str) -> None:
    decision = ExecutionPolicy().authorize_command(command, _approved())

    assert decision.allowed is False
    assert decision.reason == reason


def test_callback_is_host_only_and_scoped_as_a_secondary_endpoint() -> None:
    policy = ExecutionPolicy()

    injected = policy.authorize_command(
        "killchain_persist inside user password 'http://inside/\";id;#'",
        _approved(),
    )
    outside = policy.authorize_command(
        "killchain_persist inside user password callback",
        _approved(),
    )
    allowed = policy.authorize_command(
        "killchain_persist inside user password callback",
        _approved("inside", "callback"),
    )

    assert injected.reason == "missing_explicit_callback_target"
    assert outside.reason == "target_out_of_scope:callback"
    assert allowed.allowed is True


class _PluginManager:
    descriptor = SimpleNamespace(
        name="fixture",
        plugin_type="recon",
        description="fixture",
        version="1",
        requires=(),
        python_deps=(),
        capabilities=(),
    )

    def get_plugin(self, name):
        return self.descriptor if name == "fixture" else None

    @staticmethod
    def validate(_name):
        return ()


@pytest.mark.parametrize(
    "parameters",
    [
        {"destination": "outside"},
        {"base_url": "outside"},
        {"nested": {"destination": "outside"}},
        {"address": [203, 0, 113, 9]},
        {"operation": "curl outside"},
    ],
)
def test_plugin_kwargs_require_a_code_owned_schema(parameters) -> None:
    adapter = PluginActionAdapter(_PluginManager(), "fixture")
    request = ActionRequest(INSIDE, _approved(), parameters=parameters)

    decision = adapter.authorize(ExecutionPolicy(), request, "execute")

    assert decision.allowed is False
    assert decision.reason.startswith("plugin_network_parameter_undeclared:")


def test_opaque_handle_cannot_self_assert_its_peer() -> None:
    class FakeHandle:
        @staticmethod
        def getpeername():
            return (INSIDE, 22)

    exploit = SimpleNamespace(
        name="fixture",
        cve="CVE-2099-1",
        description="fixture",
        supported_os=(),
    )
    result = ExploitBaseAdapter(exploit).applicability(
        ActionRequest(INSIDE, _approved(), handle=FakeHandle())
    )

    assert result.applicable is False
    assert "provider_handle_binding_required" in result.missing_requirements
