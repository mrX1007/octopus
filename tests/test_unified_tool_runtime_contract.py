"""Repository-wide registry-to-runtime contracts for every built-in tool."""

from __future__ import annotations

import inspect
import json
import shlex
from dataclasses import replace

import pytest

import core.tools
import core.tools.runner as tool_runner
from core.actions import ActionRequest, OutcomeStatus, build_action_catalog
from core.ai.runtime import PipelineRuntime
from core.ai.tool_registry import ToolRegistry
from core.execution import ExecutionContext, ExecutionResult, ExecutionStatus, current_execution_context
from core.execution.policy import registered_tool_requires_approval
from core.tools.registry import get_tool, list_tools
from core.tools.runner import run_tool_by_command

pytestmark = [pytest.mark.contract, pytest.mark.security]

EXPECTED_BUILTIN_TOOL_COUNT = 116
EXPECTED_ENABLED_TOOL_COUNT = 96
EXPECTED_DISABLED_TOOL_COUNT = 20
TARGET = "192.0.2.10"
CALLBACK_TARGET = "192.0.2.11"
PROFILE_ONLY_BUILTINS = {
    "cve_lookup",
    "deploy_c2_beacon",
    "jmx2rce_cleanup",
    "jmx2rce_rce",
    "jmx2rce_read",
    "killchain_exploit",
    "killchain_full",
    "killchain_vuln_assess",
    "msf_check",
    "msf_run",
    "plugin",
    "ssh_exec",
    "ssh_session",
    "stealth_brute",
}


def _builtin_tool_defs():
    definitions = []
    for name in core.tools.BUILTIN_TOOL_NAMES:
        tool_def = get_tool(name)
        assert tool_def is not None, f"built-in registry entry disappeared: {name}"
        definitions.append(tool_def)
    return tuple(definitions)


def _approved_context() -> ExecutionContext:
    return ExecutionContext.operator(
        actor="unified-runtime-contract",
        approval_id="hermetic-contract-approval",
        target_scope=(TARGET, CALLBACK_TARGET),
        allow_active_tools=True,
    )


def _provider_command(tool_def, lookup_name: str) -> str:
    explicit_arguments = {
        "bruteforce": f"ssh {TARGET}",
        "build_go_implant": f"http://{TARGET}",
        "build_ps_stager": f"http://{TARGET}",
        "build_python_implant": f"http://{TARGET}",
        "deploy_c2_beacon": f"{TARGET} fixture-user fixture-password {CALLBACK_TARGET}",
        "killchain_full": f"{TARGET} fixture-user fixture-password {CALLBACK_TARGET}",
        "killchain_persist": f"{TARGET} fixture-user fixture-password {CALLBACK_TARGET}",
        "plugin": f"fixture {TARGET}",
        "port_forward": f"{TARGET} 8080 {TARGET} 80",
        "stealth_brute": f"ssh {TARGET}",
    }
    bound_arguments = explicit_arguments.get(
        tool_def.name,
        TARGET if tool_def.needs_target else "",
    )
    return " ".join(item for item in (lookup_name, bound_arguments) if item)


def test_builtin_registry_ai_classification_and_action_catalog_are_complete():
    definitions = _builtin_tool_defs()
    names = tuple(tool_def.name for tool_def in definitions)
    enabled_definitions = tuple(tool_def for tool_def in definitions if tool_def.enabled)
    disabled_definitions = tuple(tool_def for tool_def in definitions if not tool_def.enabled)

    assert len(core.tools.BUILTIN_TOOL_NAMES) == EXPECTED_BUILTIN_TOOL_COUNT
    assert len(set(core.tools.BUILTIN_TOOL_NAMES)) == EXPECTED_BUILTIN_TOOL_COUNT
    assert len(enabled_definitions) == EXPECTED_ENABLED_TOOL_COUNT
    assert len(disabled_definitions) == EXPECTED_DISABLED_TOOL_COUNT
    assert {tool_def.name for tool_def in disabled_definitions} == set(core.tools.MANUAL_GATED_CAPABILITY_NAMES)
    assert core.tools.QUARANTINED_CAPABILITY_NAMES == ()
    assert set(names).issubset({tool_def.name for tool_def in list_tools()})

    coverage = ToolRegistry().get_coverage_report(list(names))
    assert coverage["registered"] == EXPECTED_BUILTIN_TOOL_COUNT
    assert coverage["covered"] == EXPECTED_BUILTIN_TOOL_COUNT
    assert set(coverage["disabled"]) == set(core.tools.MANUAL_GATED_CAPABILITY_NAMES)
    assert coverage["unknown"] == []

    catalog = build_action_catalog(lambda _command, _context: "unused", tool_defs=definitions)
    assert len(catalog) == EXPECTED_BUILTIN_TOOL_COUNT
    descriptor_kinds = {descriptor.kind.value for descriptor in catalog.descriptors()}
    assert descriptor_kinds == {"registered_tool", "killchain", "plugin"}
    for tool_def in definitions:
        canonical = catalog.require(tool_def.name)
        assert canonical.adapter.descriptor.name == tool_def.name
        assert canonical.alias_used is False
        for alias in tool_def.aliases:
            resolved = catalog.require(alias)
            assert resolved.canonical_id == canonical.canonical_id
            assert resolved.adapter is canonical.adapter
            assert resolved.alias_used is True

    for tool_def in disabled_definitions:
        descriptor = catalog.require(tool_def.name).adapter.descriptor
        assert descriptor.manual_gate is True
        assert descriptor.provider_mounted is False


def test_ai_leaf_provider_namespace_is_registry_complete():
    registry = ToolRegistry()
    enabled_names = {tool_def.name for tool_def in _builtin_tool_defs() if tool_def.enabled}
    disabled_names = {tool_def.name for tool_def in _builtin_tool_defs() if not tool_def.enabled}
    leaf_providers = {provider for task in registry.task_map for provider in registry._tool_names_for_task(task)}

    assert leaf_providers <= enabled_names
    assert leaf_providers.isdisjoint(disabled_names)
    assert enabled_names - leaf_providers == PROFILE_ONLY_BUILTINS

    for task, entries in registry.task_map.items():
        for command_template, provider in entries:
            if provider in registry.task_map and provider != task:
                continue
            assert shlex.split(command_template)[0] == provider


def test_pass_the_hash_name_and_alias_are_manual_gated_without_exposing_raw_hash():
    canary = "0123456789abcdef0123456789abcdef"
    canonical = get_tool("pass_the_hash")
    registry = ToolRegistry()

    assert canonical is not None
    assert canonical.enabled is False
    assert get_tool("pth") is canonical
    assert "pass_the_hash" not in {
        provider for task in registry.task_map for provider in registry._tool_names_for_task(task)
    }

    for name in ("pass_the_hash", "pth"):
        result = run_tool_by_command(
            f"{name} {TARGET} alice {canary} CORP",
            _approved_context(),
        )
        assert "provider_disabled" in result
        assert canary not in result


def test_every_task_map_entry_has_explicit_fail_closed_scheduling_metadata():
    registry = ToolRegistry()
    supported_risks = {
        "active",
        "check_only",
        "local_build",
        "passive",
        "post_access_change",
        "post_access_read",
        "safe",
    }
    sensitive_risks = {
        "ad_remote_execution": "post_access_change",
        "domain_credential_extraction": "active",
        "exploit_privesc": "post_access_change",
        "hash_cracking": "active",
        "test_credentials": "active",
    }

    assert set(registry.task_profiles) == set(registry.task_map)
    for task, profile in registry.task_profiles.items():
        assert set(profile) == {"cost", "time", "risk", "preconditions"}, task
        assert isinstance(profile["cost"], int) and 1 <= profile["cost"] <= 6
        assert profile["time"] in {"short", "medium", "long"}
        assert profile["risk"] in supported_risks
        assert isinstance(profile["preconditions"], list)
        assert len(profile["preconditions"]) == len(set(profile["preconditions"]))
        assert all(
            isinstance(precondition, str) and precondition.strip() == precondition
            for precondition in profile["preconditions"]
        )

    for task, expected_risk in sensitive_risks.items():
        assert registry.task_profiles[task]["risk"] == expected_risk

    assert registry.task_profile("external-task")["risk"] == "unknown"


def test_registry_and_action_catalog_reject_undeclared_fuzzy_names():
    definitions = _builtin_tool_defs()
    declared_names = {spelling for tool_def in definitions for spelling in (tool_def.name, *tool_def.aliases)}
    catalog = build_action_catalog(
        lambda _command, _context: "unused",
        tool_defs=definitions,
    )

    for spelling in tuple(declared_names):
        for prefix in ("run_", "_run_"):
            candidate = f"{prefix}{spelling}"
            is_declared = candidate in declared_names
            assert (get_tool(candidate) is not None) is is_declared
            assert (catalog.resolve(candidate) is not None) is is_declared


def test_every_legacy_numeric_menu_entry_resolves_to_registered_policy_identity():
    assert len(tool_runner.TOOLS_MENU) == 46
    assert set(tool_runner._MENU_TOOL_IDS) == set(tool_runner.TOOLS_MENU)
    assert {key: tool_runner._MENU_TOOL_IDS[key] for key in ("1", "13", "16", "45", "50")} == {
        "1": "nmap",
        "13": "scrapling",
        "16": "bruteforce",
        "45": "build_go_implant",
        "50": "smtp_probe",
    }
    assert {"14", "33", "34", "48"}.isdisjoint(tool_runner.TOOLS_MENU)
    with pytest.raises(TypeError):
        tool_runner._MENU_TOOL_IDS["1"] = "web_login_brute"

    for key, (label, _provider) in tool_runner.TOOLS_MENU.items():
        policy_name = tool_runner._MENU_TOOL_IDS[key]
        assert get_tool(policy_name) is not None, (
            f"numeric menu entry {key} ({label}) has no registered policy identity"
        )


def test_legacy_default_recon_profile_uses_only_catalog_registered_tools():
    definitions = _builtin_tool_defs()
    catalog = build_action_catalog(
        lambda _command, _context: "unused",
        tool_defs=definitions,
    )

    assert len(tool_runner._DEFAULT_RECON_TOOL_NAMES) == 9
    assert len(set(tool_runner._DEFAULT_RECON_TOOL_NAMES)) == 9
    for tool_name in tool_runner._DEFAULT_RECON_TOOL_NAMES:
        tool_def = get_tool(tool_name)
        resolved = catalog.require(tool_name)
        assert tool_def is not None
        assert resolved.adapter.descriptor.name == tool_def.name


@pytest.mark.parametrize("removed_key", ["14", "48"])
def test_unregistered_active_legacy_menu_entries_stay_unreachable(removed_key):
    result = tool_runner.run_single_tool(
        removed_key,
        TARGET,
        ExecutionContext.automatic(target_scope=(TARGET,)),
    )

    assert result == f"[!] Unknown tool key: {removed_key}"


def test_legacy_numeric_menu_obeys_policy_before_stubbed_provider_dispatch(
    monkeypatch,
):
    context = ExecutionContext.automatic(target_scope=(TARGET,))
    calls: list[tuple[str, tuple[object, ...]]] = []
    monkeypatch.setattr(tool_runner, "_configured_killchain_denial", lambda _name: "")

    for key, (_label, _menu_provider) in tuple(tool_runner.TOOLS_MENU.items()):
        policy_name = tool_runner._MENU_TOOL_IDS[key]
        tool_def = get_tool(policy_name)
        assert tool_def is not None
        monkeypatch.setattr(tool_def, "dependencies", None)
        monkeypatch.setattr(tool_def, "requires", [])

        def marker(*args, _key=key, **_kwargs):
            calls.append((_key, args))
            return f"menu-stub:{_key}"

        monkeypatch.setattr(tool_def, "func", marker)
        call_count = len(calls)
        result = tool_runner.run_single_tool(key, TARGET, context)
        arguments, argument_error = tool_runner._legacy_menu_arguments(key, TARGET)
        if not tool_def.enabled:
            assert len(calls) == call_count
            assert "provider_disabled" in result
            continue
        if argument_error:
            assert len(calls) == call_count
            assert argument_error in result
            continue

        requires_approval = registered_tool_requires_approval(
            tool_def.name,
            (tool_def.name, *arguments),
        )

        if requires_approval:
            assert len(calls) == call_count
            assert "active_tool_requires_approval" in result
        else:
            assert calls[-1][0] == key
            assert any(TARGET in str(argument) for argument in calls[-1][1])
            assert result == f"menu-stub:{key}"


def test_mutating_only_the_legacy_menu_callable_cannot_change_provider_identity(
    monkeypatch,
):
    canonical_calls: list[str] = []
    rogue_calls: list[str] = []
    tool_def = get_tool("nmap")
    assert tool_def is not None
    monkeypatch.setattr(tool_def, "dependencies", None)
    monkeypatch.setattr(tool_def, "requires", [])

    def canonical(target, extra_flags=None):
        del extra_flags
        canonical_calls.append(target)
        return "canonical-provider"

    monkeypatch.setattr(tool_def, "func", canonical)
    monkeypatch.setitem(
        tool_runner.TOOLS_MENU,
        "1",
        (
            "web login brute",
            lambda target: rogue_calls.append(target) or "rogue-provider",
        ),
    )

    result = tool_runner.run_single_tool(
        "1",
        TARGET,
        _approved_context(),
    )

    assert result == "canonical-provider"
    assert canonical_calls == [TARGET]
    assert rogue_calls == []


def test_legacy_menu_special_arguments_are_explicit_and_hermetic(monkeypatch):
    calls: list[tuple[object, ...]] = []
    tool_def = get_tool("bruteforce")
    assert tool_def is not None

    def marker(*args, **_kwargs):
        calls.append(args)
        return "bruteforce-stub"

    monkeypatch.setattr(tool_def, "func", marker)

    result = tool_runner.run_single_tool("16", TARGET, _approved_context())

    assert result == "bruteforce-stub"
    assert calls == [("ssh", TARGET)]


def test_every_builtin_name_and_alias_dispatches_through_one_runtime(tmp_path):
    definitions = tuple(
        replace(tool_def, requires=[], dependencies=None) for tool_def in _builtin_tool_defs() if tool_def.enabled
    )
    context = _approved_context()
    calls: list[tuple[str, ExecutionContext]] = []

    def runner(command: str, execution_context: ExecutionContext):
        assert current_execution_context() is execution_context
        calls.append((command, execution_context))
        return {"status": "succeeded", "stdout": f"runtime-stub:{command}"}

    runtime = PipelineRuntime(str(tmp_path / "unified-runtime.db"), runner=runner)
    runtime._action_catalog = build_action_catalog(
        runtime._dispatch_runner,
        tool_defs=definitions,
    )

    expected_calls = 0
    for tool_def in definitions:
        for lookup_name in (tool_def.name, *tool_def.aliases):
            command = _provider_command(tool_def, lookup_name)
            report = runtime.execute_action(
                lookup_name,
                ActionRequest(
                    target=TARGET,
                    execution_context=context,
                    command=command,
                ),
                run_check=False,
                cleanup=False,
            )

            assert report.descriptor.name == tool_def.name
            assert report.policy_denials == []
            assert report.execution_result is not None
            assert report.execution_result.status is ExecutionStatus.SUCCEEDED
            assert report.execution_result.request_id == context.request_id
            assert report.execution_result.tool_name == tool_def.name
            assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED
            if tool_def.name == "plugin_inventory":
                assert json.loads(report.execution_result.stdout)["plugins"]
            else:
                expected_calls += 1
                assert calls[-1] == (command, context)

    assert len(calls) == expected_calls


def test_every_builtin_name_and_alias_crosses_scheduler_and_action_catalog(tmp_path):
    definitions = tuple(
        replace(tool_def, requires=[], dependencies=None) for tool_def in _builtin_tool_defs() if tool_def.enabled
    )
    context = _approved_context()
    calls: list[tuple[str, ExecutionContext]] = []

    def runner(command: str, execution_context: ExecutionContext):
        assert current_execution_context() is execution_context
        calls.append((command, execution_context))
        return {"status": "succeeded", "stdout": f"scheduler-stub:{command}"}

    runtime = PipelineRuntime(str(tmp_path / "scheduler-runtime.db"), runner=runner)
    runtime._action_catalog = build_action_catalog(
        runtime._dispatch_runner,
        tool_defs=definitions,
    )

    expected_calls = 0
    for tool_def in definitions:
        for lookup_name in (tool_def.name, *tool_def.aliases):
            command = _provider_command(tool_def, lookup_name)
            decision = runtime.decide(command, (), set(), context)
            result = runtime.execute(
                decision,
                context,
                capability=f"tool:{tool_def.name}",
            )

            assert decision.action == "execute"
            assert decision.invocation is not None
            assert decision.invocation.registered_name == tool_def.name
            assert result.status is ExecutionStatus.SUCCEEDED
            assert result.metadata["action_catalog"] is True
            assert result.metadata["action_id"] == (runtime.action_catalog.require(tool_def.name).canonical_id)
            if tool_def.name == "plugin_inventory":
                assert json.loads(result.stdout)["plugins"]
            else:
                expected_calls += 1
                assert calls[-1] == (command, context)

    assert len(calls) == expected_calls


def test_automatic_context_never_dispatches_policy_active_builtin_or_alias(tmp_path):
    definitions = tuple(
        replace(tool_def, requires=[], dependencies=None) for tool_def in _builtin_tool_defs() if tool_def.enabled
    )
    context = ExecutionContext.automatic(target_scope=(TARGET, CALLBACK_TARGET))
    calls: list[str] = []

    def runner(command: str, _execution_context: ExecutionContext):
        calls.append(command)
        return {"status": "succeeded", "stdout": f"runtime-stub:{command}"}

    runtime = PipelineRuntime(str(tmp_path / "automatic-runtime.db"), runner=runner)
    runtime._action_catalog = build_action_catalog(
        runtime._dispatch_runner,
        tool_defs=definitions,
    )

    for tool_def in definitions:
        for lookup_name in (tool_def.name, *tool_def.aliases):
            command = _provider_command(tool_def, lookup_name)
            call_count = len(calls)
            report = runtime.execute_action(
                lookup_name,
                ActionRequest(
                    target=TARGET,
                    execution_context=context,
                    command=command,
                ),
                run_check=False,
                cleanup=False,
            )
            requires_approval = registered_tool_requires_approval(
                tool_def.name,
                tuple(shlex.split(command)),
            )

            if requires_approval:
                assert len(calls) == call_count
                assert [denial.reason_code for denial in report.policy_denials] == ["active_tool_requires_approval"]
                assert report.lifecycle.outcome is OutcomeStatus.BLOCKED
            elif tool_def.name == "plugin_inventory":
                assert len(calls) == call_count
                assert report.policy_denials == []
                assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED
            else:
                assert calls[-1] == command
                assert report.policy_denials == []
                assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED


def test_real_command_facade_reaches_all_builtin_providers_without_external_io(
    monkeypatch,
):
    from core.ai import runtime as runtime_module

    context = _approved_context()
    called: list[tuple[str, ExecutionContext]] = []
    canonical_calls: list[tuple[str, str, ExecutionContext]] = []
    definitions = _builtin_tool_defs()

    def canonical_dispatch(command: str, execution_context: ExecutionContext) -> ExecutionResult:
        lookup_name = shlex.split(command)[0]
        tool_def = get_tool(lookup_name)
        assert tool_def is not None
        canonical_calls.append((tool_def.name, command, execution_context))
        return ExecutionResult(
            status=ExecutionStatus.SUCCEEDED,
            stdout=f"canonical-stub:{tool_def.name}",
        )

    monkeypatch.setattr(runtime_module, "dispatch_plugin_command", canonical_dispatch)

    for tool_def in definitions:
        assert tool_def.func is not None
        monkeypatch.setattr(tool_def, "dependencies", None)
        monkeypatch.setattr(tool_def, "requires", [])
        provider_signature = inspect.signature(tool_def.func)
        tool_name = tool_def.name

        def marker(*_args, _tool_name=tool_name, **_kwargs):
            called.append((_tool_name, current_execution_context()))
            return f"provider-stub:{_tool_name}"

        marker.__signature__ = provider_signature
        monkeypatch.setattr(tool_def, "func", marker)

    expected_names = []
    for tool_def in definitions:
        for lookup_name in (tool_def.name, *tool_def.aliases):
            result = run_tool_by_command(_provider_command(tool_def, lookup_name), context)
            if tool_def.enabled:
                if tool_def.name in {"plugin", "plugin_inventory"}:
                    assert result == f"canonical-stub:{tool_def.name}"
                    continue
                expected_names.append(tool_def.name)
                assert result == f"provider-stub:{tool_def.name}"
            else:
                assert "provider_disabled" in result

    assert [name for name, _context in called] == expected_names
    assert all(bound_context is context for _name, bound_context in called)
    assert {name for name, _command, _context in canonical_calls} == {
        "plugin",
        "plugin_inventory",
    }
    assert all(bound_context is context for _name, _command, bound_context in canonical_calls)


def test_legacy_one_argument_runtime_runner_keeps_bound_context(tmp_path):
    context = _approved_context()
    observed: list[ExecutionContext] = []

    def legacy_runner(_command: str):
        observed.append(current_execution_context())
        return "legacy-ok"

    runtime = PipelineRuntime(str(tmp_path / "legacy-runtime.db"), runner=legacy_runner)
    nmap = replace(get_tool("nmap"), requires=[], dependencies=None, enabled=True)
    runtime._action_catalog = build_action_catalog(
        runtime._dispatch_runner,
        tool_defs=(nmap,),
    )

    report = runtime.execute_action(
        "nmap",
        ActionRequest(TARGET, context, command=f"nmap {TARGET}"),
        run_check=False,
        cleanup=False,
    )

    assert report.execution_result is not None
    assert report.execution_result.status is ExecutionStatus.SUCCEEDED
    assert observed == [context]
