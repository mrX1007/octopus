"""Comprehensive test suite verifying Phase 6 unified execution lifecycle contracts."""

from __future__ import annotations

import tempfile

import pytest

from core.actions import (
    ActionExecutionReport,
    ActionExecutor,
    ActionKind,
    ActionRequest,
    build_action_catalog,
)
from core.actions.adapters_evasion import PayloadKeyingAdapter
from core.actions.input_contracts import CredentialInput, PayloadKeyingInput
from core.ai.fact_store import FactStore
from core.ai.tool_registry import ToolRegistry
from core.cli.menu_bridge import (
    MENU_CANONICAL_MAP,
    build_menu_action_request,
    dispatch_menu_choice,
)
from core.execution import (
    ExecutionContext,
    ExecutionPolicy,
    ExecutionResult,
)
from core.tools import (
    BUILTIN_TOOL_NAMES,
    DEPRECATED_TOOL_EXPORTS,
    DIRECT_PROVIDER_EXPORTS,
    LOW_LEVEL_EXECUTION_EXPORTS,
    dispatch_registered_tool,
)
from core.tools.registry import get_tool, list_tools

pytestmark = [pytest.mark.contract, pytest.mark.security]

TARGET = "192.0.2.1"
EXPECTED_ENABLED_TOOL_COUNT = 96


def _approved_context(target: str = TARGET) -> ExecutionContext:
    """Build an approved operator ExecutionContext for testing."""
    return ExecutionContext.operator(
        actor="unified-contract-test",
        approval_id="approved-contract-test",
        target_scope=(target,),
        allow_active_tools=True,
    )


def test_every_action_routes_through_catalog_executor_policy_provider_result_factstore() -> None:
    """Verify that all 96 tools + ex-quarantined capabilities route through:
    ActionCatalog -> ActionExecutor -> ExecutionPolicy -> Provider -> ExecutionResult -> FactStore.
    """
    ToolRegistry()

    definitions = [get_tool(name) for name in BUILTIN_TOOL_NAMES]
    assert all(definition is not None for definition in definitions)
    assert len(definitions) == 116
    assert sum(tool_def.enabled for tool_def in definitions) == EXPECTED_ENABLED_TOOL_COUNT

    invoked_commands: list[str] = []

    def mock_dispatch(command: str, _ctx: ExecutionContext) -> str:
        invoked_commands.append(command)
        return "mock_provider_output"

    catalog = build_action_catalog(mock_dispatch, tool_defs=definitions)
    assert len(catalog) >= 116

    policy = ExecutionPolicy()
    executor = ActionExecutor(catalog, policy)

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = f"{tmp_dir}/facts.db"
        fact_store = FactStore(db_path=db_path)

        for descriptor in catalog.descriptors():
            name = descriptor.name
            resolved = catalog.require(name)
            assert resolved.canonical_id is not None
            assert resolved.adapter is not None

            context = _approved_context(TARGET)
            request = ActionRequest(target=TARGET, execution_context=context)

            report = executor.run(name, request)
            assert isinstance(report, ActionExecutionReport)

            if report.execution_result is not None:
                assert isinstance(report.execution_result, ExecutionResult)
            fact_id = fact_store.add_fact(
                scan_id="test_scan",
                host=TARGET,
                fact_type="action_lifecycle",
                value=f"action:{name}:outcome={report.lifecycle.outcome.value}",
                source=f"action_executor:{name}",
            )
            assert fact_id > 0

        stored_facts = fact_store.get_facts("test_scan", host=TARGET)
        assert len(stored_facts) >= len(catalog)


def test_payload_keying_single_canonical_identity() -> None:
    """Verify that payload_keying has a single canonical identity across catalog and adapters."""
    catalog = build_action_catalog(lambda *_args: "unused", tool_defs=list_tools())

    resolved_by_name = catalog.resolve("payload_keying")
    resolved_by_id = catalog.resolve("plugin:payload_keying")

    assert resolved_by_name is not None
    assert resolved_by_id is not None
    assert resolved_by_name.canonical_id == "plugin:payload_keying"
    assert resolved_by_id.canonical_id == "plugin:payload_keying"
    assert resolved_by_name.adapter is resolved_by_id.adapter
    assert isinstance(resolved_by_name.adapter, PayloadKeyingAdapter)

    descriptor = resolved_by_name.adapter.descriptor
    assert descriptor.name == "payload_keying"
    assert descriptor.action_id == "plugin:payload_keying"
    assert descriptor.kind == ActionKind.PLUGIN
    assert descriptor.input_type is PayloadKeyingInput
    assert descriptor.category == "evasion"
    assert descriptor.capability_class == "evasion"

    policy = ExecutionPolicy()
    executor = ActionExecutor(catalog, policy)
    context = _approved_context(TARGET)
    request = ActionRequest(
        target=TARGET,
        execution_context=context,
        typed_input=PayloadKeyingInput("artifact://payload"),
    )
    report = executor.run("payload_keying", request)
    assert report.descriptor.action_id == "plugin:payload_keying"
    assert report.execution_result is None
    assert [item.reason_code for item in report.policy_denials] == ["provider_not_configured"]


def test_legacy_menu_options_construct_action_request_and_resolve_canonical_actions() -> None:
    """Verify legacy menu options construct ActionRequest and resolve canonical actions."""
    ToolRegistry()
    definitions = list_tools()

    def mock_dispatch(command: str, _ctx: ExecutionContext) -> str:
        return "mock_menu_output"

    catalog = build_action_catalog(mock_dispatch, tool_defs=definitions)
    policy = ExecutionPolicy()
    executor = ActionExecutor(catalog, policy)

    assert len(MENU_CANONICAL_MAP) >= 40

    from core.tools.runner import _MENU_TOOL_IDS

    explicit_choices = {
        "18",
        "20",
        "21",
        "22",
        "23",
        "24",
        "25",
        "27",
        "31",
        "36",
        "37",
        "38",
        "39",
        "40",
        "41",
        "42",
        "43",
        "44",
        "45",
        "46",
        "47",
    }
    unmapped_shodan_subactions = {"29", "30", "32"}

    for choice, canonical_id in MENU_CANONICAL_MAP.items():
        assert canonical_id.split(":", 1)[1] == _MENU_TOOL_IDS[choice]
        resolved = catalog.resolve(canonical_id)
        assert resolved is not None, f"Menu choice '{choice}' canonical_id '{canonical_id}' failed to resolve"

        if choice in explicit_choices or choice in unmapped_shodan_subactions:
            res_canonical_id, request = build_menu_action_request(
                choice,
                TARGET,
                context=_approved_context(TARGET),
            )
            assert res_canonical_id is None
            assert request is None
            continue

        res_canonical_id, request = build_menu_action_request(
            choice,
            TARGET,
            context=_approved_context(TARGET),
        )
        assert res_canonical_id == canonical_id
        assert request is not None
        assert isinstance(request, ActionRequest)
        assert request.target == TARGET
        assert request.execution_context is not None

    brute_id, brute_request = build_menu_action_request(
        "16",
        TARGET,
        context=_approved_context(TARGET),
    )
    assert brute_id == "tool:bruteforce"
    assert brute_request is not None
    assert brute_request.command == f"bruteforce ssh {TARGET}"

    scrapling_id, scrapling_request = build_menu_action_request(
        "13",
        TARGET,
        context=_approved_context(TARGET),
    )
    assert scrapling_id == "tool:scrapling"
    assert scrapling_request is not None
    assert scrapling_request.command == f"scrapling http://{TARGET}"

    fact = {
        "id": 1,
        "host": TARGET,
        "type": "confirmed_ad_access",
        "assessment_status": "verified",
        "trust_level": "trusted",
    }
    pth_id, pth_request = build_menu_action_request(
        "39",
        TARGET,
        context=_approved_context(TARGET),
        typed_input=CredentialInput("credential://opaque", TARGET),
        facts=(fact,),
        precondition_refs=("fact://1",),
    )
    assert pth_id == "killchain:pass_the_hash"
    assert pth_request is not None
    ignored_typed_id, ignored_typed_request = build_menu_action_request(
        "40",
        TARGET,
        context=_approved_context(TARGET),
        typed_input=CredentialInput("credential://opaque", TARGET),
    )
    assert ignored_typed_id is None
    assert ignored_typed_request is None
    pth_success, pth_report = dispatch_menu_choice(
        "39",
        TARGET,
        catalog,
        executor,
        context=_approved_context(TARGET),
        typed_input=CredentialInput("credential://opaque", TARGET),
        facts=(fact,),
        precondition_refs=("fact://1",),
    )
    assert pth_success is False
    assert isinstance(pth_report, ActionExecutionReport)
    assert [item.reason_code for item in pth_report.policy_denials] == ["provider_not_configured"]

    success, report_or_err = dispatch_menu_choice(
        "1",
        TARGET,
        catalog,
        executor,
        context=_approved_context(TARGET),
    )
    assert isinstance(success, bool)
    assert isinstance(report_or_err, ActionExecutionReport)

    missing_context_success, missing_context_err = dispatch_menu_choice(
        "1",
        TARGET,
        catalog,
        executor,
    )
    assert missing_context_success is False
    assert "Failed closed" in str(missing_context_err)

    bad_success, bad_err = dispatch_menu_choice("999", TARGET, catalog, executor)
    assert bad_success is False
    assert "[!] Failed closed" in str(bad_err)

    empty_target_success, empty_target_err = dispatch_menu_choice("1", "", catalog, executor)
    assert empty_target_success is False
    assert "[!] Failed closed" in str(empty_target_err)


def test_direct_provider_calls_without_execution_context_fail_closed() -> None:
    """Verify direct provider function calls without ExecutionContext fail closed."""
    with pytest.raises(TypeError, match="execution_context must be an ExecutionContext"):
        dispatch_registered_tool("nmap 192.0.2.1", None)  # type: ignore

    with pytest.raises(TypeError, match="execution_context must be an ExecutionContext"):
        dispatch_registered_tool("nmap 192.0.2.1", "invalid_context")  # type: ignore

    assert len(DEPRECATED_TOOL_EXPORTS) >= len(DIRECT_PROVIDER_EXPORTS) + len(LOW_LEVEL_EXECUTION_EXPORTS)
    for export in DIRECT_PROVIDER_EXPORTS:
        assert export in DEPRECATED_TOOL_EXPORTS
    for export in LOW_LEVEL_EXECUTION_EXPORTS:
        assert export in DEPRECATED_TOOL_EXPORTS

    from core.tools.runner import run_arbitrary_cmd

    unapproved_ctx = ExecutionContext.automatic(actor="test", origin="test")
    res = run_arbitrary_cmd("nmap 192.0.2.1", execution_context=unapproved_ctx)
    assert "[!] Execution denied:" in res or "[DENIED]" in res
