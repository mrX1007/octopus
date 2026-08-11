"""Fail-closed contracts for canonical manual-gated capability identities."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest

from core.actions import ActionExecutor, ActionRequest, build_action_catalog
from core.actions.input_contracts import (
    C2AgentInput,
    C2ChannelInput,
    C2CleanupInput,
    C2EnrollmentInput,
    CredentialInput,
    PayloadKeyingInput,
    PivotRouteInput,
    RemoteExecInput,
    ScanTarget,
    SessionInput,
    TicketInput,
)
from core.execution import ExecutionContext, ExecutionPolicy
from core.execution.policy import registered_tool_requires_approval
from core.tools.quarantined import (
    MANUAL_GATED_CAPABILITY_NAMES,
    QUARANTINED_CAPABILITY_NAMES,
)
from core.tools.registry import get_tool, list_tools

pytestmark = [pytest.mark.contract, pytest.mark.security]

TARGET = "192.0.2.10"


def _typed_inputs() -> dict[str, object]:
    credential = CredentialInput("credential://opaque", TARGET)
    session = SessionInput("session://opaque", TARGET)
    ticket = TicketInput("ticket://opaque", TARGET)
    remote = RemoteExecInput("credential://opaque", TARGET, "operation://inventory")
    channel = C2ChannelInput(TARGET, "https", "https://192.0.2.10/callback")
    return {
        "pivot_remote_forward": session,
        "pivot_ssh_chain": credential,
        "pivot_proxy_scan": PivotRouteInput("fact://1", ScanTarget(TARGET)),
        "kerberos_extract_tickets": session,
        "kerberos_crack_tickets": ticket,
        "ad_pass_the_ticket": ticket,
        "pass_the_hash": credential,
        "ad_dump_lsass": session,
        "ad_sam_dump": session,
        "ad_smbexec": remote,
        "ad_winrm_exec": remote,
        "ad_dcom_exec": remote,
        "ad_remote_execution": remote,
        "dns_c2_channel": C2ChannelInput(TARGET, "dns"),
        "c2_enroll": C2EnrollmentInput("c2-enrollment://opaque", TARGET),
        "c2_deploy": channel,
        "c2_channel_create": channel,
        "c2_task": C2AgentInput("c2-agent://opaque", "c2-task://opaque", TARGET),
        "c2_cleanup": C2CleanupInput("c2-channel://opaque", TARGET),
        "payload_keying": PayloadKeyingInput("artifact://payload"),
    }


def _preconditions(required: tuple[str, ...]) -> tuple[tuple[dict[str, object], ...], tuple[str, ...]]:
    facts: list[dict[str, object]] = []
    refs: list[str] = []
    for index, fact_type in enumerate(required, start=1):
        facts.append(
            {
                "id": index,
                "host": TARGET,
                "type": fact_type,
                "value": "confirmed",
                "assessment_status": "verified",
                "trust_level": "trusted",
            }
        )
        refs.append(f"fact://{index}")
    return tuple(facts), tuple(refs)


def _request(
    adapter_name: str,
    context: ExecutionContext,
    required: tuple[str, ...],
) -> ActionRequest:
    facts, refs = _preconditions(required)
    return ActionRequest(
        target=TARGET,
        execution_context=context,
        typed_input=_typed_inputs()[adapter_name],
        facts=facts,
        precondition_refs=refs,
    )


def _catalog():
    return build_action_catalog(lambda *_args: pytest.fail("registry provider was invoked"), tool_defs=list_tools())


def test_manual_gated_inventory_is_registered_but_not_quarantined() -> None:
    assert len(MANUAL_GATED_CAPABILITY_NAMES) == 20
    assert QUARANTINED_CAPABILITY_NAMES == ()
    assert len(list_tools()) == 116
    assert sum(tool_def.enabled for tool_def in list_tools()) == 96

    for name in MANUAL_GATED_CAPABILITY_NAMES:
        tool_def = get_tool(name)
        assert tool_def is not None
        assert tool_def.enabled is False
        assert tool_def.disabled_reason == "provider_not_configured"
        assert registered_tool_requires_approval(name) is True


def test_missing_typed_input_blocks_before_policy_or_provider() -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )

    for name in MANUAL_GATED_CAPABILITY_NAMES:
        report = executor.run(name, ActionRequest(target=TARGET, execution_context=context))
        assert report.applicability.applicable is False
        assert any(
            item.startswith("blocked_by_input:typed_input:") for item in report.applicability.missing_requirements
        )
        assert report.policy_denials == []
        assert report.execution_result is None


def test_automatic_context_cannot_cross_manual_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.automatic(target_scope=(TARGET,))

    def forbidden(_request: ActionRequest) -> object:
        pytest.fail("manual-gated provider adapter was invoked")

    for name in MANUAL_GATED_CAPABILITY_NAMES:
        adapter = catalog.require(name).adapter
        monkeypatch.setattr(adapter, "execute", forbidden)
        request = _request(name, context, adapter.descriptor.required_preconditions)
        report = executor.run(name, request)
        assert report.applicability.applicable is True
        assert [item.reason_code for item in report.policy_denials] == ["manual_gate_requires_operator_context"]
        assert report.execution_result is None


def test_approved_context_reaches_provider_not_configured_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )

    def forbidden(_request: ActionRequest) -> object:
        pytest.fail("unmounted provider adapter was invoked")

    for name in MANUAL_GATED_CAPABILITY_NAMES:
        adapter = catalog.require(name).adapter
        monkeypatch.setattr(adapter, "execute", forbidden)
        request = _request(name, context, adapter.descriptor.required_preconditions)
        report = executor.run(name, request)
        assert report.applicability.applicable is True
        assert [item.reason_code for item in report.policy_denials] == ["provider_not_configured"]
        assert report.lifecycle.outcome.value == "blocked"
        assert report.execution_result is None


def test_every_manual_identity_enforces_explicit_target_scope_before_disabled_state() -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=("198.51.100.9",),
        allow_active_tools=True,
    )

    for name in MANUAL_GATED_CAPABILITY_NAMES:
        adapter = catalog.require(name).adapter
        request = _request(name, context, adapter.descriptor.required_preconditions)
        report = executor.run(name, request)
        assert report.applicability.applicable is True
        assert [item.reason_code for item in report.policy_denials] == ["target_out_of_scope"]
        assert report.execution_result is None


def test_dns_callback_endpoint_is_in_operator_scope() -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    adapter = catalog.require("dns_c2_channel").adapter
    facts, refs = _preconditions(adapter.descriptor.required_preconditions)
    request = ActionRequest(
        target=TARGET,
        execution_context=context,
        typed_input=C2ChannelInput(TARGET, "dns", "https://198.51.100.7/callback"),
        facts=facts,
        precondition_refs=refs,
    )

    report = executor.run("dns_c2_channel", request)
    assert report.applicability.applicable is True
    assert [item.reason_code for item in report.policy_denials] == ["target_out_of_scope"]
    assert report.execution_result is None


@pytest.mark.parametrize(
    ("fact_changes", "refs"),
    [
        ({"trust_level": None}, ("fact://1",)),
        ({"trust_level": None, "observation_method": "made_up"}, ("fact://1",)),
        (
            {
                "trust_level": None,
                "observations": ({"observation_method": "made_up"},),
            },
            ("fact://1",),
        ),
        ({"observations": ("garbage",)}, ("fact://1",)),
        (
            {
                "observations": (
                    {"trust_level": "trusted"},
                    "garbage",
                )
            },
            ("fact://1",),
        ),
        ({"assessment_status": "observed"}, ("fact://1",)),
        ({"host": "198.51.100.9"}, ("fact://1",)),
        ({"fact_ref": "fact://999"}, ("fact://1",)),
        ({}, ("fact://",)),
    ],
)
def test_preconditions_require_canonical_verified_trusted_target_bound_facts(
    fact_changes: dict[str, object],
    refs: tuple[str, ...],
) -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    fact = {
        "id": 1,
        "host": TARGET,
        "type": "confirmed_ad_access",
        "value": "confirmed",
        "assessment_status": "verified",
        "trust_level": "trusted",
        **fact_changes,
    }
    report = executor.run(
        "pass_the_hash",
        ActionRequest(
            target=TARGET,
            execution_context=context,
            typed_input=CredentialInput("credential://opaque", TARGET),
            facts=(fact,),
            precondition_refs=refs,
        ),
    )
    assert report.applicability.applicable is False
    assert report.policy_denials == []
    assert report.execution_result is None


def test_unmounted_payload_identity_does_not_depend_on_local_provider_packages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("core.actions.base.importlib.util.find_spec", lambda _name: None)
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    report = executor.run(
        "payload_keying",
        ActionRequest(
            target=TARGET,
            execution_context=context,
            typed_input=PayloadKeyingInput("artifact://payload"),
        ),
    )
    assert report.applicability.applicable is True
    assert [item.reason_code for item in report.policy_denials] == ["provider_not_configured"]
    assert report.execution_result is None


@pytest.mark.parametrize(
    ("action_name", "typed_input"),
    [
        ("pass_the_hash", CredentialInput("credential://opaque", "")),
        ("pivot_remote_forward", SessionInput("session://opaque", "")),
        ("ad_smbexec", RemoteExecInput("credential://opaque", "", "operation://inventory")),
    ],
)
def test_target_bearing_typed_inputs_cannot_omit_request_target_binding(
    action_name: str,
    typed_input: object,
) -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    report = executor.run(
        action_name,
        ActionRequest(target=TARGET, execution_context=context, typed_input=typed_input),
    )
    assert report.applicability.applicable is False
    assert "blocked_by_input:typed_input_target" in report.applicability.missing_requirements


def test_invalid_nested_pivot_target_fails_closed_without_exception() -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    report = executor.run(
        "pivot_proxy_scan",
        ActionRequest(
            target=TARGET,
            execution_context=context,
            typed_input=PivotRouteInput("fact://1", None),  # type: ignore[arg-type]
        ),
    )
    assert report.applicability.applicable is False
    assert "blocked_by_input:scan_target" in report.applicability.missing_requirements


@pytest.mark.parametrize(
    ("action_name", "typed_input", "expected_reason"),
    [
        (
            "ad_smbexec",
            RemoteExecInput("credential://opaque", TARGET, 123),  # type: ignore[arg-type]
            "blocked_by_input:command",
        ),
        (
            "dns_c2_channel",
            C2ChannelInput(TARGET, 123),  # type: ignore[arg-type]
            "blocked_by_input:transport_type",
        ),
        (
            "payload_keying",
            PayloadKeyingInput("artifact://payload", []),  # type: ignore[arg-type]
            "blocked_by_input:keying_parameters",
        ),
        (
            "pivot_ssh_chain",
            CredentialInput("credential://opaque", TARGET, []),  # type: ignore[arg-type]
            "blocked_by_input:service",
        ),
        (
            "ad_smbexec",
            RemoteExecInput(
                "credential://opaque",
                TARGET,
                "operation://inventory",
                {},  # type: ignore[arg-type]
            ),
            "blocked_by_input:service",
        ),
    ],
)
def test_typed_contract_field_types_fail_closed(
    action_name: str,
    typed_input: object,
    expected_reason: str,
) -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    adapter = catalog.require(action_name).adapter
    facts, refs = _preconditions(adapter.descriptor.required_preconditions)
    report = executor.run(
        action_name,
        ActionRequest(
            target=TARGET,
            execution_context=context,
            typed_input=typed_input,
            facts=facts,
            precondition_refs=refs,
        ),
    )
    assert report.applicability.applicable is False
    assert expected_reason in report.applicability.missing_requirements


def test_malformed_observation_container_fails_closed_without_exception() -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    report = executor.run(
        "pass_the_hash",
        ActionRequest(
            target=TARGET,
            execution_context=context,
            typed_input=CredentialInput("credential://opaque", TARGET),
            facts=(
                {
                    "id": 1,
                    "host": TARGET,
                    "type": "confirmed_ad_access",
                    "assessment_status": "verified",
                    "trust_level": "trusted",
                    "observations": 7,
                },
            ),
            precondition_refs=("fact://1",),
        ),
    )
    assert report.applicability.applicable is False
    assert report.policy_denials == []


def test_one_fact_reference_cannot_satisfy_multiple_precondition_types() -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    common = {
        "id": 1,
        "host": TARGET,
        "value": "confirmed",
        "assessment_status": "verified",
        "trust_level": "trusted",
    }
    report = executor.run(
        "kerberos_extract_tickets",
        ActionRequest(
            target=TARGET,
            execution_context=context,
            typed_input=SessionInput("session://opaque", TARGET),
            facts=(
                {**common, "type": "confirmed_windows_access"},
                {**common, "type": "ad_environment_detected"},
            ),
            precondition_refs=("fact://1",),
        ),
    )
    assert report.applicability.applicable is False
    assert report.policy_denials == []


@pytest.mark.parametrize("action_name", ["kerberos_crack_tickets", "c2_enroll", "payload_keying"])
@pytest.mark.parametrize("invalid_target", ["http://", "@@", "--bad", "[]", "ssh://user:pass@host"])
def test_optional_explicit_targets_are_syntactically_validated(
    action_name: str,
    invalid_target: str,
) -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=("host",),
        allow_active_tools=True,
    )
    typed_input: object
    if action_name == "kerberos_crack_tickets":
        typed_input = TicketInput("ticket://opaque", invalid_target)
    elif action_name == "c2_enroll":
        typed_input = C2EnrollmentInput("c2-enrollment://opaque", invalid_target)
    else:
        typed_input = PayloadKeyingInput("artifact://payload")
    report = executor.run(
        action_name,
        ActionRequest(
            target=invalid_target,
            execution_context=context,
            typed_input=typed_input,
        ),
    )
    assert report.applicability.applicable is True
    assert len(report.policy_denials) == 1
    assert report.policy_denials[0].reason_code == "invalid_target"
    assert report.execution_result is None


def test_pivot_route_reference_must_bind_the_confirmed_pivot_fact() -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    common = {
        "host": TARGET,
        "value": "confirmed",
        "assessment_status": "verified",
        "trust_level": "trusted",
    }
    report = executor.run(
        "pivot_proxy_scan",
        ActionRequest(
            target=TARGET,
            execution_context=context,
            typed_input=PivotRouteInput("fact://2", ScanTarget(TARGET)),
            facts=(
                {**common, "id": 1, "type": "confirmed_pivot"},
                {**common, "id": 2, "type": "web_title"},
            ),
            precondition_refs=("fact://1", "fact://2"),
        ),
    )
    assert report.applicability.applicable is False
    assert "blocked_by_precondition:pivot_route_ref" in report.applicability.missing_requirements
    assert report.policy_denials == []


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [("facts", None), ("precondition_refs", None)],
)
def test_malformed_action_request_containers_fail_closed(
    field_name: str,
    field_value: object,
) -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    values: dict[str, object] = {
        "target": TARGET,
        "execution_context": context,
        "typed_input": CredentialInput("credential://opaque", TARGET),
        "facts": (),
        "precondition_refs": (),
        field_name: field_value,
    }
    report = executor.run("pass_the_hash", ActionRequest(**values))  # type: ignore[arg-type]
    assert report.applicability.applicable is False
    assert f"blocked_by_input:request_shape:{field_name}" in report.applicability.missing_requirements
    assert report.policy_denials == []


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("actor", None),
        ("origin", []),
        ("approval_id", None),
        ("capabilities", None),
        ("target_scope", None),
    ],
)
def test_malformed_execution_context_fields_fail_closed(
    field_name: str,
    field_value: object,
) -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    good_context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    context = replace(good_context, **{field_name: field_value})
    facts, refs = _preconditions(("confirmed_ad_access",))
    report = executor.run(
        "pass_the_hash",
        ActionRequest(
            target=TARGET,
            execution_context=context,
            typed_input=CredentialInput("credential://opaque", TARGET),
            facts=facts,
            precondition_refs=refs,
        ),
    )
    assert report.applicability.applicable is False
    assert f"blocked_by_input:execution_context_shape:{field_name}" in report.applicability.missing_requirements
    assert report.policy_denials == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda request: {"parameters": {"creds": "plaintext"}},
        lambda request: {"handle": object()},
        lambda request: {"command": "pass_the_hash 192.0.2.10"},
        lambda request: {"provider_commands": {"pass_the_hash": "pass_the_hash 192.0.2.10"}},
    ],
)
def test_raw_bypass_surfaces_are_rejected(
    mutate: Callable[[ActionRequest], dict[str, object]],
) -> None:
    catalog = _catalog()
    executor = ActionExecutor(catalog, ExecutionPolicy())
    context = ExecutionContext.operator(
        actor="operator",
        approval_id="approval",
        target_scope=(TARGET,),
        allow_active_tools=True,
    )
    adapter = catalog.require("pass_the_hash").adapter
    base = _request("pass_the_hash", context, adapter.descriptor.required_preconditions)
    values = {
        "target": base.target,
        "execution_context": base.execution_context,
        "typed_input": base.typed_input,
        "facts": base.facts,
        "precondition_refs": base.precondition_refs,
        **mutate(base),
    }
    report = executor.run("pass_the_hash", ActionRequest(**values))
    assert report.applicability.applicable is False
    assert any(
        item in {"blocked_by_input:ambient_handle", "blocked_by_input:typed_input_only"}
        for item in report.applicability.missing_requirements
    )
