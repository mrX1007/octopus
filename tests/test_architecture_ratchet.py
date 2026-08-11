"""Architecture ratchet tests for OCTOPUS capability unification (Phase 5.1).

This module enforces architecture ratchet invariants:
1. Every production capability has a registered canonical action in ActionCatalog.
2. Each capability has a declared input contract or profile.
3. Each capability has policy classification (capability_class, risk_class).
4. No production capability is stranded in quarantine without being backed by a canonical adapter.
5. All 96 canonical tools resolve correctly through ActionCatalog and ActionExecutor.
"""

from __future__ import annotations

import pytest

from core.actions import (
    ActionAdapter,
    ActionExecutor,
    ActionKind,
    ActionRequest,
    ActiveRiskClass,
    build_action_catalog,
)
from core.actions.adapters_ad_credential import (
    ADDumpLsassAdapter,
    ADPassTheTicketAdapter,
    ADSamDumpAdapter,
    PassTheHashAdapter,
)
from core.actions.adapters_ad_lateral import (
    ADDcomExecAdapter,
    ADRemoteExecutionCapabilityAdapter,
    ADSmbexecAdapter,
    ADWinrmExecAdapter,
)
from core.actions.adapters_c2 import (
    C2ChannelCreateAdapter,
    C2CleanupAdapter,
    C2DeployAdapter,
    C2EnrollAdapter,
    C2TaskAdapter,
    DNSC2ChannelAdapter,
)
from core.actions.adapters_evasion import PayloadKeyingAdapter
from core.actions.adapters_kerberos import (
    KerberosCrackTicketsAdapter,
    KerberosExtractTicketsAdapter,
)
from core.actions.adapters_pivot import (
    PivotProxyScanAdapter,
    PivotRemoteForwardAdapter,
    PivotSSHChainAdapter,
)
from core.actions.input_contracts import (
    C2ChannelInput,
    CredentialInput,
    PayloadKeyingInput,
    PivotRouteInput,
    RemoteExecInput,
    SessionInput,
    TicketInput,
)
from core.ai.tool_registry import ToolRegistry
from core.execution import ExecutionContext, ExecutionPolicy
from core.execution.policy import registered_tool_requires_approval
from core.tools.quarantined import (
    MANUAL_GATED_CAPABILITY_NAMES,
    QUARANTINED_CAPABILITY_NAMES,
)
from core.tools.registry import list_tools

pytestmark = [pytest.mark.contract, pytest.mark.security]

EXPECTED_ENABLED_TOOL_COUNT = 96
EXPECTED_TOTAL_TOOL_COUNT = 116


def _approved_context(target: str = "192.0.2.10") -> ExecutionContext:
    return ExecutionContext.operator(
        actor="ratchet-test",
        approval_id="ratchet-approval-1",
        target_scope=(target,),
        allow_active_tools=True,
    )


def test_every_production_capability_has_registered_canonical_action() -> None:
    """Requirement 1: Every production capability has a registered canonical action in ActionCatalog."""
    tools = list_tools()
    assert len(tools) == EXPECTED_TOTAL_TOOL_COUNT, (
        f"Expected {EXPECTED_TOTAL_TOOL_COUNT} registered tools, got {len(tools)}"
    )

    catalog = build_action_catalog(lambda _cmd, _ctx: "ok", tool_defs=tools)
    assert len(catalog) >= EXPECTED_TOTAL_TOOL_COUNT

    # Verify that every tool in registry resolves to a canonical action in ActionCatalog
    for tool_def in tools:
        resolved = catalog.resolve(tool_def.name)
        assert resolved is not None, f"Tool {tool_def.name} failed to resolve in ActionCatalog"
        assert resolved.canonical_id != "", f"Tool {tool_def.name} has empty canonical_id"
        assert isinstance(resolved.adapter, ActionAdapter)

        descriptor = resolved.adapter.descriptor
        assert descriptor.action_id != ""
        assert descriptor.name != ""
        assert isinstance(descriptor.kind, ActionKind)
        assert descriptor.provider != ""

    # Verify canonical adapters pre-registered in ActionCatalog
    canonical_action_ids = (
        "killchain:pivot_remote_forward",
        "killchain:pivot_ssh_chain",
        "killchain:pivot_proxy_scan",
        "killchain:kerberos_extract_tickets",
        "killchain:kerberos_crack_tickets",
        "killchain:ad_pass_the_ticket",
        "killchain:pass_the_hash",
        "killchain:ad_dump_lsass",
        "killchain:ad_sam_dump",
        "killchain:ad_smbexec",
        "killchain:ad_winrm_exec",
        "killchain:ad_dcom_exec",
        "killchain:ad_remote_execution",
        "c2:dns_c2_channel",
        "c2:c2_enroll",
        "c2:c2_deploy",
        "c2:c2_channel_create",
        "c2:c2_task",
        "c2:c2_cleanup",
        "plugin:payload_keying",
    )
    for action_id in canonical_action_ids:
        resolved = catalog.resolve(action_id)
        assert resolved is not None, f"Canonical adapter {action_id} not resolvable in ActionCatalog"
        assert resolved.canonical_id == action_id
        assert isinstance(resolved.adapter, ActionAdapter)


def test_each_capability_has_declared_input_contract_or_profile() -> None:
    """Requirement 2: Each capability has a declared input contract or profile."""
    tools = list_tools()
    catalog = build_action_catalog(lambda _cmd, _ctx: "ok", tool_defs=tools)

    # 1. Action descriptors have an input_type attribute (type or None)
    for descriptor in catalog.descriptors():
        assert hasattr(descriptor, "input_type"), f"Descriptor {descriptor.action_id} missing input_type attribute"
        input_type = descriptor.input_type
        assert input_type is None or isinstance(input_type, type), (
            f"Descriptor {descriptor.action_id} input_type must be a type or None, got {input_type}"
        )

    # 2. Canonical adapters have explicit non-None input contracts
    canonical_input_mappings = {
        ADSmbexecAdapter(): RemoteExecInput,
        ADWinrmExecAdapter(): RemoteExecInput,
        ADDcomExecAdapter(): RemoteExecInput,
        DNSC2ChannelAdapter(): C2ChannelInput,
        PayloadKeyingAdapter(): PayloadKeyingInput,
        PivotRemoteForwardAdapter(): SessionInput,
        PivotSSHChainAdapter(): CredentialInput,
        PivotProxyScanAdapter(): PivotRouteInput,
        KerberosExtractTicketsAdapter(): SessionInput,
        KerberosCrackTicketsAdapter(): TicketInput,
        ADPassTheTicketAdapter(): TicketInput,
        PassTheHashAdapter(): CredentialInput,
        ADDumpLsassAdapter(): SessionInput,
        ADSamDumpAdapter(): SessionInput,
    }
    for adapter, expected_contract in canonical_input_mappings.items():
        assert adapter.input_type is expected_contract, (
            f"Adapter {adapter.descriptor.name} expected input contract {expected_contract}, got {adapter.input_type}"
        )

    # 3. Tool registry definitions have valid dependency manifests / expressions
    for tool_def in tools:
        manifest = tool_def.dependency_manifest()
        assert isinstance(manifest, dict), f"Tool {tool_def.name} manifest must be a dict"
        assert "kind" in manifest or set(manifest) >= {"mode", "items"}

    # 4. AI tool registry task profiles exist and are complete
    ai_registry = ToolRegistry()
    for task, profile in ai_registry.task_profiles.items():
        assert "cost" in profile, f"Task {task} profile missing cost"
        assert "time" in profile, f"Task {task} profile missing time"
        assert "risk" in profile, f"Task {task} profile missing risk"
        assert "preconditions" in profile, f"Task {task} profile missing preconditions"


def test_each_capability_has_policy_classification() -> None:
    """Requirement 3: Each capability has policy classification (capability_class, risk_class)."""
    tools = list_tools()
    catalog = build_action_catalog(lambda _cmd, _ctx: "ok", tool_defs=tools)
    ctx = _approved_context("192.0.2.10")
    req = ActionRequest(target="192.0.2.10", execution_context=ctx)

    valid_capability_classes = {
        "recon",
        "exploit",
        "post",
        "lateral_movement",
        "c2",
        "evasion",
        "pivot",
        "credential_extraction",
        "osint",
        "util",
        "post_access",
        "",
    }

    for descriptor in catalog.descriptors():
        assert hasattr(descriptor, "capability_class"), f"Descriptor {descriptor.action_id} missing capability_class"
        assert hasattr(descriptor, "risk_class"), f"Descriptor {descriptor.action_id} missing risk_class"
        assert isinstance(descriptor.capability_class, str)
        assert isinstance(descriptor.risk_class, str)

        adapter = catalog.require(descriptor.action_id).adapter
        assert isinstance(adapter.capability_class, str)
        assert isinstance(adapter.risk_class, str)
        assert adapter.capability_class == descriptor.capability_class
        assert adapter.risk_class == descriptor.risk_class

        active_risk = adapter.active_risk_class(req)
        assert isinstance(active_risk, ActiveRiskClass)

    # Canonical adapters policy classification checks
    canonical_adapters = (
        ADSmbexecAdapter(),
        ADWinrmExecAdapter(),
        ADDcomExecAdapter(),
        ADRemoteExecutionCapabilityAdapter(),
        DNSC2ChannelAdapter(),
        C2EnrollAdapter(),
        C2DeployAdapter(),
        C2ChannelCreateAdapter(),
        C2TaskAdapter(),
        C2CleanupAdapter(),
        PayloadKeyingAdapter(),
        PivotProxyScanAdapter(),
        PivotRemoteForwardAdapter(),
        PivotSSHChainAdapter(),
        KerberosExtractTicketsAdapter(),
        KerberosCrackTicketsAdapter(),
        ADPassTheTicketAdapter(),
        PassTheHashAdapter(),
        ADDumpLsassAdapter(),
        ADSamDumpAdapter(),
    )
    for adapter in canonical_adapters:
        assert adapter.capability_class in valid_capability_classes, (
            f"Adapter {adapter.descriptor.name} has invalid capability_class '{adapter.capability_class}'"
        )
        assert adapter.capability_class != "", (
            f"Canonical adapter {adapter.descriptor.name} must have a non-empty capability_class"
        )
        assert adapter.risk_class in ("low", "medium", "high", "critical"), (
            f"Canonical adapter {adapter.descriptor.name} has invalid risk_class '{adapter.risk_class}'"
        )

    # Verify registered tool approval check operates cleanly on all tool names
    for tool_def in tools:
        res = registered_tool_requires_approval(tool_def.name)
        assert isinstance(res, bool)


def test_manual_gated_capabilities_are_not_quarantined_and_have_canonical_adapters() -> None:
    """Requirement 4: manual identities are explicit, canonical, and fail closed."""
    tools = list_tools()
    catalog = build_action_catalog(lambda _cmd, _ctx: "ok", tool_defs=tools)
    disabled_tools = [tool_def for tool_def in tools if not tool_def.enabled]
    assert {tool_def.name for tool_def in disabled_tools} == set(MANUAL_GATED_CAPABILITY_NAMES)
    assert QUARANTINED_CAPABILITY_NAMES == ()
    for tool_def in disabled_tools:
        assert tool_def.disabled_reason == "provider_not_configured"
        resolved = catalog.resolve(tool_def.name)
        assert resolved is not None
        assert resolved.adapter.descriptor.manual_gate is True
        assert resolved.adapter.descriptor.provider_mounted is False


def test_all_96_canonical_tools_resolve_through_action_catalog_and_executor() -> None:
    """Requirement 5: All 96 canonical tools resolve correctly through ActionCatalog and ActionExecutor."""
    tools = list_tools()
    enabled_tools = [tool_def for tool_def in tools if tool_def.enabled]

    assert len(enabled_tools) == EXPECTED_ENABLED_TOOL_COUNT, (
        f"Expected exactly {EXPECTED_ENABLED_TOOL_COUNT} enabled canonical tools, got {len(enabled_tools)}"
    )

    catalog = build_action_catalog(lambda _cmd, _ctx: "succeeded", tool_defs=tools)
    executor = ActionExecutor(catalog, ExecutionPolicy())

    for tool_def in enabled_tools:
        # Resolve by canonical name
        resolved = catalog.resolve(tool_def.name)
        assert resolved is not None, f"Enabled tool {tool_def.name} failed to resolve in ActionCatalog"
        expected_prefix = "killchain" if tool_def.name.startswith("killchain_") else "tool"
        assert resolved.canonical_id == f"{expected_prefix}:{tool_def.name}"
        assert resolved.alias_used is False, f"Canonical name {tool_def.name} should not be flagged as alias"
        assert resolved.requested_name == tool_def.name

        # Require by canonical name
        required = catalog.require(tool_def.name)
        assert required.adapter is resolved.adapter

        # Check descriptor kind
        descriptor = required.adapter.descriptor
        assert descriptor.kind in (ActionKind.REGISTERED_TOOL, ActionKind.KILLCHAIN)

        # Resolve all aliases and verify alias resolution back to canonical_id
        for alias in tool_def.aliases:
            alias_resolved = catalog.resolve(alias)
            assert alias_resolved is not None, f"Alias '{alias}' of tool {tool_def.name} failed to resolve"
            assert alias_resolved.canonical_id == resolved.canonical_id, (
                f"Alias '{alias}' resolved to '{alias_resolved.canonical_id}' instead of '{resolved.canonical_id}'"
            )
            assert alias_resolved.adapter is resolved.adapter
            assert alias_resolved.alias_used is True

        # Verify ActionExecutor can inspect and policy-authorize invocation for the canonical tool
        req = ActionRequest(
            target="192.0.2.10",
            execution_context=_approved_context("192.0.2.10"),
            command=f"{tool_def.name} 192.0.2.10" if tool_def.needs_target else tool_def.name,
        )
        decision = required.adapter.authorize(executor.policy, req, phase="execute")
        assert decision is not None
