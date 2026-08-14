"""Canonical V2 Action Semantic Bindings Matrix (§2.5)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from core.actions.models import ActionKind, CheckPolicyV2, VerifyPolicyV2
from core.actions.provider_state import ExecutionNodeKind


@dataclass(frozen=True)
class V2ActionSemanticBinding:
    action_id: str
    name: str
    aliases: tuple[str, ...]
    kind: ActionKind
    execution_node_kind: ExecutionNodeKind
    capability_class: str
    risk_class: str
    required_fact_type_ids: tuple[str, ...]
    killchain_stage: str
    manual_gate: Literal[True]
    check_policy: Literal[CheckPolicyV2.REQUIRED]
    verify_policy: Literal[VerifyPolicyV2.REQUIRED]


_V2_SEMANTIC_BINDING_MATRIX: tuple[V2ActionSemanticBinding, ...] = (
    V2ActionSemanticBinding(
        action_id="plugin:payload_keying",
        name="Payload Keying",
        aliases=(),
        kind=ActionKind.PLUGIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="evasion",
        risk_class="high",
        required_fact_type_ids=(),
        killchain_stage="weaponization",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:kerberos_extract_tickets",
        name="Extract Kerberos Tickets",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="credential_extraction",
        risk_class="high",
        required_fact_type_ids=("confirmed_windows_access", "ad_environment_detected"),
        killchain_stage="credential_access",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:kerberos_crack_tickets",
        name="Crack Kerberos Tickets",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="credential_extraction",
        risk_class="high",
        required_fact_type_ids=(),
        killchain_stage="credential_access",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:ad_pass_the_ticket",
        name="AD Pass-the-Ticket",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="lateral_movement",
        risk_class="critical",
        required_fact_type_ids=("confirmed_ad_access",),
        killchain_stage="lateral_movement",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:pass_the_hash",
        name="Pass-the-Hash",
        aliases=("pth",),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="lateral_movement",
        risk_class="critical",
        required_fact_type_ids=("confirmed_ad_access",),
        killchain_stage="lateral_movement",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:ad_dump_lsass",
        name="Dump LSASS Memory",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="credential_extraction",
        risk_class="critical",
        required_fact_type_ids=("confirmed_windows_access",),
        killchain_stage="credential_access",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:ad_sam_dump",
        name="Dump SAM Hashes",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="credential_extraction",
        risk_class="critical",
        required_fact_type_ids=("confirmed_windows_access",),
        killchain_stage="credential_access",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:ad_smbexec",
        name="AD SMBExec",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="lateral_movement",
        risk_class="critical",
        required_fact_type_ids=("confirmed_ad_access", "smb_service_available"),
        killchain_stage="lateral_movement",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:ad_winrm_exec",
        name="AD WinRM Exec",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="lateral_movement",
        risk_class="critical",
        required_fact_type_ids=("confirmed_ad_access", "winrm_service_available"),
        killchain_stage="lateral_movement",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:ad_dcom_exec",
        name="AD DCOM Exec",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="lateral_movement",
        risk_class="critical",
        required_fact_type_ids=("confirmed_ad_access", "dcom_service_available"),
        killchain_stage="lateral_movement",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:ad_remote_execution",
        name="AD Remote Execution Composite Router",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.COMPOSITE_ROUTER,
        capability_class="lateral_movement",
        risk_class="critical",
        required_fact_type_ids=("confirmed_ad_access",),
        killchain_stage="lateral_movement",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:pivot_remote_forward",
        name="Pivot Remote Port Forwarding",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="pivot",
        risk_class="high",
        required_fact_type_ids=("confirmed_ssh_access",),
        killchain_stage="lateral_movement",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:pivot_ssh_chain",
        name="Pivot SSH Chain",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="pivot",
        risk_class="high",
        required_fact_type_ids=("confirmed_ssh_access",),
        killchain_stage="lateral_movement",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="killchain:pivot_proxy_scan",
        name="Pivot Proxy Scan",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="pivot",
        risk_class="medium",
        required_fact_type_ids=("confirmed_pivot",),
        killchain_stage="lateral_movement",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="c2:dns_c2_channel",
        name="DNS C2 Channel",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="c2",
        risk_class="critical",
        required_fact_type_ids=("approved_c2_scope",),
        killchain_stage="command_and_control",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="c2:c2_enroll",
        name="C2 Agent Enrollment",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="c2",
        risk_class="critical",
        required_fact_type_ids=("approved_c2_scope",),
        killchain_stage="command_and_control",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="c2:c2_deploy",
        name="C2 Agent Deployment",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="c2",
        risk_class="critical",
        required_fact_type_ids=("confirmed_target_access", "c2_channel_authorized"),
        killchain_stage="command_and_control",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="c2:c2_channel_create",
        name="C2 Channel Router",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.COMPOSITE_ROUTER,
        capability_class="c2",
        risk_class="critical",
        required_fact_type_ids=("approved_c2_scope",),
        killchain_stage="command_and_control",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="c2:c2_task",
        name="C2 Task Execution",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="c2",
        risk_class="high",
        required_fact_type_ids=("c2_agent_enrolled",),
        killchain_stage="command_and_control",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
    V2ActionSemanticBinding(
        action_id="c2:c2_cleanup",
        name="C2 Cleanup",
        aliases=(),
        kind=ActionKind.KILLCHAIN,
        execution_node_kind=ExecutionNodeKind.LEAF,
        capability_class="c2",
        risk_class="medium",
        required_fact_type_ids=(),
        killchain_stage="command_and_control",
        manual_gate=True,
        check_policy=CheckPolicyV2.REQUIRED,
        verify_policy=VerifyPolicyV2.REQUIRED,
    ),
)

_SEMANTIC_BINDING_MAP: dict[str, V2ActionSemanticBinding] = {
    binding.action_id: binding for binding in _V2_SEMANTIC_BINDING_MATRIX
}

_ALIAS_MAP: dict[str, str] = {}
for _binding in _V2_SEMANTIC_BINDING_MATRIX:
    for _alias in _binding.aliases:
        _ALIAS_MAP[_alias] = _binding.action_id


def get_v2_semantic_binding(action_id: str) -> V2ActionSemanticBinding:
    # Resolve alias first if present
    canonical_id = _ALIAS_MAP.get(action_id, action_id)
    if canonical_id not in _SEMANTIC_BINDING_MAP:
        raise KeyError(f"Action ID '{action_id}' has no registered V2 semantic binding")
    return _SEMANTIC_BINDING_MAP[canonical_id]


def resolve_action_id_alias(alias_or_id: str) -> str:
    return _ALIAS_MAP.get(alias_or_id, alias_or_id)


def get_all_v2_semantic_bindings() -> tuple[V2ActionSemanticBinding, ...]:
    return _V2_SEMANTIC_BINDING_MATRIX


__all__ = [
    "V2ActionSemanticBinding",
    "get_all_v2_semantic_bindings",
    "get_v2_semantic_binding",
    "resolve_action_id_alias",
]
