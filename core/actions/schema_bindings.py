"""Canonical V2 Action Schema Bindings Matrix (§2.4)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class V2ActionSchemaBinding:
    action_id: str
    input_schema_id: str
    result_schema_id: str


_V2_SCHEMA_BINDING_MATRIX: tuple[V2ActionSchemaBinding, ...] = (
    V2ActionSchemaBinding(
        action_id="plugin:payload_keying",
        input_schema_id="octopus:input:payload_keying:2.0",
        result_schema_id="octopus:result:payload_keying:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:kerberos_extract_tickets",
        input_schema_id="octopus:input:kerberos_extract_tickets:2.0",
        result_schema_id="octopus:result:kerberos_extract_tickets:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:kerberos_crack_tickets",
        input_schema_id="octopus:input:kerberos_crack_tickets:2.0",
        result_schema_id="octopus:result:kerberos_crack_tickets:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:ad_pass_the_ticket",
        input_schema_id="octopus:input:ad_pass_the_ticket:2.0",
        result_schema_id="octopus:result:ad_pass_the_ticket:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:pass_the_hash",
        input_schema_id="octopus:input:pass_the_hash:2.0",
        result_schema_id="octopus:result:pass_the_hash:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:ad_dump_lsass",
        input_schema_id="octopus:input:ad_dump_lsass:2.0",
        result_schema_id="octopus:result:ad_dump_lsass:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:ad_sam_dump",
        input_schema_id="octopus:input:ad_sam_dump:2.0",
        result_schema_id="octopus:result:ad_sam_dump:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:ad_smbexec",
        input_schema_id="octopus:input:ad_smbexec:2.0",
        result_schema_id="octopus:result:ad_smbexec:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:ad_winrm_exec",
        input_schema_id="octopus:input:ad_winrm_exec:2.0",
        result_schema_id="octopus:result:ad_winrm_exec:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:ad_dcom_exec",
        input_schema_id="octopus:input:ad_dcom_exec:2.0",
        result_schema_id="octopus:result:ad_dcom_exec:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:ad_remote_execution",
        input_schema_id="octopus:input:ad_remote_execution:2.0",
        result_schema_id="octopus:result:ad_remote_execution:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:pivot_remote_forward",
        input_schema_id="octopus:input:pivot_remote_forward:2.0",
        result_schema_id="octopus:result:pivot_remote_forward:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:pivot_ssh_chain",
        input_schema_id="octopus:input:pivot_ssh_chain:2.0",
        result_schema_id="octopus:result:pivot_ssh_chain:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="killchain:pivot_proxy_scan",
        input_schema_id="octopus:input:pivot_proxy_scan:2.0",
        result_schema_id="octopus:result:pivot_proxy_scan:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="c2:dns_c2_channel",
        input_schema_id="octopus:input:dns_c2_channel:2.0",
        result_schema_id="octopus:result:dns_c2_channel:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="c2:c2_enroll",
        input_schema_id="octopus:input:c2_enroll:2.0",
        result_schema_id="octopus:result:c2_enroll:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="c2:c2_deploy",
        input_schema_id="octopus:input:c2_deploy:3.0",
        result_schema_id="octopus:result:c2_deploy:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="c2:c2_channel_create",
        input_schema_id="octopus:input:c2_channel_create:2.0",
        result_schema_id="octopus:result:c2_channel_create:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="c2:c2_task",
        input_schema_id="octopus:input:c2_task:2.0",
        result_schema_id="octopus:result:c2_task:2.0",
    ),
    V2ActionSchemaBinding(
        action_id="c2:c2_cleanup",
        input_schema_id="octopus:input:c2_cleanup:2.0",
        result_schema_id="octopus:result:c2_cleanup:2.0",
    ),
)

_SCHEMA_BINDING_MAP: dict[str, V2ActionSchemaBinding] = {
    binding.action_id: binding for binding in _V2_SCHEMA_BINDING_MATRIX
}

_INPUT_SCHEMA_BINDING_MAP: dict[str, V2ActionSchemaBinding] = {
    binding.input_schema_id: binding for binding in _V2_SCHEMA_BINDING_MATRIX
}


def get_v2_schema_binding(action_id: str) -> V2ActionSchemaBinding:
    if action_id not in _SCHEMA_BINDING_MAP:
        raise KeyError(f"Action ID '{action_id}' has no registered V2 schema binding")
    return _SCHEMA_BINDING_MAP[action_id]


def get_v2_schema_binding_by_input_schema(input_schema_id: str) -> V2ActionSchemaBinding:
    if input_schema_id not in _INPUT_SCHEMA_BINDING_MAP:
        raise KeyError(f"Input schema ID '{input_schema_id}' has no registered V2 schema binding")
    return _INPUT_SCHEMA_BINDING_MAP[input_schema_id]


def get_all_v2_schema_bindings() -> tuple[V2ActionSchemaBinding, ...]:
    return _V2_SCHEMA_BINDING_MATRIX


__all__ = [
    "V2ActionSchemaBinding",
    "get_all_v2_schema_bindings",
    "get_v2_schema_binding",
    "get_v2_schema_binding_by_input_schema",
]
