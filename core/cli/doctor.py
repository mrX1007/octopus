"""Provider doctor view with static rollout and dynamic readiness kept separate."""

from __future__ import annotations

from dataclasses import dataclass

from core.actions.canonical_state import CanonicalActionState, CanonicalActionStaticState
from core.actions.models import ActionDescriptorV2
from core.actions.provider_mounts import (
    DefaultProviderMountRegistry,
    get_provider_mount_registry,
)
from core.actions.readiness import ProviderReadinessSnapshot
from core.actions.readiness_registry import ReadinessRegistry, get_readiness_registry
from core.actions.schema_bindings import get_v2_schema_binding
from core.actions.semantic_bindings import get_v2_semantic_binding


@dataclass(frozen=True)
class ProviderDoctorRow:
    provider_id: str
    action_id: str
    configured: bool
    mounted: bool
    available: bool
    typed: bool
    raw: bool
    manual_gate: bool
    readiness: ProviderReadinessSnapshot


@dataclass(frozen=True)
class ActionDoctorReport:
    total_v2_actions: int
    configured_count: int
    mounted_count: int
    available_count: int
    action_states: tuple[CanonicalActionState, ...]

    @property
    def provider_rows(self) -> tuple[ProviderDoctorRow, ...]:
        return tuple(
            ProviderDoctorRow(
                provider_id=state.static.mount.spec.provider_owner,
                action_id=state.static.descriptor.action_id,
                configured=state.static.mount.spec.configured,
                mounted=state.static.mount.spec.mounted,
                available=state.readiness.available,
                typed=state.static.mount.spec.typed_action_supported,
                raw=state.static.mount.spec.raw_command_supported,
                manual_gate=state.static.descriptor.manual_gate,
                readiness=state.readiness,
            )
            for state in self.action_states
        )


def _project_descriptor(action_id: str) -> ActionDescriptorV2:
    semantic = get_v2_semantic_binding(action_id)
    schema = get_v2_schema_binding(action_id)
    return ActionDescriptorV2(
        schema_version="2.0",
        action_id=semantic.action_id,
        name=semantic.name,
        aliases=semantic.aliases,
        input_schema_id=schema.input_schema_id,
        result_schema_id=schema.result_schema_id,
        kind=semantic.kind,
        execution_node_kind=semantic.execution_node_kind,
        capability_class=semantic.capability_class,
        risk_class=semantic.risk_class,
        required_fact_type_ids=semantic.required_fact_type_ids,
        killchain_stage=semantic.killchain_stage,
        manual_gate=semantic.manual_gate,
        check_policy=semantic.check_policy,
        verify_policy=semantic.verify_policy,
    )


def run_action_doctor(
    *,
    mount_registry: DefaultProviderMountRegistry | None = None,
    readiness_registry: ReadinessRegistry | None = None,
) -> ActionDoctorReport:
    mounts = mount_registry or get_provider_mount_registry()
    readiness = readiness_registry or get_readiness_registry()

    states: list[CanonicalActionState] = []
    for mount in mounts.snapshots():
        descriptor = _project_descriptor(mount.spec.action_id)
        static = CanonicalActionStaticState(descriptor=descriptor, mount=mount)
        readiness_snapshot = readiness.probe(mount)
        states.append(CanonicalActionState(static=static, readiness=readiness_snapshot))

    action_states = tuple(states)
    return ActionDoctorReport(
        total_v2_actions=len(action_states),
        configured_count=sum(state.static.mount.spec.configured for state in action_states),
        mounted_count=sum(state.static.mount.spec.mounted for state in action_states),
        available_count=sum(state.readiness.available for state in action_states),
        action_states=action_states,
    )


def render_provider_doctor(report: ActionDoctorReport) -> str:
    """Render only environment/mount facts; request authorization is not inferred."""

    headings = ("Provider", "Configured", "Mounted", "Available", "Typed", "Raw", "ManualGate")
    rows = [
        (
            row.provider_id,
            _yes_no(row.configured),
            _yes_no(row.mounted),
            _yes_no(row.available),
            _yes_no(row.typed),
            _yes_no(row.raw),
            _yes_no(row.manual_gate),
        )
        for row in report.provider_rows
    ]
    widths = [max(len(headings[index]), *(len(row[index]) for row in rows)) for index in range(len(headings))]
    rendered = [" ".join(value.ljust(widths[index]) for index, value in enumerate(headings))]
    rendered.extend(" ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows)
    return "\n".join(rendered)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


__all__ = [
    "ActionDoctorReport",
    "ProviderDoctorRow",
    "render_provider_doctor",
    "run_action_doctor",
]
