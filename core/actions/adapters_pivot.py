"""Action adapters for pivoting capabilities."""

from __future__ import annotations

from core.execution import ToolInvocation
from core.execution.policy import parse_invocation

from .base import ManualGatedActionAdapter
from .input_contracts import CredentialInput, PivotRouteInput, SessionInput
from .models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)


class PivotRemoteForwardAdapter(ManualGatedActionAdapter):
    """Адаптер действия для настройки удаленного форвардинга портов через SSH."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:pivot_remote_forward",
            name="pivot_remote_forward",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.pivot:setup_remote_forward",
            category="pivot",
            description="Setup SSH remote port forwarding",
            input_type=SessionInput,
            capability_class="pivot",
            risk_class="high",
            required_preconditions=("confirmed_ssh_access",),
            killchain_stage="lateral_movement",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"pivot_remote_forward {request.target}"
        invocation = parse_invocation(command)
        return ToolInvocation(
            executable=invocation.executable,
            argv=invocation.argv,
            raw_command=command,
            registered_name=self.descriptor.name,
            targets=invocation.targets,
            uses_shell=invocation.uses_shell,
        )

    def active_risk_class(
        self,
        request: ActionRequest,
        phase: str = "execute",
    ) -> ActiveRiskClass:
        del request, phase
        return ActiveRiskClass.ACTIVE


class PivotSSHChainAdapter(ManualGatedActionAdapter):
    """Адаптер действия для создания цепочки SSH туннелей."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:pivot_ssh_chain",
            name="pivot_ssh_chain",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.pivot:create_ssh_chain",
            category="pivot",
            description="Create multi-hop SSH tunnel chain",
            input_type=CredentialInput,
            capability_class="pivot",
            risk_class="high",
            required_preconditions=("confirmed_ssh_access",),
            killchain_stage="lateral_movement",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"pivot_ssh_chain {request.target}"
        invocation = parse_invocation(command)
        return ToolInvocation(
            executable=invocation.executable,
            argv=invocation.argv,
            raw_command=command,
            registered_name=self.descriptor.name,
            targets=invocation.targets,
            uses_shell=invocation.uses_shell,
        )

    def active_risk_class(
        self,
        request: ActionRequest,
        phase: str = "execute",
    ) -> ActiveRiskClass:
        del request, phase
        return ActiveRiskClass.ACTIVE


class PivotProxyScanAdapter(ManualGatedActionAdapter):
    """Адаптер действия для сканирования через SOCKS прокси."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:pivot_proxy_scan",
            name="pivot_proxy_scan",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.pivot:scan_through_proxy",
            category="pivot",
            description="Scan target host ports through SOCKS proxy",
            input_type=PivotRouteInput,
            capability_class="pivot",
            risk_class="medium",
            required_preconditions=("confirmed_pivot",),
            killchain_stage="lateral_movement",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"pivot_proxy_scan {request.target}"
        invocation = parse_invocation(command)
        return ToolInvocation(
            executable=invocation.executable,
            argv=invocation.argv,
            raw_command=command,
            registered_name=self.descriptor.name,
            targets=invocation.targets,
            uses_shell=invocation.uses_shell,
        )

    def active_risk_class(
        self,
        request: ActionRequest,
        phase: str = "execute",
    ) -> ActiveRiskClass:
        del request, phase
        return ActiveRiskClass.ACTIVE


__all__ = [
    "PivotProxyScanAdapter",
    "PivotRemoteForwardAdapter",
    "PivotSSHChainAdapter",
]
