"""Action adapters for Active Directory lateral movement capabilities."""

from __future__ import annotations

from core.execution import ToolInvocation
from core.execution.policy import parse_invocation

from .base import ManualGatedActionAdapter
from .input_contracts import RemoteExecInput
from .models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)


class ADSmbexecAdapter(ManualGatedActionAdapter):
    """Адаптер действия для удаленного выполнения команд через SMBExec."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_smbexec",
            name="ad_smbexec",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.lateral:smbexec",
            category="lateral_movement",
            description="Execute remote command via SMBExec service creation",
            input_type=RemoteExecInput,
            capability_class="lateral_movement",
            risk_class="critical",
            required_preconditions=("confirmed_ad_access", "smb_service_available"),
            killchain_stage="lateral_movement",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"ad_smbexec {request.target}"
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


class ADWinrmExecAdapter(ManualGatedActionAdapter):
    """Адаптер действия для удаленного выполнения команд через WinRM."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_winrm_exec",
            name="ad_winrm_exec",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.lateral:winrm_exec",
            category="lateral_movement",
            description="Execute remote command via WinRM service",
            input_type=RemoteExecInput,
            capability_class="lateral_movement",
            risk_class="critical",
            required_preconditions=("confirmed_ad_access", "winrm_service_available"),
            killchain_stage="lateral_movement",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"ad_winrm_exec {request.target}"
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


class ADDcomExecAdapter(ManualGatedActionAdapter):
    """Адаптер действия для удаленного выполнения команд через DCOM."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_dcom_exec",
            name="ad_dcom_exec",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.lateral:dcom_exec",
            category="lateral_movement",
            description="Execute remote command via DCOM object invocation",
            input_type=RemoteExecInput,
            capability_class="lateral_movement",
            risk_class="critical",
            required_preconditions=("confirmed_ad_access", "dcom_service_available"),
            killchain_stage="lateral_movement",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"ad_dcom_exec {request.target}"
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


class ADRemoteExecutionCapabilityAdapter(ManualGatedActionAdapter):
    """Unmounted composite identity; any future leaf must re-enter ActionExecutor."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_remote_execution",
            name="ad_remote_execution",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.lateral:remote_execution",
            category="lateral_movement",
            description="Unmounted composite AD remote execution identity without leaf delegation",
            input_type=RemoteExecInput,
            capability_class="lateral_movement",
            risk_class="critical",
            required_preconditions=("confirmed_ad_access",),
            killchain_stage="lateral_movement",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"ad_remote_execution {request.target}"
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
    "ADDcomExecAdapter",
    "ADRemoteExecutionCapabilityAdapter",
    "ADSmbexecAdapter",
    "ADWinrmExecAdapter",
]
