"""Action adapters for Active Directory lateral movement capabilities."""

from __future__ import annotations

from typing import Any

from core.actions.base import ManualGatedActionAdapter
from core.actions.input_contracts import RemoteExecInput
from core.actions.models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)
from core.execution import ToolInvocation
from core.execution.policy import parse_invocation


class ADSmbexecAdapter(ManualGatedActionAdapter):
    """Адаптер действия для удаленного выполнения команд через SMBExec."""

    action_id: str = "killchain:ad_smbexec"
    adapter_api_version: int = 2

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

    def check_bound(self, context: Any) -> bool:
        from core.providers.ad_lateral import ADSmbexecAdapter as RealAdapter
        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.ad_lateral import ADSmbexecAdapter as RealAdapter
        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.ad_lateral import ADSmbexecAdapter as RealAdapter
        return RealAdapter().verify_bound(context)


class ADWinrmExecAdapter(ManualGatedActionAdapter):
    """Адаптер действия для удаленного выполнения команд через WinRM."""

    action_id: str = "killchain:ad_winrm_exec"
    adapter_api_version: int = 2

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

    def check_bound(self, context: Any) -> bool:
        from core.providers.ad_lateral import ADWinRMExecAdapter as RealAdapter
        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.ad_lateral import ADWinRMExecAdapter as RealAdapter
        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.ad_lateral import ADWinRMExecAdapter as RealAdapter
        return RealAdapter().verify_bound(context)


class ADDcomExecAdapter(ManualGatedActionAdapter):
    """Адаптер действия для удаленного выполнения команд через DCOM."""

    action_id: str = "killchain:ad_dcom_exec"
    adapter_api_version: int = 2

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

    def check_bound(self, context: Any) -> bool:
        from core.providers.ad_lateral import ADDComExecAdapter as RealAdapter
        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.ad_lateral import ADDComExecAdapter as RealAdapter
        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.ad_lateral import ADDComExecAdapter as RealAdapter
        return RealAdapter().verify_bound(context)


class ADRemoteExecutionCapabilityAdapter(ManualGatedActionAdapter):
    """Composite router for Active Directory remote execution; re-enters ActionExecutor."""

    action_id: str = "killchain:ad_remote_execution"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_remote_execution",
            name="ad_remote_execution",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.lateral:remote_execution",
            category="lateral_movement",
            description="Composite router for AD remote execution selecting WinRM/SMB/DCOM",
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

    def check_bound(self, context: Any) -> bool:
        from core.providers.ad_lateral import ADRemoteExecutionRouter
        return ADRemoteExecutionRouter().check_bound(context)

    def route_bound(self, context: Any) -> Any:
        from core.providers.ad_lateral import ADRemoteExecutionRouter
        return ADRemoteExecutionRouter().route_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.ad_lateral import ADRemoteExecutionRouter
        return ADRemoteExecutionRouter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.ad_lateral import ADRemoteExecutionRouter
        return ADRemoteExecutionRouter().verify_bound(context)


ADWinRMExecAdapter = ADWinrmExecAdapter
ADDComExecAdapter = ADDcomExecAdapter
ADRemoteExecutionAdapter = ADRemoteExecutionCapabilityAdapter


__all__ = [
    "ADDComExecAdapter",
    "ADDcomExecAdapter",
    "ADRemoteExecutionAdapter",
    "ADRemoteExecutionCapabilityAdapter",
    "ADSmbexecAdapter",
    "ADWinRMExecAdapter",
    "ADWinrmExecAdapter",
]
