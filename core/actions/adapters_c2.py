"""Action adapters for C2 channels and IPC daemon monitoring APIs."""

from __future__ import annotations

from core.execution import ToolInvocation
from core.execution.policy import parse_invocation

from .base import ManualGatedActionAdapter
from .input_contracts import (
    C2AgentInput,
    C2ChannelInput,
    C2CleanupInput,
    C2EnrollmentInput,
)
from .models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)


class DNSC2ChannelAdapter(ManualGatedActionAdapter):
    """Адаптер действия для настройки скрытого C2-канала через DNS."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:dns_c2_channel",
            name="dns_c2_channel",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.channels.dns:DNSChannel",
            category="c2",
            description="Establish DNS-based covert command-and-control channel",
            input_type=C2ChannelInput,
            capability_class="c2",
            risk_class="critical",
            required_preconditions=("approved_c2_scope",),
            killchain_stage="command_and_control",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"dns_c2_channel {request.target}"
        invocation = parse_invocation(command)
        callback = str(getattr(request.typed_input, "callback_endpoint", "") or "").strip()
        return ToolInvocation(
            executable=invocation.executable,
            argv=invocation.argv,
            raw_command=command,
            registered_name=self.descriptor.name,
            targets=tuple(dict.fromkeys((*invocation.targets, *((callback,) if callback else ())))),
            uses_shell=invocation.uses_shell,
        )

    def active_risk_class(
        self,
        request: ActionRequest,
        phase: str = "execute",
    ) -> ActiveRiskClass:
        del request, phase
        return ActiveRiskClass.ACTIVE


class C2EnrollAdapter(ManualGatedActionAdapter):
    """Адаптер действия для выпуска и проверки токенов регистрации C2."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_enroll",
            name="c2_enroll",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.enrollment:EnrollmentAuthority",
            category="c2",
            description="Issue or consume authenticated C2 enrollment tokens",
            input_type=C2EnrollmentInput,
            capability_class="c2",
            risk_class="critical",
            killchain_stage="command_and_control",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=False,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = "c2_enroll" + (f" {request.target}" if request.target else "")
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


class C2DeployAdapter(ManualGatedActionAdapter):
    """Адаптер действия для развертывания стейджера или импланта C2."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_deploy",
            name="c2_deploy",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.daemon:deploy",
            category="c2",
            description="Deploy C2 stager or agent payload to target host",
            input_type=C2ChannelInput,
            capability_class="c2",
            risk_class="critical",
            required_preconditions=("confirmed_target_access", "c2_channel_authorized"),
            killchain_stage="command_and_control",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"c2_deploy {request.target}"
        invocation = parse_invocation(command)
        callback = str(getattr(request.typed_input, "callback_endpoint", "") or "").strip()
        return ToolInvocation(
            executable=invocation.executable,
            argv=invocation.argv,
            raw_command=command,
            registered_name=self.descriptor.name,
            targets=tuple(dict.fromkeys((*invocation.targets, *((callback,) if callback else ())))),
            uses_shell=invocation.uses_shell,
        )

    def active_risk_class(
        self,
        request: ActionRequest,
        phase: str = "execute",
    ) -> ActiveRiskClass:
        del request, phase
        return ActiveRiskClass.ACTIVE


class C2ChannelCreateAdapter(ManualGatedActionAdapter):
    """Адаптер действия для создания транспортных каналов C2."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_channel_create",
            name="c2_channel_create",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.daemon:create_channel",
            category="c2",
            description="Create listener or transport channel for C2 daemon",
            input_type=C2ChannelInput,
            capability_class="c2",
            risk_class="critical",
            required_preconditions=("approved_c2_scope",),
            killchain_stage="command_and_control",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"c2_channel_create {request.target or 'localhost'}"
        invocation = parse_invocation(command)
        callback = str(getattr(request.typed_input, "callback_endpoint", "") or "").strip()
        return ToolInvocation(
            executable=invocation.executable,
            argv=invocation.argv,
            raw_command=command,
            registered_name=self.descriptor.name,
            targets=tuple(dict.fromkeys((*invocation.targets, *((callback,) if callback else ())))),
            uses_shell=invocation.uses_shell,
        )

    def active_risk_class(
        self,
        request: ActionRequest,
        phase: str = "execute",
    ) -> ActiveRiskClass:
        del request, phase
        return ActiveRiskClass.ACTIVE


class C2TaskAdapter(ManualGatedActionAdapter):
    """Адаптер действия для постановки задач агентам C2."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_task",
            name="c2_task",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.daemon:task_agent",
            category="c2",
            description="Queue or dispatch command tasks to registered C2 agents",
            input_type=C2AgentInput,
            capability_class="c2",
            risk_class="high",
            required_preconditions=("c2_agent_enrolled",),
            killchain_stage="command_and_control",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"c2_task {request.target or 'agent'}"
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


class C2CleanupAdapter(ManualGatedActionAdapter):
    """Адаптер действия для очистки ресурсов и закрытия каналов C2."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_cleanup",
            name="c2_cleanup",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.daemon:cleanup",
            category="c2",
            description="Teardown C2 channels and clear active daemon session state",
            input_type=C2CleanupInput,
            capability_class="c2",
            risk_class="medium",
            required_preconditions=("c2_channel_exists",),
            killchain_stage="command_and_control",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"c2_cleanup {request.target or 'localhost'}"
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
    "C2ChannelCreateAdapter",
    "C2CleanupAdapter",
    "C2DeployAdapter",
    "C2EnrollAdapter",
    "C2TaskAdapter",
    "DNSC2ChannelAdapter",
]
