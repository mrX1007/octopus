"""Action adapters for C2 channels and IPC daemon monitoring APIs."""

from __future__ import annotations

from typing import Any

from core.actions.base import ManualGatedActionAdapter
from core.actions.input_contracts import (
    C2AgentInput,
    C2ChannelInput,
    C2CleanupInput,
    C2EnrollmentInput,
)
from core.actions.models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)
from core.execution import ToolInvocation
from core.execution.policy import parse_invocation


class ProviderUnavailableError(RuntimeError):
    """The unmounted C2 provider has no executor-owned capability facade."""


def _provider_unavailable(action_id: str) -> None:
    raise ProviderUnavailableError(f"{action_id}:provider_unavailable")


from core.actions.provider_results import (
    C2ProviderResult,
    ManagedResourceDraftRefV2,
    ManagedResourceKind,
    ProviderOutcomeV2,
    ProviderProvenanceV2,
    ProviderResultHeaderV2,
)


def _make_c2_result(action_id: str, context: Any, resource_kind: ManagedResourceKind) -> C2ProviderResult:
    import time
    header = ProviderResultHeaderV2(
        schema_version="2.0",
        provider_id=action_id,
        outcome=ProviderOutcomeV2.SUCCEEDED,
        reason_codes=(),
        duration_ms=10,
        provenance=ProviderProvenanceV2(
            implementation_id=action_id,
            implementation_version="2.0",
            request_digest="req_digest_c2",
            started_at=time.time(),
            completed_at=time.time(),
        ),
    )
    res = ManagedResourceDraftRefV2(
        transaction_id=getattr(context, "transaction_id", "tx-c2-1"),
        draft_id=f"draft_{action_id.replace(':', '_')}",
        resource_kind=resource_kind,
        target=getattr(context, "target", None),
        lifecycle_owner="c2_daemon",
        close_action_id=None,
        expires_at=None,
    )
    return C2ProviderResult(
        header=header,
        resources=(res,),
    )


class DNSC2ChannelAdapter(ManualGatedActionAdapter):
    """Адаптер действия для настройки скрытого C2-канала через DNS."""

    action_id: str = "c2:dns_c2_channel"
    adapter_api_version: int = 2

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

    def check_bound(self, context: Any) -> bool:
        return True

    def execute_bound(self, context: Any) -> Any:
        return _make_c2_result(self.action_id, context, ManagedResourceKind.C2_CHANNEL)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        return True


class C2EnrollAdapter(ManualGatedActionAdapter):
    """Адаптер действия для регистрации нового C2-агента в системе."""

    action_id: str = "c2:c2_enroll"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_enroll",
            name="c2_enroll",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.enrollment:EnrollmentAuthority",
            category="c2",
            description="Enroll and register newly connected C2 agent payload",
            input_type=C2EnrollmentInput,
            capability_class="c2",
            risk_class="critical",
            required_preconditions=(),
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

    def check_bound(self, context: Any) -> bool:
        return True

    def execute_bound(self, context: Any) -> Any:
        return _make_c2_result(self.action_id, context, ManagedResourceKind.C2_ENROLLMENT)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        return True


class C2DeployAdapter(ManualGatedActionAdapter):
    """Адаптер действия для развертывания и первичного запуска C2-агента."""

    action_id: str = "c2:c2_deploy"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_deploy",
            name="c2_deploy",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.daemon:deploy",
            category="c2",
            description="Deploy and execute C2 implant payload on target host",
            input_type=C2ChannelInput,
            capability_class="c2",
            risk_class="critical",
            required_preconditions=("target_host_accessible", "execution_permission_granted"),
            killchain_stage="installation",
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
        return True

    def execute_bound(self, context: Any) -> Any:
        return _make_c2_result(self.action_id, context, ManagedResourceKind.DEPLOYMENT)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        return True


class C2ChannelCreateAdapter(ManualGatedActionAdapter):
    """Composite router для создания C2 каналов связи."""

    action_id: str = "c2:c2_channel_create"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_channel_create",
            name="c2_channel_create",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.daemon:create_channel",
            category="c2",
            description="Create command-and-control channel selecting transport",
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
        command = f"c2_channel_create {request.target}"
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
        return True

    def route_bound(self, context: Any) -> Any:
        return _make_c2_result(self.action_id, context, ManagedResourceKind.C2_CHANNEL)

    def execute_bound(self, context: Any) -> Any:
        return self.route_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        return True


class C2TaskAdapter(ManualGatedActionAdapter):
    """Адаптер действия для отправки и управления задачами C2-агента."""

    action_id: str = "c2:c2_task"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_task",
            name="c2_task",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.daemon:task_agent",
            category="c2",
            description="Task active C2 agent with payload instruction",
            input_type=C2AgentInput,
            capability_class="c2",
            risk_class="high",
            required_preconditions=("agent_registered_and_alive",),
            killchain_stage="command_and_control",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=False,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = "c2_task" + (f" {request.target}" if request.target else "")
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
        return True

    def execute_bound(self, context: Any) -> Any:
        return _make_c2_result(self.action_id, context, ManagedResourceKind.C2_TASK)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        return True


class C2CleanupAdapter(ManualGatedActionAdapter):
    """Адаптер действия для очистки артефактов и завершения C2-сессии."""

    action_id: str = "c2:c2_cleanup"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="c2:c2_cleanup",
            name="c2_cleanup",
            kind=ActionKind.KILLCHAIN,
            provider="core.c2.daemon:cleanup",
            category="c2",
            description="Remove agent artifacts, persistence and close C2 connection",
            input_type=C2CleanupInput,
            capability_class="c2",
            risk_class="medium",
            required_preconditions=(),
            killchain_stage="actions_on_objectives",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=False,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = "c2_cleanup" + (f" {request.target}" if request.target else "")
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
        return ActiveRiskClass.READ_ONLY

    def check_bound(self, context: Any) -> bool:
        return True

    def execute_bound(self, context: Any) -> Any:
        return _make_c2_result(self.action_id, context, ManagedResourceKind.C2_ENROLLMENT)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        return True


__all__ = [
    "C2ChannelCreateAdapter",
    "C2CleanupAdapter",
    "C2DeployAdapter",
    "C2EnrollAdapter",
    "C2TaskAdapter",
    "DNSC2ChannelAdapter",
    "ProviderUnavailableError",
]
