"""Action adapters for Active Directory credential access and lateral movement."""

from __future__ import annotations

from core.execution import ToolInvocation
from core.execution.policy import parse_invocation

from .base import ManualGatedActionAdapter
from .input_contracts import CredentialInput, SessionInput, TicketInput
from .models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)


class ADPassTheTicketAdapter(ManualGatedActionAdapter):
    """Адаптер действия для атаки Pass-the-Ticket в Active Directory."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_pass_the_ticket",
            name="ad_pass_the_ticket",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.credential:pass_the_ticket",
            category="lateral_movement",
            description="Perform Pass-the-Ticket attack using Kerberos ticket",
            input_type=TicketInput,
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
        command = f"ad_pass_the_ticket {request.target}"
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


class PassTheHashAdapter(ManualGatedActionAdapter):
    """Адаптер действия для атаки Pass-the-Hash."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:pass_the_hash",
            name="pass_the_hash",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.credential:pass_the_hash",
            category="lateral_movement",
            description="Perform Pass-the-Hash authentication attack",
            aliases=("pth",),
            input_type=CredentialInput,
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
        command = f"pass_the_hash {request.target}"
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


class ADDumpLsassAdapter(ManualGatedActionAdapter):
    """Адаптер действия для дампинга памяти LSASS."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_dump_lsass",
            name="ad_dump_lsass",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.credential:dump_lsass",
            category="credential_extraction",
            description="Dump LSASS process memory on remote target",
            input_type=SessionInput,
            capability_class="credential_extraction",
            risk_class="critical",
            required_preconditions=("confirmed_windows_access",),
            killchain_stage="credential_access",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"ad_dump_lsass {request.target}"
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


class ADSamDumpAdapter(ManualGatedActionAdapter):
    """Адаптер действия для дампа локальных учеток SAM/SYSTEM."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_sam_dump",
            name="ad_sam_dump",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.credential:sam_dump",
            category="credential_extraction",
            description="Dump SAM and SYSTEM registry hives from target",
            input_type=SessionInput,
            capability_class="credential_extraction",
            risk_class="critical",
            required_preconditions=("confirmed_windows_access",),
            killchain_stage="credential_access",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"ad_sam_dump {request.target}"
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
    "ADDumpLsassAdapter",
    "ADPassTheTicketAdapter",
    "ADSamDumpAdapter",
    "PassTheHashAdapter",
]
