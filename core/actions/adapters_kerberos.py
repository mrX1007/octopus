"""Action adapters for Kerberos credential extraction and cracking."""

from __future__ import annotations

from core.execution import ToolInvocation
from core.execution.policy import parse_invocation

from .base import ManualGatedActionAdapter
from .input_contracts import SessionInput, TicketInput
from .models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)


class KerberosExtractTicketsAdapter(ManualGatedActionAdapter):
    """Адаптер действия для извлечения билетов Kerberos из памяти/системы."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:kerberos_extract_tickets",
            name="kerberos_extract_tickets",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.kerberos:extract_tickets",
            category="credential_extraction",
            description="Extract Kerberos tickets from memory or filesystem",
            input_type=SessionInput,
            capability_class="credential_extraction",
            risk_class="high",
            required_preconditions=("confirmed_windows_access", "ad_environment_detected"),
            killchain_stage="credential_access",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=True,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = f"kerberos_extract_tickets {request.target}"
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


class KerberosCrackTicketsAdapter(ManualGatedActionAdapter):
    """Адаптер действия для оффлайн взлома Kerberos билетов (Kerberoast/AS-REP Roast)."""

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:kerberos_crack_tickets",
            name="kerberos_crack_tickets",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.kerberos:crack_tickets",
            category="credential_extraction",
            description="Perform offline hash cracking on extracted Kerberos tickets",
            input_type=TicketInput,
            capability_class="credential_extraction",
            risk_class="high",
            killchain_stage="credential_access",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=False,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = "kerberos_crack_tickets" + (f" {request.target}" if request.target else "")
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
    "KerberosCrackTicketsAdapter",
    "KerberosExtractTicketsAdapter",
]
