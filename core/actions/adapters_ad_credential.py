"""Action adapters for Active Directory credential extraction and reuse."""

from __future__ import annotations

from typing import Any

from core.actions.base import ManualGatedActionAdapter
from core.actions.input_contracts import (
    CredentialDumpInput,
    CredentialInput,
    LateralAuthInput,
    SessionInput,
    TicketInput,
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


class ADPassTheTicketAdapter(ManualGatedActionAdapter):
    """Адаптер действия для Pass-the-Ticket аутентификации в Active Directory."""

    action_id: str = "killchain:ad_pass_the_ticket"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_pass_the_ticket",
            name="ad_pass_the_ticket",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.credential:pass_the_ticket",
            category="lateral_movement",
            description="Authenticate to Kerberos service using existing ticket without knowing plaintext password",
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

    def check_bound(self, context: Any) -> bool:
        from core.providers.ad_credentials import ADPassTheTicketAdapter as RealAdapter
        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.ad_credentials import ADPassTheTicketAdapter as RealAdapter
        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.ad_credentials import ADPassTheTicketAdapter as RealAdapter
        return RealAdapter().verify_bound(context, result)


class PassTheHashAdapter(ManualGatedActionAdapter):
    """Адаптер действия для Pass-the-Hash аутентификации."""

    action_id: str = "killchain:pass_the_hash"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:pass_the_hash",
            name="pass_the_hash",
            aliases=("pth",),
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.credential:pass_the_hash",
            category="lateral_movement",
            description="Authenticate using NTLM hash without knowing plaintext password",
            input_type=LateralAuthInput,
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

    def check_bound(self, context: Any) -> bool:
        from core.providers.ad_credentials import PassTheHashAdapter as RealAdapter
        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.ad_credentials import PassTheHashAdapter as RealAdapter
        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.ad_credentials import PassTheHashAdapter as RealAdapter
        return RealAdapter().verify_bound(context, result)


class ADDumpLsassAdapter(ManualGatedActionAdapter):
    """Адаптер действия для извлечения учетных данных из процесса LSASS."""

    action_id: str = "killchain:ad_dump_lsass"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_dump_lsass",
            name="ad_dump_lsass",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.credential:dump_lsass",
            category="credential_extraction",
            description="Extract credentials, tickets, and hashes from LSASS process memory",
            input_type=SessionInput,
            capability_class="credential_extraction",
            risk_class="critical",
            required_preconditions=("confirmed_ad_access",),
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

    def check_bound(self, context: Any) -> bool:
        from core.providers.ad_credentials import ADDumpLsassAdapter as RealAdapter
        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.ad_credentials import ADDumpLsassAdapter as RealAdapter
        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.ad_credentials import ADDumpLsassAdapter as RealAdapter
        return RealAdapter().verify_bound(context, result)


class ADSamDumpAdapter(ManualGatedActionAdapter):
    """Адаптер действия для извлечения локальных хешей из SAM-базы."""

    action_id: str = "killchain:ad_sam_dump"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:ad_sam_dump",
            name="ad_sam_dump",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.ad.credential:sam_dump",
            category="credential_extraction",
            description="Dump local account password hashes from SAM registry hive",
            input_type=SessionInput,
            capability_class="credential_extraction",
            risk_class="high",
            required_preconditions=("confirmed_ad_access",),
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

    def check_bound(self, context: Any) -> bool:
        from core.providers.ad_credentials import ADSamDumpAdapter as RealAdapter
        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.ad_credentials import ADSamDumpAdapter as RealAdapter
        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.ad_credentials import ADSamDumpAdapter as RealAdapter
        return RealAdapter().verify_bound(context, result)


__all__ = [
    "ADDumpLsassAdapter",
    "ADPassTheTicketAdapter",
    "ADSamDumpAdapter",
    "PassTheHashAdapter",
]
