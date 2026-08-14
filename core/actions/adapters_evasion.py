"""Action adapters for evasion capabilities and plugin integration."""

from __future__ import annotations

from typing import Any

from core.actions.base import ManualGatedActionAdapter
from core.actions.input_contracts import PayloadKeyingInput
from core.actions.models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)
from core.execution import ToolInvocation
from core.execution.policy import parse_invocation


class PayloadKeyingAdapter(ManualGatedActionAdapter):
    """Manual-gated canonical identity for environmental payload keying."""

    action_id: str = "plugin:payload_keying"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="plugin:payload_keying",
            name="payload_keying",
            kind=ActionKind.PLUGIN,
            provider="modules.evasion.payload_keying:PayloadKeyingPlugin",
            category="evasion",
            description="Unifies plugin catalog resolution with tool registry resolution for environmental payload keying",
            input_type=PayloadKeyingInput,
            capability_class="evasion",
            risk_class="high",
            killchain_stage="weaponization",
            manual_gate=True,
            provider_mounted=False,
            requirements=ActionRequirements(
                active=True,
                target_required=False,
            ),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        command = "payload_keying" + (f" {request.target}" if request.target else "")
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
        from core.providers.payload_keying import PayloadKeyingAdapter as RealAdapter
        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.payload_keying import PayloadKeyingAdapter as RealAdapter
        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.payload_keying import PayloadKeyingAdapter as RealAdapter
        return RealAdapter().verify_bound(context, result)


__all__ = [
    "PayloadKeyingAdapter",
]
