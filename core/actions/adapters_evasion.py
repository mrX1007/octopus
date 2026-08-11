"""Action adapters for evasion capabilities and plugin integration."""

from __future__ import annotations

from core.execution import ToolInvocation
from core.execution.policy import parse_invocation

from .base import ManualGatedActionAdapter
from .input_contracts import PayloadKeyingInput
from .models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)


class PayloadKeyingAdapter(ManualGatedActionAdapter):
    """Manual-gated canonical identity for environmental payload keying."""

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


__all__ = [
    "PayloadKeyingAdapter",
]
