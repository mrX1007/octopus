"""Action adapters for network pivoting, SSH chaining, and proxy scanning."""

from __future__ import annotations

from typing import Any

from core.actions.base import ManualGatedActionAdapter
from core.actions.input_contracts import (
    CredentialInput,
    PivotRouteInput,
    SessionInput,
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


class PivotRemoteForwardAdapter(ManualGatedActionAdapter):
    """Адаптер действия для настройки удаленного проброса портов (Remote Forwarding)."""

    action_id: str = "killchain:pivot_remote_forward"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:pivot_remote_forward",
            name="pivot_remote_forward",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.pivot:setup_remote_forward",
            category="pivoting",
            description="Establish remote port forwarding tunnel through compromised host",
            input_type=SessionInput,
            capability_class="pivot",
            risk_class="high",
            required_preconditions=("confirmed_ssh_or_agent_access", "target_host_routable"),
            killchain_stage="command_and_control",
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

    def check_bound(self, context: Any) -> bool:
        from core.providers.pivot import PivotRemoteForwardAdapter as RealAdapter

        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.pivot import PivotRemoteForwardAdapter as RealAdapter

        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.pivot import PivotRemoteForwardAdapter as RealAdapter

        return RealAdapter().verify_bound(context, result)


class PivotSSHChainAdapter(ManualGatedActionAdapter):
    """Адаптер действия для построения цепочки SSH-туннелей (SSH Jump/Chain)."""

    action_id: str = "killchain:pivot_ssh_chain"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:pivot_ssh_chain",
            name="pivot_ssh_chain",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.pivot:create_ssh_chain",
            category="pivoting",
            description="Create multi-hop SSH connection chain through intermediate jump hosts",
            input_type=CredentialInput,
            capability_class="pivot",
            risk_class="high",
            required_preconditions=("ssh_credentials_available", "intermediate_nodes_reachable"),
            killchain_stage="command_and_control",
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

    def check_bound(self, context: Any) -> bool:
        from core.providers.pivot import PivotSshChainAdapter as RealAdapter

        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.pivot import PivotSshChainAdapter as RealAdapter

        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.pivot import PivotSshChainAdapter as RealAdapter

        return RealAdapter().verify_bound(context, result)


class PivotProxyScanAdapter(ManualGatedActionAdapter):
    """Адаптер действия для сканирования сети через настроенный SOCKS/HTTP прокси."""

    action_id: str = "killchain:pivot_proxy_scan"
    adapter_api_version: int = 2

    def __init__(self) -> None:
        self.descriptor = ActionDescriptor(
            action_id="killchain:pivot_proxy_scan",
            name="pivot_proxy_scan",
            kind=ActionKind.KILLCHAIN,
            provider="core.killchain.pivot:scan_through_proxy",
            category="reconnaissance",
            description="Scan internal network ranges through established proxy/tunnel",
            input_type=PivotRouteInput,
            capability_class="pivot",
            risk_class="medium",
            required_preconditions=("active_proxy_tunnel_present",),
            killchain_stage="reconnaissance",
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

    def check_bound(self, context: Any) -> bool:
        from core.providers.pivot import PivotProxyScanAdapter as RealAdapter

        return RealAdapter().check_bound(context)

    def execute_bound(self, context: Any) -> Any:
        from core.providers.pivot import PivotProxyScanAdapter as RealAdapter

        return RealAdapter().execute_bound(context)

    def verify_bound(self, context: Any, result: Any = None) -> bool:
        from core.providers.pivot import PivotProxyScanAdapter as RealAdapter

        return RealAdapter().verify_bound(context, result)


__all__ = [
    "PivotProxyScanAdapter",
    "PivotRemoteForwardAdapter",
    "PivotSSHChainAdapter",
]
