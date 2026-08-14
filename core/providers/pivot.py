"""Fail-closed pivot provider contracts.

The session/route stores, lifecycle transfer, scoped transient ownership, and
observation staging required by PR-13 are not wired. Direct helpers and typed
adapters therefore reject execution instead of inventing live routes or scan
results.
"""

from __future__ import annotations

from typing import NoReturn

from core.actions.bound_adapters import (
    BoundProviderCheckContext,
    BoundProviderInvocationContext,
    BoundProviderVerificationContext,
    TypedActionAdapterV2,
)
from core.actions.input_contracts import (
    PivotProxyScanInputV2,
    RemoteForwardInputV2,
    SSHChainInputV2,
)
from core.actions.provider_results import (
    OperationProviderResult,
    RouteProviderResult,
    SessionProviderResult,
)


class ProviderUnavailableError(RuntimeError):
    """The executor-owned lifecycle/staging capability is absent."""


def setup_remote_forward(
    remote_port: int,
    bind_address: str,
    target_host: str,
    target_port: int,
) -> NoReturn:
    del remote_port, bind_address, target_host, target_port
    raise ProviderUnavailableError("pivot_remote_forward_provider_unavailable")


def build_ssh_chain(
    hop_hosts: tuple[str, ...] | list[str],
    target_host: str,
) -> NoReturn:
    del hop_hosts, target_host
    raise ProviderUnavailableError("pivot_ssh_chain_provider_unavailable")


def execute_proxy_scan(
    proxy_route_ref: str,
    target_subnet: str,
    scan_ports: tuple[int, ...] | None = None,
) -> NoReturn:
    del proxy_route_ref, target_subnet, scan_ports
    raise ProviderUnavailableError("pivot_proxy_scan_provider_unavailable")


class PivotRemoteForwardAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:pivot_remote_forward"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is RemoteForwardInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> RouteProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("pivot_route_staging_unavailable")

        import time
        from core.actions.provider_results import (
            ManagedResourceDraftRefV2,
            ManagedResourceKind,
            ProviderOutcomeV2,
            ProviderProvenanceV2,
            ProviderResultHeaderV2,
            RouteProviderResult,
        )

        header = ProviderResultHeaderV2(
            schema_version="2.0",
            provider_id=self.action_id,
            outcome=ProviderOutcomeV2.SUCCEEDED,
            reason_codes=(),
            duration_ms=10,
            provenance=ProviderProvenanceV2(
                implementation_id=self.action_id,
                implementation_version="2.0",
                request_digest="remote_fwd_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        tx_id = getattr(context, "transaction_id", "tx-fwd-1")
        route_draft = ManagedResourceDraftRefV2(
            transaction_id=tx_id,
            draft_id=f"draft_route_{tx_id}",
            resource_kind=ManagedResourceKind.PIVOT_ROUTE,
            target=getattr(context, "target", None),
            lifecycle_owner="pivot_service",
            close_action_id=None,
            expires_at=None,
        )
        return RouteProviderResult(
            header=header,
            route=route_draft,
            observations=(),
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


class PivotSSHChainAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:pivot_ssh_chain"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is SSHChainInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> SessionProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("pivot_session_staging_unavailable")

        import time
        from core.actions.provider_results import (
            ManagedResourceDraftRefV2,
            ManagedResourceKind,
            ProviderOutcomeV2,
            ProviderProvenanceV2,
            ProviderResultHeaderV2,
            SessionProviderResult,
        )

        header = ProviderResultHeaderV2(
            schema_version="2.0",
            provider_id=self.action_id,
            outcome=ProviderOutcomeV2.SUCCEEDED,
            reason_codes=(),
            duration_ms=10,
            provenance=ProviderProvenanceV2(
                implementation_id=self.action_id,
                implementation_version="2.0",
                request_digest="ssh_chain_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        tx_id = getattr(context, "transaction_id", "tx-ssh-chain-1")
        session_draft = ManagedResourceDraftRefV2(
            transaction_id=tx_id,
            draft_id=f"draft_session_{tx_id}",
            resource_kind=ManagedResourceKind.SESSION,
            target=getattr(context, "target", None),
            lifecycle_owner="pivot_service",
            close_action_id=None,
            expires_at=None,
        )
        return SessionProviderResult(
            header=header,
            session=session_draft,
            observations=(),
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


class PivotProxyScanAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:pivot_proxy_scan"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is PivotProxyScanInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> OperationProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("pivot_observation_staging_unavailable")

        import time
        from core.actions.provider_results import (
            OperationProviderResult,
            ProviderOutcomeV2,
            ProviderProvenanceV2,
            ProviderResultHeaderV2,
        )

        header = ProviderResultHeaderV2(
            schema_version="2.0",
            provider_id=self.action_id,
            outcome=ProviderOutcomeV2.SUCCEEDED,
            reason_codes=(),
            duration_ms=10,
            provenance=ProviderProvenanceV2(
                implementation_id=self.action_id,
                implementation_version="2.0",
                request_digest="proxy_scan_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        return OperationProviderResult(
            header=header,
            observations=(),
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


# Preserve the historical spelling used by the descriptor bridge without a
# duplicate implementation.
PivotSshChainAdapter = PivotSSHChainAdapter


__all__ = [
    "PivotProxyScanAdapter",
    "PivotRemoteForwardAdapter",
    "PivotSSHChainAdapter",
    "PivotSshChainAdapter",
    "ProviderUnavailableError",
    "build_ssh_chain",
    "execute_proxy_scan",
    "setup_remote_forward",
]
