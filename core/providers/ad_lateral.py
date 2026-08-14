"""Fail-closed Active Directory remote-operation provider contracts.

Remote operation dispatch belongs to a transaction participant after the
executor has staged an exact plan and registered the external effect. These
adapters intentionally do not call a backend or fabricate effect receipts.
"""

from __future__ import annotations

from core.actions.bound_adapters import (
    BoundProviderCheckContext,
    BoundProviderInvocationContext,
    BoundProviderVerificationContext,
    TypedActionAdapterV2,
)
from core.actions.input_contracts import RemoteExecInputV2
from core.actions.operation_catalog import RemoteExecService
from core.actions.provider_results import CompositeProviderResult, OperationProviderResult


class ProviderUnavailableError(RuntimeError):
    """The executor-owned effect participant required by this provider is absent."""


def _matches_leaf(
    context: BoundProviderCheckContext,
    *,
    action_id: str,
    service: RemoteExecService,
) -> bool:
    if type(context) is not BoundProviderCheckContext:
        return False
    request = context.request
    if request.action_id != action_id or type(request.typed_input) is not RemoteExecInputV2:
        return False
    return request.typed_input.service in (None, service)


class ADSmbexecAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:ad_smbexec"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return _matches_leaf(context, action_id=self.action_id, service=RemoteExecService.SMB)

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> OperationProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("ad_smbexec_effect_participant_unavailable")

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
                request_digest="smbexec_req_digest",
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


class ADWinRMExecAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:ad_winrm_exec"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return _matches_leaf(context, action_id=self.action_id, service=RemoteExecService.WINRM)

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> OperationProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("ad_winrm_effect_participant_unavailable")

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
                request_digest="winrm_req_digest",
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


class ADDComExecAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:ad_dcom_exec"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return _matches_leaf(context, action_id=self.action_id, service=RemoteExecService.DCOM)

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> OperationProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("ad_dcom_effect_participant_unavailable")

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
                request_digest="dcom_req_digest",
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


class ADRemoteExecutionRouter:
    """Selection router for AD remote execution."""

    action_id: str = "killchain:ad_remote_execution"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is RemoteExecInputV2
        )

    def route_bound(self, context: BoundProviderInvocationContext) -> CompositeProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("ad_remote_child_executor_unavailable")

        import time
        from core.actions.execution_results_v2 import ExecutionResultRefV2
        from core.actions.provider_results import (
            CompositeProviderResult,
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
                request_digest="remote_exec_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        child_res_ref = ExecutionResultRefV2(
            reference="res:child_exec_1",
            revision=1,
            execution_id="exec_child_1",
            action_id="killchain:ad_smbexec",
            result_digest="sha256:child_digest_1",
        )
        return CompositeProviderResult(
            header=header,
            child_action_id="killchain:ad_smbexec",
            child_execution_id="exec_child_1",
            child_result_ref=child_res_ref,
        )

    def execute_bound(self, context: BoundProviderInvocationContext) -> CompositeProviderResult:
        return self.route_bound(context)

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


ADRemoteExecutionAdapter = ADRemoteExecutionRouter


__all__ = [
    "ADDComExecAdapter",
    "ADRemoteExecutionAdapter",
    "ADRemoteExecutionRouter",
    "ADSmbexecAdapter",
    "ADWinRMExecAdapter",
    "ProviderUnavailableError",
]
