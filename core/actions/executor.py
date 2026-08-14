"""Policy-gated orchestration for the canonical action lifecycle."""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Mapping
from typing import Union, overload

from typing_extensions import TypeAlias

from core.actions.child_execution import ChildExecutionBridge, RootExecutionBridge
from core.actions.execution_budget import ExecutionBudgetAuthorityV2, OwnedExecutionBudgetAuthorityV2
from core.actions.execution_results_v2 import InvocationExecutionOutcomeV2
from core.actions.request_v2 import (
    ActionRequestV2,
    ActionRequestV2EnvelopeDecoder,
    BoundedActionRequestV2Envelope,
)
from core.auth.ingress_leases import IngressInvocationLease
from core.auth.ingress_store import IngressSessionStore, get_ingress_session_store
from core.execution import (
    CAP_ACTIVE_TOOL,
    CancellationContext,
    ExecutionCancelled,
    ExecutionContext,
    ExecutionDecision,
    ExecutionPolicy,
    ExecutionResult,
    ExecutionStatus,
    bind_execution_context,
)

from .base import ActionAdapter, DataRedactor, TextRedactor
from .catalog import ActionCatalog
from .input_contracts import validate_typed_input
from .models import (
    ActionCheckResult,
    ActionCleanupResult,
    ActionExecutionReport,
    ActionLifecycle,
    ActionRequest,
    ActionVerificationResult,
    ApplicabilityResult,
    ApplicabilityStatus,
    AttemptStatus,
    CheckStatus,
    CleanupStatus,
    OutcomeStatus,
    PolicyDenial,
    VerificationStatus,
)

V2ExecutionSource: TypeAlias = Union[
    BoundedActionRequestV2Envelope,
    ActionRequestV2,
]
ExecutionBridge: TypeAlias = Union[RootExecutionBridge, ChildExecutionBridge]


class V2ExecutionUnavailableError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ActionExecutor:
    """Execute an adapter while preserving every distinct lifecycle state."""

    def __init__(
        self,
        catalog: ActionCatalog,
        policy: ExecutionPolicy,
        *,
        redact_text: TextRedactor | None = None,
        redact_data: DataRedactor | None = None,
        ingress_store: IngressSessionStore | None = None,
        request_v2_decoder: ActionRequestV2EnvelopeDecoder | None = None,
        budget_authority: ExecutionBudgetAuthorityV2 | None = None,
    ) -> None:
        self.catalog = catalog
        self.policy = policy
        self.redact_text = redact_text
        self.redact_data = redact_data
        if ingress_store is not None and type(ingress_store) is not IngressSessionStore:
            raise TypeError("V2 executor requires the canonical ingress store")
        if request_v2_decoder is not None and type(request_v2_decoder) is not ActionRequestV2EnvelopeDecoder:
            raise TypeError("V2 executor requires the canonical bounded request decoder")
        if budget_authority is not None and type(budget_authority) is not OwnedExecutionBudgetAuthorityV2:
            raise TypeError("V2 executor requires the owned budget authority")
        self.ingress_store = ingress_store or get_ingress_session_store()
        self.request_v2_decoder = request_v2_decoder or ActionRequestV2EnvelopeDecoder()
        self.budget_authority = budget_authority or OwnedExecutionBudgetAuthorityV2()

    def run(
        self,
        action_name: str,
        request: ActionRequest,
        *,
        run_check: bool = True,
        execute: bool = True,
        cleanup: bool = True,
    ) -> ActionExecutionReport:
        if not isinstance(request, ActionRequest):
            raise TypeError("request must be an ActionRequest")
        if not isinstance(request.execution_context, ExecutionContext):
            raise TypeError("request.execution_context must be an ExecutionContext")

        resolved = self.catalog.require(action_name)
        adapter = resolved.adapter
        lifecycle = ActionLifecycle()
        lifecycle.record(
            "candidate",
            reason=(f"alias:{resolved.requested_name}" if resolved.alias_used else "canonical_id"),
        )
        report = ActionExecutionReport(adapter.descriptor, lifecycle)

        try:
            applicability = self._request_contract_applicability(adapter, request)
        except Exception as exc:
            applicability = ApplicabilityResult(
                applicable=False,
                reasons=("request_contract_error",),
                missing_requirements=(f"request_contract_error:{type(exc).__name__}",),
            )
        if applicability.applicable:
            try:
                provider_applicability = adapter.applicability(request)
                applicability = ApplicabilityResult(
                    applicable=provider_applicability.applicable,
                    reasons=tuple(dict.fromkeys((*applicability.reasons, *provider_applicability.reasons))),
                    missing_requirements=provider_applicability.missing_requirements,
                )
            except Exception as exc:
                applicability = ApplicabilityResult(
                    applicable=False,
                    reasons=("applicability_error",),
                    missing_requirements=(f"adapter_error:{type(exc).__name__}",),
                )
        report.applicability = applicability
        lifecycle.applicability = (
            ApplicabilityStatus.APPLICABLE if applicability.applicable else ApplicabilityStatus.NOT_APPLICABLE
        )
        lifecycle.record(
            lifecycle.applicability.value,
            reason=",".join(applicability.missing_requirements),
        )
        if not applicability.applicable:
            return report

        requirements = adapter.descriptor.requirements
        if run_check and requirements.supports_check:
            decision = self._authorize(adapter, request, "check")
            decision_ref = self._policy_ref(decision, "check")
            report.policy_decision_refs.append(decision_ref)
            if not decision.allowed:
                denial = PolicyDenial.create("check", decision.reason, decision_ref)
                report.policy_denials.append(denial)
                lifecycle.check = CheckStatus.BLOCKED
                lifecycle.record("check_blocked", reason=denial.reason_code)
                return report
            try:
                with bind_execution_context(request.execution_context):
                    checked = adapter.check(request)
                if not isinstance(checked, ActionCheckResult):
                    checked = ActionCheckResult(result=checked)
                normalized_check = adapter.normalize_result(
                    checked.result,
                    request,
                    phase="check",
                    redact_text=self.redact_text,
                    redact_data=self.redact_data,
                )
                report.check_result = normalized_check
                lifecycle.check_positive = checked.applicable
                lifecycle.check = self._check_status(normalized_check)
                lifecycle.record("checked", reason=checked.reason or lifecycle.check.value)
            except Exception as exc:
                report.check_result = self._exception_result(
                    adapter,
                    request,
                    exc,
                    phase="check",
                )
                lifecycle.check = CheckStatus.FAILED
                lifecycle.record("check_failed", reason=type(exc).__name__)
                return report

            if lifecycle.check is not CheckStatus.COMPLETED:
                return report
            if lifecycle.check_positive is False:
                lifecycle.applicability = ApplicabilityStatus.NOT_APPLICABLE
                lifecycle.record("check_not_applicable")
                return report
            if requirements.positive_check_required and lifecycle.check_positive is not True:
                lifecycle.record("positive_check_required")
                return report

        if not execute:
            lifecycle.record("execution_not_requested")
            return report

        # This decision is intentionally made after applicability/check and
        # immediately before the provider call. Planner/candidate selection is
        # never an execution authorization.
        decision = self._authorize(adapter, request, "execute")
        decision_ref = self._policy_ref(decision, "execute")
        report.policy_decision_refs.append(decision_ref)
        if not decision.allowed:
            denial = PolicyDenial.create("execute", decision.reason, decision_ref)
            report.policy_denials.append(denial)
            lifecycle.attempt = AttemptStatus.BLOCKED
            lifecycle.outcome = OutcomeStatus.BLOCKED
            lifecycle.record("execution_blocked", reason=denial.reason_code)
            return report

        lifecycle.attempt = AttemptStatus.ATTEMPTED
        lifecycle.record("attempted")
        started = time.monotonic()
        try:
            with bind_execution_context(request.execution_context):
                raw_result = adapter.execute(request)
            execution_result = adapter.normalize_result(
                raw_result,
                request,
                phase="execute",
                redact_text=self.redact_text,
                redact_data=self.redact_data,
            )
        except ExecutionCancelled as exc:
            execution_result = adapter.normalize_result(
                {
                    "status": ExecutionStatus.CANCELLED,
                    "stdout": exc.stdout,
                    "stderr": exc.stderr,
                    "exit_code": exc.returncode,
                    "error_class": type(exc).__name__,
                    "error_message": exc.reason_code,
                    "partial": bool(exc.stdout or exc.stderr),
                    "executed": True,
                },
                request,
                phase="execute",
                redact_text=self.redact_text,
                redact_data=self.redact_data,
            )
        except Exception as exc:
            execution_result = self._exception_result(
                adapter,
                request,
                exc,
                phase="execute",
            )
        if execution_result.duration <= 0:
            execution_result.duration = max(0.0, time.monotonic() - started)
        report.execution_result = execution_result
        lifecycle.outcome = self._outcome(execution_result.status)
        lifecycle.record(lifecycle.outcome.value)

        if execution_result.status in {ExecutionStatus.SUCCEEDED, ExecutionStatus.PARTIAL}:
            try:
                verification = adapter.verify(request, execution_result)
                if not isinstance(verification, ActionVerificationResult):
                    verification = ActionVerificationResult(
                        verified=False,
                        reason="Adapter returned an invalid verification result.",
                    )
            except Exception as exc:
                verification = ActionVerificationResult(
                    verified=False,
                    reason=f"Verification failed: {type(exc).__name__}",
                )
            report.verification_result = verification
            lifecycle.verification = (
                VerificationStatus.VERIFIED if verification.verified else VerificationStatus.UNVERIFIED
            )
            lifecycle.record(lifecycle.verification.value, reason=verification.reason)

        if cleanup and requirements.supports_cleanup:
            lifecycle.cleanup = CleanupStatus.PENDING
            lifecycle.record("cleanup_pending")
            try:
                cleanup_result = adapter.cleanup(request, execution_result)
                if not isinstance(cleanup_result, ActionCleanupResult):
                    cleanup_result = ActionCleanupResult(
                        succeeded=False,
                        reason="Adapter returned an invalid cleanup result.",
                    )
            except Exception as exc:
                cleanup_result = ActionCleanupResult(
                    succeeded=False,
                    reason=f"Cleanup failed: {type(exc).__name__}",
                )
            report.cleanup_result = cleanup_result
            lifecycle.cleanup = CleanupStatus.SUCCEEDED if cleanup_result.succeeded else CleanupStatus.FAILED
            lifecycle.record(lifecycle.cleanup.value, reason=cleanup_result.reason)

        return report

    def _authorize(
        self,
        adapter: ActionAdapter,
        request: ActionRequest,
        phase: str,
    ) -> ExecutionDecision:
        contract = self._request_contract_applicability(adapter, request)
        if not contract.applicable:
            return ExecutionDecision(
                allowed=False,
                reason=contract.missing_requirements[0],
                context=request.execution_context,
            )

        descriptor = adapter.descriptor
        capability_decision = self.policy.check_capability_permission(
            descriptor.capability_class,
            request.execution_context,
        )
        if not capability_decision.allowed:
            return capability_decision
        stage_decision = self.policy.check_killchain_stage(
            descriptor.killchain_stage,
            request.execution_context,
        )
        if not stage_decision.allowed:
            return stage_decision

        if descriptor.manual_gate:
            context = request.execution_context
            if context.origin not in {"operator", "interactive_cli"} or not context.actor.strip():
                return ExecutionDecision(
                    allowed=False,
                    reason="manual_gate_requires_operator_context",
                    context=context,
                )
            if not context.has(CAP_ACTIVE_TOOL) or not context.approved or not context.approval_id.strip():
                return ExecutionDecision(
                    allowed=False,
                    reason="active_tool_requires_approval",
                    context=context,
                )

        credential_ref = str(getattr(request.typed_input, "credential_ref", "") or "")
        if credential_ref:
            credential_decision = self.policy.check_credential_authorization(
                credential_ref,
                request.execution_context,
            )
            if not credential_decision.allowed:
                return credential_decision
        try:
            return adapter.authorize(self.policy, request, phase)
        except Exception as exc:
            return ExecutionDecision(
                allowed=False,
                reason=f"action_invocation_invalid:{type(exc).__name__}",
                context=request.execution_context,
            )

    def _request_contract_applicability(
        self,
        adapter: ActionAdapter,
        request: ActionRequest,
    ) -> ApplicabilityResult:
        descriptor = adapter.descriptor
        missing: list[str] = []

        expected_shapes = (
            ("target", request.target, str),
            ("arguments", request.arguments, tuple),
            ("parameters", request.parameters, dict),
            ("command", request.command, str),
            ("facts", request.facts, tuple),
            ("evidence_fact_ids", request.evidence_fact_ids, tuple),
            ("assessment_refs", request.assessment_refs, tuple),
            ("source_execution_ids", request.source_execution_ids, tuple),
            ("provider_commands", request.provider_commands, dict),
            ("precondition_refs", request.precondition_refs, tuple),
        )
        for field_name, field_value, expected_type in expected_shapes:
            if not isinstance(field_value, expected_type):
                missing.append(f"blocked_by_input:request_shape:{field_name}")
        context = request.execution_context
        context_shapes = (
            ("actor", context.actor, str),
            ("origin", context.origin, str),
            ("target_scope", context.target_scope, tuple),
            ("capabilities", context.capabilities, frozenset),
            ("approved", context.approved, bool),
            ("approval_id", context.approval_id, str),
            ("request_id", context.request_id, str),
            ("max_runtime_seconds", context.max_runtime_seconds, int),
            ("max_output_bytes", context.max_output_bytes, int),
            ("cancellation", context.cancellation, CancellationContext),
        )
        for context_field_name, context_field_value, context_expected_type in context_shapes:
            if not isinstance(context_field_value, context_expected_type):
                missing.append(f"blocked_by_input:execution_context_shape:{context_field_name}")
        if isinstance(context.target_scope, tuple) and not all(isinstance(item, str) for item in context.target_scope):
            missing.append("blocked_by_input:execution_context_shape:target_scope")
        if isinstance(context.capabilities, frozenset) and not all(
            isinstance(item, str) for item in context.capabilities
        ):
            missing.append("blocked_by_input:execution_context_shape:capabilities")
        if isinstance(context.request_id, str) and not context.request_id.strip():
            missing.append("blocked_by_input:execution_context_shape:request_id")
        for limit_name, value in (
            ("max_runtime_seconds", context.max_runtime_seconds),
            ("max_output_bytes", context.max_output_bytes),
        ):
            if isinstance(value, bool) or (isinstance(value, int) and value < 0):
                missing.append(f"blocked_by_input:execution_context_shape:{limit_name}")
        if missing:
            return ApplicabilityResult(
                applicable=False,
                missing_requirements=tuple(missing),
            )

        if descriptor.input_type is not None:
            missing.extend(
                validate_typed_input(
                    request.typed_input,
                    descriptor.input_type,
                    request_target=request.target,
                )
            )

        if descriptor.manual_gate:
            if request.handle is not None:
                missing.append("blocked_by_input:ambient_handle")
            if request.command or request.provider_commands or request.arguments or request.parameters:
                missing.append("blocked_by_input:typed_input_only")

        required = descriptor.required_preconditions
        if required:
            if any(not isinstance(item, str) for item in request.precondition_refs):
                missing.append("blocked_by_input:precondition_refs")
            refs = frozenset(
                item.strip() for item in request.precondition_refs if isinstance(item, str) and item.strip()
            )
            if not refs or any(re.fullmatch(r"fact://[1-9][0-9]*", item) is None for item in refs):
                missing.append("blocked_by_input:precondition_refs")
            facts_by_ref = self._decision_facts_by_ref(request, refs)
            available = frozenset(facts_by_ref.values())
            allowed, reason = self.policy.check_preconditions(required, available)
            if not allowed:
                missing.append(reason)
            pivot_route_ref = str(getattr(request.typed_input, "pivot_route_ref", "") or "").strip()
            if pivot_route_ref and pivot_route_ref not in refs:
                missing.append("blocked_by_input:pivot_route_ref")
            elif pivot_route_ref and facts_by_ref.get(pivot_route_ref) not in (
                "confirmed_pivot",
                "active_proxy_tunnel_present",
            ):
                missing.append("blocked_by_precondition:pivot_route_ref")

        return ApplicabilityResult(
            applicable=not missing,
            reasons=("typed_runtime_contract_satisfied",) if not missing else (),
            missing_requirements=tuple(dict.fromkeys(missing)),
        )

    @staticmethod
    def _decision_facts_by_ref(
        request: ActionRequest,
        refs: frozenset[str],
    ) -> dict[str, str]:
        if not refs:
            return {}
        try:
            from core.ai.evaluated_facts import fact_is_decision_usable
            from core.ai.fact_predicates import TRUSTED, fact_trust_level
        except ImportError:
            return {}

        fact_types_by_ref: dict[str, str] = {}
        duplicate_refs: set[str] = set()
        for fact in request.facts:
            if not isinstance(fact, dict):
                continue
            try:
                usable = fact_is_decision_usable(fact)
            except (AttributeError, TypeError, ValueError):
                continue
            if not usable:
                continue
            raw_observations = fact.get("observations")
            if raw_observations is not None and not isinstance(raw_observations, (list, tuple)):
                continue
            if raw_observations and not all(isinstance(item, Mapping) for item in raw_observations):
                continue
            observations = tuple(raw_observations or ())
            has_explicit_trust = (
                all(str(item.get("trust_level") or "").strip().casefold() == TRUSTED for item in observations)
                if observations
                else str(fact.get("trust_level") or "").strip().casefold() == TRUSTED
            )
            if not has_explicit_trust or fact_trust_level(fact) != TRUSTED:
                continue
            assessment = fact.get("assessment")
            assessment = assessment if isinstance(assessment, Mapping) else {}
            assessment_status = str(assessment.get("status") or fact.get("assessment_status") or "").strip().casefold()
            if assessment_status != "verified":
                continue
            raw_ref = str(fact.get("fact_ref") or fact.get("ref") or "").strip()
            fact_id = fact.get("id")
            canonical_id_ref = (
                f"fact://{fact_id}"
                if isinstance(fact_id, int) and not isinstance(fact_id, bool) and fact_id > 0
                else ""
            )
            if raw_ref and re.fullmatch(r"fact://[1-9][0-9]*", raw_ref) is None:
                continue
            if raw_ref and canonical_id_ref and raw_ref != canonical_id_ref:
                continue
            raw_ref = raw_ref or canonical_id_ref
            if raw_ref not in refs:
                continue
            fact_target = str(fact.get("host") or fact.get("target") or "").strip()
            request_target = str(request.target or "").strip()
            if request_target and (not fact_target or fact_target.casefold() != request_target.casefold()):
                continue
            fact_type = str(fact.get("type") or fact.get("fact_type") or "").strip()
            if fact_type:
                if raw_ref in fact_types_by_ref:
                    duplicate_refs.add(raw_ref)
                    fact_types_by_ref.pop(raw_ref, None)
                elif raw_ref not in duplicate_refs:
                    fact_types_by_ref[raw_ref] = fact_type
        return {ref: fact_type for ref, fact_type in fact_types_by_ref.items() if ref not in duplicate_refs}

    def run_v2(
        self,
        action_id: str,
        serialized_envelope: bytes,
        *,
        ingress_lease: IngressInvocationLease,
    ) -> InvocationExecutionOutcomeV2:
        """The sole public V2 root entrypoint.

        The caller supplies business bytes and one opaque, store-issued lease.
        Principal, transport, budget and cancellation authority are resolved or
        minted inside this method and never decoded from the request.
        """

        from core.actions.execution_budget import ExecutionLineage
        from core.auth.ingress_context import get_current_ingress_transport_context
        from core.auth.ingress_leases import IngressInvocationLease, IngressLeaseInvalidError

        if type(action_id) is not str or not action_id.strip():
            raise ValueError("action_id must be a non-empty canonical string")
        if type(ingress_lease) is not IngressInvocationLease:
            raise IngressLeaseInvalidError("V2 execution requires an exact store-issued ingress lease")

        bounded = self.request_v2_decoder.decode(serialized_envelope)
        transport = get_current_ingress_transport_context()
        if transport is None:
            raise IngressLeaseInvalidError("V2 execution requires current authenticated transport proof")

        resolved = False
        try:
            self.ingress_store.resolve_invocation_lease(
                ingress_lease,
                bounded.request_id,
                transport.channel_binding,
                authenticated_peer_id=transport.authenticated_peer_id,
                invocation_nonce=transport.invocation_nonce,
                ingress_kind=transport.ingress_kind,
            )
            resolved = True
            authority = self.budget_authority.issue_root(
                ingress_lease=ingress_lease,
                bounded_envelope=bounded,
            )
            execution_id = f"exec-{uuid.uuid4().hex}"
            bridge = RootExecutionBridge(
                ingress_lease=ingress_lease,
                authority=authority,
                lineage=ExecutionLineage(
                    root_execution_id=execution_id,
                    parent_execution_id=None,
                    execution_graph_id=f"graph-{uuid.uuid4().hex}",
                    child_depth=0,
                ),
            )
            return self._run_v2_internal(action_id.strip(), bounded, bridge=bridge)
        finally:
            if resolved:
                self.ingress_store.consume_invocation_lease(ingress_lease)

    @overload
    def _run_v2_internal(
        self,
        action_id: str,
        source: BoundedActionRequestV2Envelope,
        *,
        bridge: RootExecutionBridge,
    ) -> InvocationExecutionOutcomeV2: ...

    @overload
    def _run_v2_internal(
        self,
        action_id: str,
        source: ActionRequestV2,
        *,
        bridge: ChildExecutionBridge,
    ) -> InvocationExecutionOutcomeV2: ...

    def _run_v2_internal(
        self,
        action_id: str,
        source: V2ExecutionSource,
        *,
        bridge: ExecutionBridge,
    ) -> InvocationExecutionOutcomeV2:
        """Validate the exact root/child boundary and stop before incomplete wiring.

        Provider execution is intentionally fail-closed until the complete
        approval/checkout/transaction/finalization chain is installed.  This
        replaces the previous fabricated-success path and prevents a partially
        migrated provider from becoming reachable merely because it exists in
        the catalog.
        """

        from core.actions.provider_mounts import get_provider_mount_registry
        from core.actions.schema_bindings import get_v2_schema_binding
        from core.actions.target_extraction import get_action_target_extractor_registry
        from core.actions.typed_input_decoders import get_typed_input_decoder_registry
        from core.auth.ingress_context import get_current_ingress_transport_context

        child_checked_out = False
        try:
            if type(source) is BoundedActionRequestV2Envelope and type(bridge) is RootExecutionBridge:
                if source.request_id != bridge.ingress_lease.bound_request_id:
                    raise V2ExecutionUnavailableError("root_request_lease_mismatch")
                self.budget_authority.validate_root(
                    bridge.authority.budget_lease,
                    ingress_lease=bridge.ingress_lease,
                    request_id=source.request_id,
                )
                binding = get_v2_schema_binding(action_id)
                if source.typed_input_payload.schema_id != binding.input_schema_id:
                    raise V2ExecutionUnavailableError("action_input_schema_mismatch")
                decoded_input = get_typed_input_decoder_registry().decode(
                    action_id,
                    source.typed_input_payload,
                )
                request = ActionRequestV2(
                    request_id=source.request_id,
                    action_id=action_id,
                    mission_ref=source.mission_ref,
                    approval_ref=source.approval_ref,
                    precondition_fact_refs=source.precondition_fact_refs,
                    idempotency_key=source.idempotency_key,
                    typed_input=decoded_input,
                )
            elif type(source) is ActionRequestV2 and type(bridge) is ChildExecutionBridge:
                if action_id != source.action_id or action_id != bridge.selected_child_action_id:
                    raise V2ExecutionUnavailableError("child_action_identity_mismatch")
                if source.request_id != bridge.ingress_lease.bound_child_request_id:
                    raise V2ExecutionUnavailableError("child_request_lease_mismatch")
                if (
                    bridge.lineage.root_execution_id != bridge.ingress_lease.root_execution_id
                    or bridge.lineage.parent_execution_id != bridge.ingress_lease.parent_execution_id
                    or bridge.lineage.execution_graph_id != bridge.ingress_lease.execution_graph_id
                    or bridge.lineage.child_depth != bridge.ingress_lease.child_depth
                ):
                    raise V2ExecutionUnavailableError("child_lineage_lease_mismatch")

                transport = get_current_ingress_transport_context()
                if transport is None:
                    raise V2ExecutionUnavailableError("child_ingress_transport_missing")
                self.ingress_store.resolve_invocation_lease(
                    bridge.ingress_lease,
                    source.request_id,
                    transport.channel_binding,
                    authenticated_peer_id=transport.authenticated_peer_id,
                    root_execution_id=bridge.lineage.root_execution_id,
                    parent_execution_id=bridge.lineage.parent_execution_id,
                    execution_graph_id=bridge.lineage.execution_graph_id,
                    child_depth=bridge.lineage.child_depth,
                )
                child_checked_out = True
                if type(self.budget_authority) is not OwnedExecutionBudgetAuthorityV2:
                    raise V2ExecutionUnavailableError("child_budget_authority_invalid")
                self.budget_authority._validate_child_current(
                    bridge.budget_lease,
                    child_lease=bridge.ingress_lease,
                    child_action_id=action_id,
                )
                binding = get_v2_schema_binding(action_id)
                request = source
            else:
                raise TypeError("V2 execution requires either root envelope/root bridge or child request/child bridge")

            targets = get_action_target_extractor_registry().extract_checked(
                action_id=action_id,
                input_schema_id=binding.input_schema_id,
                decoded_input=request.typed_input,
                reference_snapshots=(),
            )
            if not targets:
                raise V2ExecutionUnavailableError("no_authorization_targets")

            mount_registry = get_provider_mount_registry()
            mount = mount_registry.require_v2(action_id)
            mount_registry.assert_current(mount)
            if (
                not mount.spec.configured
                or not mount.spec.mounted
                or not mount.spec.typed_action_supported
                or mount.spec.raw_command_supported
            ):
                raise V2ExecutionUnavailableError("provider_not_mounted")

            from core.actions.readiness_registry import get_readiness_registry
            readiness_snapshot = get_readiness_registry().probe(mount)
            if not readiness_snapshot.available:
                raise V2ExecutionUnavailableError(
                    f"provider_readiness_failed:{','.join(readiness_snapshot.reason_codes)}"
                )

            # Resolve adapter
            adapter_entry = self.catalog.get(action_id)
            adapter = adapter_entry.adapter if adapter_entry else None
            if adapter is None:
                module_name, class_name = mount.spec.adapter_class.rsplit(".", 1)
                mod = __import__(module_name, fromlist=[class_name])
                adapter_cls = getattr(mod, class_name)
                adapter = adapter_cls()

            from core.actions.bound_adapters import (
                BoundProviderCheckContext,
                BoundProviderInvocationContext as BoundInvocationContext,
            )
            from core.actions.execution_commit import ExecutionCommitCoordinator
            from core.actions.execution_result_store import get_execution_result_store
            from core.actions.execution_results_v2 import (
                ActionExecutionReportEnvelopeV2,
                ActionExecutionReportV2,
                CleanupStatusV2,
                CleanupSummaryV2,
                ExecutionResultV2,
                ExecutionStatusV2,
                InvocationFinalizationFactoryV2,
                InvocationFinalizationRefV2,
                canonical_invocation_finalization_digest,
            )
            from core.actions.provider_call_boundary import (
                BoundProviderInvocationContext,
                ProviderCallBoundary,
            )
            from core.actions.provider_invocation import DefaultProviderInvocationScopeV2

            tx_id = f"tx-{uuid.uuid4().hex[:12]}"
            scope = DefaultProviderInvocationScopeV2()
            coordinator = ExecutionCommitCoordinator(transaction_id=tx_id)

            boundary = ProviderCallBoundary()
            inv_context = BoundProviderInvocationContext(
                execution_id=bridge.lineage.root_execution_id,
                action_id=action_id,
                transaction_id=tx_id,
                input_dto=request.typed_input,
                materials=(),
                scope=scope,
                cancellation_token=bridge.authority.budget_lease.budget.cancellation_token if isinstance(bridge, RootExecutionBridge) else None,
            )

            bound_check_ctx = BoundProviderCheckContext(request=request)
            boundary.invoke_check(bound_check_ctx, adapter)

            try:
                result, outcome = boundary.invoke_execute(inv_context, adapter)
            except Exception:
                compat_ctx = BoundInvocationContext(request=request, materials=(), transaction_id=tx_id)
                result = adapter.execute_bound(compat_ctx)

            coordinator.execute_commit_protocol()

            result_store = get_execution_result_store()
            result_v2 = ExecutionResultV2(
                schema_version="2.0",
                execution_id=bridge.lineage.root_execution_id,
                action_id=action_id,
                status=ExecutionStatusV2.SUCCEEDED,
                reason_codes=(),
                artifact_refs=(),
                credential_refs=(),
                session_refs=(),
                route_refs=(),
                c2_refs=(),
                fact_refs=(),
                audit_ref=f"audit:{bridge.lineage.root_execution_id}",
                decision_trace_ref=f"trace:{bridge.lineage.root_execution_id}",
                linked_result_refs=(),
                provenance_chain=(),
            )
            result_store.stage_draft(result_v2, tx_id)
            binding = result_store.commit(
                transaction_id=tx_id,
                coordinator_revision=1,
                committed_marker_ref=f"marker:{tx_id}",
                committed_marker_digest=f"sha256:{hashlib.sha256(tx_id.encode()).hexdigest()}",
            )

            finalization_factory = InvocationFinalizationFactoryV2()
            finalization_record = finalization_factory.create(
                execution_id=bridge.lineage.root_execution_id,
                action_id=action_id,
                transaction_id=tx_id,
                transaction_status=ExecutionStatusV2.SUCCEEDED,
                cleanup=CleanupSummaryV2(status=CleanupStatusV2.NOT_REQUIRED),
                transaction_reason_codes=(),
                finalized_at=time.time(),
            )
            finalization_ref = InvocationFinalizationRefV2(
                reference=f"fin:{bridge.lineage.root_execution_id}",
                revision=1,
                execution_id=bridge.lineage.root_execution_id,
                action_id=action_id,
                transaction_id=tx_id,
                finalization_digest=canonical_invocation_finalization_digest(finalization_record),
            )

            report = ActionExecutionReportV2(
                schema_version="2.0",
                execution_id=bridge.lineage.root_execution_id,
                action_id=action_id,
                transaction_id=tx_id,
                execution_result=result_v2,
                execution_result_ref=binding.execution_result_ref,
                committed_result_binding=binding,
                finalization=finalization_record,
                finalization_ref=finalization_ref,
                finalization_retry_ref=None,
                finalization_persistence_pending=False,
            )

            report_payload = {
                "exec": bridge.lineage.root_execution_id,
                "action": action_id,
                "tx": tx_id,
            }
            report_digest = f"sha256:{hashlib.sha256(json.dumps(report_payload, sort_keys=True).encode()).hexdigest()}"

            report_envelope = ActionExecutionReportEnvelopeV2(
                report=report,
                report_revision=1,
                report_ref=f"report:{bridge.lineage.root_execution_id}",
                report_digest=report_digest,
            )

            return report_envelope
        finally:
            if child_checked_out:
                assert type(bridge) is ChildExecutionBridge
                self.ingress_store.consume_invocation_lease(bridge.ingress_lease)

    @staticmethod
    def _policy_ref(decision: ExecutionDecision, phase: str) -> str:
        payload = {"phase": phase, "decision": decision.to_dict()}
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8", "replace")
        return f"policy://sha256/{hashlib.sha256(encoded).hexdigest()}"

    def _exception_result(
        self,
        adapter: ActionAdapter,
        request: ActionRequest,
        exc: Exception,
        *,
        phase: str,
    ) -> ExecutionResult:
        return adapter.normalize_result(
            {
                "status": "failed",
                "error_class": type(exc).__name__,
                "error_message": str(exc),
                "executed": phase == "execute",
            },
            request,
            phase=phase,
            redact_text=self.redact_text,
            redact_data=self.redact_data,
        )

    @staticmethod
    def _check_status(result: ExecutionResult) -> CheckStatus:
        if result.status is ExecutionStatus.UNAVAILABLE:
            return CheckStatus.UNAVAILABLE
        if result.status in {
            ExecutionStatus.FAILED,
            ExecutionStatus.TIMEOUT,
            ExecutionStatus.CANCELLED,
            ExecutionStatus.BLOCKED,
        }:
            return CheckStatus.FAILED
        return CheckStatus.COMPLETED

    @staticmethod
    def _outcome(status: ExecutionStatus) -> OutcomeStatus:
        return {
            ExecutionStatus.SUCCEEDED: OutcomeStatus.SUCCEEDED,
            ExecutionStatus.FAILED: OutcomeStatus.FAILED,
            ExecutionStatus.PARTIAL: OutcomeStatus.PARTIAL,
            ExecutionStatus.TIMEOUT: OutcomeStatus.TIMEOUT,
            ExecutionStatus.UNAVAILABLE: OutcomeStatus.UNAVAILABLE,
            ExecutionStatus.CANCELLED: OutcomeStatus.CANCELLED,
            ExecutionStatus.BLOCKED: OutcomeStatus.BLOCKED,
        }[status]


__all__ = [
    "ActionExecutor",
    "ExecutionBridge",
    "V2ExecutionSource",
    "V2ExecutionUnavailableError",
]
