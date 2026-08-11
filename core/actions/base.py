"""Base adapter contract shared by every existing action provider."""

from __future__ import annotations

import importlib.util
import shutil
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from core.execution import (
    ExecutionDecision,
    ExecutionPolicy,
    ExecutionResult,
    ToolInvocation,
    adapt_execution_result,
    validate_target,
)
from core.execution.policy import parse_invocation

from .input_contracts import validate_typed_input
from .models import (
    ActionCheckResult,
    ActionCleanupResult,
    ActionDescriptor,
    ActionRequest,
    ActionVerificationResult,
    ActiveRiskClass,
    ApplicabilityResult,
)

TextRedactor = Callable[..., str]
DataRedactor = Callable[..., Any]


class ActionAdapter(ABC):
    """Wrap one provider without changing that provider's public API."""

    descriptor: ActionDescriptor

    def active_risk_class(
        self,
        request: ActionRequest,
        phase: str = "execute",
    ) -> ActiveRiskClass:
        """Classify risk without granting authority or invoking a provider."""

        del request, phase
        return ActiveRiskClass.ACTIVE if self.descriptor.requirements.active else ActiveRiskClass.READ_ONLY

    def applicability(self, request: ActionRequest) -> ApplicabilityResult:
        requirements = self.descriptor.requirements
        missing: list[str] = []
        if requirements.target_required and not request.target.strip():
            missing.append("target")
        for dependency in requirements.system_dependencies:
            if shutil.which(dependency) is None:
                missing.append(f"binary:{dependency}")
        for dependency in requirements.python_dependencies:
            import_name = dependency.split("[", 1)[0].replace("-", "_")
            try:
                available = importlib.util.find_spec(import_name) is not None
            except (ImportError, AttributeError, ValueError):
                available = False
            if not available:
                missing.append(f"python:{dependency}")
        for capability in requirements.capabilities:
            if not request.execution_context.has(capability):
                missing.append(f"capability:{capability}")
        return ApplicabilityResult(
            applicable=not missing,
            reasons=("requirements_satisfied",) if not missing else (),
            missing_requirements=tuple(missing),
        )

    @abstractmethod
    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        """Build the typed invocation used for the final policy decision."""

    def authorize(
        self,
        policy: ExecutionPolicy,
        request: ActionRequest,
        phase: str,
    ) -> ExecutionDecision:
        invocation = self.invocation(request, phase)
        explicit_target = str(request.target or "").strip()
        if self.descriptor.requirements.target_required and not explicit_target:
            return ExecutionDecision(
                allowed=False,
                reason="missing_explicit_target",
                context=request.execution_context,
                invocation=invocation,
            )
        if explicit_target and (self.descriptor.requirements.target_required or self.descriptor.manual_gate):
            invocation = replace(
                invocation,
                targets=tuple(
                    dict.fromkeys(
                        (explicit_target, *invocation.targets),
                    )
                ),
            )
            if not validate_target(explicit_target):
                return ExecutionDecision(
                    allowed=False,
                    reason=f"invalid_target:{explicit_target[:120]}",
                    context=request.execution_context,
                    invocation=invocation,
                )
        return policy.authorize_registered(
            invocation,
            request.execution_context,
        )

    def check(self, request: ActionRequest) -> ActionCheckResult:
        raise NotImplementedError(f"Action {self.descriptor.action_id} has no check phase")

    @abstractmethod
    def execute(self, request: ActionRequest) -> Any:
        """Call the existing provider. Authorization is owned by the executor."""

    def verify(
        self,
        request: ActionRequest,
        result: ExecutionResult,
    ) -> ActionVerificationResult:
        if request.evidence_fact_ids and request.assessment_refs:
            return ActionVerificationResult(
                verified=True,
                reason="Caller supplied canonical evidence and assessment references.",
                evidence_fact_ids=request.evidence_fact_ids,
                assessment_refs=request.assessment_refs,
                source_execution_ids=request.source_execution_ids,
            )
        return ActionVerificationResult(
            verified=False,
            reason="Provider success is not independent evidence verification.",
        )

    def cleanup(
        self,
        request: ActionRequest,
        result: ExecutionResult | None,
    ) -> ActionCleanupResult:
        return ActionCleanupResult(succeeded=True, reason="No adapter cleanup required.")

    # --- unified runtime convenience accessors (phase-1.2) ---

    @property
    def input_type(self) -> type | None:
        """Typed input contract expected by this adapter, if any."""
        return self.descriptor.input_type

    @property
    def capability_class(self) -> str:
        """Capability category: recon, post_access, credential_extraction, etc."""
        return self.descriptor.capability_class

    @property
    def risk_class(self) -> str:
        """Risk classification: low, medium, high, critical."""
        return self.descriptor.risk_class

    @property
    def required_preconditions(self) -> tuple[str, ...]:
        """Fact-types that must exist before execution."""
        return self.descriptor.required_preconditions

    @property
    def killchain_stage(self) -> str | None:
        """Killchain stage binding, if any."""
        return self.descriptor.killchain_stage

    def normalize_result(
        self,
        value: Any,
        request: ActionRequest,
        *,
        phase: str,
        redact_text: TextRedactor | None = None,
        redact_data: DataRedactor | None = None,
    ) -> ExecutionResult:
        return adapt_execution_result(
            value,
            request_id=request.execution_context.request_id,
            tool_name=self.descriptor.name,
            max_output_bytes=request.execution_context.max_output_bytes,
            redact_text=redact_text,
            redact_data=redact_data,
        )

    @staticmethod
    def registered_invocation(command: str, registered_name: str) -> ToolInvocation:
        invocation = parse_invocation(command)
        return replace(invocation, registered_name=registered_name)


class ManualGatedActionAdapter(ActionAdapter):
    """Canonical identity whose operational provider is deliberately absent."""

    def applicability(self, request: ActionRequest) -> ApplicabilityResult:
        base = super().applicability(request)
        missing = list(base.missing_requirements)
        if self.descriptor.input_type is not None:
            missing.extend(
                validate_typed_input(
                    request.typed_input,
                    self.descriptor.input_type,
                    request_target=request.target,
                )
            )
        if request.handle is not None:
            missing.append("blocked_by_input:ambient_handle")
        if request.command or request.provider_commands or request.arguments or request.parameters:
            missing.append("blocked_by_input:typed_input_only")
        return ApplicabilityResult(
            applicable=not missing,
            reasons=("manual_gated_contract_satisfied",) if not missing else (),
            missing_requirements=tuple(dict.fromkeys(missing)),
        )

    def execute(self, request: ActionRequest) -> Any:
        del request
        return {
            "status": "unavailable",
            "executed": False,
            "error_class": "ProviderNotConfigured",
            "error_message": f"provider_not_configured:{self.descriptor.name}",
            "metadata": {
                "manual_gate": True,
                "provider_mounted": False,
            },
        }


__all__ = [
    "ActionAdapter",
    "DataRedactor",
    "ManualGatedActionAdapter",
    "TextRedactor",
]
