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
)
from core.execution.policy import parse_invocation

from .models import (
    ActionCheckResult,
    ActionCleanupResult,
    ActionDescriptor,
    ActionRequest,
    ActionVerificationResult,
    ApplicabilityResult,
)

TextRedactor = Callable[..., str]
DataRedactor = Callable[..., Any]


class ActionAdapter(ABC):
    """Wrap one provider without changing that provider's public API."""

    descriptor: ActionDescriptor

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
        return policy.authorize_registered(
            self.invocation(request, phase),
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


__all__ = ["ActionAdapter", "DataRedactor", "TextRedactor"]
