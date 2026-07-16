"""Unified catalog and lifecycle adapters over existing action providers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from .adapters import (
    ExploitBaseAdapter,
    KillchainActionAdapter,
    MetasploitActionAdapter,
    PluginActionAdapter,
    RegisteredToolAdapter,
    canonical_assessment_applicability,
    register_tool_adapters,
)
from .base import ActionAdapter
from .catalog import ActionCatalog, ResolvedAction
from .executor import ActionExecutor
from .models import (
    ACTION_DESCRIPTOR_SCHEMA_VERSION,
    ACTION_LIFECYCLE_SCHEMA_VERSION,
    ActionCheckResult,
    ActionCleanupResult,
    ActionDescriptor,
    ActionExecutionReport,
    ActionKind,
    ActionLifecycle,
    ActionRequest,
    ActionRequirements,
    ActionVerificationResult,
    ApplicabilityResult,
    ApplicabilityStatus,
    AttemptStatus,
    CheckStatus,
    CleanupStatus,
    OutcomeStatus,
    VerificationStatus,
)
from .selection import (
    PROVIDER_SELECTION_SCHEMA_VERSION,
    IngestionOutcome,
    ProviderAttempt,
    ProviderCircuitBreaker,
    ProviderCircuitState,
    ProviderDecision,
    ProviderFallbackExecutor,
    ProviderRunResult,
    ProviderSelection,
    ProviderSelector,
    RetryClassifier,
)
from .telemetry import (
    PROVIDER_TELEMETRY_SCHEMA_VERSION,
    ProviderTelemetryEvent,
    ProviderTelemetryStore,
    ProviderTelemetrySummary,
    target_class,
)


def build_action_catalog(
    dispatch: Callable[[str, Any], Any],
    *,
    tool_defs: Iterable[Any] | None = None,
) -> ActionCatalog:
    """Build adapters for the current decorator registry without replacing it."""

    if tool_defs is None:
        from core.tools.registry import list_tools

        tool_defs = list_tools()
    catalog = ActionCatalog()
    register_tool_adapters(catalog, tuple(tool_defs), dispatch)
    return catalog


__all__ = [
    "ACTION_DESCRIPTOR_SCHEMA_VERSION",
    "ACTION_LIFECYCLE_SCHEMA_VERSION",
    "PROVIDER_SELECTION_SCHEMA_VERSION",
    "PROVIDER_TELEMETRY_SCHEMA_VERSION",
    "ActionAdapter",
    "ActionCatalog",
    "ActionCheckResult",
    "ActionCleanupResult",
    "ActionDescriptor",
    "ActionExecutionReport",
    "ActionExecutor",
    "ActionKind",
    "ActionLifecycle",
    "ActionRequest",
    "ActionRequirements",
    "ActionVerificationResult",
    "ApplicabilityResult",
    "ApplicabilityStatus",
    "AttemptStatus",
    "CheckStatus",
    "CleanupStatus",
    "ExploitBaseAdapter",
    "IngestionOutcome",
    "KillchainActionAdapter",
    "MetasploitActionAdapter",
    "OutcomeStatus",
    "PluginActionAdapter",
    "ProviderAttempt",
    "ProviderCircuitBreaker",
    "ProviderCircuitState",
    "ProviderDecision",
    "ProviderFallbackExecutor",
    "ProviderRunResult",
    "ProviderSelection",
    "ProviderSelector",
    "ProviderTelemetryEvent",
    "ProviderTelemetryStore",
    "ProviderTelemetrySummary",
    "RegisteredToolAdapter",
    "ResolvedAction",
    "RetryClassifier",
    "VerificationStatus",
    "build_action_catalog",
    "canonical_assessment_applicability",
    "register_tool_adapters",
    "target_class",
]
