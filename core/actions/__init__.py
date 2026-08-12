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
    bind_provider_handle,
    canonical_assessment_applicability,
    register_tool_adapters,
)
from .base import ActionAdapter, ManualGatedActionAdapter
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
    ActiveRiskClass,
    ApplicabilityResult,
    ApplicabilityStatus,
    AttemptStatus,
    CheckStatus,
    CleanupStatus,
    OutcomeStatus,
    PolicyDenial,
    VerificationStatus,
)
from .selection import (
    PROVIDER_SELECTION_SCHEMA_VERSION,
    IngestionOutcome,
    PartialIngestCallback,
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
    plugin_manager: Any | None = None,
) -> ActionCatalog:
    """Build adapters for the current decorator registry without replacing it."""

    if tool_defs is None:
        from core.tools.registry import list_tools

        tool_defs = list_tools()
    definitions = tuple(tool_defs)
    catalog_definitions = tuple(
        tool_def
        for tool_def in definitions
        if not (plugin_manager is not None and str(getattr(tool_def, "name", "")).strip().casefold() == "plugin")
    )
    catalog = ActionCatalog()
    manual_catalog = ActionCatalog(include_manual_gated=True)
    for tool_def in catalog_definitions:
        manual = manual_catalog.resolve(str(getattr(tool_def, "name", "")))
        if manual is not None and manual.adapter.descriptor.manual_gate:
            catalog.register(manual.adapter)
    # With a runtime-owned manager, ``plugin`` is command grammar rather than
    # an executable provider.  Publishing its legacy registry adapter would
    # let direct action callers construct a second PluginManager and bypass the
    # concrete ``plugin:<name>`` adapters mounted below.
    register_tool_adapters(catalog, catalog_definitions, dispatch)
    expected = {str(tool_def.name).strip().casefold() for tool_def in catalog_definitions}
    covered = {descriptor.name.strip().casefold() for descriptor in catalog.descriptors()}
    missing = expected - covered
    unexpected = covered - expected
    if missing or unexpected:
        missing_str = ", ".join(sorted(missing)) or "none"
        unexpected_str = ", ".join(sorted(unexpected)) or "none"
        raise RuntimeError(
            f"Action catalog does not match the decorator registry: missing={missing_str}; unexpected={unexpected_str}"
        )
    if plugin_manager is not None:
        catalog.register_plugins(plugin_manager)
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
    "ActiveRiskClass",
    "ApplicabilityResult",
    "ApplicabilityStatus",
    "AttemptStatus",
    "CheckStatus",
    "CleanupStatus",
    "ExploitBaseAdapter",
    "IngestionOutcome",
    "KillchainActionAdapter",
    "ManualGatedActionAdapter",
    "MetasploitActionAdapter",
    "OutcomeStatus",
    "PartialIngestCallback",
    "PluginActionAdapter",
    "PolicyDenial",
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
    "bind_provider_handle",
    "build_action_catalog",
    "canonical_assessment_applicability",
    "register_tool_adapters",
    "target_class",
]
