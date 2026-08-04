"""Frozen contracts for the additive Benchmark v4 efficiency analysis.

V4 intentionally projects verified v3 evidence.  It does not upgrade, mutate,
or reinterpret the published v3 run schema.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from ..v3.analysis import AnalysisPlan
from ..v3.schema import (
    EXECUTION_STATUSES,
    METRIC_RELIABILITIES,
    TASK_STATUSES,
    BenchmarkV3SchemaError,
    stable_digest,
)

EFFICIENCY_PLAN_SCHEMA_VERSION = "1.1"
EFFICIENCY_RUN_SCHEMA_VERSION = "1.0"
EFFICIENCY_STATISTICS_SCHEMA_VERSION = "1.1"

PRIMARY_RESOURCES = (
    "wall_time_seconds",
    "fixture_http_requests",
)
SECONDARY_RESOURCES = (
    "unique_fixture_targets",
    "repeated_fixture_requests",
    "unsuccessful_fixture_requests",
    "evidence_bearing_requests",
    "tool_calls",
    "output_bytes",
    "model_tokens",
    "api_cost_usd",
)
QUALITY_METRIC = "verified_f1"
ALL_RESOURCES = PRIMARY_RESOURCES + SECONDARY_RESOURCES
EFFICIENCY_METHODOLOGY = MappingProxyType(
    {
        "automatic_winner": False,
        "bootstrap_unit": "scenario_then_matched_block",
        "directional_claim_population_gate": "all_scheduled_pairs_exact_frozen_scenarios",
        "claim_resources": PRIMARY_RESOURCES,
        "completion_gate": "all_scheduled_noninferiority",
        "missing_data": "unavailable_no_imputation",
        "multiple_testing": "bonferroni_comparison_pairs_x_primary_resources",
        "paired_quality_gate": "both_completed_verified_f1_noninferiority",
        "quality_gate": "all_scheduled_verified_f1_noninferiority",
        "resource_direction": "lower_is_better",
        "resource_pair_population": "both_task_status_completed",
    }
)
RESOURCE_UNITS = MappingProxyType(
    {
        "api_cost_usd": "usd",
        "evidence_bearing_requests": "requests",
        "fixture_http_requests": "requests",
        "model_tokens": "tokens",
        "output_bytes": "bytes",
        "repeated_fixture_requests": "requests",
        "tool_calls": "calls",
        "unique_fixture_targets": "targets",
        "unsuccessful_fixture_requests": "requests",
        "verified_f1": "ratio",
        "wall_time_seconds": "seconds",
    }
)

_PUBLICATION_TIERS = frozenset({"diagnostic", "canary", "full"})
_MAX_SYSTEMS = 64
_MAX_SCENARIOS = 4_096
_MAX_BLOCKS = 250_000
MAX_BOOTSTRAP_SAMPLES = 100_000
MAX_REPETITIONS = 10_000
_MAX_TEXT = 16_384


class BenchmarkV4SchemaError(BenchmarkV3SchemaError):
    """Raised when additive v4 evidence violates its frozen contract."""


@dataclass(frozen=True)
class ScheduleBlock:
    """One adjacent matched-fixture block in chronological plan order."""

    scenario_id: str
    repetition: int
    matched_fixture_seed: int
    system_order: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "system_order", tuple(self.system_order))
        _identifier(self.scenario_id, "schedule.scenario_id")
        if (
            isinstance(self.repetition, bool)
            or not isinstance(self.repetition, int)
            or not 1 <= self.repetition <= MAX_REPETITIONS
        ):
            raise BenchmarkV4SchemaError("invalid:schedule.repetition")
        if (
            isinstance(self.matched_fixture_seed, bool)
            or not isinstance(self.matched_fixture_seed, int)
            or not 0 <= self.matched_fixture_seed < 2**63
        ):
            raise BenchmarkV4SchemaError("invalid:schedule.matched_fixture_seed")
        if (
            len(self.system_order) < 2
            or len(self.system_order) > _MAX_SYSTEMS
            or len(set(self.system_order)) != len(self.system_order)
        ):
            raise BenchmarkV4SchemaError("invalid:schedule.system_order")
        for system_id in self.system_order:
            _identifier(system_id, "schedule.system_id")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ScheduleBlock:
        _exact_keys(
            payload,
            {"matched_fixture_seed", "repetition", "scenario_id", "system_order"},
            "invalid_efficiency_schedule_block",
        )
        raw_order = payload.get("system_order")
        if not _sequence(raw_order):
            raise BenchmarkV4SchemaError("invalid_efficiency_schedule_block")
        try:
            return cls(
                scenario_id=str(payload.get("scenario_id") or ""),
                repetition=_integer(payload.get("repetition"), "schedule.repetition", minimum=1),
                matched_fixture_seed=_integer(
                    payload.get("matched_fixture_seed"),
                    "schedule.matched_fixture_seed",
                    minimum=0,
                    maximum=2**63 - 1,
                ),
                system_order=tuple(str(item) for item in cast(Sequence[Any], raw_order)),
            )
        except BenchmarkV4SchemaError:
            raise
        except (TypeError, ValueError) as exc:
            raise BenchmarkV4SchemaError("invalid_efficiency_schedule_block") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched_fixture_seed": self.matched_fixture_seed,
            "repetition": self.repetition,
            "scenario_id": self.scenario_id,
            "system_order": list(self.system_order),
        }


@dataclass(frozen=True)
class EfficiencyPlan:
    """A write-once efficiency design bound to one immutable v3 plan."""

    efficiency_track_id: str
    source_analysis_plan_digest: str
    source_track_id: str
    system_ids: tuple[str, ...]
    scenario_ids: tuple[str, ...]
    repetitions: int
    comparison_pairs: tuple[tuple[str, str], ...]
    schedule: tuple[ScheduleBlock, ...]
    schedule_seed: int
    primary_resources: tuple[str, ...] = PRIMARY_RESOURCES
    secondary_resources: tuple[str, ...] = SECONDARY_RESOURCES
    quality_metric: str = QUALITY_METRIC
    noninferiority_margin: float = 0.02
    completion_noninferiority_margin: float = 0.02
    coverage_gates: Mapping[str, float] = field(default_factory=lambda: dict.fromkeys(PRIMARY_RESOURCES, 1.0))
    methodology: Mapping[str, Any] = field(default_factory=lambda: dict(EFFICIENCY_METHODOLOGY))
    alpha: float = 0.05
    bootstrap_samples: int = 10_000
    bootstrap_seed: int = 1
    publication_tier: str = "full"
    require_run_attestation: bool = True
    schema_version: str = EFFICIENCY_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "system_ids", tuple(self.system_ids))
        object.__setattr__(self, "scenario_ids", tuple(self.scenario_ids))
        object.__setattr__(self, "primary_resources", tuple(self.primary_resources))
        object.__setattr__(self, "secondary_resources", tuple(self.secondary_resources))
        object.__setattr__(self, "schedule", tuple(self.schedule))
        try:
            pairs = tuple((str(item[0]), str(item[1])) for item in self.comparison_pairs if len(item) == 2)
        except (IndexError, TypeError):
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.comparison_pair") from None
        if len(pairs) != len(self.comparison_pairs):
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.comparison_pair")
        object.__setattr__(self, "comparison_pairs", pairs)
        if not isinstance(self.coverage_gates, Mapping):
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.coverage_gates")
        if any(isinstance(value, bool) for value in self.coverage_gates.values()):
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.coverage_gates")
        try:
            gates = {str(key): float(value) for key, value in sorted(self.coverage_gates.items())}
        except (AttributeError, TypeError, ValueError) as exc:
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.coverage_gates") from exc
        object.__setattr__(self, "coverage_gates", MappingProxyType(gates))
        methodology = _methodology(self.methodology)
        object.__setattr__(self, "methodology", MappingProxyType(methodology))

        if self.schema_version != EFFICIENCY_PLAN_SCHEMA_VERSION:
            raise BenchmarkV4SchemaError("unsupported_efficiency_plan_schema")
        _identifier(self.efficiency_track_id, "efficiency_plan.efficiency_track_id")
        _identifier(self.source_track_id, "efficiency_plan.source_track_id")
        if self.efficiency_track_id == self.source_track_id:
            raise BenchmarkV4SchemaError("efficiency_track_not_isolated")
        _digest(self.source_analysis_plan_digest, "efficiency_plan.source_analysis_plan_digest")
        if (
            len(self.system_ids) < 2
            or len(self.system_ids) > _MAX_SYSTEMS
            or len(set(self.system_ids)) != len(self.system_ids)
        ):
            raise BenchmarkV4SchemaError("efficiency_plan_requires_unique_systems")
        if (
            not self.scenario_ids
            or len(self.scenario_ids) > _MAX_SCENARIOS
            or len(set(self.scenario_ids)) != len(self.scenario_ids)
        ):
            raise BenchmarkV4SchemaError("efficiency_plan_requires_unique_scenarios")
        for value in (*self.system_ids, *self.scenario_ids):
            _identifier(value, "efficiency_plan.identifier")
        if (
            isinstance(self.repetitions, bool)
            or not isinstance(self.repetitions, int)
            or not 1 <= self.repetitions <= MAX_REPETITIONS
        ):
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.repetitions")
        if (
            isinstance(self.schedule_seed, bool)
            or not isinstance(self.schedule_seed, int)
            or not 0 <= self.schedule_seed < 2**256
        ):
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.schedule_seed")
        if self.primary_resources != PRIMARY_RESOURCES:
            raise BenchmarkV4SchemaError("fixed_primary_resources_required")
        if self.secondary_resources != SECONDARY_RESOURCES:
            raise BenchmarkV4SchemaError("fixed_secondary_resources_required")
        if self.quality_metric != QUALITY_METRIC:
            raise BenchmarkV4SchemaError("fixed_quality_metric_required")
        if methodology != _methodology(EFFICIENCY_METHODOLOGY):
            raise BenchmarkV4SchemaError("fixed_efficiency_methodology_required")
        if set(gates) != set(PRIMARY_RESOURCES) or any(
            not math.isfinite(value) or not 0.0 <= value <= 1.0 for value in gates.values()
        ):
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.coverage_gates")
        for margin_name, margin in (
            ("noninferiority_margin", self.noninferiority_margin),
            ("completion_noninferiority_margin", self.completion_noninferiority_margin),
        ):
            if (
                isinstance(margin, bool)
                or not isinstance(margin, (int, float))
                or not math.isfinite(margin)
                or not 0.0 <= margin <= 1.0
            ):
                raise BenchmarkV4SchemaError(f"invalid:efficiency_plan.{margin_name}")
        if isinstance(self.alpha, bool) or not isinstance(self.alpha, (int, float)) or not 0.0 < self.alpha < 1.0:
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.alpha")
        if (
            isinstance(self.bootstrap_samples, bool)
            or not isinstance(self.bootstrap_samples, int)
            or not 100 <= self.bootstrap_samples <= MAX_BOOTSTRAP_SAMPLES
        ):
            raise BenchmarkV4SchemaError("invalid_efficiency_plan_bootstrap_samples")
        if isinstance(self.bootstrap_seed, bool) or not isinstance(self.bootstrap_seed, int) or self.bootstrap_seed < 0:
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.bootstrap_seed")
        if self.publication_tier not in _PUBLICATION_TIERS:
            raise BenchmarkV4SchemaError("invalid_efficiency_publication_tier")
        if not self.require_run_attestation and self.publication_tier != "diagnostic":
            raise BenchmarkV4SchemaError("publishable_efficiency_plan_requires_attestation")
        if not isinstance(self.require_run_attestation, bool):
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.require_run_attestation")
        _validate_comparison_pairs(self.system_ids, self.comparison_pairs)
        _validate_schedule_contract(self)

    @property
    def digest(self) -> str:
        return stable_digest(self._digest_payload())

    @property
    def plan_id(self) -> str:
        return "efficiency-plan-" + self.digest[:20]

    def _digest_payload(self) -> dict[str, Any]:
        return {
            "alpha": self.alpha,
            "bootstrap_samples": self.bootstrap_samples,
            "bootstrap_seed": self.bootstrap_seed,
            "comparison_pairs": [list(item) for item in self.comparison_pairs],
            "completion_noninferiority_margin": self.completion_noninferiority_margin,
            "coverage_gates": dict(self.coverage_gates),
            "efficiency_track_id": self.efficiency_track_id,
            "methodology": {
                **dict(self.methodology),
                "claim_resources": list(cast(Sequence[str], self.methodology["claim_resources"])),
            },
            "noninferiority_margin": self.noninferiority_margin,
            "primary_resources": list(self.primary_resources),
            "publication_tier": self.publication_tier,
            "quality_metric": self.quality_metric,
            "repetitions": self.repetitions,
            "require_run_attestation": self.require_run_attestation,
            "scenario_ids": list(self.scenario_ids),
            "schedule": [item.to_dict() for item in self.schedule],
            "schedule_seed": self.schedule_seed,
            "schema_version": self.schema_version,
            "secondary_resources": list(self.secondary_resources),
            "source_analysis_plan_digest": self.source_analysis_plan_digest,
            "source_track_id": self.source_track_id,
            "system_ids": list(self.system_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._digest_payload(),
            "frozen": True,
            "plan_digest": self.digest,
            "plan_id": self.plan_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EfficiencyPlan:
        _exact_keys(
            payload,
            {
                "alpha",
                "bootstrap_samples",
                "bootstrap_seed",
                "comparison_pairs",
                "completion_noninferiority_margin",
                "coverage_gates",
                "efficiency_track_id",
                "frozen",
                "methodology",
                "noninferiority_margin",
                "plan_digest",
                "plan_id",
                "primary_resources",
                "publication_tier",
                "quality_metric",
                "repetitions",
                "require_run_attestation",
                "scenario_ids",
                "schedule",
                "schedule_seed",
                "schema_version",
                "secondary_resources",
                "source_analysis_plan_digest",
                "source_track_id",
                "system_ids",
            },
            "invalid_efficiency_plan",
        )
        if str(payload.get("schema_version") or "") != EFFICIENCY_PLAN_SCHEMA_VERSION:
            raise BenchmarkV4SchemaError("unsupported_efficiency_plan_schema")
        raw_schedule = payload.get("schedule")
        raw_pairs = payload.get("comparison_pairs")
        raw_gates = payload.get("coverage_gates")
        raw_methodology = payload.get("methodology")
        if (
            not _sequence(raw_schedule)
            or not _sequence(raw_pairs)
            or any(
                not _sequence(item) or len(cast(Sequence[Any], item)) != 2 for item in cast(Sequence[Any], raw_pairs)
            )
            or not isinstance(raw_gates, Mapping)
            or not isinstance(raw_methodology, Mapping)
        ):
            raise BenchmarkV4SchemaError("invalid_efficiency_plan")
        try:
            plan = cls(
                efficiency_track_id=str(payload.get("efficiency_track_id") or ""),
                source_analysis_plan_digest=str(payload.get("source_analysis_plan_digest") or ""),
                source_track_id=str(payload.get("source_track_id") or ""),
                system_ids=tuple(str(item) for item in payload.get("system_ids") or ()),
                scenario_ids=tuple(str(item) for item in payload.get("scenario_ids") or ()),
                repetitions=_integer(
                    payload.get("repetitions"),
                    "efficiency_plan.repetitions",
                    minimum=1,
                    maximum=MAX_REPETITIONS,
                ),
                comparison_pairs=tuple(
                    (str(item[0]), str(item[1]))
                    for item in cast(Sequence[Any], raw_pairs)
                    if _sequence(item) and len(item) == 2
                ),
                schedule=tuple(
                    ScheduleBlock.from_dict(_mapping(item, "efficiency_plan.schedule"))
                    for item in cast(Sequence[Any], raw_schedule)
                ),
                schedule_seed=_integer(
                    payload.get("schedule_seed"),
                    "efficiency_plan.schedule_seed",
                    minimum=0,
                    maximum=2**256 - 1,
                ),
                primary_resources=tuple(str(item) for item in payload.get("primary_resources") or ()),
                secondary_resources=tuple(str(item) for item in payload.get("secondary_resources") or ()),
                quality_metric=str(payload.get("quality_metric") or ""),
                noninferiority_margin=_number(
                    payload.get("noninferiority_margin"),
                    "efficiency_plan.noninferiority_margin",
                ),
                completion_noninferiority_margin=_number(
                    payload.get("completion_noninferiority_margin"),
                    "efficiency_plan.completion_noninferiority_margin",
                ),
                coverage_gates=dict(raw_gates),
                methodology=dict(raw_methodology),
                alpha=_number(payload.get("alpha"), "efficiency_plan.alpha"),
                bootstrap_samples=_integer(
                    payload.get("bootstrap_samples"),
                    "efficiency_plan.bootstrap_samples",
                    minimum=100,
                    maximum=MAX_BOOTSTRAP_SAMPLES,
                ),
                bootstrap_seed=_integer(
                    payload.get("bootstrap_seed"),
                    "efficiency_plan.bootstrap_seed",
                    minimum=0,
                ),
                publication_tier=str(payload.get("publication_tier") or ""),
                require_run_attestation=_boolean(
                    payload.get("require_run_attestation"),
                    "efficiency_plan.require_run_attestation",
                ),
            )
        except BenchmarkV4SchemaError:
            raise
        except (TypeError, ValueError) as exc:
            raise BenchmarkV4SchemaError("invalid_efficiency_plan") from exc
        if payload.get("frozen") is not True:
            raise BenchmarkV4SchemaError("efficiency_plan_not_frozen")
        if str(payload.get("plan_digest") or "") != plan.digest:
            raise BenchmarkV4SchemaError("efficiency_plan_digest_mismatch")
        if str(payload.get("plan_id") or "") != plan.plan_id:
            raise BenchmarkV4SchemaError("efficiency_plan_id_mismatch")
        return plan


@dataclass(frozen=True)
class ResourceObservation:
    """One resource/quality value without converting missing telemetry to zero."""

    name: str
    available: bool
    reliability: str
    source: str
    unit: str
    value: float | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        _identifier(self.name, "resource.name")
        _identifier(self.source, "resource.source")
        _identifier(self.unit, "resource.unit")
        if self.reliability not in METRIC_RELIABILITIES:
            raise BenchmarkV4SchemaError("invalid:resource.reliability")
        if not isinstance(self.available, bool):
            raise BenchmarkV4SchemaError("invalid:resource.available")
        if self.available:
            if (
                self.value is None
                or isinstance(self.value, bool)
                or not math.isfinite(float(self.value))
                or float(self.value) < 0
            ):
                raise BenchmarkV4SchemaError("invalid:resource.value")
            if self.reliability == "unavailable":
                raise BenchmarkV4SchemaError("available_resource_unavailable_reliability")
            object.__setattr__(self, "value", float(self.value))
        else:
            if self.value is not None:
                raise BenchmarkV4SchemaError("unavailable_resource_has_value")
            if self.reliability != "unavailable":
                raise BenchmarkV4SchemaError("unavailable_resource_reliability")
            if not self.reason:
                raise BenchmarkV4SchemaError("unavailable_resource_requires_reason")
        if self.reason:
            _text(self.reason, "resource.reason")

    @classmethod
    def unavailable(
        cls,
        name: str,
        *,
        source: str,
        unit: str,
        reason: str,
    ) -> ResourceObservation:
        return cls(
            name=name,
            available=False,
            reliability="unavailable",
            source=source,
            unit=unit,
            reason=reason,
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ResourceObservation:
        required = {"available", "name", "reliability", "source", "unit", "value"}
        keys = set(payload)
        if not required <= keys or keys - (required | {"reason"}):
            raise BenchmarkV4SchemaError("invalid_resource_observation")
        available = _boolean(payload.get("available"), "resource.available")
        raw_value = payload.get("value")
        if not available and raw_value is not None:
            raise BenchmarkV4SchemaError("unavailable_resource_has_value")
        return cls(
            name=str(payload.get("name") or ""),
            available=available,
            reliability=str(payload.get("reliability") or ""),
            source=str(payload.get("source") or ""),
            unit=str(payload.get("unit") or ""),
            value=_number(raw_value, "resource.value") if available else None,
            reason=str(payload.get("reason") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "available": self.available,
            "name": self.name,
            "reliability": self.reliability,
            "source": self.source,
            "unit": self.unit,
            "value": float(self.value) if self.available and self.value is not None else None,
        }
        if self.reason:
            payload["reason"] = self.reason
        return payload


@dataclass(frozen=True)
class EfficiencyRunProjection:
    """Serializable v4 view of a v3 run and its controller resource evidence."""

    run_id: str
    efficiency_track_id: str
    source_track_id: str
    system_id: str
    scenario_id: str
    repetition: int
    matched_fixture_seed: int
    execution_status: str
    task_status: str
    started_at: float
    finished_at: float
    batch_id: str
    host_id: str
    efficiency_plan_attested: bool
    quality: ResourceObservation
    resources: Mapping[str, ResourceObservation]
    schema_version: str = EFFICIENCY_RUN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name, value in (
            ("run_id", self.run_id),
            ("efficiency_track_id", self.efficiency_track_id),
            ("source_track_id", self.source_track_id),
            ("system_id", self.system_id),
            ("scenario_id", self.scenario_id),
        ):
            _identifier(value, f"efficiency_run.{name}")
        if self.schema_version != EFFICIENCY_RUN_SCHEMA_VERSION:
            raise BenchmarkV4SchemaError("unsupported_efficiency_run_schema")
        if not isinstance(self.efficiency_plan_attested, bool):
            raise BenchmarkV4SchemaError("invalid:efficiency_run.efficiency_plan_attested")
        if (
            isinstance(self.repetition, bool)
            or isinstance(self.matched_fixture_seed, bool)
            or not isinstance(self.repetition, int)
            or not isinstance(self.matched_fixture_seed, int)
            or not 1 <= self.repetition <= MAX_REPETITIONS
            or not 0 <= self.matched_fixture_seed < 2**63
        ):
            raise BenchmarkV4SchemaError("invalid:efficiency_run.schedule_key")
        if (
            isinstance(self.started_at, bool)
            or isinstance(self.finished_at, bool)
            or not isinstance(self.started_at, (int, float))
            or not isinstance(self.finished_at, (int, float))
            or not math.isfinite(self.started_at)
            or not math.isfinite(self.finished_at)
        ):
            raise BenchmarkV4SchemaError("invalid:efficiency_run.timestamp")
        if self.finished_at < self.started_at:
            raise BenchmarkV4SchemaError("efficiency_run_timestamp_order")
        if self.batch_id:
            _text(self.batch_id, "efficiency_run.batch_id")
        if self.host_id:
            _text(self.host_id, "efficiency_run.host_id")
        if self.execution_status not in EXECUTION_STATUSES:
            raise BenchmarkV4SchemaError("invalid:efficiency_run.execution_status")
        if self.task_status not in TASK_STATUSES:
            raise BenchmarkV4SchemaError("invalid:efficiency_run.task_status")
        if self.quality.name != QUALITY_METRIC:
            raise BenchmarkV4SchemaError("efficiency_run_quality_metric_mismatch")
        if self.quality.available and self.quality.value is not None and not 0.0 <= self.quality.value <= 1.0:
            raise BenchmarkV4SchemaError("efficiency_run_quality_out_of_range")
        try:
            normalized = {str(key): value for key, value in sorted(self.resources.items())}
        except AttributeError as exc:
            raise BenchmarkV4SchemaError("invalid:efficiency_run.resources") from exc
        if set(normalized) != set(ALL_RESOURCES):
            raise BenchmarkV4SchemaError("efficiency_run_resource_set_mismatch")
        if any(key != value.name for key, value in normalized.items()):
            raise BenchmarkV4SchemaError("efficiency_run_resource_name_mismatch")
        if any(value.unit != RESOURCE_UNITS[key] for key, value in normalized.items()):
            raise BenchmarkV4SchemaError("efficiency_run_resource_unit_mismatch")
        if self.quality.unit != RESOURCE_UNITS[QUALITY_METRIC]:
            raise BenchmarkV4SchemaError("efficiency_run_quality_unit_mismatch")
        object.__setattr__(self, "resources", MappingProxyType(normalized))

    @property
    def block_key(self) -> tuple[str, int, int]:
        return (self.scenario_id, self.repetition, self.matched_fixture_seed)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EfficiencyRunProjection:
        _exact_keys(
            payload,
            {
                "batch_id",
                "efficiency_plan_attested",
                "efficiency_track_id",
                "execution_status",
                "finished_at",
                "host_id",
                "matched_fixture_seed",
                "quality",
                "repetition",
                "resources",
                "run_id",
                "scenario_id",
                "schema_version",
                "source_track_id",
                "started_at",
                "system_id",
                "task_status",
            },
            "invalid_efficiency_run",
        )
        raw_quality = _mapping(payload.get("quality"), "efficiency_run.quality")
        raw_resources = _mapping(payload.get("resources"), "efficiency_run.resources")
        return cls(
            run_id=str(payload.get("run_id") or ""),
            efficiency_track_id=str(payload.get("efficiency_track_id") or ""),
            source_track_id=str(payload.get("source_track_id") or ""),
            system_id=str(payload.get("system_id") or ""),
            scenario_id=str(payload.get("scenario_id") or ""),
            repetition=_integer(payload.get("repetition"), "efficiency_run.repetition", minimum=1),
            matched_fixture_seed=_integer(
                payload.get("matched_fixture_seed"),
                "efficiency_run.matched_fixture_seed",
                minimum=0,
                maximum=2**63 - 1,
            ),
            execution_status=str(payload.get("execution_status") or ""),
            task_status=str(payload.get("task_status") or ""),
            started_at=_number(payload.get("started_at"), "efficiency_run.started_at"),
            finished_at=_number(payload.get("finished_at"), "efficiency_run.finished_at"),
            batch_id=str(payload.get("batch_id") or ""),
            host_id=str(payload.get("host_id") or ""),
            efficiency_plan_attested=_boolean(
                payload.get("efficiency_plan_attested"),
                "efficiency_run.efficiency_plan_attested",
            ),
            quality=ResourceObservation.from_dict(raw_quality),
            resources={
                str(name): ResourceObservation.from_dict(_mapping(value, "efficiency_run.resource"))
                for name, value in raw_resources.items()
            },
            schema_version=str(payload.get("schema_version") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id or None,
            "efficiency_plan_attested": self.efficiency_plan_attested,
            "efficiency_track_id": self.efficiency_track_id,
            "execution_status": self.execution_status,
            "finished_at": self.finished_at,
            "host_id": self.host_id or None,
            "matched_fixture_seed": self.matched_fixture_seed,
            "quality": self.quality.to_dict(),
            "repetition": self.repetition,
            "resources": {name: value.to_dict() for name, value in self.resources.items()},
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "schema_version": self.schema_version,
            "source_track_id": self.source_track_id,
            "started_at": self.started_at,
            "system_id": self.system_id,
            "task_status": self.task_status,
        }


def build_efficiency_plan(
    source_analysis_plan: AnalysisPlan,
    *,
    efficiency_track_id: str | None = None,
    schedule_seed: int = 1,
    noninferiority_margin: float = 0.02,
    completion_noninferiority_margin: float = 0.02,
    coverage_gates: Mapping[str, float] | None = None,
    alpha: float | None = None,
    bootstrap_samples: int | None = None,
    bootstrap_seed: int | None = None,
    publication_tier: str | None = None,
    require_run_attestation: bool = True,
) -> EfficiencyPlan:
    """Build a deterministic, position-balanced companion to a v3 plan."""

    if not isinstance(source_analysis_plan, AnalysisPlan):
        raise BenchmarkV4SchemaError("efficiency_plan_requires_analysis_plan")
    if not 1 <= source_analysis_plan.repetitions <= MAX_REPETITIONS:
        raise BenchmarkV4SchemaError("invalid:efficiency_plan.repetitions")
    selected_tier = str(publication_tier or source_analysis_plan.publication_tier)
    systems = tuple(source_analysis_plan.system_ids)
    scenarios = tuple(source_analysis_plan.scenario_ids)
    seeds = {scenario_id: tuple(source_analysis_plan.fixture_seeds[scenario_id]) for scenario_id in scenarios}
    schedule = _build_schedule(
        system_ids=systems,
        scenario_ids=scenarios,
        repetitions=source_analysis_plan.repetitions,
        fixture_seeds=seeds,
        schedule_seed=schedule_seed,
    )
    gates = dict.fromkeys(PRIMARY_RESOURCES, 1.0) if coverage_gates is None else dict(coverage_gates)
    return EfficiencyPlan(
        efficiency_track_id=(efficiency_track_id or f"{source_analysis_plan.track_id}-efficiency-v4"),
        source_analysis_plan_digest=source_analysis_plan.digest,
        source_track_id=source_analysis_plan.track_id,
        system_ids=systems,
        scenario_ids=scenarios,
        repetitions=source_analysis_plan.repetitions,
        comparison_pairs=tuple(source_analysis_plan.comparison_pairs),
        schedule=schedule,
        schedule_seed=int(schedule_seed),
        noninferiority_margin=float(noninferiority_margin),
        completion_noninferiority_margin=float(completion_noninferiority_margin),
        coverage_gates=gates,
        methodology=dict(EFFICIENCY_METHODOLOGY),
        alpha=float(source_analysis_plan.alpha if alpha is None else alpha),
        bootstrap_samples=int(
            source_analysis_plan.bootstrap_samples if bootstrap_samples is None else bootstrap_samples
        ),
        bootstrap_seed=int(source_analysis_plan.bootstrap_seed if bootstrap_seed is None else bootstrap_seed),
        publication_tier=selected_tier,
        require_run_attestation=bool(require_run_attestation),
    )


def freeze_efficiency_plan(plan: EfficiencyPlan, path: str | Path) -> Path:
    """Atomically write a plan once; byte-different replacement is rejected."""

    if not isinstance(plan, EfficiencyPlan):
        raise BenchmarkV4SchemaError("invalid_efficiency_plan")
    destination = Path(path).resolve()
    payload = json.dumps(plan.to_dict(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_text(encoding="utf-8") != payload:
            raise FileExistsError("frozen_efficiency_plan_differs")
        return destination
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise
    return destination


def load_efficiency_plan(path: str | Path) -> EfficiencyPlan:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BenchmarkV4SchemaError("efficiency_plan_load_failed") from exc
    if not isinstance(payload, Mapping):
        raise BenchmarkV4SchemaError("invalid_efficiency_plan")
    return EfficiencyPlan.from_dict(payload)


def _build_schedule(
    *,
    system_ids: Sequence[str],
    scenario_ids: Sequence[str],
    repetitions: int,
    fixture_seeds: Mapping[str, Sequence[int]],
    schedule_seed: int,
) -> tuple[ScheduleBlock, ...]:
    """Use hash streams for deterministic pseudo-random block/order assignment."""

    systems = tuple(system_ids)
    blocks: list[ScheduleBlock] = []
    for scenario_id in scenario_ids:
        base = tuple(
            sorted(
                systems,
                key=lambda system_id: (
                    stable_digest(
                        {
                            "kind": "efficiency-system-order",
                            "scenario_id": scenario_id,
                            "schedule_seed": int(schedule_seed),
                            "system_id": system_id,
                        }
                    ),
                    system_id,
                ),
            )
        )
        for repetition, matched_seed in enumerate(fixture_seeds[scenario_id], start=1):
            offset = (repetition - 1) % len(base)
            order = base[offset:] + base[:offset]
            blocks.append(
                ScheduleBlock(
                    scenario_id=scenario_id,
                    repetition=repetition,
                    matched_fixture_seed=int(matched_seed),
                    system_order=order,
                )
            )
    return tuple(
        sorted(
            blocks,
            key=lambda block: (
                stable_digest(
                    {
                        "kind": "efficiency-block-order",
                        "matched_fixture_seed": block.matched_fixture_seed,
                        "repetition": block.repetition,
                        "scenario_id": block.scenario_id,
                        "schedule_seed": int(schedule_seed),
                    }
                ),
                block.scenario_id,
                block.repetition,
            ),
        )
    )


def _validate_schedule_contract(plan: EfficiencyPlan) -> None:
    expected_block_count = len(plan.scenario_ids) * plan.repetitions
    if not plan.schedule or expected_block_count > _MAX_BLOCKS or len(plan.schedule) != expected_block_count:
        raise BenchmarkV4SchemaError("invalid:efficiency_plan.schedule")
    expected_keys = {
        (scenario_id, repetition) for scenario_id in plan.scenario_ids for repetition in range(1, plan.repetitions + 1)
    }
    actual_keys = {(item.scenario_id, item.repetition) for item in plan.schedule}
    if len(actual_keys) != len(plan.schedule):
        raise BenchmarkV4SchemaError("duplicate_efficiency_schedule_block")
    if actual_keys != expected_keys:
        raise BenchmarkV4SchemaError("efficiency_schedule_block_coverage_mismatch")
    if any(set(item.system_order) != set(plan.system_ids) for item in plan.schedule):
        raise BenchmarkV4SchemaError("efficiency_schedule_system_coverage_mismatch")
    seeds: dict[str, list[int]] = {scenario_id: [0] * plan.repetitions for scenario_id in plan.scenario_ids}
    for item in plan.schedule:
        seeds[item.scenario_id][item.repetition - 1] = item.matched_fixture_seed
    expected = _build_schedule(
        system_ids=plan.system_ids,
        scenario_ids=plan.scenario_ids,
        repetitions=plan.repetitions,
        fixture_seeds=seeds,
        schedule_seed=plan.schedule_seed,
    )
    if plan.schedule != expected:
        raise BenchmarkV4SchemaError("efficiency_schedule_not_deterministic")
    for scenario_id in plan.scenario_ids:
        first_counts = {
            system_id: sum(
                item.scenario_id == scenario_id and item.system_order[0] == system_id for item in plan.schedule
            )
            for system_id in plan.system_ids
        }
        if max(first_counts.values()) - min(first_counts.values()) > 1:
            raise BenchmarkV4SchemaError("efficiency_schedule_position_imbalance")


def _validate_comparison_pairs(
    system_ids: Sequence[str],
    comparison_pairs: Sequence[tuple[str, str]],
) -> None:
    allowed = set(system_ids)
    seen: set[tuple[str, str]] = set()
    if not comparison_pairs:
        raise BenchmarkV4SchemaError("efficiency_plan_requires_comparison_pair")
    for left, right in comparison_pairs:
        if left == right or left not in allowed or right not in allowed:
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.comparison_pair")
        canonical = (min(left, right), max(left, right))
        if canonical in seen:
            raise BenchmarkV4SchemaError("duplicate_efficiency_comparison_pair")
        seen.add(canonical)


def _methodology(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(EFFICIENCY_METHODOLOGY):
        raise BenchmarkV4SchemaError("invalid:efficiency_plan.methodology")
    claims = value.get("claim_resources")
    if not _sequence(claims):
        raise BenchmarkV4SchemaError("invalid:efficiency_plan.methodology")
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if key == "claim_resources":
            normalized[key] = tuple(str(name) for name in cast(Sequence[Any], claims))
        elif isinstance(item, (str, bool)):
            normalized[key] = item
        else:
            raise BenchmarkV4SchemaError("invalid:efficiency_plan.methodology")
    return normalized


def _identifier(value: Any, name: str) -> str:
    original = str(value)
    raw = original.strip()
    lowered = raw.lower()
    if (
        original != raw
        or raw != lowered
        or not lowered
        or len(lowered) > 160
        or lowered[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_.:-" for character in lowered)
    ):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return lowered


def _digest(value: Any, name: str) -> str:
    candidate = str(value)
    if len(candidate) != 64 or any(character not in "0123456789abcdef" for character in candidate):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return candidate


def _text(value: Any, name: str) -> str:
    candidate = str(value)
    if not candidate or "\x00" in candidate or len(candidate.encode("utf-8", "replace")) > _MAX_TEXT:
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return candidate


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise BenchmarkV4SchemaError(f"invalid:{name}") from None
    if not math.isfinite(result):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return result


def _integer(
    value: Any,
    name: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    if value < minimum or (maximum is not None and value > maximum):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return value


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return value


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return value


def _exact_keys(payload: Mapping[str, Any], expected: set[str], error: str) -> None:
    if set(payload) != expected:
        raise BenchmarkV4SchemaError(error)


def _sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


__all__ = [
    "ALL_RESOURCES",
    "EFFICIENCY_METHODOLOGY",
    "EFFICIENCY_PLAN_SCHEMA_VERSION",
    "EFFICIENCY_RUN_SCHEMA_VERSION",
    "EFFICIENCY_STATISTICS_SCHEMA_VERSION",
    "MAX_BOOTSTRAP_SAMPLES",
    "MAX_REPETITIONS",
    "PRIMARY_RESOURCES",
    "QUALITY_METRIC",
    "RESOURCE_UNITS",
    "SECONDARY_RESOURCES",
    "BenchmarkV4SchemaError",
    "EfficiencyPlan",
    "EfficiencyRunProjection",
    "ResourceObservation",
    "ScheduleBlock",
    "build_efficiency_plan",
    "freeze_efficiency_plan",
    "load_efficiency_plan",
]
