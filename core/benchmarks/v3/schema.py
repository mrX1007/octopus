"""Benchmark schema 2.0 run and evaluation contracts.

The v3 contract is additive: schema 1.0 objects remain owned by
``core.benchmarks.schema``.  This module can read those objects, but it never
rewrites them or upgrades a published bundle in place.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

BENCHMARK_V3_SCHEMA_VERSION = "2.0"

EXECUTION_STATUSES = frozenset({"succeeded", "failed", "timeout", "invalid", "cancelled"})
TASK_STATUSES = frozenset({"completed", "partial", "not_completed", "not_evaluated", "invalid"})
POPULATIONS = frozenset({"all_scheduled", "completion_conditional"})
METRIC_RELIABILITIES = frozenset(
    {
        "verified",
        "measured",
        "derived",
        "self_reported",
        "legacy_incomplete",
        "unavailable",
    }
)
MODEL_SEED_STATUSES = frozenset({"applied", "rejected", "not_supported", "unknown"})
BUDGET_ENFORCEMENT_MODES = frozenset({"hard", "advisory", "observed", "none"})
ACTION_STATUSES = frozenset({"succeeded", "failed", "timeout", "blocked", "unknown"})

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 16_384
_MAX_ITEMS = 10_000
_RATE_METRICS = frozenset(
    {
        "reported_recall",
        "verified_recall",
        "full_claim_precision",
        "verified_claim_precision",
        "task_completion_rate",
    }
)


class BenchmarkV3SchemaError(ValueError):
    """Raised when a v3 payload is internally inconsistent."""


def canonical_json(payload: Any) -> str:
    """Return the byte-stable JSON representation used by all v3 digests."""

    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def stable_digest(payload: Any) -> str:
    """Hash a JSON value using the canonical v3 serialization."""

    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MetricObservation:
    """One metric value with an explicit population and reliability."""

    name: str
    population: str
    available: bool
    reliability: str
    value: float | None = None
    numerator: int | None = None
    denominator: int | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        _identifier(self.name, "metric.name")
        if self.population not in POPULATIONS:
            raise BenchmarkV3SchemaError("invalid:metric.population")
        if self.reliability not in METRIC_RELIABILITIES:
            raise BenchmarkV3SchemaError("invalid:metric.reliability")
        if self.available:
            if self.value is None or not _finite(self.value):
                raise BenchmarkV3SchemaError("invalid:metric.value")
            value = float(self.value)
            if self.name in _RATE_METRICS and not 0.0 <= value <= 1.0:
                raise BenchmarkV3SchemaError("invalid:metric.rate")
            if self.reliability == "unavailable":
                raise BenchmarkV3SchemaError("invalid:metric.reliability")
        else:
            if self.value is not None:
                raise BenchmarkV3SchemaError("unavailable_metric_has_value")
            if self.reliability != "unavailable":
                raise BenchmarkV3SchemaError("unavailable_metric_reliability")
            if not self.reason:
                raise BenchmarkV3SchemaError("unavailable_metric_requires_reason")
        if (self.numerator is None) != (self.denominator is None):
            raise BenchmarkV3SchemaError("metric_fraction_incomplete")
        if self.numerator is not None:
            if self.numerator < 0 or self.denominator is None or self.denominator < 0:
                raise BenchmarkV3SchemaError("invalid:metric.fraction")
            if self.numerator > self.denominator:
                raise BenchmarkV3SchemaError("invalid:metric.fraction")

    @classmethod
    def unavailable(
        cls,
        name: str,
        population: str,
        reason: str,
    ) -> MetricObservation:
        return cls(
            name=name,
            population=population,
            available=False,
            reliability="unavailable",
            reason=_text(reason, "metric.reason"),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> MetricObservation:
        available = bool(payload.get("available"))
        value = payload.get("value") if available else None
        return cls(
            name=_identifier(payload.get("name"), "metric.name"),
            population=str(payload.get("population") or ""),
            available=available,
            reliability=str(payload.get("reliability") or ""),
            value=float(value) if value is not None else None,
            numerator=_optional_integer(payload.get("numerator")),
            denominator=_optional_integer(payload.get("denominator")),
            reason=_optional_text(payload.get("reason"), "metric.reason"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "available": self.available,
            "name": self.name,
            "population": self.population,
            "reliability": self.reliability,
        }
        if self.available:
            if self.value is None:
                raise BenchmarkV3SchemaError("available_metric_missing_value")
            payload["value"] = float(self.value)
        if self.numerator is not None:
            payload["numerator"] = self.numerator
            payload["denominator"] = self.denominator
        if self.reason:
            payload["reason"] = self.reason
        return payload


@dataclass(frozen=True)
class ClaimAssessment:
    """A reported claim, including claims that match no private truth item."""

    claim_id: str
    text: str
    normalized_claim_id: str
    matched_truth_id: str = ""
    supported: bool = False
    verified: bool = False
    matcher_kind: str = "unmatched"
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        _identifier(self.claim_id, "claim.claim_id")
        _text(self.text, "claim.text")
        _identifier(self.normalized_claim_id, "claim.normalized_claim_id")
        if self.matched_truth_id:
            _identifier(self.matched_truth_id, "claim.matched_truth_id")
        if self.supported != bool(self.matched_truth_id):
            raise BenchmarkV3SchemaError("claim_support_mismatch")
        if self.verified and not self.supported:
            raise BenchmarkV3SchemaError("unmatched_claim_cannot_be_verified")
        _identifier(self.matcher_kind, "claim.matcher_kind")
        _bounded_identifiers(self.evidence_refs, "claim.evidence_refs")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ClaimAssessment:
        return cls(
            claim_id=_identifier(payload.get("claim_id"), "claim.claim_id"),
            text=_text(payload.get("text"), "claim.text"),
            normalized_claim_id=_identifier(
                payload.get("normalized_claim_id"),
                "claim.normalized_claim_id",
            ),
            matched_truth_id=_optional_identifier(
                payload.get("matched_truth_id"),
                "claim.matched_truth_id",
            ),
            supported=bool(payload.get("supported")),
            verified=bool(payload.get("verified")),
            matcher_kind=_identifier(
                payload.get("matcher_kind") or "unmatched",
                "claim.matcher_kind",
            ),
            evidence_refs=_identifier_tuple(
                payload.get("evidence_refs") or [],
                "claim.evidence_refs",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "evidence_refs": list(self.evidence_refs),
            "matched_truth_id": self.matched_truth_id or None,
            "matcher_kind": self.matcher_kind,
            "normalized_claim_id": self.normalized_claim_id,
            "supported": self.supported,
            "text": self.text,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class BudgetEnforcement:
    """System-specific evidence for one declared scenario budget."""

    system_id: str
    budget_name: str
    limit: float
    unit: str
    enforcement_mode: str
    measured: float | None
    exceeded: bool | None
    reliable: bool
    evidence_refs: tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        _identifier(self.system_id, "budget.system_id")
        _identifier(self.budget_name, "budget.budget_name")
        _identifier(self.unit, "budget.unit")
        if not _finite(self.limit) or float(self.limit) <= 0:
            raise BenchmarkV3SchemaError("invalid:budget.limit")
        if self.enforcement_mode not in BUDGET_ENFORCEMENT_MODES:
            raise BenchmarkV3SchemaError("invalid:budget.enforcement_mode")
        if self.measured is not None:
            if not _finite(self.measured) or float(self.measured) < 0:
                raise BenchmarkV3SchemaError("invalid:budget.measured")
            if self.exceeded is None:
                raise BenchmarkV3SchemaError("measured_budget_requires_exceeded")
            expected = float(self.measured) > float(self.limit)
            if bool(self.exceeded) != expected:
                raise BenchmarkV3SchemaError("budget_exceeded_mismatch")
        elif self.exceeded is not None:
            raise BenchmarkV3SchemaError("unmeasured_budget_has_exceeded")
        if self.reliable and self.enforcement_mode == "none":
            raise BenchmarkV3SchemaError("unenforced_budget_cannot_be_reliable")
        _bounded_references(self.evidence_refs, "budget.evidence_refs")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> BudgetEnforcement:
        measured = payload.get("measured")
        exceeded = payload.get("exceeded")
        return cls(
            system_id=_identifier(payload.get("system_id"), "budget.system_id"),
            budget_name=_identifier(
                payload.get("budget_name"),
                "budget.budget_name",
            ),
            limit=_number(payload.get("limit"), "budget.limit"),
            unit=_identifier(payload.get("unit"), "budget.unit"),
            enforcement_mode=str(payload.get("enforcement_mode") or ""),
            measured=(_number(measured, "budget.measured") if measured is not None else None),
            exceeded=bool(exceeded) if exceeded is not None else None,
            reliable=bool(payload.get("reliable")),
            evidence_refs=_reference_tuple(
                payload.get("evidence_refs") or [],
                "budget.evidence_refs",
            ),
            note=_optional_text(payload.get("note"), "budget.note"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_name": self.budget_name,
            "enforcement_mode": self.enforcement_mode,
            "evidence_refs": list(self.evidence_refs),
            "exceeded": self.exceeded,
            "limit": float(self.limit),
            "measured": float(self.measured) if self.measured is not None else None,
            "note": self.note,
            "reliable": self.reliable,
            "system_id": self.system_id,
            "unit": self.unit,
        }


@dataclass(frozen=True)
class ActionEvent:
    """Normalized per-action telemetry; absence is represented separately."""

    event_id: str
    sequence: int
    action_name: str
    action_type: str
    status: str
    started_offset_seconds: float | None = None
    duration_seconds: float | None = None
    method: str = ""
    target_class: str = ""
    output_bytes: int | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        _identifier(self.event_id, "action.event_id")
        if self.sequence < 0:
            raise BenchmarkV3SchemaError("invalid:action.sequence")
        _identifier(self.action_name, "action.action_name")
        _identifier(self.action_type, "action.action_type")
        if self.status not in ACTION_STATUSES:
            raise BenchmarkV3SchemaError("invalid:action.status")
        for value, name in (
            (self.started_offset_seconds, "action.started_offset_seconds"),
            (self.duration_seconds, "action.duration_seconds"),
        ):
            if value is not None and (not _finite(value) or value < 0):
                raise BenchmarkV3SchemaError(f"invalid:{name}")
        if self.method and not re.fullmatch(r"[A-Z]{3,16}", self.method):
            raise BenchmarkV3SchemaError("invalid:action.method")
        if self.target_class:
            _identifier(self.target_class, "action.target_class")
        if self.output_bytes is not None and self.output_bytes < 0:
            raise BenchmarkV3SchemaError("invalid:action.output_bytes")
        _bounded_identifiers(self.evidence_refs, "action.evidence_refs")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ActionEvent:
        started = payload.get("started_offset_seconds")
        duration = payload.get("duration_seconds")
        output_bytes = payload.get("output_bytes")
        return cls(
            event_id=_identifier(payload.get("event_id"), "action.event_id"),
            sequence=_integer(payload.get("sequence"), "action.sequence", minimum=0),
            action_name=_identifier(
                payload.get("action_name"),
                "action.action_name",
            ),
            action_type=_identifier(
                payload.get("action_type"),
                "action.action_type",
            ),
            status=str(payload.get("status") or ""),
            started_offset_seconds=(_number(started, "action.started_offset_seconds") if started is not None else None),
            duration_seconds=(_number(duration, "action.duration_seconds") if duration is not None else None),
            method=str(payload.get("method") or "").upper(),
            target_class=_optional_identifier(
                payload.get("target_class"),
                "action.target_class",
            ),
            output_bytes=(
                _integer(output_bytes, "action.output_bytes", minimum=0) if output_bytes is not None else None
            ),
            evidence_refs=_identifier_tuple(
                payload.get("evidence_refs") or [],
                "action.evidence_refs",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_name": self.action_name,
            "action_type": self.action_type,
            "duration_seconds": self.duration_seconds,
            "event_id": self.event_id,
            "evidence_refs": list(self.evidence_refs),
            "method": self.method or None,
            "output_bytes": self.output_bytes,
            "sequence": self.sequence,
            "started_offset_seconds": self.started_offset_seconds,
            "status": self.status,
            "target_class": self.target_class or None,
        }


@dataclass(frozen=True)
class RunEvaluation:
    """Task outcome and metrics, deliberately separate from process execution."""

    task_status: str
    completion_rule_id: str
    metrics: tuple[MetricObservation, ...]
    claims: tuple[ClaimAssessment, ...] = ()
    evaluator_id: str = "octobench-v3"

    def __post_init__(self) -> None:
        object.__setattr__(self, "claims", tuple(self.claims))
        if self.task_status not in TASK_STATUSES:
            raise BenchmarkV3SchemaError("invalid:task_status")
        _identifier(self.completion_rule_id, "completion_rule_id")
        _identifier(self.evaluator_id, "evaluator_id")
        keys = [(item.population, item.name) for item in self.metrics]
        if len(keys) != len(set(keys)):
            raise BenchmarkV3SchemaError("duplicate_population_metric")
        object.__setattr__(
            self,
            "metrics",
            tuple(sorted(self.metrics, key=lambda item: (item.population, item.name))),
        )
        claim_ids = [item.claim_id for item in self.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise BenchmarkV3SchemaError("duplicate_claim_id")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RunEvaluation:
        raw_populations = payload.get("populations")
        if not isinstance(raw_populations, Mapping):
            raise BenchmarkV3SchemaError("invalid:evaluation.populations")
        metrics: list[MetricObservation] = []
        for population, raw_metrics in raw_populations.items():
            if not isinstance(raw_metrics, Mapping):
                raise BenchmarkV3SchemaError("invalid:evaluation.metrics")
            for name, raw_metric in raw_metrics.items():
                if not isinstance(raw_metric, Mapping):
                    raise BenchmarkV3SchemaError("invalid:evaluation.metric")
                item = dict(raw_metric)
                item.setdefault("name", name)
                item.setdefault("population", population)
                metrics.append(MetricObservation.from_dict(item))
        raw_claims = payload.get("claims") or []
        if not _is_sequence(raw_claims):
            raise BenchmarkV3SchemaError("invalid:evaluation.claims")
        return cls(
            task_status=str(payload.get("task_status") or ""),
            completion_rule_id=_identifier(
                payload.get("completion_rule_id"),
                "completion_rule_id",
            ),
            metrics=tuple(metrics),
            claims=tuple(ClaimAssessment.from_dict(_mapping(item, "evaluation.claim")) for item in raw_claims),
            evaluator_id=_identifier(
                payload.get("evaluator_id") or "octobench-v3",
                "evaluator_id",
            ),
        )

    def metric(self, name: str, population: str) -> MetricObservation:
        for item in self.metrics:
            if item.name == name and item.population == population:
                return item
        return MetricObservation.unavailable(name, population, "not_recorded")

    def to_dict(self) -> dict[str, Any]:
        populations: dict[str, dict[str, Any]] = {population: {} for population in sorted(POPULATIONS)}
        for metric in sorted(self.metrics, key=lambda item: (item.population, item.name)):
            payload = metric.to_dict()
            payload.pop("name")
            payload.pop("population")
            populations[metric.population][metric.name] = payload
        return {
            "claims": [item.to_dict() for item in self.claims],
            "completion_rule_id": self.completion_rule_id,
            "evaluator_id": self.evaluator_id,
            "populations": populations,
            "task_status": self.task_status,
        }


@dataclass(frozen=True)
class BenchmarkRunV3:
    """One scheduled run under the benchmark schema 2.0 contract."""

    run_id: str
    track_id: str
    system_id: str
    scenario_id: str
    repetition: int
    execution_status: str
    evaluation: RunEvaluation
    matched_fixture_seed: int
    fixture_variant_digest: str
    applied_model_seed: int | None
    model_seed_status: str
    budget_enforcement: tuple[BudgetEnforcement, ...]
    action_telemetry: tuple[ActionEvent, ...]
    action_telemetry_available: bool
    action_telemetry_reliability: str
    duration_seconds: float
    duration_censored: bool
    censor_limit_seconds: float | None
    started_at: float
    finished_at: float
    policy_violations: tuple[str, ...] = ()
    artifact_refs: tuple[str, ...] = ()
    model_seed_evidence: tuple[str, ...] = ()
    environment: Mapping[str, Any] = field(default_factory=dict)
    error_class: str = ""
    source_schema_version: str = BENCHMARK_V3_SCHEMA_VERSION
    schema_version: str = BENCHMARK_V3_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "budget_enforcement", tuple(self.budget_enforcement))
        object.__setattr__(self, "action_telemetry", tuple(self.action_telemetry))
        object.__setattr__(self, "policy_violations", tuple(self.policy_violations))
        object.__setattr__(self, "artifact_refs", tuple(self.artifact_refs))
        object.__setattr__(self, "model_seed_evidence", tuple(self.model_seed_evidence))
        normalized_environment = _json_mapping(self.environment, "environment")
        object.__setattr__(self, "environment", _freeze_json(normalized_environment))
        if self.schema_version != BENCHMARK_V3_SCHEMA_VERSION:
            raise BenchmarkV3SchemaError("unsupported_schema_version")
        _identifier(self.run_id, "run_id")
        _identifier(self.track_id, "track_id")
        _identifier(self.system_id, "system_id")
        _identifier(self.scenario_id, "scenario_id")
        if self.repetition < 1:
            raise BenchmarkV3SchemaError("invalid:repetition")
        if self.execution_status not in EXECUTION_STATUSES:
            raise BenchmarkV3SchemaError("invalid:execution_status")
        if self.matched_fixture_seed < 0:
            raise BenchmarkV3SchemaError("invalid:matched_fixture_seed")
        if self.fixture_variant_digest and not _DIGEST.fullmatch(self.fixture_variant_digest):
            raise BenchmarkV3SchemaError("invalid:fixture_variant_digest")
        if self.source_schema_version == BENCHMARK_V3_SCHEMA_VERSION:
            if not self.fixture_variant_digest:
                raise BenchmarkV3SchemaError("native_run_missing_fixture_digest")
            if not self.budget_enforcement:
                raise BenchmarkV3SchemaError("native_run_missing_budget_enforcement")
        if self.applied_model_seed is not None and self.applied_model_seed < 0:
            raise BenchmarkV3SchemaError("invalid:applied_model_seed")
        if self.model_seed_status not in MODEL_SEED_STATUSES:
            raise BenchmarkV3SchemaError("invalid:model_seed_status")
        if self.model_seed_status == "applied" and self.applied_model_seed is None:
            raise BenchmarkV3SchemaError("applied_model_seed_missing")
        budget_names = [item.budget_name for item in self.budget_enforcement]
        if len(budget_names) != len(set(budget_names)):
            raise BenchmarkV3SchemaError("duplicate_budget_enforcement")
        if any(item.system_id != self.system_id for item in self.budget_enforcement):
            raise BenchmarkV3SchemaError("budget_system_mismatch")
        action_sequences = [item.sequence for item in self.action_telemetry]
        if action_sequences != sorted(action_sequences):
            raise BenchmarkV3SchemaError("action_telemetry_not_ordered")
        if len(action_sequences) != len(set(action_sequences)):
            raise BenchmarkV3SchemaError("duplicate_action_sequence")
        action_ids = [item.event_id for item in self.action_telemetry]
        if len(action_ids) != len(set(action_ids)):
            raise BenchmarkV3SchemaError("duplicate_action_event_id")
        if self.action_telemetry_available:
            if self.action_telemetry_reliability not in {
                "verified",
                "measured",
                "derived",
                "self_reported",
                "legacy_incomplete",
            }:
                raise BenchmarkV3SchemaError("invalid:action_telemetry_reliability")
        elif self.action_telemetry_reliability != "unavailable":
            raise BenchmarkV3SchemaError("unavailable_action_telemetry_reliability")
        if not _finite(self.duration_seconds) or self.duration_seconds < 0:
            raise BenchmarkV3SchemaError("invalid:duration_seconds")
        if self.duration_censored:
            if self.censor_limit_seconds is None:
                raise BenchmarkV3SchemaError("censored_duration_requires_limit")
            if self.censor_limit_seconds < 0:
                raise BenchmarkV3SchemaError("invalid:censor_limit_seconds")
            if self.duration_seconds > self.censor_limit_seconds + 1e-9:
                raise BenchmarkV3SchemaError("duration_exceeds_censor_limit")
        elif self.censor_limit_seconds is not None:
            if self.censor_limit_seconds < self.duration_seconds:
                raise BenchmarkV3SchemaError("invalid:censor_limit_seconds")
        if not _finite(self.started_at) or not _finite(self.finished_at):
            raise BenchmarkV3SchemaError("invalid:run_timestamp")
        if self.finished_at < self.started_at:
            raise BenchmarkV3SchemaError("run_timestamp_order")
        _bounded_identifiers(self.policy_violations, "policy_violations")
        _bounded_references(self.artifact_refs, "artifact_refs")
        _bounded_references(self.model_seed_evidence, "model_seed_evidence")
        if self.error_class:
            _identifier(self.error_class.lower(), "error_class")

    @property
    def task_status(self) -> str:
        return self.evaluation.task_status

    @property
    def completion_rule_id(self) -> str:
        return self.evaluation.completion_rule_id

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> BenchmarkRunV3:
        schema_version = str(payload.get("schema_version") or "")
        if schema_version != BENCHMARK_V3_SCHEMA_VERSION:
            raise BenchmarkV3SchemaError(f"unsupported_schema_version:{schema_version or 'missing'}")
        raw_evaluation = _mapping(payload.get("evaluation"), "evaluation")
        raw_budgets = payload.get("budget_enforcement") or []
        raw_actions = payload.get("action_telemetry") or []
        if not _is_sequence(raw_budgets) or not _is_sequence(raw_actions):
            raise BenchmarkV3SchemaError("invalid:run_telemetry")
        applied_seed = payload.get("applied_model_seed")
        censor_limit = payload.get("censor_limit_seconds")
        return cls(
            run_id=_identifier(payload.get("run_id"), "run_id"),
            track_id=_identifier(payload.get("track_id"), "track_id"),
            system_id=_identifier(payload.get("system_id"), "system_id"),
            scenario_id=_identifier(payload.get("scenario_id"), "scenario_id"),
            repetition=_integer(payload.get("repetition"), "repetition", minimum=1),
            execution_status=str(payload.get("execution_status") or ""),
            evaluation=RunEvaluation.from_dict(raw_evaluation),
            matched_fixture_seed=_integer(
                payload.get("matched_fixture_seed"),
                "matched_fixture_seed",
                minimum=0,
            ),
            fixture_variant_digest=str(payload.get("fixture_variant_digest") or ""),
            applied_model_seed=(
                _integer(applied_seed, "applied_model_seed", minimum=0) if applied_seed is not None else None
            ),
            model_seed_status=str(payload.get("model_seed_status") or ""),
            budget_enforcement=tuple(
                BudgetEnforcement.from_dict(_mapping(item, "budget_enforcement")) for item in raw_budgets
            ),
            action_telemetry=tuple(ActionEvent.from_dict(_mapping(item, "action_telemetry")) for item in raw_actions),
            action_telemetry_available=bool(payload.get("action_telemetry_available")),
            action_telemetry_reliability=str(payload.get("action_telemetry_reliability") or ""),
            duration_seconds=_number(
                payload.get("duration_seconds"),
                "duration_seconds",
            ),
            duration_censored=bool(payload.get("duration_censored")),
            censor_limit_seconds=(_number(censor_limit, "censor_limit_seconds") if censor_limit is not None else None),
            started_at=_number(payload.get("started_at"), "started_at"),
            finished_at=_number(payload.get("finished_at"), "finished_at"),
            policy_violations=_identifier_tuple(
                payload.get("policy_violations") or [],
                "policy_violations",
            ),
            artifact_refs=_reference_tuple(
                payload.get("artifact_refs") or [],
                "artifact_refs",
            ),
            model_seed_evidence=_reference_tuple(
                payload.get("model_seed_evidence") or [],
                "model_seed_evidence",
            ),
            environment=_json_mapping(
                payload.get("environment") or {},
                "environment",
            ),
            error_class=_optional_text(payload.get("error_class"), "error_class"),
            source_schema_version=_optional_text(
                payload.get("source_schema_version") or schema_version,
                "source_schema_version",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_telemetry": [item.to_dict() for item in self.action_telemetry],
            "action_telemetry_available": self.action_telemetry_available,
            "action_telemetry_reliability": self.action_telemetry_reliability,
            "applied_model_seed": self.applied_model_seed,
            "artifact_refs": list(self.artifact_refs),
            "budget_enforcement": [item.to_dict() for item in self.budget_enforcement],
            "censor_limit_seconds": self.censor_limit_seconds,
            "duration_censored": self.duration_censored,
            "duration_seconds": self.duration_seconds,
            "environment": _json_mapping(self.environment, "environment"),
            "error_class": self.error_class,
            "evaluation": self.evaluation.to_dict(),
            "execution_status": self.execution_status,
            "finished_at": self.finished_at,
            "fixture_variant_digest": self.fixture_variant_digest or None,
            "matched_fixture_seed": self.matched_fixture_seed,
            "model_seed_evidence": list(self.model_seed_evidence),
            "model_seed_status": self.model_seed_status,
            "policy_violations": list(self.policy_violations),
            "repetition": self.repetition,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "schema_version": self.schema_version,
            "source_schema_version": self.source_schema_version,
            "started_at": self.started_at,
            "system_id": self.system_id,
            "track_id": self.track_id,
        }


def load_run(payload_or_path: Mapping[str, Any] | str | Path) -> BenchmarkRunV3:
    """Read schema 2.0 or conservatively adapt a schema 1.0 run.

    Legacy process success is never promoted to task completion, legacy
    precision is labelled incomplete, and unavailable evidence stays
    unavailable.
    """

    if isinstance(payload_or_path, Mapping):
        payload = payload_or_path
    else:
        try:
            decoded = json.loads(Path(payload_or_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BenchmarkV3SchemaError("run_load_failed") from exc
        payload = _mapping(decoded, "run")
    version = str(payload.get("schema_version") or "")
    if version == BENCHMARK_V3_SCHEMA_VERSION:
        return BenchmarkRunV3.from_dict(payload)
    if version == "1.0":
        return _adapt_legacy_run(payload)
    raise BenchmarkV3SchemaError(f"unsupported_schema_version:{version or 'missing'}")


def validate_budget_enforcement(
    *,
    system_id: str,
    declared_budgets: Mapping[str, Any],
    enforcement: Sequence[BudgetEnforcement],
) -> tuple[BudgetEnforcement, ...]:
    """Require one system-specific enforcement record per declared budget."""

    _identifier(system_id, "system_id")
    expected = {_identifier(name, "budget_name") for name in declared_budgets}
    records = tuple(enforcement)
    actual = {item.budget_name for item in records}
    if expected != actual:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        detail = ",".join([*(f"missing:{item}" for item in missing), *(f"extra:{item}" for item in extra)])
        raise BenchmarkV3SchemaError(f"budget_enforcement_mismatch:{detail}")
    if any(item.system_id != system_id for item in records):
        raise BenchmarkV3SchemaError("budget_system_mismatch")
    for item in records:
        try:
            declared_limit = float(declared_budgets[item.budget_name])
        except (TypeError, ValueError):
            raise BenchmarkV3SchemaError("invalid:declared_budget") from None
        if not math.isclose(declared_limit, float(item.limit), rel_tol=0, abs_tol=1e-9):
            raise BenchmarkV3SchemaError("budget_limit_mismatch")
    return tuple(sorted(records, key=lambda item: item.budget_name))


def _adapt_legacy_run(payload: Mapping[str, Any]) -> BenchmarkRunV3:
    old_status = str(payload.get("status") or "failed").lower()
    execution_status = {
        "succeeded": "succeeded",
        "partial": "succeeded",
        "timeout": "timeout",
        "invalid": "invalid",
        "cancelled": "cancelled",
    }.get(old_status, "failed")
    task_status = {
        "partial": "partial",
        "invalid": "invalid",
    }.get(old_status, "not_evaluated")
    raw_metrics = payload.get("metrics")
    legacy_metrics = raw_metrics if isinstance(raw_metrics, Mapping) else {}
    metrics: list[MetricObservation] = []
    for population in sorted(POPULATIONS):
        conditional = population == "completion_conditional"
        eligible = not conditional or execution_status == "succeeded"
        for new_name, old_name in (
            ("reported_recall", "finding_recall"),
            ("full_claim_precision", "finding_precision"),
        ):
            raw_value = legacy_metrics.get(old_name)
            if eligible and _finite(raw_value):
                metrics.append(
                    MetricObservation(
                        name=new_name,
                        population=population,
                        available=True,
                        reliability="legacy_incomplete",
                        value=_number(raw_value, f"legacy.metrics.{old_name}"),
                        reason=(
                            "legacy_matcher_may_omit_unmatched_claims"
                            if new_name == "full_claim_precision"
                            else "legacy_reported_recall_only"
                        ),
                    )
                )
            else:
                metrics.append(
                    MetricObservation.unavailable(
                        new_name,
                        population,
                        "legacy_metric_missing_or_population_ineligible",
                    )
                )
        metrics.append(
            MetricObservation.unavailable(
                "verified_recall",
                population,
                "legacy_run_has_no_control_plane_verification",
            )
        )
    summary = payload.get("result_summary")
    result_summary = summary if isinstance(summary, Mapping) else {}
    reported = result_summary.get("reported_findings") or []
    claims: list[ClaimAssessment] = []
    if _is_sequence(reported):
        for index, item in enumerate(reported[:_MAX_ITEMS]):
            text = str(item).strip()
            if not text:
                continue
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]
            claims.append(
                ClaimAssessment(
                    claim_id=f"legacy-claim-{index + 1}",
                    text=text[:_MAX_TEXT],
                    normalized_claim_id=f"unmatched:{digest}",
                    matcher_kind="legacy_unknown",
                )
            )
    environment_raw = payload.get("environment")
    environment = _json_mapping(environment_raw, "environment") if isinstance(environment_raw, Mapping) else {}
    runner = environment.get("runner")
    runner_mapping = runner if isinstance(runner, Mapping) else {}
    system_id = _legacy_identifier(runner_mapping.get("system_id"), "legacy-system")
    budgets_raw = environment.get("budgets")
    budgets = budgets_raw if isinstance(budgets_raw, Mapping) else {}
    budget_records = tuple(
        BudgetEnforcement(
            system_id=system_id,
            budget_name=_legacy_identifier(name, f"legacy-budget-{index + 1}"),
            limit=float(value),
            unit=_legacy_budget_unit(str(name)),
            enforcement_mode="none",
            measured=None,
            exceeded=None,
            reliable=False,
            note="legacy_declared_budget_without_system_enforcement_evidence",
        )
        for index, (name, value) in enumerate(sorted(budgets.items()))
        if _finite(value) and float(value) > 0
    )
    actions_raw = payload.get("actions") or []
    action_events: list[ActionEvent] = []
    if _is_sequence(actions_raw):
        for index, value in enumerate(actions_raw[:_MAX_ITEMS]):
            action_name = _legacy_identifier(value, f"legacy-action-{index + 1}")
            action_events.append(
                ActionEvent(
                    event_id=f"legacy-event-{index + 1}",
                    sequence=index,
                    action_name=action_name,
                    action_type="legacy",
                    status="unknown",
                )
            )
    duration = max(0.0, float(payload.get("duration_seconds") or 0.0))
    started = float(payload.get("started_at") or 0.0)
    finished = float(payload.get("finished_at") or started + duration)
    if finished < started:
        finished = started + duration
    old_run_id = _legacy_identifier(payload.get("run_id"), "legacy-run")
    return BenchmarkRunV3(
        run_id=old_run_id,
        track_id="legacy-unclassified",
        system_id=system_id,
        scenario_id=_legacy_identifier(
            payload.get("scenario_id"),
            "legacy-scenario",
        ),
        repetition=max(1, int(payload.get("repetition") or 1)),
        execution_status=execution_status,
        evaluation=RunEvaluation(
            task_status=task_status,
            completion_rule_id="legacy-unverified-status-v1",
            metrics=tuple(metrics),
            claims=tuple(claims),
            evaluator_id="legacy-adapter-v1",
        ),
        matched_fixture_seed=max(0, int(payload.get("seed") or 0)),
        fixture_variant_digest="",
        applied_model_seed=None,
        model_seed_status="unknown",
        budget_enforcement=budget_records,
        action_telemetry=tuple(action_events),
        action_telemetry_available=bool(action_events),
        action_telemetry_reliability=("legacy_incomplete" if action_events else "unavailable"),
        duration_seconds=duration,
        duration_censored=execution_status == "timeout",
        censor_limit_seconds=duration if execution_status == "timeout" else None,
        started_at=started,
        finished_at=finished,
        policy_violations=_legacy_identifiers(
            payload.get("policy_violations") or [],
            "policy-violation",
        ),
        artifact_refs=_legacy_references(
            payload.get("artifact_refs") or [],
        ),
        environment=environment,
        error_class=str(payload.get("error_class") or "")[:160],
        source_schema_version="1.0",
    )


def _legacy_budget_unit(name: str) -> str:
    if "seconds" in name:
        return "seconds"
    if "bytes" in name:
        return "bytes"
    if "cost" in name:
        return "usd"
    if "token" in name:
        return "tokens"
    return "count"


def _legacy_identifier(value: Any, fallback: str) -> str:
    normalized = re.sub(r"[^a-z0-9_.:-]+", "-", str(value or "").strip().lower())
    normalized = normalized.strip("-.:")[:160]
    return normalized if normalized and _IDENTIFIER.fullmatch(normalized) else fallback


def _legacy_identifiers(value: Any, prefix: str) -> tuple[str, ...]:
    if not _is_sequence(value):
        return ()
    return tuple(_legacy_identifier(item, f"{prefix}-{index + 1}") for index, item in enumerate(value[:_MAX_ITEMS]))


def _legacy_references(value: Any) -> tuple[str, ...]:
    if not _is_sequence(value):
        return ()
    result = tuple(str(item).strip() for item in value[:_MAX_ITEMS] if str(item).strip())
    _bounded_references(result, "legacy.references")
    return result


def _identifier(value: Any, name: str) -> str:
    text = str(value or "").strip().lower()
    if not _IDENTIFIER.fullmatch(text):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    return text


def _optional_identifier(value: Any, name: str) -> str:
    if value is None or value == "":
        return ""
    return _identifier(value, name)


def _text(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text or len(text.encode("utf-8")) > _MAX_TEXT:
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    return text


def _optional_text(value: Any, name: str) -> str:
    if value is None or value == "":
        return ""
    return _text(value, name)


def _number(value: Any, name: str) -> float:
    if not _finite(value):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    return float(value)


def _integer(value: Any, name: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise BenchmarkV3SchemaError(f"invalid:{name}") from None
    if str(value).strip() not in {str(result), f"{result}.0"} and not isinstance(value, int):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    if minimum is not None and result < minimum:
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    return result


def _optional_integer(value: Any) -> int | None:
    if value is None:
        return None
    return _integer(value, "integer", minimum=0)


def _finite(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    return value


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _identifier_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not _is_sequence(value):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    result = tuple(_identifier(item, name) for item in value[:_MAX_ITEMS])
    _bounded_identifiers(result, name)
    return result


def _reference_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not _is_sequence(value):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    result = tuple(str(item).strip() for item in value[:_MAX_ITEMS])
    _bounded_references(result, name)
    return result


def _bounded_identifiers(value: Sequence[str], name: str) -> None:
    if len(value) > _MAX_ITEMS:
        raise BenchmarkV3SchemaError(f"too_many:{name}")
    for item in value:
        _identifier(item, name)


def _bounded_references(value: Sequence[str], name: str) -> None:
    if len(value) > _MAX_ITEMS:
        raise BenchmarkV3SchemaError(f"too_many:{name}")
    for item in value:
        encoded = str(item).encode("utf-8")
        if not item or len(encoded) > 2_048 or any(ord(character) < 32 for character in item):
            raise BenchmarkV3SchemaError(f"invalid:{name}")


def _json_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    try:
        encoded = canonical_json(_thaw_json(value))
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BenchmarkV3SchemaError(f"invalid:{name}") from exc
    if len(encoded.encode("utf-8")) > 1_000_000:
        raise BenchmarkV3SchemaError(f"too_large:{name}")
    return dict(decoded)


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(nested) for key, nested in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_json(item) for item in value]
    return value
