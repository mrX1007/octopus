"""Prospective, fail-closed readiness calibration for full Benchmark v4.

The readiness gate is intentionally separate from evaluation.  A frozen plan
declares a complete calibration schedule, thresholds, and a reference runner
before any calibration run is observed.  The gate accepts exactly that run
set, never a prefix or a selected subset, and rejects runs from the evaluation
track.
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

from ..v3.schema import BenchmarkRunV3, canonical_json, stable_digest
from .schema import BenchmarkV4SchemaError, EfficiencyPlan

READINESS_PROFILE_SCHEMA_VERSION = "1.1"
READINESS_PLAN_SCHEMA_VERSION = "1.1"
READINESS_EVIDENCE_SCHEMA_VERSION = "1.1"
READINESS_PHASE = "calibration"
READINESS_METHODOLOGY = MappingProxyType(
    {
        "evaluation_data_used": False,
        "missing_verified_recall": "fail_closed_no_imputation",
        "paired_claim_eligibility": (
            "both_succeeded_completed_error_free_uncensored_verified_recall_precision_positive_wall_and_verified_ledger"
        ),
        "policy_violation_gate": "zero_tolerance",
        "reference_population": "every_predeclared_calibration_block",
        "stopping_rule": "fixed_complete_schedule_no_optional_stopping",
        "verified_recall_population": "all_scheduled",
    }
)

_MAX_REPETITIONS = 100
_MAX_SCENARIOS = 4_096
_MAX_SYSTEMS = 64
_MAX_RUNS = 1_000_000
_MAX_TEXT = 16_384
_SEED_LIMIT = 2**63


class BenchmarkV4ReadinessError(BenchmarkV4SchemaError):
    """Raised when valid calibration evidence does not pass the full-run gate."""

    def __init__(self, failed_check_ids: Sequence[str]) -> None:
        self.failed_check_ids = tuple(str(item) for item in failed_check_ids)
        super().__init__("benchmark_v4_readiness_gate_failed:" + ",".join(self.failed_check_ids))


@dataclass(frozen=True)
class ReadinessProfile:
    """Reusable, hash-frozen thresholds declared before calibration."""

    profile_id: str
    reference_runner_id: str
    calibration_repetitions: int
    calibration_hard_cap_seconds: int
    minimum_paired_claim_eligible_blocks: int
    minimum_system_completed_runs: int
    minimum_system_completion_rate: float
    minimum_system_verified_recall: float
    minimum_reference_completion_rate: float
    minimum_reference_verified_recall: float
    required_evaluator_id: str = "sealed-evaluator-v3"
    maximum_policy_violations: int = 0
    methodology: Mapping[str, Any] = field(default_factory=lambda: dict(READINESS_METHODOLOGY))
    schema_version: str = READINESS_PROFILE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _identifier(self.profile_id, "readiness_profile.profile_id")
        _identifier(self.reference_runner_id, "readiness_profile.reference_runner_id")
        _identifier(self.required_evaluator_id, "readiness_profile.required_evaluator_id")
        _integer_range(
            self.calibration_repetitions,
            "readiness_profile.calibration_repetitions",
            minimum=1,
            maximum=_MAX_REPETITIONS,
        )
        _integer_range(
            self.calibration_hard_cap_seconds,
            "readiness_profile.calibration_hard_cap_seconds",
            minimum=1,
            maximum=899,
        )
        _integer_range(
            self.minimum_paired_claim_eligible_blocks,
            "readiness_profile.minimum_paired_claim_eligible_blocks",
            minimum=1,
            maximum=_MAX_RUNS,
        )
        _integer_range(
            self.minimum_system_completed_runs,
            "readiness_profile.minimum_system_completed_runs",
            minimum=1,
            maximum=_MAX_RUNS,
        )
        for name, value in (
            ("minimum_system_completion_rate", self.minimum_system_completion_rate),
            ("minimum_system_verified_recall", self.minimum_system_verified_recall),
            ("minimum_reference_completion_rate", self.minimum_reference_completion_rate),
            ("minimum_reference_verified_recall", self.minimum_reference_verified_recall),
        ):
            _positive_rate(value, f"readiness_profile.{name}")
        if self.maximum_policy_violations != 0 or isinstance(self.maximum_policy_violations, bool):
            raise BenchmarkV4SchemaError("readiness_profile_requires_zero_policy_violations")
        methodology = _methodology(self.methodology)
        if methodology != dict(READINESS_METHODOLOGY):
            raise BenchmarkV4SchemaError("fixed_readiness_methodology_required")
        object.__setattr__(self, "methodology", MappingProxyType(methodology))
        if self.schema_version != READINESS_PROFILE_SCHEMA_VERSION:
            raise BenchmarkV4SchemaError("unsupported_readiness_profile_schema")

    @property
    def digest(self) -> str:
        return stable_digest(self._digest_payload())

    def _digest_payload(self) -> dict[str, Any]:
        return {
            "calibration_hard_cap_seconds": self.calibration_hard_cap_seconds,
            "calibration_repetitions": self.calibration_repetitions,
            "maximum_policy_violations": self.maximum_policy_violations,
            "methodology": dict(self.methodology),
            "minimum_paired_claim_eligible_blocks": self.minimum_paired_claim_eligible_blocks,
            "minimum_reference_completion_rate": self.minimum_reference_completion_rate,
            "minimum_reference_verified_recall": self.minimum_reference_verified_recall,
            "minimum_system_completed_runs": self.minimum_system_completed_runs,
            "minimum_system_completion_rate": self.minimum_system_completion_rate,
            "minimum_system_verified_recall": self.minimum_system_verified_recall,
            "profile_id": self.profile_id,
            "reference_runner_id": self.reference_runner_id,
            "required_evaluator_id": self.required_evaluator_id,
            "schema_version": self.schema_version,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._digest_payload(), "frozen": True, "profile_digest": self.digest}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReadinessProfile:
        _exact_keys(
            payload,
            {
                "calibration_hard_cap_seconds",
                "calibration_repetitions",
                "frozen",
                "maximum_policy_violations",
                "methodology",
                "minimum_paired_claim_eligible_blocks",
                "minimum_reference_completion_rate",
                "minimum_reference_verified_recall",
                "minimum_system_completed_runs",
                "minimum_system_completion_rate",
                "minimum_system_verified_recall",
                "profile_digest",
                "profile_id",
                "reference_runner_id",
                "required_evaluator_id",
                "schema_version",
            },
            "invalid_readiness_profile",
        )
        methodology = payload.get("methodology")
        if not isinstance(methodology, Mapping):
            raise BenchmarkV4SchemaError("invalid_readiness_profile")
        try:
            profile = cls(
                profile_id=str(payload.get("profile_id") or ""),
                reference_runner_id=str(payload.get("reference_runner_id") or ""),
                required_evaluator_id=str(payload.get("required_evaluator_id") or ""),
                calibration_hard_cap_seconds=_integer(
                    payload.get("calibration_hard_cap_seconds"),
                    "readiness_profile.calibration_hard_cap_seconds",
                ),
                calibration_repetitions=_integer(
                    payload.get("calibration_repetitions"),
                    "readiness_profile.calibration_repetitions",
                ),
                minimum_paired_claim_eligible_blocks=_integer(
                    payload.get("minimum_paired_claim_eligible_blocks"),
                    "readiness_profile.minimum_paired_claim_eligible_blocks",
                ),
                minimum_system_completed_runs=_integer(
                    payload.get("minimum_system_completed_runs"),
                    "readiness_profile.minimum_system_completed_runs",
                ),
                minimum_system_completion_rate=_number(
                    payload.get("minimum_system_completion_rate"),
                    "readiness_profile.minimum_system_completion_rate",
                ),
                minimum_system_verified_recall=_number(
                    payload.get("minimum_system_verified_recall"),
                    "readiness_profile.minimum_system_verified_recall",
                ),
                minimum_reference_completion_rate=_number(
                    payload.get("minimum_reference_completion_rate"),
                    "readiness_profile.minimum_reference_completion_rate",
                ),
                minimum_reference_verified_recall=_number(
                    payload.get("minimum_reference_verified_recall"),
                    "readiness_profile.minimum_reference_verified_recall",
                ),
                maximum_policy_violations=_integer(
                    payload.get("maximum_policy_violations"),
                    "readiness_profile.maximum_policy_violations",
                ),
                methodology=dict(methodology),
                schema_version=str(payload.get("schema_version") or ""),
            )
        except BenchmarkV4SchemaError:
            raise
        except (TypeError, ValueError) as exc:
            raise BenchmarkV4SchemaError("invalid_readiness_profile") from exc
        if payload.get("frozen") is not True:
            raise BenchmarkV4SchemaError("readiness_profile_not_frozen")
        if str(payload.get("profile_digest") or "") != profile.digest:
            raise BenchmarkV4SchemaError("readiness_profile_digest_mismatch")
        return profile


@dataclass(frozen=True)
class ReadinessPlan:
    """Exact calibration schedule bound to one immutable full efficiency plan."""

    profile: ReadinessProfile
    efficiency_plan_digest: str
    efficiency_track_id: str
    source_analysis_plan_digest: str
    source_track_id: str
    calibration_track_id: str
    system_ids: tuple[str, ...]
    scenario_ids: tuple[str, ...]
    fixture_seeds: Mapping[str, tuple[int, ...]]
    schema_version: str = READINESS_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.profile, ReadinessProfile):
            raise BenchmarkV4SchemaError("readiness_plan_requires_profile")
        object.__setattr__(self, "system_ids", tuple(self.system_ids))
        object.__setattr__(self, "scenario_ids", tuple(self.scenario_ids))
        if not isinstance(self.fixture_seeds, Mapping):
            raise BenchmarkV4SchemaError("invalid:readiness_plan.fixture_seeds")
        try:
            seeds = MappingProxyType({str(key): tuple(value) for key, value in sorted(self.fixture_seeds.items())})
        except TypeError as exc:
            raise BenchmarkV4SchemaError("invalid:readiness_plan.fixture_seeds") from exc
        object.__setattr__(self, "fixture_seeds", seeds)
        for value, name in (
            (self.efficiency_plan_digest, "readiness_plan.efficiency_plan_digest"),
            (self.source_analysis_plan_digest, "readiness_plan.source_analysis_plan_digest"),
        ):
            _digest(value, name)
        for track_id in (self.efficiency_track_id, self.source_track_id, self.calibration_track_id):
            _identifier(track_id, "readiness_plan.track_id")
        if len({self.efficiency_track_id, self.source_track_id, self.calibration_track_id}) != 3:
            raise BenchmarkV4SchemaError("readiness_calibration_track_not_isolated")
        if (
            len(self.system_ids) < 2
            or len(self.system_ids) > _MAX_SYSTEMS
            or len(set(self.system_ids)) != len(self.system_ids)
            or self.profile.reference_runner_id in self.system_ids
        ):
            raise BenchmarkV4SchemaError("readiness_plan_requires_unique_systems")
        if (
            not self.scenario_ids
            or len(self.scenario_ids) > _MAX_SCENARIOS
            or len(set(self.scenario_ids)) != len(self.scenario_ids)
        ):
            raise BenchmarkV4SchemaError("readiness_plan_requires_unique_scenarios")
        for value in (*self.system_ids, *self.scenario_ids):
            _identifier(value, "readiness_plan.identifier")
        if set(seeds) != set(self.scenario_ids):
            raise BenchmarkV4SchemaError("readiness_plan_fixture_seed_scenarios")
        flattened: list[int] = []
        for values in seeds.values():
            if len(values) != self.profile.calibration_repetitions or len(set(values)) != len(values):
                raise BenchmarkV4SchemaError("readiness_plan_fixture_seed_count")
            for fixture_seed in values:
                _integer_range(fixture_seed, "readiness_plan.fixture_seed", minimum=0, maximum=_SEED_LIMIT - 1)
                flattened.append(fixture_seed)
        if len(flattened) != len(set(flattened)):
            raise BenchmarkV4SchemaError("duplicate_readiness_fixture_seed")
        scheduled_per_system = len(self.scenario_ids) * self.profile.calibration_repetitions
        if self.profile.minimum_system_completed_runs > scheduled_per_system:
            raise BenchmarkV4SchemaError("readiness_threshold_unattainable")
        if self.profile.minimum_paired_claim_eligible_blocks > scheduled_per_system:
            raise BenchmarkV4SchemaError("readiness_threshold_unattainable")
        if self.schema_version != READINESS_PLAN_SCHEMA_VERSION:
            raise BenchmarkV4SchemaError("unsupported_readiness_plan_schema")

    @property
    def digest(self) -> str:
        return stable_digest(self._digest_payload())

    @property
    def plan_id(self) -> str:
        return "readiness-plan-" + self.digest[:20]

    @property
    def expected_run_count(self) -> int:
        return len(self.scenario_ids) * self.profile.calibration_repetitions * (len(self.system_ids) + 1)

    def expected_run_keys(self) -> tuple[tuple[str, int, int, str], ...]:
        participants = (self.profile.reference_runner_id, *self.system_ids)
        return tuple(
            (scenario_id, repetition, self.fixture_seeds[scenario_id][repetition - 1], system_id)
            for scenario_id in self.scenario_ids
            for repetition in range(1, self.profile.calibration_repetitions + 1)
            for system_id in participants
        )

    def _digest_payload(self) -> dict[str, Any]:
        return {
            "calibration_track_id": self.calibration_track_id,
            "efficiency_plan_digest": self.efficiency_plan_digest,
            "efficiency_track_id": self.efficiency_track_id,
            "fixture_seeds": {key: list(value) for key, value in self.fixture_seeds.items()},
            "profile": self.profile.to_dict(),
            "scenario_ids": list(self.scenario_ids),
            "schema_version": self.schema_version,
            "source_analysis_plan_digest": self.source_analysis_plan_digest,
            "source_track_id": self.source_track_id,
            "system_ids": list(self.system_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._digest_payload(), "frozen": True, "plan_digest": self.digest, "plan_id": self.plan_id}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReadinessPlan:
        _exact_keys(
            payload,
            {
                "calibration_track_id",
                "efficiency_plan_digest",
                "efficiency_track_id",
                "fixture_seeds",
                "frozen",
                "plan_digest",
                "plan_id",
                "profile",
                "scenario_ids",
                "schema_version",
                "source_analysis_plan_digest",
                "source_track_id",
                "system_ids",
            },
            "invalid_readiness_plan",
        )
        raw_profile = payload.get("profile")
        raw_seeds = payload.get("fixture_seeds")
        if not isinstance(raw_profile, Mapping) or not isinstance(raw_seeds, Mapping):
            raise BenchmarkV4SchemaError("invalid_readiness_plan")
        try:
            plan = cls(
                profile=ReadinessProfile.from_dict(raw_profile),
                efficiency_plan_digest=str(payload.get("efficiency_plan_digest") or ""),
                efficiency_track_id=str(payload.get("efficiency_track_id") or ""),
                source_analysis_plan_digest=str(payload.get("source_analysis_plan_digest") or ""),
                source_track_id=str(payload.get("source_track_id") or ""),
                calibration_track_id=str(payload.get("calibration_track_id") or ""),
                system_ids=tuple(
                    str(item) for item in _sequence(payload.get("system_ids"), "readiness_plan.system_ids")
                ),
                scenario_ids=tuple(
                    str(item) for item in _sequence(payload.get("scenario_ids"), "readiness_plan.scenario_ids")
                ),
                fixture_seeds={
                    str(key): tuple(
                        _integer(item, "readiness_plan.fixture_seed")
                        for item in _sequence(value, "readiness_plan.fixture_seeds")
                    )
                    for key, value in raw_seeds.items()
                },
                schema_version=str(payload.get("schema_version") or ""),
            )
        except BenchmarkV4SchemaError:
            raise
        except (TypeError, ValueError) as exc:
            raise BenchmarkV4SchemaError("invalid_readiness_plan") from exc
        if payload.get("frozen") is not True:
            raise BenchmarkV4SchemaError("readiness_plan_not_frozen")
        if str(payload.get("plan_digest") or "") != plan.digest:
            raise BenchmarkV4SchemaError("readiness_plan_digest_mismatch")
        if str(payload.get("plan_id") or "") != plan.plan_id:
            raise BenchmarkV4SchemaError("readiness_plan_id_mismatch")
        return plan


@dataclass(frozen=True)
class CalibrationSummary:
    """Minimal aggregate retained for one system or reference scenario."""

    subject_id: str
    role: str
    scheduled_runs: int
    execution_succeeded_runs: int
    completed_runs: int
    verified_recall_available_runs: int
    mean_verified_recall: float | None
    policy_violation_count: int

    def __post_init__(self) -> None:
        _identifier(self.subject_id, "readiness_summary.subject_id")
        if self.role not in {"reference_scenario", "system"}:
            raise BenchmarkV4SchemaError("invalid:readiness_summary.role")
        for name, value in (
            ("scheduled_runs", self.scheduled_runs),
            ("execution_succeeded_runs", self.execution_succeeded_runs),
            ("completed_runs", self.completed_runs),
            ("verified_recall_available_runs", self.verified_recall_available_runs),
            ("policy_violation_count", self.policy_violation_count),
        ):
            _integer_range(value, f"readiness_summary.{name}", minimum=0, maximum=_MAX_RUNS)
        if self.scheduled_runs < 1 or any(
            value > self.scheduled_runs
            for value in (
                self.execution_succeeded_runs,
                self.completed_runs,
                self.verified_recall_available_runs,
            )
        ):
            raise BenchmarkV4SchemaError("invalid:readiness_summary.counts")
        if self.verified_recall_available_runs == 0:
            if self.mean_verified_recall is not None:
                raise BenchmarkV4SchemaError("unavailable_readiness_recall_has_mean")
        elif self.mean_verified_recall is None:
            raise BenchmarkV4SchemaError("available_readiness_recall_missing_mean")
        else:
            _rate(self.mean_verified_recall, "readiness_summary.mean_verified_recall")

    @property
    def completion_rate(self) -> float:
        return _rounded(self.completed_runs / self.scheduled_runs)

    @property
    def verified_recall_coverage(self) -> float:
        return _rounded(self.verified_recall_available_runs / self.scheduled_runs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "completed_runs": self.completed_runs,
            "completion_rate": self.completion_rate,
            "execution_succeeded_runs": self.execution_succeeded_runs,
            "mean_verified_recall": self.mean_verified_recall,
            "policy_violation_count": self.policy_violation_count,
            "role": self.role,
            "scheduled_runs": self.scheduled_runs,
            "subject_id": self.subject_id,
            "verified_recall_available_runs": self.verified_recall_available_runs,
            "verified_recall_coverage": self.verified_recall_coverage,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CalibrationSummary:
        _exact_keys(
            payload,
            {
                "completed_runs",
                "completion_rate",
                "execution_succeeded_runs",
                "mean_verified_recall",
                "policy_violation_count",
                "role",
                "scheduled_runs",
                "subject_id",
                "verified_recall_available_runs",
                "verified_recall_coverage",
            },
            "invalid_readiness_summary",
        )
        mean = payload.get("mean_verified_recall")
        summary = cls(
            subject_id=str(payload.get("subject_id") or ""),
            role=str(payload.get("role") or ""),
            scheduled_runs=_integer(payload.get("scheduled_runs"), "readiness_summary.scheduled_runs"),
            execution_succeeded_runs=_integer(
                payload.get("execution_succeeded_runs"), "readiness_summary.execution_succeeded_runs"
            ),
            completed_runs=_integer(payload.get("completed_runs"), "readiness_summary.completed_runs"),
            verified_recall_available_runs=_integer(
                payload.get("verified_recall_available_runs"),
                "readiness_summary.verified_recall_available_runs",
            ),
            mean_verified_recall=(
                _number(mean, "readiness_summary.mean_verified_recall") if mean is not None else None
            ),
            policy_violation_count=_integer(
                payload.get("policy_violation_count"), "readiness_summary.policy_violation_count"
            ),
        )
        if canonical_json(payload) != canonical_json(summary.to_dict()):
            raise BenchmarkV4SchemaError("readiness_summary_derived_value_mismatch")
        return summary


@dataclass(frozen=True)
class ReadinessCheck:
    check_id: str
    passed: bool
    detail: str

    def __post_init__(self) -> None:
        _identifier(self.check_id, "readiness_check.check_id")
        if not isinstance(self.passed, bool):
            raise BenchmarkV4SchemaError("invalid:readiness_check.passed")
        _text(self.detail, "readiness_check.detail")

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "detail": self.detail,
            "status": "passed" if self.passed else "failed",
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReadinessCheck:
        _exact_keys(payload, {"check_id", "detail", "status"}, "invalid_readiness_check")
        status = str(payload.get("status") or "")
        if status not in {"passed", "failed"}:
            raise BenchmarkV4SchemaError("invalid:readiness_check.status")
        return cls(
            check_id=str(payload.get("check_id") or ""),
            passed=status == "passed",
            detail=str(payload.get("detail") or ""),
        )


@dataclass(frozen=True)
class ReadinessEvidence:
    """Deterministic evidence summary; it contains no evaluation observations."""

    readiness_plan_digest: str
    readiness_plan_id: str
    efficiency_plan_digest: str
    calibration_track_id: str
    source_run_digest: str
    expected_run_count: int
    observed_run_count: int
    attested_run_count: int
    matched_fixture_block_count: int
    paired_claim_eligible_block_count: int
    reference_scenarios: tuple[CalibrationSummary, ...]
    systems: tuple[CalibrationSummary, ...]
    checks: tuple[ReadinessCheck, ...]
    methodology: Mapping[str, Any] = field(default_factory=lambda: dict(READINESS_METHODOLOGY))
    schema_version: str = READINESS_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "reference_scenarios", tuple(self.reference_scenarios))
        object.__setattr__(self, "systems", tuple(self.systems))
        object.__setattr__(self, "checks", tuple(self.checks))
        _digest(self.readiness_plan_digest, "readiness_evidence.readiness_plan_digest")
        _digest(self.efficiency_plan_digest, "readiness_evidence.efficiency_plan_digest")
        _digest(self.source_run_digest, "readiness_evidence.source_run_digest")
        _identifier(self.readiness_plan_id, "readiness_evidence.readiness_plan_id")
        _identifier(self.calibration_track_id, "readiness_evidence.calibration_track_id")
        for name, value in (
            ("expected_run_count", self.expected_run_count),
            ("observed_run_count", self.observed_run_count),
            ("attested_run_count", self.attested_run_count),
            ("matched_fixture_block_count", self.matched_fixture_block_count),
            ("paired_claim_eligible_block_count", self.paired_claim_eligible_block_count),
        ):
            _integer_range(value, f"readiness_evidence.{name}", minimum=0, maximum=_MAX_RUNS)
        if not self.reference_scenarios or not self.systems or not self.checks:
            raise BenchmarkV4SchemaError("readiness_evidence_incomplete")
        if any(item.role != "reference_scenario" for item in self.reference_scenarios):
            raise BenchmarkV4SchemaError("readiness_reference_summary_role_mismatch")
        if any(item.role != "system" for item in self.systems):
            raise BenchmarkV4SchemaError("readiness_system_summary_role_mismatch")
        if len({item.subject_id for item in self.reference_scenarios}) != len(self.reference_scenarios):
            raise BenchmarkV4SchemaError("duplicate_readiness_reference_summary")
        if len({item.subject_id for item in self.systems}) != len(self.systems):
            raise BenchmarkV4SchemaError("duplicate_readiness_system_summary")
        if len({item.check_id for item in self.checks}) != len(self.checks):
            raise BenchmarkV4SchemaError("duplicate_readiness_check")
        methodology = _methodology(self.methodology)
        if methodology != dict(READINESS_METHODOLOGY):
            raise BenchmarkV4SchemaError("fixed_readiness_methodology_required")
        object.__setattr__(self, "methodology", MappingProxyType(methodology))
        if self.schema_version != READINESS_EVIDENCE_SCHEMA_VERSION:
            raise BenchmarkV4SchemaError("unsupported_readiness_evidence_schema")

    @property
    def ready(self) -> bool:
        return all(item.passed for item in self.checks)

    @property
    def digest(self) -> str:
        return stable_digest(self._digest_payload())

    @property
    def evidence_id(self) -> str:
        return "readiness-evidence-" + self.digest[:20]

    def _digest_payload(self) -> dict[str, Any]:
        return {
            "attested_run_count": self.attested_run_count,
            "calibration_track_id": self.calibration_track_id,
            "checks": [item.to_dict() for item in self.checks],
            "efficiency_plan_digest": self.efficiency_plan_digest,
            "expected_run_count": self.expected_run_count,
            "matched_fixture_block_count": self.matched_fixture_block_count,
            "paired_claim_eligible_block_count": self.paired_claim_eligible_block_count,
            "methodology": dict(self.methodology),
            "observed_run_count": self.observed_run_count,
            "readiness_plan_digest": self.readiness_plan_digest,
            "readiness_plan_id": self.readiness_plan_id,
            "reference_scenarios": [item.to_dict() for item in self.reference_scenarios],
            "schema_version": self.schema_version,
            "source_run_digest": self.source_run_digest,
            "systems": [item.to_dict() for item in self.systems],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._digest_payload(),
            "evidence_digest": self.digest,
            "evidence_id": self.evidence_id,
            "frozen": True,
            "status": "ready" if self.ready else "blocked",
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any], *, plan: ReadinessPlan) -> ReadinessEvidence:
        if not isinstance(plan, ReadinessPlan):
            raise BenchmarkV4SchemaError("invalid_readiness_plan")
        _exact_keys(
            payload,
            {
                "attested_run_count",
                "calibration_track_id",
                "checks",
                "efficiency_plan_digest",
                "evidence_digest",
                "evidence_id",
                "expected_run_count",
                "frozen",
                "matched_fixture_block_count",
                "paired_claim_eligible_block_count",
                "methodology",
                "observed_run_count",
                "readiness_plan_digest",
                "readiness_plan_id",
                "reference_scenarios",
                "schema_version",
                "source_run_digest",
                "status",
                "systems",
            },
            "invalid_readiness_evidence",
        )
        raw_methodology = payload.get("methodology")
        if not isinstance(raw_methodology, Mapping):
            raise BenchmarkV4SchemaError("invalid_readiness_evidence")
        try:
            evidence = cls(
                readiness_plan_digest=str(payload.get("readiness_plan_digest") or ""),
                readiness_plan_id=str(payload.get("readiness_plan_id") or ""),
                efficiency_plan_digest=str(payload.get("efficiency_plan_digest") or ""),
                calibration_track_id=str(payload.get("calibration_track_id") or ""),
                source_run_digest=str(payload.get("source_run_digest") or ""),
                expected_run_count=_integer(payload.get("expected_run_count"), "readiness_evidence.expected_run_count"),
                observed_run_count=_integer(payload.get("observed_run_count"), "readiness_evidence.observed_run_count"),
                attested_run_count=_integer(payload.get("attested_run_count"), "readiness_evidence.attested_run_count"),
                matched_fixture_block_count=_integer(
                    payload.get("matched_fixture_block_count"),
                    "readiness_evidence.matched_fixture_block_count",
                ),
                paired_claim_eligible_block_count=_integer(
                    payload.get("paired_claim_eligible_block_count"),
                    "readiness_evidence.paired_claim_eligible_block_count",
                ),
                reference_scenarios=tuple(
                    CalibrationSummary.from_dict(_mapping(item, "readiness_evidence.reference_scenarios"))
                    for item in _sequence(payload.get("reference_scenarios"), "readiness_evidence.reference_scenarios")
                ),
                systems=tuple(
                    CalibrationSummary.from_dict(_mapping(item, "readiness_evidence.systems"))
                    for item in _sequence(payload.get("systems"), "readiness_evidence.systems")
                ),
                checks=tuple(
                    ReadinessCheck.from_dict(_mapping(item, "readiness_evidence.checks"))
                    for item in _sequence(payload.get("checks"), "readiness_evidence.checks")
                ),
                methodology=dict(raw_methodology),
                schema_version=str(payload.get("schema_version") or ""),
            )
        except BenchmarkV4SchemaError:
            raise
        except (TypeError, ValueError) as exc:
            raise BenchmarkV4SchemaError("invalid_readiness_evidence") from exc
        _validate_evidence_against_plan(evidence, plan)
        expected_checks = _readiness_checks(
            plan,
            evidence.reference_scenarios,
            evidence.systems,
            paired_claim_eligible_block_count=evidence.paired_claim_eligible_block_count,
        )
        if evidence.checks != expected_checks:
            raise BenchmarkV4SchemaError("readiness_evidence_check_mismatch")
        if payload.get("frozen") is not True:
            raise BenchmarkV4SchemaError("readiness_evidence_not_frozen")
        if str(payload.get("status") or "") != ("ready" if evidence.ready else "blocked"):
            raise BenchmarkV4SchemaError("readiness_evidence_status_mismatch")
        if str(payload.get("evidence_digest") or "") != evidence.digest:
            raise BenchmarkV4SchemaError("readiness_evidence_digest_mismatch")
        if str(payload.get("evidence_id") or "") != evidence.evidence_id:
            raise BenchmarkV4SchemaError("readiness_evidence_id_mismatch")
        return evidence


def build_readiness_plan(
    efficiency_plan: EfficiencyPlan,
    profile: ReadinessProfile,
    *,
    calibration_track_id: str | None = None,
    calibration_seed: int = 1,
) -> ReadinessPlan:
    """Freeze a calibration design without consulting any observed run."""

    if not isinstance(efficiency_plan, EfficiencyPlan):
        raise BenchmarkV4SchemaError("readiness_requires_efficiency_plan")
    if not isinstance(profile, ReadinessProfile):
        raise BenchmarkV4SchemaError("readiness_requires_profile")
    if efficiency_plan.publication_tier != "full":
        raise BenchmarkV4SchemaError("readiness_gate_requires_full_efficiency_plan")
    seed = _integer_range(calibration_seed, "readiness_plan.calibration_seed", minimum=0, maximum=2**256 - 1)
    evaluation_seeds = {block.matched_fixture_seed for block in efficiency_plan.schedule}
    used = set(evaluation_seeds)
    fixture_seeds: dict[str, tuple[int, ...]] = {}
    for scenario_id in efficiency_plan.scenario_ids:
        values: list[int] = []
        for repetition in range(1, profile.calibration_repetitions + 1):
            values.append(
                _unique_calibration_seed(
                    efficiency_plan_digest=efficiency_plan.digest,
                    calibration_seed=seed,
                    scenario_id=scenario_id,
                    repetition=repetition,
                    used=used,
                )
            )
        fixture_seeds[scenario_id] = tuple(values)
    return ReadinessPlan(
        profile=profile,
        efficiency_plan_digest=efficiency_plan.digest,
        efficiency_track_id=efficiency_plan.efficiency_track_id,
        source_analysis_plan_digest=efficiency_plan.source_analysis_plan_digest,
        source_track_id=efficiency_plan.source_track_id,
        calibration_track_id=(calibration_track_id or f"{efficiency_plan.efficiency_track_id}-readiness"),
        system_ids=efficiency_plan.system_ids,
        scenario_ids=efficiency_plan.scenario_ids,
        fixture_seeds=fixture_seeds,
    )


def validate_readiness_plan(plan: ReadinessPlan, efficiency_plan: EfficiencyPlan) -> None:
    """Validate all bindings and prove calibration/evaluation seed isolation."""

    if not isinstance(plan, ReadinessPlan) or not isinstance(efficiency_plan, EfficiencyPlan):
        raise BenchmarkV4SchemaError("readiness_plan_binding_requires_frozen_plans")
    if efficiency_plan.publication_tier != "full":
        raise BenchmarkV4SchemaError("readiness_gate_requires_full_efficiency_plan")
    if (
        plan.efficiency_plan_digest != efficiency_plan.digest
        or plan.efficiency_track_id != efficiency_plan.efficiency_track_id
        or plan.source_analysis_plan_digest != efficiency_plan.source_analysis_plan_digest
        or plan.source_track_id != efficiency_plan.source_track_id
        or plan.system_ids != efficiency_plan.system_ids
        or plan.scenario_ids != efficiency_plan.scenario_ids
    ):
        raise BenchmarkV4SchemaError("readiness_efficiency_plan_binding_mismatch")
    calibration_seeds = {seed for values in plan.fixture_seeds.values() for seed in values}
    evaluation_seeds = {block.matched_fixture_seed for block in efficiency_plan.schedule}
    if calibration_seeds & evaluation_seeds:
        raise BenchmarkV4SchemaError("readiness_evaluation_fixture_seed_overlap")


def assess_readiness(
    plan: ReadinessPlan,
    efficiency_plan: EfficiencyPlan,
    runs: Sequence[BenchmarkRunV3],
) -> ReadinessEvidence:
    """Summarize exactly one complete calibration schedule, never a prefix."""

    validate_readiness_plan(plan, efficiency_plan)
    items = tuple(runs)
    if any(not isinstance(run, BenchmarkRunV3) for run in items):
        raise BenchmarkV4SchemaError("readiness_requires_v3_runs")
    expected_keys = plan.expected_run_keys()
    by_key = {(run.scenario_id, run.repetition, run.matched_fixture_seed, run.system_id): run for run in items}
    if len(by_key) != len(items):
        raise BenchmarkV4SchemaError("duplicate_readiness_run")
    if len({run.run_id for run in items}) != len(items):
        raise BenchmarkV4SchemaError("duplicate_readiness_run_id")
    if set(by_key) != set(expected_keys):
        raise BenchmarkV4SchemaError("readiness_runs_do_not_match_frozen_schedule")
    ordered = tuple(by_key[key] for key in expected_keys)
    for run in ordered:
        expected_role = "reference" if run.system_id == plan.profile.reference_runner_id else "system"
        if run.track_id != plan.calibration_track_id:
            raise BenchmarkV4SchemaError("readiness_evaluation_track_run_forbidden")
        if (
            run.environment.get("readiness_plan_digest") != plan.digest
            or run.environment.get("efficiency_plan_digest") != efficiency_plan.digest
            or run.environment.get("readiness_phase") != READINESS_PHASE
            or run.environment.get("readiness_role") != expected_role
        ):
            raise BenchmarkV4SchemaError("readiness_run_attestation_mismatch")
        metric = run.evaluation.metric("verified_recall", "all_scheduled")
        if run.evaluation.evaluator_id != plan.profile.required_evaluator_id:
            raise BenchmarkV4SchemaError("readiness_evaluator_mismatch")
        if metric.available and metric.reliability != "verified":
            raise BenchmarkV4SchemaError("readiness_recall_not_verified")
    block_digests: dict[tuple[str, int, int], set[str]] = {}
    for run in ordered:
        key = (run.scenario_id, run.repetition, run.matched_fixture_seed)
        block_digests.setdefault(key, set()).add(run.fixture_variant_digest)
    if any(len(values) != 1 or "" in values for values in block_digests.values()):
        raise BenchmarkV4SchemaError("readiness_fixture_variant_mismatch")

    reference_scenarios = tuple(
        _summarize_runs(
            scenario_id,
            "reference_scenario",
            tuple(
                run
                for run in ordered
                if run.system_id == plan.profile.reference_runner_id and run.scenario_id == scenario_id
            ),
        )
        for scenario_id in plan.scenario_ids
    )
    systems = tuple(
        _summarize_runs(system_id, "system", tuple(run for run in ordered if run.system_id == system_id))
        for system_id in plan.system_ids
    )
    paired_claim_eligible_block_count = sum(
        all(_paired_product_run_eligible(by_key[(*block, system_id)]) for system_id in plan.system_ids)
        for block in block_digests
    )
    checks = _readiness_checks(
        plan,
        reference_scenarios,
        systems,
        paired_claim_eligible_block_count=paired_claim_eligible_block_count,
    )
    return ReadinessEvidence(
        readiness_plan_digest=plan.digest,
        readiness_plan_id=plan.plan_id,
        efficiency_plan_digest=efficiency_plan.digest,
        calibration_track_id=plan.calibration_track_id,
        source_run_digest=stable_digest(
            {
                "readiness_plan_digest": plan.digest,
                "runs": [run.to_dict() for run in ordered],
            }
        ),
        expected_run_count=plan.expected_run_count,
        observed_run_count=len(ordered),
        attested_run_count=len(ordered),
        matched_fixture_block_count=len(block_digests),
        paired_claim_eligible_block_count=paired_claim_eligible_block_count,
        reference_scenarios=reference_scenarios,
        systems=systems,
        checks=checks,
    )


def verify_readiness_evidence(
    plan: ReadinessPlan,
    efficiency_plan: EfficiencyPlan,
    runs: Sequence[BenchmarkRunV3],
    evidence: ReadinessEvidence,
) -> None:
    """Recompute a summary byte-for-byte from its attested calibration runs."""

    if not isinstance(evidence, ReadinessEvidence):
        raise BenchmarkV4SchemaError("invalid_readiness_evidence")
    expected = assess_readiness(plan, efficiency_plan, runs)
    if canonical_json(evidence.to_dict()) != canonical_json(expected.to_dict()):
        raise BenchmarkV4SchemaError("readiness_evidence_recomputation_mismatch")


def assert_full_campaign_ready(
    plan: ReadinessPlan,
    efficiency_plan: EfficiencyPlan,
    evidence: ReadinessEvidence,
) -> None:
    """Fail fast before the first full evaluation run when any gate is closed."""

    validate_readiness_plan(plan, efficiency_plan)
    if not isinstance(evidence, ReadinessEvidence):
        raise BenchmarkV4SchemaError("invalid_readiness_evidence")
    _validate_evidence_against_plan(evidence, plan)
    if evidence.checks != _readiness_checks(
        plan,
        evidence.reference_scenarios,
        evidence.systems,
        paired_claim_eligible_block_count=evidence.paired_claim_eligible_block_count,
    ):
        raise BenchmarkV4SchemaError("readiness_evidence_check_mismatch")
    failed = tuple(item.check_id for item in evidence.checks if not item.passed)
    if failed:
        raise BenchmarkV4ReadinessError(failed)


def freeze_readiness_profile(profile: ReadinessProfile, path: str | Path) -> Path:
    if not isinstance(profile, ReadinessProfile):
        raise BenchmarkV4SchemaError("invalid_readiness_profile")
    return _freeze_payload(profile.to_dict(), path, differs="frozen_readiness_profile_differs")


def load_readiness_profile(path: str | Path) -> ReadinessProfile:
    return ReadinessProfile.from_dict(_load_mapping(path, "readiness_profile_load_failed"))


def freeze_readiness_plan(plan: ReadinessPlan, path: str | Path) -> Path:
    if not isinstance(plan, ReadinessPlan):
        raise BenchmarkV4SchemaError("invalid_readiness_plan")
    return _freeze_payload(plan.to_dict(), path, differs="frozen_readiness_plan_differs")


def load_readiness_plan(path: str | Path) -> ReadinessPlan:
    return ReadinessPlan.from_dict(_load_mapping(path, "readiness_plan_load_failed"))


def freeze_readiness_evidence(evidence: ReadinessEvidence, path: str | Path) -> Path:
    if not isinstance(evidence, ReadinessEvidence):
        raise BenchmarkV4SchemaError("invalid_readiness_evidence")
    return _freeze_payload(evidence.to_dict(), path, differs="frozen_readiness_evidence_differs")


def load_readiness_evidence(path: str | Path, *, plan: ReadinessPlan) -> ReadinessEvidence:
    if not isinstance(plan, ReadinessPlan):
        raise BenchmarkV4SchemaError("invalid_readiness_plan")
    return ReadinessEvidence.from_dict(_load_mapping(path, "readiness_evidence_load_failed"), plan=plan)


def _summarize_runs(subject_id: str, role: str, runs: Sequence[BenchmarkRunV3]) -> CalibrationSummary:
    recalls = []
    for run in runs:
        metric = run.evaluation.metric("verified_recall", "all_scheduled")
        if metric.available:
            recalls.append(float(cast(float, metric.value)))
    return CalibrationSummary(
        subject_id=subject_id,
        role=role,
        scheduled_runs=len(runs),
        execution_succeeded_runs=sum(run.execution_status == "succeeded" for run in runs),
        completed_runs=sum(run.execution_status == "succeeded" and run.task_status == "completed" for run in runs),
        verified_recall_available_runs=len(recalls),
        mean_verified_recall=(_rounded(math.fsum(recalls) / len(recalls)) if recalls else None),
        policy_violation_count=sum(len(run.policy_violations) for run in runs),
    )


def _readiness_checks(
    plan: ReadinessPlan,
    reference_scenarios: Sequence[CalibrationSummary],
    systems: Sequence[CalibrationSummary],
    *,
    paired_claim_eligible_block_count: int,
) -> tuple[ReadinessCheck, ...]:
    profile = plan.profile
    checks = [
        ReadinessCheck(
            "fixed_schedule_complete",
            sum(item.scheduled_runs for item in reference_scenarios) + sum(item.scheduled_runs for item in systems)
            == plan.expected_run_count,
            f"expected_runs:{plan.expected_run_count}",
        )
    ]
    checks.append(
        ReadinessCheck(
            "paired_claim_eligible_blocks",
            paired_claim_eligible_block_count >= profile.minimum_paired_claim_eligible_blocks,
            f"observed:{paired_claim_eligible_block_count};minimum:{profile.minimum_paired_claim_eligible_blocks}",
        )
    )
    for item in reference_scenarios:
        checks.append(
            ReadinessCheck(
                f"reference_completion:{item.subject_id}",
                item.completion_rate >= profile.minimum_reference_completion_rate,
                f"completion_rate:{item.completion_rate};minimum:{profile.minimum_reference_completion_rate}",
            )
        )
        checks.append(
            ReadinessCheck(
                f"reference_verified_recall:{item.subject_id}",
                item.verified_recall_coverage == 1.0
                and item.mean_verified_recall is not None
                and item.mean_verified_recall >= profile.minimum_reference_verified_recall,
                "coverage:"
                f"{item.verified_recall_coverage};mean:{item.mean_verified_recall};"
                f"minimum:{profile.minimum_reference_verified_recall}",
            )
        )
    for item in systems:
        checks.append(
            ReadinessCheck(
                f"system_completion:{item.subject_id}",
                item.completed_runs >= profile.minimum_system_completed_runs
                and item.completion_rate >= profile.minimum_system_completion_rate,
                f"completed:{item.completed_runs};rate:{item.completion_rate};"
                f"minimum_runs:{profile.minimum_system_completed_runs};"
                f"minimum_rate:{profile.minimum_system_completion_rate}",
            )
        )
        checks.append(
            ReadinessCheck(
                f"system_verified_recall:{item.subject_id}",
                item.verified_recall_coverage == 1.0
                and item.mean_verified_recall is not None
                and item.mean_verified_recall >= profile.minimum_system_verified_recall,
                "coverage:"
                f"{item.verified_recall_coverage};mean:{item.mean_verified_recall};"
                f"minimum:{profile.minimum_system_verified_recall}",
            )
        )
    policy_violations = sum(item.policy_violation_count for item in (*reference_scenarios, *systems))
    checks.append(
        ReadinessCheck(
            "policy_violations",
            policy_violations <= profile.maximum_policy_violations,
            f"observed:{policy_violations};maximum:{profile.maximum_policy_violations}",
        )
    )
    return tuple(checks)


def _validate_evidence_against_plan(evidence: ReadinessEvidence, plan: ReadinessPlan) -> None:
    if (
        evidence.readiness_plan_digest != plan.digest
        or evidence.readiness_plan_id != plan.plan_id
        or evidence.efficiency_plan_digest != plan.efficiency_plan_digest
        or evidence.calibration_track_id != plan.calibration_track_id
        or evidence.expected_run_count != plan.expected_run_count
        or evidence.observed_run_count != plan.expected_run_count
        or evidence.attested_run_count != plan.expected_run_count
        or evidence.matched_fixture_block_count != len(plan.scenario_ids) * plan.profile.calibration_repetitions
        or evidence.paired_claim_eligible_block_count > len(plan.scenario_ids) * plan.profile.calibration_repetitions
        or tuple(item.subject_id for item in evidence.reference_scenarios) != plan.scenario_ids
        or tuple(item.subject_id for item in evidence.systems) != plan.system_ids
    ):
        raise BenchmarkV4SchemaError("readiness_evidence_plan_binding_mismatch")


def _paired_product_run_eligible(run: BenchmarkRunV3) -> bool:
    """Require the calibration inputs needed by a v4 directional claim."""

    recall = run.evaluation.metric("verified_recall", "all_scheduled")
    precision = run.evaluation.metric("verified_claim_precision", "all_scheduled")
    declared_ledger_entries = run.environment.get("controller_ledger_entries")
    return bool(
        run.execution_status == "succeeded"
        and run.task_status == "completed"
        and not run.error_class
        and not run.duration_censored
        and recall.available
        and recall.reliability == "verified"
        and recall.value is not None
        and float(recall.value) > 0.0
        and recall.denominator is not None
        and recall.denominator > 0
        and recall.numerator is not None
        and recall.numerator > 0
        and precision.available
        and precision.reliability == "verified"
        and precision.value is not None
        and float(precision.value) > 0.0
        and math.isfinite(float(run.duration_seconds))
        and float(run.duration_seconds) > 0.0
        and run.action_telemetry_available
        and run.action_telemetry_reliability == "verified"
        and type(declared_ledger_entries) is int
        and declared_ledger_entries > 0
        and declared_ledger_entries == run.action_event_count
    )


def _unique_calibration_seed(
    *,
    efficiency_plan_digest: str,
    calibration_seed: int,
    scenario_id: str,
    repetition: int,
    used: set[int],
) -> int:
    for nonce in range(1_000):
        candidate = (
            int(
                stable_digest(
                    {
                        "calibration_seed": calibration_seed,
                        "efficiency_plan_digest": efficiency_plan_digest,
                        "kind": "benchmark-v4-readiness-fixture",
                        "nonce": nonce,
                        "repetition": repetition,
                        "scenario_id": scenario_id,
                    }
                )[:16],
                16,
            )
            % _SEED_LIMIT
        )
        if candidate not in used:
            used.add(candidate)
            return candidate
    raise BenchmarkV4SchemaError("readiness_fixture_seed_exhausted")


def _freeze_payload(payload: Mapping[str, Any], path: str | Path, *, differs: str) -> Path:
    destination = Path(path).resolve()
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        try:
            existing = destination.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise BenchmarkV4SchemaError("readiness_frozen_payload_read_failed") from exc
        if existing != rendered:
            raise FileExistsError(differs)
        return destination
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent), text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise
    return destination


def _load_mapping(path: str | Path, error: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BenchmarkV4SchemaError(error) from exc
    if not isinstance(payload, Mapping):
        raise BenchmarkV4SchemaError(error)
    return payload


def _methodology(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(READINESS_METHODOLOGY):
        raise BenchmarkV4SchemaError("invalid:readiness_methodology")
    normalized: dict[str, Any] = {}
    for key, expected in READINESS_METHODOLOGY.items():
        observed = value.get(key)
        if type(observed) is not type(expected):
            raise BenchmarkV4SchemaError("invalid:readiness_methodology")
        normalized[key] = observed
    return normalized


def _exact_keys(payload: Mapping[str, Any], expected: set[str], error: str) -> None:
    if set(payload) != expected:
        raise BenchmarkV4SchemaError(error)


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return value


def _sequence(value: Any, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return value


def _identifier(value: Any, name: str) -> str:
    candidate = str(value or "")
    if (
        not candidate
        or len(candidate) > 160
        or not candidate[0].isalnum()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_.:-" for character in candidate)
    ):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return candidate


def _digest(value: Any, name: str) -> str:
    candidate = str(value or "")
    if len(candidate) != 64 or any(character not in "0123456789abcdef" for character in candidate):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return candidate


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT or "\x00" in value:
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return value


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return value


def _integer_range(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    parsed = _integer(value, name)
    if not minimum <= parsed <= maximum:
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return parsed


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return float(value)


def _rate(value: Any, name: str) -> float:
    parsed = _number(value, name)
    if not 0.0 <= parsed <= 1.0:
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return parsed


def _positive_rate(value: Any, name: str) -> float:
    parsed = _rate(value, name)
    if parsed <= 0.0:
        raise BenchmarkV4SchemaError(f"invalid:{name}")
    return parsed


def _rounded(value: float) -> float:
    return round(float(value), 12)


__all__ = [
    "READINESS_EVIDENCE_SCHEMA_VERSION",
    "READINESS_METHODOLOGY",
    "READINESS_PHASE",
    "READINESS_PLAN_SCHEMA_VERSION",
    "READINESS_PROFILE_SCHEMA_VERSION",
    "BenchmarkV4ReadinessError",
    "CalibrationSummary",
    "ReadinessCheck",
    "ReadinessEvidence",
    "ReadinessPlan",
    "ReadinessProfile",
    "assert_full_campaign_ready",
    "assess_readiness",
    "build_readiness_plan",
    "freeze_readiness_evidence",
    "freeze_readiness_plan",
    "freeze_readiness_profile",
    "load_readiness_evidence",
    "load_readiness_plan",
    "load_readiness_profile",
    "validate_readiness_plan",
    "verify_readiness_evidence",
]
