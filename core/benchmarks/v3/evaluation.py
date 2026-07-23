"""Sealed truth evaluation and run construction for Benchmark v3."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .schema import (
    EXECUTION_STATUSES,
    ActionEvent,
    BenchmarkRunV3,
    BenchmarkV3SchemaError,
    BudgetEnforcement,
    ClaimAssessment,
    MetricObservation,
    RunEvaluation,
    stable_digest,
    validate_budget_enforcement,
)

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class TruthClaim:
    """Private matcher and evidence contract for one expected claim."""

    truth_id: str
    canonical_text: str
    aliases: tuple[str, ...] = ()
    required_evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "aliases", tuple(self.aliases))
        object.__setattr__(
            self,
            "required_evidence_ids",
            tuple(self.required_evidence_ids),
        )
        _safe_identifier(self.truth_id, "truth_id")
        if not _normalize_text(self.canonical_text):
            raise BenchmarkV3SchemaError("invalid:truth.canonical_text")
        if any(not _normalize_text(item) for item in self.aliases):
            raise BenchmarkV3SchemaError("invalid:truth.alias")
        for evidence_id in self.required_evidence_ids:
            _safe_identifier(evidence_id, "truth.required_evidence_id")

    def to_private_dict(self) -> dict[str, Any]:
        return {
            "aliases": list(self.aliases),
            "canonical_text": self.canonical_text,
            "required_evidence_ids": list(self.required_evidence_ids),
            "truth_id": self.truth_id,
        }


@dataclass(frozen=True)
class ReportedClaim:
    """One claim emitted by a product, before private-truth evaluation."""

    text: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        if not self.text.strip() or len(self.text.encode("utf-8")) > 16_384:
            raise BenchmarkV3SchemaError("invalid:reported_claim.text")
        for item in self.evidence_refs:
            _safe_identifier(item, "reported_claim.evidence_ref")

    @classmethod
    def from_value(cls, value: str | Mapping[str, Any]) -> ReportedClaim:
        if isinstance(value, Mapping):
            text = str(value.get("text") or value.get("claim") or "").strip()
            raw_refs = value.get("evidence_refs") or []
            if not isinstance(raw_refs, Sequence) or isinstance(raw_refs, (str, bytes, bytearray)):
                raise BenchmarkV3SchemaError("invalid:reported_claim.evidence_refs")
            refs = tuple(str(item).strip().lower() for item in raw_refs if str(item).strip())
        else:
            text = str(value).strip()
            refs = ()
        if not text or len(text.encode("utf-8")) > 16_384:
            raise BenchmarkV3SchemaError("invalid:reported_claim.text")
        for item in refs:
            _safe_identifier(item, "reported_claim.evidence_ref")
        return cls(text=text, evidence_refs=refs)


@dataclass(frozen=True)
class CompletionRule:
    """Frozen task-completion semantics for one scenario."""

    rule_id: str
    required_truth_ids: tuple[str, ...]
    minimum_verified_recall: float = 1.0
    reject_unsupported_claims: bool = True
    allow_policy_violations: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "required_truth_ids", tuple(self.required_truth_ids))
        _safe_identifier(self.rule_id, "completion_rule.rule_id")
        for truth_id in self.required_truth_ids:
            _safe_identifier(truth_id, "completion_rule.required_truth_id")
        if len(set(self.required_truth_ids)) != len(self.required_truth_ids):
            raise BenchmarkV3SchemaError("duplicate_completion_truth_id")
        if not 0.0 <= float(self.minimum_verified_recall) <= 1.0:
            raise BenchmarkV3SchemaError("invalid:minimum_verified_recall")

    def to_private_dict(self) -> dict[str, Any]:
        return {
            "allow_policy_violations": self.allow_policy_violations,
            "minimum_verified_recall": self.minimum_verified_recall,
            "reject_unsupported_claims": self.reject_unsupported_claims,
            "required_truth_ids": list(self.required_truth_ids),
            "rule_id": self.rule_id,
        }


def evaluate_claims(
    *,
    execution_status: str,
    reported_claims: Sequence[str | Mapping[str, Any] | ReportedClaim],
    truth_claims: Sequence[TruthClaim],
    completion_rule: CompletionRule,
    observed_evidence_ids: Sequence[str] = (),
    verified_truth_ids: Sequence[str] = (),
    policy_violations: Sequence[str] = (),
    evaluator_id: str = "sealed-evaluator-v3",
) -> RunEvaluation:
    """Evaluate every reported claim, including arbitrary hallucinations.

    Matching is intentionally exact after Unicode-preserving case/whitespace
    normalization.  Unknown text receives a deterministic ``unmatched:`` ID
    and remains in the precision denominator.  Products never need access to
    this private matcher table.
    """

    if execution_status not in EXECUTION_STATUSES:
        raise BenchmarkV3SchemaError("invalid:execution_status")
    truths = tuple(truth_claims)
    truth_by_id = {item.truth_id: item for item in truths}
    if len(truth_by_id) != len(truths):
        raise BenchmarkV3SchemaError("duplicate_truth_id")
    unknown_required = set(completion_rule.required_truth_ids) - set(truth_by_id)
    if unknown_required:
        raise BenchmarkV3SchemaError("completion_rule_unknown_truth_id")
    explicit_verified = {str(item).strip().lower() for item in verified_truth_ids}
    if explicit_verified - set(truth_by_id):
        raise BenchmarkV3SchemaError("verified_unknown_truth_id")
    observed = {str(item).strip().lower() for item in observed_evidence_ids}
    for item in observed:
        _safe_identifier(item, "observed_evidence_id")

    matcher: dict[str, tuple[str, str]] = {}
    for truth in truths:
        candidates = (
            (truth.truth_id, "truth_id"),
            (truth.canonical_text, "canonical"),
            *((alias, "alias") for alias in truth.aliases),
        )
        for candidate, kind in candidates:
            normalized = _normalize_text(candidate)
            existing = matcher.get(normalized)
            if existing is not None and existing[0] != truth.truth_id:
                raise BenchmarkV3SchemaError("ambiguous_truth_matcher")
            matcher[normalized] = (truth.truth_id, kind)

    assessments: list[ClaimAssessment] = []
    matched_truth_ids: set[str] = set()
    verified_matches: set[str] = set()
    for index, raw in enumerate(reported_claims):
        claim = raw if isinstance(raw, ReportedClaim) else ReportedClaim.from_value(raw)
        normalized_text = _normalize_text(claim.text)
        match = matcher.get(normalized_text)
        claim_digest = hashlib.sha256(f"{index}\0{normalized_text}".encode()).hexdigest()[:24]
        if match is None:
            normalized_claim_id = "unmatched:" + hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()[:24]
            assessments.append(
                ClaimAssessment(
                    claim_id=f"claim-{index + 1}-{claim_digest[:10]}",
                    text=claim.text,
                    normalized_claim_id=normalized_claim_id,
                    matcher_kind="unmatched",
                    evidence_refs=claim.evidence_refs,
                )
            )
            continue
        truth_id, matcher_kind = match
        truth = truth_by_id[truth_id]
        required_evidence = set(truth.required_evidence_ids)
        evidence_verified = bool(required_evidence) and required_evidence <= (set(claim.evidence_refs) & observed)
        verified = truth_id in explicit_verified or evidence_verified
        matched_truth_ids.add(truth_id)
        if verified:
            verified_matches.add(truth_id)
        assessments.append(
            ClaimAssessment(
                claim_id=f"claim-{index + 1}-{claim_digest[:10]}",
                text=claim.text,
                normalized_claim_id=truth_id,
                matched_truth_id=truth_id,
                supported=True,
                verified=verified,
                matcher_kind=matcher_kind,
                evidence_refs=claim.evidence_refs,
            )
        )

    total_truth = len(truths)
    total_claims = len(assessments)
    supported_claims = sum(item.supported for item in assessments)
    verified_claims = sum(item.verified for item in assessments)
    reported_recall = _rate(len(matched_truth_ids), total_truth, empty=1.0)
    verified_recall = _rate(len(verified_matches), total_truth, empty=1.0)
    full_precision = _rate(supported_claims, total_claims, empty=1.0)
    verified_precision = _rate(verified_claims, total_claims, empty=1.0)

    required_verified = set(completion_rule.required_truth_ids) <= verified_matches
    no_unsupported = not any(not item.supported for item in assessments)
    threshold_met = verified_recall >= completion_rule.minimum_verified_recall
    policy_ok = completion_rule.allow_policy_violations or not policy_violations
    if not policy_ok or execution_status == "invalid":
        task_status = "invalid"
    elif (
        execution_status == "succeeded"
        and required_verified
        and threshold_met
        and (no_unsupported or not completion_rule.reject_unsupported_claims)
    ):
        task_status = "completed"
    elif matched_truth_ids or verified_matches:
        task_status = "partial"
    else:
        task_status = "not_completed"

    metrics: list[MetricObservation] = []
    metric_values = (
        ("reported_recall", reported_recall, len(matched_truth_ids), total_truth),
        ("verified_recall", verified_recall, len(verified_matches), total_truth),
        ("full_claim_precision", full_precision, supported_claims, total_claims),
        (
            "verified_claim_precision",
            verified_precision,
            verified_claims,
            total_claims,
        ),
    )
    for name, value, numerator, denominator in metric_values:
        reliability = "verified" if "verified" in name else "derived"
        metrics.append(
            MetricObservation(
                name=name,
                population="all_scheduled",
                available=True,
                reliability=reliability,
                value=value,
                numerator=numerator,
                denominator=denominator,
            )
        )
        if execution_status == "succeeded":
            metrics.append(
                MetricObservation(
                    name=name,
                    population="completion_conditional",
                    available=True,
                    reliability=reliability,
                    value=value,
                    numerator=numerator,
                    denominator=denominator,
                )
            )
        else:
            metrics.append(
                MetricObservation.unavailable(
                    name,
                    "completion_conditional",
                    "execution_did_not_complete",
                )
            )
    return RunEvaluation(
        task_status=task_status,
        completion_rule_id=completion_rule.rule_id,
        metrics=tuple(metrics),
        claims=tuple(assessments),
        evaluator_id=evaluator_id,
    )


def verified_truth_ids_from_evidence(
    truth_claims: Sequence[TruthClaim],
    observed_evidence_ids: Sequence[str],
) -> tuple[str, ...]:
    """Resolve controller-ledger observations without exposing IDs to a product."""

    observed = {str(item).strip().lower() for item in observed_evidence_ids}
    for item in observed:
        _safe_identifier(item, "observed_evidence_id")
    verified = {
        truth.truth_id
        for truth in truth_claims
        if truth.required_evidence_ids and set(truth.required_evidence_ids) <= observed
    }
    return tuple(sorted(verified))


def build_budget_enforcement(
    *,
    system_id: str,
    declared_budgets: Mapping[str, Any],
    observed_usage: Mapping[str, Any],
    enforcement_modes: Mapping[str, str],
    units: Mapping[str, str] | None = None,
    evidence_refs: Mapping[str, Sequence[str]] | None = None,
) -> tuple[BudgetEnforcement, ...]:
    """Build a complete, auditable budget table for one system/run."""

    unit_overrides = units or {}
    references = evidence_refs or {}
    records: list[BudgetEnforcement] = []
    if set(enforcement_modes) != set(declared_budgets):
        raise BenchmarkV3SchemaError("budget_enforcement_modes_incomplete")
    unknown_usage = set(observed_usage) - set(declared_budgets)
    if unknown_usage:
        raise BenchmarkV3SchemaError("observed_unknown_budget")
    for name in sorted(declared_budgets):
        try:
            limit = float(declared_budgets[name])
        except (TypeError, ValueError):
            raise BenchmarkV3SchemaError("invalid:declared_budget") from None
        raw_measured = observed_usage.get(name)
        measured = float(raw_measured) if raw_measured is not None else None
        mode = str(enforcement_modes[name])
        reliable = mode in {"hard", "observed"} and measured is not None
        records.append(
            BudgetEnforcement(
                system_id=system_id,
                budget_name=name,
                limit=limit,
                unit=str(unit_overrides.get(name) or _budget_unit(name)),
                enforcement_mode=mode,
                measured=measured,
                exceeded=measured > limit if measured is not None else None,
                reliable=reliable,
                evidence_refs=tuple(references.get(name) or ()),
                note=("" if reliable else "usage_or_enforcement_not_independently_verified"),
            )
        )
    return validate_budget_enforcement(
        system_id=system_id,
        declared_budgets=declared_budgets,
        enforcement=records,
    )


def make_run(
    *,
    track_id: str,
    system_id: str,
    scenario_id: str,
    repetition: int,
    execution_status: str,
    evaluation: RunEvaluation,
    matched_fixture_seed: int,
    fixture_variant_digest: str,
    applied_model_seed: int | None,
    model_seed_status: str,
    budget_enforcement: Sequence[BudgetEnforcement],
    action_telemetry: Sequence[ActionEvent],
    action_telemetry_available: bool,
    action_telemetry_reliability: str,
    duration_seconds: float,
    timeout_limit_seconds: float | None,
    started_at: float,
    finished_at: float,
    policy_violations: Sequence[str] = (),
    artifact_refs: Sequence[str] = (),
    model_seed_evidence: Sequence[str] = (),
    environment: Mapping[str, Any] | None = None,
    error_class: str = "",
) -> BenchmarkRunV3:
    """Construct a stable v3 run ID after evaluation and attestations exist."""

    duration_censored = execution_status == "timeout" or evaluation.task_status != "completed"
    censor_limit = (
        max(float(duration_seconds), float(timeout_limit_seconds or duration_seconds)) if duration_censored else None
    )
    identity = {
        "fixture_variant_digest": fixture_variant_digest,
        "matched_fixture_seed": matched_fixture_seed,
        "repetition": repetition,
        "scenario_id": scenario_id,
        "system_id": system_id,
        "track_id": track_id,
    }
    run_id = "run-" + stable_digest(identity)[:32]
    return BenchmarkRunV3(
        run_id=run_id,
        track_id=track_id,
        system_id=system_id,
        scenario_id=scenario_id,
        repetition=repetition,
        execution_status=execution_status,
        evaluation=evaluation,
        matched_fixture_seed=matched_fixture_seed,
        fixture_variant_digest=fixture_variant_digest,
        applied_model_seed=applied_model_seed,
        model_seed_status=model_seed_status,
        budget_enforcement=tuple(budget_enforcement),
        action_telemetry=tuple(action_telemetry),
        action_telemetry_available=action_telemetry_available,
        action_telemetry_reliability=action_telemetry_reliability,
        duration_seconds=duration_seconds,
        duration_censored=duration_censored,
        censor_limit_seconds=censor_limit,
        started_at=started_at,
        finished_at=finished_at,
        policy_violations=tuple(policy_violations),
        artifact_refs=tuple(artifact_refs),
        model_seed_evidence=tuple(model_seed_evidence),
        environment=dict(environment or {}),
        error_class=error_class,
    )


def _normalize_text(value: str) -> str:
    return _WHITESPACE.sub(" ", str(value).strip().casefold())


def _safe_identifier(value: str, name: str) -> str:
    text = str(value).strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,159}", text):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    return text


def _rate(numerator: int, denominator: int, *, empty: float) -> float:
    if denominator == 0:
        return float(empty)
    return float(numerator) / float(denominator)


def _budget_unit(name: str) -> str:
    if name.endswith("_seconds"):
        return "seconds"
    if name.endswith("_bytes"):
        return "bytes"
    if name.endswith("_tokens"):
        return "tokens"
    if name.endswith("_usd"):
        return "usd"
    return "count"
