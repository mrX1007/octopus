"""Controller-only bridge between competitor campaigns and Benchmark v3.

The legacy campaign runner remains the execution transport.  This module owns
the additive v3 concerns: frozen paired seeds, private fixture state, sealed
claim evaluation, ledger-backed action telemetry, and schema-2.0 run records.
Nothing in this module rewrites schema-1.0 objects or published v1/v2 bundles.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schema import BenchmarkScenario
from ..v3.analysis import AnalysisPlan, load_analysis_plan
from ..v3.evaluation import (
    ReportedClaim,
    build_budget_enforcement,
    evaluate_claims,
    make_run,
    verified_truth_ids_from_evidence,
)
from ..v3.fixture import (
    LAB_V3_VERSION,
    SCENARIO_FAMILIES,
    FixtureVariant,
    generate_fixture_variant,
    load_private_fixture,
)
from ..v3.ledger import ControlPlaneLedger, read_ledger
from ..v3.schema import BenchmarkRunV3, BenchmarkV3SchemaError, canonical_json, stable_digest

V3_CAMPAIGN_CONFIG_SCHEMA_VERSION = "1.0"
V3_PRODUCT_CLAIM_CONTRACT = "native-final-report-claims-v1"

_CONFIG_KEYS = frozenset(
    {
        "analysis_plan",
        "batch_id",
        "host_id",
        "state_directory",
        "schema_version",
    }
)
_SAFE_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,159}$")
_V3_EVIDENCE_TOKEN = re.compile(r"^OCTOBENCH_V3_[A-Z0-9]{16,160}$")


@dataclass(frozen=True)
class BenchmarkV3CampaignConfig:
    """Private controller inputs for one additive v3 campaign."""

    analysis_plan_path: Path
    state_directory: Path
    batch_id: str
    host_id: str
    schema_version: str = V3_CAMPAIGN_CONFIG_SCHEMA_VERSION

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        base_directory: str | Path,
    ) -> BenchmarkV3CampaignConfig:
        if str(payload.get("schema_version") or "") != V3_CAMPAIGN_CONFIG_SCHEMA_VERSION:
            raise BenchmarkV3SchemaError("unsupported_v3_campaign_config_schema")
        if set(payload) - _CONFIG_KEYS:
            raise BenchmarkV3SchemaError("unknown_v3_campaign_config_key")
        base = Path(base_directory).resolve()
        analysis_plan = _resolved_path(
            payload.get("analysis_plan"),
            base=base,
            name="analysis_plan",
        )
        state_directory = _resolved_path(
            payload.get("state_directory"),
            base=base,
            name="state_directory",
        )
        return cls(
            analysis_plan_path=analysis_plan,
            state_directory=state_directory,
            batch_id=_identifier(payload.get("batch_id"), "batch_id"),
            host_id=_identifier(payload.get("host_id"), "host_id"),
        )

    def plan(self) -> AnalysisPlan:
        return load_analysis_plan(self.analysis_plan_path)

    def fingerprint_payload(self) -> dict[str, Any]:
        plan = self.plan()
        return {
            "schema_version": self.schema_version,
            "analysis_plan_digest": plan.digest,
            "batch_id": self.batch_id,
            "host_id": self.host_id,
            "track_id": plan.track_id,
        }

    def public_payload(self) -> dict[str, Any]:
        return self.fingerprint_payload()


@dataclass(frozen=True)
class V3RunArtifacts:
    run_directory: Path
    private_manifest: Path
    product_view: Path
    ledger: Path
    controller_metadata: Path


def scenario_family(scenario_id: str) -> str:
    candidate = str(scenario_id or "").strip().lower()
    for family in SCENARIO_FAMILIES:
        if candidate == f"{family.replace('_', '-')}-v3":
            return family
    raise BenchmarkV3SchemaError("unknown_v3_scenario_id")


def validate_campaign_plan(
    config: BenchmarkV3CampaignConfig,
    *,
    system_ids: Sequence[str],
    scenarios: Sequence[BenchmarkScenario],
    repetitions: int,
) -> AnalysisPlan:
    plan = config.plan()
    scenario_ids = tuple(item.scenario_id for item in scenarios)
    for scenario in scenarios:
        if str(scenario.lab.get("version") or "") != LAB_V3_VERSION:
            raise BenchmarkV3SchemaError("v3_plan_requires_v3_lab_scenarios")
        scenario_family(scenario.scenario_id)
    if tuple(system_ids) != plan.system_ids:
        raise BenchmarkV3SchemaError("v3_plan_system_mismatch")
    if scenario_ids != plan.scenario_ids:
        raise BenchmarkV3SchemaError("v3_plan_scenario_mismatch")
    if int(repetitions) != plan.repetitions:
        raise BenchmarkV3SchemaError("v3_plan_repetition_mismatch")
    return plan


def planned_fixture_seed(
    plan: AnalysisPlan,
    *,
    scenario_id: str,
    repetition: int,
) -> int:
    try:
        return int(plan.fixture_seeds[scenario_id][int(repetition) - 1])
    except (IndexError, KeyError, TypeError):
        raise BenchmarkV3SchemaError("v3_plan_schedule_mismatch") from None


def run_artifacts(
    state_directory: str | Path,
    *,
    campaign_id: str,
    system_id: str,
    scenario_id: str,
    repetition: int,
    seed: int,
) -> V3RunArtifacts:
    normalized_campaign_id = _identifier(campaign_id, "campaign_id")
    normalized_system_id = _identifier(system_id, "system_id")
    normalized_scenario_id = _identifier(scenario_id, "scenario_id")
    normalized_repetition = int(repetition)
    normalized_seed = int(seed)
    descriptor = {
        "campaign_id": normalized_campaign_id,
        "repetition": normalized_repetition,
        "scenario_id": normalized_scenario_id,
        "seed": normalized_seed,
        "system_id": normalized_system_id,
    }
    if normalized_repetition < 1 or not 0 <= normalized_seed < 2**63:
        raise BenchmarkV3SchemaError("invalid_v3_run_identity")
    digest = stable_digest(descriptor)
    root = Path(state_directory).resolve()
    directory = root / normalized_campaign_id / digest
    return V3RunArtifacts(
        run_directory=directory,
        private_manifest=directory / "private-fixture.json",
        product_view=directory / "product-view.json",
        ledger=directory / "request-ledger.jsonl",
        controller_metadata=directory / "controller-run.json",
    )


def prepare_fixture_run(
    state_directory: str | Path,
    *,
    campaign_id: str,
    system_id: str,
    scenario_id: str,
    repetition: int,
    seed: int,
    base_url: str,
) -> tuple[FixtureVariant, V3RunArtifacts]:
    """Create an idempotent private manifest and a fresh per-run ledger."""

    family = scenario_family(scenario_id)
    variant = generate_fixture_variant(family, matched_fixture_seed=int(seed))
    if variant.scenario_id != scenario_id:
        raise BenchmarkV3SchemaError("v3_fixture_scenario_mismatch")
    artifacts = run_artifacts(
        state_directory,
        campaign_id=campaign_id,
        system_id=system_id,
        scenario_id=scenario_id,
        repetition=repetition,
        seed=seed,
    )
    artifacts.run_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(artifacts.run_directory, 0o700)
    variant.write_private_manifest(artifacts.private_manifest)
    _atomic_private_json(
        artifacts.product_view,
        variant.product_view(base_url=base_url),
    )
    with suppress(FileNotFoundError):
        artifacts.ledger.unlink()
    metadata = {
        "campaign_id": campaign_id,
        "fixture_variant_digest": variant.variant_digest,
        "lab_version": variant.lab_version,
        "repetition": int(repetition),
        "scenario_id": scenario_id,
        "schema_version": "1.0",
        "system_id": system_id,
    }
    _atomic_private_json(artifacts.controller_metadata, metadata)
    return variant, artifacts


def build_v3_run(
    *,
    config: BenchmarkV3CampaignConfig,
    plan: AnalysisPlan,
    scenario: BenchmarkScenario,
    system_id: str,
    repetition: int,
    seed: int,
    result: Mapping[str, Any],
    started_at: float,
    finished_at: float,
    reset_attestation: Mapping[str, Any],
) -> BenchmarkRunV3:
    expected_seed = planned_fixture_seed(
        plan,
        scenario_id=scenario.scenario_id,
        repetition=repetition,
    )
    if int(seed) != expected_seed:
        raise BenchmarkV3SchemaError("v3_run_seed_not_in_plan")
    artifacts = run_artifacts(
        config.state_directory,
        campaign_id=str(reset_attestation.get("campaign_id") or ""),
        system_id=system_id,
        scenario_id=scenario.scenario_id,
        repetition=repetition,
        seed=seed,
    )
    variant = load_private_fixture(artifacts.private_manifest)
    if (
        variant.scenario_id != scenario.scenario_id
        or variant.matched_fixture_seed != seed
        or variant.lab_version != LAB_V3_VERSION
    ):
        raise BenchmarkV3SchemaError("v3_fixture_attestation_mismatch")
    ledger = ControlPlaneLedger(
        variant_digest=variant.variant_digest,
        path=artifacts.ledger,
        fsync=False,
    )
    snapshot = ledger.snapshot()

    execution_status = _execution_status(result.get("status"))
    reported_claims = _reported_claims(
        result.get("reported_claims") or [],
        variant=variant,
    )
    policy_violations = tuple(
        sorted(
            {
                *(_policy_identifier(item) for item in snapshot.violations),
                *(
                    _policy_identifier(item)
                    for item in result.get("policy_violations") or []
                ),
            }
            - {""}
        )
    )
    evaluation = evaluate_claims(
        execution_status=execution_status,
        reported_claims=reported_claims,
        truth_claims=variant.truth_claims,
        completion_rule=variant.completion_rule,
        observed_evidence_ids=snapshot.observed_evidence_ids,
        verified_truth_ids=verified_truth_ids_from_evidence(
            variant.truth_claims,
            snapshot.observed_evidence_ids,
        ),
        policy_violations=policy_violations,
    )

    declared_budgets = {
        str(name): value
        for name, value in scenario.budgets.items()
        if str(name).startswith("max_") and _positive_number(value)
    }
    metrics = result.get("metrics")
    usage_metrics = metrics if isinstance(metrics, Mapping) else {}
    observed_usage: dict[str, float] = {"max_seconds": float(result.get("duration_seconds") or 0.0)}
    metric_to_budget = {
        "api_cost_usd": "max_cost_usd",
        "model_tokens": "max_model_tokens",
        "output_bytes": "max_output_bytes",
        "tool_calls": "max_tools",
    }
    for metric_name, budget_name in metric_to_budget.items():
        if budget_name in declared_budgets and _nonnegative_number(usage_metrics.get(metric_name)):
            observed_usage[budget_name] = float(usage_metrics[metric_name])
    policy = scenario.budgets.get("policy")
    policy_mapping = policy if isinstance(policy, Mapping) else {}
    enforcement_modes = {
        name: _enforcement_mode(policy_mapping.get(name), measured=name in observed_usage)
        for name in declared_budgets
    }
    budgets = build_budget_enforcement(
        system_id=system_id,
        declared_budgets=declared_budgets,
        observed_usage=observed_usage,
        enforcement_modes=enforcement_modes,
    )
    duration = max(0.0, float(result.get("duration_seconds") or 0.0))
    timeout_limit = float(declared_budgets.get("max_seconds") or duration)
    artifact_refs = {
        f"sha256:{variant.variant_digest}",
        f"sha256:{snapshot.root_digest}",
        *(str(item) for item in result.get("artifact_refs") or []),
    }
    environment = {
        "analysis_plan_digest": plan.digest,
        "batch_id": config.batch_id,
        "claim_contract": V3_PRODUCT_CLAIM_CONTRACT,
        "controller_ledger_entries": snapshot.entry_count,
        "lab_version": variant.lab_version,
        "host_id": config.host_id,
        "reset_attestation": dict(reset_attestation),
        "scenario_family": variant.scenario_family,
    }
    return make_run(
        track_id=plan.track_id,
        system_id=system_id,
        scenario_id=scenario.scenario_id,
        repetition=repetition,
        execution_status=execution_status,
        evaluation=evaluation,
        matched_fixture_seed=seed,
        fixture_variant_digest=variant.variant_digest,
        applied_model_seed=None,
        model_seed_status="not_supported",
        budget_enforcement=budgets,
        action_telemetry=ledger.action_events(),
        action_telemetry_available=True,
        action_telemetry_reliability="verified",
        duration_seconds=duration,
        timeout_limit_seconds=timeout_limit,
        started_at=float(started_at),
        finished_at=float(finished_at),
        policy_violations=policy_violations,
        artifact_refs=tuple(sorted(artifact_refs)),
        environment=environment,
        error_class=str(result.get("error_class") or ""),
    )


def fixture_reveals(
    config: BenchmarkV3CampaignConfig,
    plan: AnalysisPlan,
    *,
    campaign_id: str,
) -> tuple[dict[str, Any], ...]:
    """Reveal one paired fixture variant after all campaign runs are sealed."""

    system_id = plan.system_ids[0]
    reveals: list[dict[str, Any]] = []
    for scenario_id in plan.scenario_ids:
        for repetition, seed in enumerate(plan.fixture_seeds[scenario_id], start=1):
            artifacts = run_artifacts(
                config.state_directory,
                campaign_id=campaign_id,
                system_id=system_id,
                scenario_id=scenario_id,
                repetition=repetition,
                seed=seed,
            )
            variant = load_private_fixture(artifacts.private_manifest)
            if (
                variant.scenario_id != scenario_id
                or variant.matched_fixture_seed != seed
            ):
                raise BenchmarkV3SchemaError("v3_fixture_reveal_mismatch")
            reveals.append(variant.reveal_manifest(campaign_closed=True))
    return tuple(reveals)


def controller_ledger_records(
    config: BenchmarkV3CampaignConfig,
    runs: Sequence[BenchmarkRunV3],
    *,
    campaign_id: str,
) -> tuple[dict[str, Any], ...]:
    """Return public, independently verifiable request-ledger chains per run."""

    records: list[dict[str, Any]] = []
    for run in sorted(runs, key=lambda item: item.run_id):
        artifacts = run_artifacts(
            config.state_directory,
            campaign_id=campaign_id,
            system_id=run.system_id,
            scenario_id=run.scenario_id,
            repetition=run.repetition,
            seed=run.matched_fixture_seed,
        )
        entries = read_ledger(
            artifacts.ledger,
            variant_digest=run.fixture_variant_digest,
        )
        root_digest = entries[-1].entry_digest if entries else "0" * 64
        if (
            len(entries) != len(run.action_telemetry)
            or f"sha256:{root_digest}" not in run.artifact_refs
        ):
            raise BenchmarkV3SchemaError("v3_public_ledger_run_mismatch")
        records.append(
            {
                "entries": [item.to_dict() for item in entries],
                "fixture_variant_digest": run.fixture_variant_digest,
                "ledger_root_digest": root_digest,
                "matched_fixture_seed": run.matched_fixture_seed,
                "repetition": run.repetition,
                "run_id": run.run_id,
                "scenario_id": run.scenario_id,
                "schema_version": "1.0",
                "system_id": run.system_id,
            }
        )
    return tuple(records)


def _reported_claims(
    raw_claims: Any,
    *,
    variant: FixtureVariant,
) -> tuple[ReportedClaim, ...]:
    if not isinstance(raw_claims, Sequence) or isinstance(raw_claims, (str, bytes, bytearray)):
        raise BenchmarkV3SchemaError("invalid_v3_reported_claims")
    evidence_by_alias: dict[str, tuple[str, ...]] = {}
    for truth in variant.truth_claims:
        for alias in truth.aliases:
            normalized = " ".join(alias.casefold().split())
            if _V3_EVIDENCE_TOKEN.fullmatch(alias):
                evidence_by_alias[normalized] = truth.required_evidence_ids
    claims: list[ReportedClaim] = []
    for value in raw_claims[:512]:
        text = str(value or "").strip()
        if not text:
            continue
        normalized = " ".join(text.casefold().split())
        claims.append(
            ReportedClaim(
                text=text,
                evidence_refs=evidence_by_alias.get(normalized, ()),
            )
        )
    return tuple(claims)


def _execution_status(value: Any) -> str:
    status = str(value or "failed").strip().lower()
    return {
        "cancelled": "cancelled",
        "failed": "failed",
        "invalid": "invalid",
        "partial": "failed",
        "succeeded": "succeeded",
        "timeout": "timeout",
    }.get(status, "invalid")


def _enforcement_mode(value: Any, *, measured: bool) -> str:
    candidate = str(value or "").strip().lower()
    if candidate == "hard":
        return "hard"
    if candidate in {"observational", "observed"}:
        return "observed" if measured else "advisory"
    if candidate == "advisory":
        return "advisory"
    return "none"


def _identifier(value: Any, name: str) -> str:
    candidate = str(value or "").strip().lower()
    if not _SAFE_IDENTIFIER.fullmatch(candidate):
        raise BenchmarkV3SchemaError(f"invalid:v3.{name}")
    return candidate


def _policy_identifier(value: Any) -> str:
    candidate = re.sub(r"[^a-z0-9_.:-]+", "-", str(value or "").strip().lower())
    return candidate.strip("-")[:160]


def _resolved_path(value: Any, *, base: Path, name: str) -> Path:
    candidate = str(value or "").strip()
    if not candidate or "\x00" in candidate:
        raise BenchmarkV3SchemaError(f"invalid:v3.{name}")
    return (base / candidate).resolve()


def _positive_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        candidate = float(value)
        return math.isfinite(candidate) and candidate > 0
    except (TypeError, ValueError):
        return False


def _nonnegative_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        candidate = float(value)
        return math.isfinite(candidate) and candidate >= 0
    except (TypeError, ValueError):
        return False


def _atomic_private_json(path: Path, payload: Mapping[str, Any]) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = destination.with_name(
        f".{destination.name}.tmp-{os.getpid()}-{hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:8]}"
    )
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


__all__ = [
    "V3_CAMPAIGN_CONFIG_SCHEMA_VERSION",
    "V3_PRODUCT_CLAIM_CONTRACT",
    "BenchmarkV3CampaignConfig",
    "V3RunArtifacts",
    "build_v3_run",
    "fixture_reveals",
    "planned_fixture_seed",
    "prepare_fixture_run",
    "run_artifacts",
    "scenario_family",
    "validate_campaign_plan",
]
