"""Immutable read-time view over canonical facts and their current validity."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from core.knowledge.identity import canonicalize_scope_values

EVALUATED_FACT_SNAPSHOT_SCHEMA_VERSION = "1.0"


def fact_is_decision_usable(fact: Mapping[str, Any]) -> bool:
    """Return whether a fact may support a current decision.

    Historical facts remain available to reporting and replay.  A contradicted,
    stale, or degraded observation cannot close a current stage/capability gate.
    Unknown freshness is retained for compatibility when no execution outcome
    exists; a timeout is represented separately as degraded coverage and is
    therefore excluded without being converted into negative evidence.
    """

    assessment = fact.get("assessment")
    assessment = assessment if isinstance(assessment, Mapping) else {}
    assessment_status = str(
        assessment.get("status") or fact.get("assessment_status") or "observed"
    ).strip().casefold()
    freshness_status = str(fact.get("freshness_status") or "").strip().casefold()
    coverage_status = str(fact.get("coverage_status") or "").strip().casefold()
    return (
        assessment_status != "contradicted"
        and freshness_status != "stale"
        and coverage_status != "degraded"
    )


@dataclass(frozen=True)
class EvaluatedFact:
    """One immutable serialized fact inside an evaluated snapshot."""

    fact_id: int | None
    assessment_id: str
    assessment_status: str
    freshness_status: str
    coverage_status: str
    decision_usable: bool
    payload_json: str

    @classmethod
    def from_mapping(cls, fact: Mapping[str, Any]) -> EvaluatedFact:
        payload = dict(fact)
        assessment = payload.get("assessment")
        assessment = assessment if isinstance(assessment, Mapping) else {}
        raw_id = payload.get("id")
        try:
            fact_id = int(raw_id) if raw_id is not None else None
        except (TypeError, ValueError):
            fact_id = None
        return cls(
            fact_id=fact_id,
            assessment_id=str(
                assessment.get("assessment_id") or payload.get("assessment_id") or ""
            ),
            assessment_status=str(
                assessment.get("status")
                or payload.get("assessment_status")
                or "observed"
            ).strip().casefold(),
            freshness_status=str(payload.get("freshness_status") or "unknown")
            .strip()
            .casefold(),
            coverage_status=str(payload.get("coverage_status") or "unknown")
            .strip()
            .casefold(),
            decision_usable=fact_is_decision_usable(payload),
            payload_json=json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.payload_json)


@dataclass(frozen=True)
class EvaluatedFactSnapshot:
    """One coherent fact/assessment/freshness view for downstream consumers."""

    scan_id: str
    canonical_scope: tuple[str, ...]
    evaluated_at: float
    freshness_policy_version: str
    coverage_status: str
    facts: tuple[EvaluatedFact, ...]
    supporting_execution_ids: tuple[str, ...]
    source_identities: tuple[str, ...]
    observation_methods: tuple[str, ...]
    snapshot_ref: str
    schema_version: str = EVALUATED_FACT_SNAPSHOT_SCHEMA_VERSION

    @classmethod
    def build(
        cls,
        scan_id: str,
        scope: str | Iterable[str],
        facts: Iterable[Mapping[str, Any]],
        *,
        evaluated_at: float | None = None,
    ) -> EvaluatedFactSnapshot:
        fact_items = tuple(
            EvaluatedFact.from_mapping(item)
            for item in facts
            if isinstance(item, Mapping)
        )
        fact_dicts = tuple(item.to_dict() for item in fact_items)
        scope_items = (scope,) if isinstance(scope, str) else tuple(scope)
        canonical_scope = canonicalize_scope_values(scope_items)
        evaluation_times: list[float] = []
        for fact in fact_dicts:
            freshness = fact.get("freshness")
            if not isinstance(freshness, Mapping):
                continue
            timestamp = _finite_number(freshness.get("evaluated_at"))
            if timestamp is not None:
                evaluation_times.append(timestamp)
        snapshot_time = float(
            evaluated_at
            if evaluated_at is not None
            else (max(evaluation_times) if evaluation_times else time.time())
        )
        policy_versions = {
            str((fact.get("freshness") or {}).get("policy_version") or "").strip()
            for fact in fact_dicts
            if isinstance(fact.get("freshness"), Mapping)
        }
        policy_versions.discard("")
        freshness_policy_version = (
            next(iter(policy_versions))
            if len(policy_versions) == 1
            else ("mixed" if policy_versions else "unknown")
        )
        coverage_states = {item.coverage_status for item in fact_items}
        if "degraded" in coverage_states:
            coverage_status = "degraded"
        elif coverage_states and coverage_states == {"complete"}:
            coverage_status = "complete"
        else:
            coverage_status = "unknown"

        execution_ids: set[str] = set()
        source_identities: set[str] = set()
        observation_methods: set[str] = set()
        for fact in fact_dicts:
            assessment = fact.get("assessment")
            assessment = assessment if isinstance(assessment, Mapping) else {}
            execution_ids.update(
                str(item).strip()
                for item in assessment.get("source_execution_ids") or ()
                if str(item).strip()
            )
            observation_provenance = False
            for observation in fact.get("observations") or ():
                if not isinstance(observation, Mapping):
                    continue
                identity = _provenance_token(
                    observation.get("source_identity")
                ) or _source_identity(
                    observation.get("source")
                )
                method = _provenance_token(observation.get("observation_method"))
                if identity:
                    observation_provenance = True
                    source_identities.add(identity)
                if method:
                    observation_provenance = True
                    observation_methods.add(method)
                elif identity:
                    observation_methods.add(_observation_method(identity))
            if not observation_provenance:
                sources = list(fact.get("sources") or ())
                if fact.get("source"):
                    sources.append(fact["source"])
                for source in sources:
                    identity = _source_identity(source)
                    if identity:
                        source_identities.add(identity)
                        observation_methods.add(_observation_method(identity))

        digest_payload = {
            "schema_version": EVALUATED_FACT_SNAPSHOT_SCHEMA_VERSION,
            "scan_id": str(scan_id),
            "canonical_scope": canonical_scope,
            "evaluated_at": snapshot_time,
            "freshness_policy_version": freshness_policy_version,
            "facts": [item.payload_json for item in fact_items],
        }
        digest = hashlib.sha256(
            json.dumps(
                digest_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        return cls(
            scan_id=str(scan_id),
            canonical_scope=canonical_scope,
            evaluated_at=snapshot_time,
            freshness_policy_version=freshness_policy_version,
            coverage_status=coverage_status,
            facts=fact_items,
            supporting_execution_ids=tuple(sorted(execution_ids)),
            source_identities=tuple(sorted(source_identities)),
            observation_methods=tuple(sorted(observation_methods)),
            snapshot_ref=f"evaluated-facts://sha256/{digest}",
        )

    def historical_facts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.to_dict() for item in self.facts)

    def decision_facts(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.to_dict() for item in self.facts if item.decision_usable)

    def to_context(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "snapshot_ref": self.snapshot_ref,
            "scan_id": self.scan_id,
            "canonical_scope": list(self.canonical_scope),
            "evaluated_at": self.evaluated_at,
            "freshness_policy_version": self.freshness_policy_version,
            "coverage_status": self.coverage_status,
            "historical_fact_count": len(self.facts),
            "decision_fact_count": sum(item.decision_usable for item in self.facts),
            "assessment_heads": [
                {
                    "fact_id": item.fact_id,
                    "assessment_id": item.assessment_id,
                    "status": item.assessment_status,
                    "freshness_status": item.freshness_status,
                    "coverage_status": item.coverage_status,
                    "decision_usable": item.decision_usable,
                }
                for item in self.facts
            ],
            "supporting_execution_ids": list(self.supporting_execution_ids),
            "source_identities": list(self.source_identities),
            "observation_methods": list(self.observation_methods),
        }

    def to_payload(self) -> dict[str, Any]:
        """Serialize the complete content-addressed snapshot for durable use."""

        return {
            "schema_version": self.schema_version,
            "snapshot_ref": self.snapshot_ref,
            "scan_id": self.scan_id,
            "canonical_scope": list(self.canonical_scope),
            "evaluated_at": self.evaluated_at,
            "freshness_policy_version": self.freshness_policy_version,
            "coverage_status": self.coverage_status,
            "facts": list(self.historical_facts()),
            "supporting_execution_ids": list(self.supporting_execution_ids),
            "source_identities": list(self.source_identities),
            "observation_methods": list(self.observation_methods),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> EvaluatedFactSnapshot:
        """Restore and integrity-check a durable snapshot payload."""

        if not isinstance(payload, Mapping):
            raise ValueError("evaluated fact snapshot payload must be an object")
        schema_version = str(payload.get("schema_version") or "")
        if schema_version != EVALUATED_FACT_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported evaluated fact snapshot schema: {schema_version!r}"
            )
        scope = payload.get("canonical_scope")
        facts = payload.get("facts")
        if not isinstance(scope, (list, tuple)) or not isinstance(facts, (list, tuple)):
            raise ValueError("evaluated fact snapshot scope and facts must be arrays")
        if any(not isinstance(item, Mapping) for item in facts):
            raise ValueError("evaluated fact snapshot facts must be objects")
        snapshot = cls.build(
            str(payload.get("scan_id") or ""),
            tuple(str(item) for item in scope),
            tuple(dict(item) for item in facts),
            evaluated_at=_finite_number(payload.get("evaluated_at")),
        )
        expected_ref = str(payload.get("snapshot_ref") or "")
        if not expected_ref or snapshot.snapshot_ref != expected_ref:
            raise ValueError("evaluated fact snapshot integrity check failed")
        declared = {
            "freshness_policy_version": snapshot.freshness_policy_version,
            "coverage_status": snapshot.coverage_status,
            "supporting_execution_ids": list(snapshot.supporting_execution_ids),
            "source_identities": list(snapshot.source_identities),
            "observation_methods": list(snapshot.observation_methods),
        }
        if any(payload.get(key) != value for key, value in declared.items()):
            raise ValueError("evaluated fact snapshot derived metadata does not match")
        return snapshot


def _finite_number(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 and parsed not in {float("inf"), float("-inf")} else None


def _source_identity(value: Any) -> str:
    text = str(value or "").strip().casefold()
    if not text:
        return ""
    first = re.split(r"\s+", text, maxsplit=1)[0]
    return re.sub(r"[^a-z0-9_.:/-]+", "_", first).strip("_")


def _provenance_token(value: Any) -> str:
    text = str(value or "").strip().casefold()
    return re.sub(r"[^a-z0-9_.:/-]+", "_", text).strip("_")


def _observation_method(source_identity: str) -> str:
    value = source_identity.casefold()
    if any(marker in value for marker in ("check", "verify")):
        return "verification_check"
    if any(marker in value for marker in ("browser", "curl", "http", "web")):
        return "application_observation"
    if any(marker in value for marker in ("nmap", "scan", "probe")):
        return "network_observation"
    if any(marker in value for marker in ("inventory", "session", "ssh")):
        return "authenticated_observation"
    return "reported_observation"


__all__ = [
    "EVALUATED_FACT_SNAPSHOT_SCHEMA_VERSION",
    "EvaluatedFact",
    "EvaluatedFactSnapshot",
    "fact_is_decision_usable",
]
