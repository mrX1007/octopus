"""Action precondition evaluation and bindings for V2 actions (§2.5)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from core.actions.semantic_bindings import get_v2_semantic_binding
from core.actions.trusted_facts import (
    TrustedFactSnapshot,
    TrustedFactType,
)


class PreconditionCardinalityV2(str, Enum):
    AT_LEAST_ONE = "at_least_one"
    EACH_MATCHING_TARGET = "each_matching_target"


@dataclass(frozen=True)
class ActionPreconditionBindingV2:
    required_fact_type_id: str
    predicate_id: str
    cardinality: PreconditionCardinalityV2


@dataclass(frozen=True)
class PreconditionDecisionV2:
    satisfied: bool
    matched_fact_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]


class ActionPreconditionRegistryV2:
    def __init__(self) -> None:
        self._bindings = {
            fact_type: ActionPreconditionBindingV2(
                required_fact_type_id=fact_type.value,
                predicate_id=f"trusted_fact:{fact_type.value}:2.0",
                cardinality=PreconditionCardinalityV2.AT_LEAST_ONE,
            )
            for fact_type in TrustedFactType
        }

    def bindings(self) -> tuple[ActionPreconditionBindingV2, ...]:
        return tuple(self._bindings[fact_type] for fact_type in TrustedFactType)

    def require_binding(self, required_fact_type_id: str) -> ActionPreconditionBindingV2:
        try:
            fact_type = TrustedFactType(required_fact_type_id)
            return self._bindings[fact_type]
        except (KeyError, ValueError) as exc:
            raise KeyError(f"unknown required fact type: {required_fact_type_id}") from exc

    def evaluate_preconditions(
        self,
        action_id: str,
        facts: tuple[TrustedFactSnapshot, ...],
    ) -> PreconditionDecisionV2:
        semantic = get_v2_semantic_binding(action_id)
        required_ids = semantic.required_fact_type_ids

        if not required_ids:
            return PreconditionDecisionV2(satisfied=True, matched_fact_refs=(), reason_codes=())

        matched_refs: list[str] = []
        reasons: list[str] = []
        satisfied = True

        facts_by_type: dict[TrustedFactType, list[TrustedFactSnapshot]] = {}
        for fact in facts:
            if type(fact) is not TrustedFactSnapshot:
                raise TypeError("preconditions require exact TrustedFactSnapshot values")
            facts_by_type.setdefault(fact.fact_type, []).append(fact)

        for req_id in required_ids:
            binding = self.require_binding(req_id)
            fact_type = TrustedFactType(binding.required_fact_type_id)
            matching = facts_by_type.get(fact_type, [])
            valid_facts = [fact for fact in matching if fact.satisfies_positive_precondition]
            if not valid_facts:
                satisfied = False
                reasons.append(f"missing_required_fact:{req_id}")
            else:
                for fact in valid_facts:
                    matched_refs.append(fact.fact_ref)

        return PreconditionDecisionV2(
            satisfied=satisfied,
            matched_fact_refs=tuple(matched_refs),
            reason_codes=tuple(reasons),
        )


_GLOBAL_PRECONDITION_REGISTRY = ActionPreconditionRegistryV2()


def get_action_precondition_registry_v2() -> ActionPreconditionRegistryV2:
    return _GLOBAL_PRECONDITION_REGISTRY


__all__ = [
    "ActionPreconditionBindingV2",
    "ActionPreconditionRegistryV2",
    "PreconditionCardinalityV2",
    "PreconditionDecisionV2",
    "get_action_precondition_registry_v2",
]
