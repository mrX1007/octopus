"""Public binding between readiness, full v3 evidence, and the v4 companion."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from core.benchmarks.v3 import publication as v3_publication
from core.benchmarks.v3.schema import BenchmarkV3SchemaError
from core.benchmarks.v4 import publication as v4_publication
from core.benchmarks.v4.schema import BenchmarkV4SchemaError

pytestmark = [pytest.mark.benchmark, pytest.mark.unit]

_ATTESTATION = {
    "campaign_id": "campaign-ready",
    "cleanup_attestation_digest": "1" * 64,
    "evidence_digest": "2" * 64,
    "plan_digest": "3" * 64,
    "profile_digest": "4" * 64,
    "reset_attestation_set_digest": "5" * 64,
    "source_run_digest": "6" * 64,
    "status": "ready",
}


def _context(attestation: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "campaign": {
            "campaign_id": "campaign-ready",
            "benchmark_v3": {"efficiency_plan_digest": "7" * 64},
            "benchmark_v4_readiness": {
                "plan_digest": "3" * 64,
                "profile_digest": "4" * 64,
            },
        },
        "readiness_attestation": dict(attestation or _ATTESTATION),
    }


def _run(attestation: dict[str, Any] | None = None) -> Any:
    return SimpleNamespace(
        environment={
            "efficiency_plan_digest": "7" * 64,
            "readiness_attestation": dict(attestation or _ATTESTATION),
        }
    )


def _source(context: dict[str, Any], run: Any, *, tier: str = "full") -> v4_publication.VerifiedV3Evidence:
    plan = SimpleNamespace(
        digest="8" * 64,
        publication_tier=tier,
        track_id="small-model-stress-v3",
    )
    return v4_publication.VerifiedV3Evidence(
        root=Path("."),
        source_plan=cast(Any, plan),
        runs=cast(Any, (run,)),
        controller_ledgers=(),
        campaign_context=context,
        bundle_digest="9" * 64,
        verification={},
    )


def test_exact_public_readiness_binding_propagates_to_v4_source_attestation() -> None:
    context = _context()
    run = _run()
    plan = cast(Any, SimpleNamespace(publication_tier="full"))

    v3_publication._validate_public_readiness_binding(plan, (run,), context)
    source_attestation = v4_publication._source_attestation(_source(context, run))

    assert source_attestation["schema_version"] == "1.1"
    assert source_attestation["readiness_attestation"] == _ATTESTATION


@pytest.mark.parametrize(
    "tamper",
    [
        "missing",
        "status",
        "digest",
        "campaign",
        "profile_binding",
        "run_binding",
    ],
)
def test_full_publication_rejects_missing_or_mismatched_readiness(tamper: str) -> None:
    context = _context()
    run = _run()
    if tamper == "missing":
        context.pop("readiness_attestation")
    elif tamper == "status":
        context["readiness_attestation"]["status"] = "blocked"
    elif tamper == "digest":
        context["readiness_attestation"]["evidence_digest"] = "not-a-digest"
    elif tamper == "campaign":
        context["readiness_attestation"]["campaign_id"] = "other-campaign"
    elif tamper == "profile_binding":
        context["campaign"]["benchmark_v4_readiness"]["profile_digest"] = "0" * 64
    else:
        run = _run({**_ATTESTATION, "cleanup_attestation_digest": "0" * 64})

    plan = cast(Any, SimpleNamespace(publication_tier="full"))
    with pytest.raises(BenchmarkV3SchemaError, match="v3_readiness_attestation_mismatch"):
        v3_publication._validate_public_readiness_binding(plan, (run,), context)
    with pytest.raises(BenchmarkV4SchemaError, match="v4_readiness_attestation_mismatch"):
        v4_publication._validated_public_readiness_attestation(_source(context, run))


def test_plain_v3_and_canary_v4_keep_the_legacy_attestation_shape() -> None:
    plain_context = {"campaign": {"campaign_id": "plain", "benchmark_v3": {}}}
    plain_run = SimpleNamespace(environment={})
    full_plan = cast(Any, SimpleNamespace(publication_tier="full"))
    v3_publication._validate_public_readiness_binding(full_plan, (plain_run,), plain_context)

    canary = _source(deepcopy(plain_context), plain_run, tier="canary")
    assert v4_publication._source_attestation(canary)["schema_version"] == "1.0"
    assert "readiness_attestation" not in v4_publication._source_attestation(canary)


@pytest.mark.parametrize("location", ["campaign", "context", "run"])
def test_v3_rejects_orphaned_readiness_markers_without_efficiency_binding(location: str) -> None:
    context = {"campaign": {"campaign_id": "plain", "benchmark_v3": {}}}
    run = SimpleNamespace(environment={})
    if location == "campaign":
        context["campaign"]["benchmark_v4_readiness"] = {
            "plan_digest": "3" * 64,
            "profile_digest": "4" * 64,
        }
    elif location == "context":
        context["readiness_attestation"] = dict(_ATTESTATION)
    else:
        run = SimpleNamespace(environment={"readiness_attestation": dict(_ATTESTATION)})

    full_plan = cast(Any, SimpleNamespace(publication_tier="full"))
    with pytest.raises(BenchmarkV3SchemaError, match="v3_readiness_attestation_mismatch"):
        v3_publication._validate_public_readiness_binding(full_plan, (run,), context)
