"""Non-mergeable Benchmark v3 track definitions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .schema import BenchmarkRunV3, BenchmarkV3SchemaError


class TrackIsolationError(BenchmarkV3SchemaError):
    """Raised when unlike benchmark tracks would share a leaderboard."""


@dataclass(frozen=True)
class TrackDefinition:
    track_id: str
    purpose: str
    model_policy: str
    source_access: str
    outcome_contract: str
    minimum_repetitions: int
    minimum_paired_blocks: int
    minimum_batches: int
    minimum_hosts: int
    paired_fixture_seeds: bool = True
    merge_group: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "merge_group": self.merge_group,
            "minimum_batches": self.minimum_batches,
            "minimum_hosts": self.minimum_hosts,
            "minimum_paired_blocks": self.minimum_paired_blocks,
            "minimum_repetitions": self.minimum_repetitions,
            "model_policy": self.model_policy,
            "outcome_contract": self.outcome_contract,
            "paired_fixture_seeds": self.paired_fixture_seeds,
            "purpose": self.purpose,
            "source_access": self.source_access,
            "track_id": self.track_id,
        }


TRACKS: dict[str, TrackDefinition] = {
    "small-model-stress-v3": TrackDefinition(
        track_id="small-model-stress-v3",
        purpose="Engineering robustness under an intentionally constrained small model.",
        model_policy="same_constrained_small_model_class",
        source_access="blackbox",
        outcome_contract="discovery_task",
        minimum_repetitions=12,
        minimum_paired_blocks=12,
        minimum_batches=1,
        minimum_hosts=1,
        merge_group="small-model-stress-v3-only",
    ),
    "shared-model-full-system-v1": TrackDefinition(
        track_id="shared-model-full-system-v1",
        purpose="Full-system comparison using the same externally attested model backend.",
        model_policy="identical_shared_backend_and_parameters",
        source_access="blackbox",
        outcome_contract="discovery_task",
        minimum_repetitions=12,
        minimum_paired_blocks=12,
        minimum_batches=1,
        minimum_hosts=1,
        merge_group="shared-model-full-system-v1-only",
    ),
    "vendor-native-v1": TrackDefinition(
        track_id="vendor-native-v1",
        purpose="Each system uses its recommended production model and operating mode.",
        model_policy="vendor_recommended_native",
        source_access="blackbox",
        outcome_contract="discovery_task",
        minimum_repetitions=30,
        minimum_paired_blocks=30,
        minimum_batches=2,
        minimum_hosts=2,
        merge_group="vendor-native-v1-only",
    ),
    "whitebox-v1": TrackDefinition(
        track_id="whitebox-v1",
        purpose="Source-aware systems are evaluated with explicitly declared code access.",
        model_policy="declared_per_system",
        source_access="whitebox",
        outcome_contract="source_aware_discovery",
        minimum_repetitions=12,
        minimum_paired_blocks=12,
        minimum_batches=1,
        minimum_hosts=1,
        merge_group="whitebox-v1-only",
    ),
    "ctf-v1": TrackDefinition(
        track_id="ctf-v1",
        purpose="Flag-capture and CTF-oriented systems use a flag completion contract.",
        model_policy="declared_per_system",
        source_access="challenge_defined",
        outcome_contract="flag_capture",
        minimum_repetitions=12,
        minimum_paired_blocks=12,
        minimum_batches=1,
        minimum_hosts=1,
        merge_group="ctf-v1-only",
    ),
    "octopus-ablation-v1": TrackDefinition(
        track_id="octopus-ablation-v1",
        purpose="Paired OCTOPUS retry, scoring, freshness, and resume toggle ablations.",
        model_policy="identical_within_paired_block",
        source_access="internal_ablation",
        outcome_contract="paired_ablation",
        minimum_repetitions=20,
        minimum_paired_blocks=20,
        minimum_batches=1,
        minimum_hosts=1,
        merge_group="octopus-ablation-v1-only",
    ),
}


def get_track(track_id: str) -> TrackDefinition:
    try:
        return TRACKS[str(track_id).strip().lower()]
    except KeyError:
        raise TrackIsolationError("unknown_benchmark_track") from None


def validate_single_track(
    runs_or_track_ids: Sequence[BenchmarkRunV3 | str],
) -> TrackDefinition:
    """Reject a mixed leaderboard before aggregation or publication."""

    track_ids = {
        item.track_id if isinstance(item, BenchmarkRunV3) else str(item).strip().lower() for item in runs_or_track_ids
    }
    if not track_ids:
        raise TrackIsolationError("leaderboard_requires_runs")
    if len(track_ids) != 1:
        raise TrackIsolationError("mixed_tracks_forbidden:" + ",".join(sorted(track_ids)))
    return get_track(next(iter(track_ids)))


def validate_track_design(
    track_id: str,
    *,
    repetitions: int,
    paired_blocks: int,
    batches: int,
    hosts: int,
    publication_tier: str = "full",
) -> TrackDefinition:
    """Validate frozen design minima; diagnostic/canary output is unpublished."""

    track = get_track(track_id)
    tier = str(publication_tier).strip().lower()
    if tier not in {"diagnostic", "canary", "full"}:
        raise TrackIsolationError("invalid_publication_tier")
    if tier == "diagnostic":
        if repetitions != 1:
            raise TrackIsolationError("diagnostic_requires_one_repetition")
        return track
    if tier == "canary":
        if repetitions != 2:
            raise TrackIsolationError("canary_requires_two_repetitions")
        return track
    minimums = {
        "batches": (batches, track.minimum_batches),
        "hosts": (hosts, track.minimum_hosts),
        "paired_blocks": (paired_blocks, track.minimum_paired_blocks),
        "repetitions": (repetitions, track.minimum_repetitions),
    }
    failures = [
        f"{name}:{actual}<{minimum}" for name, (actual, minimum) in sorted(minimums.items()) if actual < minimum
    ]
    if failures:
        raise TrackIsolationError("track_design_below_minimum:" + ",".join(failures))
    return track


def leaderboard_contract(track_id: str) -> dict[str, Any]:
    """Return publication metadata that makes isolation machine-checkable."""

    track = get_track(track_id)
    return {
        "automatic_cross_track_ranking": False,
        "merge_group": track.merge_group,
        "mixed_track_input": "reject",
        "track": track.to_dict(),
    }


def validate_manifest_track(payloads: Sequence[Mapping[str, Any]]) -> TrackDefinition:
    """Validate system manifests without importing the legacy manifest model."""

    return validate_single_track([str(payload.get("track_id") or payload.get("track") or "") for payload in payloads])
