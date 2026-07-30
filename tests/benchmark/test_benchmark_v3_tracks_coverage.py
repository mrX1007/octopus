"""Complete branch coverage for Benchmark v3 track isolation rules."""

from __future__ import annotations

import pytest

from core.benchmarks.v3 import tracks

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def test_track_lookup_serialization_and_leaderboard_contract() -> None:
    track = tracks.get_track("  SMALL-MODEL-STRESS-V3  ")
    serialized = track.to_dict()
    assert serialized["track_id"] == "small-model-stress-v3"
    assert serialized["minimum_repetitions"] == 12

    contract = tracks.leaderboard_contract(track.track_id)
    assert contract == {
        "automatic_cross_track_ranking": False,
        "merge_group": "small-model-stress-v3-only",
        "mixed_track_input": "reject",
        "track": serialized,
    }

    with pytest.raises(tracks.TrackIsolationError, match="unknown_benchmark_track"):
        tracks.get_track("missing-track")


def test_single_track_and_manifest_validation() -> None:
    with pytest.raises(tracks.TrackIsolationError, match="leaderboard_requires_runs"):
        tracks.validate_single_track(())
    with pytest.raises(tracks.TrackIsolationError, match="mixed_tracks_forbidden"):
        tracks.validate_single_track(
            ("small-model-stress-v3", "vendor-native-v1"),
        )

    expected = tracks.get_track("small-model-stress-v3")
    assert tracks.validate_single_track(("SMALL-MODEL-STRESS-V3",)) == expected
    assert (
        tracks.validate_manifest_track(
            (
                {"track": "small-model-stress-v3"},
                {"track_id": "small-model-stress-v3"},
            ),
        )
        == expected
    )


def test_diagnostic_and_canary_track_design_rules() -> None:
    track_id = "small-model-stress-v3"
    common = {"paired_blocks": 0, "batches": 0, "hosts": 0}

    with pytest.raises(tracks.TrackIsolationError, match="invalid_publication_tier"):
        tracks.validate_track_design(
            track_id,
            repetitions=1,
            publication_tier="unknown",
            **common,
        )
    with pytest.raises(
        tracks.TrackIsolationError,
        match="diagnostic_requires_one_repetition",
    ):
        tracks.validate_track_design(
            track_id,
            repetitions=2,
            publication_tier="diagnostic",
            **common,
        )
    assert (
        tracks.validate_track_design(
            track_id,
            repetitions=1,
            publication_tier="diagnostic",
            **common,
        ).track_id
        == track_id
    )

    with pytest.raises(
        tracks.TrackIsolationError,
        match="canary_requires_two_repetitions",
    ):
        tracks.validate_track_design(
            track_id,
            repetitions=1,
            publication_tier="canary",
            **common,
        )
    assert (
        tracks.validate_track_design(
            track_id,
            repetitions=2,
            publication_tier="canary",
            **common,
        ).track_id
        == track_id
    )


def test_full_track_design_reports_all_minima_and_accepts_exact_design() -> None:
    track = tracks.get_track("small-model-stress-v3")
    with pytest.raises(
        tracks.TrackIsolationError,
        match="track_design_below_minimum",
    ) as exc_info:
        tracks.validate_track_design(
            track.track_id,
            repetitions=0,
            paired_blocks=0,
            batches=0,
            hosts=0,
            publication_tier="full",
        )
    assert str(exc_info.value) == (
        "track_design_below_minimum:batches:0<1,hosts:0<1,paired_blocks:0<12,repetitions:0<12"
    )

    assert (
        tracks.validate_track_design(
            track.track_id,
            repetitions=track.minimum_repetitions,
            paired_blocks=track.minimum_paired_blocks,
            batches=track.minimum_batches,
            hosts=track.minimum_hosts,
            publication_tier="full",
        )
        == track
    )
