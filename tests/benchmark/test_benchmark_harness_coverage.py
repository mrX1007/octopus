"""Boundary coverage for benchmark harness normalization."""

from __future__ import annotations

from pathlib import Path

import pytest

import core.benchmarks.harness as harness_module
from core.benchmarks.harness import BenchmarkHarness
from core.benchmarks.schema import load_scenario

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _scenario():
    return load_scenario(
        Path(__file__).resolve().parents[2] / "benchmarks" / "scenarios" / "01-service-discovery-verification.json"
    )


def test_runner_nonmapping_is_converted_to_failed_run():
    harness = BenchmarkHarness(lambda *_args: "bad", clock=lambda: 1.0)
    run = harness._run_once(_scenario(), repetition=1, seed=1)
    assert run.status == "failed"
    assert run.error_class == "TypeError"


def test_reported_error_class_and_recorded_timestamps_are_retained():
    harness = BenchmarkHarness(
        lambda *_args: {
            "status": "failed",
            "error_class": "Runner.Timeout",
            "started_at": 10,
            "finished_at": 12,
            "duration_seconds": 2,
        },
        clock=lambda: 99.0,
    )
    run = harness._run_once(_scenario(), repetition=1, seed=1)
    assert run.error_class == "Runner.Timeout"
    assert run.started_at == 10
    assert run.finished_at == 12
    assert run.duration_seconds == 2


def test_string_tuple_and_metadata_type_boundaries():
    assert harness_module._string_tuple("one") == ("one",)
    assert harness_module._string_tuple(1) == ()
    assert harness_module._string_tuple(["", "one", "one"]) == ("one",)

    assert harness_module._bounded_metadata(None) is None
    assert harness_module._bounded_metadata(True) is True
    assert harness_module._bounded_metadata(1) == 1
    assert harness_module._bounded_metadata(1.5) == 1.5
    assert harness_module._bounded_metadata(float("inf")) is None
    assert harness_module._bounded_metadata({1: ["x"]}) == {"1": ["x"]}
    nested = [[[[["deep"]]]]]
    assert harness_module._bounded_metadata(nested)[0][0][0][0] == "[depth-bounded]"
    value = object()
    assert harness_module._bounded_metadata(value).startswith("<object object")


def test_optional_timestamp_error_class_number_and_rate_boundaries():
    assert harness_module._optional_timestamp("bad") is None
    assert harness_module._optional_timestamp(-1) is None
    assert harness_module._optional_timestamp(1) == 1
    assert harness_module._optional_error_class(None) == ""
    assert harness_module._optional_error_class("bad value") == "InvalidRunnerErrorClass"
    assert harness_module._optional_error_class("Valid.Error") == "Valid.Error"
    assert harness_module._nonnegative_number("bad", default=2) == 2
    assert harness_module._nonnegative_number(-1) == 0
    assert harness_module._nonnegative_number(1.25) == 1.25
    assert harness_module._rate(0, 0, empty=1.0) == 1.0
    assert harness_module._rate(1, 2, empty=1.0) == 0.5
