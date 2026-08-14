"""C2 enrollment bound configuration tests."""

from __future__ import annotations

import pytest

from core.runtime_config import C2EnrollmentBounds, load_c2_enrollment_bounds

pytestmark = pytest.mark.unit


def test_enrollment_bound_config_defaults() -> None:
    assert load_c2_enrollment_bounds(config={}, environ={}) == C2EnrollmentBounds()


def test_enrollment_bound_environment_overrides() -> None:
    bounds = load_c2_enrollment_bounds(
        config={},
        environ={
            "OCTOPUS_C2_ENROLLMENT_TTL_MIN_SECONDS": "120",
            "OCTOPUS_C2_ENROLLMENT_TTL_DEFAULT_SECONDS": "600",
            "OCTOPUS_C2_ENROLLMENT_TTL_MAX_SECONDS": "1200",
            "OCTOPUS_C2_ENROLLMENT_MAX_USES_DEFAULT": "1",
            "OCTOPUS_C2_ENROLLMENT_MAX_USES_MAX": "1",
        },
    )
    assert (bounds.ttl_min_seconds, bounds.ttl_default_seconds, bounds.ttl_max_seconds) == (120, 600, 1200)


def test_invalid_enrollment_bounds_fail_startup() -> None:
    with pytest.raises(ValueError, match="TTL bounds"):
        load_c2_enrollment_bounds(
            config={"c2": {"enrollment": {"ttl_min_seconds": 1000, "ttl_default_seconds": 100}}},
            environ={},
        )
    with pytest.raises(ValueError, match="single-use"):
        load_c2_enrollment_bounds(
            config={"c2": {"enrollment": {"max_uses_default": 2}}},
            environ={},
        )
