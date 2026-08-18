"""C2 enrollment bound configuration tests."""

from __future__ import annotations

import pytest

import core.runtime_config as rc
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

    # Non-integer bound
    with pytest.raises(ValueError, match="integers"):
        C2EnrollmentBounds(ttl_min_seconds="not an int")  # type: ignore[arg-type]

    # Exceeds safety bound
    with pytest.raises(ValueError, match="hard safety bound"):
        C2EnrollmentBounds(ttl_max_seconds=100_000)

    # c2.enrollment not a mapping
    with pytest.raises(ValueError, match="must be a mapping"):
        load_c2_enrollment_bounds(config={"c2": {"enrollment": "invalid"}}, environ={})

    # _strict_config_int with invalid value
    with pytest.raises(ValueError, match="bounded integer"):
        rc._strict_config_int("not_a_number", key="test_key")

    # config=None default
    b = load_c2_enrollment_bounds(config=None, environ={})
    assert isinstance(b, C2EnrollmentBounds)
