"""Tests for enrollment build checkout service."""

from __future__ import annotations

import pytest

from core.c2.enrollment_build_checkout import (
    EnrollmentBuildCheckoutServiceV1,
)

pytestmark = pytest.mark.unit


def test_reserve_build():
    service = EnrollmentBuildCheckoutServiceV1()
    res = service.reserve_build(mission_id="m1", subject_id="s1", target_os="linux", target_arch="amd64")
    assert res.reservation_id.startswith("res_build_")
    assert res.mission_id == "m1"
    assert res.status == "reserved"


def test_checkout_build_material():
    service = EnrollmentBuildCheckoutServiceV1()
    res = service.reserve_build(mission_id="m1", subject_id="s1")

    material = service.checkout_build_material(res.reservation_id)
    assert material["reservation_id"] == res.reservation_id
    assert material["mission_id"] == "m1"
    assert "build_token" in material

    query_res = service.query_reservation(res.reservation_id)
    assert query_res is not None
    assert query_res.status == "checked_out"


def test_checkout_expired_or_missing_reservation_raises():
    service = EnrollmentBuildCheckoutServiceV1()
    with pytest.raises(KeyError, match="not found"):
        service.checkout_build_material("res_nonexistent")

    expired_res = service.reserve_build(mission_id="m1", subject_id="s1", ttl_seconds=-10.0)
    with pytest.raises(ValueError, match="expired"):
        service.checkout_build_material(expired_res.reservation_id)


def test_release_reservation():
    service = EnrollmentBuildCheckoutServiceV1()
    res = service.reserve_build(mission_id="m1", subject_id="s1")
    assert service.release_reservation(res.reservation_id) is True
    assert service.query_reservation(res.reservation_id) is None
