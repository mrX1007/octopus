"""Doctor reports rollout/readiness facts without inventing authorization."""

from __future__ import annotations

import pytest

from core.cli.doctor import render_provider_doctor, run_action_doctor

pytestmark = pytest.mark.unit


def test_doctor_reports_configured_mounted_available_separately() -> None:
    report = run_action_doctor()
    assert report.total_v2_actions == 20
    assert report.configured_count == 20
    assert report.mounted_count == 20
    assert report.available_count <= 20
    assert len(report.provider_rows) == 20
    assert all(row.configured for row in report.provider_rows)
    assert all(row.mounted for row in report.provider_rows)
    assert all(row.typed for row in report.provider_rows)
    assert not any(row.raw for row in report.provider_rows)


def test_doctor_does_not_print_authorized_without_request() -> None:
    rendered = render_provider_doctor(run_action_doctor())
    assert "Configured" in rendered
    assert "Mounted" in rendered
    assert "Available" in rendered
    assert "authorized" not in rendered.casefold()
    assert "executable" not in rendered.casefold()


def test_doctor_never_derives_mount_state_from_readiness() -> None:
    report = run_action_doctor()
    mounted_action_ids = {
        state.static.mount.spec.action_id for state in report.action_states if state.static.mount.spec.mounted
    }
    for row in report.provider_rows:
        assert row.mounted is (row.action_id in mounted_action_ids)
