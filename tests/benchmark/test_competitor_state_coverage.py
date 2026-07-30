"""Complete failure and persistence coverage for competitor campaign state."""

from __future__ import annotations

import builtins
import json
import runpy

import pytest

import core.benchmarks.competitors.state as state_module
from core.benchmarks.competitors.state import (
    CAMPAIGN_STATE_SCHEMA_VERSION,
    CampaignFingerprintMismatch,
    CampaignJournal,
    CampaignLockedError,
    CampaignStateError,
    campaign_fingerprint,
    schedule_run_key,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _journal(tmp_path, *, campaign_id="campaign", payload=None):
    return CampaignJournal(
        tmp_path,
        campaign_id=campaign_id,
        fingerprint=campaign_fingerprint(payload or {"input": "one"}),
    )


def _schedule(system="system"):
    key = schedule_run_key(system, "scenario", 1, 2)
    return key, [{"run_key": key, "system_id": system}]


def test_import_fallback_marks_locking_unsupported(monkeypatch) -> None:
    real_import = builtins.__import__

    def import_without_fcntl(name, *args, **kwargs):
        if name == "fcntl":
            raise ImportError("unsupported platform")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_fcntl)
    namespace = runpy.run_path(
        state_module.__file__,
        run_name="competitor_state_without_fcntl",
    )

    assert namespace["fcntl"] is None


def test_constructor_identifiers_fingerprint_and_diagnostics(tmp_path):
    journal = _journal(tmp_path, campaign_id=" Campaign.ONE ")
    assert journal.campaign_id == "campaign.one"
    assert journal.diagnostics_directory == tmp_path / "campaign.one" / "diagnostics"

    with pytest.raises(CampaignStateError, match="invalid_campaign_fingerprint"):
        CampaignJournal(tmp_path, campaign_id="ok", fingerprint="bad")
    for value in ("", ".hidden", "bad value", "x" * 129):
        with pytest.raises(CampaignStateError, match="invalid_campaign_id"):
            CampaignJournal(
                tmp_path,
                campaign_id=value,
                fingerprint=campaign_fingerprint({}),
            )


def test_lock_unsupported_contention_and_success_paths(tmp_path, monkeypatch):
    journal = _journal(tmp_path)
    monkeypatch.setattr(state_module, "fcntl", None)
    with pytest.raises(CampaignStateError, match="campaign_lock_unsupported"), journal.lock():
        pass

    class FcntlDouble:
        LOCK_EX = 1
        LOCK_NB = 2
        LOCK_UN = 4

        def __init__(self, fail=False):
            self.fail = fail
            self.calls = []

        def flock(self, descriptor, operation):
            self.calls.append((descriptor, operation))
            if self.fail and operation != self.LOCK_UN:
                raise BlockingIOError

    blocked = FcntlDouble(fail=True)
    monkeypatch.setattr(state_module, "fcntl", blocked)
    with pytest.raises(CampaignLockedError, match="campaign_locked"), journal.lock():
        pass

    available = FcntlDouble()
    monkeypatch.setattr(state_module, "fcntl", available)
    with journal.lock():
        assert journal.campaign_root.exists()
    assert [operation for _descriptor, operation in available.calls] == [3, 4]


def test_initialize_rejects_invalid_duplicate_and_changed_schedules(tmp_path):
    journal = _journal(tmp_path)
    with pytest.raises(CampaignStateError, match="invalid_campaign_schedule"):
        journal.initialize([])
    with pytest.raises(CampaignStateError, match="invalid_campaign_schedule"):
        journal.initialize([{"run_key": "bad"}])
    key, schedule = _schedule()
    with pytest.raises(CampaignStateError, match="duplicate_campaign_run_key"):
        journal.initialize([schedule[0], schedule[0]])

    journal.initialize(schedule)
    journal.initialize(schedule)
    changed_key, changed = _schedule("changed")
    assert changed_key != key
    with pytest.raises(CampaignFingerprintMismatch, match="campaign_schedule_mismatch"):
        journal.initialize(changed)

    other = _journal(tmp_path, payload={"input": "different"})
    with pytest.raises(CampaignFingerprintMismatch, match="campaign_fingerprint_mismatch"):
        other.initialize(schedule)


def test_run_key_guards_missing_read_and_immutable_record_paths(tmp_path):
    journal = _journal(tmp_path)
    key, schedule = _schedule()
    with pytest.raises(CampaignStateError, match="invalid_run_key"):
        journal.read_run("bad")
    with pytest.raises(CampaignStateError, match="campaign_journal_not_initialized"):
        journal.read_run(key)
    journal.initialize(schedule)
    other = schedule_run_key("other", "scenario", 1, 2)
    with pytest.raises(CampaignStateError, match="run_not_in_campaign_schedule"):
        journal.read_run(other)
    assert journal.read_run(key) is None
    assert journal.completed_run_count() == 0

    path = journal.write_run(key, {"result": {"status": "ok"}})
    assert journal.read_run(key)["result"] == {"status": "ok"}
    assert journal.write_run(key, {"result": {"status": "ok"}}) == path
    assert journal.completed_run_count() == 1
    with pytest.raises(CampaignStateError, match="immutable_run_record_conflict"):
        journal.write_run(key, {"result": {"status": "different"}})


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"schema_version": "bad"}, "unsupported_run_record_schema"),
        ({"campaign_id": "bad"}, "run_record_campaign_mismatch"),
        ({"fingerprint": "bad"}, "run_record_fingerprint_mismatch"),
        ({"run_key": "0" * 64}, "run_record_key_mismatch"),
        ({"result": "bad"}, "run_record_missing_result"),
    ],
)
def test_run_record_validation_errors(tmp_path, changes, error):
    journal = _journal(tmp_path)
    key, schedule = _schedule()
    journal.initialize(schedule)
    record = {
        "schema_version": CAMPAIGN_STATE_SCHEMA_VERSION,
        "campaign_id": journal.campaign_id,
        "fingerprint": journal.fingerprint,
        "run_key": key,
        "result": {},
        **changes,
    }
    with pytest.raises(CampaignStateError, match=error):
        journal._validate_record(record, run_key=key)


def test_attestation_read_write_empty_and_each_mismatch(tmp_path):
    journal = _journal(tmp_path)
    assert journal.read_attestations() == ()
    key, schedule = _schedule()
    journal.initialize(schedule)
    path = journal.write_attestation(key, {"status": "reset"})
    assert journal.read_attestations()[0]["status"] == "reset"

    original = json.loads(path.read_text(encoding="utf-8"))
    cases = [
        {**original, "schema_version": "bad"},
        {**original, "campaign_id": "bad"},
        {**original, "fingerprint": "bad"},
        {**original, "run_key": "0" * 64},
    ]
    for invalid in cases:
        path.write_text(json.dumps(invalid), encoding="utf-8")
        with pytest.raises(CampaignStateError, match="attestation_record_mismatch"):
            journal.read_attestations()
    path.write_text(json.dumps(original), encoding="utf-8")

    unscheduled_path = path.with_name(f"{'f' * 64}.json")
    unscheduled_path.write_text(json.dumps({**original, "run_key": "f" * 64}), encoding="utf-8")
    with pytest.raises(CampaignStateError, match="attestation_record_mismatch"):
        journal.read_attestations()


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"schema_version": "bad"}, "unsupported_cleanup_attestation_schema"),
        ({"campaign_id": "bad"}, "cleanup_attestation_campaign_mismatch"),
        ({"fingerprint": "bad"}, "cleanup_attestation_fingerprint_mismatch"),
        ({"status": "unknown"}, "invalid_cleanup_attestation_status"),
    ],
)
def test_cleanup_attestation_validation_errors(tmp_path, changes, error):
    journal = _journal(tmp_path)
    record = {
        "schema_version": CAMPAIGN_STATE_SCHEMA_VERSION,
        "campaign_id": journal.campaign_id,
        "fingerprint": journal.fingerprint,
        "status": "succeeded",
        **changes,
    }
    with pytest.raises(CampaignStateError, match=error):
        journal._validate_cleanup_attestation(record)


def test_cleanup_preflight_status_and_read_paths(tmp_path):
    journal = _journal(tmp_path)
    _key, schedule = _schedule()
    journal.initialize(schedule)
    assert journal.read_cleanup_attestation() is None
    journal.write_cleanup_attestation({"status": "succeeded"})
    assert journal.read_cleanup_attestation()["status"] == "succeeded"
    assert journal.write_preflight({"ok": True}).exists()
    status_path = journal.set_status("x" * 200, detail={"ok": True})
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert len(status["status"]) == 128


def test_atomic_json_cleanup_and_suppressed_cleanup_error(tmp_path, monkeypatch):
    destination = tmp_path / "state.json"
    monkeypatch.setattr(
        state_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("replace failed")),
    )
    with pytest.raises(RuntimeError, match="replace failed"):
        state_module._atomic_json(destination, {"ok": True})

    monkeypatch.setattr(
        state_module.Path,
        "unlink",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )
    with pytest.raises(RuntimeError, match="replace failed"):
        state_module._atomic_json(destination, {"ok": True})


def test_read_mapping_errors_and_nonmapping(tmp_path):
    with pytest.raises(CampaignStateError, match="campaign_state_read_failed"):
        state_module._read_mapping(tmp_path / "missing.json")
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(CampaignStateError, match="campaign_state_read_failed"):
        state_module._read_mapping(invalid)
    nonmapping = tmp_path / "list.json"
    nonmapping.write_text("[]", encoding="utf-8")
    with pytest.raises(CampaignStateError, match="campaign_state_not_mapping"):
        state_module._read_mapping(nonmapping)


def test_json_safe_type_depth_and_number_boundaries():
    assert state_module._json_safe(None) is None
    assert state_module._json_safe("x") == "x"
    assert state_module._json_safe(True) is True
    assert state_module._json_safe(1) == 1
    assert state_module._json_safe(1.5) == 1.5
    assert state_module._json_safe({1: ["x"]}) == {"1": ["x"]}
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CampaignStateError, match="nonfinite"):
            state_module._json_safe(value)
    with pytest.raises(CampaignStateError, match="non_json_value"):
        state_module._json_safe(object())
    with pytest.raises(CampaignStateError, match="depth_exceeded"):
        state_module._json_safe([[[[[[[[[]]]]]]]]])
