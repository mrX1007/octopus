"""Complete validation and persistence coverage for the v3 ledger."""

from __future__ import annotations

import pytest

import core.benchmarks.v3.ledger as ledger_module
from core.benchmarks.v3.ledger import (
    ControlPlaneLedger,
    LedgerEntry,
    iter_verified_ledger_entries,
    read_ledger,
    verify_ledger_entries,
)
from core.benchmarks.v3.schema import BenchmarkV3SchemaError

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

DIGEST = "a" * 64


def _entry_payload():
    ledger = ControlPlaneLedger(variant_digest=DIGEST, clock=lambda: 1.0)
    return ledger.record(method="GET", target="/", route_id="route", status=200).to_dict()


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"sequence": "bad"}, "invalid_ledger_entry"),
        ({"sequence": 0}, "invalid_ledger_entry"),
        ({"status": 99}, "invalid_ledger_entry"),
        ({"method": "TRACE"}, "invalid_ledger_method"),
        ({"target_digest": "bad"}, "invalid_ledger_digest"),
        ({"previous_digest": "bad"}, "invalid_ledger_digest"),
        ({"entry_digest": "bad"}, "invalid_ledger_digest"),
    ],
)
def test_ledger_entry_rejects_invalid_fields(changes, message):
    with pytest.raises(BenchmarkV3SchemaError, match=message):
        LedgerEntry.from_dict({**_entry_payload(), **changes})


def test_snapshot_dict_empty_and_populated_status_classes():
    ledger = ControlPlaneLedger(variant_digest=DIGEST, clock=lambda: 1.0)
    assert ledger.snapshot().to_dict() == {
        "entry_count": 0,
        "observed_evidence_ids": [],
        "root_digest": "0" * 64,
        "schema_version": "1.0",
        "variant_digest": DIGEST,
        "violations": [],
        "visited_route_ids": [],
    }
    for index, status in enumerate((408, 204, 401, 500), start=1):
        ledger.record(
            method="GET",
            target=f"/{index}",
            route_id=f"route-{index}",
            status=status,
            evidence_ids=("two", "one", "one"),
            violation="attempt" if index == 1 else "",
        )
    assert [event.status for event in ledger.action_events()] == [
        "timeout",
        "succeeded",
        "blocked",
        "failed",
    ]
    assert ledger.snapshot().observed_evidence_ids == ("one", "two")
    assert ledger.snapshot().violations == ("get_mutation_attempt",)


def test_constructor_record_validation_persistence_reload_and_fsync(tmp_path, monkeypatch):
    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:variant_digest"):
        ControlPlaneLedger(variant_digest="bad")

    path = tmp_path / "ledger.jsonl"
    fsync_calls = []
    monkeypatch.setattr(ledger_module.os, "fsync", lambda fd: fsync_calls.append(fd))
    ledger = ControlPlaneLedger(variant_digest=DIGEST, path=path, clock=lambda: 2.0, fsync=True)
    assert path.exists()
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_ledger_method"):
        ledger.record(method="TRACE", target="/", route_id="r", status=200)
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_ledger_status"):
        ledger.record(method="GET", target="/", route_id="r", status=99)
    ledger.record(method="GET", target="/", route_id="", status=200)
    assert fsync_calls

    reloaded = ControlPlaneLedger(variant_digest=DIGEST, path=path, fsync=False)
    assert len(reloaded.entries()) == 1
    assert reloaded.entries()[0].route_id == "unmatched-route"


def test_read_ledger_rejects_missing_invalid_json_and_nonobject(tmp_path):
    with pytest.raises(BenchmarkV3SchemaError, match="ledger_read_failed"):
        read_ledger(tmp_path / "missing.jsonl", variant_digest=DIGEST)
    invalid = tmp_path / "invalid.jsonl"
    invalid.write_text("{\n", encoding="utf-8")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_ledger_json"):
        read_ledger(invalid, variant_digest=DIGEST)
    nonobject = tmp_path / "nonobject.jsonl"
    nonobject.write_text("[]\n", encoding="utf-8")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_ledger_entry"):
        read_ledger(nonobject, variant_digest=DIGEST)


def test_verifier_rejects_variant_payload_chain_and_digest_errors():
    payload = _entry_payload()
    assert verify_ledger_entries([payload], variant_digest=DIGEST)[0].sequence == 1

    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:variant_digest"):
        tuple(iter_verified_ledger_entries([], variant_digest="bad"))
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_ledger_entry"):
        tuple(iter_verified_ledger_entries([[]], variant_digest=DIGEST))
    with pytest.raises(BenchmarkV3SchemaError, match="broken_ledger_chain"):
        verify_ledger_entries([{**payload, "sequence": 2}], variant_digest=DIGEST)
    with pytest.raises(BenchmarkV3SchemaError, match="broken_ledger_chain"):
        verify_ledger_entries([{**payload, "previous_digest": "b" * 64}], variant_digest=DIGEST)
    with pytest.raises(BenchmarkV3SchemaError, match="ledger_digest_mismatch"):
        verify_ledger_entries([{**payload, "entry_digest": "b" * 64}], variant_digest=DIGEST)


def test_digest_helper_short_circuit_boundaries():
    assert ledger_module._is_digest(DIGEST) is True
    assert ledger_module._is_digest("short") is False
    assert ledger_module._is_digest("z" * 64) is False
