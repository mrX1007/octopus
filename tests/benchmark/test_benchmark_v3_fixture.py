from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from core.benchmarks.v3 import (
    SCENARIO_FAMILIES,
    ControlPlaneLedger,
    FixtureRuntime,
    generate_fixture_variant,
    read_ledger,
)
from core.benchmarks.v3.schema import BenchmarkV3SchemaError
from core.benchmarks.v3.server import create_server

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def test_all_required_families_are_deterministic_and_seeded() -> None:
    assert set(SCENARIO_FAMILIES) == {
        "canonical_alias_dedup",
        "clean_negative",
        "deep_navigation",
        "discovery_metadata",
        "documented_missing",
        "multi_service",
        "noisy_openapi",
        "pagination_cycle",
        "redirect_loop",
        "slow_dead_end",
        "static_js_discovery",
        "transient_recovery",
    }
    for family in SCENARIO_FAMILIES:
        first = generate_fixture_variant(family, matched_fixture_seed=4242)
        paired = generate_fixture_variant(family, matched_fixture_seed=4242)
        other = generate_fixture_variant(family, matched_fixture_seed=4243)
        assert first.to_private_dict() == paired.to_private_dict()
        assert first.variant_digest == paired.variant_digest
        assert first.variant_digest != other.variant_digest
        assert first.entry_target.startswith("/")
        assert first.entry_target in {route.target for route in first.routes}


def test_product_view_excludes_private_seed_matcher_truth_and_nonce() -> None:
    variant = generate_fixture_variant("deep_navigation", matched_fixture_seed=991)
    product = variant.product_view()
    encoded = json.dumps(product, sort_keys=True).lower()

    for forbidden in ("seed", "matcher", "truth", "nonce", "evidence"):
        assert forbidden not in encoded
    assert product["read_only"] is True
    assert product["mutation_response"] == 405
    assert "private_evaluation" in variant.to_private_dict()


def test_mutations_return_405_and_are_recorded_without_state_change(tmp_path: Path) -> None:
    variant = generate_fixture_variant("deep_navigation", matched_fixture_seed=123)
    ledger_path = tmp_path / "controller" / "ledger.jsonl"
    ledger = ControlPlaneLedger(
        variant_digest=variant.variant_digest,
        path=ledger_path,
        clock=lambda: 100.0,
        fsync=False,
    )
    runtime = FixtureRuntime(variant, ledger)
    mutation = runtime.handle("POST", variant.entry_target)
    read = runtime.handle("GET", variant.entry_target)

    assert mutation.status == 405
    assert mutation.headers["Allow"] == "GET, HEAD"
    assert read.status == 200
    snapshot = ledger.snapshot()
    assert snapshot.entry_count == 2
    assert snapshot.violations == ("post_mutation_attempt",)
    persisted = read_ledger(ledger_path, variant_digest=variant.variant_digest)
    assert persisted[0].violation == "read_only_mutation_attempt"
    assert [item.method for item in persisted] == ["POST", "GET"]


def test_route_observation_proves_private_evidence_in_control_ledger() -> None:
    variant = generate_fixture_variant("static_js_discovery", matched_fixture_seed=31)
    ledger = ControlPlaneLedger(
        variant_digest=variant.variant_digest,
        clock=lambda: 1.0,
    )
    runtime = FixtureRuntime(variant, ledger)
    evidence_route = next(route for route in variant.routes if route.evidence_ids)

    response = runtime.handle("GET", evidence_route.target)

    assert response.status == 200
    assert ledger.snapshot().observed_evidence_ids == evidence_route.evidence_ids
    assert ledger.action_events()[0].evidence_refs == evidence_route.evidence_ids


def test_head_does_not_verify_body_only_evidence() -> None:
    variant = generate_fixture_variant("static_js_discovery", matched_fixture_seed=32)
    ledger = ControlPlaneLedger(
        variant_digest=variant.variant_digest,
        clock=lambda: 1.0,
    )
    runtime = FixtureRuntime(variant, ledger)
    evidence_route = next(route for route in variant.routes if route.evidence_ids)

    response = runtime.handle("HEAD", evidence_route.target)

    assert response.status == 200
    assert ledger.snapshot().visited_route_ids == (evidence_route.route_id,)
    assert ledger.snapshot().observed_evidence_ids == ()


def test_transient_sequence_is_429_503_then_recovered() -> None:
    variant = generate_fixture_variant("transient_recovery", matched_fixture_seed=61)
    ledger = ControlPlaneLedger(variant_digest=variant.variant_digest, clock=lambda: 1.0)
    runtime = FixtureRuntime(variant, ledger)
    transient = next(route for route in variant.routes if route.response_statuses)

    responses = [runtime.handle("GET", transient.target) for _ in range(3)]

    assert [item.status for item in responses] == [429, 503, 200]
    assert ledger.snapshot().observed_evidence_ids == transient.evidence_ids


def test_reveal_is_gated_and_private_manifest_round_trips(tmp_path: Path) -> None:
    variant = generate_fixture_variant("clean_negative", matched_fixture_seed=11)
    with pytest.raises(PermissionError, match="closed_campaign"):
        variant.reveal_manifest(campaign_closed=False)

    private_path = variant.write_private_manifest(tmp_path / "private.json")
    reveal = variant.reveal_manifest(campaign_closed=True)

    assert private_path.stat().st_mode & 0o777 == 0o600
    assert reveal["generator"]["matched_fixture_seed"] == 11
    assert reveal["variant_digest"] == variant.variant_digest


def test_persisted_ledger_detects_tampering(tmp_path: Path) -> None:
    variant = generate_fixture_variant("clean_negative", matched_fixture_seed=22)
    path = tmp_path / "ledger.jsonl"
    ledger = ControlPlaneLedger(
        variant_digest=variant.variant_digest,
        path=path,
        clock=lambda: 10.0,
        fsync=False,
    )
    FixtureRuntime(variant, ledger).handle("GET", variant.entry_target)
    payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    payload["status"] = 500
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    with pytest.raises(BenchmarkV3SchemaError, match="digest_mismatch"):
        read_ledger(path, variant_digest=variant.variant_digest)


@pytest.mark.integration
def test_http_server_serves_variant_and_blocks_mutation(tmp_path: Path) -> None:
    variant = generate_fixture_variant("clean_negative", matched_fixture_seed=72)
    manifest = variant.write_private_manifest(tmp_path / "private.json")
    ledger_path = tmp_path / "ledger.jsonl"
    try:
        server = create_server(
            private_manifest_path=manifest,
            ledger_path=ledger_path,
            host="127.0.0.1",
            port=0,
        )
    except PermissionError:
        pytest.skip("sandbox forbids loopback socket binding")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urlopen(base_url + variant.entry_target, timeout=2) as response:
            assert response.status == 200
            assert response.headers["X-Octobench-Variant"] == variant.variant_id
        request = Request(base_url + variant.entry_target, data=b"", method="POST")
        with pytest.raises(HTTPError) as captured:
            urlopen(request, timeout=2)
        assert captured.value.code == 405
        assert captured.value.headers["Allow"] == "GET, HEAD"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    entries = read_ledger(ledger_path, variant_digest=variant.variant_digest)
    assert [item.method for item in entries] == ["GET", "POST"]
    assert entries[-1].violation == "read_only_mutation_attempt"
