"""Validation, runtime, and persistence edge coverage for fixture v3."""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest

import core.benchmarks.v3.fixture as fixture_module
from core.benchmarks.v3.evaluation import CompletionRule
from core.benchmarks.v3.fixture import (
    FixtureRoute,
    FixtureRuntime,
    FixtureVariant,
    generate_fixture_variant,
    load_private_fixture,
)
from core.benchmarks.v3.ledger import ControlPlaneLedger
from core.benchmarks.v3.schema import BenchmarkV3SchemaError

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _route(**changes):
    values = {
        "route_id": "route-1",
        "target": "/target",
        "status": 200,
        "content_type": "text/plain",
        "body": "body",
        "headers": {},
    }
    values.update(changes)
    return FixtureRoute(**values)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"route_id": ""}, "invalid:fixture.route_id"),
        ({"target": "target"}, "invalid:fixture.target"),
        ({"target": "/target#fragment"}, "invalid:fixture.target"),
        ({"status": 99}, "invalid:fixture.status"),
        ({"status": 600}, "invalid:fixture.status"),
        ({"content_type": ""}, "invalid:fixture.content_type"),
        ({"content_type": "bad\rvalue"}, "invalid:fixture.content_type"),
        ({"content_type": "bad\nvalue"}, "invalid:fixture.content_type"),
        ({"body": "x" * 1_000_001}, "fixture_body_too_large"),
        ({"delay_ms": -1}, "invalid:fixture.delay_ms"),
        ({"delay_ms": 10_001}, "invalid:fixture.delay_ms"),
        ({"response_statuses": (99,)}, "invalid:fixture.response_statuses"),
        ({"response_statuses": (600,)}, "invalid:fixture.response_statuses"),
        ({"headers": {"bad name": "value"}}, "invalid:fixture.header"),
        ({"headers": {"Good": "bad\rvalue"}}, "invalid:fixture.header"),
        ({"headers": {"Good": "bad\nvalue"}}, "invalid:fixture.header"),
    ],
)
def test_route_rejects_every_invalid_field(changes, message):
    with pytest.raises(BenchmarkV3SchemaError, match=message):
        _route(**changes)


def test_route_from_dict_requires_mapping_headers_and_round_trips():
    route = _route(headers={"X-Test": "yes"}, evidence_ids=("ev",))
    assert FixtureRoute.from_dict(route.to_private_dict()) == route
    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:fixture.headers"):
        FixtureRoute.from_dict({**route.to_private_dict(), "headers": ["bad"]})


def test_variant_rejects_family_seed_route_truth_entry_and_digest_mismatches():
    variant = generate_fixture_variant("clean_negative", matched_fixture_seed=1)
    cases = [
        ({"scenario_family": "unknown"}, "unknown_fixture_scenario_family"),
        ({"matched_fixture_seed": -1}, "invalid:matched_fixture_seed"),
        ({"routes": (variant.routes[0], variant.routes[0])}, "duplicate_fixture_route"),
        ({"entry_target": "/missing"}, "fixture_entry_target_missing"),
        (
            {
                "completion_rule": CompletionRule(
                    rule_id="missing-rule",
                    required_truth_ids=("missing",),
                    minimum_verified_recall=1.0,
                )
            },
            "fixture_completion_truth_missing",
        ),
        ({"variant_digest": "bad"}, "fixture_variant_digest_mismatch"),
    ]
    for changes, message in cases:
        with pytest.raises(BenchmarkV3SchemaError, match=message):
            replace(variant, **changes)


def test_private_manifest_validates_envelope_and_filters_nonobjects():
    variant = generate_fixture_variant("clean_negative", matched_fixture_seed=2)
    payload = variant.to_private_dict()
    invalid_payloads = [
        ({**payload, "schema_version": "999"}, "unsupported_fixture_schema"),
        ({**payload, "generator": []}, "invalid_fixture_manifest"),
        ({**payload, "scenario": []}, "invalid_fixture_manifest"),
        ({**payload, "private_evaluation": []}, "invalid_fixture_manifest"),
        (
            {
                **payload,
                "private_evaluation": {
                    **payload["private_evaluation"],
                    "truth_claims": "bad",
                },
            },
            "invalid_fixture_truth",
        ),
        (
            {
                **payload,
                "private_evaluation": {
                    **payload["private_evaluation"],
                    "completion_rule": [],
                },
            },
            "invalid_fixture_completion_rule",
        ),
        (
            {**payload, "generator": {**payload["generator"], "matched_fixture_seed": None}},
            "missing_fixture_seed",
        ),
    ]
    for invalid, message in invalid_payloads:
        with pytest.raises(BenchmarkV3SchemaError, match=message):
            FixtureVariant.from_private_dict(invalid)

    filtered = copy.deepcopy(payload)
    filtered["routes"].append("ignored")
    filtered["private_evaluation"]["truth_claims"].append("ignored")
    assert FixtureVariant.from_private_dict(filtered) == variant


def test_reveal_writer_and_product_base_url(tmp_path):
    variant = generate_fixture_variant("clean_negative", matched_fixture_seed=3)
    path = variant.write_reveal_manifest(tmp_path / "reveal.json", campaign_closed=True)
    assert path.stat().st_mode & 0o777 == 0o600
    assert variant.product_view(base_url="http://example.test/")["base_url"] == "http://example.test"


def test_runtime_rejects_wrong_ledger_and_covers_all_method_and_route_paths():
    variant = generate_fixture_variant("redirect_loop", matched_fixture_seed=4)
    with pytest.raises(BenchmarkV3SchemaError, match="fixture_ledger_variant_mismatch"):
        FixtureRuntime(variant, ControlPlaneLedger(variant_digest="0" * 64))

    ledger = ControlPlaneLedger(variant_digest=variant.variant_digest, clock=lambda: 1.0)
    runtime = FixtureRuntime(variant, ledger)
    assert runtime.handle("DELETE", "/missing").status == 405
    options = runtime.handle("OPTIONS", variant.entry_target)
    assert options.status == 204
    assert options.headers["Allow"] == "GET, HEAD, OPTIONS"
    assert runtime.handle("TRACE", "/missing").status == 405
    handoff = runtime.handle("GET", "/")
    assert handoff.status == 200
    assert variant.entry_target.encode() in handoff.body
    assert runtime.handle("GET", "/missing").status == 404

    evidence_header_route = next(
        route for route in variant.routes if any(name.lower() == "x-octobench-evidence" for name in route.headers)
    )
    assert runtime.handle("HEAD", evidence_header_route.target).status in {302, 307}
    assert set(evidence_header_route.evidence_ids).issubset(ledger.snapshot().observed_evidence_ids)
    assert ledger.snapshot().violations == (
        "delete_mutation_attempt",
        "get_mutation_attempt",
    )


@pytest.mark.parametrize("seed", [True, -1, 2**63])
def test_generate_rejects_invalid_seed(seed):
    with pytest.raises(BenchmarkV3SchemaError, match="invalid:matched_fixture_seed"):
        generate_fixture_variant("clean_negative", matched_fixture_seed=seed)


def test_generate_rejects_unknown_family():
    with pytest.raises(BenchmarkV3SchemaError, match="unknown_fixture_scenario_family"):
        generate_fixture_variant("unknown", matched_fixture_seed=1)


def test_load_private_fixture_errors_and_nonobject(tmp_path):
    with pytest.raises(BenchmarkV3SchemaError, match="fixture_manifest_load_failed"):
        load_private_fixture(tmp_path / "missing.json")
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(BenchmarkV3SchemaError, match="fixture_manifest_load_failed"):
        load_private_fixture(invalid)
    nonobject = tmp_path / "nonobject.json"
    nonobject.write_text("[]", encoding="utf-8")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_fixture_manifest"):
        load_private_fixture(nonobject)


class _CollisionRng:
    def __init__(self):
        self.calls = 0

    def choice(self, values):
        attempt = self.calls // 11
        position = self.calls % 11
        self.calls += 1
        if position == 10:
            return "amber"
        return "a" if attempt == 0 else "b"


def test_builder_path_retries_a_collision():
    builder = fixture_module._VariantBuilder("clean_negative", 1, _CollisionRng())
    builder._targets.add("/amber-aaaaaaaaaa")
    assert builder.path() == "/amber-bbbbbbbbbb"


def test_normalize_target_and_blinding_recursion():
    assert fixture_module._normalize_target("/path?b=2&a=1") == "/path?a=1&b=2"
    with pytest.raises(BenchmarkV3SchemaError, match=r"invalid:fixture.target"):
        fixture_module._normalize_target("relative")
    fixture_module._assert_blinded_product_view({"safe": [{"nested": "value"}]})
    with pytest.raises(BenchmarkV3SchemaError, match="private_fixture_key"):
        fixture_module._assert_blinded_product_view({"safe": [{"truth_value": 1}]})


def test_atomic_manifest_cleans_temporary_file_on_failure(tmp_path, monkeypatch):
    destination = tmp_path / "manifest.json"
    monkeypatch.setattr(
        fixture_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("replace failed")),
    )
    with pytest.raises(OSError, match="replace failed"):
        fixture_module._atomic_private_json(destination, {"safe": True})
    assert not destination.exists()


def test_atomic_manifest_suppresses_cleanup_error(tmp_path, monkeypatch):
    monkeypatch.setattr(
        fixture_module.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("replace failed")),
    )
    monkeypatch.setattr(
        fixture_module.os,
        "unlink",
        lambda *_args: (_ for _ in ()).throw(OSError("unlink failed")),
    )
    with pytest.raises(RuntimeError, match="replace failed"):
        fixture_module._atomic_private_json(tmp_path / "manifest.json", {"safe": True})
