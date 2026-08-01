"""Hermetic failure-boundary coverage for Benchmark v4 publication."""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.benchmarks.v3 import publish_v3_results
from core.benchmarks.v4 import publication
from core.benchmarks.v4.schema import BenchmarkV4SchemaError
from tests.benchmark.test_benchmark_v4_publication import (
    _canary_inputs,
    _rewrite_checksums,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.unit]


@pytest.fixture(scope="module")
def published_bundle(tmp_path_factory):
    root = tmp_path_factory.mktemp("benchmark-v4-publication-coverage")
    source_plan, efficiency_plan, runs, context, ledgers = _canary_inputs()
    source = publish_v3_results(
        source_plan,
        runs,
        root / "source-v3",
        campaign_context=context,
        controller_ledgers=ledgers,
    )
    companion = publication.publish_v4_results(
        efficiency_plan,
        source,
        root / "companion-v4",
    )
    evidence = publication.load_verified_v3_evidence(source)
    return source_plan, efficiency_plan, source, companion, evidence


@pytest.fixture
def companion_copy(published_bundle, tmp_path):
    companion = published_bundle[3]
    destination = tmp_path / "companion-v4"
    shutil.copytree(companion, destination)
    return destination


def _source_stub(source_plan):
    return publication.VerifiedV3Evidence(
        root=Path("."),
        source_plan=source_plan,
        runs=(),
        controller_ledgers=(),
        campaign_context={},
        bundle_digest="a" * 64,
        verification={},
    )


def _minimal_statistics(plan):
    return {
        "fairness": {},
        "paired_effects": [],
        "systems": {system_id: {} for system_id in plan.system_ids},
    }


def _write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_load_verified_source_rejects_payload_and_artifact_shapes(monkeypatch, tmp_path):
    source_plan, *_rest = _canary_inputs()
    monkeypatch.setattr(publication, "verify_v3_results", lambda _root: {"runs": 0})

    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / "publication.json").write_text("{", encoding="utf-8")
    (malformed / "campaign-context.json").write_text("{}", encoding="utf-8")
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_payload_invalid"):
        publication.load_verified_v3_evidence(malformed)

    nonmapping = tmp_path / "nonmapping"
    nonmapping.mkdir()
    _write_json(nonmapping / "publication.json", [])
    _write_json(nonmapping / "campaign-context.json", {})
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_payload_invalid"):
        publication.load_verified_v3_evidence(nonmapping)

    bad_artifacts = tmp_path / "bad-artifacts"
    bad_artifacts.mkdir()
    _write_json(bad_artifacts / "publication.json", {"artifacts": []})
    _write_json(bad_artifacts / "campaign-context.json", {})
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_publication_invalid"):
        publication.load_verified_v3_evidence(bad_artifacts)

    valid_shell = tmp_path / "valid-shell"
    valid_shell.mkdir()
    _write_json(
        valid_shell / "publication.json",
        {"artifacts": {"controller_ledgers": "ledgers.jsonl", "run_records": "runs.jsonl"}},
    )
    _write_json(valid_shell / "campaign-context.json", {})
    monkeypatch.setattr(publication, "load_analysis_plan", lambda _path: source_plan)
    monkeypatch.setattr(publication, "_iter_compact_runs", lambda *_args: ())
    monkeypatch.setattr(publication, "_iter_compact_ledgers", lambda *_args: ())
    monkeypatch.setattr(publication, "verify_v3_results", lambda _root: {"runs": object()})
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_verification_invalid"):
        publication.load_verified_v3_evidence(valid_shell)

    monkeypatch.setattr(publication, "verify_v3_results", lambda _root: {"runs": 1})
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_evidence_count_mismatch"):
        publication.load_verified_v3_evidence(valid_shell)

    monkeypatch.setattr(publication, "_iter_compact_runs", lambda *_args: (object(),))
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_evidence_count_mismatch"):
        publication.load_verified_v3_evidence(valid_shell)


def test_render_guards_and_empty_effect_fallback():
    _source_plan, plan, *_rest = _canary_inputs()
    with pytest.raises(BenchmarkV4SchemaError, match="v4_statistics_systems_invalid"):
        publication.render_efficiency_svg(plan, {"systems": []})
    with pytest.raises(BenchmarkV4SchemaError, match="v4_statistics_effects_invalid"):
        publication.render_efficiency_svg(
            plan,
            {"paired_effects": {}, "systems": {system_id: {} for system_id in plan.system_ids}},
        )
    with pytest.raises(BenchmarkV4SchemaError, match="v4_statistics_effect_count_invalid"):
        publication._render_effect_panel(
            plan,
            {},
            {},
            [{"quality_qualified_pairs": True}],
            (),
            0,
        )
    assert "No paired effects available" in "".join(publication._render_effect_panel(plan, {}, {}, [], (), 0))


def test_scalar_render_helpers_cover_missing_values():
    assert publication._mapping_value({"item": []}, "item") == {}
    assert publication._nested_number({"value": True}, "value") is None
    assert publication._nested_number({"value": "bad"}, "value") is None
    assert publication._display_number(None) == "N/A"
    assert publication._display_number(0.5, percent=True) == "50.0%"
    assert publication._float(0.0) == "0"


def test_publish_rejects_source_mismatch_and_existing_destination(monkeypatch, tmp_path):
    source_plan, plan, *_rest = _canary_inputs()
    mismatched = _source_stub(replace(source_plan, bootstrap_seed=source_plan.bootstrap_seed + 1))
    monkeypatch.setattr(publication, "load_verified_v3_evidence", lambda _root: mismatched)
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_plan_digest_mismatch"):
        publication.publish_v4_results(plan, tmp_path / "source", tmp_path / "mismatch")

    source = _source_stub(source_plan)
    monkeypatch.setattr(publication, "load_verified_v3_evidence", lambda _root: source)
    monkeypatch.setattr(publication, "extract_efficiency_runs", lambda *_args: ())
    monkeypatch.setattr(publication, "analyze_efficiency", lambda *_args: _minimal_statistics(plan))
    destination = tmp_path / "existing"
    destination.mkdir()
    with pytest.raises(FileExistsError, match="v4_publication_destination_exists"):
        publication.publish_v4_results(plan, tmp_path / "source", destination)


def test_publish_cleans_failure_and_detects_destination_race(monkeypatch, tmp_path):
    source_plan, plan, *_rest = _canary_inputs()
    source = _source_stub(source_plan)
    monkeypatch.setattr(publication, "load_verified_v3_evidence", lambda _root: source)
    monkeypatch.setattr(publication, "extract_efficiency_runs", lambda *_args: ())
    monkeypatch.setattr(publication, "analyze_efficiency", lambda *_args: _minimal_statistics(plan))

    failed = tmp_path / "failed"
    monkeypatch.setattr(
        publication,
        "freeze_efficiency_plan",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("fixture")),
    )
    with pytest.raises(RuntimeError, match="fixture"):
        publication.publish_v4_results(plan, tmp_path / "source", failed)
    assert not failed.exists()
    assert not list(tmp_path.glob(".failed-tmp-*"))

    monkeypatch.undo()
    source = _source_stub(source_plan)
    monkeypatch.setattr(publication, "load_verified_v3_evidence", lambda _root: source)
    monkeypatch.setattr(publication, "extract_efficiency_runs", lambda *_args: ())
    monkeypatch.setattr(publication, "analyze_efficiency", lambda *_args: _minimal_statistics(plan))
    raced = tmp_path / "raced"

    def create_race(_root, _source):
        raced.mkdir()

    monkeypatch.setattr(publication, "_verify_v4_results", create_race)
    with pytest.raises(FileExistsError, match="v4_publication_destination_exists"):
        publication.publish_v4_results(plan, tmp_path / "source", raced)
    assert raced.is_dir()
    assert not list(tmp_path.glob(".raced-tmp-*"))


def test_verify_rejects_nonfile_and_file_set_mismatches(companion_copy, published_bundle):
    evidence = published_bundle[4]
    (companion_copy / "directory").mkdir()
    with pytest.raises(BenchmarkV4SchemaError, match="v4_publication_file_set_mismatch"):
        publication._verify_v4_results(companion_copy, evidence)

    shutil.rmtree(companion_copy / "directory")
    (companion_copy / "extra.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(BenchmarkV4SchemaError, match="v4_publication_file_set_mismatch"):
        publication._verify_v4_results(companion_copy, evidence)


def test_verify_rejects_checksum_and_required_set_mismatches(companion_copy, published_bundle):
    evidence = published_bundle[4]
    with (companion_copy / "efficiency.svg").open("a", encoding="utf-8") as handle:
        handle.write("<!-- tampered -->\n")
    with pytest.raises(BenchmarkV4SchemaError, match="v4_publication_checksum_mismatch"):
        publication._verify_v4_results(companion_copy, evidence)

    shutil.copyfile(published_bundle[3] / "efficiency.svg", companion_copy / "efficiency.svg")
    (companion_copy / "efficiency.svg").unlink()
    _rewrite_checksums(companion_copy)
    with pytest.raises(BenchmarkV4SchemaError, match="v4_publication_file_set_mismatch"):
        publication._verify_v4_results(companion_copy, evidence)


def test_verify_rejects_noncanonical_checksum_order(companion_copy, published_bundle):
    evidence = published_bundle[4]
    checksum_path = companion_copy / "SHA256SUMS"
    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    checksum_path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    with pytest.raises(BenchmarkV4SchemaError, match="v4_publication_checksums_invalid"):
        publication._verify_v4_results(companion_copy, evidence)


@pytest.mark.parametrize(
    ("target", "replacement"),
    [
        ("publication.json", "{"),
        ("efficiency-statistics.json", "[]\n"),
    ],
)
def test_verify_rejects_malformed_or_nonmapping_payloads(
    companion_copy,
    published_bundle,
    target,
    replacement,
):
    evidence = published_bundle[4]
    (companion_copy / target).write_text(replacement, encoding="utf-8")
    _rewrite_checksums(companion_copy)
    with pytest.raises(BenchmarkV4SchemaError, match="v4_publication_payload_invalid"):
        publication._verify_v4_results(companion_copy, evidence)


@pytest.mark.parametrize("target", ["publication.json", "source-attestation.json"])
def test_verify_rejects_manifest_or_attestation_mismatch(
    companion_copy,
    published_bundle,
    target,
):
    evidence = published_bundle[4]
    payload = json.loads((companion_copy / target).read_text(encoding="utf-8"))
    payload["schema_version"] = "different"
    _write_json(companion_copy / target, payload)
    _rewrite_checksums(companion_copy)
    expected = "v4_publication_manifest_invalid" if target == "publication.json" else "v4_source_attestation_invalid"
    with pytest.raises(BenchmarkV4SchemaError, match=expected):
        publication._verify_v4_results(companion_copy, evidence)


def test_verify_rejects_source_plan_mismatch(companion_copy, published_bundle):
    evidence = published_bundle[4]
    altered_plan = replace(
        evidence.source_plan,
        bootstrap_seed=evidence.source_plan.bootstrap_seed + 1,
    )
    altered_source = replace(evidence, source_plan=altered_plan)
    (companion_copy / "source-attestation.json").write_text(
        publication._pretty_json(publication._source_attestation(altered_source)),
        encoding="utf-8",
    )
    _rewrite_checksums(companion_copy)
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_plan_digest_mismatch"):
        publication._verify_v4_results(companion_copy, altered_source)


def test_verify_detects_statistics_mapping_mismatch(
    monkeypatch,
    companion_copy,
    published_bundle,
):
    evidence = published_bundle[4]
    statistics_path = companion_copy / "efficiency-statistics.json"
    statistics = json.loads(statistics_path.read_text(encoding="utf-8"))
    regenerated = dict(statistics)
    regenerated["not_serialized"] = True
    original_pretty_json = publication._pretty_json

    def stable_pretty_json(payload):
        if payload is regenerated:
            return original_pretty_json(statistics)
        return original_pretty_json(payload)

    monkeypatch.setattr(publication, "analyze_efficiency", lambda *_args: regenerated)
    monkeypatch.setattr(publication, "_pretty_json", stable_pretty_json)
    with pytest.raises(BenchmarkV4SchemaError, match="v4_publication_recompute_mismatch"):
        publication._verify_v4_results(companion_copy, evidence)


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        (b"[]\n", "v4_source_run_invalid"),
        (b"{\n", "v4_source_run_invalid"),
    ],
)
def test_compact_run_loader_rejects_invalid_records(tmp_path, raw, error):
    path = tmp_path / "runs.jsonl"
    path.write_bytes(raw)
    with pytest.raises(BenchmarkV4SchemaError, match=error):
        tuple(publication._iter_compact_runs(tmp_path, (path.name,)))

    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_run_invalid"):
        tuple(publication._iter_compact_runs(tmp_path, ("missing.jsonl",)))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"entries": "bad"},
        {"entries": [None]},
        {"entries": [{"evidence_ids": [], "method": "GET", "status": True, "target_digest": "x"}]},
        {"entries": [{"evidence_ids": "bad", "method": "GET", "status": 200, "target_digest": "x"}]},
    ],
)
def test_compact_ledger_loader_rejects_invalid_records(tmp_path, payload):
    path = tmp_path / "ledgers.jsonl"
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_ledger_invalid"):
        tuple(publication._iter_compact_ledgers(tmp_path, (path.name,)))


def test_compact_ledger_loader_rejects_malformed_or_missing_files(tmp_path):
    path = tmp_path / "ledgers.jsonl"
    path.write_text("{\n", encoding="utf-8")
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_ledger_invalid"):
        tuple(publication._iter_compact_ledgers(tmp_path, (path.name,)))
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_ledger_invalid"):
        tuple(publication._iter_compact_ledgers(tmp_path, ("missing.jsonl",)))


def test_artifact_names_and_checksum_parser_guards(tmp_path):
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_publication_invalid"):
        publication._artifact_names("other.jsonl", prefix="runs")
    with pytest.raises(BenchmarkV4SchemaError, match="v4_source_publication_invalid"):
        publication._artifact_names([], prefix="runs")

    with pytest.raises(BenchmarkV4SchemaError, match="v4_publication_checksums_missing"):
        publication._read_checksums(tmp_path / "missing")
    checksum_path = tmp_path / "SHA256SUMS"
    checksum_path.write_text("bad\n", encoding="utf-8")
    with pytest.raises(BenchmarkV4SchemaError, match="v4_publication_checksums_invalid"):
        publication._read_checksums(checksum_path)


def test_projection_sort_key_rejects_unscheduled_projection():
    _source_plan, plan, *_rest = _canary_inputs()
    projection = SimpleNamespace(
        block_key=("not-scheduled", 1, 1),
        run_id="run",
        system_id="alpha",
    )
    with pytest.raises(BenchmarkV4SchemaError, match="v4_projection_not_in_schedule"):
        publication._projection_sort_key(plan, projection)
