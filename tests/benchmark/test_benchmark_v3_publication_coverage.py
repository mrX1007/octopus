"""Hermetic failure-boundary coverage for benchmark v3 publication."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from core.benchmarks.v3 import (
    BenchmarkV3SchemaError,
    build_analysis_plan,
    generate_fixture_variant,
    publication,
)
from tests.benchmark.test_benchmark_v3_analysis import (
    _canary_inputs,
    _rewrite_checksums,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.unit]


def _plan(*, tier="canary", systems=("alpha", "beta"), repetitions=None):
    if repetitions is None:
        repetitions = 1 if tier == "diagnostic" else 2
    return build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=systems,
        scenario_ids=["deep-navigation-v3"],
        repetitions=repetitions,
        base_fixture_seed=321,
        publication_tier=tier,
        bootstrap_samples=100,
        deadlines_seconds=(5.0, 10.0),
    )


def _inputs(*, tier="canary", systems=("alpha", "beta"), repetitions=None):
    plan = _plan(tier=tier, systems=systems, repetitions=repetitions)
    runs, context, ledgers = _canary_inputs(plan)
    return plan, runs, context, ledgers


def _bundle(tmp_path, name="bundle"):
    plan, runs, context, ledgers = _inputs()
    root = publication.publish_v3_results(
        plan,
        runs,
        tmp_path / name,
        campaign_context=context,
        controller_ledgers=ledgers,
    )
    return root, plan, runs, context, ledgers


def _json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path, payload):
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_csv_record_svg_contract_and_scalar_helpers():
    plan, runs, _context, _ledgers = _inputs()
    csv_text = publication.render_runs_csv(plan, runs)
    assert csv_text.count("\n") == 5
    assert publication.render_run_records(runs).endswith("\n")
    assert publication.svg_contract()["panels"] == list(publication.SVG_PANEL_IDS)
    assert publication._bool(True) == "true"
    assert publication._bool(False) == "false"
    assert publication._empty(None) == ""
    assert publication._empty(1.25) == "1.25"
    assert publication._empty(1) == 1
    assert publication._float(1 / 3) == "0.333333333"
    assert publication._run_sort_key(runs[0])[-1] == runs[0].run_id
    assert runs[0].task_status == runs[0].evaluation.task_status
    assert runs[0].completion_rule_id == runs[0].evaluation.completion_rule_id


def test_render_statistics_svg_rejects_missing_system_contracts():
    plan = _plan()
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_statistics_systems"):
        publication.render_statistics_svg(plan, {"systems": []})
    with pytest.raises(BenchmarkV3SchemaError, match="statistics_missing_system"):
        publication.render_statistics_svg(plan, {"systems": {}})


def test_publish_rejects_diagnostic_track_and_existing_destination(monkeypatch, tmp_path):
    plan, runs, context, ledgers = _inputs(tier="diagnostic")
    with pytest.raises(BenchmarkV3SchemaError, match="diagnostic_runs_are_not_publishable"):
        publication.publish_v3_results(
            plan,
            runs,
            tmp_path / "diagnostic",
            campaign_context=context,
            controller_ledgers=ledgers,
        )

    plan, runs, context, ledgers = _inputs()
    monkeypatch.setattr(
        publication,
        "validate_single_track",
        lambda _runs: SimpleNamespace(track_id="other"),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="publication_track_mismatch"):
        publication.publish_v3_results(
            plan,
            runs,
            tmp_path / "wrong-track",
            campaign_context=context,
            controller_ledgers=ledgers,
        )
    monkeypatch.undo()

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FileExistsError, match="publication_destination_exists"):
        publication.publish_v3_results(
            plan,
            runs,
            existing,
            campaign_context=context,
            controller_ledgers=ledgers,
        )


def test_publish_cleans_temporary_directory_on_failure(monkeypatch, tmp_path):
    plan, runs, context, ledgers = _inputs()
    destination = tmp_path / "failed"
    monkeypatch.setattr(
        publication,
        "freeze_analysis_plan",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("fixture")),
    )
    with pytest.raises(RuntimeError, match="fixture"):
        publication.publish_v3_results(
            plan,
            runs,
            destination,
            campaign_context=context,
            controller_ledgers=ledgers,
        )
    assert not destination.exists()
    assert not list(tmp_path.glob(".failed-tmp-*"))


def test_publish_detects_destination_race(monkeypatch, tmp_path):
    plan, runs, context, ledgers = _inputs()
    destination = tmp_path / "raced"
    original = publication.render_statistics_svg

    def race(*args):
        destination.mkdir()
        return original(*args)

    monkeypatch.setattr(publication, "render_statistics_svg", race)
    with pytest.raises(FileExistsError, match="publication_destination_exists"):
        publication.publish_v3_results(
            plan,
            runs,
            destination,
            campaign_context=context,
            controller_ledgers=ledgers,
        )
    assert destination.is_dir()
    assert not list(tmp_path.glob(".raced-tmp-*"))


def test_repack_rejects_unsafe_or_existing_destinations(tmp_path):
    source, *_rest = _bundle(tmp_path, "source")
    with pytest.raises(ValueError, match="v3_repack_destination_inside_source"):
        publication.repack_v3_results(source, source)
    with pytest.raises(ValueError, match="v3_repack_destination_inside_source"):
        publication.repack_v3_results(source, source / "nested")
    existing = tmp_path / "existing-repack"
    existing.mkdir()
    with pytest.raises(FileExistsError, match="publication_destination_exists"):
        publication.repack_v3_results(source, existing)


def test_repack_cleans_failure_and_detects_destination_race(monkeypatch, tmp_path):
    source, *_rest = _bundle(tmp_path, "source")
    destination = tmp_path / "failed-repack"
    monkeypatch.setattr(
        publication.shutil,
        "copyfile",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture")),
    )
    with pytest.raises(OSError, match="fixture"):
        publication.repack_v3_results(source, destination)
    assert not destination.exists()
    assert not list(tmp_path.glob(".failed-repack-tmp-*"))
    monkeypatch.undo()

    raced = tmp_path / "raced-repack"
    original_verify = publication.verify_v3_results

    def race(root):
        result = original_verify(root)
        raced.mkdir()
        return result

    monkeypatch.setattr(publication, "verify_v3_results", race)
    with pytest.raises(FileExistsError, match="publication_destination_exists"):
        publication.repack_v3_results(source, raced)
    assert raced.is_dir()


def test_verify_rejects_missing_invalid_and_mismatched_checksums(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_checksums_missing"):
        publication.verify_v3_results(empty)

    for index, line in enumerate(
        (
            "bad",
            "g" * 64 + "  file",
            "a" * 64 + "  ",
            "a" * 64 + "  sub/file",
            "a" * 64 + "  file\n" + "b" * 64 + "  file",
        )
    ):
        root = tmp_path / f"bad-checksum-{index}"
        root.mkdir()
        (root / "SHA256SUMS").write_text(line + "\n", encoding="utf-8")
        with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_checksums"):
            publication.verify_v3_results(root)

    root = tmp_path / "set-mismatch"
    root.mkdir()
    (root / "SHA256SUMS").write_text("", encoding="utf-8")
    (root / "extra").write_text("x", encoding="utf-8")
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_file_set_mismatch"):
        publication.verify_v3_results(root)

    root = tmp_path / "digest-mismatch"
    root.mkdir()
    (root / "file").write_text("x", encoding="utf-8")
    (root / "SHA256SUMS").write_text("0" * 64 + "  file\n", encoding="utf-8")
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_checksum_mismatch"):
        publication.verify_v3_results(root)


@pytest.mark.parametrize(
    ("target", "replacement", "error"),
    [
        ("publication.json", "{", "invalid_v3_publication_payload"),
        ("statistics.json", "[]", "v3_publication_contract_mismatch"),
        ("campaign-context.json", "{", "invalid_v3_publication_payload"),
        ("campaign-context.json", "[]", "v3_publication_contract_mismatch"),
    ],
)
def test_verify_rejects_malformed_or_wrong_shape_payloads(
    tmp_path,
    target,
    replacement,
    error,
):
    root, *_rest = _bundle(tmp_path)
    (root / target).write_text(replacement, encoding="utf-8")
    _rewrite_checksums(root)
    with pytest.raises(BenchmarkV3SchemaError, match=error):
        publication.verify_v3_results(root)


def test_verify_rejects_nonmapping_publication_and_artifacts(tmp_path):
    root, *_rest = _bundle(tmp_path, "publication-shape")
    _write_json(root / "publication.json", [])
    _rewrite_checksums(root)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication.verify_v3_results(root)

    root, *_rest = _bundle(tmp_path, "artifact-shape")
    manifest = _json(root / "publication.json")
    manifest["artifacts"] = []
    _write_json(root / "publication.json", manifest)
    _rewrite_checksums(root)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication.verify_v3_results(root)


def test_verify_rejects_contract_file_and_manifest_mismatch(tmp_path):
    root, *_rest = _bundle(tmp_path, "extra-file")
    (root / "extra.txt").write_text("extra", encoding="utf-8")
    _rewrite_checksums(root)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication.verify_v3_results(root)

    root, *_rest = _bundle(tmp_path, "manifest-mismatch")
    manifest = _json(root / "publication.json")
    manifest["analysis_plan_digest"] = "0" * 64
    _write_json(root / "publication.json", manifest)
    _rewrite_checksums(root)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication.verify_v3_results(root)


def test_verify_rejects_csv_statistics_and_visualization_mismatch(tmp_path):
    root, *_rest = _bundle(tmp_path, "csv-mismatch")
    with (root / "runs.csv").open("a", encoding="utf-8") as handle:
        handle.write("\n")
    _rewrite_checksums(root)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_runs_csv_mismatch"):
        publication.verify_v3_results(root)

    root, *_rest = _bundle(tmp_path, "statistics-mismatch")
    statistics = _json(root / "statistics.json")
    statistics["extra"] = True
    _write_json(root / "statistics.json", statistics)
    _rewrite_checksums(root)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_statistics_mismatch"):
        publication.verify_v3_results(root)

    root, *_rest = _bundle(tmp_path, "svg-mismatch")
    with (root / "comparison.svg").open("a", encoding="utf-8") as handle:
        handle.write("<!-- extra -->\n")
    _rewrite_checksums(root)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_visualization_mismatch"):
        publication.verify_v3_results(root)


def test_validate_jsonl_shard_sizes_guards(monkeypatch, tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication._validate_jsonl_shard_sizes(tmp_path, [empty.name])
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_payload"):
        publication._validate_jsonl_shard_sizes(tmp_path, ["missing.jsonl"])

    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first.write_bytes(b"a")
    second.write_bytes(b"b")
    monkeypatch.setattr(publication, "_MAX_JSONL_ARTIFACT_BYTES", 1)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication._validate_jsonl_shard_sizes(tmp_path, [first.name, second.name])

    monkeypatch.setattr(publication, "_MAX_JSONL_ARTIFACT_BYTES", 100)
    monkeypatch.setattr(publication, "_MAX_JSONL_SHARD_BYTES", 0)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_contract_mismatch"):
        publication._validate_jsonl_shard_sizes(tmp_path, [first.name])


def test_iter_jsonl_records_rejects_malformed_nonmapping_missing_and_empty(tmp_path):
    for name, raw in (
        ("bad-utf8.jsonl", b"\xff\n"),
        ("bad-json.jsonl", b"{\n"),
        ("not-mapping.jsonl", b"[]\n"),
        ("empty.jsonl", b""),
    ):
        (tmp_path / name).write_bytes(raw)
        with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_jsonl"):
            tuple(publication._iter_jsonl_records(tmp_path, [name]))
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_payload"):
        tuple(publication._iter_jsonl_records(tmp_path, ["missing.jsonl"]))


def test_canonical_jsonl_and_record_validation_guards(tmp_path):
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_jsonl"):
        publication._canonical_jsonl_line({"bad": object()})
    record = publication._JsonlRecord(
        path=tmp_path / "record.jsonl",
        offset=0,
        raw_line=b'{"a": 1}\n',
        payload={"a": 1},
    )
    with pytest.raises(BenchmarkV3SchemaError, match="mismatch"):
        publication._validate_canonical_shard_record(
            record,
            b'{"a":1}\n',
            first_in_shard=False,
            previous_shard_bytes=None,
            mismatch_error="mismatch",
        )


def test_load_run_projections_rejects_duplicate_sort_key(tmp_path):
    _plan_value, runs, _context, _ledgers = _inputs()
    line = publication._canonical_jsonl_line(runs[0].to_dict())
    (tmp_path / "runs.jsonl").write_bytes(line + line)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_run_records_mismatch"):
        publication._load_run_projections(
            tmp_path,
            ["runs.jsonl"],
            publication_version="1.0",
        )


def test_non_full_publication_rejects_readiness_attestation() -> None:
    plan = SimpleNamespace(publication_tier="canary")
    run = SimpleNamespace(environment={})
    context = {"readiness_attestation": {"status": "ready"}}

    with pytest.raises(BenchmarkV3SchemaError, match="v3_readiness_attestation_mismatch"):
        publication._validate_public_readiness_binding(plan, (run,), context)


def test_validated_run_and_action_projection_guards():
    _plan_value, runs, _context, _ledgers = _inputs()
    payload = runs[0].to_dict()
    payload["action_telemetry"] = "bad"
    with pytest.raises(BenchmarkV3SchemaError, match="invalid:run_telemetry"):
        publication._validated_run_projection(payload)

    with pytest.raises(BenchmarkV3SchemaError, match="invalid:action_telemetry"):
        publication._validated_action_projection([None])
    action = runs[0].action_telemetry[0].to_dict()
    extra = dict(action, extra=True)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_run_records_mismatch"):
        publication._validated_action_projection([extra])
    later = dict(action, event_id="event-later", sequence=2)
    earlier = dict(action, event_id="event-earlier", sequence=1)
    with pytest.raises(BenchmarkV3SchemaError, match="action_telemetry_not_ordered"):
        publication._validated_action_projection([later, earlier])
    duplicate_sequence = dict(action, event_id="event-two")
    with pytest.raises(BenchmarkV3SchemaError, match="duplicate_action_sequence"):
        publication._validated_action_projection([action, duplicate_sequence])
    duplicate_id = dict(action, sequence=1)
    with pytest.raises(BenchmarkV3SchemaError, match="duplicate_action_event_id"):
        publication._validated_action_projection([action, duplicate_id])


def test_fixture_variant_projection_guards():
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_fixture_reveals_missing"):
        publication._fixture_variants({})
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_fixture_reveal"):
        publication._fixture_variants({"fixture_reveals": [None]})
    variant = generate_fixture_variant("deep_navigation", matched_fixture_seed=1)
    reveal = variant.reveal_manifest(campaign_closed=True)
    with pytest.raises(BenchmarkV3SchemaError, match="duplicate_v3_fixture_reveal"):
        publication._fixture_variants({"fixture_reveals": [reveal, reveal]})


def _projection_inputs(*, systems=("alpha", "beta")):
    _plan_value, runs, context, ledgers = _inputs(systems=systems)
    projections = tuple(publication._validated_run_projection(run.to_dict()) for run in runs)
    variants = publication._fixture_variants(context)
    return projections, variants, ledgers


def test_verify_streamed_ledgers_rejects_unknown_duplicate_and_missing_runs(tmp_path):
    projections, variants, ledgers = _projection_inputs(systems=("alpha", "beta"))

    unknown = dict(ledgers[0], run_id="unknown")
    (tmp_path / "unknown.jsonl").write_text(
        publication.canonical_json(unknown) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(BenchmarkV3SchemaError, match="v3_public_ledger_run_set_mismatch"):
        publication._verify_streamed_ledgers(
            tmp_path,
            ["unknown.jsonl"],
            projections,
            publication_version="1.0",
            variants=variants,
        )

    duplicate = publication.canonical_json(ledgers[0]) + "\n"
    (tmp_path / "duplicate.jsonl").write_text(duplicate + duplicate, encoding="utf-8")
    with pytest.raises(BenchmarkV3SchemaError, match="v3_public_ledger_run_set_mismatch"):
        publication._verify_streamed_ledgers(
            tmp_path,
            ["duplicate.jsonl"],
            projections,
            publication_version="1.0",
            variants=variants,
        )

    (tmp_path / "missing.jsonl").write_text(
        publication.canonical_json(ledgers[0]) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(BenchmarkV3SchemaError, match="v3_public_ledger_run_set_mismatch"):
        publication._verify_streamed_ledgers(
            tmp_path,
            ["missing.jsonl"],
            projections,
            publication_version="1.0",
            variants=variants,
        )


def test_verify_streamed_ledger_record_contract_guards():
    projections, variants, ledgers = _projection_inputs()
    run = projections[0]
    record = ledgers[0]
    bad_metadata = dict(record, system_id="other")
    with pytest.raises(BenchmarkV3SchemaError, match="v3_public_ledger_run_mismatch"):
        publication._verify_streamed_ledger_record(bad_metadata, run, variants=variants)
    invalid_entries = dict(record, entries="bad")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_public_ledger_entries"):
        publication._verify_streamed_ledger_record(invalid_entries, run, variants=variants)

    bad_count = replace(run, environment={"controller_ledger_entries": "bad"})
    with pytest.raises(BenchmarkV3SchemaError, match="v3_public_ledger_run_mismatch"):
        publication._verify_streamed_ledger_record(record, bad_count, variants=variants)
    unavailable = replace(run, action_telemetry_available=False)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_public_ledger_run_mismatch"):
        publication._verify_streamed_ledger_record(record, unavailable, variants=variants)


def test_verify_projection_evaluation_missing_material_and_claim_refs():
    projections, variants, _ledgers = _projection_inputs()
    run = projections[0]
    with pytest.raises(BenchmarkV3SchemaError, match="v3_evaluation_audit_material_missing"):
        publication._verify_projection_evaluation(
            run,
            variants={},
            observed_evidence_ids=(),
        )

    claim = run.evaluation.claims[0]
    bad_claim = replace(claim, evidence_refs=("wrong",))
    bad_evaluation = replace(run.evaluation, claims=(bad_claim,))
    bad_run = replace(run, evaluation=bad_evaluation)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_claim_evidence_projection_mismatch"):
        publication._verify_projection_evaluation(
            bad_run,
            variants=variants,
            observed_evidence_ids=(),
        )


def _location(path, raw, *, length=None, offset=0, sort_key=(0,)):
    path.write_bytes(raw)
    return publication._JsonlLocation(
        path=path,
        offset=offset,
        length=len(raw) if length is None else length,
        sort_key=sort_key,
    )


def test_write_repacked_jsonl_shards_rejects_invalid_locations(monkeypatch, tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_jsonl"):
        publication._write_repacked_jsonl_shards([], output, prefix="runs")

    missing = publication._JsonlLocation(
        path=tmp_path / "missing",
        offset=0,
        length=1,
        sort_key=(0,),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_payload"):
        publication._write_repacked_jsonl_shards([missing], output, prefix="runs")

    short = _location(tmp_path / "short", b"{}\n", length=99)
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_payload"):
        publication._write_repacked_jsonl_shards([short], output, prefix="runs")
    malformed = _location(tmp_path / "malformed", b"\xff\n")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_jsonl"):
        publication._write_repacked_jsonl_shards([malformed], output, prefix="runs")
    nonmapping = _location(tmp_path / "nonmapping", b"[]\n")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_jsonl"):
        publication._write_repacked_jsonl_shards([nonmapping], output, prefix="runs")

    good = _location(tmp_path / "good", b'{"a":1}\n')
    monkeypatch.setattr(publication, "_MAX_JSONL_SHARD_BYTES", 1)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_jsonl_record_too_large"):
        publication._write_repacked_jsonl_shards([good], output, prefix="runs")
    monkeypatch.setattr(publication, "_MAX_JSONL_SHARD_BYTES", 100)
    monkeypatch.setattr(publication, "_MAX_JSONL_ARTIFACT_BYTES", 1)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_publication_jsonl_too_large"):
        publication._write_repacked_jsonl_shards([good], output, prefix="runs")


def test_write_repacked_jsonl_shards_rolls_over_and_closes_on_error(monkeypatch, tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    first = _location(tmp_path / "first", b'{"a":1}\n', sort_key=(0,))
    second = _location(tmp_path / "second", b'{"b":2}\n', sort_key=(1,))
    monkeypatch.setattr(publication, "_MAX_JSONL_SHARD_BYTES", 12)
    names = publication._write_repacked_jsonl_shards([first, second], output, prefix="runs")
    assert names == ("runs-0000.jsonl", "runs-0001.jsonl")

    missing = publication._JsonlLocation(
        path=tmp_path / "missing",
        offset=0,
        length=1,
        sort_key=(2,),
    )
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_publication_payload"):
        publication._write_repacked_jsonl_shards([first, missing], output, prefix="again")


def test_campaign_context_validation_guards(monkeypatch):
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_campaign_context"):
        publication._validated_campaign_context([])
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_campaign_context"):
        publication._validated_campaign_context({"bad": object()})
    monkeypatch.setattr(publication, "canonical_json", lambda _value: "[]")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_campaign_context"):
        publication._validated_campaign_context({})
    monkeypatch.setattr(
        publication,
        "canonical_json",
        lambda _value: '{"x":"' + "x" * 8_000_001 + '"}',
    )
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_campaign_context"):
        publication._validated_campaign_context({})


def test_controller_ledger_validation_guards(monkeypatch):
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_controller_ledgers"):
        publication._validated_controller_ledgers("bad")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_controller_ledgers"):
        publication._validated_controller_ledgers([None])
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_v3_controller_ledgers"):
        publication._validated_controller_ledgers([{"bad": object()}])
    monkeypatch.setattr(publication, "_MAX_JSONL_ARTIFACT_BYTES", 1)
    with pytest.raises(BenchmarkV3SchemaError, match="v3_controller_ledgers_too_large"):
        publication._validated_controller_ledgers([{"run_id": "run"}])
    monkeypatch.setattr(publication, "_MAX_JSONL_ARTIFACT_BYTES", 100)
    assert publication._validated_controller_ledgers([{"run_id": "z"}, {"run_id": "a"}]) == (
        {"run_id": "a"},
        {"run_id": "z"},
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (408, "timeout"),
        (504, "timeout"),
        (200, "succeeded"),
        (399, "succeeded"),
        (401, "blocked"),
        (405, "blocked"),
        (500, "failed"),
    ],
)
def test_ledger_action_status_mapping(status, expected):
    assert publication._ledger_action_status(status) == expected


def test_campaign_context_matcher_rejects_shape_and_reveal_contracts(monkeypatch):
    plan, runs, context, _ledgers = _inputs()
    assert publication._campaign_context_matches_plan(context, plan, runs)
    assert not publication._campaign_context_matches_plan({}, plan, runs)
    assert not publication._campaign_context_matches_plan(
        {"fixture_reveals": "bad"},
        plan,
        runs,
    )
    assert not publication._campaign_context_matches_plan(
        {"fixture_reveals": []},
        plan,
        runs,
    )
    assert not publication._campaign_context_matches_plan(
        {"fixture_reveals": [None]},
        plan,
        runs,
    )
    assert not publication._campaign_context_matches_plan(
        {"fixture_reveals": [{}]},
        plan,
        runs,
    )

    duplicate = json.loads(json.dumps(context))
    duplicate["fixture_reveals"].append(duplicate["fixture_reveals"][0])
    assert not publication._campaign_context_matches_plan(duplicate, plan, runs)

    broken = json.loads(json.dumps(context))
    monkeypatch.setattr(
        publication.FixtureVariant,
        "from_private_dict",
        lambda _reveal: (_ for _ in ()).throw(BenchmarkV3SchemaError("fixture")),
    )
    assert not publication._campaign_context_matches_plan(broken, plan, runs)
    monkeypatch.undo()

    missing_seed = json.loads(json.dumps(context))
    missing_seed["fixture_reveals"][0]["generator"].pop("matched_fixture_seed")
    missing_seed["fixture_reveals"][0]["reveal"]["generator_digest"] = publication.stable_digest(
        missing_seed["fixture_reveals"][0]["generator"]
    )
    variant = generate_fixture_variant(
        "deep_navigation",
        matched_fixture_seed=plan.fixture_seeds[plan.scenario_ids[0]][0],
    )
    monkeypatch.setattr(
        publication.FixtureVariant,
        "from_private_dict",
        lambda _reveal: variant,
    )
    assert not publication._campaign_context_matches_plan(missing_seed, plan, runs)


def test_campaign_context_matcher_rejects_final_contract_mismatches():
    plan, runs, context, _ledgers = _inputs()
    for mutate in (
        lambda value: value.update(schema_version="bad"),
        lambda value: value.update(campaign=[]),
        lambda value: value["campaign"]["benchmark_v3"].update(analysis_plan_digest="bad"),
        lambda value: value["campaign"]["benchmark_v3"].update(track_id="bad"),
        lambda value: value["fixture_reveals"].clear(),
    ):
        changed = json.loads(json.dumps(context))
        mutate(changed)
        assert not publication._campaign_context_matches_plan(changed, plan, runs)

    wrong_run = replace(runs[0], fixture_variant_digest="0" * 64)
    assert not publication._campaign_context_matches_plan(context, plan, [wrong_run])


def test_outcome_panel_contract_guards():
    plan = _plan()
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_statistics_system"):
        publication._overall({}, "alpha")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_statistics_overall"):
        publication._overall({"alpha": {}}, "alpha")
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_statistics_outcome"):
        publication._render_outcome_panel(
            {"alpha": {"overall": {"field": []}}},
            ["alpha"],
            ["red"],
            0,
            "field",
            plan,
        )
    with pytest.raises(BenchmarkV3SchemaError, match="invalid_statistics_outcome_counts"):
        publication._render_outcome_panel(
            {"alpha": {"overall": {"field": {"counts": []}}}},
            ["alpha"],
            ["red"],
            0,
            "field",
            plan,
        )


@pytest.mark.parametrize(
    "overall",
    [
        {"metrics": []},
        {"metrics": {"all_scheduled": []}},
        {"metrics": {"all_scheduled": {"verified_recall": []}}},
        {"metrics": {"all_scheduled": {"verified_recall": {"wilson": []}}}},
        {"metrics": {"all_scheduled": {"verified_recall": {"wilson": {"estimate": 0.5, "lower": None, "upper": 0.8}}}}},
    ],
)
def test_recall_panel_contract_guards(overall):
    with pytest.raises(BenchmarkV3SchemaError, match="statistics_missing_verified_recall"):
        publication._render_recall_panel(
            {"alpha": {"overall": overall}},
            ["alpha"],
            ["red"],
            0,
            "",
            _plan(),
        )


def test_recall_panel_renders_unavailable_metric():
    overall = {
        "metrics": {"all_scheduled": {"verified_recall": {"wilson": {"estimate": None, "lower": None, "upper": None}}}}
    }
    fragments = publication._render_recall_panel(
        {"alpha": {"overall": overall}},
        ["alpha"],
        ["red"],
        0,
        "",
        _plan(),
    )
    assert any("unavailable" in item for item in fragments)


def test_duration_panel_contract_guard_and_median_fallback():
    with pytest.raises(BenchmarkV3SchemaError, match="statistics_missing_duration"):
        publication._render_duration_panel(
            {"alpha": {"overall": {"duration": {"available": False}}}},
            ["alpha"],
            ["red"],
            0,
            "",
            _plan(),
        )
    fragments = publication._render_duration_panel(
        {
            "alpha": {
                "overall": {
                    "duration": {
                        "available": True,
                        "restricted_mean_completion_seconds": 2,
                        "median_completion_seconds": None,
                        "completion_events": 0,
                        "sample_size": 1,
                    }
                }
            }
        },
        ["alpha"],
        ["red"],
        0,
        "",
        _plan(),
    )
    assert any("not reached" in item for item in fragments)


def test_sha256_reads_until_eof(tmp_path):
    path = tmp_path / "payload"
    path.write_bytes(b"abc")
    assert publication._sha256(path) == hashlib.sha256(b"abc").hexdigest()
