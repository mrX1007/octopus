"""Hermetic branch coverage for competitor campaign publication bundles."""

from __future__ import annotations

import json
import math
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.benchmarks.competitors import publication

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

RESULTS = Path(__file__).parents[2] / "benchmarks" / "competitors" / "results"
CURRENT_BUNDLE = RESULTS / "linux-blackbox-small-model-v2-20260721t202413z"
LEGACY_BUNDLE = RESULTS / "linux-blackbox-small-model-v1-20260721t134205z"


class Payload:
    def __init__(self, **values):
        self.values = values

    def to_dict(self):
        return dict(self.values)


def _publish_arguments(destination: Path, *, renderings: bool = True):
    comparison = {
        "schema_version": "1.1",
        "matrix_id": "matrix",
    }
    if renderings:
        comparison["renderings"] = {"comparison_svg": "comparison.svg"}
    matrix = SimpleNamespace(
        matrix_id="matrix",
        aggregates={"system": {"scenario": Payload(value=1)}},
        to_dict=lambda: comparison,
    )
    manifest = SimpleNamespace(
        system_id="system",
        to_public_dict=lambda: {"system_id": "system"},
    )
    scenario = SimpleNamespace(
        scenario_id="scenario",
        to_dict=lambda: {"scenario_id": "scenario"},
    )
    digest = "a" * 64
    return {
        "destination": destination,
        "matrix": matrix,
        "campaign": {"campaign_id": "campaign", "repetitions": 1},
        "fingerprint": "benchmark-campaign://sha256/value",
        "manifests": [manifest],
        "scenarios": [scenario],
        "preflight": {"status": "healthy"},
        "schedule": [{"run_key": digest}],
        "attestations": [
            {"run_key": digest, "status": "healthy"},
            {"run_key": "not-a-digest", "status": "healthy"},
        ],
        "cleanup": {"status": "succeeded"},
        "provenance": {
            "schema_version": "1",
            "fingerprint": "benchmark-campaign://sha256/value",
        },
        "campaign_status": {"status": "succeeded"},
    }


def test_publish_campaign_bundle_writes_both_layouts(monkeypatch, tmp_path):
    verified = []
    monkeypatch.setattr(
        publication,
        "verify_campaign_bundle",
        lambda path: verified.append(Path(path)) or {"status": "verified"},
    )
    monkeypatch.setattr(publication, "render_comparison_markdown", lambda matrix: "markdown\n")
    monkeypatch.setattr(publication, "render_comparison_svg", lambda *args: "<svg/>\n")
    monkeypatch.setattr(publication, "metric_statistics_by_pair", lambda aggregates: {})

    destination = tmp_path / "published"
    assert publication.publish_campaign_bundle(**_publish_arguments(destination)) == destination
    assert destination.is_dir()
    assert (destination / publication.COMPARISON_SVG_PATH).read_text() == "<svg/>\n"
    assert (destination / "aggregates/system/scenario.json").is_file()
    assert (destination / f"attestations/{'a' * 64}.json").is_file()
    assert (destination / "attestations/attestation-000002.json").is_file()
    assert verified

    legacy = tmp_path / "without-rendering"
    args = _publish_arguments(legacy, renderings=False)
    args["manifests"] = []
    args["scenarios"] = []
    args["schedule"] = []
    args["attestations"] = []
    args["matrix"].aggregates = {}
    publication.publish_campaign_bundle(**args)
    assert not (legacy / publication.COMPARISON_SVG_PATH).exists()


def test_publish_refuses_existing_paths_and_cleans_failures(monkeypatch, tmp_path):
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FileExistsError, match="publication_destination_exists"):
        publication.publish_campaign_bundle(**_publish_arguments(existing))

    target = tmp_path / "target"
    target.write_text("target")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(FileExistsError, match="publication_destination_exists"):
        publication.publish_campaign_bundle(**_publish_arguments(link))

    monkeypatch.setattr(publication, "render_comparison_markdown", lambda matrix: "markdown")
    monkeypatch.setattr(publication, "render_comparison_svg", lambda *args: "svg")
    monkeypatch.setattr(publication, "metric_statistics_by_pair", lambda aggregates: {})
    monkeypatch.setattr(
        publication,
        "verify_campaign_bundle",
        lambda path: (_ for _ in ()).throw(publication.CampaignPublicationError("verify failed")),
    )
    destination = tmp_path / "failed"
    with pytest.raises(publication.CampaignPublicationError, match="verify failed"):
        publication.publish_campaign_bundle(**_publish_arguments(destination))
    assert not destination.exists()
    assert not tuple(tmp_path.glob(".failed.tmp-*"))

    raced = tmp_path / "raced"

    def race(_temporary):
        raced.mkdir()
        return {"status": "verified"}

    monkeypatch.setattr(publication, "verify_campaign_bundle", race)
    with pytest.raises(FileExistsError, match="publication_destination_exists"):
        publication.publish_campaign_bundle(**_publish_arguments(raced))
    assert not tuple(tmp_path.glob(".raced.tmp-*"))


def _checksum_directory(root: Path, *, name: str = "payload.txt", content: bytes = b"value") -> Path:
    root.mkdir()
    payload = root / name
    payload.parent.mkdir(parents=True, exist_ok=True)
    payload.write_bytes(content)
    digest = publication._sha256_file(payload)
    (root / "SHA256SUMS").write_text(f"{digest}  {name}\n", encoding="utf-8")
    return root


def test_checksum_structure_and_read_guards(monkeypatch, tmp_path):
    with pytest.raises(publication.CampaignPublicationError, match="checksum_file_missing"):
        publication.verify_campaign_bundle(tmp_path / "missing")
    plain_file = tmp_path / "plain"
    plain_file.write_text("x")
    with pytest.raises(publication.CampaignPublicationError, match="checksum_file_missing"):
        publication.verify_campaign_bundle(plain_file)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(publication.CampaignPublicationError, match="checksum_file_missing"):
        publication.verify_campaign_bundle(linked_root)

    root = _checksum_directory(tmp_path / "read-error")
    original = Path.read_text

    def fail_checksum(path, *args, **kwargs):
        if path.name == "SHA256SUMS":
            raise OSError("unreadable")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_checksum)
    with pytest.raises(publication.CampaignPublicationError, match="checksum_read_failed"):
        publication.verify_campaign_bundle(root)
    monkeypatch.setattr(Path, "read_text", original)

    checksum_link_root = tmp_path / "checksum-link"
    checksum_link_root.mkdir()
    checksum_target = tmp_path / "checksum-target"
    checksum_target.write_text("")
    (checksum_link_root / "SHA256SUMS").symlink_to(checksum_target)
    with pytest.raises(publication.CampaignPublicationError, match="checksum_file_missing"):
        publication.verify_campaign_bundle(checksum_link_root)


@pytest.mark.parametrize(
    ("line", "error"),
    [
        ("broken", "publication_checksum_format_invalid"),
        (f"{'g' * 64}  file", "publication_checksum_format_invalid"),
        (f"{'0' * 64}  /absolute", "publication_checksum_path_invalid"),
        (f"{'0' * 64}  ../escape", "publication_checksum_path_invalid"),
        (f"{'0' * 64}  bad\\name", "publication_checksum_path_invalid"),
        (f"{'0' * 64}  bad\x00name", "publication_checksum_path_invalid"),
        (f"{'0' * 64}  SHA256SUMS", "publication_checksum_path_invalid"),
    ],
)
def test_checksum_line_rejections(tmp_path, line, error):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "SHA256SUMS").write_text(line + "\n", encoding="utf-8")
    with pytest.raises(publication.CampaignPublicationError, match=error):
        publication.verify_campaign_bundle(root)


def test_checksum_duplicates_symlinks_coverage_digest_and_required_files(tmp_path):
    duplicate = _checksum_directory(tmp_path / "duplicate")
    line = (duplicate / "SHA256SUMS").read_text()
    (duplicate / "SHA256SUMS").write_text(line + line)
    with pytest.raises(publication.CampaignPublicationError, match="duplicate_path"):
        publication.verify_campaign_bundle(duplicate)

    symlinked = tmp_path / "symlinked"
    symlinked.mkdir()
    external = tmp_path / "external"
    external.write_text("value")
    (symlinked / "payload.txt").symlink_to(external)
    (symlinked / "SHA256SUMS").write_text(
        f"{publication._sha256_file(external)}  payload.txt\n"
    )
    with pytest.raises(publication.CampaignPublicationError, match="symlink_forbidden"):
        publication.verify_campaign_bundle(symlinked)

    mismatch = _checksum_directory(tmp_path / "coverage")
    (mismatch / "extra.txt").write_text("extra")
    with pytest.raises(publication.CampaignPublicationError, match="coverage_mismatch"):
        publication.verify_campaign_bundle(mismatch)

    digest = _checksum_directory(tmp_path / "digest")
    (digest / "payload.txt").write_text("tampered")
    with pytest.raises(publication.CampaignPublicationError, match="checksum_mismatch"):
        publication.verify_campaign_bundle(digest)

    required = _checksum_directory(tmp_path / "required")
    with pytest.raises(publication.CampaignPublicationError, match="required_file_missing"):
        publication.verify_campaign_bundle(required)


def test_scalar_collection_and_metric_validators(tmp_path):
    valid_json = tmp_path / "valid.json"
    valid_json.write_text('{"a":1}')
    assert publication._read_json_mapping(valid_json) == {"a": 1}
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{")
    with pytest.raises(publication.CampaignPublicationError):
        publication._read_json_mapping(invalid_json)
    invalid_json.write_text("[]")
    with pytest.raises(publication.CampaignPublicationError):
        publication._read_json_mapping(invalid_json)

    assert publication._mapping_sequence([{"a": 1}]) == ({"a": 1},)
    for value in (None, "text", [1]):
        with pytest.raises(publication.CampaignPublicationError):
            publication._mapping_sequence(value)
    assert publication._identity_values([{"id": "a"}], "id") == ("a",)
    for value in ([], [{"id": "a"}, {"id": "a"}], [{"id": "../bad"}]):
        with pytest.raises(publication.CampaignPublicationError):
            publication._identity_values(value, "id")

    assert publication._positive_integer(1) == 1
    with pytest.raises(publication.CampaignPublicationError):
        publication._positive_integer(0)
    assert publication._nonnegative_integer(0) == 0
    with pytest.raises(publication.CampaignPublicationError):
        publication._nonnegative_integer(-1)
    for value in (True, "bad", 1.5):
        with pytest.raises(publication.CampaignPublicationError):
            publication._integer(value)
    assert publication._integer(2) == 2

    assert publication._nonnegative_number(1.5) == 1.5
    for value in (True, "1", math.inf, -1):
        with pytest.raises(publication.CampaignPublicationError):
            publication._nonnegative_number(value)
    assert publication._string_sequence(["a", "b"]) == ("a", "b")
    for value in (None, "a", [1], ["a", "a"]):
        with pytest.raises(publication.CampaignPublicationError):
            publication._string_sequence(value)
    assert publication._metrics_mapping({"score": 1}) == {"score": 1.0}
    with pytest.raises(publication.CampaignPublicationError):
        publication._metrics_mapping([])

    statistics = publication._aggregate_metric_statistics(
        [("failed", {"unused": 1}), ("succeeded", {"score": 1}), ("succeeded", {"score": 3})]
    )
    assert statistics["score"] == {
        "count": 2.0,
        "median": 2.0,
        "variance": 1.0,
        "minimum": 1.0,
        "maximum": 3.0,
    }
    assert "unused" not in statistics


def test_metadata_identity_methodology_and_sanitization_helpers():
    payload = {
        "system_id": "system",
        "version": "1",
        "source_revision": "revision",
        "track": "blackbox",
        "fairness_profile": {"name": "fair"},
        "metadata": {"execution_mode": "local", "token": "private"},
        "model": {"name": "model"},
        "tool_versions": {"tool": "1"},
    }
    metadata = publication._comparison_system_metadata(payload)
    assert metadata["system_id"] == "system"
    assert "token" not in metadata["metadata"]
    missing_model = publication._comparison_system_metadata(
        {
            "system_id": "other",
            "track": "blackbox",
            "fairness_profile": {"name": "fair"},
        }
    )
    assert missing_model["model_metadata"] == {}
    with pytest.raises(publication.CampaignPublicationError):
        publication._comparison_system_metadata([])

    scenario = {
        "scenario_id": "scenario",
        "name": "Scenario",
        "category": "discovery",
        "lab": {"version": "1"},
        "target": {"version": "2"},
        "model": {},
        "tool_versions": {},
        "budgets": {},
        "seed": 0,
        "tags": ["tag"],
        "strategy_config": {"evaluation_profile": {"mode": "strict"}},
    }
    assert publication._comparison_scenario_metadata(scenario)["evaluation_profile"] == {"mode": "strict"}
    scenario["strategy_config"] = {"evaluation_profile": "legacy"}
    assert publication._comparison_scenario_metadata(scenario)["evaluation_profile"] == {}

    systems = {"system": payload}
    methodology = publication._comparison_methodology(systems)
    assert methodology["execution_mode"] == "local"
    assert publication._system_identity(payload).startswith("benchmark-system://sha256/")

    assert publication._execution_mode({"execution_mode": "direct"}) == "direct"
    assert publication._execution_mode({"mode": "mode"}) == "mode"
    assert publication._execution_mode({"runner_mode": "runner"}) == "runner"
    assert publication._execution_mode({"metadata": {"execution_mode": "metadata"}}) == "metadata"
    assert publication._execution_mode({}) == "external_command"
    with pytest.raises(publication.CampaignPublicationError):
        publication._execution_mode({"execution_mode": " "})
    assert publication._model_metadata({"model_metadata": {"a": 1}}) == {"a": 1}
    assert publication._model_metadata({"model": {"b": 2}}) == {"b": 2}
    assert publication._model_metadata({}) == {}

    assert publication._common_value([{"key": "same"}, {"key": "same"}], "key") == "same"
    for values in ([{"key": ""}], [{"key": "a"}, {"key": "b"}]):
        with pytest.raises(publication.CampaignPublicationError):
            publication._common_value(values, "key")
    assert publication._common_json_value([{"key": {"a": 1}}, {"key": {"a": 1}}], "key") == {"a": 1}
    for values in ([{"key": None}], [{"key": ""}], [{"key": 1}, {"key": 2}]):
        with pytest.raises(publication.CampaignPublicationError):
            publication._common_json_value(values, "key")
    assert publication._common_execution_mode([{"mode": "same"}, {"mode": "same"}]) == "same"
    with pytest.raises(publication.CampaignPublicationError):
        publication._common_execution_mode([{"mode": "a"}, {"mode": "b"}])

    nested = {"token": "secret", "safe": {"value": [[[[[["deep"]]]]]]}}
    sanitized = publication._sanitize_public_metadata(nested)
    assert "token" not in sanitized
    assert "[depth-bounded]" in str(sanitized)
    assert publication._sanitize_public_metadata((1, object()))[0] == 1
    assert isinstance(publication._sanitize_public_metadata(object()), str)
    assert publication._sanitize_public_metadata(None) is None
    with pytest.raises(publication.CampaignPublicationError):
        publication._required_mapping([])
    assert publication._required_mapping({"a": 1}) == {"a": 1}


def test_provenance_canonical_secret_and_path_helpers(tmp_path):
    campaign = {"campaign": 1}
    systems = {"system": {"system_id": "system"}}
    scenarios = {"scenario": {"scenario_id": "scenario"}}
    provenance = {
        "schema_version": "1",
        "fingerprint": "fingerprint",
        "controller_source_sha256": "a" * 64,
        "repository_revision": "revision",
        "runtime": {"python": "3"},
        "input_sha256": {"private": "ignored"},
        "environment_sha256": {"secret": "ignored"},
    }
    published = publication._published_provenance(
        provenance,
        campaign=campaign,
        systems=systems,
        scenarios=scenarios,
    )
    assert set(published) == publication._PUBLIC_PROVENANCE_KEYS
    publication._verify_provenance_inputs(
        published,
        campaign=campaign,
        systems=systems,
        scenarios=scenarios,
    )
    with pytest.raises(publication.CampaignPublicationError):
        publication._verify_provenance_inputs(
            {}, campaign=campaign, systems=systems, scenarios=scenarios
        )
    invalid = dict(published)
    invalid["input_sha256"] = {}
    with pytest.raises(publication.CampaignPublicationError):
        publication._verify_provenance_inputs(
            invalid, campaign=campaign, systems=systems, scenarios=scenarios
        )
    invalid = json.loads(json.dumps(published))
    invalid["input_sha256"]["campaign"] = "wrong"
    with pytest.raises(publication.CampaignPublicationError):
        publication._verify_provenance_inputs(
            invalid, campaign=campaign, systems=systems, scenarios=scenarios
        )

    stable = publication._stable_id("namespace", {"a": 1})
    assert stable == f"namespace://sha256/{publication._canonical_digest({'a': 1})}"
    assert publication._json_equal({"b": 2, "a": 1}, {"a": 1, "b": 2})
    assert not publication._json_equal({"a": 1}, {"a": 2})

    root = tmp_path / "canaries"
    root.mkdir()
    (root / "directory").mkdir()
    (root / "safe.txt").write_text("safe")
    publication._scan_secret_canaries(root, [])
    publication._scan_secret_canaries(root, ["", "missing", "missing"])
    (root / "unsafe.txt").write_text("contains canary")
    with pytest.raises(publication.SecretCanaryDetected):
        publication._scan_secret_canaries(root, ["canary"])

    written = tmp_path / "nested" / "payload.json"
    publication._write_json(written, {"value": 1})
    assert json.loads(written.read_text()) == {"value": 1}
    assert publication._sha256_file(written) == publication._canonical_digest(
        json.loads(written.read_text())
    ) or len(publication._sha256_file(written)) == 64

    assert publication._safe_component("safe") == "safe"
    for value in ("", ".", "..", "a/b", "a\\b", "a\x00b"):
        with pytest.raises(publication.CampaignPublicationError, match="unsafe_publication_path"):
            publication._safe_component(value)
    assert publication._is_digest("a" * 64)
    assert not publication._is_digest("a" * 63)
    assert not publication._is_digest("g" * 64)


def _copy_bundle(tmp_path: Path, *, legacy: bool = False) -> Path:
    source = LEGACY_BUNDLE if legacy else CURRENT_BUNDLE
    destination = tmp_path / ("legacy" if legacy else "current")
    shutil.copytree(source, destination)
    return destination


def _observed(root: Path) -> dict[str, Path]:
    return {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }


def _mutate_json(root: Path, relative: str, mutate) -> None:
    path = root / relative
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def _first_aggregate(root: Path) -> str:
    return next((root / "aggregates").glob("*/*.json")).relative_to(root).as_posix()


def _first_attestation(root: Path) -> str:
    return next((root / "attestations").glob("*.json")).relative_to(root).as_posix()


@pytest.mark.parametrize(
    ("relative", "mutate", "error"),
    [
        ("comparison.json", lambda doc: doc.__setitem__("schema_version", "invalid"), "semantic_invalid"),
        ("comparison.json", lambda doc: doc.__setitem__("renderings", {}), "semantic_invalid"),
        ("schedule.json", lambda doc: doc.__setitem__("fingerprint", "invalid"), "semantic_invalid"),
        ("inputs/campaign.json", lambda doc: doc.__setitem__("fingerprint", "different"), "semantic_invalid"),
        ("campaign-status.json", lambda doc: doc.__setitem__("matrix_id", "different"), "semantic_invalid"),
        ("inputs/campaign.json", lambda doc: doc.__setitem__("repetitions", 1), "semantic_invalid"),
        ("schedule.json", lambda doc: doc["runs"][0].__setitem__("order", 99), "semantic_invalid"),
        ("schedule.json", lambda doc: doc["runs"].pop(), "semantic_incomplete"),
        ("inputs/systems/octopus.json", lambda doc: doc.__setitem__("system_id", "different"), "semantic_invalid"),
        ("comparison.json", lambda doc: doc.__setitem__("systems", []), "semantic_invalid"),
        ("comparison.json", lambda doc: doc["systems"][0].__setitem__("version", "wrong"), "semantic_invalid"),
        ("comparison.json", lambda doc: doc.__setitem__("methodology", {}), "semantic_invalid"),
        ("comparison.json", lambda doc: doc.__setitem__("summaries", []), "semantic_invalid"),
        ("campaign-status.json", lambda doc: doc.__setitem__("status_counts", {}), "semantic_invalid"),
        ("campaign-status.json", lambda doc: doc.__setitem__("status", "wrong"), "semantic_invalid"),
    ],
)
def test_semantic_document_rejections(tmp_path, relative, mutate, error):
    root = _copy_bundle(tmp_path)
    _mutate_json(root, relative, mutate)
    with pytest.raises(publication.CampaignPublicationError, match=error):
        publication._verify_semantic_completeness(root, _observed(root))


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("scenario", "semantic_invalid"),
        ("summary_type", "semantic_invalid"),
        ("run_status", "semantic_invalid"),
        ("run_id", "semantic_invalid"),
        ("missing_run", "semantic_incomplete"),
        ("aggregate_id", "semantic_invalid"),
    ],
)
def test_semantic_aggregate_rejections(tmp_path, mutation, error):
    root = _copy_bundle(tmp_path)
    relative = _first_aggregate(root)

    def mutate(document):
        if mutation == "scenario":
            document["scenario"] = {}
        elif mutation == "summary_type":
            document["runs"][0]["result_summary"] = []
        elif mutation == "run_status":
            document["runs"][0]["status"] = "unknown"
        elif mutation == "run_id":
            document["runs"][0]["run_id"] = "wrong"
        elif mutation == "missing_run":
            document["runs"].pop()
        else:
            document["aggregate_id"] = "wrong"

    _mutate_json(root, relative, mutate)
    with pytest.raises(publication.CampaignPublicationError, match=error):
        publication._verify_semantic_completeness(root, _observed(root))


def test_semantic_observed_layout_and_legacy_rendering_guards(tmp_path):
    current = _copy_bundle(tmp_path)
    observed = _observed(current)
    observed.pop(publication.COMPARISON_SVG_PATH)
    with pytest.raises(publication.CampaignPublicationError, match="semantic_incomplete"):
        publication._verify_semantic_completeness(current, observed)

    current = tmp_path / "current-path"
    shutil.copytree(CURRENT_BUNDLE, current)
    observed = _observed(current)
    observed.pop(next(name for name in observed if name.startswith("aggregates/")))
    with pytest.raises(publication.CampaignPublicationError, match="semantic_incomplete"):
        publication._verify_semantic_completeness(current, observed)

    legacy = tmp_path / "legacy-rendering"
    shutil.copytree(LEGACY_BUNDLE, legacy)
    _mutate_json(legacy, "comparison.json", lambda doc: doc.__setitem__("renderings", {}))
    with pytest.raises(publication.CampaignPublicationError, match="semantic_invalid"):
        publication._verify_semantic_completeness(legacy, _observed(legacy))


def test_semantic_matrix_visual_markdown_attestation_and_cleanup_guards(tmp_path):
    matrix = _copy_bundle(tmp_path)

    def change_matrix(document):
        document["matrix_id"] = "different"

    _mutate_json(matrix, "comparison.json", change_matrix)
    _mutate_json(matrix, "campaign-status.json", change_matrix)
    with pytest.raises(publication.CampaignPublicationError, match="semantic_invalid"):
        publication._verify_semantic_completeness(matrix, _observed(matrix))

    svg_missing = tmp_path / "svg-missing"
    shutil.copytree(CURRENT_BUNDLE, svg_missing)
    (svg_missing / publication.COMPARISON_SVG_PATH).unlink()
    observed = _observed(svg_missing)
    observed[publication.COMPARISON_SVG_PATH] = svg_missing / publication.COMPARISON_SVG_PATH
    with pytest.raises(publication.CampaignPublicationError, match="semantic_invalid"):
        publication._verify_semantic_completeness(svg_missing, observed)

    svg_mismatch = tmp_path / "svg-mismatch"
    shutil.copytree(CURRENT_BUNDLE, svg_mismatch)
    (svg_mismatch / publication.COMPARISON_SVG_PATH).write_text("wrong")
    with pytest.raises(publication.CampaignPublicationError, match="visualization_mismatch"):
        publication._verify_semantic_completeness(svg_mismatch, _observed(svg_mismatch))

    markdown_missing = tmp_path / "markdown-missing"
    shutil.copytree(CURRENT_BUNDLE, markdown_missing)
    (markdown_missing / "comparison.md").unlink()
    observed = _observed(markdown_missing)
    observed["comparison.md"] = markdown_missing / "comparison.md"
    with pytest.raises(publication.CampaignPublicationError, match="semantic_invalid"):
        publication._verify_semantic_completeness(markdown_missing, observed)

    markdown_mismatch = tmp_path / "markdown-mismatch"
    shutil.copytree(CURRENT_BUNDLE, markdown_mismatch)
    (markdown_mismatch / "comparison.md").write_text("wrong")
    with pytest.raises(publication.CampaignPublicationError, match="markdown_mismatch"):
        publication._verify_semantic_completeness(markdown_mismatch, _observed(markdown_mismatch))

    attestation = tmp_path / "attestation"
    shutil.copytree(CURRENT_BUNDLE, attestation)
    _mutate_json(
        attestation,
        _first_attestation(attestation),
        lambda doc: doc.__setitem__("status", "failed"),
    )
    with pytest.raises(publication.CampaignPublicationError, match="semantic_invalid"):
        publication._verify_semantic_completeness(attestation, _observed(attestation))

    cleanup = tmp_path / "cleanup"
    shutil.copytree(CURRENT_BUNDLE, cleanup)
    _mutate_json(cleanup, "cleanup.json", lambda doc: doc.__setitem__("status", "unknown"))
    with pytest.raises(publication.CampaignPublicationError, match="semantic_invalid"):
        publication._verify_semantic_completeness(cleanup, _observed(cleanup))

    publication_guard = tmp_path / "publication-guard"
    shutil.copytree(CURRENT_BUNDLE, publication_guard)
    _mutate_json(
        publication_guard,
        "comparison.json",
        lambda doc: doc.__setitem__("publication", {}),
    )
    comparison = json.loads((publication_guard / "comparison.json").read_text())
    (publication_guard / "comparison.md").write_text(
        publication.render_comparison_markdown_payload(comparison),
        encoding="utf-8",
    )
    with pytest.raises(publication.CampaignPublicationError, match="semantic_invalid"):
        publication._verify_semantic_completeness(
            publication_guard,
            _observed(publication_guard),
        )
