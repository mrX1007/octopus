"""Hermetic branch coverage for competitor matrix orchestration."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.benchmarks.competitors import matrix

pytestmark = [pytest.mark.unit, pytest.mark.benchmark]


def minimal_result(*, schema_version="1.0") -> matrix.CompetitorMatrixResult:
    return matrix.CompetitorMatrixResult(
        matrix_id="matrix-fixture",
        track="full_system",
        fairness_profile={"profile_id": "fixture"},
        execution_mode="replay",
        repetitions=1,
        systems=(
            {
                "system_id": "system-fixture",
                "display_name": "System Fixture",
                "version": "1.0",
                "source_revision": "revision",
                "model": {"name": "fixture"},
                "tool_versions": {"tool": "1.0"},
            },
        ),
        scenarios=(
            {
                "scenario_id": "scenario-fixture",
                "evaluation_profile": {},
                "tags": [],
                "lab_version": "lab-v1",
                "target_version": "target-v1",
                "budgets": {},
            },
        ),
        aggregates={},
        summaries=(
            {
                "scenario_id": "scenario-fixture",
                "system_id": "system-fixture",
                "status_counts": {"succeeded": 1},
                "duration_median_seconds": 1.0,
                "metric_medians": {},
                "metric_counts": {},
            },
        ),
        completeness={"publication_complete": True},
        generated_at=1.0,
        schema_version=schema_version,
    )


class StubManifest:
    def __init__(self, system_id):
        self.system_id = system_id

    def to_dict(self):
        return {"system_id": self.system_id}


def test_legacy_result_omits_renderings_and_strict_failure_defaults_false() -> None:
    result = minimal_result()
    assert "renderings" not in result.to_dict()
    assert result.has_strict_failures is False


def test_matrix_rejects_repetition_scenario_and_duplicate_scenario_edges() -> None:
    with pytest.raises(matrix.CompetitorSchemaError, match="repetitions_below_minimum"):
        matrix.run_competitor_matrix((), (), repetitions=1)

    manifests = (StubManifest("one"), StubManifest("two"))
    with pytest.raises(matrix.CompetitorSchemaError, match="matrix_requires_scenarios"):
        matrix.run_competitor_matrix(manifests, ())

    duplicate = SimpleNamespace(scenario_id="duplicate")
    with pytest.raises(matrix.CompetitorSchemaError, match="duplicate_scenario_id"):
        matrix.run_competitor_matrix(manifests, (duplicate, duplicate))


def test_legacy_publication_omits_svg(tmp_path) -> None:
    destination = matrix.publish_competitor_matrix(
        minimal_result(),
        tmp_path / "legacy-publication",
    )
    assert (destination / "comparison.json").is_file()
    assert (destination / "comparison.md").is_file()
    assert not (destination / matrix.COMPARISON_SVG_PATH).exists()


def test_publication_race_cleans_temporary_directory(tmp_path, monkeypatch) -> None:
    destination = tmp_path / "raced-publication"
    original_write_json = matrix._write_json

    def racing_write(path, payload):
        original_write_json(path, payload)
        if path.name == "comparison.json":
            destination.mkdir()

    monkeypatch.setattr(matrix, "_write_json", racing_write)
    with pytest.raises(FileExistsError, match="publication_destination_exists"):
        matrix.publish_competitor_matrix(minimal_result(), destination)

    assert destination.is_dir()
    assert not list(tmp_path.glob(".raced-publication-tmp-*"))


def valid_comparison():
    return minimal_result().to_dict()


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda payload: payload.update(schema_version="2.0"), "unsupported_matrix_schema"),
        (lambda payload: payload.update(methodology=[]), "invalid:methodology"),
        (lambda payload: payload.update(publication=[]), "invalid:publication"),
        (lambda payload: payload.update(repetitions=0), "invalid:repetitions"),
    ],
)
def test_markdown_payload_rejects_invalid_top_level_contract(mutation, error) -> None:
    payload = valid_comparison()
    mutation(payload)
    with pytest.raises(matrix.CompetitorSchemaError, match=error):
        matrix.render_comparison_markdown_payload(payload)


def test_legacy_markdown_uses_legacy_headers_without_quality_column() -> None:
    rendered = matrix.render_comparison_markdown_payload(valid_comparison())
    assert "Duration median (s)" in rendered
    assert "Quality n" not in rendered
    assert "comparison.svg" not in rendered


def test_manifest_and_identity_helpers_reject_invalid_shapes() -> None:
    with pytest.raises(matrix.CompetitorSchemaError, match="missing_to_dict"):
        matrix._manifest_payload(object())
    with pytest.raises(matrix.CompetitorSchemaError, match="not_mapping"):
        matrix._manifest_payload(SimpleNamespace(to_dict=list))
    with pytest.raises(matrix.CompetitorSchemaError, match="missing:system_id"):
        matrix._system_id({})


def test_common_value_helpers_reject_missing_and_mixed_values() -> None:
    with pytest.raises(matrix.CompetitorSchemaError, match="missing:track"):
        matrix._common_value(({},), "track")
    with pytest.raises(matrix.CompetitorSchemaError, match="missing:fairness"):
        matrix._common_json_value(({},), "fairness")
    with pytest.raises(matrix.CompetitorSchemaError, match="mixed_fairness"):
        matrix._common_json_value(
            ({"fairness": {"id": "one"}}, {"fairness": {"id": "two"}}),
            "fairness",
        )


def test_framework_and_declared_fairness_optional_paths() -> None:
    payloads_without_models = ({"model": {}}, {"model": {}})
    with pytest.raises(matrix.CompetitorSchemaError, match="requires_model_metadata"):
        matrix._require_equal_framework_models(payloads_without_models)

    matrix._validate_declared_tool_fairness((), None)
    matrix._validate_declared_tool_fairness((), {"same_tool_versions": False})
    matrix._validate_declared_model_fairness((), None)
    matrix._validate_declared_model_fairness((), {"same_model": False})
    with pytest.raises(matrix.CompetitorSchemaError, match="requires_model_metadata"):
        matrix._validate_declared_model_fairness(
            payloads_without_models,
            {"same_model": True},
        )


def test_public_metadata_uses_explicit_source_fallback_and_type_guard(monkeypatch) -> None:
    payload = {
        "system_id": "fixture",
        "version": "1",
        "track": "full_system",
        "fairness_profile": {},
        "execution_mode": "replay",
        "model": {"name": "fixture-model"},
        "public_metadata": {"display_name": "Fixture"},
    }
    public = matrix._public_system_metadata(payload)
    assert public["display_name"] == "Fixture"
    assert public["model_metadata"] == {"name": "fixture-model"}

    monkeypatch.setattr(matrix, "_sanitize_public_metadata", lambda _value: [])
    with pytest.raises(matrix.CompetitorSchemaError, match="invalid:public_metadata"):
        matrix._public_system_metadata(payload)


def test_public_metadata_sanitizer_bounds_sequences_and_unknown_objects() -> None:
    nested = {"level": {"level": {"level": {"level": {"level": {"level": "value"}}}}}}
    assert "[depth-bounded]" in repr(matrix._sanitize_public_metadata(nested))
    assert matrix._sanitize_public_metadata(("one", "two")) == ["one", "two"]
    marker = object()
    assert matrix._sanitize_public_metadata(marker) == str(marker)


@pytest.mark.parametrize("value", ["", ".", ".."])
def test_safe_path_component_rejects_empty_and_reserved_names(value) -> None:
    with pytest.raises(matrix.CompetitorSchemaError, match="unsafe_path_component"):
        matrix._safe_path_component(value)


@pytest.mark.parametrize("value", ["slash/name", "back\\slash", "nul\x00name"])
def test_safe_path_component_rejects_separators(value) -> None:
    with pytest.raises(matrix.CompetitorSchemaError, match="unsafe_path_component"):
        matrix._safe_path_component(value)


def test_mapping_and_formatting_helpers_cover_invalid_and_empty_values() -> None:
    with pytest.raises(matrix.CompetitorSchemaError, match="invalid:items"):
        matrix._mapping_items("not-a-sequence", "items")
    with pytest.raises(matrix.CompetitorSchemaError, match="invalid:items"):
        matrix._mapping_items([{}, "not-a-mapping"], "items")

    assert matrix._compact_json("fixture") == "fixture"
    assert matrix._format_metric(None) == "—"
