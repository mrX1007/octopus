"""Hermetic branch coverage for competitor system manifests."""

from __future__ import annotations

import json

import pytest

from core.benchmarks.competitors import schema

pytestmark = [pytest.mark.unit, pytest.mark.benchmark]


def adapter_payload(**overrides):
    payload = {
        "kind": "command",
        "argv": ["adapter", "{scenario_path}", "{output_path}"],
    }
    payload.update(overrides)
    return payload


def fairness_payload(**overrides):
    payload = {
        "profile_id": "fixture-profile",
        "same_model": True,
        "same_tool_versions": True,
        "same_hardware": True,
        "same_budgets": True,
    }
    payload.update(overrides)
    return payload


def manifest_payload():
    return {
        "schema_version": "1.0",
        "system_id": "fixture-system",
        "name": "Fixture System",
        "version": "1.0",
        "source_revision": "revision",
        "track": "framework_only",
        "execution_mode": "replay",
        "fairness_profile": fairness_payload(),
        "model": {
            "provider": "fixture",
            "name": "fixture-model",
            "parameters": {"temperature": 0},
        },
        "tool_versions": {"fixture-tool": "1.0"},
        "adapter": adapter_payload(),
        "metadata": {"publisher": "fixture"},
    }


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (adapter_payload(kind="plugin"), "unsupported_adapter_kind"),
        (adapter_payload(argv="adapter"), "invalid:adapter.argv"),
        (adapter_payload(argv=[]), "invalid_length:adapter.argv"),
        (
            adapter_payload(argv=["argument"] * (schema._MAX_ARGUMENTS + 1)),
            "invalid_length:adapter.argv",
        ),
        (
            adapter_payload(working_directory="one", cwd="two"),
            "conflicting:adapter.working_directory",
        ),
        (
            adapter_payload(
                environment_passthrough=["FIRST"],
                env_passthrough=["SECOND"],
            ),
            "conflicting:adapter.environment_passthrough",
        ),
        (
            adapter_payload(environment_passthrough="VARIABLE"),
            "invalid:adapter.env_passthrough",
        ),
        (
            adapter_payload(
                environment_passthrough=[f"VARIABLE_{index}" for index in range(schema._MAX_ENVIRONMENT_NAMES + 1)]
            ),
            "too_many_items:adapter.env_passthrough",
        ),
        (
            adapter_payload(environment_passthrough=["1INVALID"]),
            "invalid_environment_name:adapter.env_passthrough",
        ),
        (
            adapter_payload(environment_passthrough=["OCTOPUS_BENCHMARK_SEED"]),
            "reserved_environment_name",
        ),
    ],
)
def test_adapter_rejects_every_invalid_boundary(payload, error) -> None:
    with pytest.raises(schema.CompetitorSchemaError, match=error):
        schema.CommandAdapterConfig.from_dict(payload)


def test_adapter_aliases_and_duplicate_environment_names_are_canonical() -> None:
    adapter = schema.CommandAdapterConfig.from_dict(
        adapter_payload(
            cwd="nested\\directory",
            env_passthrough=["FIXTURE_ENV", "FIXTURE_ENV"],
        )
    )
    assert adapter.cwd == "nested/directory"
    assert adapter.env_passthrough == ("FIXTURE_ENV",)


def test_fairness_flags_and_optional_notes_are_validated() -> None:
    with pytest.raises(
        schema.CompetitorSchemaError,
        match=r"invalid:fairness_profile\.same_model",
    ):
        schema.FairnessProfile.from_dict(fairness_payload(same_model="yes"))

    profile = schema.FairnessProfile.from_dict(fairness_payload(notes="Explicit fixture note"))
    assert profile.to_dict()["notes"] == "Explicit fixture note"


def test_manifest_rejects_top_level_contract_violations(monkeypatch) -> None:
    invalid_payloads = []

    unsupported = manifest_payload()
    unsupported["schema_version"] = "2.0"
    invalid_payloads.append((unsupported, "unsupported_schema_version"))

    invalid_track = manifest_payload()
    invalid_track["track"] = "mixed"
    invalid_payloads.append((invalid_track, "invalid:track"))

    invalid_mode = manifest_payload()
    invalid_mode["execution_mode"] = "offline"
    invalid_payloads.append((invalid_mode, "invalid:execution_mode"))

    invalid_fairness = manifest_payload()
    invalid_fairness["fairness_profile"] = []
    invalid_payloads.append((invalid_fairness, "invalid:fairness_profile"))

    empty_tools = manifest_payload()
    empty_tools["tool_versions"] = {}
    invalid_payloads.append((empty_tools, "empty:tool_versions"))

    invalid_adapter = manifest_payload()
    invalid_adapter["adapter"] = []
    invalid_payloads.append((invalid_adapter, "invalid:adapter"))

    for payload, error in invalid_payloads:
        with pytest.raises(schema.CompetitorSchemaError, match=error):
            schema.SystemManifest.from_dict(payload)

    monkeypatch.setattr(schema, "_MAX_PUBLIC_MANIFEST_BYTES", 1)
    with pytest.raises(schema.CompetitorSchemaError, match="manifest_too_large"):
        schema.SystemManifest.from_dict(manifest_payload())


def test_manifest_load_failures_shape_and_duplicate_ids(tmp_path) -> None:
    with pytest.raises(schema.CompetitorSchemaError, match="manifest_load_failed"):
        schema.load_system_manifest(tmp_path / "missing.json")

    non_mapping = tmp_path / "non-mapping.json"
    non_mapping.write_text("[]", encoding="utf-8")
    with pytest.raises(schema.CompetitorSchemaError, match="manifest_not_mapping"):
        schema.load_system_manifest(non_mapping)
    non_mapping.unlink()

    for name in ("first.json", "second.json"):
        (tmp_path / name).write_text(
            json.dumps(manifest_payload()),
            encoding="utf-8",
        )
    with pytest.raises(schema.CompetitorSchemaError, match="duplicate_system_id"):
        schema.load_system_manifests(tmp_path)


def test_scalar_and_mapping_helpers_reject_invalid_bounds(monkeypatch) -> None:
    with pytest.raises(schema.CompetitorSchemaError, match="invalid_identifier"):
        schema._identifier("not valid", "fixture")

    for value, error in (
        ("", "missing:fixture"),
        ("nul\x00value", "invalid_text:fixture"),
        ("x" * (schema._MAX_TEXT_BYTES + 1), "text_too_long:fixture"),
    ):
        with pytest.raises(schema.CompetitorSchemaError, match=error):
            schema._text(value, "fixture")

    for value, error in (
        ("nul\x00value", "invalid_text:optional"),
        ("x" * (schema._MAX_TEXT_BYTES + 1), "text_too_long:optional"),
    ):
        with pytest.raises(schema.CompetitorSchemaError, match=error):
            schema._optional_text(value, "optional")
    assert schema._optional_text(" fixture ", "optional") == "fixture"

    with pytest.raises(schema.CompetitorSchemaError, match="invalid:fixture"):
        schema._mapping([], "fixture")
    monkeypatch.setattr(schema, "_MAX_MAPPING_ITEMS", 1)
    with pytest.raises(schema.CompetitorSchemaError, match="too_many_items:fixture"):
        schema._mapping({"one": 1, "two": 2}, "fixture")


def test_bounded_json_covers_depth_numbers_collections_and_types(monkeypatch) -> None:
    with pytest.raises(schema.CompetitorSchemaError, match="json_depth_exceeded"):
        schema._bounded_json(None, depth=schema._MAX_JSON_DEPTH + 1)

    assert schema._bounded_json(1.5, depth=1) == 1.5
    with pytest.raises(schema.CompetitorSchemaError, match="nonfinite_json_number"):
        schema._bounded_json(float("inf"), depth=1)

    assert schema._bounded_json({"nested": [1]}, depth=1) == {"nested": [1]}
    assert schema._bounded_json((1, 2), depth=1) == [1, 2]
    with pytest.raises(schema.CompetitorSchemaError, match="non_json_value"):
        schema._bounded_json(object(), depth=1)

    monkeypatch.setattr(schema, "_MAX_MAPPING_ITEMS", 1)
    with pytest.raises(schema.CompetitorSchemaError, match="too_many_json_items"):
        schema._bounded_json({"one": 1, "two": 2}, depth=1)
    with pytest.raises(schema.CompetitorSchemaError, match="too_many_json_items"):
        schema._bounded_json([1, 2], depth=1)


def test_secret_key_scan_traverses_sequences_without_finding_false_positives() -> None:
    schema._reject_secret_bearing_keys([])
    schema._reject_secret_bearing_keys(
        [
            {"public": "fixture"},
            ("plain",),
        ]
    )


@pytest.mark.parametrize(
    "value",
    [
        "/absolute",
        "../parent",
        "/".join(["part"] * 33),
    ],
)
def test_working_directory_rejects_nonportable_paths(value) -> None:
    with pytest.raises(schema.CompetitorSchemaError, match=r"invalid:adapter\.cwd"):
        schema._working_directory(value)
