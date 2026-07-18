"""System-manifest and bounded command-adapter contract tests."""

from __future__ import annotations

import json
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from core.benchmarks import load_scenario
from core.benchmarks.competitors import (
    CommandSystemRunner,
    CompetitorSchemaError,
    SystemManifest,
    SystemProtocolError,
    SystemUnavailableError,
    load_system_manifest,
    load_system_manifests,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

SCENARIO_PATH = (
    Path(__file__).parents[2]
    / "benchmarks"
    / "scenarios"
    / "01-service-discovery-verification.json"
)
JSON_SCHEMA_PATH = (
    Path(__file__).parents[2]
    / "docs"
    / "schemas"
    / "benchmark-system-v1.schema.json"
)


def _manifest_payload(argv: list[str]) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "system_id": "example-system",
        "name": "Example System",
        "version": "2.1.0",
        "source_revision": "abc123",
        "track": "framework_only",
        "execution_mode": "replay",
        "fairness_profile": {
            "profile_id": "shared-replay-v1",
            "same_model": True,
            "same_tool_versions": True,
            "same_hardware": True,
            "same_budgets": True,
        },
        "model": {
            "provider": "deterministic",
            "name": "fixture",
            "parameters": {"temperature": 0},
        },
        "tool_versions": {"adapter": "1.0"},
        "adapter": {
            "kind": "command",
            "argv": argv,
            "working_directory": ".",
            "environment_passthrough": ["COMPETITOR_TEST_SECRET"],
        },
        "metadata": {"publisher": "test"},
    }


def _write_manifest(tmp_path: Path, payload: dict[str, object]) -> Path:
    destination = tmp_path / "system.json"
    destination.write_text(json.dumps(payload), encoding="utf-8")
    return destination


def test_portable_manifest_schema_matches_runtime_canonical_keys() -> None:
    schema = json.loads(JSON_SCHEMA_PATH.read_text(encoding="utf-8"))
    adapter_schema = schema["properties"]["adapter"]
    manifest = SystemManifest.from_dict(
        _manifest_payload(
            ["adapter", "{scenario_path}", "{output_path}"]
        )
    )

    assert schema["properties"]["schema_version"] == {"const": "1.0"}
    assert schema["properties"]["execution_mode"] == {
        "enum": ["live", "replay"]
    }
    assert set(adapter_schema["required"]) == {
        "kind",
        "argv",
        "working_directory",
        "environment_passthrough",
    }
    assert set(manifest.to_dict()["adapter"]) == set(
        adapter_schema["required"]
    )
    assert "adapter" not in manifest.to_public_dict()


def test_manifest_is_versioned_portable_and_never_serializes_environment_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "never-publish-this-value"
    monkeypatch.setenv("COMPETITOR_TEST_SECRET", secret)
    source = _write_manifest(
        tmp_path,
        _manifest_payload(
            [
                sys.executable,
                "adapter.py",
                "{scenario_path}",
                "{output_path}",
            ]
        ),
    )

    manifest = load_system_manifest(source)
    public = manifest.to_dict()
    encoded = json.dumps(public)

    assert manifest.source_path == source.resolve()
    assert "source_path" not in public
    assert public["adapter"]["working_directory"] == "."
    assert public["adapter"]["environment_passthrough"] == [
        "COMPETITOR_TEST_SECRET"
    ]
    assert secret not in encoded
    assert load_system_manifests(tmp_path) == (manifest,)


def test_manifest_rejects_unsafe_placeholders_secrets_and_false_framework_parity() -> None:
    payload = _manifest_payload(
        ["adapter", "{scenario_path}", "{output_path}", "{unknown}"]
    )
    with pytest.raises(CompetitorSchemaError, match="invalid_adapter_placeholder"):
        SystemManifest.from_dict(payload)

    payload = _manifest_payload(["adapter", "{scenario_path}"])
    with pytest.raises(CompetitorSchemaError, match="missing_adapter_placeholders"):
        SystemManifest.from_dict(payload)

    payload = _manifest_payload(["adapter", "{scenario_path}", "{output_path}"])
    payload["model"]["parameters"] = {"api_key": "sensitive"}
    with pytest.raises(CompetitorSchemaError, match="secret_bearing_public_key"):
        SystemManifest.from_dict(payload)

    payload = _manifest_payload(["adapter", "{scenario_path}", "{output_path}"])
    payload["fairness_profile"]["same_model"] = False
    with pytest.raises(CompetitorSchemaError, match="framework_track_requires_parity"):
        SystemManifest.from_dict(payload)


def test_command_runner_passes_only_allowlisted_environment_and_normalizes_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = tmp_path / "adapter.py"
    adapter.write_text(
        """\
import json
import os
import sys

scenario = json.load(open(sys.argv[1], encoding="utf-8"))
payload = {
    "status": "succeeded",
    "actions": ["replay_service_discovery", "verify_service"],
    "reported_findings": ["ssh_service", "https_service"],
    "verified_findings": ["ssh_service"],
    "coverage_gaps": [],
    "metrics": {
        "allowlisted_environment": float(os.environ.get("COMPETITOR_TEST_SECRET") == "available"),
        "undeclared_environment_absent": float("COMPETITOR_UNDECLARED" not in os.environ),
        "seed_matches": float(os.environ["OCTOPUS_BENCHMARK_SEED"] == "101"),
        "scenario_matches": float(scenario["scenario_id"] == "service-discovery-verification"),
    },
    "artifact_refs": ["artifact://example/result"],
}
json.dump(payload, open(sys.argv[2], "w", encoding="utf-8"))
""",
        encoding="utf-8",
    )
    source = _write_manifest(
        tmp_path,
        _manifest_payload(
            [sys.executable, "adapter.py", "{scenario_path}", "{output_path}"]
        ),
    )
    monkeypatch.setenv("COMPETITOR_TEST_SECRET", "available")
    monkeypatch.setenv("COMPETITOR_UNDECLARED", "must-not-pass")
    scenario = load_scenario(SCENARIO_PATH)

    result = CommandSystemRunner(load_system_manifest(source))(scenario, 1, 101)

    assert result["status"] == "succeeded"
    assert result["actions"] == ["replay_service_discovery", "verify_service"]
    assert result["metrics"] == {
        "allowlisted_environment": 1.0,
        "scenario_matches": 1.0,
        "seed_matches": 1.0,
        "undeclared_environment_absent": 1.0,
    }
    assert result["duration_seconds"] >= 0
    assert "available" not in json.dumps(
        CommandSystemRunner(load_system_manifest(source)).public_metadata()
    )


def test_runner_enforces_action_output_and_timeout_budgets(tmp_path: Path) -> None:
    scenario = load_scenario(SCENARIO_PATH)
    adapter = tmp_path / "adapter.py"
    adapter.write_text(
        """\
import json
import sys

json.dump({"actions": ["replay_service_discovery"] * 9}, open(sys.argv[2], "w"))
""",
        encoding="utf-8",
    )
    manifest = load_system_manifest(
        _write_manifest(
            tmp_path,
            _manifest_payload(
                [sys.executable, "adapter.py", "{scenario_path}", "{output_path}"]
            ),
        )
    )
    with pytest.raises(SystemProtocolError, match=r"^system_protocol_error$"):
        CommandSystemRunner(manifest)(scenario, 1, 101)

    adapter.write_text(
        """\
import sys
import time

print("x" * 10000)
time.sleep(1)
""",
        encoding="utf-8",
    )
    with pytest.raises(SystemProtocolError, match=r"^system_protocol_error$"):
        CommandSystemRunner(manifest, max_output_bytes=128)(scenario, 1, 101)

    adapter.write_text("import time\ntime.sleep(2)\n", encoding="utf-8")
    result = CommandSystemRunner(manifest, timeout_seconds=0.05)(scenario, 1, 101)
    assert result["status"] == "timeout"
    assert result["actions"] == []
    assert result["error_class"] == "AdapterWallTimeout"


def test_runner_preserves_result_written_during_bounded_completion_grace(
    tmp_path: Path,
) -> None:
    scenario = load_scenario(SCENARIO_PATH)
    scenario = replace(
        scenario,
        budgets={**scenario.budgets, "max_seconds": 0.1},
    )
    adapter = tmp_path / "adapter.py"
    adapter.write_text(
        """\
import json
import sys
import time

time.sleep(0.2)
json.dump(
    {
        "status": "succeeded",
        "reported_findings": ["ssh_service"],
        "metrics": {"adapter_result_preserved": 1},
    },
    open(sys.argv[2], "w"),
)
""",
        encoding="utf-8",
    )
    manifest = load_system_manifest(
        _write_manifest(
            tmp_path,
            _manifest_payload(
                [sys.executable, "adapter.py", "{scenario_path}", "{output_path}"]
            ),
        )
    )

    started = time.monotonic()
    result = CommandSystemRunner(manifest)(scenario, 1, 101)
    elapsed = time.monotonic() - started

    assert result["status"] == "timeout"
    assert result["error_class"] == "AdapterExecutionDeadlineExceeded"
    assert result["reported_findings"] == ["ssh_service"]
    assert result["metrics"] == {"adapter_result_preserved": 1.0}
    assert result["duration_seconds"] == pytest.approx(0.1)
    assert elapsed < 2.0


def test_explicit_runner_timeout_remains_an_absolute_wall_cap(
    tmp_path: Path,
) -> None:
    scenario = load_scenario(SCENARIO_PATH)
    adapter = tmp_path / "adapter.py"
    adapter.write_text("import time\ntime.sleep(2)\n", encoding="utf-8")
    manifest = load_system_manifest(
        _write_manifest(
            tmp_path,
            _manifest_payload(
                [sys.executable, "adapter.py", "{scenario_path}", "{output_path}"]
            ),
        )
    )

    started = time.monotonic()
    result = CommandSystemRunner(manifest, timeout_seconds=0.05)(scenario, 1, 101)
    elapsed = time.monotonic() - started

    assert result["status"] == "timeout"
    assert result["error_class"] == "AdapterWallTimeout"
    assert result["duration_seconds"] == pytest.approx(0.05)
    assert elapsed < 1.0


def test_unavailable_adapter_error_never_exposes_command_or_environment(
    tmp_path: Path,
) -> None:
    sensitive_executable = "/missing/secret-bearing-adapter-name"
    manifest = load_system_manifest(
        _write_manifest(
            tmp_path,
            _manifest_payload(
                [sensitive_executable, "{scenario_path}", "{output_path}"]
            ),
        )
    )

    with pytest.raises(SystemUnavailableError) as failure:
        CommandSystemRunner(manifest)(load_scenario(SCENARIO_PATH), 1, 101)

    assert str(failure.value) == "system_unavailable"
    assert sensitive_executable not in str(failure.value)
    assert "COMPETITOR_TEST_SECRET" not in str(failure.value)
