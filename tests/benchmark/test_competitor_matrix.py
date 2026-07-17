"""Fair competitor matrix orchestration and publication contracts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from core.benchmarks.competitors.__main__ import main as competitor_main
from core.benchmarks.competitors.matrix import (
    publish_competitor_matrix,
    run_competitor_matrix,
)
from core.benchmarks.competitors.schema import (
    CompetitorSchemaError,
    SystemManifest,
)
from core.benchmarks.schema import load_scenario

pytestmark = pytest.mark.benchmark

SCENARIO_PATH = (
    Path(__file__).parents[2]
    / "benchmarks"
    / "scenarios"
    / "01-service-discovery-verification.json"
)


def _manifest(
    system_id: str,
    *,
    track: str = "framework_only",
    model_name: str = "shared-model",
    tool_version: str = "1.0",
    execution_mode: str = "live",
) -> SystemManifest:
    return SystemManifest.from_dict(
        {
            "schema_version": "1.0",
            "system_id": system_id,
            "name": system_id.upper(),
            "version": "2.0",
            "source_revision": "revision-123",
            "track": track,
            "execution_mode": execution_mode,
            "fairness_profile": {
                "profile_id": "same-lab-v1",
                "same_model": True,
                "same_tool_versions": True,
                "same_hardware": True,
                "same_budgets": True,
            },
            "model": {
                "provider": "test-provider",
                "name": model_name,
                "parameters": {"temperature": 0},
            },
            "tool_versions": {"fixture_tool": tool_version},
            "adapter": {
                "kind": "command",
                "argv": [
                    "must-not-be-published",
                    "{scenario_path}",
                    "{output_path}",
                ],
            },
            "metadata": {
                "public_note": "fixture",
            },
        }
    )


def _runner_factory(manifest: SystemManifest):
    def runner(scenario, repetition, _seed):
        expected = list(scenario.ground_truth.get("expected_findings") or [])
        return {
            "status": "succeeded",
            "actions": [scenario.allowed_actions[0]],
            "reported_findings": expected,
            "verified_findings": expected,
            "duration_seconds": float(repetition),
            "metrics": {
                "evidence_completeness": 0.9,
                "no_op_task_rate": 0.1 if manifest.system_id == "alpha" else 0.2,
                "repeated_task_rate": 0.0,
                "api_cost_usd": 0.25,
            },
        }

    return runner


def test_matrix_runs_same_scenario_for_each_system_and_is_order_stable():
    scenario = load_scenario(SCENARIO_PATH)
    manifests = (_manifest("alpha"), _manifest("beta"))

    result = run_competitor_matrix(
        manifests,
        (scenario,),
        repetitions=5,
        runner_factory=_runner_factory,
        clock=lambda: 100.0,
    )
    reversed_result = run_competitor_matrix(
        tuple(reversed(manifests)),
        (scenario,),
        repetitions=5,
        runner_factory=_runner_factory,
        clock=lambda: 100.0,
    )

    assert result.schema_version == "1.0"
    assert result.matrix_id == reversed_result.matrix_id
    assert set(result.aggregates) == {"alpha", "beta"}
    assert all(len(item.runs) == 5 for item in result.aggregates["alpha"].values())
    assert result.completeness == {
        "expected_aggregates": 2,
        "written_aggregates": 2,
        "missing_aggregates": 0,
        "publication_complete": True,
        "total_runs": 10,
        "succeeded_runs": 10,
        "failed_runs": 0,
        "invalid_runs": 0,
        "timeout_runs": 0,
        "partial_runs": 0,
        "policy_violations": 0,
        "error_runs": 0,
    }
    assert {item["duration_median_seconds"] for item in result.summaries} == {3.0}
    assert all("adapter" not in item for item in result.systems)
    assert "must-not-be-published" not in json.dumps(result.to_dict())


def test_publication_is_atomic_checksummed_and_refuses_overwrite(tmp_path):
    scenario = load_scenario(SCENARIO_PATH)
    result = run_competitor_matrix(
        (_manifest("alpha"), _manifest("beta")),
        (scenario,),
        runner_factory=_runner_factory,
        clock=lambda: 100.0,
    )
    destination = publish_competitor_matrix(result, tmp_path / "publication")

    expected_files = {
        "SHA256SUMS",
        "comparison.json",
        "comparison.md",
        f"aggregates/alpha/{scenario.scenario_id}.json",
        f"aggregates/beta/{scenario.scenario_id}.json",
    }
    assert {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file()
    } == expected_files

    checksum_lines = (destination / "SHA256SUMS").read_text().splitlines()
    assert len(checksum_lines) == 4
    for line in checksum_lines:
        digest, relative_path = line.split("  ", 1)
        content = (destination / relative_path).read_bytes()
        assert hashlib.sha256(content).hexdigest() == digest

    markdown = (destination / "comparison.md").read_text()
    assert "live and replay results are never mixed" in markdown
    assert "does not select, rank, or declare an automatic winner" in markdown
    assert "Duration median (s)" in markdown
    assert "Evidence" in markdown
    assert "No-op" in markdown
    assert "Repeat" in markdown
    assert "Cost USD" in markdown
    with pytest.raises(FileExistsError, match="publication_destination_exists"):
        publish_competitor_matrix(result, destination)


@pytest.mark.parametrize(
    ("manifests", "error"),
    [
        ((_manifest("alpha"),), "matrix_requires_at_least_two_systems"),
        (
            (_manifest("alpha"), _manifest("alpha")),
            "duplicate_system_id",
        ),
        (
            (_manifest("alpha"), _manifest("beta", track="full_system")),
            "mixed_track",
        ),
        (
            (_manifest("alpha"), _manifest("beta", model_name="other-model")),
            "framework_only_requires_equal_model_metadata",
        ),
        (
            (_manifest("alpha"), _manifest("beta", tool_version="2.0")),
            "fairness_profile_requires_equal_tool_versions",
        ),
        (
            (_manifest("alpha"), _manifest("beta", execution_mode="replay")),
            "mixed_execution_mode",
        ),
    ],
)
def test_matrix_rejects_unfair_or_ambiguous_inputs(manifests, error):
    scenario = load_scenario(SCENARIO_PATH)

    with pytest.raises(CompetitorSchemaError, match=error):
        run_competitor_matrix(
            manifests,
            (scenario,),
            runner_factory=_runner_factory,
        )


def test_failures_are_publishable_but_trigger_strict_result():
    scenario = load_scenario(SCENARIO_PATH)

    def factory(manifest):
        if manifest.system_id == "beta":
            def fail(*_args):
                raise RuntimeError("adapter failure")

            return fail
        return _runner_factory(manifest)

    result = run_competitor_matrix(
        (_manifest("alpha"), _manifest("beta")),
        (scenario,),
        runner_factory=factory,
        clock=lambda: 100.0,
    )

    assert result.completeness["written_aggregates"] == 2
    assert result.completeness["failed_runs"] == 5
    assert result.has_strict_failures is True


@pytest.mark.parametrize("status", ["timeout", "partial"])
def test_timeout_and_partial_runs_are_published_as_strict_errors(status):
    scenario = load_scenario(SCENARIO_PATH)

    def factory(_manifest):
        def nonconforming(_scenario, _repetition, _seed):
            return {"status": status, "actions": []}

        return nonconforming

    result = run_competitor_matrix(
        (_manifest("alpha"), _manifest("beta")),
        (scenario,),
        runner_factory=factory,
        clock=lambda: 100.0,
    )

    expected_timeout = 10 if status == "timeout" else 0
    expected_partial = 10 if status == "partial" else 0
    assert result.completeness["timeout_runs"] == expected_timeout
    assert result.completeness["partial_runs"] == expected_partial
    assert result.completeness["error_runs"] == 10
    assert result.has_strict_failures is True
    assert {summary["timeout_runs"] for summary in result.summaries} == {
        expected_timeout // 2
    }
    assert {summary["partial_runs"] for summary in result.summaries} == {
        expected_partial // 2
    }
    assert {summary["error_runs"] for summary in result.summaries} == {5}


def test_cli_runs_two_command_adapters_and_publishes_matrix(tmp_path):
    scenario_directory = tmp_path / "scenarios"
    scenario_directory.mkdir()
    (scenario_directory / "service.json").write_text(
        SCENARIO_PATH.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    adapter = tmp_path / "adapter.py"
    adapter.write_text(
        """\
import json
import sys

scenario = json.load(open(sys.argv[1], encoding="utf-8"))
result = {
    "status": "succeeded",
    "actions": [scenario["allowed_actions"][0]],
    "reported_findings": scenario["ground_truth"]["expected_findings"],
    "verified_findings": scenario["ground_truth"]["expected_findings"],
    "metrics": {"evidence_completeness": 1.0},
}
json.dump(result, open(sys.argv[2], "w", encoding="utf-8"))
""",
        encoding="utf-8",
    )
    manifest_paths = []
    for system_id in ("alpha", "beta"):
        payload = _manifest(system_id, execution_mode="replay").to_dict()
        payload["adapter"] = {
            "kind": "command",
            "argv": [
                sys.executable,
                "adapter.py",
                "{scenario_path}",
                "{output_path}",
            ],
            "working_directory": ".",
            "environment_passthrough": [],
        }
        path = tmp_path / f"{system_id}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        manifest_paths.append(path)

    destination = tmp_path / "publication"
    exit_code = competitor_main(
        [
            "--system-manifest",
            str(manifest_paths[0]),
            "--system-manifest",
            str(manifest_paths[1]),
            "--scenario-directory",
            str(scenario_directory),
            "--output-directory",
            str(destination),
            "--repetitions",
            "5",
            "--strict",
        ]
    )

    comparison = json.loads(
        (destination / "comparison.json").read_text(encoding="utf-8")
    )
    assert exit_code == 0
    assert comparison["methodology"]["execution_mode"] == "replay"
    assert comparison["publication"]["succeeded_runs"] == 10
    assert comparison["publication"]["failed_runs"] == 0
    assert (destination / "SHA256SUMS").is_file()
