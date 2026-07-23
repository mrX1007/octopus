"""Connected Benchmark v3 launcher, runner, lab, and publication contracts."""

from __future__ import annotations

import csv
import json
import os
import re
import sys
from pathlib import Path

import pytest

from core.ai.evidence import RegexParser
from core.benchmarks.competitors import adapter as adapter_module
from core.benchmarks.competitors import labctl, launch
from core.benchmarks.competitors.campaign import CampaignConfig, run_campaign
from core.benchmarks.competitors.lab import ResetAttestation
from core.benchmarks.competitors.runner import (
    CommandSystemRunner,
    SystemProtocolError,
)
from core.benchmarks.competitors.schema import SystemManifest
from core.benchmarks.competitors.v3_integration import prepare_fixture_run
from core.benchmarks.v3 import (
    ControlPlaneLedger,
    FixtureRuntime,
    build_analysis_plan,
    freeze_analysis_plan,
    load_analysis_plan,
    verify_v3_results,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

_TOKEN = re.compile(r"OCTOBENCH_V3_[A-Z0-9]{16,160}")
_V3_DEFINITION = launch._CAMPAIGN_DEFINITIONS[
    launch._SMALL_MODEL_CAMPAIGN_V3_DEFINITION_ID
]


def _scenario_payload(repetitions: int = 5) -> dict:
    payloads = launch._generated_v3_scenario_payloads(
        repetitions,
        campaign_definition=_V3_DEFINITION,
    )
    return payloads["scenarios/deep-navigation-v3.json"]


def _manifest_payload(system_id: str, *, argv: list[str] | None = None) -> dict:
    return {
        "schema_version": "1.0",
        "system_id": system_id,
        "name": system_id.upper(),
        "version": "1.0",
        "source_revision": "a" * 40,
        "execution_mode": "replay",
        "track": "full_system",
        "fairness_profile": {
            "profile_id": "small-model-stress-v3-test",
            "same_model": True,
            "same_tool_versions": False,
            "same_hardware": True,
            "same_budgets": False,
        },
        "model": {
            "provider": "fixture",
            "name": "shared-model",
            "parameters": {},
        },
        "tool_versions": {"command-adapter-protocol": "1.1-v3-claims"},
        "adapter": {
            "kind": "command",
            "argv": argv
            or [
                sys.executable,
                "-c",
                "raise SystemExit(0)",
                "{scenario_path}",
                "{output_path}",
            ],
            "working_directory": ".",
            "environment_passthrough": [],
        },
        "metadata": {"benchmark_v3_track_id": "small-model-stress-v3"},
    }


def _small_model_environment() -> dict[str, str]:
    model = launch._SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL
    return {
        "OCTOBENCH_ACK_AUTHORIZED": "YES",
        "OCTOBENCH_ACK_ISOLATED_HOST": "YES",
        "OCTOPUS_OLLAMA_URL": "http://127.0.0.1:11434/api/generate",
        "OCTOPUS_OLLAMA_MODEL": model,
        "OCTOBENCH_OLLAMA_CONTEXT_LENGTH": "65536",
        "OCTOBENCH_OLLAMA_SERVER_VERSION": "0.18.3",
        "OCTOBENCH_OLLAMA_NUM_PARALLEL": "1",
        "OCTOBENCH_OLLAMA_MAX_LOADED_MODELS": "1",
        "OCTOBENCH_OLLAMA_FLASH_ATTENTION": "1",
        "OCTOBENCH_OLLAMA_KV_CACHE_TYPE": "q8_0",
        "OCTOBENCH_STRIX_BIN": "/opt/strix/bin/strix",
        "STRIX_IMAGE": launch._STRIX_IMAGE,
        "STRIX_LLM": f"ollama/{model}",
        "LLM_API_BASE": "http://127.0.0.1:11434",
        "OCTOBENCH_V3_BASE_FIXTURE_SEED": "8f" * 32,
    }


def test_v3_launcher_generates_plan_and_twelve_blinded_scenarios(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launch, "ROOT", tmp_path)

    config_path = launch._prepare_generated_campaign(
        "v3-generated-test",
        profile="core",
        environment=_small_model_environment(),
        environment_file=None,
        octopus_revision="b" * 40,
        campaign_definition=_V3_DEFINITION,
    )

    config = json.loads(config_path.read_text(encoding="utf-8"))
    plan = load_analysis_plan(config_path.parent / "analysis-plan.json")
    scenarios = tuple(sorted((config_path.parent / "scenarios").glob("*.json")))
    manifests = [
        json.loads((config_path.parent / f"{system_id}.json").read_text(encoding="utf-8"))
        for system_id in ("octopus", "strix")
    ]

    assert len(scenarios) == 12
    assert plan.repetitions == 12
    assert plan.track_id == "small-model-stress-v3"
    assert config["benchmark_v3"]["analysis_plan"] == str(
        config_path.parent / "analysis-plan.json"
    )
    assert config["benchmark_v3"]["batch_id"] == "batch-1"
    assert config["benchmark_v3"]["host_id"].startswith("host-")
    assert {
        item["tool_versions"]["command-adapter-protocol"] for item in manifests
    } == {"1.1-v3-claims"}
    assert all(
        json.loads(path.read_text(encoding="utf-8"))["ground_truth"]
        == {"expected_findings": [], "forbidden_findings": []}
        for path in scenarios
    )
    assert "8f" * 32 not in json.dumps(
        {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in config_path.parent.rglob("*.json")
        },
        sort_keys=True,
    )


def test_v3_claim_protocol_ignores_raw_observations_and_retains_hallucinations() -> None:
    token = "OCTOBENCH_V3_" + "A" * 32
    claims = adapter_module._extract_v3_reported_claims(
        "\n".join(
            (
                f"raw response: {token}",
                f"Claim: {token}",
                f"Claim: invented admin service {token}",
                "Finding: another invented service",
            )
        )
    )

    assert claims == (
        token,
        f"invented admin service {token}",
        "another invented service",
    )


def test_octopus_v3_claim_projection_uses_only_canonical_final_report() -> None:
    token = "OCTOBENCH_V3_" + "B" * 32

    claims = adapter_module._octopus_v3_reported_claims(
        {
            "machine_report": {
                "sections": {
                    "observations": [
                        {"kind": "benchmark_observation", "detail": token},
                        {
                            "kind": "benchmark_observation",
                            "detail": f"invented admin {token}",
                        },
                        {"kind": "web_endpoint", "detail": "invented endpoint"},
                    ]
                }
            }
        }
    )

    assert claims == (token, f"invented admin {token}", "invented endpoint")
    assert adapter_module._octopus_v3_reported_claims(
        {"machine_report": {"sections": {"observations": []}}}
    ) == ()


def test_octopus_parser_records_exact_v3_nonce_as_an_observation() -> None:
    token = "OCTOBENCH_V3_" + "C" * 32

    facts = RegexParser().parse(
        "read_only_http",
        json.dumps({"evidence": token, "service": "live"}),
        "scan-test",
    )

    assert {
        (fact["type"], fact["value"])
        for fact in facts
        if fact["type"] == "benchmark_observation"
    } == {("benchmark_observation", token)}


def test_octopus_v3_uses_full_tool_budget_without_adapter_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "OCTOBENCH_V3_" + "D" * 32
    observed: dict[str, object] = {}

    class FactStore:
        @staticmethod
        def get_facts(_scan_id, _target):
            return [{"type": "benchmark_observation", "value": token}]

    class Pipeline:
        def __init__(self, _database):
            self.fact_store = FactStore()
            self.tools_run_count = 1

        @staticmethod
        def run_scan(_scan_id, _target, **kwargs):
            observed.update(kwargs)
            return {"status": "done"}

        @staticmethod
        def trace_report(_scan_id, _target):
            return {
                "machine_report": {
                    "sections": {
                        "observations": [
                            {"kind": "benchmark_observation", "detail": token}
                        ]
                    }
                }
            }

    monkeypatch.setattr("core.ai.pipeline.AIPipeline", Pipeline)
    monkeypatch.setattr(
        adapter_module,
        "_octopus_exact_http_probe",
        lambda *_args: pytest.fail("v3 must not run an adapter-side probe"),
    )
    scenario = launch.BenchmarkScenario.from_dict(_scenario_payload())

    outcome = adapter_module._run_octopus(
        scenario,
        "http://127.0.0.1:8080",
        tmp_path,
        timeout=10.0,
        max_output=100_000,
    )

    assert observed["max_tools"] == 40
    assert observed["raw_scan"] == ""
    assert outcome.metrics["tool_calls"] == 1.0
    assert outcome.reported_claims == (token,)


def test_v3_runner_hides_fixture_seed_and_campaign_directory(
    tmp_path: Path,
) -> None:
    generated = tmp_path / "generated" / "campaign"
    generated.mkdir(parents=True)
    (generated / "analysis-plan.json").write_text("private\n", encoding="utf-8")
    observation = tmp_path / "product-view.json"
    product_script = tmp_path / "product.py"
    product_script.write_text(
        """import json
import os
import sys
from pathlib import Path

Path(sys.argv[3]).write_text(
    json.dumps({"cwd": os.getcwd(), "seed": os.environ.get("OCTOPUS_BENCHMARK_SEED")}),
    encoding="utf-8",
)
Path(sys.argv[2]).write_text(
    json.dumps(
        {
            "status": "succeeded",
            "actions": [],
            "reported_claims": [],
            "reported_findings": [],
            "verified_findings": [],
            "coverage_gaps": [],
            "metrics": {},
            "duration_seconds": 0.01,
            "artifact_refs": [],
            "error_class": "",
        }
    ),
    encoding="utf-8",
)
""",
        encoding="utf-8",
    )
    manifest = SystemManifest.from_dict(
        _manifest_payload(
            "alpha",
            argv=[
                sys.executable,
                str(product_script),
                "{scenario_path}",
                "{output_path}",
                str(observation),
            ],
        ),
        source_path=generated / "alpha.json",
    )
    scenario = launch.BenchmarkScenario.from_dict(_scenario_payload())

    result = CommandSystemRunner(manifest)(scenario, 1, 9_223_372_036)
    visible = json.loads(observation.read_text(encoding="utf-8"))

    assert result["status"] == "succeeded"
    assert visible["seed"] is None
    assert Path(visible["cwd"]) != generated
    assert not (Path(visible["cwd"]) / "analysis-plan.json").exists()

    leaking_payload = _manifest_payload(
        "alpha",
        argv=[
            sys.executable,
            "-c",
            "raise SystemExit(0)",
            "{scenario_path}",
            "{output_path}",
            "{seed}",
        ],
    )
    leaking = SystemManifest.from_dict(
        leaking_payload,
        source_path=generated / "leaking.json",
    )
    with pytest.raises(SystemProtocolError):
        CommandSystemRunner(leaking)(scenario, 1, 123)


def test_labctl_v3_reset_prepares_private_fixture_and_binds_only_run_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n", encoding="utf-8")
    observed: dict[str, object] = {}

    class Process:
        pid = 12345

        @staticmethod
        def wait(*, timeout):
            observed["timeout"] = timeout
            return 0

    def popen(argv, **kwargs):
        observed["argv"] = argv
        observed["environment"] = kwargs["env"]
        observed["cwd"] = kwargs["cwd"]
        return Process()

    monkeypatch.setattr(labctl, "_V3_COMPOSE_PATH", compose)
    monkeypatch.setattr(labctl.subprocess, "Popen", popen)
    monkeypatch.setattr(
        labctl,
        "_wait_for_health",
        lambda *_args, **_kwargs: {"lab_version": labctl.V3_LAB_VERSION},
    )

    result = labctl.main(
        [
            "reset",
            "--lab-definition",
            labctl.V3_LAB_VERSION,
            "--scenario-id",
            "deep-navigation-v3",
            "--target",
            "http://127.0.0.1:8080",
            "--campaign-id",
            "campaign-test",
            "--system-id",
            "alpha",
            "--repetition",
            "1",
            "--matched-fixture-seed",
            "12345",
            "--state-directory",
            str(tmp_path / "state"),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    child_environment = observed["environment"]
    assert result == 0
    assert output["fixture_variant_digest"]
    assert isinstance(child_environment, dict)
    run_directory = Path(child_environment["OCTOBENCH_V3_RUN_DIRECTORY"])
    assert (run_directory / "private-fixture.json").stat().st_mode & 0o777 == 0o600
    assert (run_directory / "product-view.json").stat().st_mode & 0o777 == 0o600
    assert child_environment["OCTOBENCH_LAB_SCENARIO_ID"] == "deep-navigation-v3"
    assert "OCTOBENCH_V3_BASE_FIXTURE_SEED" not in child_environment


class _FixtureLab:
    def __init__(self, state_directory: Path) -> None:
        self.state_directory = state_directory
        self.runtimes: dict[tuple[str, str, int, int], FixtureRuntime] = {}

    def reset_and_health(self, context):
        variant, artifacts = prepare_fixture_run(
            self.state_directory,
            campaign_id=context.campaign_id,
            system_id=context.system_id,
            scenario_id=context.scenario_id,
            repetition=context.repetition,
            seed=context.seed,
            base_url="http://127.0.0.1:8080",
        )
        ledger = ControlPlaneLedger(
            variant_digest=variant.variant_digest,
            path=artifacts.ledger,
            fsync=False,
        )
        self.runtimes[
            (
                context.system_id,
                context.scenario_id,
                context.repetition,
                context.seed,
            )
        ] = FixtureRuntime(variant, ledger)
        return ResetAttestation(
            context=context,
            reset_duration_seconds=0.01,
            health_duration_seconds=0.01,
            reset_command_sha256="a" * 64,
            health_command_sha256="b" * 64,
            observed_at=1.0,
        )

    def cleanup(self, _context) -> None:
        return None


def test_v3_campaign_uses_paired_fixtures_and_publishes_task_failures(
    tmp_path: Path,
) -> None:
    repetitions = 12
    campaign_id = "v3-campaign-test"
    scenario_directory = tmp_path / "scenarios"
    scenario_directory.mkdir()
    scenario_payload = _scenario_payload(repetitions)
    (scenario_directory / "deep-navigation-v3.json").write_text(
        json.dumps(scenario_payload),
        encoding="utf-8",
    )
    manifest_paths = []
    for system_id in ("alpha", "beta"):
        path = tmp_path / f"{system_id}.json"
        path.write_text(json.dumps(_manifest_payload(system_id)), encoding="utf-8")
        manifest_paths.append(path)
    plan = build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=("alpha", "beta"),
        scenario_ids=("deep-navigation-v3",),
        repetitions=repetitions,
        base_fixture_seed=73,
        publication_tier="full",
        bootstrap_samples=100,
    )
    plan_path = freeze_analysis_plan(plan, tmp_path / "analysis-plan.json")
    payload = {
        "schema_version": "1.0",
        "campaign_id": campaign_id,
        "system_manifests": [path.name for path in manifest_paths],
        "scenario_directory": scenario_directory.name,
        "output_directory": "publication",
        "state_directory": "journal",
        "repetitions": repetitions,
        "required_environment": [],
        "secret_environment": [],
        "strict_statuses": ["failed", "invalid", "partial", "timeout"],
        "lab": {
            "reset": {
                "argv": [sys.executable, "-c", "raise SystemExit(0)"],
                "working_directory": ".",
            },
            "health": {
                "argv": [sys.executable, "-c", "raise SystemExit(0)"],
                "working_directory": ".",
            },
        },
        "benchmark_v3": {
            "analysis_plan": str(plan_path),
            "batch_id": "batch-test",
            "host_id": "host-test",
            "schema_version": "1.0",
            "state_directory": str(tmp_path / "fixture-state"),
        },
    }
    config_path = tmp_path / "campaign.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    config = CampaignConfig.from_dict(payload, source_path=config_path)
    lab = _FixtureLab(tmp_path / "fixture-state")

    def runner_factory(manifest):
        def runner(scenario, repetition, seed):
            runtime = lab.runtimes[
                (manifest.system_id, scenario.scenario_id, repetition, seed)
            ]
            observed_tokens: list[str] = []
            runtime.handle("GET", "/")
            for route in runtime.variant.routes:
                response = runtime.handle("GET", route.target)
                observed_tokens.extend(
                    token.decode("ascii")
                    for token in re.findall(
                        rb"OCTOBENCH_V3_[A-Z0-9]{16,160}",
                        response.body,
                    )
                )
            claims = list(dict.fromkeys(observed_tokens))
            if manifest.system_id == "alpha" and repetition == 1:
                # Canonical claims are independently verified from controller
                # ledger evidence; products never need private evidence IDs.
                claims = [runtime.variant.truth_claims[0].canonical_text]
            if manifest.system_id == "beta" and repetition == 1:
                claims = []
            status = (
                "partial"
                if manifest.system_id == "beta" and repetition == 2
                else "succeeded"
            )
            return {
                "status": status,
                "actions": [],
                "reported_claims": claims,
                "reported_findings": [],
                "verified_findings": [],
                "coverage_gaps": [],
                "metrics": {
                    "output_bytes": 128.0,
                    "tool_calls": float(len(runtime.variant.routes) + 1),
                },
                "duration_seconds": 0.02,
                "artifact_refs": [],
            }

        return runner

    outcome = run_campaign(
        config,
        environment={"PATH": os.defpath},
        runner_factory=runner_factory,
        lab_controller=lab,
    )

    verification = verify_v3_results(outcome.bundle_path)
    with (outcome.bundle_path / "runs.csv").open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        rows = tuple(csv.DictReader(handle))
    context = json.loads(
        (outcome.bundle_path / "campaign-context.json").read_text(encoding="utf-8")
    )
    run_records = tuple(
        json.loads(line)
        for line in (outcome.bundle_path / "runs.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    ledger_records = tuple(
        json.loads(line)
        for line in (outcome.bundle_path / "ledgers.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    )

    assert outcome.exit_code == 1
    assert outcome.status == "completed_with_failures"
    assert verification["runs"] == repetitions * 2
    assert len(run_records) == repetitions * 2
    assert len(ledger_records) == repetitions * 2
    assert {item["run_id"] for item in run_records} == {
        item["run_id"] for item in ledger_records
    }
    assert all(item["entries"] for item in ledger_records)
    assert sum(row["task_status"] == "completed" for row in rows) == 22
    assert sum(row["task_status"] == "partial" for row in rows) == 1
    assert sum(row["task_status"] == "not_completed" for row in rows) == 1
    assert context["campaign_status"]["task_status_counts"] == {
        "completed": 22,
        "not_completed": 1,
        "partial": 1,
    }
    assert len(context["fixture_reveals"]) == repetitions
    assert all(
        reveal["reveal"]["campaign_closed"] is True
        for reveal in context["fixture_reveals"]
    )
    for repetition, seed in enumerate(
        plan.fixture_seeds["deep-navigation-v3"],
        start=1,
    ):
        paired = [
            row["fixture_variant_digest"]
            for row in rows
            if int(row["repetition"]) == repetition
            and int(row["matched_fixture_seed"]) == seed
        ]
        assert len(paired) == 2
        assert len(set(paired)) == 1


def test_v3_docker_context_is_whitelisted() -> None:
    root = Path(__file__).resolve().parents[2]
    ignore = (
        root
        / "benchmarks"
        / "competitors"
        / "labs"
        / "discovery-lab-v3"
        / "Dockerfile.dockerignore"
    ).read_text(encoding="utf-8")

    assert ignore.splitlines()[0] == "**"
    assert "!core/benchmarks/v3/**" in ignore
    assert not any(
        sensitive in ignore
        for sensitive in ("!.git", "!.benchmark-state", "!venv", "!secrets.env")
    )
