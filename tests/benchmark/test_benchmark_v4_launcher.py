"""Prospective launcher and schedule integration for Benchmark v4."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.benchmarks.competitors import launch
from core.benchmarks.competitors.campaign import _build_schedule, load_campaign_config
from core.benchmarks.competitors.schema import load_system_manifest
from core.benchmarks.schema import load_scenarios
from core.benchmarks.v3 import load_analysis_plan
from core.benchmarks.v4 import load_efficiency_plan

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


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
        "OCTOBENCH_V3_BATCH_ID": "batch-v4",
        "OCTOBENCH_V3_HOST_ID": "host-v4",
    }


def test_v4_launcher_freezes_twenty_repetition_efficiency_schedule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    definition = launch._CAMPAIGN_DEFINITIONS[
        launch._SMALL_MODEL_CAMPAIGN_V4_DEFINITION_ID
    ]

    config_path = launch._prepare_generated_campaign(
        "v4-generated-test",
        profile="core",
        environment=_small_model_environment(),
        environment_file=None,
        octopus_revision="b" * 40,
        campaign_definition=definition,
    )

    config_payload = json.loads(config_path.read_text(encoding="utf-8"))
    source_plan = load_analysis_plan(config_path.parent / "analysis-plan.json")
    efficiency_plan = load_efficiency_plan(config_path.parent / "efficiency-plan.json")
    config = load_campaign_config(config_path)
    manifests = tuple(load_system_manifest(path) for path in config.system_manifest_paths)
    scenarios = load_scenarios(config.scenario_directory)
    schedule = _build_schedule(
        config,
        manifests,
        scenarios,
        v3_plan=source_plan,
        efficiency_plan=efficiency_plan,
    )

    assert source_plan.repetitions == efficiency_plan.repetitions == 20
    assert efficiency_plan.source_analysis_plan_digest == source_plan.digest
    assert efficiency_plan.efficiency_track_id == "small-model-efficiency-v4"
    assert len(efficiency_plan.schedule) == 12 * 20
    assert len(schedule) == 12 * 20 * 2
    assert [
        (item["scenario_id"], item["repetition"], item["seed"], item["system_id"])
        for item in schedule
    ] == [
        (block.scenario_id, block.repetition, block.matched_fixture_seed, system_id)
        for block in efficiency_plan.schedule
        for system_id in block.system_order
    ]
    assert config_payload["benchmark_v3"]["efficiency_plan"] == str(
        config_path.parent / "efficiency-plan.json"
    )
    assert config.benchmark_v3 is not None
    assert config.benchmark_v3.public_payload()["efficiency_plan_digest"] == efficiency_plan.digest
    assert "8f" * 32 not in "".join(
        path.read_text(encoding="utf-8")
        for path in sorted(config_path.parent.rglob("*.json"))
    )

    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._campaign_definition(
            launch._SMALL_MODEL_CAMPAIGN_V4_DEFINITION_ID,
            profile="extended",
        )


def test_v3_launcher_contract_does_not_gain_v4_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    definition = launch._CAMPAIGN_DEFINITIONS[
        launch._SMALL_MODEL_CAMPAIGN_V3_DEFINITION_ID
    ]

    config_path = launch._prepare_generated_campaign(
        "v3-compatibility-test",
        profile="core",
        environment=_small_model_environment(),
        environment_file=None,
        octopus_revision="b" * 40,
        campaign_definition=definition,
    )

    config_payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert "efficiency_plan" not in config_payload["benchmark_v3"]
    assert not (config_path.parent / "efficiency-plan.json").exists()
    for system_id in ("octopus", "strix"):
        manifest = json.loads(
            (config_path.parent / f"{system_id}.json").read_text(encoding="utf-8")
        )
        assert "benchmark_v4_efficiency_track_id" not in manifest["metadata"]
