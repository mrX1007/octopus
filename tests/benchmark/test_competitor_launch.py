"""One-command Linux competitor campaign launcher tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.benchmarks.competitors import launch
from core.benchmarks.competitors.campaign import load_campaign_config
from core.benchmarks.competitors.schema import load_system_manifest

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

OCTOPUS_REVISION = "0123456789abcdef0123456789abcdef01234567"
STRIX_REVISION = "91d9a847166fe2f82125643d13e099b0d989bbe4"
PENTESTGPT_REVISION = "83ae3647603de8c66229f0877faef77a53f5c8f6"
PENTAGI_REVISION = "a112db206b2fb7866c367c33348f52f5cdc207d0"
SHARED_OLLAMA_MODEL = "qwen3.5:9b"
SHARED_OLLAMA_API_DIGEST = "c" * 64
SHARED_OLLAMA_DIGEST = "sha256:" + SHARED_OLLAMA_API_DIGEST
SHARED_OLLAMA_SIZE = 6_321_987_654
SHARED_OLLAMA_SIZE_VRAM = 10_987_654_321
SHARED_OLLAMA_CONTEXT_LENGTH = 65_536
SHARED_OLLAMA_SERVER_VERSION = "0.18.3"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_reviewed_catalog_matches_launcher_and_bootstrap_pins() -> None:
    root = REPOSITORY_ROOT
    catalog = json.loads(
        (root / "benchmarks" / "competitors" / "catalog.json").read_text(
            encoding="utf-8"
        )
    )
    entries = {item["system_id"]: item for item in catalog["systems"]}
    launcher = {
        item.system_id: item
        for item in launch._system_pins("extended", octopus_revision=OCTOPUS_REVISION)
        if item.system_id != "octopus"
    }
    assert set(launcher) == {"strix", "pentagi"}
    assert launcher["strix"].version == entries["strix"]["tag"]
    assert launcher["strix"].source_revision == entries["strix"]["source_revision"]
    assert launcher["pentagi"].version == entries["pentagi"]["tag"]
    assert launcher["pentagi"].source_revision == launch._PENTAGI_RUNTIME_SOURCE
    assert (
        entries["pentagi"]["source_revision"]
        == PENTAGI_REVISION
        == launch._PENTAGI_REVIEWED_REVISION
    )

    bootstrap = (
        root / "scripts" / "benchmarks" / "bootstrap_competitors_linux.sh"
    ).read_text(encoding="utf-8")
    prefixes = {
        "strix": "STRIX",
        "pentestgpt": "PENTESTGPT",
        "pentagi": "PENTAGI",
        "shannon": "SHANNON",
    }
    for system_id, prefix in prefixes.items():
        entry = entries[system_id]
        assert f'readonly {prefix}_URL="{entry["repository_url"]}.git"' in bootstrap
        assert f'readonly {prefix}_TAG="{entry["tag"]}"' in bootstrap
        assert (
            f'readonly {prefix}_REVISION="{entry["source_revision"]}"' in bootstrap
        )
    assert bootstrap.index("\nrequire_glibc_234\n") < bootstrap.index(
        "\nrequire_command git\n"
    )
    assert "require_command nmap" not in bootstrap
    assert all(
        "Nmap" not in entries[system_id]["requirements"]["commands"]
        for system_id in ("strix", "pentestgpt")
    )
    assert entries["pentestgpt"]["comparison"]["launcher_profiles"] == []
    assert entries["pentestgpt"]["bootstrap"]["default"] is False
    assert "--with-pentestgpt" in bootstrap
    assert entries["strix"]["bootstrap"]["sandbox_image"] == launch._STRIX_IMAGE
    assert f'readonly STRIX_IMAGE="{launch._STRIX_IMAGE}"' in bootstrap
    assert 'docker pull --platform linux/amd64 "$STRIX_IMAGE"' in bootstrap
    assert 'docker image inspect' in bootstrap


def _core_environment() -> dict[str, str]:
    return {
        "OCTOBENCH_ACK_AUTHORIZED": "YES",
        "OCTOBENCH_ACK_ISOLATED_HOST": "YES",
        "OCTOPUS_OLLAMA_URL": "http://127.0.0.1:11434/api/generate",
        "OCTOPUS_OLLAMA_MODEL": SHARED_OLLAMA_MODEL,
        "OCTOBENCH_OLLAMA_CONTEXT_LENGTH": str(SHARED_OLLAMA_CONTEXT_LENGTH),
        "OCTOBENCH_OLLAMA_SERVER_VERSION": SHARED_OLLAMA_SERVER_VERSION,
        "OCTOBENCH_OLLAMA_NUM_PARALLEL": "1",
        "OCTOBENCH_OLLAMA_MAX_LOADED_MODELS": "1",
        "OCTOBENCH_STRIX_BIN": "/opt/strix/bin/strix",
        "STRIX_IMAGE": launch._STRIX_IMAGE,
        "STRIX_LLM": f"ollama/{SHARED_OLLAMA_MODEL}",
        "LLM_API_BASE": "http://127.0.0.1:11434",
    }


def _small_model_environment() -> dict[str, str]:
    model = launch._SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL
    return {
        **_core_environment(),
        "OCTOPUS_OLLAMA_MODEL": model,
        "STRIX_LLM": f"ollama/{model}",
        "OCTOBENCH_OLLAMA_FLASH_ATTENTION": "1",
        "OCTOBENCH_OLLAMA_KV_CACHE_TYPE": "q8_0",
    }


def _extended_environment() -> dict[str, str]:
    return {
        **_core_environment(),
        "OCTOBENCH_PENTAGI_URL": "http://10.20.30.40:8443",
        "OCTOBENCH_PENTAGI_TOKEN": "secret-pentagi-canary-93824",
        "OCTOBENCH_PENTAGI_PROVIDER": "openai",
        "OCTOBENCH_PENTAGI_MODEL": "pentagi-model",
    }


def _write_environment(path: Path, values: dict[str, str], *, mode: int = 0o600) -> Path:
    path.write_text(
        "\n".join(f"{name}={value}" for name, value in values.items()) + "\n",
        encoding="utf-8",
    )
    path.chmod(mode)
    return path


class _OllamaTagsResponse:
    def __init__(self, payload: bytes, *, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def __enter__(self) -> _OllamaTagsResponse:
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self, limit: int) -> bytes:
        return self._payload[:limit]


def _stub_ollama_tags(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
    *,
    context_length: int = SHARED_OLLAMA_CONTEXT_LENGTH,
    server_version: str = SHARED_OLLAMA_SERVER_VERSION,
    process_payload: Any | None = None,
) -> tuple[dict[str, Any], list[Any]]:
    observed: dict[str, Any] = {"requests": [], "timeouts": []}
    handlers: list[Any] = []

    default_process_payload = {
        "models": [
            {
                "name": SHARED_OLLAMA_MODEL,
                "model": SHARED_OLLAMA_MODEL,
                "digest": SHARED_OLLAMA_API_DIGEST,
                "size": SHARED_OLLAMA_SIZE,
                "size_vram": SHARED_OLLAMA_SIZE_VRAM,
                "context_length": context_length,
            }
        ]
    }

    class Opener:
        def open(
            self,
            request: urllib.request.Request,
            *,
            timeout: float,
        ) -> _OllamaTagsResponse:
            path = urllib.parse.urlsplit(request.full_url).path
            observed["requests"].append(request)
            observed["timeouts"].append(timeout)
            if path == "/api/tags":
                response_payload = payload
                observed["request"] = request
                observed["timeout"] = timeout
            elif path == "/api/version":
                response_payload = {"version": server_version}
            elif path == "/api/generate":
                response_payload = {
                    "model": SHARED_OLLAMA_MODEL,
                    "done": True,
                }
            elif path == "/api/ps":
                response_payload = (
                    default_process_payload
                    if process_payload is None
                    else process_payload
                )
            else:  # pragma: no cover - catches accidental endpoint expansion
                raise AssertionError(f"unexpected Ollama path: {path}")
            encoded = (
                response_payload
                if isinstance(response_payload, bytes)
                else json.dumps(response_payload).encode()
            )
            return _OllamaTagsResponse(encoded)

    def build_opener(*configured_handlers: Any) -> Opener:
        handlers.extend(configured_handlers)
        return Opener()

    monkeypatch.setattr(launch.urllib.request, "build_opener", build_opener)
    return observed, handlers


def _prepare_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    monkeypatch.setattr(launch, "_repository_revision", lambda: OCTOPUS_REVISION)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    for name in launch._OPTIONAL_DOCKER_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    source_campaigns = (
        REPOSITORY_ROOT
        / "benchmarks"
        / "competitors"
        / "campaigns"
    )
    destination_campaigns = (
        tmp_path / "benchmarks" / "competitors" / "campaigns"
    )
    for source in source_campaigns.glob("*/scenarios/*.json"):
        destination = destination_campaigns / source.relative_to(source_campaigns)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())


def _runtime_attestations() -> dict[str, dict[str, Any]]:
    attestations = {
        system_id: {
            "attestation": "clean-checkout-and-runtime-artifacts",
            "checkout_revision": revision,
            "source_tree_sha256": character * 64,
            "lock_sha256": character.upper() * 64,
            "executable_sha256": character.swapcase() * 64,
            "source_revision_attested": True,
        }
        for system_id, revision, character in (
            ("octopus", OCTOPUS_REVISION, "a"),
            ("strix", STRIX_REVISION, "b"),
        )
    }
    attestations["strix"]["sandbox_image"] = launch._STRIX_IMAGE
    for system_id in ("octopus", "strix"):
        attestations[system_id]["ollama_model_digest"] = (
            launch._SMALL_MODEL_CAMPAIGN_OLLAMA_DIGEST
        )
    return attestations


def _run_prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    profile: str = "core",
    values: dict[str, str] | None = None,
    campaign_id: str = "campaign-v1",
    campaign_definition: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    _prepare_root(tmp_path, monkeypatch)
    environment_file = _write_environment(
        tmp_path / "campaign.env",
        _core_environment() if values is None else values,
    )
    arguments = [
        "--campaign-id",
        campaign_id,
        "--profile",
        profile,
        "--environment-file",
        str(environment_file),
        "--prepare-only",
    ]
    if campaign_definition is not None:
        arguments.extend(("--campaign-definition", campaign_definition))
    exit_code = launch.main(arguments)
    captured = capsys.readouterr()
    assert exit_code == 0, captured.err
    config_path = Path(captured.out.strip())
    return config_path, json.loads(config_path.read_text(encoding="utf-8"))


def test_core_prepare_generates_exact_pins_commands_and_secret_free_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path, config = _run_prepare(tmp_path, monkeypatch, capsys)
    generated = config_path.parent
    manifests = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in generated.glob("*.json")
        if path.name != "campaign.json"
    }

    assert set(manifests) == {"octopus", "strix"}
    assert {
        name: (payload["version"], payload["source_revision"])
        for name, payload in manifests.items()
    } == {
        "octopus": ("v1.0.0", OCTOPUS_REVISION),
        "strix": ("v1.1.0", STRIX_REVISION),
    }
    expected_python = str(tmp_path / "venv" / "bin" / "python")
    expected_adapter = str(
        tmp_path / "benchmarks" / "competitors" / "run_adapter.py"
    )
    for system_id, payload in manifests.items():
        assert payload["track"] == "full_system"
        assert payload["execution_mode"] == "live"
        assert payload["fairness_profile"] == {
            "profile_id": "linux-blackbox-shared-ollama-v1",
            "same_model": True,
            "notes": (
                "OCTOPUS and Strix use the same neutral Ollama provider, model tag, "
                "weights, server and exact context length; prompts, request APIs and "
                "all other inference defaults remain product-native and distinct."
            ),
            "same_tool_versions": False,
            "same_hardware": True,
            "same_budgets": False,
        }
        assert payload["model"] == {
            "provider": "ollama",
            "name": SHARED_OLLAMA_MODEL,
            "parameters": {"context_length": SHARED_OLLAMA_CONTEXT_LENGTH},
        }
        assert payload["tool_versions"]["ollama"] == SHARED_OLLAMA_SERVER_VERSION
        context_environment_present = (
            "OCTOBENCH_OLLAMA_CONTEXT_LENGTH"
            in payload["adapter"]["environment_passthrough"]
        )
        assert context_environment_present is (system_id == "octopus")
        assert payload["adapter"]["argv"] == [
            expected_python,
            expected_adapter,
            "--system",
            system_id,
            "--scenario",
            "{scenario_path}",
            "--output",
            "{output_path}",
        ]
        assert payload["adapter"]["working_directory"] == "."
        expected_provenance = {
            "attestation": "deferred-to-actual-launch",
            "required_source_revision": payload["source_revision"],
            "source_revision_attested": False,
        }
        if system_id == "strix":
            expected_provenance["sandbox_image"] = launch._STRIX_IMAGE
            assert payload["metadata"]["scan_mode"] == "quick"
            assert payload["tool_versions"]["strix-sandbox-image"] == (
                launch._STRIX_IMAGE
            )
            assert "STRIX_IMAGE" in payload["adapter"]["environment_passthrough"]
            assert "LLM_API_BASE" in payload["adapter"]["environment_passthrough"]
            assert "LLM_API_KEY" not in payload["adapter"]["environment_passthrough"]
        assert payload["metadata"]["runtime_provenance"] == expected_provenance

    assert config_path == (
        tmp_path / ".benchmark-state" / "generated" / "campaign-v1" / "campaign.json"
    )
    assert config["scenario_directory"] == str(
        generated / "scenarios"
    )
    generated_scenario = json.loads(
        (generated / "scenarios" / "authorized-discovery-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert generated_scenario["repetitions"] == 6
    assert config["output_directory"] == str(
        tmp_path / "benchmarks" / "competitors" / "results" / "campaign-v1"
    )
    assert config["state_directory"] == str(
        tmp_path / ".benchmark-state" / "journal"
    )
    assert config["repetitions"] == 6
    assert config["campaign_definition"] == "linux-blackbox-v1"
    assert generated_scenario["budgets"]["max_seconds"] == 300
    loaded_config = load_campaign_config(config_path)
    assert loaded_config.campaign_id == "campaign-v1"
    assert {
        load_system_manifest(path).system_id
        for path in loaded_config.system_manifest_paths
    } == {"octopus", "strix"}
    assert config["secret_environment"] == []
    for command, action in (
        (config["lab"]["reset"], "reset"),
        (config["lab"]["health"], "health"),
        (config["lab"]["cleanup"], "cleanup"),
    ):
        assert command["argv"] == [
            expected_python,
            str(tmp_path / "benchmarks" / "competitors" / "run_lab.py"),
            action,
        ]
        assert command["environment_passthrough"] == [
            "PATH",
            "HOME",
            "OCTOBENCH_TARGET_URL",
            "OCTOBENCH_HOST_IP",
            "OCTOBENCH_LAB_BIND",
            "OCTOBENCH_LAB_PORT",
        ]

    serialized = "\n".join(
        path.read_text(encoding="utf-8") for path in generated.rglob("*.json")
    )
    assert _core_environment()["LLM_API_BASE"] not in serialized
    assert all(
        path.stat().st_mode & 0o777 == 0o600 for path in generated.rglob("*.json")
    )


def test_small_model_campaign_definition_is_frozen_distinct_and_public(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path, config = _run_prepare(
        tmp_path,
        monkeypatch,
        capsys,
        values=_small_model_environment(),
        campaign_id="small-model-v1",
        campaign_definition="linux-blackbox-small-model-v1",
    )
    scenarios = tuple((config_path.parent / "scenarios").glob("*.json"))
    assert [path.name for path in scenarios] == [
        "authorized-discovery-altered-small-model-stress-v1.json"
    ]
    scenario = json.loads(scenarios[0].read_text(encoding="utf-8"))
    assert scenario["scenario_id"] == (
        "authorized-discovery-altered-small-model-stress-v1"
    )
    assert scenario["budgets"]["max_seconds"] == 600
    assert scenario["repetitions"] == 6
    assert scenario["model"] == {
        "provider": "ollama",
        "name": launch._SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL,
        "parameters": {
            "context_length": launch._SMALL_MODEL_CAMPAIGN_OLLAMA_CONTEXT_LENGTH
        },
    }
    assert scenario["tool_versions"]["ollama"] == (
        launch._SMALL_MODEL_CAMPAIGN_OLLAMA_SERVER_VERSION
    )
    assert scenario["strategy_config"]["evaluation_profile"] == {
        "profile_id": "altered-sub-70b-stress-v1",
        "classification": "small-model-stress",
        "vendor_representative": False,
        "model_tag": launch._SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL,
        "model_digest": launch._SMALL_MODEL_CAMPAIGN_OLLAMA_DIGEST,
        "context_length": launch._SMALL_MODEL_CAMPAIGN_OLLAMA_CONTEXT_LENGTH,
    }
    assert scenario["strategy_config"]["runtime_policy"] == {
        "ollama_flash_attention": True,
        "ollama_kv_cache_type": "q8_0",
        "ollama_num_parallel": 1,
        "ollama_max_loaded_models": 1,
        "attestation": "operator-declared-where-api-not-exposed",
    }
    calibration = scenario["strategy_config"]["time_budget_calibration"]
    assert calibration["derived_hard_max_seconds"] == 600
    assert calibration["calibration_scope"] == "engineering-smoke-not-statistical"
    assert calibration["observations_seconds"] == {
        "octopus": 334.237465,
        "strix": 334.265284,
    }
    assert "non-vendor-representative" in scenario["tags"]
    assert config["campaign_definition"] == "linux-blackbox-small-model-v1"
    loaded_config = load_campaign_config(config_path)
    assert loaded_config.campaign_definition == "linux-blackbox-small-model-v1"
    assert loaded_config.fingerprint_payload()["campaign_definition"] == (
        "linux-blackbox-small-model-v1"
    )
    assert loaded_config.public_payload()["campaign_definition"] == (
        "linux-blackbox-small-model-v1"
    )
    assert {
        "OCTOBENCH_OLLAMA_FLASH_ATTENTION",
        "OCTOBENCH_OLLAMA_KV_CACHE_TYPE",
    }.issubset(config["required_environment"])

    for system_id in ("octopus", "strix"):
        manifest = json.loads(
            (config_path.parent / f"{system_id}.json").read_text(encoding="utf-8")
        )
        assert manifest["metadata"]["campaign_definition_id"] == (
            "linux-blackbox-small-model-v1"
        )
        assert manifest["metadata"]["evaluation_scope"] == (
            "altered-small-model-stress"
        )
        assert manifest["metadata"]["vendor_representative"] is False
        assert manifest["fairness_profile"]["profile_id"] == (
            "linux-blackbox-shared-ollama-altered-small-model-v1"
        )
        assert "not a vendor-representative score" in manifest[
            "fairness_profile"
        ]["notes"]


@pytest.mark.parametrize(
    "campaign_definition",
    ("unknown-v1", "../linux-blackbox-v1", "/tmp/linux-blackbox-v1"),
)
def test_campaign_definition_rejects_unknown_or_path_values(
    capsys: pytest.CaptureFixture[str],
    campaign_definition: str,
) -> None:
    assert launch.main(
        [
            "--campaign-id",
            "invalid-definition-v1",
            "--campaign-definition",
            campaign_definition,
            "--prepare-only",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {
        "error": "invalid_campaign_definition"
    }


def test_small_model_campaign_definition_rejects_wrong_profile_or_runtime() -> None:
    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._campaign_definition(
            "linux-blackbox-small-model-v1",
            profile="extended",
        )

    definition = launch._campaign_definition(
        "linux-blackbox-small-model-v1",
        profile="core",
    )
    launch._validate_campaign_definition_configuration(
        definition,
        _small_model_environment(),
    )
    launch._validate_campaign_definition_runtime(
        definition,
        {
            system_id: {
                "ollama_model_digest": launch._SMALL_MODEL_CAMPAIGN_OLLAMA_DIGEST
            }
            for system_id in ("octopus", "strix")
        },
    )
    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._validate_campaign_definition_configuration(
            definition,
            {**_small_model_environment(), "OCTOBENCH_OLLAMA_KV_CACHE_TYPE": "q4_0"},
        )
    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._validate_campaign_definition_runtime(
            definition,
            {
                "octopus": {"ollama_model_digest": "sha256:" + "0" * 64},
                "strix": {
                    "ollama_model_digest": launch._SMALL_MODEL_CAMPAIGN_OLLAMA_DIGEST
                },
            },
        )


def test_extended_profile_adds_exact_pentagi_pin_and_environment_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path, config = _run_prepare(
        tmp_path,
        monkeypatch,
        capsys,
        profile="extended",
        values=_extended_environment(),
        campaign_id="extended-v1",
    )
    pentagi = json.loads(
        (config_path.parent / "pentagi.json").read_text(encoding="utf-8")
    )

    assert pentagi["version"] == "v2.1.0"
    assert pentagi["source_revision"] == launch._PENTAGI_RUNTIME_SOURCE
    assert pentagi["model"] == {
        "provider": "openai",
        "name": "pentagi-model",
        "parameters": {},
    }
    assert set(pentagi["adapter"]["environment_passthrough"]) == {
        "PATH",
        "HOME",
            "OCTOBENCH_TARGET_URL",
            "OCTOBENCH_ACK_AUTHORIZED",
            "OCTOBENCH_ACK_ISOLATED_HOST",
            "OCTOBENCH_PENTAGI_URL",
        "OCTOBENCH_PENTAGI_TOKEN",
        "OCTOBENCH_PENTAGI_PROVIDER",
        "OCTOBENCH_PENTAGI_MODEL",
    }
    assert pentagi["metadata"]["runtime_provenance"] == {
        "attestation": "service-release-provider-model-at-adapter-runtime",
        "service_release": "2.1.0",
        "source_revision_attested": False,
    }
    assert config["secret_environment"] == ["OCTOBENCH_PENTAGI_TOKEN"]
    assert config["repetitions"] == 6
    generated_scenario = json.loads(
        (
            config_path.parent
            / "scenarios"
            / "authorized-discovery-v1.json"
        ).read_text(encoding="utf-8")
    )
    assert generated_scenario["repetitions"] == 6
    serialized = "\n".join(
        path.read_text(encoding="utf-8") for path in config_path.parent.glob("*.json")
    )
    assert _extended_environment()["OCTOBENCH_PENTAGI_TOKEN"] not in serialized


def test_environment_file_requires_exact_private_permissions_and_required_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    environment_file = _write_environment(
        tmp_path / "campaign.env",
        _core_environment(),
        mode=0o644,
    )

    assert launch.main(
        [
            "--campaign-id",
            "permissions-v1",
            "--environment-file",
            str(environment_file),
            "--prepare-only",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {
        "error": "environment_file_permissions"
    }

    values = _core_environment()
    values.pop("LLM_API_BASE")
    _write_environment(environment_file, values)
    assert launch.main(
        [
            "--campaign-id",
            "missing-v1",
            "--environment-file",
            str(environment_file),
            "--prepare-only",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "missing_environment"}

    values = _core_environment()
    values["OCTOBENCH_ACK_ISOLATED_HOST"] = "NO"
    _write_environment(environment_file, values)
    assert launch.main(
        [
            "--campaign-id",
            "isolation-v1",
            "--environment-file",
            str(environment_file),
            "--prepare-only",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "isolation_required"}

    values = _core_environment()
    values["STRIX_IMAGE"] = "ghcr.io/usestrix/strix-sandbox:latest"
    _write_environment(environment_file, values)
    assert launch.main(
        [
            "--campaign-id",
            "wrong-image-v1",
            "--environment-file",
            str(environment_file),
            "--prepare-only",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "invalid_strix_image"}


@pytest.mark.parametrize(
    "updates",
    [
        {"LLM_API_BASE": "http://127.0.0.2:11434"},
        {"LLM_API_BASE": "http://127.0.0.1:11434/api/generate"},
        {"STRIX_LLM": "ollama/another-qwen"},
        {"OCTOPUS_OLLAMA_MODEL": "octopus-qwen", "STRIX_LLM": "ollama/octopus-qwen"},
        {"OCTOPUS_OLLAMA_URL": "http://127.0.0.1:11434/v1"},
        {"OCTOBENCH_OLLAMA_CONTEXT_LENGTH": "2048"},
        {"OCTOBENCH_OLLAMA_CONTEXT_LENGTH": "not-an-integer"},
        {"OCTOBENCH_OLLAMA_SERVER_VERSION": "invalid version"},
        {"OCTOBENCH_OLLAMA_NUM_PARALLEL": "2"},
        {"OCTOBENCH_OLLAMA_MAX_LOADED_MODELS": "2"},
    ],
)
def test_shared_ollama_contract_rejects_mismatched_or_biased_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    updates: dict[str, str],
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    values = {**_core_environment(), **updates}
    environment_file = _write_environment(tmp_path / "campaign.env", values)

    assert launch.main(
        [
            "--campaign-id",
            "invalid-shared-model-v1",
            "--environment-file",
            str(environment_file),
            "--prepare-only",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {
        "error": "invalid_shared_ollama_configuration"
    }


@pytest.mark.parametrize(
    ("octopus_url", "strix_base"),
    [
        (
            "http://127.0.0.1:11434/api/generate/",
            "http://127.0.0.1:11434/",
        ),
        (
            "http://[::1]:11434/api/generate",
            "http://[::1]:11434",
        ),
    ],
)
def test_shared_ollama_contract_accepts_canonical_equivalent_urls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    octopus_url: str,
    strix_base: str,
) -> None:
    values = {
        **_core_environment(),
        "OCTOPUS_OLLAMA_URL": octopus_url,
        "LLM_API_BASE": strix_base,
    }

    config_path, _config = _run_prepare(
        tmp_path,
        monkeypatch,
        capsys,
        values=values,
        campaign_id="canonical-shared-model-v1",
    )

    assert config_path.is_file()


def test_optional_llm_api_key_is_conditionally_passed_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "secret-optional-ollama-key-93824"
    config_path, config = _run_prepare(
        tmp_path,
        monkeypatch,
        capsys,
        values={**_core_environment(), "LLM_API_KEY": secret},
        campaign_id="optional-key-v1",
    )
    strix = json.loads((config_path.parent / "strix.json").read_text(encoding="utf-8"))
    octopus = json.loads(
        (config_path.parent / "octopus.json").read_text(encoding="utf-8")
    )

    assert "LLM_API_KEY" in strix["adapter"]["environment_passthrough"]
    assert "LLM_API_KEY" in octopus["adapter"]["environment_passthrough"]
    assert "LLM_API_KEY" in config["required_environment"]
    assert config["secret_environment"] == ["LLM_API_KEY"]
    assert secret not in "\n".join(
        path.read_text(encoding="utf-8") for path in config_path.parent.rglob("*.json")
    )


def test_optional_docker_environment_is_conditionally_passed_to_lab_and_strix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configured = {
        "DOCKER_HOST": "unix:///run/user/1000/docker.sock",
        "DOCKER_CONTEXT": "rootless",
        "DOCKER_CONFIG": "/tmp/docker-config",
        "XDG_RUNTIME_DIR": "/run/user/1000",
        "DOCKER_TLS_VERIFY": "1",
        "DOCKER_CERT_PATH": "/tmp/docker-certs",
        "CONTAINER_HOST": "unix:///run/user/1000/podman.sock",
    }
    config_path, config = _run_prepare(
        tmp_path,
        monkeypatch,
        capsys,
        values={**_core_environment(), **configured},
        campaign_id="docker-env-v1",
    )
    strix = json.loads((config_path.parent / "strix.json").read_text(encoding="utf-8"))

    for name in configured:
        assert name in strix["adapter"]["environment_passthrough"]
        assert name in config["lab"]["reset"]["environment_passthrough"]
    absent_path, absent_config = _run_prepare(
        tmp_path / "absent",
        monkeypatch,
        capsys,
        campaign_id="docker-env-absent-v1",
    )
    absent_strix = json.loads(
        (absent_path.parent / "strix.json").read_text(encoding="utf-8")
    )
    assert not set(launch._OPTIONAL_DOCKER_ENVIRONMENT).intersection(
        absent_strix["adapter"]["environment_passthrough"]
    )
    assert not set(launch._OPTIONAL_DOCKER_ENVIRONMENT).intersection(
        absent_config["lab"]["reset"]["environment_passthrough"]
    )


def test_prepare_only_is_platform_and_dirty_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    environment_file = _write_environment(tmp_path / "campaign.env", _core_environment())
    clean_calls: list[bool] = []
    monkeypatch.setattr(launch.sys, "platform", "darwin")
    monkeypatch.setattr(
        launch,
        "_repository_is_clean",
        lambda: clean_calls.append(True) or False,
    )

    assert launch.main(
        [
            "--campaign-id",
            "prepare-v1",
            "--environment-file",
            str(environment_file),
            "--prepare-only",
        ]
    ) == 0
    assert Path(capsys.readouterr().out.strip()).name == "campaign.json"
    assert clean_calls == []


def test_actual_run_enforces_linux_clean_tree_and_new_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    environment_file = _write_environment(tmp_path / "campaign.env", _core_environment())
    arguments = [
        "--campaign-id",
        "guard-v1",
        "--environment-file",
        str(environment_file),
    ]
    run_calls: list[bool] = []
    monkeypatch.setattr(launch, "run_campaign", lambda *_args, **_kwargs: run_calls.append(True))

    monkeypatch.setattr(launch.sys, "platform", "darwin")
    assert launch.main(arguments) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "linux_required"}

    monkeypatch.setattr(launch.sys, "platform", "linux")
    monkeypatch.setattr(launch, "_repository_is_clean", lambda: False)
    assert launch.main(arguments) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "repository_dirty"}

    monkeypatch.setattr(launch, "_repository_is_clean", lambda: True)
    output = tmp_path / "benchmarks" / "competitors" / "results" / "guard-v1"
    output.mkdir(parents=True)
    assert launch.main(arguments) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "output_exists"}
    assert run_calls == []

    with pytest.raises(SystemExit):
        launch._argument_parser().parse_args(
            ["--campaign-id", "guard-v1", "--allow-dirty"]
        )
    capsys.readouterr()


def test_linux_run_sets_detected_target_and_returns_campaign_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    environment_file = _write_environment(
        tmp_path / "campaign.env",
        _small_model_environment(),
    )
    monkeypatch.setattr(launch.sys, "platform", "linux")
    monkeypatch.setattr(launch, "_repository_is_clean", lambda: True)
    monkeypatch.setattr(
        launch,
        "_lab_address",
        lambda _environment, *, port: "http://10.1.2.3:8080",
    )
    monkeypatch.setattr(
        launch,
        "_validate_runtime_prerequisites",
        lambda _environment, *, octopus_revision: _runtime_attestations(),
    )
    observed: dict[str, Any] = {}

    def run(config: Path, *, environment: dict[str, str]) -> SimpleNamespace:
        observed["config"] = config
        observed["environment"] = environment
        return SimpleNamespace(bundle_path=tmp_path / "published", exit_code=7)

    monkeypatch.setattr(launch, "run_campaign", run)

    exit_code = launch.main(
        [
            "--campaign-id",
            "run-v1",
            "--campaign-definition",
            "linux-blackbox-small-model-v1",
            "--environment-file",
            str(environment_file),
        ]
    )

    assert exit_code == 7
    assert observed["config"] == (
        tmp_path / ".benchmark-state" / "generated" / "run-v1" / "campaign.json"
    )
    assert observed["environment"]["OCTOBENCH_TARGET_URL"] == (
        "http://10.1.2.3:8080"
    )
    assert observed["environment"]["OCTOBENCH_LAB_BIND"] == "10.1.2.3"
    assert observed["environment"]["OCTOBENCH_HOST_IP"] == "10.1.2.3"
    assert observed["environment"]["OCTOBENCH_LAB_PORT"] == "8080"
    assert observed["environment"]["LLM_API_BASE"] == (
        _small_model_environment()["LLM_API_BASE"]
    )
    manifest = json.loads(
        (
            tmp_path
            / ".benchmark-state"
            / "generated"
            / "run-v1"
            / "strix.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["metadata"]["runtime_provenance"] == _runtime_attestations()[
        "strix"
    ]
    scenario = json.loads(
        (
            tmp_path
            / ".benchmark-state"
            / "generated"
            / "run-v1"
            / "scenarios"
            / "authorized-discovery-altered-small-model-stress-v1.json"
        ).read_text(encoding="utf-8")
    )
    assert scenario["repetitions"] == 6
    assert scenario["budgets"]["max_seconds"] == 600
    assert capsys.readouterr().out == f"{tmp_path / 'published'}\n"


def test_linux_diagnostic_pilot_runs_privately_and_returns_pilot_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    environment_file = _write_environment(
        tmp_path / "campaign.env",
        _small_model_environment(),
    )
    monkeypatch.setattr(launch.sys, "platform", "linux")
    monkeypatch.setattr(launch, "_repository_is_clean", lambda: True)
    monkeypatch.setattr(
        launch,
        "_lab_address",
        lambda _environment, *, port: "http://10.1.2.3:8080",
    )
    monkeypatch.setattr(
        launch,
        "_validate_runtime_prerequisites",
        lambda _environment, *, octopus_revision: _runtime_attestations(),
    )
    observed: dict[str, Any] = {}
    summary_path = (
        tmp_path
        / ".benchmark-state"
        / "diagnostics"
        / "pilot-v1"
        / "summary.json"
    )

    def run_diagnostic(config: Path, **kwargs: Any) -> SimpleNamespace:
        observed["config"] = config
        observed.update(kwargs)
        return SimpleNamespace(summary_path=summary_path, exit_code=1)

    monkeypatch.setattr(launch, "run_diagnostic_pilot", run_diagnostic)
    exit_code = launch.main(
        [
            "--campaign-id",
            "pilot-v1",
            "--campaign-definition",
            "linux-blackbox-small-model-v1",
            "--environment-file",
            str(environment_file),
            "--diagnostic-pilot",
            "--pilot-system",
            "strix",
            "--pilot-seconds",
            "1200",
        ]
    )

    assert exit_code == 1
    assert observed["config"] == (
        tmp_path / ".benchmark-state" / "generated" / "pilot-v1" / "campaign.json"
    )
    assert observed["root"] == tmp_path / ".benchmark-state" / "diagnostics"
    assert observed["budget_seconds"] == 1200.0
    assert observed["selected_system"] == "strix"
    assert observed["environment"]["OCTOBENCH_TARGET_URL"] == (
        "http://10.1.2.3:8080"
    )
    assert capsys.readouterr().out == f"{summary_path}\n"

    observed.clear()
    assert launch.main(
        [
            "--campaign-id",
            "pilot-default-v1",
            "--environment-file",
            str(environment_file),
            "--diagnostic-pilot",
        ]
    ) == 1
    assert observed["budget_seconds"] == launch.DEFAULT_PILOT_SECONDS
    assert observed["selected_system"] is None
    capsys.readouterr()

    public_output = (
        tmp_path
        / "benchmarks"
        / "competitors"
        / "results"
        / "pilot-collision-v1"
    )
    public_output.mkdir(parents=True)
    assert launch.main(
        [
            "--campaign-id",
            "pilot-collision-v1",
            "--environment-file",
            str(environment_file),
            "--diagnostic-pilot",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "output_exists"}

    def diagnostic_failure(*_args: Any, **_kwargs: Any) -> None:
        raise launch.DiagnosticError("private-provider-secret-93824")

    monkeypatch.setattr(launch, "run_diagnostic_pilot", diagnostic_failure)
    assert launch.main(
        [
            "--campaign-id",
            "diagnostic-error-v1",
            "--environment-file",
            str(environment_file),
            "--diagnostic-pilot",
        ]
    ) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.err) == {"error": "diagnostic_failed"}
    assert "private-provider-secret-93824" not in captured.err

    diagnostic_output = (
        tmp_path
        / ".benchmark-state"
        / "diagnostics"
        / "public-collision-v1"
    )
    diagnostic_output.mkdir(parents=True)
    assert launch.main(
        [
            "--campaign-id",
            "public-collision-v1",
            "--environment-file",
            str(environment_file),
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "output_exists"}


def test_diagnostic_only_options_reject_incompatible_launch_modes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert launch.main(
        ["--campaign-id", "invalid-v1", "--pilot-seconds", "120"]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "campaign_failed"}

    assert launch.main(
        [
            "--campaign-id",
            "invalid-v2",
            "--prepare-only",
            "--diagnostic-pilot",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "campaign_failed"}


def test_relative_product_binaries_are_resolved_from_repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    values = _core_environment()
    values["OCTOBENCH_STRIX_BIN"] = ".benchmark-tools/strix/bin/strix"
    environment_file = _write_environment(tmp_path / "campaign.env", values)

    environment = launch._merged_environment(environment_file)

    assert environment["OCTOBENCH_STRIX_BIN"] == str(
        tmp_path / ".benchmark-tools" / "strix" / "bin" / "strix"
    )


@pytest.mark.parametrize(
    "configured",
    ("0.0.0.0", "::", "8.8.8.8", "169.254.1.2", "example.test", "[::1]:8080"),
)
def test_explicit_lab_bind_rejects_non_private_or_non_ip_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    configured: str,
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    values = {**_core_environment(), "OCTOBENCH_LAB_BIND": configured}
    environment_file = _write_environment(tmp_path / "campaign.env", values)

    assert launch.main(
        [
            "--campaign-id",
            "invalid-bind-v1",
            "--environment-file",
            str(environment_file),
            "--prepare-only",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "invalid_lab_bind"}


def test_runtime_lab_environment_canonicalizes_all_preflight_passthrough_values() -> None:
    runtime = launch._runtime_lab_environment(
        {
            "OCTOBENCH_HOST_IP": "10.20.30.40",
            "OCTOBENCH_LAB_PORT": "9090",
            "OCTOBENCH_LAB_BIND": "10.20.30.40",
        }
    )

    assert runtime["OCTOBENCH_TARGET_URL"] == "http://10.20.30.40:9090"
    assert runtime["OCTOBENCH_HOST_IP"] == "10.20.30.40"
    assert runtime["OCTOBENCH_LAB_PORT"] == "9090"
    assert runtime["OCTOBENCH_LAB_BIND"] == "10.20.30.40"

    with pytest.raises(launch.LaunchError, match="invalid_lab_bind"):
        launch._runtime_lab_environment(
            {
                "OCTOBENCH_HOST_IP": "10.20.30.40",
                "OCTOBENCH_LAB_PORT": "9090",
                "OCTOBENCH_LAB_BIND": "127.0.0.1",
            }
        )


def test_generated_scenario_directory_is_nested_atomic_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path, _config = _run_prepare(
        tmp_path,
        monkeypatch,
        capsys,
        campaign_id="idempotent-v1",
    )
    environment_file = tmp_path / "campaign.env"
    arguments = [
        "--campaign-id",
        "idempotent-v1",
        "--environment-file",
        str(environment_file),
        "--prepare-only",
    ]

    assert launch.main(arguments) == 0
    assert Path(capsys.readouterr().out.strip()) == config_path
    scenario = config_path.parent / "scenarios" / "authorized-discovery-v1.json"
    scenario.write_text("{}\n", encoding="utf-8")
    scenario.chmod(0o600)

    assert launch.main(arguments) == 2
    assert json.loads(capsys.readouterr().err) == {
        "error": "generated_state_conflict"
    }


def test_reusing_campaign_id_with_another_definition_conflicts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    environment_file = _write_environment(
        tmp_path / "campaign.env",
        _small_model_environment(),
    )
    base_arguments = [
        "--campaign-id",
        "definition-collision-v1",
        "--environment-file",
        str(environment_file),
        "--prepare-only",
    ]
    assert launch.main(base_arguments) == 0
    capsys.readouterr()

    assert launch.main(
        [
            *base_arguments,
            "--campaign-definition",
            "linux-blackbox-small-model-v1",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().err) == {
        "error": "generated_state_conflict"
    }


def test_campaign_definition_directory_must_be_real_and_in_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    definition = launch._campaign_definition(
        "linux-blackbox-small-model-v1",
        profile="core",
    )
    scenario_directory = (
        tmp_path
        / "benchmarks"
        / "competitors"
        / "campaigns"
        / "linux-blackbox-small-model-v1"
        / "scenarios"
    )
    real_directory = scenario_directory.with_name("real-scenarios")
    scenario_directory.rename(real_directory)
    scenario_directory.symlink_to(real_directory, target_is_directory=True)

    with pytest.raises(launch.LaunchError, match="campaign_definition_unavailable"):
        launch._scenario_directory(definition)


def test_campaign_definition_rejects_symlinked_campaign_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    definition = launch._campaign_definition(
        "linux-blackbox-small-model-v1",
        profile="core",
    )
    campaign_root = tmp_path / "benchmarks" / "competitors" / "campaigns"
    relocated_root = tmp_path / "relocated-campaigns"
    campaign_root.rename(relocated_root)
    campaign_root.symlink_to(relocated_root, target_is_directory=True)

    with pytest.raises(launch.LaunchError, match="campaign_definition_unavailable"):
        launch._scenario_directory(definition)


def test_runtime_prerequisites_attest_one_ollama_digest_for_both_systems(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_root(tmp_path, monkeypatch)
    executable = tmp_path / "venv" / "bin" / "python"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"python\n")
    executable.chmod(0o700)
    launcher_directory = tmp_path / "benchmarks" / "competitors"
    launcher_directory.mkdir(parents=True, exist_ok=True)
    for name in ("run_adapter.py", "run_lab.py"):
        (launcher_directory / name).write_bytes(b"# launcher\n")
    monkeypatch.setattr(launch.shutil, "which", lambda *_args, **_kwargs: "/bin/docker")
    monkeypatch.setattr(
        launch,
        "_attest_octopus_runtime",
        lambda **_kwargs: {"runtime": "octopus"},
    )
    monkeypatch.setattr(
        launch,
        "_attest_local_runtime",
        lambda *_args, **_kwargs: {"runtime": "strix"},
    )
    monkeypatch.setattr(
        launch,
        "_attest_strix_sandbox_image",
        lambda *_args, **_kwargs: {"sandbox": "attested"},
    )
    secret = "private-ollama-canary-93824"
    observed, handlers = _stub_ollama_tags(
        monkeypatch,
        {
            "models": [
                {
                    "name": SHARED_OLLAMA_MODEL,
                    "model": SHARED_OLLAMA_MODEL,
                    "digest": SHARED_OLLAMA_API_DIGEST,
                    "size": SHARED_OLLAMA_SIZE,
                }
            ]
        },
    )
    environment = {
        **_core_environment(),
        "PATH": "/usr/bin:/bin",
        "LLM_API_KEY": secret,
    }

    attestations = launch._validate_runtime_prerequisites(
        environment,
        octopus_revision=OCTOPUS_REVISION,
    )

    expected = {
        "ollama_model_attestation": "api-tags",
        "ollama_model_digest": SHARED_OLLAMA_DIGEST,
        "ollama_model_size_bytes": SHARED_OLLAMA_SIZE,
        "ollama_runtime_attestation": "api-version-unload-empty-preload-and-ps",
        "ollama_server_version": SHARED_OLLAMA_SERVER_VERSION,
        "ollama_context_length": SHARED_OLLAMA_CONTEXT_LENGTH,
        "ollama_model_size_vram_bytes": SHARED_OLLAMA_SIZE_VRAM,
        "ollama_num_parallel_declared": 1,
        "ollama_max_loaded_models_declared": 1,
        "ollama_server_policy_attestation": "operator-declared-api-not-exposed",
    }
    assert {key: attestations["octopus"][key] for key in expected} == expected
    assert {key: attestations["strix"][key] for key in expected} == expected
    request = observed["request"]
    assert request.full_url == "http://127.0.0.1:11434/api/tags"
    assert request.get_header("Authorization") == f"Bearer {secret}"
    assert observed["timeout"] == launch._OLLAMA_ATTESTATION_TIMEOUT_SECONDS
    requests = observed["requests"]
    assert [urllib.parse.urlsplit(item.full_url).path for item in requests] == [
        "/api/tags",
        "/api/version",
        "/api/generate",
        "/api/generate",
        "/api/ps",
    ]
    unload = requests[2]
    assert unload.method == "POST"
    assert json.loads(unload.data or b"") == {
        "model": SHARED_OLLAMA_MODEL,
        "keep_alive": 0,
    }
    preload = requests[3]
    assert preload.method == "POST"
    assert json.loads(preload.data or b"") == {
        "model": SHARED_OLLAMA_MODEL,
        "prompt": "",
        "stream": False,
        "keep_alive": "5m",
    }
    assert observed["timeouts"] == [
        launch._OLLAMA_ATTESTATION_TIMEOUT_SECONDS,
        launch._OLLAMA_ATTESTATION_TIMEOUT_SECONDS,
        launch._OLLAMA_PRELOAD_TIMEOUT_SECONDS,
        launch._OLLAMA_PRELOAD_TIMEOUT_SECONDS,
        launch._OLLAMA_ATTESTATION_TIMEOUT_SECONDS,
    ]
    assert all(
        item.get_header("Authorization") == f"Bearer {secret}"
        for item in requests
    )
    assert any(
        isinstance(item, urllib.request.ProxyHandler) and item.proxies == {}
        for item in handlers
    )
    assert any(isinstance(item, launch._NoRedirectHandler) for item in handlers)
    tls_handler = next(
        item for item in handlers if isinstance(item, urllib.request.HTTPSHandler)
    )
    assert tls_handler._context.verify_mode == launch.ssl.CERT_REQUIRED
    assert tls_handler._context.check_hostname is True
    assert secret not in json.dumps(attestations)


def test_ollama_runtime_attestation_rejects_missing_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_ollama_tags(
        monkeypatch,
        {
            "models": [
                {
                    "name": "another-model:latest",
                    "digest": SHARED_OLLAMA_DIGEST,
                    "size": SHARED_OLLAMA_SIZE,
                }
            ]
        },
    )

    with pytest.raises(launch.LaunchError) as captured:
        launch._attest_shared_ollama_runtime(_core_environment())

    assert captured.value.code == "runtime_unavailable"
    assert str(captured.value) == "runtime_unavailable"


def test_ollama_runtime_attestation_rejects_context_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_ollama_tags(
        monkeypatch,
        {
            "models": [
                {
                    "name": SHARED_OLLAMA_MODEL,
                    "digest": SHARED_OLLAMA_API_DIGEST,
                    "size": SHARED_OLLAMA_SIZE,
                }
            ]
        },
        context_length=32_768,
    )

    with pytest.raises(launch.LaunchError) as captured:
        launch._attest_shared_ollama_runtime(_core_environment())

    assert captured.value.code == "ollama_context_mismatch"


def test_ollama_runtime_attestation_rejects_server_version_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_ollama_tags(
        monkeypatch,
        {
            "models": [
                {
                    "name": SHARED_OLLAMA_MODEL,
                    "digest": SHARED_OLLAMA_API_DIGEST,
                    "size": SHARED_OLLAMA_SIZE,
                }
            ]
        },
        server_version="0.18.2",
    )

    with pytest.raises(launch.LaunchError) as captured:
        launch._attest_shared_ollama_runtime(_core_environment())

    assert captured.value.code == "ollama_version_mismatch"


@pytest.mark.parametrize(
    "process_payload",
    (
        {"models": []},
        {
            "models": [
                {
                    "name": SHARED_OLLAMA_MODEL,
                    "digest": "d" * 64,
                    "size_vram": SHARED_OLLAMA_SIZE_VRAM,
                    "context_length": SHARED_OLLAMA_CONTEXT_LENGTH,
                }
            ]
        },
        {
            "models": [
                {
                    "name": SHARED_OLLAMA_MODEL,
                    "digest": SHARED_OLLAMA_API_DIGEST,
                    "size_vram": SHARED_OLLAMA_SIZE_VRAM,
                    "context_length": True,
                }
            ]
        },
        {
            "models": [
                {
                    "name": SHARED_OLLAMA_MODEL,
                    "digest": SHARED_OLLAMA_API_DIGEST,
                    "size_vram": SHARED_OLLAMA_SIZE_VRAM,
                    "context_length": SHARED_OLLAMA_CONTEXT_LENGTH,
                },
                {
                    "name": "unrelated-model:latest",
                    "digest": "e" * 64,
                    "size_vram": 1,
                    "context_length": SHARED_OLLAMA_CONTEXT_LENGTH,
                },
            ]
        },
    ),
)
def test_ollama_runtime_attestation_rejects_malformed_process_payload(
    monkeypatch: pytest.MonkeyPatch,
    process_payload: Any,
) -> None:
    _stub_ollama_tags(
        monkeypatch,
        {
            "models": [
                {
                    "name": SHARED_OLLAMA_MODEL,
                    "digest": SHARED_OLLAMA_API_DIGEST,
                    "size": SHARED_OLLAMA_SIZE,
                }
            ]
        },
        process_payload=process_payload,
    )

    with pytest.raises(launch.LaunchError, match=r"^runtime_unavailable$"):
        launch._attest_shared_ollama_runtime(_core_environment())


@pytest.mark.parametrize(
    "payload",
    (
        b"not-json",
        {},
        {"models": "not-a-list"},
        {
            "models": [
                {
                    "name": SHARED_OLLAMA_MODEL,
                    "digest": "not-a-sha256",
                    "size": SHARED_OLLAMA_SIZE,
                }
            ]
        },
        {
            "models": [
                {
                    "name": SHARED_OLLAMA_MODEL,
                    "digest": SHARED_OLLAMA_DIGEST,
                    "size": 0,
                }
            ]
        },
    ),
)
def test_ollama_runtime_attestation_rejects_malformed_endpoint_payload(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
) -> None:
    _stub_ollama_tags(monkeypatch, payload)

    with pytest.raises(launch.LaunchError, match=r"^runtime_unavailable$"):
        launch._attest_shared_ollama_runtime(_core_environment())


def test_ollama_runtime_attestation_hides_unreachable_endpoint_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "private-ollama-canary-93824"

    class Opener:
        def open(self, *_args: Any, **_kwargs: Any) -> None:
            raise urllib.error.URLError(f"upstream rejected {secret}")

    monkeypatch.setattr(
        launch.urllib.request,
        "build_opener",
        lambda *_handlers: Opener(),
    )

    with pytest.raises(launch.LaunchError) as captured:
        launch._attest_shared_ollama_runtime(
            {**_core_environment(), "LLM_API_KEY": secret}
        )

    assert captured.value.code == "runtime_unavailable"
    assert str(captured.value) == "runtime_unavailable"
    assert secret not in str(captured.value)


def test_local_runtime_attestation_checks_layout_version_and_binds_digests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools_root = tmp_path / "tools"
    spec = launch._LocalRuntimeSpec(
        system_id="example",
        source_revision="d" * 40,
        source_layout="src/example",
        executable_environment="EXAMPLE_BIN",
        executable_layout="venvs/example/bin/example",
        interpreter_layout="venvs/example/bin/python",
        distribution_name="example-package",
        distribution_version="1.2.3",
    )
    source = tools_root / "src" / "example"
    executable = tools_root / "venvs" / "example" / "bin" / "example"
    interpreter = executable.parent / "python"
    interpreter_target = tmp_path / "system-python"
    source.mkdir(parents=True)
    executable.parent.mkdir(parents=True)
    (source / "uv.lock").write_bytes(b"frozen-lock\n")
    executable.write_bytes(b"example executable\n")
    interpreter_target.write_bytes(b"python executable\n")
    interpreter.symlink_to(interpreter_target)
    os.chmod(executable, 0o700)
    os.chmod(interpreter_target, 0o700)
    observed: dict[str, Any] = {}

    def clean_checkout(path: Path, revision: str) -> str:
        observed["checkout"] = (path, revision)
        return "e" * 64

    monkeypatch.setattr(launch, "_attest_clean_checkout", clean_checkout)

    def installed_distribution_version(
        runtime_interpreter: Path,
        distribution: str,
    ) -> str:
        observed["distribution"] = (runtime_interpreter, distribution)
        return "1.2.3"

    monkeypatch.setattr(
        launch,
        "_installed_distribution_version",
        installed_distribution_version,
    )

    attestation = launch._attest_local_runtime(
        spec,
        tools_root=tools_root,
        environment={"EXAMPLE_BIN": str(executable)},
    )

    assert observed["checkout"] == (source, "d" * 40)
    assert observed["distribution"] == (interpreter, "example-package")
    assert attestation["source_tree_sha256"] == "e" * 64
    assert attestation["lock_sha256"] == hashlib.sha256(
        b"frozen-lock\n"
    ).hexdigest()
    assert attestation["executable_sha256"] == hashlib.sha256(
        b"example executable\n"
    ).hexdigest()
    assert attestation["distribution_version"] == "1.2.3"

    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_local_runtime(
            spec,
            tools_root=tools_root,
            environment={"EXAMPLE_BIN": str(tmp_path / "other")},
        )


def test_checkout_attestation_rejects_wrong_revision_and_dirty_tree(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    def git(*arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=checkout,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return completed.stdout.strip()

    git("init")
    (checkout / "tracked.txt").write_text("reviewed source\n", encoding="utf-8")
    git("add", "tracked.txt")
    git(
        "-c",
        "user.name=OCTOBENCH",
        "-c",
        "user.email=octobench@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    revision = git("rev-parse", "HEAD")

    assert len(launch._attest_clean_checkout(checkout, revision)) == 64
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_clean_checkout(checkout, "0" * 40)

    (checkout / "tracked.txt").write_text("dirty source\n", encoding="utf-8")
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_clean_checkout(checkout, revision)


def test_pentagi_custom_ca_is_optional_and_content_bound_for_actual_runs(
    tmp_path: Path,
) -> None:
    ca_file = tmp_path / "pentagi-ca.pem"
    ca_file.write_bytes(b"test-ca-certificate\n")
    environment = {
        **_extended_environment(),
        "OCTOBENCH_PENTAGI_CA_FILE": str(ca_file),
    }
    pentagi = next(
        item
        for item in launch._system_pins(
            "extended",
            octopus_revision=OCTOPUS_REVISION,
        )
        if item.system_id == "pentagi"
    )

    manifest = launch._manifest_payload(
        pentagi,
        profile="extended",
        environment=environment,
        runtime_attestation=None,
        actual_run=True,
    )

    assert "OCTOBENCH_PENTAGI_CA_FILE" in manifest["adapter"][
        "environment_passthrough"
    ]
    provenance = manifest["metadata"]["runtime_provenance"]
    assert provenance["custom_ca_configured"] is True
    assert provenance["ca_file_sha256"] == hashlib.sha256(
        b"test-ca-certificate\n"
    ).hexdigest()
