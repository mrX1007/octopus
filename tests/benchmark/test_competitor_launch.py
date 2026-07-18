"""One-command Linux competitor campaign launcher tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
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
        "OCTOBENCH_STRIX_BIN": "/opt/strix/bin/strix",
        "STRIX_IMAGE": launch._STRIX_IMAGE,
        "STRIX_LLM": f"ollama/{SHARED_OLLAMA_MODEL}",
        "LLM_API_BASE": "http://127.0.0.1:11434",
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
    scenario_directory = (
        tmp_path
        / "benchmarks"
        / "competitors"
        / "campaigns"
        / "linux-blackbox-v1"
        / "scenarios"
    )
    scenario_directory.mkdir(parents=True)
    source_scenarios = (
        REPOSITORY_ROOT
        / "benchmarks"
        / "competitors"
        / "campaigns"
        / "linux-blackbox-v1"
        / "scenarios"
    )
    for source in source_scenarios.glob("*.json"):
        (scenario_directory / source.name).write_bytes(source.read_bytes())


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
    return attestations


def _run_prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    profile: str = "core",
    values: dict[str, str] | None = None,
    campaign_id: str = "campaign-v1",
) -> tuple[Path, dict[str, Any]]:
    _prepare_root(tmp_path, monkeypatch)
    environment_file = _write_environment(
        tmp_path / "campaign.env",
        _core_environment() if values is None else values,
    )
    exit_code = launch.main(
        [
            "--campaign-id",
            campaign_id,
            "--profile",
            profile,
            "--environment-file",
            str(environment_file),
            "--prepare-only",
        ]
    )
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
                "weights and server; product-native prompts, request APIs and "
                "inference defaults remain distinct."
            ),
            "same_tool_versions": False,
            "same_hardware": True,
            "same_budgets": False,
        }
        assert payload["model"] == {
            "provider": "ollama",
            "name": SHARED_OLLAMA_MODEL,
            "parameters": {},
        }
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

    assert "LLM_API_KEY" in strix["adapter"]["environment_passthrough"]
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
    environment_file = _write_environment(tmp_path / "campaign.env", _core_environment())
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
        _core_environment()["LLM_API_BASE"]
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
            / "authorized-discovery-v1.json"
        ).read_text(encoding="utf-8")
    )
    assert scenario["repetitions"] == 6
    assert capsys.readouterr().out == f"{tmp_path / 'published'}\n"


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
