"""Hermetic branch coverage for the competitor campaign launcher."""

from __future__ import annotations

import hashlib
import json
import runpy
import subprocess
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.benchmarks.competitors import launch
from tests.benchmark import test_competitor_launch as launch_fixtures

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

REVISION = "0123456789abcdef0123456789abcdef01234567"
MODEL = "qwen3.5:9b"
DIGEST = "c" * 64


def _core_environment() -> dict[str, str]:
    return {
        "OCTOBENCH_ACK_AUTHORIZED": "YES",
        "OCTOBENCH_ACK_ISOLATED_HOST": "YES",
        "OCTOPUS_OLLAMA_URL": "http://127.0.0.1:11434/api/generate",
        "OCTOPUS_OLLAMA_MODEL": MODEL,
        "OCTOBENCH_OLLAMA_CONTEXT_LENGTH": "65536",
        "OCTOBENCH_OLLAMA_SERVER_VERSION": "0.18.3",
        "OCTOBENCH_OLLAMA_NUM_PARALLEL": "1",
        "OCTOBENCH_OLLAMA_MAX_LOADED_MODELS": "1",
        "OCTOBENCH_STRIX_BIN": "/opt/strix/bin/strix",
        "STRIX_IMAGE": launch._STRIX_IMAGE,
        "STRIX_LLM": f"ollama/{MODEL}",
        "LLM_API_BASE": "http://127.0.0.1:11434",
    }


def _write_environment(path: Path, contents: str) -> Path:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o600)
    return path


def _raises(error: BaseException):
    def raise_error(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    return raise_error


class _Response:
    def __init__(self, payload: bytes, *, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response

    def open(self, *_args: Any, **_kwargs: Any) -> _Response:
        return self.response


def test_redirect_and_main_exception_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = launch.urllib.request.Request("http://127.0.0.1/source")
    with pytest.raises(launch.urllib.error.HTTPError) as redirected:
        launch._NoRedirectHandler().redirect_request(
            request,
            None,
            302,
            "redirected",
            {},
            "http://127.0.0.1/destination",
        )
    assert redirected.value.code == 302

    for error, expected in (
        (launch.LabControlError("health_invalid"), "campaign_failed"),
        (RuntimeError("private-canary"), "campaign_failed"),
    ):
        monkeypatch.setattr(launch, "_campaign_id", _raises(error))
        assert launch.main(["--campaign-id", "boundary-v1"]) == 2
        assert json.loads(capsys.readouterr().err) == {"error": expected}


def test_readiness_mode_rejects_non_v4_campaign_definition(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        launch.main(
            [
                "--campaign-id",
                "wrong-readiness-definition",
                "--campaign-definition",
                launch._SMALL_MODEL_CAMPAIGN_V3_DEFINITION_ID,
                "--readiness-calibration",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().err) == {"error": "campaign_definition_mismatch"}


def test_v4_generated_campaign_fails_closed_on_invalid_readiness_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launch_fixtures._prepare_root(tmp_path, monkeypatch)
    environment = {
        **launch_fixtures._small_model_environment(),
        "OCTOBENCH_V3_BASE_FIXTURE_SEED": "ab" * 32,
    }
    definition = launch._CAMPAIGN_DEFINITIONS[launch._SMALL_MODEL_CAMPAIGN_V4_DEFINITION_ID]
    common = {
        "profile": "core",
        "environment": environment,
        "environment_file": None,
        "octopus_revision": launch_fixtures.OCTOPUS_REVISION,
        "campaign_definition": definition,
    }

    with monkeypatch.context() as patch:
        patch.setattr(launch, "load_readiness_profile", _raises(ValueError("invalid profile")))
        with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
            launch._prepare_generated_campaign("invalid-readiness-profile", **common)

    with monkeypatch.context() as patch:
        patch.setattr(
            launch,
            "build_readiness_plan",
            lambda *_args, **_kwargs: SimpleNamespace(scenario_ids=()),
        )
        with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
            launch._prepare_generated_campaign("invalid-readiness-plan", **common)


def test_manifest_and_campaign_payload_guards() -> None:
    systems = launch._system_pins("extended", octopus_revision=REVISION)
    pentagi = next(item for item in systems if item.system_id == "pentagi")
    pentagi_environment = {
        **_core_environment(),
        "OCTOBENCH_PENTAGI_URL": "http://10.20.30.40:8443",
        "OCTOBENCH_PENTAGI_TOKEN": "secret",
        "OCTOBENCH_PENTAGI_PROVIDER": "openai",
        "OCTOBENCH_PENTAGI_MODEL": "model",
        "OCTOBENCH_PENTAGI_CA_FILE": "/deferred/ca.pem",
    }
    manifest = launch._manifest_payload(
        pentagi,
        profile="extended",
        environment=pentagi_environment,
        runtime_attestation=None,
        actual_run=False,
    )
    assert manifest["metadata"]["runtime_provenance"]["ca_file_attestation"] == "deferred-to-actual-launch"

    octopus = next(item for item in systems if item.system_id == "octopus")
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._manifest_payload(
            octopus,
            profile="core",
            environment=_core_environment(),
            runtime_attestation=None,
            actual_run=True,
        )

    strix = next(item for item in systems if item.system_id == "strix")
    with pytest.raises(launch.LaunchError, match="invalid_strix_image"):
        launch._manifest_payload(
            strix,
            profile="core",
            environment={**_core_environment(), "STRIX_IMAGE": "wrong"},
            runtime_attestation=None,
            actual_run=False,
        )

    v3 = launch._CAMPAIGN_DEFINITIONS[launch._SMALL_MODEL_CAMPAIGN_V3_DEFINITION_ID]
    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._campaign_payload(
            "campaign-v3",
            systems=launch._system_pins("core", octopus_revision=REVISION),
            environment={},
            environment_file=None,
            repetitions=12,
            campaign_definition=v3,
            analysis_plan=None,
        )

    v4 = launch._CAMPAIGN_DEFINITIONS[launch._SMALL_MODEL_CAMPAIGN_V4_DEFINITION_ID]
    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._campaign_payload(
            "campaign-v4",
            systems=launch._system_pins("core", octopus_revision=REVISION),
            environment={},
            environment_file=None,
            repetitions=20,
            campaign_definition=v4,
            analysis_plan=SimpleNamespace(),
            efficiency_plan=None,
        )

    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._campaign_payload(
            "campaign-v3",
            systems=launch._system_pins("core", octopus_revision=REVISION),
            environment={},
            environment_file=None,
            repetitions=12,
            campaign_definition=v3,
            analysis_plan=SimpleNamespace(),
            efficiency_plan=SimpleNamespace(),
        )
    with pytest.raises(launch.LaunchError, match="campaign_failed"):
        launch._profile_repetitions(())


def test_generated_scenario_input_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition = launch._CAMPAIGN_DEFINITIONS[launch._DEFAULT_CAMPAIGN_DEFINITION_ID]

    class BrokenSource:
        def glob(self, _pattern: str) -> Iterator[Path]:
            raise OSError("unavailable")

    monkeypatch.setattr(launch, "_scenario_directory", lambda _definition: BrokenSource())
    with pytest.raises(launch.LaunchError, match="campaign_failed"):
        launch._generated_scenario_payloads(6, campaign_definition=definition)

    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(launch, "_scenario_directory", lambda _definition: empty)
    with pytest.raises(launch.LaunchError, match="campaign_failed"):
        launch._generated_scenario_payloads(6, campaign_definition=definition)

    not_a_file = tmp_path / "not-file"
    not_a_file.mkdir()
    (not_a_file / "scenario.json").mkdir()
    monkeypatch.setattr(launch, "_scenario_directory", lambda _definition: not_a_file)
    with pytest.raises(launch.LaunchError, match="campaign_failed"):
        launch._generated_scenario_payloads(6, campaign_definition=definition)

    invalid_json = tmp_path / "invalid-json"
    invalid_json.mkdir()
    (invalid_json / "scenario.json").write_text("not-json", encoding="utf-8")
    monkeypatch.setattr(launch, "_scenario_directory", lambda _definition: invalid_json)
    with pytest.raises(launch.LaunchError, match="campaign_failed"):
        launch._generated_scenario_payloads(6, campaign_definition=definition)

    invalid_payload = tmp_path / "invalid-payload"
    invalid_payload.mkdir()
    (invalid_payload / "scenario.json").write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        launch,
        "_scenario_directory",
        lambda _definition: invalid_payload,
    )
    with pytest.raises(launch.LaunchError, match="campaign_failed"):
        launch._generated_scenario_payloads(6, campaign_definition=definition)

    mismatched_v3 = launch._CampaignDefinition(
        definition_id="mismatched-v3",
        allowed_profiles=frozenset({"core"}),
        benchmark_v3_track_id="wrong-track",
        lab_definition_id=launch.LAB_V3_VERSION,
    )
    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._generated_v3_scenario_payloads(
            12,
            campaign_definition=mismatched_v3,
        )


def test_v3_configuration_guards_and_valid_path() -> None:
    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._configured_v3_base_seed({})
    with pytest.raises(launch.LaunchError, match="campaign_definition_mismatch"):
        launch._configured_v3_design_id(
            {"DESIGN": "../invalid"},
            "DESIGN",
            default="batch-1",
        )

    definition = launch._CAMPAIGN_DEFINITIONS[launch._SMALL_MODEL_CAMPAIGN_V3_DEFINITION_ID]
    environment = {
        "OCTOPUS_OLLAMA_MODEL": definition.ollama_model or "",
        "OCTOBENCH_OLLAMA_CONTEXT_LENGTH": str(definition.ollama_context_length),
        "OCTOBENCH_OLLAMA_SERVER_VERSION": definition.ollama_server_version or "",
        "OCTOBENCH_OLLAMA_FLASH_ATTENTION": "1",
        "OCTOBENCH_OLLAMA_KV_CACHE_TYPE": "q8_0",
        launch._V3_BASE_FIXTURE_SEED_ENVIRONMENT: "ab" * 16,
    }
    launch._validate_campaign_definition_configuration(definition, environment)


def test_merged_environment_and_environment_file_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HOME", raising=False)
    merged = launch._merged_environment(None)
    assert "HOME" not in merged

    monkeypatch.setattr(launch, "_load_environment_file", lambda _path: {"PATH": "bad"})
    with pytest.raises(launch.LaunchError, match="environment_file_invalid"):
        launch._merged_environment(tmp_path / "unused.env")

    monkeypatch.undo()
    missing = tmp_path / "missing.env"
    with pytest.raises(launch.LaunchError, match="environment_file_unavailable"):
        launch._load_environment_file(missing)

    oversized = _write_environment(tmp_path / "oversized.env", "A=12\n")
    with monkeypatch.context() as patch:
        patch.setattr(launch, "_MAX_ENVIRONMENT_FILE_BYTES", 1)
        with pytest.raises(launch.LaunchError, match="environment_file_invalid"):
            launch._load_environment_file(oversized)

    undecodable = tmp_path / "undecodable.env"
    undecodable.write_bytes(b"\xff")
    undecodable.chmod(0o600)
    with pytest.raises(launch.LaunchError, match="environment_file_unavailable"):
        launch._load_environment_file(undecodable)

    too_many_lines = _write_environment(tmp_path / "lines.env", "A=1\nB=2\n")
    with monkeypatch.context() as patch:
        patch.setattr(launch, "_MAX_ENVIRONMENT_LINES", 1)
        with pytest.raises(launch.LaunchError, match="environment_file_invalid"):
            launch._load_environment_file(too_many_lines)

    valid = _write_environment(
        tmp_path / "valid.env",
        "# comment\n\nQUOTED='value'\n",
    )
    assert launch._load_environment_file(valid) == {"QUOTED": "value"}

    invalid = tmp_path / "invalid.env"
    for contents in (
        "export A=1\n",
        "INVALID-NAME=value\n",
        "A=1\nA=2\n",
        "A=before\x00after\n",
    ):
        _write_environment(invalid, contents)
        with pytest.raises(launch.LaunchError, match="environment_file_invalid"):
            launch._load_environment_file(invalid)


def test_required_environment_url_and_runtime_address_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(launch.LaunchError, match="authorization_required"):
        launch._validate_required_environment({}, ())
    with pytest.raises(launch.LaunchError, match="missing_environment"):
        launch._validate_required_environment(
            {
                "OCTOBENCH_ACK_AUTHORIZED": "YES",
                "OCTOBENCH_ACK_ISOLATED_HOST": "YES",
                "PATH": "/bin",
            },
            (),
        )

    with pytest.raises(
        launch.LaunchError,
        match="invalid_shared_ollama_configuration",
    ):
        launch._ollama_url_parts("http://127.0.0.1:invalid")
    with pytest.raises(
        launch.LaunchError,
        match="invalid_shared_ollama_configuration",
    ):
        launch._ollama_url_parts("ftp://127.0.0.1/service")

    for address in (
        "http://127.0.0.1:invalid",
        "http://127.0.0.1",
        "http://example.test:8080",
        "http://8.8.8.8:8080",
    ):
        monkeypatch.setattr(launch, "_lab_address", lambda *_args, value=address, **_kwargs: value)
        with pytest.raises(launch.LaunchError, match="campaign_failed"):
            launch._runtime_lab_environment({})

    assert launch._validated_lab_bind("[::1]") == "[::1]"


def test_runtime_prerequisite_layout_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._validate_runtime_prerequisites({}, octopus_revision=REVISION)

    python = tmp_path / "venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    python.chmod(0o700)
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._validate_runtime_prerequisites({}, octopus_revision=REVISION)

    launchers = tmp_path / "benchmarks" / "competitors"
    launchers.mkdir(parents=True)
    for name in ("run_adapter.py", "run_lab.py"):
        (launchers / name).write_text("# launcher\n", encoding="utf-8")
    monkeypatch.setattr(launch.shutil, "which", lambda *_args, **_kwargs: None)
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._validate_runtime_prerequisites({}, octopus_revision=REVISION)


def _ollama_sequence(
    monkeypatch: pytest.MonkeyPatch,
    values: list[Mapping[str, Any] | BaseException],
) -> None:
    sequence = iter(values)

    def request(*_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
        value = next(sequence)
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(launch.urllib.request, "build_opener", lambda *_handlers: object())
    monkeypatch.setattr(launch, "_ollama_json_request", request)


def _valid_tags() -> dict[str, Any]:
    return {
        "models": [
            {
                "name": MODEL,
                "digest": DIGEST,
                "size": 1,
            }
        ]
    }


def test_ollama_runtime_late_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_shared_ollama_runtime({**_core_environment(), "LLM_API_BASE": ""})

    _ollama_sequence(
        monkeypatch,
        [_valid_tags(), {"version": "0.18.3"}, OSError("preload failed")],
    )
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_shared_ollama_runtime(_core_environment())

    _ollama_sequence(
        monkeypatch,
        [
            _valid_tags(),
            {"version": "0.18.3"},
            {},
            {},
            {"models": [{"name": "another-model"}]},
        ],
    )
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_shared_ollama_runtime(_core_environment())


def test_ollama_json_request_rejects_status_and_error_payload() -> None:
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._ollama_json_request(
            _Opener(_Response(b"{}", status=503)),
            "http://127.0.0.1/api/tags",
            headers={},
            timeout=1,
        )
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._ollama_json_request(
            _Opener(_Response(b'{"error":"failed"}')),
            "http://127.0.0.1/api/tags",
            headers={},
            timeout=1,
        )


def test_strix_sandbox_attestation_is_fully_stubbed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def succeed(*args: Any, **kwargs: Any) -> SimpleNamespace:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=f"sha256:{'a' * 64}|linux/amd64\n",
        )

    monkeypatch.setattr(launch.subprocess, "run", succeed)
    attestation = launch._attest_strix_sandbox_image(
        "/stub/docker",
        environment={
            "PATH": "/stub/bin",
            "HOME": "",
            "DOCKER_CONTEXT": "rootless",
        },
    )
    assert attestation["sandbox_image_id"] == f"sha256:{'a' * 64}"
    assert observed["args"][0][0] == "/stub/docker"
    assert observed["kwargs"]["env"]["DOCKER_CONTEXT"] == "rootless"
    assert "HOME" not in observed["kwargs"]["env"]

    monkeypatch.setattr(launch.subprocess, "run", _raises(OSError("no docker")))
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_strix_sandbox_image("/stub/docker", environment={})

    monkeypatch.setattr(
        launch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="invalid"),
    )
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_strix_sandbox_image("/stub/docker", environment={})


def test_tools_and_runtime_artifact_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    assert launch._tools_root({"OCTOBENCH_TOOLS_ROOT": "tools"}) == tmp_path / "tools"

    executable = tmp_path / "venv" / "bin" / "python"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"python")
    executable.chmod(0o700)
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_octopus_runtime(executable=executable, revision=REVISION)

    lock = tmp_path / "requirements" / "locks" / "linux-x86_64" / "cp312" / "runtime.txt"
    lock.parent.mkdir(parents=True)
    lock.write_bytes(b"lock")
    monkeypatch.setattr(launch, "_attest_clean_checkout", lambda *_args: "d" * 64)
    attestation = launch._attest_octopus_runtime(
        executable=executable,
        revision=REVISION,
    )
    assert attestation["source_tree_sha256"] == "d" * 64
    assert attestation["lock_sha256"] == hashlib.sha256(b"lock").hexdigest()

    tools = tmp_path / "competitor-tools"
    spec = launch._LocalRuntimeSpec(
        system_id="example",
        source_revision="e" * 40,
        source_layout="src/example",
        executable_environment="EXAMPLE_BIN",
        executable_layout="venv/bin/example",
        interpreter_layout="venv/bin/python",
        distribution_name="example",
        distribution_version="1.0",
    )
    expected_executable = tools / spec.executable_layout
    environment = {"EXAMPLE_BIN": str(expected_executable)}
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_local_runtime(spec, tools_root=tools, environment=environment)

    source = tools / spec.source_layout
    interpreter = tools / spec.interpreter_layout
    source.mkdir(parents=True)
    expected_executable.parent.mkdir(parents=True)
    expected_executable.write_bytes(b"executable")
    interpreter.write_bytes(b"python")
    expected_executable.chmod(0o700)
    interpreter.chmod(0o700)
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_local_runtime(spec, tools_root=tools, environment=environment)

    (source / spec.lock_layout).write_bytes(b"lock")
    monkeypatch.setattr(launch, "_attest_clean_checkout", lambda *_args: "f" * 64)
    monkeypatch.setattr(launch, "_installed_distribution_version", lambda *_args: "wrong")
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_local_runtime(spec, tools_root=tools, environment=environment)


def _stub_git_outputs(
    monkeypatch: pytest.MonkeyPatch,
    outputs: list[bytes],
) -> None:
    values = iter(outputs)
    monkeypatch.setattr(launch, "_git_output", lambda *_args: next(values))


def test_checkout_attestation_with_mocked_git_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    encoded_checkout = str(checkout.resolve()).encode()

    _stub_git_outputs(monkeypatch, [b"\xff"])
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_clean_checkout(checkout, REVISION)

    _stub_git_outputs(monkeypatch, [str(tmp_path).encode()])
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_clean_checkout(checkout, REVISION)

    _stub_git_outputs(monkeypatch, [encoded_checkout, b"0" * 40])
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_clean_checkout(checkout, REVISION)

    _stub_git_outputs(monkeypatch, [encoded_checkout, REVISION.encode(), b"dirty"])
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._attest_clean_checkout(checkout, REVISION)

    tree = b"100644 blob abc\tfile\n"
    _stub_git_outputs(monkeypatch, [encoded_checkout, REVISION.encode(), b"", tree])
    assert launch._attest_clean_checkout(checkout, REVISION) == hashlib.sha256(tree).hexdigest()


def test_subprocess_helpers_are_fully_stubbed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        launch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b"output"),
    )
    assert launch._git_output(tmp_path, "status") == b"output"
    monkeypatch.setattr(launch.subprocess, "run", _raises(OSError("missing")))
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._git_output(tmp_path, "status")
    monkeypatch.setattr(
        launch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=b""),
    )
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._git_output(tmp_path, "status")

    monkeypatch.setattr(
        launch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="1.2.3\n"),
    )
    assert launch._installed_distribution_version(tmp_path / "python", "package") == "1.2.3"
    monkeypatch.setattr(launch.subprocess, "run", _raises(subprocess.SubprocessError()))
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._installed_distribution_version(tmp_path / "python", "package")
    monkeypatch.setattr(
        launch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
    )
    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._installed_distribution_version(tmp_path / "python", "package")


def test_repository_helpers_are_fully_stubbed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launch, "ROOT", tmp_path)
    monkeypatch.setattr(
        launch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=REVISION + "\n"),
    )
    assert launch._repository_revision() == REVISION
    monkeypatch.setattr(
        launch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="invalid"),
    )
    with pytest.raises(launch.LaunchError, match="git_unavailable"):
        launch._repository_revision()
    monkeypatch.setattr(launch.subprocess, "run", _raises(OSError("no git")))
    with pytest.raises(launch.LaunchError, match="git_unavailable"):
        launch._repository_revision()

    monkeypatch.setattr(
        launch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b""),
    )
    assert launch._repository_is_clean() is True
    monkeypatch.setattr(
        launch.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b"dirty"),
    )
    assert launch._repository_is_clean() is False
    monkeypatch.setattr(launch.subprocess, "run", _raises(OSError("no git")))
    with pytest.raises(launch.LaunchError, match="git_unavailable"):
        launch._repository_is_clean()

    with pytest.raises(launch.LaunchError, match="runtime_unavailable"):
        launch._sha256_file(tmp_path / "missing")


def test_secret_atomic_snapshot_and_path_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(launch.LaunchError, match="secret_serialization_rejected"):
        launch._reject_serialized_secrets(
            {"payload.json": {"value": "secret-canary"}},
            environment={"SECRET": "secret-canary"},
            names=("SECRET",),
        )

    with pytest.raises(launch.LaunchError, match="generated_state_conflict"):
        launch._atomic_generated_directory(
            tmp_path / "generated",
            {"../escape.json": {"safe": True}},
        )

    symlink_root = tmp_path / "symlink-root"
    symlink_root.mkdir()
    target = symlink_root / "target"
    target.write_bytes(b"target")
    (symlink_root / "link").symlink_to(target)
    assert launch._directory_snapshot(symlink_root) is None

    mode_root = tmp_path / "mode-root"
    mode_root.mkdir()
    unsafe = mode_root / "unsafe"
    unsafe.write_bytes(b"unsafe")
    unsafe.chmod(0o644)
    assert launch._directory_snapshot(mode_root) is None

    class BrokenRoot:
        def rglob(self, _pattern: str) -> Iterator[Path]:
            raise OSError("unavailable")

    assert launch._directory_snapshot(BrokenRoot()) is None

    with pytest.raises(launch.LaunchError, match="invalid_campaign_id"):
        launch._campaign_id("../invalid")

    monkeypatch.setattr(launch, "ROOT", tmp_path / "missing-root")
    definition = launch._CAMPAIGN_DEFINITIONS[launch._DEFAULT_CAMPAIGN_DEFINITION_ID]
    with pytest.raises(launch.LaunchError, match="campaign_definition_unavailable"):
        launch._scenario_directory(definition)


def test_module_entrypoint_uses_main_guard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["launch", "--campaign-id", "../invalid"])
    with pytest.warns(RuntimeWarning, match="found in sys.modules"), pytest.raises(SystemExit) as captured:
        runpy.run_module(
            "core.benchmarks.competitors.launch",
            run_name="__main__",
            alter_sys=True,
        )
    assert captured.value.code == 2
    assert json.loads(capsys.readouterr().err) == {"error": "invalid_campaign_id"}
