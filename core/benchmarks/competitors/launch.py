"""One-command preparation and launch for the Linux black-box campaign."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..schema import BenchmarkScenario
from .adapter import STRIX_BENCHMARK_SCAN_MODE
from .campaign import CampaignConfig, run_campaign
from .labctl import LabControlError, _lab_address
from .schema import SystemManifest

ROOT = Path(__file__).resolve().parents[3]
GENERATED_SCHEMA_VERSION = "1.0"
MINIMUM_REPETITIONS = 5

_CAMPAIGN_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_MAX_ENVIRONMENT_FILE_BYTES = 262_144
_MAX_ENVIRONMENT_LINES = 512
_MAX_ENVIRONMENT_VALUE_BYTES = 65_536
_STRIX_REVISION = "91d9a847166fe2f82125643d13e099b0d989bbe4"
_STRIX_IMAGE = (
    "ghcr.io/usestrix/strix-sandbox@"
    "sha256:2e3a7e63a90428979ce34fbf80a8e83bb375d0d1146597a5d74087a259ee925c"
)
_PENTAGI_REVIEWED_REVISION = "a112db206b2fb7866c367c33348f52f5cdc207d0"
_PENTAGI_RUNTIME_SOURCE = "not-attested:service-release-v2.1.0"
_PRIVATE_BIND_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "::1/128",
    )
)

_COMMON_ADAPTER_ENVIRONMENT = (
    "PATH",
    "HOME",
    "OCTOBENCH_TARGET_URL",
    "OCTOBENCH_ACK_AUTHORIZED",
    "OCTOBENCH_ACK_ISOLATED_HOST",
)
_LAB_ENVIRONMENT = (
    "PATH",
    "HOME",
    "OCTOBENCH_TARGET_URL",
    "OCTOBENCH_HOST_IP",
    "OCTOBENCH_LAB_BIND",
    "OCTOBENCH_LAB_PORT",
)
_OPTIONAL_DOCKER_ENVIRONMENT = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "XDG_RUNTIME_DIR",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "CONTAINER_HOST",
)
_BASE_REQUIRED_ENVIRONMENT = (
    "OCTOBENCH_ACK_AUTHORIZED",
    "OCTOBENCH_ACK_ISOLATED_HOST",
    "OCTOPUS_OLLAMA_URL",
    "OCTOPUS_OLLAMA_MODEL",
    "OCTOBENCH_STRIX_BIN",
    "STRIX_IMAGE",
    "STRIX_LLM",
    "LLM_API_BASE",
)
_EXTENDED_REQUIRED_ENVIRONMENT = (
    "OCTOBENCH_PENTAGI_URL",
    "OCTOBENCH_PENTAGI_TOKEN",
    "OCTOBENCH_PENTAGI_PROVIDER",
    "OCTOBENCH_PENTAGI_MODEL",
)
_EXTENDED_SECRET_ENVIRONMENT = ("OCTOBENCH_PENTAGI_TOKEN",)

_FAIRNESS_PROFILE_BASE = {
    "same_tool_versions": False,
    "same_hardware": True,
    "same_budgets": False,
}


@dataclass(frozen=True)
class _SystemPin:
    system_id: str
    display_name: str
    version: str
    source_revision: str
    model_provider_environment: str | None
    model_name_environment: str
    adapter_environment: tuple[str, ...]


@dataclass(frozen=True)
class _LocalRuntimeSpec:
    system_id: str
    source_revision: str
    source_layout: str
    executable_environment: str
    executable_layout: str
    interpreter_layout: str
    distribution_name: str
    distribution_version: str
    lock_layout: str = "uv.lock"


_LOCAL_RUNTIME_SPECS = (
    _LocalRuntimeSpec(
        system_id="strix",
        source_revision=_STRIX_REVISION,
        source_layout="src/strix",
        executable_environment="OCTOBENCH_STRIX_BIN",
        executable_layout="venvs/strix-1.1.0/bin/strix",
        interpreter_layout="venvs/strix-1.1.0/bin/python",
        distribution_name="strix-agent",
        distribution_version="1.1.0",
    ),
)


class LaunchError(RuntimeError):
    """Launch failure whose message is a stable, non-sensitive code."""

    _CODES = frozenset(
        {
            "authorization_required",
            "campaign_failed",
            "environment_file_invalid",
            "environment_file_permissions",
            "environment_file_unavailable",
            "generated_state_conflict",
            "git_unavailable",
            "invalid_campaign_id",
            "invalid_lab_bind",
            "invalid_shared_ollama_configuration",
            "invalid_strix_image",
            "isolation_required",
            "linux_required",
            "missing_environment",
            "output_exists",
            "repository_dirty",
            "runtime_unavailable",
            "secret_serialization_rejected",
        }
    )

    def __init__(self, code: str) -> None:
        stable = code if code in self._CODES else "campaign_failed"
        self.code = stable
        super().__init__(stable)


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        campaign_id = _campaign_id(args.campaign_id)
        environment = _merged_environment(args.environment_file)
        required = _required_environment(args.profile)
        _validate_required_environment(environment, required)
        _validate_shared_ollama_configuration(environment)
        _validate_strix_image_reference(environment)
        _validated_lab_bind(environment.get("OCTOBENCH_LAB_BIND"))
        revision = _repository_revision()
        if args.prepare_only:
            config_path = _prepare_generated_campaign(
                campaign_id,
                profile=args.profile,
                environment=environment,
                environment_file=args.environment_file,
                octopus_revision=revision,
            )
            print(config_path)
            return 0
        if not sys.platform.startswith("linux"):
            raise LaunchError("linux_required")
        if not _repository_is_clean():
            raise LaunchError("repository_dirty")
        output_directory = _output_directory(campaign_id)
        if output_directory.exists() or output_directory.is_symlink():
            raise LaunchError("output_exists")
        runtime_environment = _runtime_lab_environment(environment)
        runtime_attestations = _validate_runtime_prerequisites(
            runtime_environment,
            octopus_revision=revision,
        )
        config_path = _prepare_generated_campaign(
            campaign_id,
            profile=args.profile,
            environment=runtime_environment,
            environment_file=args.environment_file,
            octopus_revision=revision,
            runtime_attestations=runtime_attestations,
        )
        outcome = run_campaign(config_path, environment=runtime_environment)
    except LaunchError as exc:
        _print_error(exc.code)
        return 2
    except LabControlError:
        _print_error("campaign_failed")
        return 2
    except Exception:
        # The launcher is a secret boundary.  Campaign, filesystem, Git and
        # runtime exception details are intentionally not reflected to stdout.
        _print_error("campaign_failed")
        return 2
    print(outcome.bundle_path)
    return int(outcome.exit_code)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare and run the pinned Linux black-box competitor campaign.",
    )
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument(
        "--profile",
        choices=("core", "extended"),
        default="core",
    )
    parser.add_argument("--environment-file", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    return parser


def _prepare_generated_campaign(
    campaign_id: str,
    *,
    profile: str,
    environment: Mapping[str, str],
    environment_file: Path | None,
    octopus_revision: str,
    runtime_attestations: Mapping[str, Mapping[str, Any]] | None = None,
) -> Path:
    systems = _system_pins(profile, octopus_revision=octopus_revision)
    generated_directory = _generated_directory(campaign_id)
    repetitions = _profile_repetitions(systems)
    payloads = {
        f"{system.system_id}.json": _manifest_payload(
            system,
            profile=profile,
            environment=environment,
            runtime_attestation=(
                runtime_attestations.get(system.system_id)
                if runtime_attestations is not None
                else None
            ),
            actual_run=runtime_attestations is not None,
        )
        for system in systems
    }
    scenario_payloads = _generated_scenario_payloads(repetitions)
    payloads.update(scenario_payloads)
    config_name = "campaign.json"
    payloads[config_name] = _campaign_payload(
        campaign_id,
        systems=systems,
        environment=environment,
        environment_file=environment_file,
        repetitions=repetitions,
    )
    for system in systems:
        SystemManifest.from_dict(
            payloads[f"{system.system_id}.json"],
            source_path=generated_directory / f"{system.system_id}.json",
        )
    for _name, payload in scenario_payloads.items():
        BenchmarkScenario.from_dict(payload)
    CampaignConfig.from_dict(
        payloads[config_name],
        source_path=generated_directory / config_name,
    )
    _reject_serialized_secrets(
        payloads,
        environment=environment,
        names=_secret_environment(profile, environment),
    )
    _atomic_generated_directory(generated_directory, payloads)
    return generated_directory / config_name


def _system_pins(
    profile: str,
    *,
    octopus_revision: str,
) -> tuple[_SystemPin, ...]:
    systems: tuple[_SystemPin, ...] = (
        _SystemPin(
            "octopus",
            "OCTOPUS",
            "v1.0.0",
            octopus_revision,
            None,
            "OCTOPUS_OLLAMA_MODEL",
            ("OCTOPUS_OLLAMA_URL", "OCTOPUS_OLLAMA_MODEL"),
        ),
        _SystemPin(
            "strix",
            "Strix",
            "v1.1.0",
            _STRIX_REVISION,
            None,
            "OCTOPUS_OLLAMA_MODEL",
            (
                "OCTOBENCH_STRIX_BIN",
                "STRIX_IMAGE",
                "STRIX_LLM",
                "LLM_API_BASE",
            ),
        ),
    )
    if profile == "extended":
        systems += (
            _SystemPin(
                "pentagi",
                "PentAGI",
                "v2.1.0",
                _PENTAGI_RUNTIME_SOURCE,
                "OCTOBENCH_PENTAGI_PROVIDER",
                "OCTOBENCH_PENTAGI_MODEL",
                _EXTENDED_REQUIRED_ENVIRONMENT,
            ),
        )
    return systems


def _manifest_payload(
    system: _SystemPin,
    *,
    profile: str,
    environment: Mapping[str, str],
    runtime_attestation: Mapping[str, Any] | None,
    actual_run: bool,
) -> dict[str, Any]:
    provider = (
        str(environment[system.model_provider_environment])
        if system.model_provider_environment is not None
        else {
            "octopus": "ollama",
            "strix": "ollama",
        }[system.system_id]
    )
    adapter_environment = tuple(
        dict.fromkeys((*_COMMON_ADAPTER_ENVIRONMENT, *system.adapter_environment))
    )
    pentagi_ca_file = str(environment.get("OCTOBENCH_PENTAGI_CA_FILE") or "").strip()
    if system.system_id == "pentagi" and pentagi_ca_file:
        adapter_environment = (*adapter_environment, "OCTOBENCH_PENTAGI_CA_FILE")
    if system.system_id == "strix":
        adapter_environment = (
            *adapter_environment,
            *_configured_optional_environment(
                environment,
                ("LLM_API_KEY",),
            ),
            *_configured_optional_environment(
                environment,
                _OPTIONAL_DOCKER_ENVIRONMENT,
            ),
        )
    python = ROOT / "venv" / "bin" / "python"
    adapter = ROOT / "benchmarks" / "competitors" / "run_adapter.py"
    if system.system_id == "pentagi":
        runtime_provenance: dict[str, Any] = {
            "attestation": "service-release-provider-model-at-adapter-runtime",
            "service_release": "2.1.0",
            "source_revision_attested": False,
        }
        if pentagi_ca_file:
            runtime_provenance["custom_ca_configured"] = True
            if actual_run:
                runtime_provenance["ca_file_sha256"] = _sha256_file(
                    Path(pentagi_ca_file)
                )
            else:
                runtime_provenance["ca_file_attestation"] = (
                    "deferred-to-actual-launch"
                )
    elif runtime_attestation is not None:
        runtime_provenance = dict(runtime_attestation)
    elif actual_run:
        raise LaunchError("runtime_unavailable")
    else:
        runtime_provenance = {
            "attestation": "deferred-to-actual-launch",
            "required_source_revision": system.source_revision,
            "source_revision_attested": False,
        }
    if system.system_id == "strix":
        if str(environment.get("STRIX_IMAGE") or "") != _STRIX_IMAGE:
            raise LaunchError("invalid_strix_image")
        runtime_provenance["sandbox_image"] = _STRIX_IMAGE
    tool_versions = {
        "command-adapter-protocol": "1.0",
        system.system_id: system.version,
    }
    if system.system_id == "strix":
        tool_versions["strix-sandbox-image"] = _STRIX_IMAGE
    return {
        "schema_version": GENERATED_SCHEMA_VERSION,
        "system_id": system.system_id,
        "name": system.display_name,
        "version": system.version,
        "source_revision": system.source_revision,
        "execution_mode": "live",
        "track": "full_system",
        "fairness_profile": _fairness_profile(profile),
        "model": {
            "provider": provider,
            "name": str(environment[system.model_name_environment]),
            "parameters": {},
        },
        "tool_versions": tool_versions,
        "adapter": {
            "kind": "command",
            "argv": [
                str(python),
                str(adapter),
                "--system",
                system.system_id,
                "--scenario",
                "{scenario_path}",
                "--output",
                "{output_path}",
            ],
            "working_directory": ".",
            "environment_passthrough": list(adapter_environment),
        },
        "metadata": {
            "campaign_profile": profile,
            "integration": "repository-command-adapter",
            "action_conformance": "not_assessed",
            **(
                {"scan_mode": STRIX_BENCHMARK_SCAN_MODE}
                if system.system_id == "strix"
                else {}
            ),
            "runtime_provenance": runtime_provenance,
        },
    }


def _campaign_payload(
    campaign_id: str,
    *,
    systems: Sequence[_SystemPin],
    environment: Mapping[str, str],
    environment_file: Path | None,
    repetitions: int,
) -> dict[str, Any]:
    python = ROOT / "venv" / "bin" / "python"
    lab = ROOT / "benchmarks" / "competitors" / "run_lab.py"
    lab_environment = (
        *_LAB_ENVIRONMENT,
        *_configured_optional_environment(
            environment,
            _OPTIONAL_DOCKER_ENVIRONMENT,
        ),
    )

    def command(action: str, timeout: float) -> dict[str, Any]:
        return {
            "argv": [str(python), str(lab), action],
            "working_directory": str(ROOT.resolve()),
            "timeout_seconds": timeout,
            "environment_passthrough": list(lab_environment),
        }
    required = tuple(
        dict.fromkeys(
            (
                *_required_environment(
                    "extended" if any(item.system_id == "pentagi" for item in systems) else "core"
                ),
                *_COMMON_ADAPTER_ENVIRONMENT,
                *_configured_optional_environment(
                    environment,
                    ("LLM_API_KEY",),
                ),
            )
        )
    )
    profile = "extended" if any(item.system_id == "pentagi" for item in systems) else "core"
    payload: dict[str, Any] = {
        "schema_version": GENERATED_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "system_manifests": [
            str(_generated_directory(campaign_id) / f"{item.system_id}.json")
            for item in systems
        ],
        "scenario_directory": str(_generated_directory(campaign_id) / "scenarios"),
        "output_directory": str(_output_directory(campaign_id)),
        "state_directory": str(ROOT / ".benchmark-state" / "journal"),
        # Six forward/reverse rotations keep both two-system core and
        # three-system extended profiles position-balanced.
        "repetitions": repetitions,
        "required_environment": list(required),
        "secret_environment": list(_secret_environment(profile, environment)),
        "strict_statuses": ["failed", "invalid", "partial", "timeout"],
        "lab": {
            "reset": command("reset", 900.0),
            "health": command("health", 30.0),
            "cleanup": command("cleanup", 900.0),
        },
    }
    if environment_file is not None:
        payload["environment_file"] = str(environment_file.resolve())
    return payload


def _profile_repetitions(systems: Sequence[_SystemPin]) -> int:
    if len(systems) not in {2, 3}:
        raise LaunchError("campaign_failed")
    return 6


def _configured_optional_environment(
    environment: Mapping[str, str],
    names: Sequence[str],
) -> tuple[str, ...]:
    return tuple(name for name in names if str(environment.get(name) or "").strip())


def _generated_scenario_payloads(repetitions: int) -> dict[str, dict[str, Any]]:
    source = _scenario_directory()
    try:
        candidates = tuple(sorted(source.glob("*.json")))
    except OSError:
        raise LaunchError("campaign_failed") from None
    if not candidates:
        raise LaunchError("campaign_failed")
    payloads: dict[str, dict[str, Any]] = {}
    for path in candidates:
        if path.is_symlink() or not path.is_file():
            raise LaunchError("campaign_failed")
        try:
            decoded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
            raise LaunchError("campaign_failed") from None
        if not isinstance(decoded, Mapping):
            raise LaunchError("campaign_failed")
        payload = dict(decoded)
        payload["repetitions"] = repetitions
        BenchmarkScenario.from_dict(payload)
        payloads[f"scenarios/{path.name}"] = payload
    return payloads


def _required_environment(profile: str) -> tuple[str, ...]:
    if profile == "extended":
        return (*_BASE_REQUIRED_ENVIRONMENT, *_EXTENDED_REQUIRED_ENVIRONMENT)
    return _BASE_REQUIRED_ENVIRONMENT


def _fairness_profile(profile: str) -> dict[str, Any]:
    shared_model = profile == "core"
    return {
        "profile_id": (
            "linux-blackbox-shared-ollama-v1"
            if shared_model
            else "linux-blackbox-shared-ollama-plus-pentagi-v1"
        ),
        "same_model": shared_model,
        "notes": (
            "OCTOPUS and Strix use the same neutral Ollama provider, model tag, "
            "weights and server; product-native prompts, request APIs and "
            "inference defaults remain distinct."
            if shared_model
            else "OCTOPUS and Strix share neutral Ollama/Qwen; PentAGI retains "
            "its separately attested service model."
        ),
        **_FAIRNESS_PROFILE_BASE,
    }


def _secret_environment(
    profile: str,
    environment: Mapping[str, str],
) -> tuple[str, ...]:
    names = list(
        _configured_optional_environment(environment, ("LLM_API_KEY",))
    )
    if profile == "extended":
        names.extend(_EXTENDED_SECRET_ENVIRONMENT)
    return tuple(names)


def _merged_environment(environment_file: Path | None) -> dict[str, str]:
    process_environment = {str(key): str(value) for key, value in os.environ.items()}
    merged = dict(process_environment)
    if environment_file is not None:
        file_values = _load_environment_file(environment_file)
        if {"PATH", "HOME", "OCTOBENCH_TARGET_URL"} & set(file_values):
            raise LaunchError("environment_file_invalid")
        merged.update(file_values)
    for name in ("PATH", "HOME"):
        if name in process_environment:
            merged[name] = process_environment[name]
    for name in (
        "OCTOBENCH_STRIX_BIN",
        "OCTOBENCH_PENTAGI_CA_FILE",
    ):
        value = str(merged.get(name) or "").strip()
        if value:
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = ROOT / path
            merged[name] = str(path.resolve())
    return merged


def _load_environment_file(path: Path) -> dict[str, str]:
    try:
        metadata = path.lstat()
    except OSError:
        raise LaunchError("environment_file_unavailable") from None
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise LaunchError("environment_file_permissions")
    if metadata.st_size > _MAX_ENVIRONMENT_FILE_BYTES:
        raise LaunchError("environment_file_invalid")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        raise LaunchError("environment_file_unavailable") from None
    if len(lines) > _MAX_ENVIRONMENT_LINES:
        raise LaunchError("environment_file_invalid")
    values: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or "=" not in line:
            raise LaunchError("environment_file_invalid")
        name, value = line.split("=", 1)
        name = name.strip()
        if not _ENVIRONMENT_NAME.fullmatch(name) or name in values:
            raise LaunchError("environment_file_invalid")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if (
            "\x00" in value
            or len(value.encode("utf-8", "replace")) > _MAX_ENVIRONMENT_VALUE_BYTES
        ):
            raise LaunchError("environment_file_invalid")
        values[name] = value
    return values


def _validate_required_environment(
    environment: Mapping[str, str],
    required: Sequence[str],
) -> None:
    if str(environment.get("OCTOBENCH_ACK_AUTHORIZED") or "") != "YES":
        raise LaunchError("authorization_required")
    if str(environment.get("OCTOBENCH_ACK_ISOLATED_HOST") or "") != "YES":
        raise LaunchError("isolation_required")
    if any(not str(environment.get(name) or "").strip() for name in required):
        raise LaunchError("missing_environment")
    if any(not str(environment.get(name) or "").strip() for name in ("PATH", "HOME")):
        raise LaunchError("missing_environment")


def _validate_strix_image_reference(environment: Mapping[str, str]) -> None:
    if str(environment.get("STRIX_IMAGE") or "").strip() != _STRIX_IMAGE:
        raise LaunchError("invalid_strix_image")


def _validate_shared_ollama_configuration(
    environment: Mapping[str, str],
) -> None:
    model = str(environment.get("OCTOPUS_OLLAMA_MODEL") or "").strip()
    strix_model = str(environment.get("STRIX_LLM") or "").strip()
    if (
        not model
        or any(character.isspace() for character in model)
        or model.casefold() == "octopus-qwen"
        or strix_model != f"ollama/{model}"
    ):
        raise LaunchError("invalid_shared_ollama_configuration")

    octopus_origin, octopus_path = _ollama_url_parts(
        environment.get("OCTOPUS_OLLAMA_URL")
    )
    strix_origin, strix_path = _ollama_url_parts(environment.get("LLM_API_BASE"))
    if (
        octopus_origin != strix_origin
        or octopus_path.rstrip("/") != "/api/generate"
        or strix_path not in {"", "/"}
    ):
        raise LaunchError("invalid_shared_ollama_configuration")


def _ollama_url_parts(value: Any) -> tuple[tuple[str, str, int], str]:
    candidate = str(value or "").strip()
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        raise LaunchError("invalid_shared_ollama_configuration") from None
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if (
        scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise LaunchError("invalid_shared_ollama_configuration")
    canonical_port = port if port is not None else (443 if scheme == "https" else 80)
    return (scheme, host, canonical_port), parsed.path


def _runtime_lab_environment(environment: Mapping[str, str]) -> dict[str, str]:
    runtime = {str(name): str(value) for name, value in environment.items()}
    target_url = _lab_address(runtime, port=None)
    split = urlsplit(target_url)
    host = split.hostname
    try:
        port = split.port
    except ValueError:
        raise LaunchError("campaign_failed") from None
    if not host or port is None:
        raise LaunchError("campaign_failed")
    try:
        target_address = ipaddress.ip_address(host)
    except ValueError:
        raise LaunchError("campaign_failed") from None
    if not _private_bind_address(target_address):
        raise LaunchError("campaign_failed")
    configured_bind = _validated_lab_bind(runtime.get("OCTOBENCH_LAB_BIND"))
    target_bind = _compose_bind(target_address)
    if configured_bind is not None and configured_bind != target_bind:
        raise LaunchError("invalid_lab_bind")
    runtime["OCTOBENCH_TARGET_URL"] = target_url
    runtime["OCTOBENCH_HOST_IP"] = target_address.compressed
    runtime["OCTOBENCH_LAB_PORT"] = str(port)
    runtime["OCTOBENCH_LAB_BIND"] = configured_bind or target_bind
    return runtime


def _validated_lab_bind(value: Any) -> str | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    elif "[" in candidate or "]" in candidate:
        raise LaunchError("invalid_lab_bind")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        raise LaunchError("invalid_lab_bind") from None
    if not _private_bind_address(address):
        raise LaunchError("invalid_lab_bind")
    return _compose_bind(address)


def _private_bind_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return not address.is_unspecified and any(
        address in network for network in _PRIVATE_BIND_NETWORKS
    )


def _compose_bind(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return f"[{address.compressed}]" if address.version == 6 else address.compressed


def _validate_runtime_prerequisites(
    environment: Mapping[str, str],
    *,
    octopus_revision: str,
) -> dict[str, dict[str, Any]]:
    octopus_python = ROOT / "venv" / "bin" / "python"
    if not octopus_python.is_file() or not os.access(octopus_python, os.X_OK):
        raise LaunchError("runtime_unavailable")
    launchers = (
        ROOT / "benchmarks" / "competitors" / "run_adapter.py",
        ROOT / "benchmarks" / "competitors" / "run_lab.py",
    )
    if any(not path.is_file() for path in launchers):
        raise LaunchError("runtime_unavailable")
    search_path = str(environment.get("PATH") or os.defpath)
    docker = shutil.which("docker", path=search_path)
    if docker is None:
        raise LaunchError("runtime_unavailable")
    attestations = {
        "octopus": _attest_octopus_runtime(
            executable=octopus_python,
            revision=octopus_revision,
        )
    }
    tools_root = _tools_root(environment)
    for spec in _LOCAL_RUNTIME_SPECS:
        attestations[spec.system_id] = _attest_local_runtime(
            spec,
            tools_root=tools_root,
            environment=environment,
        )
    attestations["strix"].update(
        _attest_strix_sandbox_image(docker, environment=environment)
    )
    return attestations


def _attest_strix_sandbox_image(
    docker: str,
    *,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    docker_environment = dict(os.environ)
    for name in ("PATH", "HOME", *_OPTIONAL_DOCKER_ENVIRONMENT):
        value = str(environment.get(name) or "").strip()
        if value:
            docker_environment[name] = value
        else:
            docker_environment.pop(name, None)
    try:
        completed = subprocess.run(
            [
                docker,
                "image",
                "inspect",
                "--format",
                "{{.Id}}|{{.Os}}/{{.Architecture}}",
                _STRIX_IMAGE,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=30,
            text=True,
            env=docker_environment,
        )
    except (OSError, subprocess.SubprocessError):
        raise LaunchError("runtime_unavailable") from None
    parts = completed.stdout.strip().lower().split("|", 1)
    if (
        completed.returncode != 0
        or len(parts) != 2
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", parts[0])
        or parts[1] != "linux/amd64"
    ):
        raise LaunchError("runtime_unavailable")
    return {
        "sandbox_image": _STRIX_IMAGE,
        "sandbox_image_id": parts[0],
        "sandbox_platform": parts[1],
    }


def _tools_root(environment: Mapping[str, str]) -> Path:
    configured = str(environment.get("OCTOBENCH_TOOLS_ROOT") or "").strip()
    path = Path(configured).expanduser() if configured else ROOT / ".benchmark-tools"
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def _attest_octopus_runtime(
    *,
    executable: Path,
    revision: str,
) -> dict[str, Any]:
    lock = ROOT / "requirements" / "locks" / "linux-x86_64" / "cp312" / "runtime.txt"
    if not lock.is_file():
        raise LaunchError("runtime_unavailable")
    source_tree_sha256 = _attest_clean_checkout(ROOT, revision)
    return {
        "attestation": "clean-checkout-and-runtime-artifacts",
        "checkout_revision": revision,
        "source_tree_sha256": source_tree_sha256,
        "lock_layout": "requirements/locks/linux-x86_64/cp312/runtime.txt",
        "lock_sha256": _sha256_file(lock),
        "executable_layout": "venv/bin/python",
        "executable_sha256": _sha256_file(executable),
        "source_revision_attested": True,
    }


def _attest_local_runtime(
    spec: _LocalRuntimeSpec,
    *,
    tools_root: Path,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    source = (tools_root / spec.source_layout).resolve()
    executable = (tools_root / spec.executable_layout).resolve()
    # Keep the virtualenv entry point intact. Resolving ``bin/python`` follows
    # its normal symlink to the system interpreter and bypasses the venv where
    # the competitor distribution is installed.
    interpreter = tools_root / spec.interpreter_layout
    configured = Path(
        str(environment.get(spec.executable_environment) or "")
    ).expanduser().resolve()
    if configured != executable:
        raise LaunchError("runtime_unavailable")
    if (
        not source.is_dir()
        or not executable.is_file()
        or not os.access(executable, os.X_OK)
        or not interpreter.is_file()
        or not os.access(interpreter, os.X_OK)
    ):
        raise LaunchError("runtime_unavailable")
    lock = source / spec.lock_layout
    if not lock.is_file():
        raise LaunchError("runtime_unavailable")
    source_tree_sha256 = _attest_clean_checkout(source, spec.source_revision)
    installed_version = _installed_distribution_version(
        interpreter,
        spec.distribution_name,
    )
    if installed_version != spec.distribution_version:
        raise LaunchError("runtime_unavailable")
    return {
        "attestation": "clean-checkout-and-runtime-artifacts",
        "checkout_revision": spec.source_revision,
        "source_layout": spec.source_layout,
        "source_tree_sha256": source_tree_sha256,
        "lock_layout": f"{spec.source_layout}/{spec.lock_layout}",
        "lock_sha256": _sha256_file(lock),
        "executable_layout": spec.executable_layout,
        "executable_sha256": _sha256_file(executable),
        "distribution_name": spec.distribution_name,
        "distribution_version": installed_version,
        "source_revision_attested": True,
    }


def _attest_clean_checkout(path: Path, expected_revision: str) -> str:
    top_level = _git_output(path, "rev-parse", "--show-toplevel")
    try:
        resolved_top_level = Path(top_level.decode("utf-8").strip()).resolve()
    except UnicodeError:
        raise LaunchError("runtime_unavailable") from None
    if resolved_top_level != path.resolve():
        raise LaunchError("runtime_unavailable")
    head = _git_output(path, "rev-parse", "HEAD").decode("ascii", "strict").strip().lower()
    if head != expected_revision:
        raise LaunchError("runtime_unavailable")
    status = _git_output(
        path,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status:
        raise LaunchError("runtime_unavailable")
    tree = _git_output(path, "ls-tree", "-r", "--full-tree", "HEAD")
    return hashlib.sha256(tree).hexdigest()


def _git_output(path: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=str(path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        raise LaunchError("runtime_unavailable") from None
    if completed.returncode != 0:
        raise LaunchError("runtime_unavailable")
    return completed.stdout


def _installed_distribution_version(interpreter: Path, distribution: str) -> str:
    script = (
        "import importlib.metadata as m,sys;"
        "sys.stdout.write(m.version(sys.argv[1]))"
    )
    try:
        completed = subprocess.run(
            [str(interpreter), "-I", "-c", script, distribution],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=15,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise LaunchError("runtime_unavailable") from None
    if completed.returncode != 0:
        raise LaunchError("runtime_unavailable")
    return completed.stdout.strip()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        raise LaunchError("runtime_unavailable") from None
    return digest.hexdigest()


def _repository_revision() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=5,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise LaunchError("git_unavailable") from None
    revision = completed.stdout.strip().lower()
    if completed.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise LaunchError("git_unavailable")
    return revision


def _repository_is_clean() -> bool:
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            shell=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise LaunchError("git_unavailable") from None
    return completed.returncode == 0 and not completed.stdout


def _reject_serialized_secrets(
    payloads: Mapping[str, Mapping[str, Any]],
    *,
    environment: Mapping[str, str],
    names: Sequence[str],
) -> None:
    serialized = json.dumps(payloads, sort_keys=True, separators=(",", ":"))
    for name in names:
        value = str(environment.get(name) or "")
        if len(value) >= 4 and value in serialized:
            raise LaunchError("secret_serialization_rejected")


def _atomic_generated_directory(
    destination: Path,
    payloads: Mapping[str, Mapping[str, Any]],
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.tmp-",
            dir=str(destination.parent),
        )
    )
    try:
        for name, payload in sorted(payloads.items()):
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts or not relative.name:
                raise LaunchError("generated_state_conflict")
            path = temporary / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.parent.chmod(0o700)
            path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
        if destination.exists() or destination.is_symlink():
            if (
                destination.is_symlink()
                or not destination.is_dir()
                or not _directories_equal(destination, temporary)
            ):
                raise LaunchError("generated_state_conflict")
            return
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)


def _directories_equal(left: Path, right: Path) -> bool:
    left_snapshot = _directory_snapshot(left)
    right_snapshot = _directory_snapshot(right)
    return left_snapshot is not None and left_snapshot == right_snapshot


def _directory_snapshot(root: Path) -> dict[str, bytes] | None:
    snapshot: dict[str, bytes] = {}
    try:
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                return None
            if path.is_dir():
                continue
            if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
                return None
            snapshot[path.relative_to(root).as_posix()] = path.read_bytes()
    except OSError:
        return None
    return snapshot


def _campaign_id(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    if not _CAMPAIGN_ID.fullmatch(candidate):
        raise LaunchError("invalid_campaign_id")
    return candidate


def _generated_directory(campaign_id: str) -> Path:
    return ROOT / ".benchmark-state" / "generated" / campaign_id


def _scenario_directory() -> Path:
    return ROOT / "benchmarks" / "competitors" / "campaigns" / "linux-blackbox-v1" / "scenarios"


def _output_directory(campaign_id: str) -> Path:
    return ROOT / "benchmarks" / "competitors" / "results" / campaign_id


def _print_error(code: str) -> None:
    print(
        json.dumps({"error": code}, sort_keys=True, separators=(",", ":")),
        file=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
