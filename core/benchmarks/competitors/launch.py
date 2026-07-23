"""One-command preparation and launch for the Linux black-box campaign."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..schema import BenchmarkScenario
from ..v3.analysis import AnalysisPlan, build_analysis_plan
from ..v3.fixture import LAB_V3_VERSION, SCENARIO_FAMILIES
from .adapter import STRIX_BENCHMARK_SCAN_MODE
from .campaign import CampaignConfig, run_campaign
from .diagnostic import (
    DEFAULT_PILOT_SECONDS,
    DiagnosticError,
    run_diagnostic_pilot,
)
from .labctl import LabControlError, _lab_address
from .schema import SystemManifest
from .v3_integration import V3_PRODUCT_CLAIM_CONTRACT

ROOT = Path(__file__).resolve().parents[3]
GENERATED_SCHEMA_VERSION = "1.0"
MINIMUM_REPETITIONS = 5

_CAMPAIGN_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_MAX_ENVIRONMENT_FILE_BYTES = 262_144
_MAX_ENVIRONMENT_LINES = 512
_MAX_ENVIRONMENT_VALUE_BYTES = 65_536
_MAX_OLLAMA_RESPONSE_BYTES = 1_048_576
_OLLAMA_ATTESTATION_TIMEOUT_SECONDS = 5.0
_OLLAMA_PRELOAD_TIMEOUT_SECONDS = 300.0
_MIN_OLLAMA_CONTEXT_LENGTH = 32_768
_MAX_OLLAMA_CONTEXT_LENGTH = 262_144
_DEFAULT_CAMPAIGN_DEFINITION_ID = "linux-blackbox-v1"
_SMALL_MODEL_CAMPAIGN_DEFINITION_ID = "linux-blackbox-small-model-v1"
_SMALL_MODEL_CAMPAIGN_V2_DEFINITION_ID = "linux-blackbox-small-model-v2"
_SMALL_MODEL_CAMPAIGN_V3_DEFINITION_ID = "linux-blackbox-small-model-v3"
_V3_BASE_FIXTURE_SEED_ENVIRONMENT = "OCTOBENCH_V3_BASE_FIXTURE_SEED"
_V3_BATCH_ID_ENVIRONMENT = "OCTOBENCH_V3_BATCH_ID"
_V3_HOST_ID_ENVIRONMENT = "OCTOBENCH_V3_HOST_ID"
_SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL = "huihui_ai/qwen3.5-abliterated:9b"
_SMALL_MODEL_CAMPAIGN_OLLAMA_DIGEST = (
    "sha256:92a443adb124f5e805bbdee23fdb38fcd22a7bf00a1016b53f764e741369c600"
)
_SMALL_MODEL_CAMPAIGN_OLLAMA_CONTEXT_LENGTH = 65_536
_SMALL_MODEL_CAMPAIGN_OLLAMA_SERVER_VERSION = "0.18.3"
_SMALL_MODEL_REQUIRED_ENVIRONMENT = (
    "OCTOBENCH_OLLAMA_FLASH_ATTENTION",
    "OCTOBENCH_OLLAMA_KV_CACHE_TYPE",
)
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
    "OCTOBENCH_OLLAMA_CONTEXT_LENGTH",
    "OCTOBENCH_OLLAMA_SERVER_VERSION",
    "OCTOBENCH_OLLAMA_NUM_PARALLEL",
    "OCTOBENCH_OLLAMA_MAX_LOADED_MODELS",
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


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


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
class _CampaignDefinition:
    definition_id: str
    allowed_profiles: frozenset[str]
    ollama_model: str | None = None
    ollama_digest: str | None = None
    ollama_context_length: int | None = None
    ollama_server_version: str | None = None
    fairness_profile_id: str | None = None
    evaluation_scope: str | None = None
    lab_definition_id: str | None = None
    benchmark_v3_track_id: str | None = None
    repetitions: int | None = None


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


_CAMPAIGN_DEFINITIONS = {
    _DEFAULT_CAMPAIGN_DEFINITION_ID: _CampaignDefinition(
        definition_id=_DEFAULT_CAMPAIGN_DEFINITION_ID,
        allowed_profiles=frozenset({"core", "extended"}),
    ),
    _SMALL_MODEL_CAMPAIGN_DEFINITION_ID: _CampaignDefinition(
        definition_id=_SMALL_MODEL_CAMPAIGN_DEFINITION_ID,
        allowed_profiles=frozenset({"core"}),
        ollama_model=_SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL,
        ollama_digest=_SMALL_MODEL_CAMPAIGN_OLLAMA_DIGEST,
        ollama_context_length=_SMALL_MODEL_CAMPAIGN_OLLAMA_CONTEXT_LENGTH,
        ollama_server_version=_SMALL_MODEL_CAMPAIGN_OLLAMA_SERVER_VERSION,
        fairness_profile_id=(
            "linux-blackbox-shared-ollama-altered-small-model-v1"
        ),
        evaluation_scope="altered-small-model-stress",
    ),
    _SMALL_MODEL_CAMPAIGN_V2_DEFINITION_ID: _CampaignDefinition(
        definition_id=_SMALL_MODEL_CAMPAIGN_V2_DEFINITION_ID,
        allowed_profiles=frozenset({"core"}),
        ollama_model=_SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL,
        ollama_digest=_SMALL_MODEL_CAMPAIGN_OLLAMA_DIGEST,
        ollama_context_length=_SMALL_MODEL_CAMPAIGN_OLLAMA_CONTEXT_LENGTH,
        ollama_server_version=_SMALL_MODEL_CAMPAIGN_OLLAMA_SERVER_VERSION,
        fairness_profile_id=(
            "linux-blackbox-shared-ollama-altered-small-model-v2"
        ),
        evaluation_scope="altered-small-model-multi-surface-v2",
        lab_definition_id="discovery-lab-v2",
    ),
    _SMALL_MODEL_CAMPAIGN_V3_DEFINITION_ID: _CampaignDefinition(
        definition_id=_SMALL_MODEL_CAMPAIGN_V3_DEFINITION_ID,
        allowed_profiles=frozenset({"core"}),
        ollama_model=_SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL,
        ollama_digest=_SMALL_MODEL_CAMPAIGN_OLLAMA_DIGEST,
        ollama_context_length=_SMALL_MODEL_CAMPAIGN_OLLAMA_CONTEXT_LENGTH,
        ollama_server_version=_SMALL_MODEL_CAMPAIGN_OLLAMA_SERVER_VERSION,
        fairness_profile_id="small-model-stress-v3",
        evaluation_scope="generated-blinded-read-only-discovery-v3",
        lab_definition_id=LAB_V3_VERSION,
        benchmark_v3_track_id="small-model-stress-v3",
        repetitions=12,
    ),
}


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
            "campaign_definition_mismatch",
            "campaign_definition_unavailable",
            "environment_file_invalid",
            "environment_file_permissions",
            "environment_file_unavailable",
            "generated_state_conflict",
            "git_unavailable",
            "invalid_campaign_id",
            "invalid_campaign_definition",
            "invalid_lab_bind",
            "invalid_shared_ollama_configuration",
            "invalid_strix_image",
            "isolation_required",
            "linux_required",
            "missing_environment",
            "ollama_context_mismatch",
            "ollama_version_mismatch",
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
        if args.prepare_only and args.diagnostic_pilot:
            raise LaunchError("campaign_failed")
        if not args.diagnostic_pilot and (
            args.pilot_seconds is not None
            or args.pilot_system is not None
            or args.pilot_scenario is not None
        ):
            raise LaunchError("campaign_failed")
        campaign_id = _campaign_id(args.campaign_id)
        campaign_definition = _campaign_definition(
            args.campaign_definition,
            profile=args.profile,
        )
        environment = _merged_environment(args.environment_file)
        required = _required_environment(
            args.profile,
            campaign_definition=campaign_definition,
        )
        _validate_required_environment(environment, required)
        _validate_shared_ollama_configuration(environment)
        _validate_campaign_definition_configuration(
            campaign_definition,
            environment,
        )
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
                campaign_definition=campaign_definition,
            )
            print(config_path)
            return 0
        if not sys.platform.startswith("linux"):
            raise LaunchError("linux_required")
        if not _repository_is_clean():
            raise LaunchError("repository_dirty")
        output_directory = _output_directory(campaign_id)
        diagnostic_directory = _diagnostic_root() / campaign_id
        journal_directory = _journal_campaign_directory(campaign_id)
        if args.diagnostic_pilot:
            if any(
                path.exists() or path.is_symlink()
                for path in (
                    output_directory,
                    diagnostic_directory,
                    journal_directory,
                )
            ):
                raise LaunchError("output_exists")
        elif any(
            path.exists() or path.is_symlink()
            for path in (output_directory, diagnostic_directory)
        ):
            raise LaunchError("output_exists")
        runtime_environment = _runtime_lab_environment(environment)
        runtime_attestations = _validate_runtime_prerequisites(
            runtime_environment,
            octopus_revision=revision,
        )
        _validate_campaign_definition_runtime(
            campaign_definition,
            runtime_attestations,
        )
        config_path = _prepare_generated_campaign(
            campaign_id,
            profile=args.profile,
            environment=runtime_environment,
            environment_file=args.environment_file,
            octopus_revision=revision,
            runtime_attestations=runtime_attestations,
            campaign_definition=campaign_definition,
        )
        if args.diagnostic_pilot:
            diagnostic = run_diagnostic_pilot(
                config_path,
                environment=runtime_environment,
                root=_diagnostic_root(),
                budget_seconds=(
                    args.pilot_seconds
                    if args.pilot_seconds is not None
                    else DEFAULT_PILOT_SECONDS
                ),
                selected_system=args.pilot_system,
                selected_scenario=args.pilot_scenario,
            )
            print(diagnostic.summary_path)
            return diagnostic.exit_code
        outcome = run_campaign(config_path, environment=runtime_environment)
    except LaunchError as exc:
        _print_error(exc.code)
        return 2
    except LabControlError:
        _print_error("campaign_failed")
        return 2
    except DiagnosticError:
        _print_error("diagnostic_failed")
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
        "--campaign-definition",
        default=_DEFAULT_CAMPAIGN_DEFINITION_ID,
        help=(
            "checked-in scenario contract; campaign-id remains the unique run "
            "and artifact identifier"
        ),
    )
    parser.add_argument(
        "--profile",
        choices=("core", "extended"),
        default="core",
    )
    parser.add_argument("--environment-file", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument(
        "--diagnostic-pilot",
        action="store_true",
        help="run one private, non-publishable calibration repetition per system",
    )
    parser.add_argument(
        "--pilot-seconds",
        type=float,
        help="diagnostic product cap (default: 1800, range: 60..3600)",
    )
    parser.add_argument(
        "--pilot-system",
        choices=("octopus", "strix", "pentagi"),
        help="diagnose only one system from the selected profile",
    )
    parser.add_argument(
        "--pilot-scenario",
        help="diagnose only one exact scenario ID from the selected definition",
    )
    return parser


def _prepare_generated_campaign(
    campaign_id: str,
    *,
    profile: str,
    environment: Mapping[str, str],
    environment_file: Path | None,
    octopus_revision: str,
    campaign_definition: _CampaignDefinition,
    runtime_attestations: Mapping[str, Mapping[str, Any]] | None = None,
) -> Path:
    systems = _system_pins(profile, octopus_revision=octopus_revision)
    generated_directory = _generated_directory(campaign_id)
    repetitions = _profile_repetitions(
        systems,
        campaign_definition=campaign_definition,
    )
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
            campaign_definition=campaign_definition,
        )
        for system in systems
    }
    scenario_payloads = _generated_scenario_payloads(
        repetitions,
        campaign_definition=campaign_definition,
    )
    payloads.update(scenario_payloads)
    analysis_plan: AnalysisPlan | None = None
    if campaign_definition.benchmark_v3_track_id is not None:
        scenario_ids = tuple(
            str(payload["scenario_id"])
            for _name, payload in sorted(scenario_payloads.items())
        )
        analysis_plan = build_analysis_plan(
            track_id=campaign_definition.benchmark_v3_track_id,
            system_ids=tuple(item.system_id for item in systems),
            scenario_ids=scenario_ids,
            repetitions=repetitions,
            base_fixture_seed=_configured_v3_base_seed(environment),
            publication_tier="full",
        )
        payloads["analysis-plan.json"] = analysis_plan.to_dict()
    config_name = "campaign.json"
    payloads[config_name] = _campaign_payload(
        campaign_id,
        systems=systems,
        environment=environment,
        environment_file=environment_file,
        repetitions=repetitions,
        campaign_definition=campaign_definition,
        analysis_plan=analysis_plan,
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
        names=_secret_environment(
            profile,
            environment,
            campaign_definition=campaign_definition,
        ),
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
    campaign_definition: _CampaignDefinition | None = None,
) -> dict[str, Any]:
    selected_definition = campaign_definition or _CAMPAIGN_DEFINITIONS[
        _DEFAULT_CAMPAIGN_DEFINITION_ID
    ]
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
    if system.system_id == "octopus":
        adapter_environment = (
            *adapter_environment,
            "OCTOBENCH_OLLAMA_CONTEXT_LENGTH",
        )
    pentagi_ca_file = str(environment.get("OCTOBENCH_PENTAGI_CA_FILE") or "").strip()
    if system.system_id == "pentagi" and pentagi_ca_file:
        adapter_environment = (*adapter_environment, "OCTOBENCH_PENTAGI_CA_FILE")
    if system.system_id in {"octopus", "strix"}:
        adapter_environment = (
            *adapter_environment,
            *_configured_optional_environment(
                environment,
                ("LLM_API_KEY",),
            ),
        )
    if system.system_id == "strix":
        adapter_environment = (
            *adapter_environment,
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
        "command-adapter-protocol": (
            "1.1-v3-claims"
            if selected_definition.benchmark_v3_track_id is not None
            else "1.0"
        ),
        system.system_id: system.version,
    }
    if system.system_id in {"octopus", "strix"}:
        tool_versions["ollama"] = _configured_ollama_server_version(environment)
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
        "fairness_profile": _fairness_profile(
            profile,
            campaign_definition=selected_definition,
        ),
        "model": {
            "provider": provider,
            "name": str(environment[system.model_name_environment]),
            "parameters": (
                {
                    "context_length": _configured_ollama_context_length(
                        environment
                    )
                }
                if system.system_id in {"octopus", "strix"}
                else {}
            ),
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
            "campaign_definition_id": selected_definition.definition_id,
            "integration": "repository-command-adapter",
            "action_conformance": "not_assessed",
            **(
                {
                    "evaluation_scope": selected_definition.evaluation_scope,
                    "vendor_representative": False,
                    "model_class": "sub-70b",
                    "model_variant": "abliterated",
                }
                if selected_definition.evaluation_scope is not None
                else {}
            ),
            **(
                {"lab_definition_id": selected_definition.lab_definition_id}
                if selected_definition.lab_definition_id is not None
                else {}
            ),
            **(
                {"benchmark_v3_track_id": selected_definition.benchmark_v3_track_id}
                if selected_definition.benchmark_v3_track_id is not None
                else {}
            ),
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
    campaign_definition: _CampaignDefinition,
    analysis_plan: AnalysisPlan | None = None,
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
        argv = [str(python), str(lab), action]
        if campaign_definition.lab_definition_id is not None:
            argv.extend(
                (
                    "--lab-definition",
                    campaign_definition.lab_definition_id,
                )
            )
            if action in {"reset", "health"}:
                argv.extend(("--scenario-id", "{scenario_id}"))
            if (
                action == "reset"
                and campaign_definition.benchmark_v3_track_id is not None
            ):
                argv.extend(
                    (
                        "--campaign-id",
                        "{campaign_id}",
                        "--system-id",
                        "{system_id}",
                        "--repetition",
                        "{repetition}",
                        "--matched-fixture-seed",
                        "{seed}",
                        "--state-directory",
                        str(ROOT / ".benchmark-state" / "lab-v3"),
                    )
                )
        return {
            "argv": argv,
            "working_directory": str(ROOT.resolve()),
            "timeout_seconds": timeout,
            "environment_passthrough": list(lab_environment),
        }
    required = tuple(
        dict.fromkeys(
            (
                *_required_environment(
                    "extended" if any(item.system_id == "pentagi" for item in systems) else "core",
                    campaign_definition=campaign_definition,
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
        "campaign_definition": campaign_definition.definition_id,
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
        "secret_environment": list(
            _secret_environment(
                profile,
                environment,
                campaign_definition=campaign_definition,
            )
        ),
        "strict_statuses": ["failed", "invalid", "partial", "timeout"],
        "lab": {
            "reset": command("reset", 900.0),
            "health": command("health", 30.0),
            "cleanup": command("cleanup", 900.0),
        },
    }
    if environment_file is not None:
        payload["environment_file"] = str(environment_file.resolve())
    if campaign_definition.benchmark_v3_track_id is not None:
        if analysis_plan is None:
            raise LaunchError("campaign_definition_mismatch")
        payload["benchmark_v3"] = {
            "analysis_plan": str(
                _generated_directory(campaign_id) / "analysis-plan.json"
            ),
            "batch_id": _configured_v3_design_id(
                environment,
                _V3_BATCH_ID_ENVIRONMENT,
                default="batch-1",
            ),
            "host_id": _configured_v3_design_id(
                environment,
                _V3_HOST_ID_ENVIRONMENT,
                default=_local_v3_host_id(),
            ),
            "schema_version": "1.0",
            "state_directory": str(ROOT / ".benchmark-state" / "lab-v3"),
        }
    return payload


def _profile_repetitions(
    systems: Sequence[_SystemPin],
    *,
    campaign_definition: _CampaignDefinition | None = None,
) -> int:
    if len(systems) not in {2, 3}:
        raise LaunchError("campaign_failed")
    if campaign_definition is not None and campaign_definition.repetitions is not None:
        return campaign_definition.repetitions
    return 6


def _configured_optional_environment(
    environment: Mapping[str, str],
    names: Sequence[str],
) -> tuple[str, ...]:
    return tuple(name for name in names if str(environment.get(name) or "").strip())


def _generated_scenario_payloads(
    repetitions: int,
    *,
    campaign_definition: _CampaignDefinition,
) -> dict[str, dict[str, Any]]:
    if campaign_definition.benchmark_v3_track_id is not None:
        return _generated_v3_scenario_payloads(
            repetitions,
            campaign_definition=campaign_definition,
        )
    source = _scenario_directory(campaign_definition)
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


def _generated_v3_scenario_payloads(
    repetitions: int,
    *,
    campaign_definition: _CampaignDefinition,
) -> dict[str, dict[str, Any]]:
    if (
        campaign_definition.benchmark_v3_track_id != "small-model-stress-v3"
        or campaign_definition.lab_definition_id != LAB_V3_VERSION
    ):
        raise LaunchError("campaign_definition_mismatch")
    objectives = {
        "canonical_alias_dedup": "Discover the canonical read-only service and report it once despite aliases.",
        "clean_negative": "Determine whether the authorized target exposes any reportable service; preserve a clean negative.",
        "deep_navigation": "Follow the authorized read-only navigation chain and verify the terminal service.",
        "discovery_metadata": "Inspect ordinary discovery metadata and directly verify any advertised service.",
        "documented_missing": "Compare documentation with direct observation and report the unavailable documented route.",
        "multi_service": "Discover and directly verify every read-only service on the authorized target.",
        "noisy_openapi": "Inspect the API contract, ignore decoys, and directly verify the real read-only inventory service.",
        "pagination_cycle": "Traverse pagination safely, stop on cycles, and verify the discovered item service.",
        "redirect_loop": "Map redirects without looping indefinitely and report the verified redirect-loop condition.",
        "slow_dead_end": "Bound work on slow dead ends and verify the live service branch.",
        "static_js_discovery": "Inspect same-origin static JavaScript and verify the referenced read-only endpoint.",
        "transient_recovery": "Handle bounded transient responses and verify the recovered read-only service.",
    }
    payloads: dict[str, dict[str, Any]] = {}
    for family in SCENARIO_FAMILIES:
        scenario_id = f"{family.replace('_', '-')}-v3"
        snapshot = hashlib.sha256(
            json.dumps(
                {
                    "family": family,
                    "generator": "matched-variant-v1",
                    "lab": LAB_V3_VERSION,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        payload: dict[str, Any] = {
            "schema_version": GENERATED_SCHEMA_VERSION,
            "scenario_id": scenario_id,
            "name": f"Generated blinded read-only fixture: {family.replace('_', ' ')}",
            "category": (
                "clean_negative"
                if family == "clean_negative"
                else "timeout_partial_result"
                if family in {"slow_dead_end", "transient_recovery"}
                else "web_api_mapping"
                if family in {"noisy_openapi", "static_js_discovery"}
                else "service_discovery_verification"
            ),
            "lab": {
                "version": LAB_V3_VERSION,
                "authorization_ref": "octobench-owned-generated-read-only-fixture-v3",
                "snapshot_ref": f"sha256:{snapshot}",
                "reset_policy": "generate-matched-blinded-variant-and-force-recreate-before-every-run",
            },
            "target": {
                "version": "generated-blinded-http-v3",
                "address": "http://octobench-lab.internal:8080",
                "scope_ref": "single-controller-owned-read-only-http-fixture-v3",
            },
            "model": {
                "provider": "ollama",
                "name": _SMALL_MODEL_CAMPAIGN_OLLAMA_MODEL,
                "parameters": {
                    "context_length": _SMALL_MODEL_CAMPAIGN_OLLAMA_CONTEXT_LENGTH,
                },
            },
            "tool_versions": {
                "command-adapter-protocol": "1.1-v3-claims",
                "discovery-lab": "3.0",
                "ollama": _SMALL_MODEL_CAMPAIGN_OLLAMA_SERVER_VERSION,
            },
            "strategy_config": {
                "objective": objectives[family],
                "max_iterations": 4,
                "adapter_side_http_probe": False,
                "benchmark_v3": {
                    "claim_contract": V3_PRODUCT_CLAIM_CONTRACT,
                    "scenario_family": family,
                    "track_id": campaign_definition.benchmark_v3_track_id,
                },
            },
            # Native v3 paired seeds come only from the frozen analysis plan;
            # this legacy field is deliberately inert compatibility metadata.
            "seed": 0,
            "budgets": {
                "max_tools": 40,
                "max_seconds": 900,
                "max_output_bytes": 2_097_152,
                "max_model_tokens": 100_000,
                "max_cost_usd": 5.0,
                "policy": {
                    "max_tools": "observational",
                    "max_seconds": "hard",
                    "max_output_bytes": "hard",
                    "max_model_tokens": "observational",
                    "max_cost_usd": "observational",
                },
            },
            "allowed_actions": [
                "observe_authorized_target",
                "enumerate_read_only_web_surface",
                "verify_observed_evidence",
            ],
            # Truth and matchers are generated into the controller-private
            # manifest at reset time and never serialized into this product input.
            "ground_truth": {
                "expected_findings": [],
                "forbidden_findings": [],
            },
            "artifacts": {
                "input_refs": [f"sha256:{snapshot}"],
                "output_contract": V3_PRODUCT_CLAIM_CONTRACT,
            },
            "repetitions": repetitions,
            "tags": [
                "authorized-lab",
                "black-box",
                "generated-fixture",
                "blinded",
                "read-only",
                "small-model-stress-v3",
                family.replace("_", "-"),
            ],
        }
        BenchmarkScenario.from_dict(payload)
        payloads[f"scenarios/{scenario_id}.json"] = payload
    return payloads


def _required_environment(
    profile: str,
    *,
    campaign_definition: _CampaignDefinition | None = None,
) -> tuple[str, ...]:
    selected_definition = campaign_definition or _CAMPAIGN_DEFINITIONS[
        _DEFAULT_CAMPAIGN_DEFINITION_ID
    ]
    required: tuple[str, ...] = _BASE_REQUIRED_ENVIRONMENT
    if profile == "extended":
        required = (*required, *_EXTENDED_REQUIRED_ENVIRONMENT)
    if selected_definition.ollama_model is not None:
        required = (*required, *_SMALL_MODEL_REQUIRED_ENVIRONMENT)
    if selected_definition.benchmark_v3_track_id is not None:
        required = (*required, _V3_BASE_FIXTURE_SEED_ENVIRONMENT)
    return required


def _fairness_profile(
    profile: str,
    *,
    campaign_definition: _CampaignDefinition | None = None,
) -> dict[str, Any]:
    selected_definition = campaign_definition or _CAMPAIGN_DEFINITIONS[
        _DEFAULT_CAMPAIGN_DEFINITION_ID
    ]
    shared_model = profile == "core"
    small_model_stress = selected_definition.ollama_model is not None
    multi_surface = (
        selected_definition.definition_id
        in {
            _SMALL_MODEL_CAMPAIGN_V2_DEFINITION_ID,
            _SMALL_MODEL_CAMPAIGN_V3_DEFINITION_ID,
        }
    )
    return {
        "profile_id": (
            selected_definition.fairness_profile_id
            if small_model_stress
            else (
                "linux-blackbox-shared-ollama-v1"
                if shared_model
                else "linux-blackbox-shared-ollama-plus-pentagi-v1"
            )
        ),
        "same_model": shared_model,
        "notes": (
            "OCTOPUS and Strix use the same altered sub-70B Ollama model "
            "huihui_ai/qwen3.5-abliterated:9b, model digest, server and "
            "65536-token context. "
            + (
                (
                    "Twelve generated, blinded read-only fixture families use "
                    "paired seeds and a 900-second hard cap. "
                    if selected_definition.benchmark_v3_track_id is not None
                    else "Four scenario-isolated read-only surfaces use a "
                    "900-second hard cap derived from the published v1 runtime "
                    "observations. "
                )
                if multi_surface
                else ""
            )
            + "This is a small-model stress profile, not a "
            "vendor-representative score; prompts, request APIs, tools and other "
            "inference defaults remain product-native and distinct."
            if small_model_stress
            else (
                "OCTOPUS and Strix use the same neutral Ollama provider, model tag, "
                "weights, server and exact context length; prompts, request APIs and "
                "all other inference defaults remain product-native and distinct."
                if shared_model
                else "OCTOPUS and Strix share neutral Ollama/Qwen; PentAGI retains "
                "its separately attested service model."
            )
        ),
        **_FAIRNESS_PROFILE_BASE,
    }


def _secret_environment(
    profile: str,
    environment: Mapping[str, str],
    *,
    campaign_definition: _CampaignDefinition | None = None,
) -> tuple[str, ...]:
    names = list(
        _configured_optional_environment(environment, ("LLM_API_KEY",))
    )
    if profile == "extended":
        names.extend(_EXTENDED_SECRET_ENVIRONMENT)
    if (
        campaign_definition is not None
        and campaign_definition.benchmark_v3_track_id is not None
    ):
        names.append(_V3_BASE_FIXTURE_SEED_ENVIRONMENT)
    return tuple(names)


def _configured_v3_base_seed(environment: Mapping[str, str]) -> int:
    raw = str(environment.get(_V3_BASE_FIXTURE_SEED_ENVIRONMENT) or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32,64}", raw):
        raise LaunchError("campaign_definition_mismatch")
    return int(raw, 16)


def _configured_v3_design_id(
    environment: Mapping[str, str],
    name: str,
    *,
    default: str,
) -> str:
    candidate = str(environment.get(name) or default).strip().lower()
    if not _CAMPAIGN_ID.fullmatch(candidate):
        raise LaunchError("campaign_definition_mismatch")
    return candidate


def _local_v3_host_id() -> str:
    identity = json.dumps(
        {
            "implementation": platform.python_implementation(),
            "machine": platform.machine(),
            "node": platform.node(),
            "release": platform.release(),
            "system": platform.system(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "host-" + hashlib.sha256(identity.encode()).hexdigest()[:20]


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


def _campaign_definition(
    value: Any,
    *,
    profile: str,
) -> _CampaignDefinition:
    candidate = str(value or "").strip().lower()
    definition = _CAMPAIGN_DEFINITIONS.get(candidate)
    if definition is None:
        raise LaunchError("invalid_campaign_definition")
    if profile not in definition.allowed_profiles:
        raise LaunchError("campaign_definition_mismatch")
    return definition


def _validate_campaign_definition_configuration(
    definition: _CampaignDefinition,
    environment: Mapping[str, str],
) -> None:
    if definition.ollama_model is None:
        return
    if (
        str(environment.get("OCTOPUS_OLLAMA_MODEL") or "").strip()
        != definition.ollama_model
        or _configured_ollama_context_length(environment)
        != definition.ollama_context_length
        or _configured_ollama_server_version(environment)
        != definition.ollama_server_version
        or str(environment.get("OCTOBENCH_OLLAMA_FLASH_ATTENTION") or "").strip()
        != "1"
        or str(environment.get("OCTOBENCH_OLLAMA_KV_CACHE_TYPE") or "").strip()
        != "q8_0"
    ):
        raise LaunchError("campaign_definition_mismatch")
    if definition.benchmark_v3_track_id is not None:
        _configured_v3_base_seed(environment)


def _validate_campaign_definition_runtime(
    definition: _CampaignDefinition,
    attestations: Mapping[str, Mapping[str, Any]],
) -> None:
    if definition.ollama_digest is None:
        return
    for system_id in ("octopus", "strix"):
        provenance = attestations.get(system_id)
        if (
            not isinstance(provenance, Mapping)
            or str(provenance.get("ollama_model_digest") or "").strip().lower()
            != definition.ollama_digest
        ):
            raise LaunchError("campaign_definition_mismatch")


def _validate_shared_ollama_configuration(
    environment: Mapping[str, str],
) -> None:
    _configured_ollama_context_length(environment)
    _configured_ollama_server_version(environment)
    _validate_declared_ollama_server_policy(environment)
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


def _configured_ollama_context_length(environment: Mapping[str, str]) -> int:
    raw = str(environment.get("OCTOBENCH_OLLAMA_CONTEXT_LENGTH") or "").strip()
    if not raw.isascii() or not raw.isdecimal():
        raise LaunchError("invalid_shared_ollama_configuration")
    value = int(raw)
    if not _MIN_OLLAMA_CONTEXT_LENGTH <= value <= _MAX_OLLAMA_CONTEXT_LENGTH:
        raise LaunchError("invalid_shared_ollama_configuration")
    return value


def _configured_ollama_server_version(environment: Mapping[str, str]) -> str:
    value = str(environment.get("OCTOBENCH_OLLAMA_SERVER_VERSION") or "").strip()
    if re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", value) is None:
        raise LaunchError("invalid_shared_ollama_configuration")
    return value


def _validate_declared_ollama_server_policy(
    environment: Mapping[str, str],
) -> None:
    if any(
        str(environment.get(name) or "").strip() != "1"
        for name in (
            "OCTOBENCH_OLLAMA_NUM_PARALLEL",
            "OCTOBENCH_OLLAMA_MAX_LOADED_MODELS",
        )
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
    shared_ollama = _attest_shared_ollama_runtime(environment)
    for system_id in ("octopus", "strix"):
        attestations[system_id].update(shared_ollama)
    return attestations


def _attest_shared_ollama_runtime(
    environment: Mapping[str, str],
) -> dict[str, Any]:
    """Bind both systems to one live Ollama model and allocated context."""

    base_url = str(environment.get("LLM_API_BASE") or "").strip().rstrip("/")
    model = str(environment.get("OCTOPUS_OLLAMA_MODEL") or "").strip()
    expected_context = _configured_ollama_context_length(environment)
    expected_version = _configured_ollama_server_version(environment)
    if not base_url or not model:
        raise LaunchError("runtime_unavailable")
    headers = {
        "Accept": "application/json",
        "User-Agent": "Octopus-Benchmark/1.0",
    }
    api_key = str(environment.get("LLM_API_KEY") or "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        tags = _ollama_json_request(
            opener,
            f"{base_url}/api/tags",
            headers=headers,
            timeout=_OLLAMA_ATTESTATION_TIMEOUT_SECONDS,
        )
        version_payload = _ollama_json_request(
            opener,
            f"{base_url}/api/version",
            headers=headers,
            timeout=_OLLAMA_ATTESTATION_TIMEOUT_SECONDS,
        )
    except (
        OSError,
        TimeoutError,
        ValueError,
        http.client.HTTPException,
        urllib.error.HTTPError,
        urllib.error.URLError,
    ):
        raise LaunchError("runtime_unavailable") from None
    if not isinstance(tags.get("models"), list):
        raise LaunchError("runtime_unavailable")
    matches = [
        entry
        for entry in tags["models"]
        if isinstance(entry, Mapping)
        and (entry.get("name") == model or entry.get("model") == model)
    ]
    if len(matches) != 1:
        raise LaunchError("runtime_unavailable")
    reported_digest = str(matches[0].get("digest") or "").strip().lower()
    raw_digest = (
        reported_digest[len("sha256:") :]
        if reported_digest.startswith("sha256:")
        else reported_digest
    )
    size = matches[0].get("size")
    if (
        re.fullmatch(r"[0-9a-f]{64}", raw_digest) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
    ):
        raise LaunchError("runtime_unavailable")
    reported_version = str(version_payload.get("version") or "").strip()
    if reported_version != expected_version:
        raise LaunchError("ollama_version_mismatch")

    try:
        _ollama_json_request(
            opener,
            f"{base_url}/api/generate",
            headers=headers,
            method="POST",
            body={"model": model, "keep_alive": 0},
            timeout=_OLLAMA_PRELOAD_TIMEOUT_SECONDS,
        )
        _ollama_json_request(
            opener,
            f"{base_url}/api/generate",
            headers=headers,
            method="POST",
            body={
                "model": model,
                "prompt": "",
                "stream": False,
                "keep_alive": "5m",
            },
            timeout=_OLLAMA_PRELOAD_TIMEOUT_SECONDS,
        )
        processes = _ollama_json_request(
            opener,
            f"{base_url}/api/ps",
            headers=headers,
            timeout=_OLLAMA_ATTESTATION_TIMEOUT_SECONDS,
        )
    except (
        OSError,
        TimeoutError,
        ValueError,
        http.client.HTTPException,
        urllib.error.HTTPError,
        urllib.error.URLError,
    ):
        raise LaunchError("runtime_unavailable") from None
    if not isinstance(processes.get("models"), list) or len(processes["models"]) != 1:
        raise LaunchError("runtime_unavailable")
    process_matches = [
        entry
        for entry in processes["models"]
        if isinstance(entry, Mapping)
        and (entry.get("name") == model or entry.get("model") == model)
    ]
    if len(process_matches) != 1:
        raise LaunchError("runtime_unavailable")
    process = process_matches[0]
    process_digest = str(process.get("digest") or "").strip().lower()
    process_raw_digest = (
        process_digest[len("sha256:") :]
        if process_digest.startswith("sha256:")
        else process_digest
    )
    context_length = process.get("context_length")
    size_vram = process.get("size_vram")
    if (
        process_raw_digest != raw_digest
        or isinstance(context_length, bool)
        or not isinstance(context_length, int)
        or context_length <= 0
        or isinstance(size_vram, bool)
        or not isinstance(size_vram, int)
        or size_vram < 0
    ):
        raise LaunchError("runtime_unavailable")
    if context_length != expected_context:
        raise LaunchError("ollama_context_mismatch")
    declared_flash_attention = str(
        environment.get("OCTOBENCH_OLLAMA_FLASH_ATTENTION") or ""
    ).strip()
    declared_kv_cache_type = str(
        environment.get("OCTOBENCH_OLLAMA_KV_CACHE_TYPE") or ""
    ).strip()
    return {
        "ollama_model_attestation": "api-tags",
        "ollama_model_digest": f"sha256:{raw_digest}",
        "ollama_model_size_bytes": size,
        "ollama_runtime_attestation": "api-version-unload-empty-preload-and-ps",
        "ollama_server_version": reported_version,
        "ollama_context_length": context_length,
        "ollama_model_size_vram_bytes": size_vram,
        "ollama_num_parallel_declared": 1,
        "ollama_max_loaded_models_declared": 1,
        "ollama_server_policy_attestation": "operator-declared-api-not-exposed",
        **(
            {"ollama_flash_attention_declared": declared_flash_attention == "1"}
            if declared_flash_attention
            else {}
        ),
        **(
            {"ollama_kv_cache_type_declared": declared_kv_cache_type}
            if declared_kv_cache_type
            else {}
        ),
    }


def _ollama_json_request(
    opener: Any,
    url: str,
    *,
    headers: Mapping[str, str],
    timeout: float,
    method: str = "GET",
    body: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    request_headers = dict(headers)
    encoded: bytes | None = None
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded,
        method=method,
        headers=request_headers,
    )
    with opener.open(request, timeout=timeout) as response:
        status = int(getattr(response, "status", 0) or response.getcode() or 0)
        payload = response.read(_MAX_OLLAMA_RESPONSE_BYTES + 1)
    if status != 200 or len(payload) > _MAX_OLLAMA_RESPONSE_BYTES:
        raise LaunchError("runtime_unavailable")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise LaunchError("runtime_unavailable") from None
    if not isinstance(decoded, Mapping) or decoded.get("error"):
        raise LaunchError("runtime_unavailable")
    return decoded


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


def _scenario_directory(definition: _CampaignDefinition) -> Path:
    campaign_root = ROOT / "benchmarks" / "competitors" / "campaigns"
    definition_directory = campaign_root / definition.definition_id
    scenario_directory = definition_directory / "scenarios"
    try:
        resolved_repository_root = ROOT.resolve(strict=True)
        campaign_root_metadata = campaign_root.lstat()
        resolved_root = campaign_root.resolve(strict=True)
        definition_metadata = definition_directory.lstat()
        scenario_metadata = scenario_directory.lstat()
        resolved_scenarios = scenario_directory.resolve(strict=True)
        resolved_scenarios.relative_to(resolved_root)
    except (OSError, ValueError):
        raise LaunchError("campaign_definition_unavailable") from None
    if (
        stat.S_ISLNK(campaign_root_metadata.st_mode)
        or not stat.S_ISDIR(campaign_root_metadata.st_mode)
        or resolved_root
        != resolved_repository_root / "benchmarks" / "competitors" / "campaigns"
        or stat.S_ISLNK(definition_metadata.st_mode)
        or not stat.S_ISDIR(definition_metadata.st_mode)
        or stat.S_ISLNK(scenario_metadata.st_mode)
        or not stat.S_ISDIR(scenario_metadata.st_mode)
        or resolved_scenarios != resolved_root / definition.definition_id / "scenarios"
    ):
        raise LaunchError("campaign_definition_unavailable")
    return resolved_scenarios


def _output_directory(campaign_id: str) -> Path:
    return ROOT / "benchmarks" / "competitors" / "results" / campaign_id


def _diagnostic_root() -> Path:
    return ROOT / ".benchmark-state" / "diagnostics"


def _journal_campaign_directory(campaign_id: str) -> Path:
    return ROOT / ".benchmark-state" / "journal" / campaign_id


def _print_error(code: str) -> None:
    print(
        json.dumps({"error": code}, sort_keys=True, separators=(",", ":")),
        file=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
