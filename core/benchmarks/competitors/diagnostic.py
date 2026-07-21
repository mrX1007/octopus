"""Non-publishable one-run calibration for live competitor adapters.

The publication campaign deliberately requires repeated runs.  This module is
the cheaper prerequisite: it executes each selected adapter exactly once with
owner-only raw diagnostics, so runtime/model failures can be fixed before a
multi-hour campaign is attempted.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ..schema import BenchmarkScenario, load_scenarios
from .campaign import CampaignConfig, load_campaign_config
from .lab import CommandLabController, LabRunContext
from .runner import CommandSystemRunner, SystemRunnerError
from .schema import CommandAdapterConfig, SystemManifest, load_system_manifest

DIAGNOSTIC_SCHEMA_VERSION = "1.0"
DEFAULT_PILOT_SECONDS = 1_800.0
MIN_PILOT_SECONDS = 60.0
MAX_PILOT_SECONDS = 3_600.0
_PRODUCT_LOG_ENVIRONMENT = "OCTOBENCH_DIAGNOSTIC_PRODUCT_LOG"
_ERROR_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_SAFE_RUNTIME_PROVENANCE_KEYS = frozenset(
    {
        "attestation",
        "ca_file_sha256",
        "checkout_revision",
        "custom_ca_configured",
        "distribution_name",
        "distribution_version",
        "executable_layout",
        "executable_sha256",
        "lock_layout",
        "lock_sha256",
        "ollama_model_attestation",
        "ollama_model_digest",
        "ollama_model_size_bytes",
        "ollama_model_size_vram_bytes",
        "ollama_context_length",
        "ollama_flash_attention_declared",
        "ollama_kv_cache_type_declared",
        "ollama_max_loaded_models_declared",
        "ollama_num_parallel_declared",
        "ollama_runtime_attestation",
        "ollama_server_policy_attestation",
        "ollama_server_version",
        "sandbox_image",
        "sandbox_image_id",
        "sandbox_platform",
        "service_release",
        "source_layout",
        "source_revision_attested",
        "source_tree_sha256",
    }
)


class DiagnosticError(RuntimeError):
    """Stable failure raised before a useful private summary can be written."""


@dataclass(frozen=True)
class DiagnosticOutcome:
    summary_path: Path
    status: str
    exit_code: int


def run_diagnostic_pilot(
    config: CampaignConfig | str | Path,
    *,
    environment: Mapping[str, str],
    root: str | Path,
    budget_seconds: float = DEFAULT_PILOT_SECONDS,
    selected_system: str | None = None,
) -> DiagnosticOutcome:
    """Run one private calibration repetition per selected system/scenario."""

    resolved = load_campaign_config(config) if isinstance(config, (str, Path)) else config
    budget = _pilot_seconds(budget_seconds)
    manifests = tuple(
        load_system_manifest(path) for path in resolved.system_manifest_paths
    )
    if selected_system is not None:
        manifests = tuple(
            item for item in manifests if item.system_id == selected_system
        )
        if not manifests:
            raise DiagnosticError("diagnostic_system_unavailable")
    scenarios = tuple(
        _with_budget(item, budget) for item in load_scenarios(resolved.scenario_directory)
    )
    if not manifests or not scenarios:
        raise DiagnosticError("diagnostic_inputs_unavailable")

    worker = _diagnostic_worker_path()
    diagnostic_root = Path(root).resolve()
    _create_private_directory(diagnostic_root)
    destination = diagnostic_root / resolved.campaign_id
    _create_new_private_directory(destination)
    raw_root = destination / "raw"
    _create_private_directory(raw_root)
    summary_path = destination / "summary.json"

    effective_environment = {str(key): str(value) for key, value in environment.items()}
    controller = CommandLabController(
        resolved.reset_command,
        resolved.health_command,
        cleanup=resolved.cleanup_command,
        environment=effective_environment,
    )
    runs: list[dict[str, Any]] = []
    cleanup_failed = False
    operator_interrupted = False

    with _temporary_environment(effective_environment):
        for manifest in manifests:
            for scenario in scenarios:
                context = _lab_context(resolved.campaign_id, manifest, scenario)
                run_directory = raw_root / manifest.system_id / scenario.scenario_id
                _create_private_directory(run_directory.parent)
                _create_private_directory(run_directory)
                adapter_log = run_directory / "adapter.log"
                product_log = run_directory / "product.log"
                diagnostic_manifest = _diagnostic_manifest(
                    manifest,
                    worker=worker,
                )
                run_environment = {
                    **effective_environment,
                    _PRODUCT_LOG_ENVIRONMENT: str(product_log),
                }
                lifecycle_started = time.monotonic()
                adapter_started: float | None = None
                adapter_wall_duration = 0.0
                status = "failed"
                error_class = "DiagnosticExecutionFailure"
                duration = 0.0
                reset_healthy = False
                run_cleanup_status = "not_attempted"
                try:
                    controller.reset_and_health(context)
                    reset_healthy = True
                    with _temporary_environment(run_environment):
                        adapter_started = time.monotonic()
                        result = CommandSystemRunner(
                            diagnostic_manifest,
                            private_log_path=adapter_log,
                        )(scenario, 1, scenario.seed)
                        adapter_wall_duration = max(
                            0.0,
                            time.monotonic() - adapter_started,
                        )
                    status = str(result.get("status") or "failed")
                    error_class = _safe_error_class(result.get("error_class"))
                    duration = _nonnegative_number(
                        result.get("duration_seconds"),
                        default=adapter_wall_duration,
                    )
                except SystemRunnerError as exc:
                    error_class = type(exc).__name__
                    if adapter_started is not None:
                        adapter_wall_duration = max(
                            0.0,
                            time.monotonic() - adapter_started,
                        )
                    duration = adapter_wall_duration
                except KeyboardInterrupt:
                    operator_interrupted = True
                    status = "interrupted"
                    error_class = "OperatorInterrupt"
                    if adapter_started is not None:
                        adapter_wall_duration = max(
                            0.0,
                            time.monotonic() - adapter_started,
                        )
                    duration = adapter_wall_duration
                except Exception as exc:
                    error_class = _safe_error_class(type(exc).__name__)
                    if adapter_started is not None:
                        adapter_wall_duration = max(
                            0.0,
                            time.monotonic() - adapter_started,
                        )
                    duration = adapter_wall_duration
                finally:
                    try:
                        controller.cleanup(context)
                        run_cleanup_status = "succeeded"
                    except Exception:
                        cleanup_failed = True
                        run_cleanup_status = "failed"
                    if reset_healthy and not _private_log_exists(adapter_log):
                        _write_private_bytes(adapter_log, b"")

                runs.append(
                    {
                        "system_id": manifest.system_id,
                        "scenario_id": scenario.scenario_id,
                        "repetition": 1,
                        "seed": scenario.seed,
                        "status": status,
                        "error_class": error_class,
                        "product_duration_seconds": round(duration, 6),
                        "adapter_wall_seconds": round(adapter_wall_duration, 6),
                        "lifecycle_wall_seconds": round(
                            max(0.0, time.monotonic() - lifecycle_started),
                            6,
                        ),
                        "reset_healthy": reset_healthy,
                        "cleanup_status": run_cleanup_status,
                        "adapter_log_sha256": _optional_file_digest(adapter_log),
                        "adapter_log_bytes": _optional_file_size(adapter_log),
                        "product_log_sha256": _optional_file_digest(product_log),
                        "product_log_bytes": _optional_file_size(product_log),
                        "system": _system_provenance(manifest),
                        "manifest_sha256": _optional_file_digest(
                            manifest.source_path
                        ),
                        "lab_version": context.lab_version,
                        "snapshot_ref": context.snapshot_ref,
                    }
                )
                if operator_interrupted:
                    break
            if operator_interrupted:
                break

    status = (
        "interrupted"
        if operator_interrupted
        else "succeeded"
        if (
            runs
            and not cleanup_failed
            and all(item["status"] == "succeeded" for item in runs)
        )
        else "completed_with_failures"
    )
    payload = {
        "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        "campaign_id": resolved.campaign_id,
        "purpose": "runtime_calibration",
        "publishable": False,
        "scenario_scope": _scenario_scope(scenarios),
        "budget_seconds": budget,
        "status": status,
        "cleanup_status": "failed" if cleanup_failed else "succeeded",
        "campaign_config_sha256": _optional_file_digest(resolved.source_path),
        "runs": runs,
    }
    _write_private_json(summary_path, payload)
    exit_code = 0 if status == "succeeded" else 130 if status == "interrupted" else 1
    return DiagnosticOutcome(
        summary_path=summary_path,
        status=status,
        exit_code=exit_code,
    )


def _diagnostic_manifest(
    manifest: SystemManifest,
    *,
    worker: Path,
) -> SystemManifest:
    adapter = CommandAdapterConfig(
        argv=(
            manifest.adapter.argv[0],
            str(worker),
            "--system",
            manifest.system_id,
            "--scenario",
            "{scenario_path}",
            "--output",
            "{output_path}",
        ),
        cwd=manifest.adapter.cwd,
        env_passthrough=tuple(
            dict.fromkeys(
                (*manifest.adapter.env_passthrough, _PRODUCT_LOG_ENVIRONMENT)
            )
        ),
    )
    return replace(manifest, adapter=adapter)


def _diagnostic_worker_path() -> Path:
    root = Path(__file__).resolve().parents[3]
    worker = root / "benchmarks" / "competitors" / "run_diagnostic_adapter.py"
    if not worker.is_file():
        raise DiagnosticError("diagnostic_worker_unavailable")
    return worker


def _with_budget(
    scenario: BenchmarkScenario,
    budget_seconds: float,
) -> BenchmarkScenario:
    return replace(
        scenario,
        budgets={**scenario.budgets, "max_seconds": budget_seconds},
    )


def _lab_context(
    campaign_id: str,
    manifest: SystemManifest,
    scenario: BenchmarkScenario,
) -> LabRunContext:
    return LabRunContext(
        campaign_id=campaign_id,
        system_id=manifest.system_id,
        scenario_id=scenario.scenario_id,
        repetition=1,
        seed=scenario.seed,
        lab_version=str(scenario.lab.get("version") or "unknown"),
        snapshot_ref=str(scenario.lab.get("snapshot_ref") or "unknown"),
    )


def _pilot_seconds(value: Any) -> float:
    if isinstance(value, bool):
        raise DiagnosticError("diagnostic_budget_invalid")
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise DiagnosticError("diagnostic_budget_invalid") from None
    if (
        not math.isfinite(parsed)
        or parsed < MIN_PILOT_SECONDS
        or parsed > MAX_PILOT_SECONDS
    ):
        raise DiagnosticError("diagnostic_budget_invalid")
    return parsed


def _safe_error_class(value: Any) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    return candidate if _ERROR_CLASS.fullmatch(candidate) else "DiagnosticErrorClass"


def _nonnegative_number(value: Any, *, default: float) -> float:
    if isinstance(value, bool):
        return max(0.0, float(default))
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return max(0.0, float(default))
    return parsed if math.isfinite(parsed) and parsed >= 0 else max(0.0, float(default))


def _create_private_directory(path: Path) -> None:
    parent = path.parent
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise DiagnosticError("diagnostic_directory_unsafe")
        return
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def _create_new_private_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise DiagnosticError("diagnostic_destination_exists")
    try:
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
    except FileExistsError:
        raise DiagnosticError("diagnostic_destination_exists") from None
    except OSError:
        raise DiagnosticError("diagnostic_directory_unsafe") from None


def _write_private_json(path: Path, payload: Mapping[str, Any]) -> None:
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode("utf-8")
    _write_private_bytes(path, encoded)


def _write_private_bytes(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise DiagnosticError("diagnostic_file_unsafe")
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise DiagnosticError("diagnostic_file_unavailable")
            written += count
    except OSError:
        raise DiagnosticError("diagnostic_file_unavailable") from None
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _private_log_exists(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600


def _optional_file_digest(path: Path | None) -> str | None:
    if path is None:
        return None
    if not _private_log_exists(path):
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        return None
    return "sha256:" + digest.hexdigest()


def _optional_file_size(path: Path | None) -> int | None:
    if path is None or not _private_log_exists(path):
        return None
    try:
        return path.stat().st_size
    except OSError:
        return None


def _system_provenance(manifest: SystemManifest) -> dict[str, Any]:
    model = manifest.model
    runtime = manifest.metadata.get("runtime_provenance")
    safe_runtime: dict[str, Any] = {}
    if isinstance(runtime, Mapping):
        for key in sorted(_SAFE_RUNTIME_PROVENANCE_KEYS):
            value = runtime.get(key)
            if isinstance(value, (bool, int)) or (
                isinstance(value, str)
                and len(value.encode("utf-8")) <= 4_096
            ):
                safe_runtime[key] = value
    return {
        "system_id": manifest.system_id,
        "version": manifest.version,
        "source_revision": manifest.source_revision,
        "track": manifest.track,
        "model_provider": str(model.get("provider") or ""),
        "model_name": str(model.get("name") or ""),
        "runtime_provenance": safe_runtime,
    }


def _scenario_scope(scenarios: tuple[BenchmarkScenario, ...]) -> str:
    if scenarios and all(
        item.category == "service_discovery_verification"
        and "read-only" in item.tags
        for item in scenarios
    ):
        return "smoke_only"
    return "calibration_only"


@contextmanager
def _temporary_environment(values: Mapping[str, str]) -> Iterator[None]:
    previous = dict(os.environ)
    os.environ.clear()
    os.environ.update({str(key): str(value) for key, value in values.items()})
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


__all__ = [
    "DEFAULT_PILOT_SECONDS",
    "DiagnosticError",
    "DiagnosticOutcome",
    "run_diagnostic_pilot",
]
