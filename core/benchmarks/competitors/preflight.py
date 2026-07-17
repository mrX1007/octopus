"""Non-mutating, fail-closed checks for competitor benchmark campaigns."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schema import BenchmarkScenario
from .lab import LabCommand, command_executable_available
from .schema import SystemManifest

PREFLIGHT_SCHEMA_VERSION = "1.0"
_PLACEHOLDER_MARKERS = (
    "replace-with-",
    "change-me",
    "changeme",
    "your-key-here",
    "authorized-target.invalid",
)


class CampaignPreflightError(RuntimeError):
    """Raised when a campaign must not launch any adapter."""

    def __init__(self, report: PreflightReport) -> None:
        self.report = report
        super().__init__("campaign_preflight_failed")


@dataclass(frozen=True)
class PreflightCheck:
    check_id: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": "passed" if self.passed else "failed",
            "detail": self.detail,
        }


@dataclass(frozen=True)
class PreflightReport:
    campaign_id: str
    checks: tuple[PreflightCheck, ...]
    schema_version: str = PREFLIGHT_SCHEMA_VERSION

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.checks)

    def raise_for_failure(self) -> None:
        if not self.passed:
            raise CampaignPreflightError(self)

    def to_dict(self) -> dict[str, Any]:
        failed = sum(1 for item in self.checks if not item.passed)
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "status": "passed" if self.passed else "failed",
            "check_count": len(self.checks),
            "failed_check_count": failed,
            "checks": [item.to_dict() for item in self.checks],
        }


def run_campaign_preflight(
    *,
    campaign_id: str,
    output_directory: str | Path,
    manifests: Sequence[SystemManifest],
    scenarios: Sequence[BenchmarkScenario],
    required_environment: Sequence[str],
    environment: Mapping[str, str],
    reset_command: LabCommand,
    health_command: LabCommand,
    placeholder_inputs: Sequence[tuple[str, Any]] = (),
    environment_file: str | Path | None = None,
) -> PreflightReport:
    """Inspect all launch prerequisites without executing reset or adapters."""

    checks: list[PreflightCheck] = []
    destination = Path(output_directory)
    destination_present = destination.exists() or destination.is_symlink()
    checks.append(
        PreflightCheck(
            "output_destination_new",
            not destination_present,
            "new_destination" if not destination_present else "destination_exists",
        )
    )
    checks.append(
        PreflightCheck(
            "minimum_systems",
            len(manifests) >= 2,
            f"system_count:{len(manifests)}",
        )
    )
    checks.append(
        PreflightCheck(
            "scenario_catalog",
            bool(scenarios),
            f"scenario_count:{len(scenarios)}",
        )
    )
    matrix_compatible = _matrix_inputs_compatible(manifests)
    checks.append(
        PreflightCheck(
            "matrix_compatibility",
            matrix_compatible,
            "compatible" if matrix_compatible else "mixed_fairness_or_execution_contract",
        )
    )

    missing_environment = sorted(
        {
            str(name)
            for name in required_environment
            if not str(environment.get(str(name), ""))
        }
    )
    checks.append(
        PreflightCheck(
            "required_environment",
            not missing_environment,
            (
                "all_required_environment_present"
                if not missing_environment
                else "missing:" + ",".join(missing_environment)
            ),
        )
    )
    if "OCTOBENCH_ACK_AUTHORIZED" in required_environment:
        authorization_acknowledged = (
            str(environment.get("OCTOBENCH_ACK_AUTHORIZED") or "") == "YES"
        )
        checks.append(
            PreflightCheck(
                "authorized_lab_acknowledgement",
                authorization_acknowledged,
                (
                    "authorization_acknowledged"
                    if authorization_acknowledged
                    else "authorization_ack_required"
                ),
            )
        )
    for name in sorted(set(required_environment)):
        if not name.endswith("_BIN"):
            continue
        available = _environment_executable_available(
            str(environment.get(name) or ""),
            environment,
        )
        checks.append(
            PreflightCheck(
                f"environment_executable:{name}",
                available,
                "executable_available" if available else "executable_missing",
            )
        )
    if environment_file is not None:
        path = Path(environment_file)
        secure = path.is_file() and (path.stat().st_mode & 0o077) == 0
        checks.append(
            PreflightCheck(
                "environment_file_permissions",
                secure,
                "private_mode" if secure else "environment_file_not_private",
            )
        )

    for manifest in manifests:
        cwd, executable_available = _manifest_adapter_available(manifest, environment)
        checks.append(
            PreflightCheck(
                f"adapter_cwd:{manifest.system_id}",
                cwd.is_dir(),
                "working_directory_available" if cwd.is_dir() else "working_directory_missing",
            )
        )
        checks.append(
            PreflightCheck(
                f"adapter_executable:{manifest.system_id}",
                executable_available,
                "executable_available" if executable_available else "executable_missing",
            )
        )

    for name, command in (("reset", reset_command), ("health", health_command)):
        available = command_executable_available(command, environment)
        checks.append(
            PreflightCheck(
                f"lab_{name}_command",
                available,
                "command_available" if available else "command_unavailable",
            )
        )

    values_to_scan: list[tuple[str, Any]] = list(placeholder_inputs)
    values_to_scan.extend(
        (f"system:{item.system_id}", item.to_dict()) for item in manifests
    )
    values_to_scan.extend(
        (f"scenario:{item.scenario_id}", item.to_dict()) for item in scenarios
    )
    placeholder_locations = sorted(
        name for name, value in values_to_scan if _contains_placeholder(value)
    )
    placeholder_locations.extend(
        f"environment:{name}"
        for name in sorted(set(required_environment))
        if _contains_placeholder(str(environment.get(name) or ""))
    )
    checks.append(
        PreflightCheck(
            "completed_placeholders",
            not placeholder_locations,
            (
                "no_placeholders"
                if not placeholder_locations
                else "placeholder_inputs:" + ",".join(placeholder_locations)
            ),
        )
    )
    return PreflightReport(campaign_id=campaign_id, checks=tuple(checks))


def _manifest_adapter_available(
    manifest: SystemManifest,
    environment: Mapping[str, str],
) -> tuple[Path, bool]:
    base = (
        manifest.source_path.parent
        if manifest.source_path is not None
        else Path.cwd()
    ).resolve()
    cwd = (base / manifest.adapter.cwd).resolve()
    try:
        cwd.relative_to(base)
    except ValueError:
        return cwd, False
    if not cwd.is_dir():
        return cwd, False
    executable = manifest.adapter.argv[0]
    if "{" in executable or "}" in executable:
        return cwd, False
    candidate = Path(executable)
    if candidate.is_absolute():
        return cwd, candidate.is_file() and os.access(candidate, os.X_OK)
    if "/" in executable:
        resolved = (cwd / candidate).resolve()
        return cwd, resolved.is_file() and os.access(resolved, os.X_OK)
    path = (
        environment.get("PATH", os.defpath)
        if "PATH" in manifest.adapter.env_passthrough
        else os.defpath
    )
    return cwd, shutil.which(executable, path=path) is not None


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        lowered = value.strip().lower()
        return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)
    if isinstance(value, Mapping):
        return any(
            _contains_placeholder(key) or _contains_placeholder(item)
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_contains_placeholder(item) for item in value)
    return False


def _environment_executable_available(
    executable: str,
    environment: Mapping[str, str],
) -> bool:
    if not executable or "\x00" in executable:
        return False
    candidate = Path(executable).expanduser()
    if candidate.is_absolute() or "/" in executable:
        resolved = candidate.resolve()
        return resolved.is_file() and os.access(resolved, os.X_OK)
    return shutil.which(executable, path=environment.get("PATH", os.defpath)) is not None


def _matrix_inputs_compatible(manifests: Sequence[SystemManifest]) -> bool:
    if len(manifests) < 2:
        return False
    tracks = {item.track for item in manifests}
    modes = {item.execution_mode for item in manifests}
    fairness = {
        json.dumps(
            item.fairness_profile.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        for item in manifests
    }
    if len(tracks) != 1 or len(modes) != 1 or len(fairness) != 1:
        return False
    if next(iter(tracks)) == "framework_only":
        models = {
            json.dumps(item.model, sort_keys=True, separators=(",", ":"))
            for item in manifests
        }
        tools = {
            json.dumps(item.tool_versions, sort_keys=True, separators=(",", ":"))
            for item in manifests
        }
        return len(models) == 1 and len(tools) == 1
    return True


__all__ = [
    "PREFLIGHT_SCHEMA_VERSION",
    "CampaignPreflightError",
    "PreflightCheck",
    "PreflightReport",
    "run_campaign_preflight",
]
