"""Versioned, portable manifests for benchmark systems under test.

The public contract deliberately describes *how* to invoke an adapter without
capturing the caller's environment.  ``source_path`` is retained only as local
runtime state so relative working directories can be resolved safely.
"""

from __future__ import annotations

import json
import math
import re
import string
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

SYSTEM_MANIFEST_SCHEMA_VERSION = "1.0"
SYSTEM_TRACKS = ("framework_only", "full_system")
SYSTEM_EXECUTION_MODES = ("live", "replay")
ALLOWED_COMMAND_PLACEHOLDERS = frozenset(
    {
        "scenario_path",
        "output_path",
        "repetition",
        "seed",
        "system_id",
    }
)
REQUIRED_COMMAND_PLACEHOLDERS = frozenset({"scenario_path", "output_path"})

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_MAX_TEXT_BYTES = 4_096
_MAX_ARGUMENTS = 64
_MAX_ENVIRONMENT_NAMES = 128
_MAX_MAPPING_ITEMS = 256
_MAX_JSON_DEPTH = 8
_MAX_PUBLIC_MANIFEST_BYTES = 256_000


class CompetitorSchemaError(ValueError):
    """Raised when a system manifest violates the public 1.0 contract."""


@dataclass(frozen=True)
class CommandAdapterConfig:
    """A shell-free command adapter with an explicit environment allowlist."""

    argv: tuple[str, ...]
    cwd: str = "."
    env_passthrough: tuple[str, ...] = ()
    kind: str = "command"

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CommandAdapterConfig:
        kind = str(payload.get("kind") or "command").strip().lower()
        if kind != "command":
            raise CompetitorSchemaError("unsupported_adapter_kind")

        raw_argv = payload.get("argv")
        if not _is_sequence(raw_argv):
            raise CompetitorSchemaError("invalid:adapter.argv")
        if not raw_argv or len(raw_argv) > _MAX_ARGUMENTS:
            raise CompetitorSchemaError("invalid_length:adapter.argv")
        argv = tuple(
            _command_argument(value, f"adapter.argv[{index}]")
            for index, value in enumerate(raw_argv)
        )
        placeholders = set().union(*(_placeholders(item) for item in argv))
        missing = sorted(REQUIRED_COMMAND_PLACEHOLDERS - placeholders)
        if missing:
            raise CompetitorSchemaError(
                "missing_adapter_placeholders:" + ",".join(missing)
            )

        if (
            "working_directory" in payload
            and "cwd" in payload
            and payload["working_directory"] != payload["cwd"]
        ):
            raise CompetitorSchemaError("conflicting:adapter.working_directory")
        cwd = _working_directory(
            payload.get("working_directory", payload.get("cwd", "."))
        )
        if (
            "environment_passthrough" in payload
            and "env_passthrough" in payload
            and payload["environment_passthrough"] != payload["env_passthrough"]
        ):
            raise CompetitorSchemaError("conflicting:adapter.environment_passthrough")
        raw_environment = payload.get(
            "environment_passthrough",
            payload.get("env_passthrough"),
        ) or []
        if not _is_sequence(raw_environment):
            raise CompetitorSchemaError("invalid:adapter.env_passthrough")
        if len(raw_environment) > _MAX_ENVIRONMENT_NAMES:
            raise CompetitorSchemaError("too_many_items:adapter.env_passthrough")
        environment: list[str] = []
        for value in raw_environment:
            name = str(value or "").strip()
            if not _ENVIRONMENT_NAME.fullmatch(name):
                raise CompetitorSchemaError(
                    "invalid_environment_name:adapter.env_passthrough"
                )
            if name.startswith("OCTOPUS_BENCHMARK_"):
                raise CompetitorSchemaError("reserved_environment_name")
            if name not in environment:
                environment.append(name)

        return cls(argv=argv, cwd=cwd, env_passthrough=tuple(environment))

    def to_dict(self) -> dict[str, Any]:
        """Return public configuration; environment values are never included."""

        return {
            "kind": self.kind,
            "argv": list(self.argv),
            "working_directory": self.cwd,
            "environment_passthrough": list(self.env_passthrough),
        }


@dataclass(frozen=True)
class FairnessProfile:
    """Explicit declarations that keep benchmark tracks interpretable."""

    profile_id: str
    same_model: bool
    same_tool_versions: bool
    same_hardware: bool
    same_budgets: bool
    notes: str = ""

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FairnessProfile:
        required_flags = (
            "same_model",
            "same_tool_versions",
            "same_hardware",
            "same_budgets",
        )
        flags: dict[str, bool] = {}
        for name in required_flags:
            value = payload.get(name)
            if not isinstance(value, bool):
                raise CompetitorSchemaError(f"invalid:fairness_profile.{name}")
            flags[name] = value
        raw_notes = payload.get("notes")
        notes = "" if raw_notes is None else _optional_text(raw_notes, "fairness_profile.notes")
        return cls(
            profile_id=_identifier(
                payload.get("profile_id"),
                "fairness_profile.profile_id",
            ),
            same_model=flags["same_model"],
            same_tool_versions=flags["same_tool_versions"],
            same_hardware=flags["same_hardware"],
            same_budgets=flags["same_budgets"],
            notes=notes,
        )

    @property
    def declares_framework_parity(self) -> bool:
        return all(
            (
                self.same_model,
                self.same_tool_versions,
                self.same_hardware,
                self.same_budgets,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "profile_id": self.profile_id,
            "same_model": self.same_model,
            "same_tool_versions": self.same_tool_versions,
            "same_hardware": self.same_hardware,
            "same_budgets": self.same_budgets,
        }
        if self.notes:
            payload["notes"] = self.notes
        return payload


@dataclass(frozen=True)
class SystemManifest:
    """Identity, fairness declaration, and adapter for one benchmark system."""

    system_id: str
    name: str
    version: str
    source_revision: str
    track: str
    execution_mode: str
    fairness_profile: FairnessProfile
    model: dict[str, Any]
    tool_versions: dict[str, str]
    adapter: CommandAdapterConfig
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SYSTEM_MANIFEST_SCHEMA_VERSION
    source_path: Path | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        source_path: str | Path | None = None,
    ) -> SystemManifest:
        schema_version = str(payload.get("schema_version") or "")
        if schema_version != SYSTEM_MANIFEST_SCHEMA_VERSION:
            raise CompetitorSchemaError(
                f"unsupported_schema_version:{schema_version or 'missing'}"
            )

        system_id = _identifier(payload.get("system_id"), "system_id")
        name = _text(payload.get("name"), "name")
        version = _text(payload.get("version"), "version")
        source_revision = _text(payload.get("source_revision"), "source_revision")
        track = str(payload.get("track") or "").strip().lower()
        if track not in SYSTEM_TRACKS:
            raise CompetitorSchemaError("invalid:track")
        execution_mode = str(payload.get("execution_mode") or "").strip().lower()
        if execution_mode not in SYSTEM_EXECUTION_MODES:
            raise CompetitorSchemaError("invalid:execution_mode")

        raw_fairness_profile = payload.get("fairness_profile")
        if not isinstance(raw_fairness_profile, Mapping):
            raise CompetitorSchemaError("invalid:fairness_profile")
        fairness_profile = FairnessProfile.from_dict(raw_fairness_profile)
        if track == "framework_only" and not fairness_profile.declares_framework_parity:
            raise CompetitorSchemaError("framework_track_requires_parity")

        model = _mapping(payload.get("model"), "model", reject_secret_keys=True)
        model = {
            "provider": _text(model.get("provider"), "model.provider"),
            "name": _text(model.get("name"), "model.name"),
            "parameters": _mapping(model.get("parameters"), "model.parameters"),
        }

        raw_tools = _mapping(payload.get("tool_versions"), "tool_versions")
        tool_versions = {
            _identifier(key, "tool_versions.name"): _text(
                value,
                "tool_versions.version",
            )
            for key, value in raw_tools.items()
        }
        if not tool_versions:
            raise CompetitorSchemaError("empty:tool_versions")

        raw_adapter = payload.get("adapter")
        if not isinstance(raw_adapter, Mapping):
            raise CompetitorSchemaError("invalid:adapter")
        adapter = CommandAdapterConfig.from_dict(raw_adapter)
        metadata = _mapping(
            payload.get("metadata") or {},
            "metadata",
            reject_secret_keys=True,
        )
        internal_source = Path(source_path).resolve() if source_path is not None else None

        manifest = cls(
            system_id=system_id,
            name=name,
            version=version,
            source_revision=source_revision,
            track=track,
            execution_mode=execution_mode,
            fairness_profile=fairness_profile,
            model=model,
            tool_versions=tool_versions,
            adapter=adapter,
            metadata=metadata,
            source_path=internal_source,
        )
        encoded = json.dumps(
            manifest.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > _MAX_PUBLIC_MANIFEST_BYTES:
            raise CompetitorSchemaError("manifest_too_large")
        return manifest

    def to_dict(self) -> dict[str, Any]:
        """Serialize the public manifest without paths or environment values."""

        return {
            "schema_version": self.schema_version,
            "system_id": self.system_id,
            "name": self.name,
            "version": self.version,
            "source_revision": self.source_revision,
            "track": self.track,
            "execution_mode": self.execution_mode,
            "fairness_profile": self.fairness_profile.to_dict(),
            "model": dict(self.model),
            "tool_versions": dict(self.tool_versions),
            "adapter": self.adapter.to_dict(),
            "metadata": dict(self.metadata),
        }

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize publishable identity/configuration without adapter internals."""

        payload = self.to_dict()
        payload.pop("adapter", None)
        return payload


# Compatibility wording for callers that think in terms of competitors rather
# than the more neutral system-under-test contract.
CompetitorManifest = SystemManifest
CommandAdapter = CommandAdapterConfig


def load_system_manifest(path: str | Path) -> SystemManifest:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CompetitorSchemaError(
            f"manifest_load_failed:{type(exc).__name__}"
        ) from None
    if not isinstance(payload, Mapping):
        raise CompetitorSchemaError("manifest_not_mapping")
    return SystemManifest.from_dict(payload, source_path=source)


def load_system_manifests(directory: str | Path) -> tuple[SystemManifest, ...]:
    root = Path(directory)
    manifests = tuple(
        load_system_manifest(path) for path in sorted(root.glob("*.json"))
    )
    identifiers = [item.system_id for item in manifests]
    if len(identifiers) != len(set(identifiers)):
        raise CompetitorSchemaError("duplicate_system_id")
    return manifests


def _identifier(value: Any, name: str) -> str:
    candidate = str(value or "").strip().lower()
    if not _IDENTIFIER.fullmatch(candidate):
        raise CompetitorSchemaError(f"invalid_identifier:{name}")
    return candidate


def _text(value: Any, name: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        raise CompetitorSchemaError(f"missing:{name}")
    if "\x00" in candidate:
        raise CompetitorSchemaError(f"invalid_text:{name}")
    if len(candidate.encode("utf-8", "replace")) > _MAX_TEXT_BYTES:
        raise CompetitorSchemaError(f"text_too_long:{name}")
    return candidate


def _optional_text(value: Any, name: str) -> str:
    candidate = str(value).strip()
    if "\x00" in candidate:
        raise CompetitorSchemaError(f"invalid_text:{name}")
    if len(candidate.encode("utf-8", "replace")) > _MAX_TEXT_BYTES:
        raise CompetitorSchemaError(f"text_too_long:{name}")
    return candidate


def _mapping(
    value: Any,
    name: str,
    *,
    reject_secret_keys: bool = False,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CompetitorSchemaError(f"invalid:{name}")
    if len(value) > _MAX_MAPPING_ITEMS:
        raise CompetitorSchemaError(f"too_many_items:{name}")
    result = {
        _text(key, f"{name}.key"): _bounded_json(item, depth=1)
        for key, item in value.items()
    }
    if reject_secret_keys:
        _reject_secret_bearing_keys(result)
    return result


def _bounded_json(value: Any, *, depth: int) -> Any:
    if depth > _MAX_JSON_DEPTH:
        raise CompetitorSchemaError("json_depth_exceeded")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str):
            return _text(value, "json.value")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CompetitorSchemaError("nonfinite_json_number")
        return value
    if isinstance(value, Mapping):
        if len(value) > _MAX_MAPPING_ITEMS:
            raise CompetitorSchemaError("too_many_json_items")
        return {
            _text(key, "json.key"): _bounded_json(item, depth=depth + 1)
            for key, item in value.items()
        }
    if _is_sequence(value):
        if len(value) > _MAX_MAPPING_ITEMS:
            raise CompetitorSchemaError("too_many_json_items")
        return [_bounded_json(item, depth=depth + 1) for item in value]
    raise CompetitorSchemaError("non_json_value")


def _reject_secret_bearing_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            parts = set(normalized.split("_"))
            if (
                {"password", "secret", "credential", "authorization"} & parts
                or normalized in {"token", "api_key", "apikey"}
                or normalized.endswith("_token")
                or normalized.startswith("token_")
            ):
                raise CompetitorSchemaError("secret_bearing_public_key")
            _reject_secret_bearing_keys(item)
    elif _is_sequence(value):
        for item in value:
            _reject_secret_bearing_keys(item)


def _command_argument(value: Any, name: str) -> str:
    argument = _text(value, name)
    _placeholders(argument)
    return argument


def _placeholders(argument: str) -> set[str]:
    fields: set[str] = set()
    try:
        parsed = string.Formatter().parse(argument)
        for _literal, field_name, format_spec, conversion in parsed:
            if field_name is None:
                continue
            if (
                field_name not in ALLOWED_COMMAND_PLACEHOLDERS
                or format_spec
                or conversion
            ):
                raise CompetitorSchemaError("invalid_adapter_placeholder")
            fields.add(field_name)
    except ValueError:
        raise CompetitorSchemaError("invalid_adapter_placeholder") from None
    return fields


def _working_directory(value: Any) -> str:
    candidate = _text(value, "adapter.cwd").replace("\\", "/")
    path = PurePosixPath(candidate)
    if path.is_absolute() or ".." in path.parts or len(path.parts) > 32:
        raise CompetitorSchemaError("invalid:adapter.cwd")
    return path.as_posix()


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


__all__ = [
    "ALLOWED_COMMAND_PLACEHOLDERS",
    "REQUIRED_COMMAND_PLACEHOLDERS",
    "SYSTEM_EXECUTION_MODES",
    "SYSTEM_MANIFEST_SCHEMA_VERSION",
    "SYSTEM_TRACKS",
    "CommandAdapter",
    "CommandAdapterConfig",
    "CompetitorManifest",
    "CompetitorSchemaError",
    "FairnessProfile",
    "SystemManifest",
    "load_system_manifest",
    "load_system_manifests",
]
