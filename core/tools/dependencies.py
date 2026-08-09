"""Typed, deterministic dependency availability for registered tools.

Availability probes are deliberately local.  They may inspect the current
Python environment, PATH, packaged resources, configured service credentials,
and reviewed vendor artifacts, but they never contact a remote service or run a
dependency executable.
"""

from __future__ import annotations

import hashlib
import importlib.resources
import importlib.util
import json
import os
import re
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Union

_BINARY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_DISTRIBUTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_IMPORT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class DependencyKind(str, Enum):
    BINARY = "binary"
    PYTHON = "python"
    RESOURCE = "resource"
    SERVICE = "service"
    VENDOR = "vendor"


class DependencyMode(str, Enum):
    ALL = "all"
    ANY = "any"


class ResourceType(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"


def _required_text(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    normalized = value.strip()
    if not normalized or "\x00" in normalized:
        raise ValueError(f"{label} must be non-empty")
    return normalized


def _relative_resource_path(value: str, label: str) -> str:
    normalized = _required_text(value, label)
    if "\\" in normalized:
        raise ValueError(f"{label} must be a relative POSIX path")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} must be a relative POSIX path")
    return path.as_posix()


@dataclass(frozen=True)
class BinaryDependency:
    name: str
    kind: DependencyKind = field(default=DependencyKind.BINARY, init=False)

    def __post_init__(self) -> None:
        name = _required_text(self.name, "binary dependency")
        if _BINARY_NAME.fullmatch(name) is None:
            raise ValueError("binary dependency must be an executable name, not a path")
        object.__setattr__(self, "name", name)

    @property
    def label(self) -> str:
        return f"binary:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "name": self.name}


@dataclass(frozen=True)
class PythonDependency:
    import_name: str
    distribution: str = ""
    kind: DependencyKind = field(default=DependencyKind.PYTHON, init=False)

    def __post_init__(self) -> None:
        import_name = _required_text(self.import_name, "Python dependency")
        if _IMPORT_NAME.fullmatch(import_name) is None:
            raise ValueError("Python dependency must be a dotted import name")
        distribution = self.distribution
        if not isinstance(distribution, str):
            raise TypeError("Python distribution must be text")
        distribution = distribution.strip()
        if distribution and _DISTRIBUTION_NAME.fullmatch(distribution) is None:
            raise ValueError("Python distribution must be a package name")
        object.__setattr__(self, "import_name", import_name)
        object.__setattr__(self, "distribution", distribution)

    @property
    def name(self) -> str:
        return self.distribution or self.import_name

    @property
    def label(self) -> str:
        return f"python:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        payload = {"import_name": self.import_name, "kind": self.kind.value, "name": self.name}
        if self.distribution:
            payload["distribution"] = self.distribution
        return payload


@dataclass(frozen=True)
class ResourceDependency:
    package: str
    path: str
    resource_type: ResourceType = ResourceType.FILE
    kind: DependencyKind = field(default=DependencyKind.RESOURCE, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.package, str):
            raise TypeError("resource package must be text")
        package = self.package.strip()
        if package and _IMPORT_NAME.fullmatch(package) is None:
            raise ValueError("resource package must be a dotted import name")
        if not isinstance(self.resource_type, ResourceType):
            try:
                object.__setattr__(self, "resource_type", ResourceType(self.resource_type))
            except (TypeError, ValueError) as exc:
                raise ValueError("resource type must be file or directory") from exc
        object.__setattr__(self, "package", package)
        object.__setattr__(self, "path", _relative_resource_path(self.path, "resource path"))

    @property
    def label(self) -> str:
        locator = f"{self.package}:{self.path}" if self.package else self.path
        return f"resource:{self.resource_type.value}:{locator}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "package": self.package,
            "path": self.path,
            "resource_type": self.resource_type.value,
        }


@dataclass(frozen=True)
class ServiceDependency:
    name: str
    secret_name: str = ""
    environment: tuple[str, ...] = ()
    kind: DependencyKind = field(default=DependencyKind.SERVICE, init=False)

    def __post_init__(self) -> None:
        name = _required_text(self.name, "service dependency")
        if _SERVICE_NAME.fullmatch(name) is None:
            raise ValueError("service dependency must be a service name")
        if not isinstance(self.secret_name, str):
            raise TypeError("service secret name must be text")
        secret_name = self.secret_name.strip()
        if secret_name and _ENVIRONMENT_NAME.fullmatch(secret_name) is None:
            raise ValueError("service secret name must be an identifier")
        if isinstance(self.environment, str) or not isinstance(self.environment, Sequence):
            raise TypeError("service environment must be a sequence of identifiers")
        environment = tuple(_required_text(item, "service environment variable") for item in self.environment)
        if any(_ENVIRONMENT_NAME.fullmatch(item) is None for item in environment):
            raise ValueError("service environment variable must be an identifier")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "secret_name", secret_name)
        object.__setattr__(
            self,
            "environment",
            tuple(dict.fromkeys(environment)),
        )

    @property
    def label(self) -> str:
        return f"service:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": self.kind.value, "name": self.name}
        if self.secret_name:
            payload["secret_name"] = self.secret_name
        if self.environment:
            payload["environment"] = list(self.environment)
        return payload


@dataclass(frozen=True)
class VendorDependency:
    path: str
    sha256: str = ""
    kind: DependencyKind = field(default=DependencyKind.VENDOR, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _relative_resource_path(self.path, "vendor artifact path"))
        if not isinstance(self.sha256, str):
            raise TypeError("vendor artifact sha256 must be text")
        digest = self.sha256.strip().lower()
        if digest and (len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest)):
            raise ValueError("vendor artifact sha256 must be a lowercase SHA-256 digest")
        object.__setattr__(self, "sha256", digest)

    @property
    def label(self) -> str:
        return f"vendor:{self.path}"

    def to_dict(self) -> dict[str, Any]:
        payload = {"kind": self.kind.value, "path": self.path}
        if self.sha256:
            payload["sha256"] = self.sha256
        return payload


DependencyLeaf = Union[
    BinaryDependency,
    PythonDependency,
    ResourceDependency,
    ServiceDependency,
    VendorDependency,
]


@dataclass(frozen=True)
class DependencyGroup:
    mode: DependencyMode
    items: tuple[DependencySpec, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.mode, DependencyMode):
            try:
                object.__setattr__(self, "mode", DependencyMode(self.mode))
            except (TypeError, ValueError) as exc:
                raise ValueError("dependency group mode must be all or any") from exc
        if not isinstance(self.items, tuple):
            raise TypeError("dependency group items must be a tuple")
        if any(not isinstance(item, _DEPENDENCY_TYPES) for item in self.items):
            raise TypeError("dependency group contains an invalid dependency")

    @property
    def label(self) -> str:
        labels = ",".join(dependency_label(item) for item in self.items)
        return f"{self.mode.value}({labels})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [dependency_to_dict(item) for item in self.items],
            "mode": self.mode.value,
        }


DependencySpec = Union[DependencyLeaf, DependencyGroup]
DependencyInput = Union[str, DependencySpec]

_DEPENDENCY_TYPES = (
    BinaryDependency,
    PythonDependency,
    ResourceDependency,
    ServiceDependency,
    VendorDependency,
    DependencyGroup,
)


def binary(name: str) -> BinaryDependency:
    return BinaryDependency(name)


def python(import_name: str, *, distribution: str = "") -> PythonDependency:
    return PythonDependency(import_name, distribution)


def resource(
    package: str,
    path: str,
    *,
    resource_type: ResourceType = ResourceType.FILE,
) -> ResourceDependency:
    return ResourceDependency(package, path, resource_type)


def service(
    name: str,
    *,
    secret_name: str = "",
    environment: Sequence[str] = (),
) -> ServiceDependency:
    if isinstance(environment, str):
        raise TypeError("service environment must be a sequence of identifiers")
    return ServiceDependency(name, secret_name, tuple(environment))


def vendor(path: str, *, sha256: str = "") -> VendorDependency:
    return VendorDependency(path, sha256)


def all_of(*items: DependencyInput) -> DependencyGroup:
    return DependencyGroup(DependencyMode.ALL, tuple(normalize_dependency(item) for item in items))


def any_of(*items: DependencyInput) -> DependencyGroup:
    return DependencyGroup(DependencyMode.ANY, tuple(normalize_dependency(item) for item in items))


def normalize_dependency(value: DependencyInput) -> DependencySpec:
    if isinstance(value, _DEPENDENCY_TYPES):
        return value
    token = _required_text(value, "dependency token")
    if token.startswith("any:"):
        options = tuple(item.strip() for item in token.split(":", 1)[1].split(",") if item.strip())
        return any_of(*options)
    if token.startswith("all:"):
        options = tuple(item.strip() for item in token.split(":", 1)[1].split(",") if item.strip())
        return all_of(*options)
    if token.startswith("python:"):
        return python(token.split(":", 1)[1])
    if token.startswith("binary:"):
        return binary(token.split(":", 1)[1])
    if token.startswith("resource:"):
        locator = token.split(":", 1)[1]
        resource_type = ResourceType.FILE
        if locator.startswith("directory:"):
            resource_type = ResourceType.DIRECTORY
            locator = locator.split(":", 1)[1]
        elif locator.startswith("file:"):
            locator = locator.split(":", 1)[1]
        if ":" in locator:
            package, path = locator.split(":", 1)
            return resource(package, path, resource_type=resource_type)
        return resource("", locator, resource_type=resource_type)
    if token.startswith("service:"):
        return service(token.split(":", 1)[1])
    if token.startswith("vendor:"):
        return vendor(token.split(":", 1)[1])
    return binary(token)


def normalize_dependencies(value: DependencySpec | Sequence[DependencyInput] | None) -> DependencySpec:
    if value is None:
        return all_of()
    if isinstance(value, _DEPENDENCY_TYPES):
        return value
    if isinstance(value, str):
        return all_of(value)
    if not isinstance(value, Sequence):
        raise TypeError("dependencies must be a dependency or sequence")
    return all_of(*value)


def dependency_label(spec: DependencySpec) -> str:
    return spec.label


def dependency_to_dict(spec: DependencySpec) -> dict[str, Any]:
    return spec.to_dict()


def requirement_labels(spec: DependencySpec) -> tuple[str, ...]:
    if isinstance(spec, DependencyGroup) and spec.mode is DependencyMode.ALL:
        return tuple(dependency_label(item) for item in spec.items)
    return (dependency_label(spec),)


def dependency_leaves(spec: DependencySpec) -> tuple[DependencyLeaf, ...]:
    """Return the stable, declaration-order leaf inventory for one expression."""

    if not isinstance(spec, DependencyGroup):
        return (spec,)
    leaves: list[DependencyLeaf] = []
    for item in spec.items:
        leaves.extend(dependency_leaves(item))
    return tuple(leaves)


@dataclass(frozen=True)
class DependencyContext:
    root: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    environment: Mapping[str, str] = field(default_factory=lambda: os.environ)
    service_states: Mapping[str, bool] = field(default_factory=dict)
    vendor_manifest: Path | None = None
    secret_resolver: Callable[[str], str] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))
        if self.vendor_manifest is not None:
            object.__setattr__(self, "vendor_manifest", Path(self.vendor_manifest))
        if not isinstance(self.environment, Mapping) or not isinstance(self.service_states, Mapping):
            raise TypeError("dependency context environment and service states must be mappings")
        if self.secret_resolver is not None and not callable(self.secret_resolver):
            raise TypeError("dependency context secret resolver must be callable")


@dataclass(frozen=True)
class DependencyEvaluation:
    requirement: DependencySpec
    available: bool
    detail: str
    children: tuple[DependencyEvaluation, ...] = ()

    @property
    def missing(self) -> tuple[str, ...]:
        if self.available:
            return ()
        if not self.children:
            return (dependency_label(self.requirement),)
        if isinstance(self.requirement, DependencyGroup) and self.requirement.mode is DependencyMode.ANY:
            return (dependency_label(self.requirement),)
        missing: list[str] = []
        for child in self.children:
            missing.extend(child.missing)
        return tuple(dict.fromkeys(missing))

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "children": [child.to_dict() for child in self.children],
            "detail": self.detail,
            "requirement": dependency_to_dict(self.requirement),
        }


def _contained_local_path(root: Path, relative_path: str) -> Path | None:
    """Resolve one in-tree path while rejecting symlinked path components."""

    try:
        canonical_root = root.resolve(strict=True)
    except OSError:
        return None
    candidate = canonical_root.joinpath(*PurePosixPath(relative_path).parts)
    current = canonical_root
    for part in PurePosixPath(relative_path).parts:
        current = current / part
        if current.is_symlink():
            return None
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(canonical_root)
    except (OSError, ValueError):
        return None
    return resolved


def _resource_matches_type(candidate: Any, resource_type: ResourceType) -> bool:
    predicate = candidate.is_file if resource_type is ResourceType.FILE else candidate.is_dir
    try:
        return bool(predicate())
    except (OSError, TypeError):
        return False


def _resource_available(requirement: ResourceDependency, context: DependencyContext) -> bool:
    if requirement.package:
        try:
            package_candidate = importlib.resources.files(requirement.package).joinpath(requirement.path)
            return _resource_matches_type(package_candidate, requirement.resource_type)
        except (ImportError, ModuleNotFoundError, AttributeError, OSError, TypeError):
            return False
    local_candidate = _contained_local_path(context.root, requirement.path)
    if local_candidate is None:
        return False
    return _resource_matches_type(local_candidate, requirement.resource_type)


def _service_available(requirement: ServiceDependency, context: DependencyContext) -> bool:
    if requirement.name in context.service_states:
        return bool(context.service_states[requirement.name])
    environment_names = tuple(dict.fromkeys((*requirement.environment, requirement.secret_name)))
    if any(bool(context.environment.get(name, "")) for name in environment_names if name):
        return True
    if requirement.secret_name:
        try:
            resolver = context.secret_resolver
            if resolver is None:
                from config import get_secret

                resolver = get_secret
            return bool(resolver(requirement.secret_name))
        except (ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
            return False
    return False


def _vendor_available(requirement: VendorDependency, context: DependencyContext) -> bool:
    try:
        root = context.root.resolve(strict=True)
    except OSError:
        return False
    manifest_path = context.vendor_manifest or root / "quality" / "vendor-manifest.json"
    if manifest_path.is_symlink():
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        return False
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    if not isinstance(artifacts, list):
        return False
    record = next(
        (item for item in artifacts if isinstance(item, dict) and str(item.get("path") or "") == requirement.path),
        None,
    )
    if record is None:
        return False
    manifest_digest = str(record.get("sha256") or "").lower()
    if requirement.sha256 and manifest_digest != requirement.sha256:
        return False
    if len(manifest_digest) != 64 or any(character not in "0123456789abcdef" for character in manifest_digest):
        return False
    candidate = _contained_local_path(root, requirement.path)
    if candidate is None or not candidate.is_file():
        return False
    try:
        actual_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    except OSError:
        return False
    return actual_digest == manifest_digest


def evaluate_dependency(
    requirement: DependencySpec | Sequence[DependencyInput],
    context: DependencyContext | None = None,
) -> DependencyEvaluation:
    spec = normalize_dependencies(requirement)
    active_context = context or DependencyContext()
    if isinstance(spec, DependencyGroup):
        children = tuple(evaluate_dependency(item, active_context) for item in spec.items)
        available = (
            all(child.available for child in children)
            if spec.mode is DependencyMode.ALL
            else bool(children) and any(child.available for child in children)
        )
        return DependencyEvaluation(
            spec, available, "requirements_satisfied" if available else "requirements_missing", children
        )
    if isinstance(spec, BinaryDependency):
        available = shutil.which(spec.name) is not None
    elif isinstance(spec, PythonDependency):
        try:
            available = importlib.util.find_spec(spec.import_name) is not None
        except (ImportError, AttributeError, ModuleNotFoundError, ValueError):
            available = False
    elif isinstance(spec, ResourceDependency):
        available = _resource_available(spec, active_context)
    elif isinstance(spec, ServiceDependency):
        available = _service_available(spec, active_context)
    else:
        available = _vendor_available(spec, active_context)
    return DependencyEvaluation(spec, available, "available" if available else "missing")


__all__ = [
    "BinaryDependency",
    "DependencyContext",
    "DependencyEvaluation",
    "DependencyGroup",
    "DependencyKind",
    "DependencyMode",
    "DependencySpec",
    "PythonDependency",
    "ResourceDependency",
    "ResourceType",
    "ServiceDependency",
    "VendorDependency",
    "all_of",
    "any_of",
    "binary",
    "dependency_label",
    "dependency_leaves",
    "dependency_to_dict",
    "evaluate_dependency",
    "normalize_dependencies",
    "normalize_dependency",
    "python",
    "requirement_labels",
    "resource",
    "service",
    "vendor",
]
