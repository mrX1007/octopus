#!/usr/bin/env python3
"""Generate deterministic CycloneDX SBOMs from exact repository inputs."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from urllib.parse import quote

_PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?==(?P<version>[^\s;]+)")
_HASH = re.compile(r"--hash=sha256:([0-9a-fA-F]{64})")
_PROJECT_FIELD = re.compile(r'^\s*(?P<field>name|version)\s*=\s*"(?P<value>[^"\r\n]+)"\s*$')
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SbomError(RuntimeError):
    """A repository input cannot be represented as a deterministic SBOM."""


def _read_text(path: Path, label: str) -> str:
    if path.is_symlink():
        raise SbomError(f"{label} must not be a symlink: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SbomError(f"cannot read {label}: {type(exc).__name__}") from exc


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_file(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise SbomError(f"{label} is not a regular file: {path}")
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise SbomError(f"cannot hash {label}: {type(exc).__name__}") from exc


def _records(text: str) -> tuple[str, ...]:
    records: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        fragment = line[:-1].rstrip() if continued else line
        pending = f"{pending} {fragment}".strip()
        if not continued:
            records.append(pending)
            pending = ""
    if pending:
        raise SbomError("unterminated requirement continuation")
    return tuple(records)


def _python_components(lock_path: Path) -> list[dict]:
    text = _read_text(lock_path, "lock")
    components: list[dict] = []
    seen = set()
    for record in _records(text):
        if record.startswith("--"):
            continue
        match = _PIN.match(record)
        hashes = sorted({value.lower() for value in _HASH.findall(record)})
        if match is None or not hashes:
            raise SbomError(f"lock record is not exact and hashed: {record[:120]}")
        name = match.group("name")
        version = match.group("version")
        canonical_name = re.sub(r"[-_.]+", "-", name).lower()
        purl = f"pkg:pypi/{quote(canonical_name)}@{quote(version)}"
        if purl in seen:
            raise SbomError(f"duplicate Python lock component: {canonical_name}=={version}")
        seen.add(purl)
        components.append(
            {
                "bom-ref": purl,
                "hashes": [{"alg": "SHA-256", "content": value} for value in hashes],
                "name": canonical_name,
                "purl": purl,
                "type": "library",
                "version": version,
            }
        )
    return sorted(components, key=lambda item: item["bom-ref"])


def _serial(payload: Mapping[str, object]) -> str:
    digest = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    return f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def build_sbom(lock_path: Path) -> dict:
    """Return a backward-compatible Python-lock CycloneDX 1.5 document."""

    components = _python_components(lock_path)
    payload = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "components": components,
        "specVersion": "1.5",
        "version": 1,
    }
    return {**payload, "serialNumber": _serial(payload)}


def _relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\\" in value or "\x00" in value:
        raise SbomError(f"invalid {label}")
    path = PurePosixPath(value.strip())
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SbomError(f"invalid {label}")
    return path.as_posix()


def _repository_candidate(root: Path, relative: str, label: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise SbomError(f"{label} traverses a symlink: {relative}")
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise SbomError(f"{label} escapes the repository: {relative}") from exc
    return resolved


def _tree_digest(path: Path, root: Path) -> str:
    if path.is_symlink() or not path.is_dir():
        raise SbomError(f"resource directory is unavailable: {path.relative_to(root).as_posix()}")
    records: list[tuple[str, str]] = []
    for current, directory_names, file_names in os.walk(path, followlinks=False):
        current_path = Path(current)
        for name in sorted(directory_names):
            if (current_path / name).is_symlink():
                raise SbomError(f"resource directory contains a symlink: {(current_path / name).relative_to(root)}")
        for name in sorted(file_names):
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_file():
                raise SbomError(f"resource directory contains a non-file: {candidate.relative_to(root)}")
            records.append((candidate.relative_to(path).as_posix(), _sha256_file(candidate, "resource file")))
    return hashlib.sha256(_canonical_bytes(records)).hexdigest()


def _project_identity(root: Path) -> tuple[str, str]:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file() or pyproject.is_symlink():
        return "octopus-security", "0+unknown"
    fields: dict[str, str] = {}
    in_project = False
    for line in _read_text(pyproject, "pyproject.toml").splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_project = stripped == "[project]"
            continue
        if not in_project:
            continue
        match = _PROJECT_FIELD.fullmatch(line)
        if match is not None:
            fields[match.group("field")] = match.group("value").strip()
    return fields.get("name", "octopus-security"), fields.get("version", "0+unknown")


def _go_requirements(go_mod: Path, go_sum: Path) -> tuple[str, list[dict]]:
    module_path = ""
    requirements: dict[str, tuple[str, bool]] = {}
    in_require = False
    for raw_line in _read_text(go_mod, "go.mod").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        declaration = stripped.split("//", 1)[0].strip()
        indirect = "// indirect" in stripped
        if declaration == "require (":
            if in_require:
                raise SbomError("nested require block in go.mod")
            in_require = True
            continue
        if declaration == ")":
            if not in_require:
                raise SbomError("unexpected closing block in go.mod")
            in_require = False
            continue
        fields = declaration.split()
        if in_require:
            if len(fields) != 2:
                raise SbomError(f"invalid go.mod requirement: {declaration}")
            dependency, version = fields
        elif fields[0] == "require":
            if len(fields) != 3:
                raise SbomError(f"invalid go.mod requirement: {declaration}")
            dependency, version = fields[1:]
        elif fields[0] == "module":
            if len(fields) != 2 or module_path:
                raise SbomError("go.mod must contain one module declaration")
            module_path = fields[1]
            continue
        elif fields[0] in {"exclude", "replace", "retract"}:
            raise SbomError(f"unsupported go.mod dependency directive: {fields[0]}")
        else:
            continue
        if not dependency or not version or any(character.isspace() for character in dependency + version):
            raise SbomError(f"invalid go.mod requirement: {declaration}")
        if dependency in requirements and requirements[dependency][0] != version:
            raise SbomError(f"duplicate Go module with conflicting versions: {dependency}")
        requirements[dependency] = (version, indirect)
    if in_require or not module_path:
        raise SbomError("unterminated require block or missing module declaration in go.mod")

    checksums: dict[tuple[str, str], str] = {}
    for line in _read_text(go_sum, "go.sum").splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise SbomError(f"invalid go.sum row: {line[:120]}")
        dependency, version, checksum = fields
        if version.endswith("/go.mod"):
            continue
        if not checksum.startswith("h1:"):
            raise SbomError(f"unsupported Go module checksum: {dependency} {version}")
        try:
            raw_digest = base64.b64decode(checksum[3:], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SbomError(f"invalid Go module checksum: {dependency} {version}") from exc
        if len(raw_digest) != 32:
            raise SbomError(f"invalid Go SHA-256 checksum: {dependency} {version}")
        key = (dependency, version)
        digest = raw_digest.hex()
        if key in checksums and checksums[key] != digest:
            raise SbomError(f"conflicting Go module checksums: {dependency} {version}")
        checksums[key] = digest

    components = []
    for dependency, (version, indirect) in sorted(requirements.items()):
        archive_digest = checksums.get((dependency, version))
        if archive_digest is None:
            raise SbomError(f"go.sum is missing the module archive checksum: {dependency} {version}")
        purl = f"pkg:golang/{quote(dependency, safe='/')}@{quote(version)}"
        components.append(
            {
                "bom-ref": purl,
                "hashes": [{"alg": "SHA-256", "content": archive_digest}],
                "name": dependency,
                "properties": [{"name": "octopus:go:indirect", "value": str(indirect).lower()}],
                "purl": purl,
                "type": "library",
                "version": version,
            }
        )
    return module_path, components


def _add_component(components: dict[str, dict], component: dict) -> str:
    reference = str(component.get("bom-ref") or "")
    if not reference:
        raise SbomError("component is missing bom-ref")
    existing = components.get(reference)
    if existing is not None and existing != component:
        raise SbomError(f"conflicting component identity: {reference}")
    components[reference] = component
    return reference


def _vendor_components(root: Path, manifest_path: Path) -> list[dict]:
    try:
        manifest = json.loads(_read_text(manifest_path, "vendor manifest"))
    except json.JSONDecodeError as exc:
        raise SbomError("vendor manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise SbomError("vendor manifest schema_version must be 1")
    submodules = manifest.get("submodules")
    artifacts = manifest.get("artifacts")
    if not isinstance(submodules, list) or not isinstance(artifacts, list):
        raise SbomError("vendor manifest must contain submodules and artifacts lists")

    components: list[dict] = []
    seen_paths = set()
    for entry in submodules:
        if not isinstance(entry, dict):
            raise SbomError("vendor submodule entry must be an object")
        path = _relative_path(entry.get("path"), "vendor submodule path")
        commit = str(entry.get("commit") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40}", commit) or path in seen_paths:
            raise SbomError(f"invalid or duplicate vendor submodule: {path}")
        seen_paths.add(path)
        candidate = _repository_candidate(root, path, "vendor submodule")
        if not candidate.is_dir():
            raise SbomError(f"vendor submodule directory is unavailable: {path}")
        purl = f"pkg:generic/{quote(path, safe='/')}@{commit}"
        components.append(
            {
                "bom-ref": purl,
                "name": PurePosixPath(path).name,
                "properties": [{"name": "octopus:vendor:path", "value": path}],
                "purl": purl,
                "type": "library",
                "version": commit,
            }
        )
    for entry in artifacts:
        if not isinstance(entry, dict):
            raise SbomError("vendor artifact entry must be an object")
        path = _relative_path(entry.get("path"), "vendor artifact path")
        digest = str(entry.get("sha256") or "").strip().lower()
        if _SHA256.fullmatch(digest) is None or path in seen_paths:
            raise SbomError(f"invalid or duplicate vendor artifact: {path}")
        seen_paths.add(path)
        candidate = _repository_candidate(root, path, "vendor artifact")
        if _sha256_file(candidate, "vendor artifact") != digest:
            raise SbomError(f"vendor artifact digest mismatch: {path}")
        properties = [{"name": "octopus:vendor:path", "value": path}]
        platform = entry.get("platform")
        if isinstance(platform, dict):
            for field in ("arch", "os"):
                value = str(platform.get(field) or "").strip()
                if value:
                    properties.append({"name": f"octopus:vendor:{field}", "value": value})
        reference = f"urn:octopus:vendor:{quote(path, safe='')}"
        components.append(
            {
                "bom-ref": reference,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "name": PurePosixPath(path).name,
                "properties": sorted(properties, key=lambda item: item["name"]),
                "type": "file",
            }
        )
    return components


def load_registered_tool_inventory(root: Path) -> dict:
    """Import the canonical built-in registry and return its declarations."""

    root_text = str(root)
    inserted = not sys.path or sys.path[0] != root_text
    if inserted:
        sys.path.insert(0, root_text)
    try:
        importlib.import_module("core.tools")
        registry = importlib.import_module("core.tools.registry")
        inventory = registry.dependency_inventory()
    except (AttributeError, ImportError, RuntimeError, TypeError, ValueError) as exc:
        raise SbomError(f"cannot load registered-tool dependency inventory: {type(exc).__name__}") from exc
    finally:
        if inserted and sys.path and sys.path[0] == root_text:
            sys.path.pop(0)
    if not isinstance(inventory, dict):
        raise SbomError("registered-tool dependency inventory is not an object")
    return inventory


def _tool_dependency_components(
    root: Path,
    inventory: Mapping[str, object],
) -> tuple[list[dict], list[dict], list[dict], set[str]]:
    tool_records = inventory.get("tools")
    if inventory.get("schema_version") != "1.0" or not isinstance(tool_records, list):
        raise SbomError("registered-tool dependency inventory schema is invalid")
    components: dict[str, dict] = {}
    services: dict[str, dict] = {}
    properties: list[dict] = []
    references: set[str] = set()
    seen_tools = set()

    def visit(expression: object) -> None:
        if not isinstance(expression, dict):
            raise SbomError("tool dependency expression must be an object")
        if "mode" in expression:
            if expression.get("mode") not in {"all", "any"} or not isinstance(expression.get("items"), list):
                raise SbomError("tool dependency group is invalid")
            for item in expression["items"]:
                visit(item)
            return
        kind = expression.get("kind")
        if kind == "binary":
            name = str(expression.get("name") or "").strip()
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name) is None:
                raise SbomError("tool binary dependency name is invalid")
            purl = f"pkg:generic/{quote(name)}"
            references.add(
                _add_component(
                    components,
                    {
                        "bom-ref": purl,
                        "name": name,
                        "properties": [{"name": "octopus:dependency:kind", "value": "binary"}],
                        "purl": purl,
                        "type": "application",
                    },
                )
            )
        elif kind == "python":
            name = str(expression.get("distribution") or expression.get("name") or "").strip()
            canonical = re.sub(r"[-_.]+", "-", name).lower()
            if not canonical:
                raise SbomError("tool Python dependency name is invalid")
            purl = f"pkg:pypi/{quote(canonical)}"
            references.add(
                _add_component(
                    components,
                    {
                        "bom-ref": purl,
                        "name": canonical,
                        "properties": [{"name": "octopus:dependency:kind", "value": "python"}],
                        "purl": purl,
                        "type": "library",
                    },
                )
            )
        elif kind == "resource":
            package = str(expression.get("package") or "").strip()
            path = _relative_path(expression.get("path"), "tool resource path")
            resource_type = expression.get("resource_type")
            if resource_type not in {"file", "directory"}:
                raise SbomError("tool resource type is invalid")
            locator = f"{package}:{path}" if package else path
            reference = f"urn:octopus:resource:{quote(locator, safe='')}"
            component = {
                "bom-ref": reference,
                "name": locator,
                "properties": [
                    {"name": "octopus:dependency:kind", "value": "resource"},
                    {"name": "octopus:resource:type", "value": str(resource_type)},
                ],
                "type": "file",
            }
            if not package:
                candidate = _repository_candidate(root, path, "tool resource")
                digest = (
                    _sha256_file(candidate, "tool resource")
                    if resource_type == "file"
                    else _tree_digest(candidate, root)
                )
                component["hashes"] = [{"alg": "SHA-256", "content": digest}]
            references.add(_add_component(components, component))
        elif kind == "service":
            name = str(expression.get("name") or "").strip()
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is None:
                raise SbomError("tool service dependency name is invalid")
            reference = f"urn:octopus:service:{quote(name, safe='')}"
            services[reference] = {"bom-ref": reference, "name": name}
            references.add(reference)
        elif kind == "vendor":
            path = _relative_path(expression.get("path"), "tool vendor path")
            reference = f"urn:octopus:vendor:{quote(path, safe='')}"
            references.add(
                _add_component(
                    components,
                    {
                        "bom-ref": reference,
                        "name": PurePosixPath(path).name,
                        "properties": [
                            {"name": "octopus:dependency:kind", "value": "vendor"},
                            {"name": "octopus:vendor:path", "value": path},
                        ],
                        "type": "file",
                    },
                )
            )
        else:
            raise SbomError(f"unknown tool dependency kind: {kind}")

    for record in tool_records:
        if not isinstance(record, dict):
            raise SbomError("tool inventory record must be an object")
        name = str(record.get("name") or "").strip()
        if not name or name in seen_tools:
            raise SbomError(f"invalid or duplicate tool inventory name: {name}")
        seen_tools.add(name)
        expression = record.get("dependencies")
        visit(expression)
        properties.append(
            {
                "name": f"octopus:tool-dependency:{name}",
                "value": _canonical_bytes(expression).decode("utf-8"),
            }
        )
    properties.append(
        {
            "name": "octopus:tool-dependency-inventory:sha256",
            "value": hashlib.sha256(_canonical_bytes(inventory)).hexdigest(),
        }
    )
    return (
        sorted(components.values(), key=lambda item: item["bom-ref"]),
        sorted(services.values(), key=lambda item: item["bom-ref"]),
        sorted(properties, key=lambda item: item["name"]),
        references,
    )


def build_repository_sbom(
    lock_path: Path,
    root: Path,
    *,
    go_mod: Path | None = None,
    vendor_manifest: Path | None = None,
    tool_inventory: Mapping[str, object] | None = None,
) -> dict:
    """Return a deterministic multi-ecosystem repository CycloneDX document."""

    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise SbomError(f"cannot resolve repository root: {type(exc).__name__}") from exc
    lock_path = lock_path if lock_path.is_absolute() else root / lock_path
    name, version = _project_identity(root)
    app_ref = f"pkg:pypi/{quote(re.sub(r'[-_.]+', '-', name).lower())}@{quote(version)}"
    app_component = {
        "bom-ref": app_ref,
        "name": name,
        "purl": app_ref,
        "type": "application",
        "version": version,
    }
    components: dict[str, dict] = {}
    root_dependencies: set[str] = set()
    dependency_rows: list[dict] = []
    metadata_properties = [
        {"name": "octopus:input:python-lock:sha256", "value": _sha256_file(lock_path, "lock")}
    ]
    for component in _python_components(lock_path):
        root_dependencies.add(_add_component(components, component))

    if go_mod is not None:
        go_mod = go_mod if go_mod.is_absolute() else root / go_mod
        go_sum = go_mod.with_suffix(".sum")
        module_path, go_components = _go_requirements(go_mod, go_sum)
        module_ref = f"pkg:golang/{quote(module_path, safe='/')}@{quote(version)}"
        _add_component(
            components,
            {
                "bom-ref": module_ref,
                "name": module_path,
                "properties": [{"name": "octopus:go:first-party", "value": "true"}],
                "purl": module_ref,
                "type": "application",
                "version": version,
            },
        )
        go_references = []
        for component in go_components:
            go_references.append(_add_component(components, component))
        root_dependencies.add(module_ref)
        dependency_rows.append({"dependsOn": sorted(go_references), "ref": module_ref})
        metadata_properties.extend(
            [
                {"name": "octopus:input:go.mod:sha256", "value": _sha256_file(go_mod, "go.mod")},
                {"name": "octopus:input:go.sum:sha256", "value": _sha256_file(go_sum, "go.sum")},
            ]
        )

    if vendor_manifest is not None:
        vendor_manifest = vendor_manifest if vendor_manifest.is_absolute() else root / vendor_manifest
        for component in _vendor_components(root, vendor_manifest):
            root_dependencies.add(_add_component(components, component))
        metadata_properties.append(
            {
                "name": "octopus:input:vendor-manifest:sha256",
                "value": _sha256_file(vendor_manifest, "vendor manifest"),
            }
        )

    services: list[dict] = []
    if tool_inventory is not None:
        tool_components, services, tool_properties, tool_references = _tool_dependency_components(root, tool_inventory)
        locked_python = {
            str(component.get("name")): reference
            for reference, component in components.items()
            if str(component.get("purl") or "").startswith("pkg:pypi/") and "version" in component
        }
        for component in tool_components:
            reference = str(component["bom-ref"])
            if reference in components:
                root_dependencies.add(reference)
                continue
            if reference.startswith("pkg:pypi/") and "version" not in component:
                locked_reference = locked_python.get(str(component.get("name")))
                if locked_reference:
                    tool_references.discard(reference)
                    tool_references.add(locked_reference)
                    continue
            root_dependencies.add(_add_component(components, component))
        root_dependencies.update(tool_references)
        metadata_properties.extend(tool_properties)

    dependency_rows.append({"dependsOn": sorted(root_dependencies), "ref": app_ref})
    metadata_properties.sort(key=lambda item: item["name"])
    payload: dict[str, object] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "components": sorted(components.values(), key=lambda item: item["bom-ref"]),
        "dependencies": sorted(dependency_rows, key=lambda item: item["ref"]),
        "metadata": {"component": app_component, "properties": metadata_properties},
        "specVersion": "1.5",
        "version": 1,
    }
    if services:
        payload["services"] = services
    return {**payload, "serialNumber": _serial(payload)}


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--go-mod", type=Path)
    parser.add_argument("--vendor-manifest", type=Path)
    parser.add_argument("--include-tool-dependencies", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        if args.root is None and args.go_mod is None and args.vendor_manifest is None and not args.include_tool_dependencies:
            payload = build_sbom(args.lock)
        else:
            root = (args.root or Path.cwd()).resolve(strict=True)
            inventory = load_registered_tool_inventory(root) if args.include_tool_dependencies else None
            payload = build_repository_sbom(
                args.lock,
                root,
                go_mod=args.go_mod,
                vendor_manifest=args.vendor_manifest,
                tool_inventory=inventory,
            )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, SbomError) as exc:
        print(f"SBOM generation failed: {exc}", file=sys.stderr)
        return 1
    print(
        "SBOM generated: "
        f"{len(payload['components'])} components, {len(payload.get('services', []))} services"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
