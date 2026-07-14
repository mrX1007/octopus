#!/usr/bin/env python3
"""Verify pinned vendor submodules and approved platform artifacts.

The manifest duplicates security-sensitive gitlink and artifact identities so
that a dependency update is an explicit, reviewable parent-repository change.
No vendor code is imported or executed by this verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform as host_platform
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SUPPORTED_OSES = frozenset({"darwin", "linux", "windows"})
_SUPPORTED_ARCHES = frozenset({"amd64", "arm64"})


class VendorVerificationError(RuntimeError):
    """Raised when a vendor trust invariant is not satisfied."""


@dataclass(frozen=True)
class SubmoduleSpec:
    path: PurePosixPath
    commit: str


@dataclass(frozen=True)
class ArtifactSpec:
    path: PurePosixPath
    submodule: PurePosixPath
    os_name: str
    architecture: str
    sha256: str

    @property
    def platform(self) -> str:
        return f"{self.os_name}/{self.architecture}"


@dataclass(frozen=True)
class VendorManifest:
    submodules: tuple[SubmoduleSpec, ...]
    artifacts: tuple[ArtifactSpec, ...]


@dataclass(frozen=True)
class VerificationResult:
    submodules_checked: int
    artifacts_checked: int
    platform_selector: str


def _require_exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value)
    required = set(expected)
    if actual != required:
        missing = sorted(required - actual)
        unknown = sorted(actual - required)
        raise VendorVerificationError(
            f"{label} has invalid keys (missing={missing}, unknown={unknown})"
        )


def _relative_posix_path(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise VendorVerificationError(f"{label} must be a canonical relative POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise VendorVerificationError(f"{label} must be a canonical relative POSIX path")
    return path


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VendorVerificationError(f"cannot read vendor manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise VendorVerificationError("vendor manifest root must be a JSON object")
    return payload


def load_manifest(path: Path) -> VendorManifest:
    """Load and strictly validate a version-1 vendor manifest."""
    payload = _load_json(path)
    _require_exact_keys(payload, {"schema_version", "submodules", "artifacts"}, "manifest")
    if payload["schema_version"] != 1:
        raise VendorVerificationError("unsupported vendor manifest schema_version")

    raw_submodules = payload["submodules"]
    raw_artifacts = payload["artifacts"]
    if not isinstance(raw_submodules, list) or not raw_submodules:
        raise VendorVerificationError("manifest.submodules must be a non-empty list")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise VendorVerificationError("manifest.artifacts must be a non-empty list")

    submodules: list[SubmoduleSpec] = []
    submodule_paths = set()
    for index, item in enumerate(raw_submodules):
        label = f"manifest.submodules[{index}]"
        if not isinstance(item, dict):
            raise VendorVerificationError(f"{label} must be an object")
        _require_exact_keys(item, {"path", "commit"}, label)
        path_value = _relative_posix_path(item["path"], f"{label}.path")
        commit = item["commit"]
        if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit):
            raise VendorVerificationError(f"{label}.commit must be a lowercase 40-character Git ID")
        if path_value in submodule_paths:
            raise VendorVerificationError(f"duplicate submodule path: {path_value}")
        submodule_paths.add(path_value)
        submodules.append(SubmoduleSpec(path=path_value, commit=commit))

    artifacts: list[ArtifactSpec] = []
    artifact_paths = set()
    for index, item in enumerate(raw_artifacts):
        label = f"manifest.artifacts[{index}]"
        if not isinstance(item, dict):
            raise VendorVerificationError(f"{label} must be an object")
        _require_exact_keys(item, {"path", "submodule", "platform", "sha256"}, label)
        artifact_path = _relative_posix_path(item["path"], f"{label}.path")
        submodule_path = _relative_posix_path(item["submodule"], f"{label}.submodule")
        if submodule_path not in submodule_paths:
            raise VendorVerificationError(f"{label}.submodule is not declared")
        try:
            artifact_path.relative_to(submodule_path)
        except ValueError as exc:
            raise VendorVerificationError(f"{label}.path is outside its declared submodule") from exc

        raw_platform = item["platform"]
        if not isinstance(raw_platform, dict):
            raise VendorVerificationError(f"{label}.platform must be an object")
        _require_exact_keys(raw_platform, {"os", "arch"}, f"{label}.platform")
        os_name = raw_platform["os"]
        architecture = raw_platform["arch"]
        if os_name not in _SUPPORTED_OSES or architecture not in _SUPPORTED_ARCHES:
            raise VendorVerificationError(f"{label}.platform is unsupported")

        sha256 = item["sha256"]
        if not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256):
            raise VendorVerificationError(f"{label}.sha256 must be a lowercase SHA-256 digest")
        if artifact_path in artifact_paths:
            raise VendorVerificationError(f"duplicate artifact path: {artifact_path}")
        artifact_paths.add(artifact_path)
        artifacts.append(
            ArtifactSpec(
                path=artifact_path,
                submodule=submodule_path,
                os_name=os_name,
                architecture=architecture,
                sha256=sha256,
            )
        )

    return VendorManifest(submodules=tuple(submodules), artifacts=tuple(artifacts))


def _run_git(cwd: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VendorVerificationError(f"git invocation failed in {cwd}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown Git error"
        raise VendorVerificationError(f"git {' '.join(args)} failed in {cwd}: {detail}")
    return completed.stdout.strip()


def _resolved_inside(root: Path, relative_path: PurePosixPath, label: str) -> Path:
    candidate = root.joinpath(*relative_path.parts)
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise VendorVerificationError(f"{label} resolves outside the repository") from exc
    return candidate


def _verify_submodule(root: Path, spec: SubmoduleSpec, require_clean: bool) -> None:
    path_text = spec.path.as_posix()
    index_line = _run_git(root, "ls-files", "--stage", "--", path_text)
    fields = index_line.split(None, 3)
    if len(fields) != 4 or fields[0] != "160000" or fields[3] != path_text:
        raise VendorVerificationError(f"{path_text} is not a pinned parent-repository gitlink")
    if fields[1] != spec.commit:
        raise VendorVerificationError(
            f"gitlink mismatch for {path_text}: expected {spec.commit}, got {fields[1]}"
        )

    checkout = _resolved_inside(root, spec.path, f"submodule {path_text}")
    if checkout.is_symlink() or not checkout.is_dir():
        raise VendorVerificationError(f"submodule checkout is missing or is a symlink: {path_text}")
    actual_commit = _run_git(checkout, "rev-parse", "--verify", "HEAD")
    if actual_commit != spec.commit:
        raise VendorVerificationError(
            f"submodule HEAD mismatch for {path_text}: expected {spec.commit}, got {actual_commit}"
        )
    if require_clean:
        status = _run_git(checkout, "status", "--porcelain=v1", "--untracked-files=all")
        if status:
            raise VendorVerificationError(f"submodule checkout is not clean: {path_text}")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise VendorVerificationError(f"cannot hash vendor artifact {path}: {exc}") from exc
    return digest.hexdigest()


def _verify_artifact(root: Path, manifest: VendorManifest, spec: ArtifactSpec) -> None:
    artifact_path = _resolved_inside(root, spec.path, f"artifact {spec.path}")
    submodule_path = _resolved_inside(root, spec.submodule, f"submodule {spec.submodule}")
    if artifact_path.is_symlink() or not artifact_path.is_file():
        raise VendorVerificationError(f"vendor artifact is missing or is a symlink: {spec.path}")
    try:
        artifact_path.resolve(strict=True).relative_to(submodule_path.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise VendorVerificationError(f"vendor artifact escapes its submodule: {spec.path}") from exc

    submodule_spec = next(item for item in manifest.submodules if item.path == spec.submodule)
    relative_to_submodule = spec.path.relative_to(spec.submodule).as_posix()
    tree_entry = _run_git(
        submodule_path,
        "ls-tree",
        submodule_spec.commit,
        "--",
        relative_to_submodule,
    )
    if not tree_entry or not tree_entry.endswith("\t" + relative_to_submodule):
        raise VendorVerificationError(
            f"vendor artifact is not tracked by pinned commit {submodule_spec.commit}: {spec.path}"
        )

    actual_hash = _hash_file(artifact_path)
    if actual_hash != spec.sha256:
        raise VendorVerificationError(
            f"SHA-256 mismatch for {spec.path}: expected {spec.sha256}, got {actual_hash}"
        )


def _auto_platform() -> str:
    os_map = {"darwin": "darwin", "linux": "linux", "win32": "windows", "cygwin": "windows"}
    arch_map = {"aarch64": "arm64", "amd64": "amd64", "arm64": "arm64", "x86_64": "amd64"}
    os_name = os_map.get(sys.platform)
    architecture = arch_map.get(host_platform.machine().lower())
    if os_name is None or architecture is None:
        raise VendorVerificationError(
            f"cannot map host platform {sys.platform}/{host_platform.machine()} to the vendor manifest"
        )
    return f"{os_name}/{architecture}"


def _normalize_platform_selector(selector: str) -> str:
    if selector == "all":
        return selector
    if selector == "auto":
        return _auto_platform()
    parts = selector.split("/")
    if len(parts) != 2 or parts[0] not in _SUPPORTED_OSES or parts[1] not in _SUPPORTED_ARCHES:
        raise VendorVerificationError("platform must be 'all', 'auto', or one of <linux|darwin|windows>/<amd64|arm64>")
    return selector


def verify_repository(
    root: Path,
    manifest_path: Path,
    platform_selector: str = "auto",
    require_clean: bool = True,
) -> VerificationResult:
    """Verify submodule and artifact identities without executing vendor code."""
    root = root.resolve(strict=True)
    manifest = load_manifest(manifest_path.resolve(strict=True))
    selected_platform = _normalize_platform_selector(platform_selector)

    for submodule in manifest.submodules:
        _verify_submodule(root, submodule, require_clean=require_clean)

    if selected_platform == "all":
        selected_artifacts = manifest.artifacts
    else:
        selected_artifacts = tuple(
            artifact for artifact in manifest.artifacts if artifact.platform == selected_platform
        )
    if not selected_artifacts:
        raise VendorVerificationError(f"manifest has no approved artifacts for {selected_platform}")
    for artifact in selected_artifacts:
        _verify_artifact(root, manifest, artifact)

    return VerificationResult(
        submodules_checked=len(manifest.submodules),
        artifacts_checked=len(selected_artifacts),
        platform_selector=selected_platform,
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path, default=Path("quality/vendor-manifest.json"))
    parser.add_argument("--platform", default="auto")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="permit local submodule modifications; hashes and pinned commits are still verified",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    root = args.root.resolve()
    manifest_path = args.manifest
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    try:
        result = verify_repository(
            root,
            manifest_path,
            platform_selector=args.platform,
            require_clean=not args.allow_dirty,
        )
    except (OSError, VendorVerificationError) as exc:
        print(f"vendor verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        "vendor verification passed: "
        f"{result.submodules_checked} submodules, "
        f"{result.artifacts_checked} artifacts ({result.platform_selector})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
