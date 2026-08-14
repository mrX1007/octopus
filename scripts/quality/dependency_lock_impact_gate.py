"""Fail-closed impact and input-hash checks for generated dependency locks."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath

from scripts.lock_requirements import PROFILE_INPUTS, TARGETS

_MANIFEST_PATH = "requirements/locks/manifest.json"


class DependencyLockImpactError(RuntimeError):
    pass


def _normalized_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise DependencyLockImpactError(f"changed path is not canonical: {value!r}")
    return str(path)


def required_lock_paths_for_input(requirement_path: str) -> tuple[str, ...]:
    requirement_path = _normalized_path(requirement_path)
    impacted_profiles = tuple(profile for profile, inputs in PROFILE_INPUTS.items() if requirement_path in inputs)
    return tuple(
        f"requirements/locks/{target.platform_id}/{target.tag}/{profile}.txt"
        for target in TARGETS
        for profile in impacted_profiles
    )


def validate_changed_path_impact(changed_paths: Iterable[str]) -> None:
    changed = frozenset(_normalized_path(path) for path in changed_paths)
    requirement_inputs = frozenset(input_path for inputs in PROFILE_INPUTS.values() for input_path in inputs)
    modified_inputs = changed & requirement_inputs
    if not modified_inputs:
        return
    required = {_MANIFEST_PATH}
    for input_path in modified_inputs:
        required.update(required_lock_paths_for_input(input_path))
    missing = sorted(required - changed)
    if missing:
        raise DependencyLockImpactError("requirement change is missing generated lock impacts: " + ", ".join(missing))


def validate_manifest_input_hashes(root: Path) -> None:
    manifest_path = root / _MANIFEST_PATH
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DependencyLockImpactError("dependency lock manifest cannot be read") from exc
    hashes = manifest.get("input_sha256") if isinstance(manifest, dict) else None
    if not isinstance(hashes, dict):
        raise DependencyLockImpactError("dependency lock manifest has no input_sha256 map")
    expected_inputs = frozenset(input_path for inputs in PROFILE_INPUTS.values() for input_path in inputs)
    if set(hashes) != expected_inputs:
        raise DependencyLockImpactError("dependency lock manifest input inventory mismatch")
    for input_path in sorted(expected_inputs):
        source = root / input_path
        try:
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as exc:
            raise DependencyLockImpactError(f"requirement input cannot be read: {input_path}") from exc
        if hashes[input_path] != digest:
            raise DependencyLockImpactError(f"dependency lock manifest input digest mismatch: {input_path}")


def _working_tree_paths(root: Path) -> tuple[str, ...]:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    paths: list[str] = []
    for line in completed.stdout.splitlines():
        value = line[3:]
        if " -> " in value:
            value = value.split(" -> ", 1)[1]
        paths.append(value)
    return tuple(paths)


def run_gate(
    *,
    root: Path | None = None,
    changed_paths: Iterable[str] | None = None,
) -> None:
    repository = (root or Path(__file__).resolve().parents[2]).resolve()
    paths = tuple(changed_paths) if changed_paths is not None else _working_tree_paths(repository)
    validate_changed_path_impact(paths)
    validate_manifest_input_hashes(repository)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--changed-path", action="append", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        run_gate(root=args.root, changed_paths=args.changed_path)
    except (DependencyLockImpactError, subprocess.SubprocessError) as exc:
        print(f"dependency lock impact gate failed: {exc}")
        return 1
    print("dependency lock impact gate succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
