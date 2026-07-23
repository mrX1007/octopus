#!/usr/bin/env python3
"""Build and verify reproducible, hash-locked OCTOPUS requirement profiles.

``validate`` is fully offline. ``update`` and ``check`` invoke the exact uv
version declared below; ``check`` resolves into a temporary directory and
never rewrites the checked-in artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EPOCH = "2026-07-14T00:00:00Z"
SOURCE_DATE_EPOCH = "1783987200"
UV_VERSION = "0.11.28"
INDEX_URL = "https://pypi.org/simple"
SCHEMA_VERSION = 1
PLATFORM_ID = "linux-x86_64"
PYTHON_PLATFORM = "x86_64-manylinux_2_34"


@dataclass(frozen=True)
class Target:
    """One concrete resolver target."""

    tag: str
    python_version: str
    implementation: str = "cpython"
    platform_id: str = PLATFORM_ID
    python_platform: str = PYTHON_PLATFORM

    def to_manifest(self) -> dict[str, str]:
        return {
            "implementation": self.implementation,
            "platform": self.platform_id,
            "python_platform": self.python_platform,
            "python_version": self.python_version,
            "tag": self.tag,
        }


TARGETS = (
    Target("cp39", "3.9"),
    Target("cp310", "3.10"),
    Target("cp311", "3.11"),
    Target("cp312", "3.12"),
)

PROFILE_INPUTS: dict[str, tuple[str, ...]] = {
    "runtime": ("requirements/runtime.txt",),
    "c2": ("requirements/runtime.txt", "requirements/c2.txt"),
    "reporting": (
        "requirements/runtime.txt",
        "requirements/reporting.txt",
    ),
    "osint-browser": (
        "requirements/runtime.txt",
        "requirements/osint-browser.txt",
    ),
    "test": (
        "requirements/runtime.txt",
        "requirements/c2.txt",
        "requirements/reporting.txt",
        "requirements/dev.txt",
    ),
    "mysql": ("requirements/runtime.txt", "requirements/mysql.txt"),
    "external-tools": (
        "requirements/runtime.txt",
        "requirements/external-tools.txt",
    ),
    "platform": ("requirements/runtime.txt", "requirements/platform.txt"),
    "full": (
        "requirements/runtime.txt",
        "requirements/c2.txt",
        "requirements/reporting.txt",
        "requirements/osint-browser.txt",
        "requirements/dev.txt",
        "requirements/mysql.txt",
        "requirements/external-tools.txt",
        "requirements/platform.txt",
    ),
}
PROFILE_SDIST_ALLOWLIST: dict[str, tuple[str, ...]] = {
    "runtime": (),
    "c2": (),
    "reporting": (),
    "osint-browser": ("shodan",),
    "test": (),
    "mysql": (),
    "external-tools": (),
    "platform": (),
    "full": ("shodan",),
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HASH_OPTION_RE = re.compile(
    r"(?:^|\s)--hash=sha256:([0-9a-fA-F]{64})(?=\s|$)"
)
_PIN_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:\[[A-Za-z0-9._,-]+\])?"
    r"==[A-Za-z0-9][A-Za-z0-9._+!~-]*$"
)
_REDACT_URL_AUTH_RE = re.compile(r"(https?://)[^/@\s:]+:[^/@\s]+@", re.I)


class LockError(RuntimeError):
    """A deterministic lock contract was violated."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relative_file(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise LockError(f"path escapes repository root: {relative}") from exc
    if not candidate.is_file():
        raise LockError(f"required input is missing or not a file: {relative}")
    return candidate


def _unsafe_requirement_reason(line: str) -> str | None:
    lowered = line.lower()
    if line.startswith("-"):
        return "installer options/includes are forbidden"
    if "@" in line or "://" in lowered:
        return "direct references and URLs are forbidden"
    if lowered.startswith(("git+", "hg+", "svn+", "bzr+", "file:")):
        return "VCS and local references are forbidden"
    if line.startswith(("/", "./", "../", "~")):
        return "local paths are forbidden"
    if any(token in line for token in ("$", "`", "&&", "||", "\x00", "\r")):
        return "shell/control tokens are forbidden"
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^]]+\])?", line):
        return "line is not a named package requirement"
    return None


def validate_requirement_input_text(text: str, *, source: str) -> None:
    """Reject requirement-file features that bypass the declared index policy."""

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].rstrip()
        reason = _unsafe_requirement_reason(line)
        if reason:
            raise LockError(
                f"unsafe requirement in {source}:{line_number}: {reason}"
            )


def _read_and_validate_inputs(root: Path) -> tuple[dict[str, str], dict[str, str]]:
    contents: dict[str, str] = {}
    hashes: dict[str, str] = {}
    for relative in sorted({item for values in PROFILE_INPUTS.values() for item in values}):
        path = _safe_relative_file(root, relative)
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LockError(f"requirement input is not UTF-8: {relative}") from exc
        validate_requirement_input_text(text, source=relative)
        contents[relative] = text
        hashes[relative] = _sha256(raw)
    return contents, hashes


def render_lock_header(
    *,
    target: Target,
    profile: str,
    inputs: Sequence[str],
) -> str:
    """Return the stable header prepended to uv's headerless output."""

    sdist_allowlist = PROFILE_SDIST_ALLOWLIST[profile]
    sdist_policy = ",".join(sdist_allowlist) if sdist_allowlist else "none"
    return (
        "# OCTOPUS deterministic dependency lock; DO NOT EDIT.\n"
        f"# schema-version: {SCHEMA_VERSION}\n"
        f"# epoch: {EPOCH}\n"
        f"# resolver: uv=={UV_VERSION}\n"
        f"# target: {target.platform_id}/{target.tag} "
        f"({target.implementation}, {target.python_version}, {target.python_platform})\n"
        f"# profile: {profile}\n"
        f"# inputs: {', '.join(inputs)}\n"
        "# policy: hashes-required; binary-default; no-direct-references\n"
        f"# sdist-allowlist: {sdist_policy}\n"
        "#\n"
    )


def _logical_lock_records(text: str, *, source: str) -> list[str]:
    records: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment}".strip()
        if continued:
            continue
        records.append(pending)
        pending = ""
    if pending:
        raise LockError(f"unterminated continuation in {source}")
    return records


def validate_lock_text(
    text: str,
    *,
    source: str,
    sdist_allowlist: Sequence[str] = (),
) -> None:
    """Validate pins, hashes and forbidden directives without network access."""

    if "\x00" in text or "\r" in text:
        raise LockError(f"invalid control character in {source}")
    records = _logical_lock_records(text, source=source)
    if not records:
        raise LockError(f"lock contains no packages: {source}")

    expected_sdist = {name.lower() for name in sdist_allowlist}
    observed_sdist: list[str] = []
    binary_policy_count = 0
    for record in records:
        if record in {"--only-binary :all:", "--only-binary=:all:"}:
            binary_policy_count += 1
            continue
        no_binary_match = re.fullmatch(r"--no-binary(?:=|\s+)([A-Za-z0-9._-]+)", record)
        if no_binary_match:
            package = re.sub(r"[-_.]+", "-", no_binary_match.group(1)).lower()
            observed_sdist.append(package)
            continue
        if record.startswith("-"):
            raise LockError(f"unsupported installer directive in {source}: {record}")
        hashes = _HASH_OPTION_RE.findall(record)
        if not hashes:
            raise LockError(f"unhashed requirement in {source}: {record}")
        without_hashes = _HASH_OPTION_RE.sub(" ", record).strip()
        if "--" in without_hashes:
            raise LockError(f"unsupported installer directive in {source}: {record}")
        reason = _unsafe_requirement_reason(without_hashes)
        if reason:
            raise LockError(f"unsafe locked requirement in {source}: {reason}")
        requirement = without_hashes.split(";", 1)[0].strip()
        if not _PIN_RE.fullmatch(requirement):
            raise LockError(f"locked requirement is not exactly pinned in {source}: {record}")
    if binary_policy_count != 1:
        raise LockError(
            f"lock must contain exactly one '--only-binary :all:' policy in {source}"
        )
    if len(observed_sdist) != len(set(observed_sdist)) or set(observed_sdist) != expected_sdist:
        raise LockError(
            f"lock sdist allowlist mismatch in {source}: "
            f"expected={sorted(expected_sdist)}, observed={sorted(observed_sdist)}"
        )


def _resolver_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith(("PIP_", "UV_")):
            environment.pop(name, None)
    environment.update(
        {
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
            "UV_NO_CONFIG": "true",
        }
    )
    return environment


def _run(
    argv: Sequence[str],
    *,
    root: Path,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv),
            cwd=str(root),
            env=_resolver_environment(),
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise LockError(f"resolver executable was not found: {argv[0]}") from exc
    except (OSError, ValueError) as exc:
        raise LockError(f"resolver could not be executed safely: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        diagnostic = _REDACT_URL_AUTH_RE.sub(r"\1[REDACTED]@", exc.stderr or "")
        diagnostic = diagnostic[-4000:].strip()
        suffix = f": {diagnostic}" if diagnostic else ""
        raise LockError(f"uv failed with exit code {exc.returncode}{suffix}") from exc


def _assert_uv_version(root: Path, uv_executable: str) -> None:
    completed = _run([uv_executable, "--version"], root=root)
    match = re.match(r"^uv\s+([^\s]+)", completed.stdout.strip())
    actual = match.group(1) if match else "unknown"
    if actual != UV_VERSION:
        raise LockError(f"uv=={UV_VERSION} is required; found {actual}")


def _compile_argv(
    uv_executable: str,
    source: Path,
    output: Path,
    target: Target,
    profile: str,
) -> list[str]:
    argv = [
        uv_executable,
        "pip",
        "compile",
        str(source),
        "--output-file",
        str(output),
        "--python-version",
        target.python_version,
        "--python-platform",
        target.python_platform,
        "--generate-hashes",
        "--only-binary",
        ":all:",
    ]
    for package in PROFILE_SDIST_ALLOWLIST[profile]:
        argv.extend(("--no-binary", package))
    argv.extend(
        [
            "--emit-build-options",
            "--no-header",
            "--no-annotate",
        "--index-strategy",
        "first-index",
        "--default-index",
        INDEX_URL,
        "--exclude-newer",
            EPOCH,
        ]
    )
    return argv


def _profile_source(profile: str, inputs: Sequence[str], contents: Mapping[str, str]) -> str:
    sections = [f"# profile: {profile}\n"]
    for relative in inputs:
        sections.append(f"\n# source: {relative}\n")
        sections.append(contents[relative])
        if not contents[relative].endswith("\n"):
            sections.append("\n")
    return "".join(sections)


def _lock_relative_path(target: Target, profile: str) -> str:
    return f"requirements/locks/{target.platform_id}/{target.tag}/{profile}.txt"


def _manifest_document(
    input_hashes: Mapping[str, str],
    locks: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "$schema": "manifest.schema.json",
        "epoch": EPOCH,
        "input_sha256": dict(sorted(input_hashes.items())),
        "locks": list(locks),
        "policy": {
            "allow_direct_references": False,
            "require_hashes": True,
            "sdist_policy": {
                "default": "deny",
                "allowlist_by_profile": {
                    profile: list(packages)
                    for profile, packages in PROFILE_SDIST_ALLOWLIST.items()
                },
            },
        },
        "profiles": {name: list(inputs) for name, inputs in PROFILE_INPUTS.items()},
        "resolver": {"index": INDEX_URL, "name": "uv", "version": UV_VERSION},
        "schema_version": SCHEMA_VERSION,
        "state": "resolved",
        "targets": [target.to_manifest() for target in TARGETS],
    }


def _manifest_bytes(document: Mapping[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def _validate_epoch(root: Path) -> None:
    epoch_path = _safe_relative_file(root, "requirements/locks/EPOCH")
    if epoch_path.read_text(encoding="utf-8") != f"{EPOCH}\n":
        raise LockError(f"requirements/locks/EPOCH must contain exactly {EPOCH}")


def _build_candidate(
    root: Path,
    destination: Path,
    *,
    uv_executable: str,
) -> None:
    _validate_epoch(root)
    contents, input_hashes = _read_and_validate_inputs(root)
    _assert_uv_version(root, uv_executable)
    input_dir = destination / ".inputs"
    input_dir.mkdir(parents=True)
    lock_entries: list[dict[str, Any]] = []

    for target in TARGETS:
        for profile, inputs in PROFILE_INPUTS.items():
            source = input_dir / f"{target.tag}-{profile}.in"
            source.write_text(_profile_source(profile, inputs, contents), encoding="utf-8")
            relative = _lock_relative_path(target, profile)
            output = destination / Path(relative).relative_to("requirements/locks")
            output.parent.mkdir(parents=True, exist_ok=True)
            _run(
                _compile_argv(uv_executable, source, output, target, profile),
                root=root,
            )
            try:
                resolved = output.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise LockError(f"uv did not produce a UTF-8 lock for {relative}") from exc
            resolved = resolved.lstrip("\n")
            if not resolved.endswith("\n"):
                resolved += "\n"
            final = render_lock_header(target=target, profile=profile, inputs=inputs) + resolved
            validate_lock_text(
                final,
                source=relative,
                sdist_allowlist=PROFILE_SDIST_ALLOWLIST[profile],
            )
            output.write_text(final, encoding="utf-8")
            lock_entries.append(
                {
                    "input_sha256": {name: input_hashes[name] for name in inputs},
                    "path": relative,
                    "profile": profile,
                    "sha256": _sha256(output.read_bytes()),
                    "target": target.tag,
                }
            )

    manifest = _manifest_document(input_hashes, lock_entries)
    (destination / "manifest.json").write_bytes(_manifest_bytes(manifest))
    shutil.rmtree(input_dir)


def _copy_candidate(root: Path, candidate: Path) -> None:
    locks_root = root / "requirements" / "locks"
    for target in TARGETS:
        for profile in PROFILE_INPUTS:
            relative = Path(target.platform_id) / target.tag / f"{profile}.txt"
            source = candidate / relative
            destination = locks_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                dir=destination.parent,
                prefix=f".{destination.name}.",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                handle.write(source.read_bytes())
            os.replace(temporary, destination)

    manifest_source = candidate / "manifest.json"
    manifest_destination = locks_root / "manifest.json"
    with tempfile.NamedTemporaryFile(
        dir=locks_root,
        prefix=".manifest.json.",
        delete=False,
    ) as handle:
        temporary_manifest = Path(handle.name)
        handle.write(manifest_source.read_bytes())
    os.replace(temporary_manifest, manifest_destination)


def update_locks(root: Path, *, uv_executable: str = "uv") -> None:
    """Resolve all 24 artifacts, validate them, then replace managed outputs."""

    root = root.resolve()
    with tempfile.TemporaryDirectory(prefix="octopus-lock-update-") as temporary:
        candidate = Path(temporary)
        _build_candidate(root, candidate, uv_executable=uv_executable)
        _copy_candidate(root, candidate)
    validate_locks(root)


def _candidate_files() -> tuple[Path, ...]:
    files = [Path("manifest.json")]
    files.extend(
        Path(target.platform_id) / target.tag / f"{profile}.txt"
        for target in TARGETS
        for profile in PROFILE_INPUTS
    )
    return tuple(files)


def check_locks(root: Path, *, uv_executable: str = "uv") -> None:
    """Re-resolve in a temporary tree and byte-compare without mutation."""

    root = root.resolve()
    with tempfile.TemporaryDirectory(prefix="octopus-lock-check-") as temporary:
        candidate = Path(temporary)
        _build_candidate(root, candidate, uv_executable=uv_executable)
        locks_root = root / "requirements" / "locks"
        changed = [
            str(relative)
            for relative in _candidate_files()
            if not (locks_root / relative).is_file()
            or (locks_root / relative).read_bytes() != (candidate / relative).read_bytes()
        ]
    if changed:
        raise LockError("dependency locks are out of date: " + ", ".join(changed))
    validate_locks(root)


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockError(f"invalid lock manifest: {exc}") from exc
    if not isinstance(document, dict):
        raise LockError("lock manifest must be a JSON object")
    return document


def validate_locks(root: Path) -> None:
    """Offline validation of the manifest, input digests and all lock files."""

    root = root.resolve()
    _validate_epoch(root)
    _, input_hashes = _read_and_validate_inputs(root)
    manifest_path = _safe_relative_file(root, "requirements/locks/manifest.json")
    manifest = _load_manifest(manifest_path)
    if manifest.get("state") != "resolved":
        raise LockError("lock manifest is unresolved; run the authenticated update workflow")
    expected_base = _manifest_document(input_hashes, [])
    for field in (
        "$schema",
        "epoch",
        "input_sha256",
        "policy",
        "profiles",
        "resolver",
        "schema_version",
        "state",
        "targets",
    ):
        if manifest.get(field) != expected_base[field]:
            raise LockError(f"manifest field is invalid or stale: {field}")

    locks = manifest.get("locks")
    if not isinstance(locks, list):
        raise LockError("manifest locks must be a list")
    by_path: dict[str, Mapping[str, Any]] = {}
    for entry in locks:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise LockError("manifest contains an invalid lock entry")
        path = entry["path"]
        if path in by_path:
            raise LockError(f"manifest contains a duplicate lock entry: {path}")
        by_path[path] = entry

    expected_paths = {
        _lock_relative_path(target, profile)
        for target in TARGETS
        for profile in PROFILE_INPUTS
    }
    if set(by_path) != expected_paths:
        missing = sorted(expected_paths - set(by_path))
        unexpected = sorted(set(by_path) - expected_paths)
        raise LockError(f"manifest matrix is incomplete; missing={missing}, unexpected={unexpected}")

    for target in TARGETS:
        for profile, inputs in PROFILE_INPUTS.items():
            relative = _lock_relative_path(target, profile)
            entry = by_path[relative]
            expected_inputs = {name: input_hashes[name] for name in inputs}
            if entry.get("target") != target.tag or entry.get("profile") != profile:
                raise LockError(f"manifest metadata mismatch for {relative}")
            if entry.get("input_sha256") != expected_inputs:
                raise LockError(f"manifest input digest mismatch for {relative}")
            digest = entry.get("sha256")
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                raise LockError(f"manifest lock digest is invalid for {relative}")
            path = _safe_relative_file(root, relative)
            raw = path.read_bytes()
            if _sha256(raw) != digest:
                raise LockError(f"lock digest mismatch for {relative}")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise LockError(f"lock is not UTF-8: {relative}") from exc
            header = render_lock_header(target=target, profile=profile, inputs=inputs)
            if not text.startswith(header):
                raise LockError(f"lock header mismatch for {relative}")
            validate_lock_text(
                text,
                source=relative,
                sdist_allowlist=PROFILE_SDIST_ALLOWLIST[profile],
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("update", "check"):
        child = subparsers.add_parser(command)
        child.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        child.add_argument("--uv", default="uv", help=f"uv=={UV_VERSION} executable")
    validate = subparsers.add_parser("validate")
    validate.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "update":
            update_locks(args.root, uv_executable=args.uv)
        elif args.command == "check":
            check_locks(args.root, uv_executable=args.uv)
        else:
            validate_locks(args.root)
    except LockError as exc:
        print(f"lock validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"dependency lock {args.command} succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
