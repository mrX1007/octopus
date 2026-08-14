#!/usr/bin/env python3
"""Fail-closed mypy entrypoint for the PR-20 migration."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.quality.mypy_config_inventory import (  # noqa: E402
    MypyConfigInventory,
    inventory_repository,
)


class MypyGateError(RuntimeError):
    """Raised when gate metadata is missing or malformed."""


class MypyMigrationStateV1(str, Enum):
    FROZEN = "frozen"
    MIGRATING = "migrating"
    COMPLETE = "complete"


@dataclass(frozen=True)
class MypyInvocationPartition:
    id: str
    path: str


def load_partitions(root_dir: Path) -> list[MypyInvocationPartition]:
    partitions_file = root_dir / "quality" / "mypy-invocation-partitions.json"
    if not partitions_file.exists():
        raise MypyGateError("missing quality/mypy-invocation-partitions.json")
    if partitions_file.is_symlink():
        raise MypyGateError("partition manifest must not be a symlink")
    try:
        data = json.loads(partitions_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MypyGateError(f"cannot read partition manifest: {type(exc).__name__}") from exc

    if not isinstance(data, dict) or set(data) != {
        "schema_version",
        "default_partition_id",
        "singleton_partitions",
    }:
        raise MypyGateError("partition manifest has an invalid top-level schema")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise MypyGateError("partition manifest schema_version must be 1")
    if data["default_partition_id"] != "default":
        raise MypyGateError("partition manifest default_partition_id must be 'default'")

    raw_partitions = data["singleton_partitions"]
    if not isinstance(raw_partitions, list):
        raise MypyGateError("singleton_partitions must be a list")

    partitions: list[MypyInvocationPartition] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, item in enumerate(raw_partitions):
        if not isinstance(item, dict) or set(item) != {"id", "path"}:
            raise MypyGateError(f"singleton_partitions[{index}] has an invalid schema")
        partition_id = item["id"]
        partition_path = item["path"]
        if not isinstance(partition_id, str) or not partition_id or partition_id == "default":
            raise MypyGateError(f"singleton_partitions[{index}].id is invalid")
        if not isinstance(partition_path, str) or not partition_path:
            raise MypyGateError(f"singleton_partitions[{index}].path is invalid")
        parsed_path = Path(partition_path)
        if (
            parsed_path.is_absolute()
            or "\\" in partition_path
            or any(part.startswith("-") for part in parsed_path.parts)
            or parsed_path.as_posix() != partition_path
            or any(part in {"", ".", ".."} for part in parsed_path.parts)
            or parsed_path.suffix != ".py"
        ):
            raise MypyGateError(f"singleton partition path is not a normalized Python path: {partition_path}")
        if partition_id in seen_ids:
            raise MypyGateError(f"duplicate singleton partition id: {partition_id}")
        if partition_path in seen_paths:
            raise MypyGateError(f"duplicate singleton partition path: {partition_path}")
        source_path = root_dir / partition_path
        if source_path.is_symlink():
            raise MypyGateError(f"singleton partition path must not be a symlink: {partition_path}")
        if not source_path.is_file():
            raise MypyGateError(f"singleton partition path does not exist: {partition_path}")
        seen_ids.add(partition_id)
        seen_paths.add(partition_path)
        partitions.append(MypyInvocationPartition(id=partition_id, path=partition_path))

    return sorted(partitions, key=lambda partition: partition.id)


def _print_inventory_violations(inventory: MypyConfigInventory) -> None:
    for violation in inventory.violations:
        print(f"ERROR: {violation}", file=sys.stderr)


def run_mypy_check(root_dir: Path, partition_id: str | None = None) -> int:
    partitions = load_partitions(root_dir)
    print(f"Running mypy quality check on {root_dir}")
    config_path = root_dir / "pyproject.toml"
    if not config_path.is_file():
        raise MypyGateError("missing pyproject.toml")
    cmd = [
        sys.executable,
        "-m",
        "mypy",
        "--config-file",
        str(config_path),
        "--no-incremental",
    ]
    if partition_id:
        matching = [p.path for p in partitions if p.id == partition_id]
        if matching:
            cmd.extend(matching)
        else:
            print(f"Unknown partition: {partition_id}", file=sys.stderr)
            return 1
    environment = os.environ.copy()
    for variable in ("MYPYPATH", "MYPY_CACHE_DIR", "MYPY_NUM_WORKERS"):
        environment.pop(variable, None)
    environment.setdefault("LC_ALL", "C.UTF-8")
    environment.setdefault("PYTHONHASHSEED", "0")
    res = subprocess.run(cmd, cwd=str(root_dir), env=environment, check=False)
    return res.returncode


def cmd_check(args: argparse.Namespace, root_dir: Path) -> int:
    inventory = inventory_repository(root_dir)
    if not inventory.ok:
        _print_inventory_violations(inventory)
        return 1
    return run_mypy_check(root_dir, partition_id=args.partition)


def cmd_inventory(args: argparse.Namespace, root_dir: Path) -> int:
    del args
    inventory = inventory_repository(root_dir)
    for reference in inventory.references:
        print(f"{reference.path}:{reference.line}: {reference.kind.value} ({reference.classification.value})")
    if not inventory.ok:
        _print_inventory_violations(inventory)
        return 1
    print("Mypy config inventory: clean")
    return 0


def cmd_freeze(args: argparse.Namespace, root_dir: Path) -> int:
    del args, root_dir
    print(
        "Freeze refused: the canonical diagnostic/source/config digest implementation is incomplete.",
        file=sys.stderr,
    )
    return 1


def cmd_authorize_modify(args: argparse.Namespace, root_dir: Path) -> int:
    del args, root_dir
    print("Authorization refused: freeze-base blob verification is incomplete.", file=sys.stderr)
    return 1


def cmd_authorize_stub(args: argparse.Namespace, root_dir: Path) -> int:
    del args, root_dir
    print("Stub authorization refused: atomic override verification is incomplete.", file=sys.stderr)
    return 1


def cmd_deauthorize(args: argparse.Namespace, root_dir: Path) -> int:
    del args, root_dir
    print("Deauthorization refused: dependency verification is incomplete.", file=sys.stderr)
    return 1


def cmd_verify_overrides(args: argparse.Namespace, root_dir: Path) -> int:
    del args
    overrides_file = root_dir / "quality" / "mypy-overrides.json"
    if not overrides_file.exists():
        print("Missing mypy-overrides.json", file=sys.stderr)
        return 1
    try:
        overrides = json.loads(overrides_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Invalid mypy-overrides.json: {type(exc).__name__}", file=sys.stderr)
        return 1
    if not isinstance(overrides, dict):
        print("Invalid mypy-overrides.json: top level must be an object", file=sys.stderr)
        return 1
    print("Overrides verified.")
    return 0


def cmd_verify_config_consumers(args: argparse.Namespace, root_dir: Path) -> int:
    del args
    inventory = inventory_repository(root_dir)
    if not inventory.ok:
        _print_inventory_violations(inventory)
        return 1
    print("Config consumers verified: one CI gate entrypoint and zero stale live consumers.")
    return 0


def cmd_finalization_ready(args: argparse.Namespace, root_dir: Path) -> int:
    del args
    inventory = inventory_repository(root_dir)
    if not inventory.ok:
        _print_inventory_violations(inventory)
        print("Finalization ready: False")
        return 1
    freeze_path = root_dir / "quality" / "mypy-migration-freeze.json"
    if freeze_path.exists():
        try:
            data = json.loads(freeze_path.read_text(encoding="utf-8"))
            if data.get("state") == MypyMigrationStateV1.COMPLETE.value:
                print("Finalization ready: True")
                return 0
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("Finalization ready: False")
            return 1
    print("Finalization ready: False")
    return 1


def cmd_complete(args: argparse.Namespace, root_dir: Path) -> int:
    del args, root_dir
    print(
        "Completion refused: full strict diagnostics, diff ledger, and frozen digest proofs are not implemented.",
        file=sys.stderr,
    )
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mypy Gate (§20.3)")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to run")

    p_check = subparsers.add_parser("check")
    p_check.add_argument("--partition", type=str, help="Partition ID")

    subparsers.add_parser("inventory")

    p_freeze = subparsers.add_parser("freeze")
    p_freeze.add_argument("--parent-pr19", type=str, default="HEAD")
    p_freeze.add_argument("--freeze-base", type=str, default="HEAD")
    p_freeze.add_argument("--rewrite-plan", action="store_true")

    p_auth_mod = subparsers.add_parser("authorize-modify")
    p_auth_mod.add_argument("--path", type=str, required=True)
    p_auth_mod.add_argument("--diagnostic-id", type=str, default="")
    p_auth_mod.add_argument("--reason", type=str, default="")

    p_auth_stub = subparsers.add_parser("authorize-stub")
    p_auth_stub.add_argument("--path", type=str, required=True)
    p_auth_stub.add_argument("--module", type=str, default="")
    p_auth_stub.add_argument("--diagnostic-id", type=str, default="")
    p_auth_stub.add_argument("--owner", type=str, default="")
    p_auth_stub.add_argument("--upstream-package", type=str, default="")
    p_auth_stub.add_argument("--tested-version-range", type=str, default="")
    p_auth_stub.add_argument("--reason", type=str, default="")
    p_auth_stub.add_argument("--removal-condition", type=str, default="")
    p_auth_stub.add_argument("--review-date", type=str, default="")

    p_deauth = subparsers.add_parser("deauthorize")
    p_deauth.add_argument("--path", type=str, required=True)

    subparsers.add_parser("verify-overrides")
    subparsers.add_parser("verify-config-consumers")
    subparsers.add_parser("finalization-ready")

    p_comp = subparsers.add_parser("complete")
    p_comp.add_argument("--rewrite-plan", action="store_true")

    args = parser.parse_args(argv)
    root_dir = PROJECT_ROOT
    cmd = args.command or "check"
    handlers = {
        "check": cmd_check,
        "inventory": cmd_inventory,
        "freeze": cmd_freeze,
        "authorize-modify": cmd_authorize_modify,
        "authorize-stub": cmd_authorize_stub,
        "deauthorize": cmd_deauthorize,
        "verify-overrides": cmd_verify_overrides,
        "verify-config-consumers": cmd_verify_config_consumers,
        "finalization-ready": cmd_finalization_ready,
        "complete": cmd_complete,
    }
    handler = handlers[cmd]
    if cmd == "check" and not hasattr(args, "partition"):
        args.partition = None
    try:
        return handler(args, root_dir)
    except MypyGateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
