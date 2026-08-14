#!/usr/bin/env python3
"""Generate or validate the canonical ProviderMountRegistry snapshot."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TypedDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.actions.provider_mounts import (  # noqa: E402
    DefaultProviderMountRegistry,
    get_provider_mount_registry,
)
from core.actions.schema_bindings import get_all_v2_schema_bindings  # noqa: E402


class MountSpecManifest(TypedDict):
    schema_version: str
    action_id: str
    adapter_class: str
    adapter_api_version: int
    provider_owner: str
    provider_transport: str
    execution_mode: str
    readiness_probe_id: str
    configured: bool
    mounted: bool
    typed_action_supported: bool
    raw_command_supported: bool


class MountEntryManifest(TypedDict):
    revision: int
    mount_digest: str
    spec: MountSpecManifest


class MountManifest(TypedDict):
    schema_version: str
    entry_count: int
    entries: list[MountEntryManifest]


def generate_mount_manifest(
    registry: DefaultProviderMountRegistry | None = None,
) -> MountManifest:
    active_registry = registry or get_provider_mount_registry()
    snapshots = active_registry.snapshots()
    for snapshot in snapshots:
        active_registry.assert_current(snapshot)
    entries: list[MountEntryManifest] = [
        {
            "revision": snapshot.revision,
            "mount_digest": snapshot.mount_digest,
            "spec": {
                "schema_version": snapshot.spec.schema_version,
                "action_id": snapshot.spec.action_id,
                "adapter_class": snapshot.spec.adapter_class,
                "adapter_api_version": snapshot.spec.adapter_api_version,
                "provider_owner": snapshot.spec.provider_owner,
                "provider_transport": snapshot.spec.provider_transport.value,
                "execution_mode": snapshot.spec.execution_mode.value,
                "readiness_probe_id": snapshot.spec.readiness_probe_id,
                "configured": snapshot.spec.configured,
                "mounted": snapshot.spec.mounted,
                "typed_action_supported": snapshot.spec.typed_action_supported,
                "raw_command_supported": snapshot.spec.raw_command_supported,
            },
        }
        for snapshot in snapshots
    ]
    manifest = MountManifest(
        schema_version="2.0",
        entry_count=len(entries),
        entries=entries,
    )
    _validate_generated_manifest(manifest)
    return manifest


def _validate_generated_manifest(manifest: MountManifest) -> None:
    entries = manifest["entries"]
    expected_action_ids = {binding.action_id for binding in get_all_v2_schema_bindings()}
    action_ids = {entry["spec"]["action_id"] for entry in entries}
    if len(entries) != 20 or action_ids != expected_action_ids:
        raise ValueError("provider_mount_manifest_must_match_exact_20_v2_identities")
    if any("available" in entry["spec"] for entry in entries):
        raise ValueError("dynamic_readiness_forbidden_in_provider_mount_manifest")
    if len({entry["revision"] for entry in entries}) != len(entries):
        raise ValueError("provider_mount_revisions_must_be_unique")
    if len({entry["mount_digest"] for entry in entries}) != len(entries):
        raise ValueError("provider_mount_digests_must_be_unique")
    if not all(entry["spec"]["configured"] for entry in entries):
        raise ValueError("canonical_v2_provider_must_be_configured")
    if not all(entry["spec"]["typed_action_supported"] for entry in entries):
        raise ValueError("canonical_v2_provider_must_be_typed")
    if any(entry["spec"]["raw_command_supported"] for entry in entries):
        raise ValueError("canonical_v2_provider_must_not_support_raw_commands")


def _canonical_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments not in ([], ["check"], ["generate"]):
        print("usage: provider_mount_gate.py [check|generate]", file=sys.stderr)
        return 2

    manifest_path = PROJECT_ROOT / "quality" / "provider-mounts.json"
    generated = generate_mount_manifest()
    if arguments == ["generate"]:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(_canonical_json(generated), encoding="utf-8")
        print(f"Generated {manifest_path}")
        return 0

    if not manifest_path.exists():
        print(f"Error: generated manifest is missing: {manifest_path}", file=sys.stderr)
        return 1
    try:
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error: cannot read provider mount manifest: {exc}", file=sys.stderr)
        return 1
    if existing != generated:
        print(
            "Error: quality/provider-mounts.json is not the canonical runtime snapshot; "
            "run provider_mount_gate.py generate.",
            file=sys.stderr,
        )
        return 1
    print(
        "Provider mount manifest gate: OK "
        f"({generated['entry_count']} configured, "
        f"{sum(1 for entry in generated['entries'] if entry['spec']['mounted'])} mounted)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
