#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM from an exact requirement lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import quote

_PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?==(?P<version>[^\s;]+)")
_HASH = re.compile(r"--hash=sha256:([0-9a-fA-F]{64})")


class SbomError(RuntimeError):
    """The lock cannot be represented as a deterministic SBOM."""


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


def build_sbom(lock_path: Path) -> dict:
    """Return one CycloneDX 1.5 document for a hash-pinned lock."""

    try:
        text = lock_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SbomError(f"cannot read lock: {type(exc).__name__}") from exc
    components: list[dict] = []
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
    components.sort(key=lambda item: (item["name"], item["version"]))
    canonical = json.dumps(components, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "components": components,
        "serialNumber": f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}",
        "specVersion": "1.5",
        "version": 1,
    }


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        payload = build_sbom(args.lock)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, SbomError) as exc:
        print(f"SBOM generation failed: {exc}", file=sys.stderr)
        return 1
    print(f"SBOM generated: {len(payload['components'])} components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
