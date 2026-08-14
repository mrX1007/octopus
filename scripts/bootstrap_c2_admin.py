#!/usr/bin/env python3
"""Root-only offline bootstrap for the first C2 administrator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.c2.bootstrap import (  # noqa: E402
    DEFAULT_BOOTSTRAP_KEY_PATH,
    bootstrap_admin_operator,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline root-only bootstrap of the first Octopus C2 administrator"
    )
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--client-uid", type=int, required=True)
    parser.add_argument("--client-gid", type=int, required=True)
    parser.add_argument("--name", default="bootstrap-admin")
    parser.add_argument("--key-path", type=Path, default=DEFAULT_BOOTSTRAP_KEY_PATH)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = bootstrap_admin_operator(
            db_path=args.db_path,
            client_uid=args.client_uid,
            client_gid=args.client_gid,
            name=args.name,
            key_path=args.key_path,
        )
    except Exception as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return 1
    # Only non-secret identifiers and the already-known destination are shown.
    print(
        f"first administrator {result.admin_id} committed; key published to {result.key_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
