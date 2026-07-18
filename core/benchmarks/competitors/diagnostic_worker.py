"""Private adapter worker for non-publishable runtime calibration.

The ordinary adapter intentionally discards raw vendor output after hashing it.
This worker is used only by the ignored diagnostic pilot.  It intercepts the
bounded product-process log while the adapter workspace still exists and copies
the exact bytes to an owner-only destination supplied by the pilot controller.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..schema import load_scenario
from . import adapter

_PRODUCT_LOG_ENVIRONMENT = "OCTOBENCH_DIAGNOSTIC_PRODUCT_LOG"


class DiagnosticWorkerError(RuntimeError):
    """The private diagnostic sink is missing or unsafe."""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one product adapter with private diagnostic capture.",
    )
    parser.add_argument("--system", required=True, choices=adapter.SUPPORTED_SYSTEMS)
    parser.add_argument("--scenario", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        product_log = _initialize_private_log(
            os.environ.get(_PRODUCT_LOG_ENVIRONMENT),
        )
        scenario = load_scenario(args.scenario)
        result = _run_with_private_capture(args.system, scenario, product_log)
    except Exception:
        # Unlike the publication adapter, this traceback is intentional: the
        # parent runner captures it only in an ignored owner-only adapter log.
        traceback.print_exc(file=sys.stderr)
        result = adapter._failed_result()
    try:
        adapter._atomic_write_json(args.output, result)
    except OSError:
        return 2
    return 0


def _run_with_private_capture(
    system: str,
    scenario: Any,
    product_log: Path,
) -> dict[str, Any]:
    original = adapter._run_bounded_process

    def capture(*args: Any, **kwargs: Any):
        outcome = original(*args, **kwargs)
        workspace = Path(kwargs["cwd"])
        limit = int(kwargs["max_output"])
        source = workspace / "adapter-stdout.log"
        if source.is_file() and not source.is_symlink():
            with source.open("rb") as raw_log:
                _append_private_bytes(product_log, raw_log.read(limit))
        return outcome

    adapter._run_bounded_process = capture
    try:
        return adapter.run_product_adapter(system, scenario)
    finally:
        adapter._run_bounded_process = original


def _initialize_private_log(value: str | None) -> Path:
    candidate = Path(str(value or ""))
    if not candidate.is_absolute():
        raise DiagnosticWorkerError("private_log_required")
    parent_descriptor: int | None = None
    descriptor: int | None = None
    parent_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        parent_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(candidate.parent, parent_flags)
        parent_metadata = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) & 0o077
        ):
            raise DiagnosticWorkerError("private_log_parent_unsafe")
        descriptor = os.open(
            candidate.name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise DiagnosticWorkerError("private_log_not_regular")
    except DiagnosticWorkerError:
        raise
    except OSError:
        raise DiagnosticWorkerError("private_log_unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    return candidate


def _append_private_bytes(destination: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise DiagnosticWorkerError("private_log_changed")
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise DiagnosticWorkerError("private_log_write_failed")
            written += count
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["DiagnosticWorkerError", "main"]
