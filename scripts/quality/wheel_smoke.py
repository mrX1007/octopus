#!/usr/bin/env python3
"""Verify installed-wheel data files and console entry points in isolation."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import venv
import zipfile
from collections.abc import Sequence
from pathlib import Path


class WheelSmokeError(RuntimeError):
    """The built distribution is incomplete or cannot run after installation."""


def validate_wheel(path: str | Path) -> dict[str, int]:
    wheel = Path(path).resolve(strict=True)
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    scenarios = {
        name
        for name in names
        if name.startswith("benchmarks/scenarios/") and name.endswith(".json")
    }
    required = {
        "benchmarks/results/noop-repeat-comparison-v1.json",
        "benchmarks/competitors/labs/discovery-lab-v3/Dockerfile",
        "benchmarks/competitors/labs/discovery-lab-v3/Dockerfile.dockerignore",
        "benchmarks/competitors/labs/discovery-lab-v3/app.py",
        "benchmarks/competitors/labs/discovery-lab-v3/compose.yaml",
        "core/benchmarks/v3/fixture.py",
        "core/benchmarks/v3/publication.py",
    }
    missing = required - names
    if len(scenarios) != 10 or missing:
        raise WheelSmokeError(
            "wheel_data_missing:"
            + ",".join(sorted({*missing, f"scenario_count={len(scenarios)}"}))
        )

    with tempfile.TemporaryDirectory(prefix="octopus-wheel-smoke-") as temporary:
        root = Path(temporary)
        environment = root / "environment"
        venv.EnvBuilder(
            with_pip=True,
            system_site_packages=True,
        ).create(environment)
        scripts = environment / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        _run(
            [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
            cwd=root,
        )
        version_output = _run(
            [str(scripts / "octopus"), "--version"],
            cwd=root,
            require_empty_stderr=True,
        )
        if version_output != "octopus 1.1.0\n":
            raise WheelSmokeError("installed_version_output_not_clean")
        for command in ("octopus", "octobench", "octobench-competitors"):
            executable = scripts / (f"{command}.exe" if os.name == "nt" else command)
            help_output = _run(
                [str(executable), "--help"],
                cwd=root,
                require_empty_stderr=True,
            )
            if "usage:" not in help_output or "[!]" in help_output or "Warning" in help_output:
                raise WheelSmokeError(f"installed_help_output_not_clean:{command}")
        _run(
            [str(scripts / "octobench")],
            cwd=root,
            require_empty_stderr=True,
        )
        outputs = tuple((root / "octobench-results").rglob("*.json"))
        if len(outputs) != 11:
            raise WheelSmokeError(f"installed_octobench_output_count:{len(outputs)}")
    return {"files": len(names), "scenarios": len(scenarios)}


def _run(
    argv: Sequence[str],
    *,
    cwd: Path,
    require_empty_stderr: bool = False,
) -> str:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            timeout=120,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WheelSmokeError(f"installed_command_failed:{Path(argv[0]).name}") from exc
    if require_empty_stderr and completed.stderr:
        raise WheelSmokeError(
            f"installed_command_stderr_not_clean:{Path(argv[0]).name}"
        )
    return completed.stdout


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_wheel(args.wheel)
    except (OSError, WheelSmokeError, zipfile.BadZipFile) as exc:
        print(f"wheel smoke failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"wheel smoke passed: {result['files']} files, "
        f"{result['scenarios']} scenarios"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
