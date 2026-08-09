#!/usr/bin/env python3
"""Verify installed-wheel data files and console entry points in isolation."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from collections.abc import Sequence
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath


class WheelSmokeError(RuntimeError):
    """The built distribution is incomplete or cannot run after installation."""


_REQUIRED_WHEEL_RESOURCES = {
    "core/c2/go.mod",
    "core/c2/go.sum",
    "core/c2/implant.go",
    "core/c2/toolchain.json",
}
_REQUIRED_SDIST_RESOURCES = {
    *_REQUIRED_WHEEL_RESOURCES,
    "core/opsec/ja3_client.go",
}
_FORBIDDEN_WHEEL_RESOURCES = {
    "core/opsec/ja3_client.go",
}
_SYSTEMD_RESOURCE_SUFFIX = ".data/data/share/octopus-security/systemd/octopus-c2.service"


def _canonical_project_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _wheel_version(archive: zipfile.ZipFile, names: set[str]) -> str:
    metadata_files = {
        name
        for name in names
        if len(PurePosixPath(name).parts) == 2
        and PurePosixPath(name).parts[0].endswith(".dist-info")
        and PurePosixPath(name).name == "METADATA"
    }
    if len(metadata_files) != 1:
        raise WheelSmokeError(f"wheel_metadata_count:{len(metadata_files)}")

    metadata = BytesParser(policy=policy.default).parsebytes(archive.read(next(iter(metadata_files))))
    project_name = str(metadata.get("Name", "")).strip()
    version = str(metadata.get("Version", "")).strip()
    if _canonical_project_name(project_name) != "octopus-security":
        raise WheelSmokeError(f"wheel_metadata_project_invalid:{project_name or 'missing'}")
    if not version or "\n" in version or "\r" in version:
        raise WheelSmokeError("wheel_metadata_version_invalid")
    return version


def validate_wheel(path: str | Path) -> dict[str, int]:
    wheel = Path(path).resolve(strict=True)
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        wheel_version = _wheel_version(archive, names)
    scenarios = {name for name in names if name.startswith("benchmarks/scenarios/") and name.endswith(".json")}
    required = {
        "config.yaml",
        "benchmarks/results/noop-repeat-comparison-v1.json",
        "benchmarks/competitors/labs/discovery-lab-v3/Dockerfile",
        "benchmarks/competitors/labs/discovery-lab-v3/Dockerfile.dockerignore",
        "benchmarks/competitors/labs/discovery-lab-v3/app.py",
        "benchmarks/competitors/labs/discovery-lab-v3/compose.yaml",
        "core/benchmarks/v3/fixture.py",
        "core/benchmarks/v3/publication.py",
        *_REQUIRED_WHEEL_RESOURCES,
    }
    missing = required - names
    forbidden = _FORBIDDEN_WHEEL_RESOURCES & names
    if forbidden:
        raise WheelSmokeError("wheel_data_forbidden:" + ",".join(sorted(forbidden)))
    service_files = {name for name in names if name.endswith(_SYSTEMD_RESOURCE_SUFFIX)}
    if len(service_files) != 1:
        missing.add(f"systemd_service_count={len(service_files)}")
    if len(scenarios) != 10 or missing:
        raise WheelSmokeError("wheel_data_missing:" + ",".join(sorted({*missing, f"scenario_count={len(scenarios)}"})))

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
        config_output = _run(
            [
                str(python),
                "-c",
                (
                    "import importlib.util, pathlib; "
                    "spec = importlib.util.find_spec('config'); "
                    "assert spec is not None and spec.origin is not None; "
                    "path = pathlib.Path(spec.origin).with_name('config.yaml'); "
                    "assert path.is_file(); "
                    "print(path.name)"
                ),
            ],
            cwd=root,
            require_empty_stderr=True,
        )
        if config_output != "config.yaml\n":
            raise WheelSmokeError("installed_config_not_adjacent")
        transport_output = _run(
            [
                str(python),
                "-c",
                (
                    "import os\n"
                    "os.environ.pop('OCTOPUS_GO_TLS_BINARY', None)\n"
                    "from core.opsec.network import OpsecClient\n"
                    "client = OpsecClient()\n"
                    "assert type(client.transport).__name__ == 'PythonTransport'\n"
                    "try:\n    OpsecClient(use_go_tls=True)\n"
                    "except RuntimeError as exc:\n    assert 'OCTOPUS_GO_TLS_BINARY' in str(exc)\n"
                    "else:\n    raise AssertionError('Go TLS opt-in did not fail closed')\n"
                    "print(type(client.transport).__name__)"
                ),
            ],
            cwd=root,
            require_empty_stderr=True,
        )
        if transport_output != "PythonTransport\n":
            raise WheelSmokeError("installed_opsec_default_not_portable")
        purelib = _run(
            [
                str(python),
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ],
            cwd=root,
            require_empty_stderr=True,
        ).strip()
        _validate_missing_c2_extra(python=python, purelib=purelib, cwd=root)
        version_output = _run(
            [str(scripts / "octopus"), "--version"],
            cwd=root,
            require_empty_stderr=True,
        )
        if version_output != f"octopus {wheel_version}\n":
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


def validate_sdist(path: str | Path) -> dict[str, int]:
    sdist = Path(path).resolve(strict=True)
    with tarfile.open(sdist, mode="r:gz") as archive:
        names = set(archive.getnames())
    config_files = {
        name for name in names if len(PurePosixPath(name).parts) == 2 and PurePosixPath(name).name == "config.yaml"
    }
    if len(config_files) != 1:
        raise WheelSmokeError(f"sdist_config_count:{len(config_files)}")
    relative_names = {
        str(PurePosixPath(*PurePosixPath(name).parts[1:])) for name in names if len(PurePosixPath(name).parts) > 1
    }
    required = {
        "config.yaml",
        "data/octopus-c2.service",
        *_REQUIRED_SDIST_RESOURCES,
    }
    missing = required - relative_names
    if missing:
        raise WheelSmokeError("sdist_data_missing:" + ",".join(sorted(missing)))
    return {"files": len(names), "configs": len(config_files)}


def _validate_missing_c2_extra(*, python: Path, purelib: str, cwd: Path) -> None:
    try:
        completed = subprocess.run(
            [
                str(python),
                "-S",
                "-c",
                ("import sys; sys.path.insert(0, sys.argv[1]); import octopus_c2; raise SystemExit(octopus_c2.main())"),
                purelib,
            ],
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            env={key: value for key, value in os.environ.items() if key not in {"PYTHONHOME", "PYTHONPATH"}},
            timeout=120,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WheelSmokeError("installed_command_failed:octopus-c2") from exc
    if (
        completed.returncode != 2
        or completed.stdout
        or "octopus-security[c2]" not in completed.stderr
        or "fastapi" not in completed.stderr
        or "uvicorn" not in completed.stderr
        or "Traceback" in completed.stderr
    ):
        raise WheelSmokeError("installed_missing_extra_output_not_clean:octopus-c2")


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
            env={key: value for key, value in os.environ.items() if key not in {"PYTHONHOME", "PYTHONPATH"}},
            timeout=120,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WheelSmokeError(f"installed_command_failed:{Path(argv[0]).name}") from exc
    if require_empty_stderr and completed.stderr:
        raise WheelSmokeError(f"installed_command_stderr_not_clean:{Path(argv[0]).name}")
    return completed.stdout


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_wheel(args.wheel)
        sdist_result = validate_sdist(args.sdist) if args.sdist else None
    except (OSError, WheelSmokeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"wheel smoke failed: {exc}", file=sys.stderr)
        return 1
    summary = f"wheel smoke passed: {result['files']} files, {result['scenarios']} scenarios"
    if sdist_result:
        summary += f", sdist {sdist_result['files']} files"
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
