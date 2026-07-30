from __future__ import annotations

import io
import os
import runpy
import subprocess
import sys
import tarfile
import types
import zipfile
from pathlib import Path

import pytest

from scripts.quality import wheel_smoke

pytestmark = pytest.mark.contract
ROOT = Path(__file__).resolve().parents[1]
REQUIRED_WHEEL_FILES = {
    "config.yaml",
    "benchmarks/results/noop-repeat-comparison-v1.json",
    "benchmarks/competitors/labs/discovery-lab-v3/Dockerfile",
    "benchmarks/competitors/labs/discovery-lab-v3/Dockerfile.dockerignore",
    "benchmarks/competitors/labs/discovery-lab-v3/app.py",
    "benchmarks/competitors/labs/discovery-lab-v3/compose.yaml",
    "core/benchmarks/v3/fixture.py",
    "core/benchmarks/v3/publication.py",
}


def _wheel_names(*, scenarios: int = 10, missing: str | None = None) -> set[str]:
    names = set(REQUIRED_WHEEL_FILES)
    if missing is not None:
        names.remove(missing)
    names.update(f"benchmarks/scenarios/{index:02d}.json" for index in range(scenarios))
    names.update(
        {
            "benchmarks/scenarios/not-json.txt",
            "elsewhere/not-a-scenario.json",
        }
    )
    return names


def _write_wheel(path: Path, names: set[str]) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        for name in sorted(names):
            archive.writestr(name, "{}")


def _write_sdist(path: Path, names: tuple[str, ...]) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for name in names:
            payload = b"content"
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def _patch_wheel_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    os_name: str = "posix",
    config_output: str = "config.yaml\n",
    version_output: str = "octopus 1.1.0\n",
    help_output: str = "usage: command\n",
    output_count: int = 11,
) -> tuple[list[list[str]], list[tuple[Path, str, Path]]]:
    calls: list[list[str]] = []
    c2_checks: list[tuple[Path, str, Path]] = []
    os_proxy = types.SimpleNamespace(name=os_name, environ=os.environ)
    monkeypatch.setattr(wheel_smoke, "os", os_proxy)

    class FakeBuilder:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs == {"with_pip": True, "system_site_packages": True}

        def create(self, environment: Path) -> None:
            scripts = environment / ("Scripts" if os_name == "nt" else "bin")
            scripts.mkdir(parents=True)

    monkeypatch.setattr(wheel_smoke.venv, "EnvBuilder", FakeBuilder)

    def fake_run(argv: list[str], *, cwd: Path, require_empty_stderr: bool = False) -> str:
        calls.append(list(argv))
        assert isinstance(cwd, Path)
        if "-c" in argv:
            code = argv[argv.index("-c") + 1]
            if "find_spec('config')" in code:
                return config_output
            if "sysconfig.get_path('purelib')" in code:
                return "/isolated/purelib\n"
        if "--version" in argv:
            return version_output
        if "--help" in argv:
            return help_output
        executable = Path(argv[0]).name
        if executable in {"octobench", "octobench.exe"} and len(argv) == 1:
            output = cwd / "octobench-results"
            output.mkdir()
            for index in range(output_count):
                (output / f"{index}.json").write_text("{}", encoding="utf-8")
        return ""

    monkeypatch.setattr(wheel_smoke, "_run", fake_run)
    monkeypatch.setattr(
        wheel_smoke,
        "_validate_missing_c2_extra",
        lambda *, python, purelib, cwd: c2_checks.append((python, purelib, cwd)),
    )
    return calls, c2_checks


@pytest.mark.parametrize(
    ("os_name", "python_name", "command_name"),
    (("posix", "python", "octopus"), ("nt", "python.exe", "octopus.exe")),
)
def test_validate_wheel_accepts_complete_archive_on_both_script_layouts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    os_name: str,
    python_name: str,
    command_name: str,
) -> None:
    wheel = tmp_path / "complete.whl"
    names = _wheel_names()
    _write_wheel(wheel, names)
    calls, c2_checks = _patch_wheel_runtime(monkeypatch, os_name=os_name)

    assert wheel_smoke.validate_wheel(wheel) == {"files": len(names), "scenarios": 10}
    assert any(Path(call[0]).name == python_name for call in calls)
    assert any(Path(call[0]).name == command_name and "--help" in call for call in calls)
    assert len(c2_checks) == 1
    assert c2_checks[0][0].name == python_name
    assert c2_checks[0][1] == "/isolated/purelib"


@pytest.mark.parametrize(
    ("scenarios", "missing", "expected"),
    (
        (9, None, "scenario_count=9"),
        (10, "config.yaml", "config.yaml"),
    ),
)
def test_validate_wheel_rejects_incomplete_data(
    tmp_path: Path,
    scenarios: int,
    missing: str | None,
    expected: str,
) -> None:
    wheel = tmp_path / "incomplete.whl"
    _write_wheel(wheel, _wheel_names(scenarios=scenarios, missing=missing))

    with pytest.raises(wheel_smoke.WheelSmokeError, match="wheel_data_missing") as raised:
        wheel_smoke.validate_wheel(wheel)

    assert expected in str(raised.value)


@pytest.mark.parametrize(
    ("runtime_options", "expected"),
    (
        ({"config_output": "wrong\n"}, "installed_config_not_adjacent"),
        ({"version_output": "octopus dev\n"}, "installed_version_output_not_clean"),
        ({"help_output": "commands only\n"}, "installed_help_output_not_clean:octopus"),
        ({"help_output": "usage: command [!]\n"}, "installed_help_output_not_clean:octopus"),
        ({"help_output": "usage: command Warning\n"}, "installed_help_output_not_clean:octopus"),
        ({"output_count": 10}, "installed_octobench_output_count:10"),
    ),
)
def test_validate_wheel_rejects_unclean_installed_behavior(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_options: dict[str, object],
    expected: str,
) -> None:
    wheel = tmp_path / "complete.whl"
    _write_wheel(wheel, _wheel_names())
    _patch_wheel_runtime(monkeypatch, **runtime_options)

    with pytest.raises(wheel_smoke.WheelSmokeError, match=expected):
        wheel_smoke.validate_wheel(wheel)


def test_validate_sdist_requires_one_top_level_config(tmp_path: Path) -> None:
    valid = tmp_path / "valid.tar.gz"
    valid_names = (
        "octopus-1.1.0/config.yaml",
        "octopus-1.1.0/not-config.yaml",
        "octopus-1.1.0/nested/config.yaml",
    )
    _write_sdist(valid, valid_names)
    assert wheel_smoke.validate_sdist(valid) == {"files": 3, "configs": 1}

    missing = tmp_path / "missing.tar.gz"
    _write_sdist(missing, ("octopus-1.1.0/not-config.yaml",))
    with pytest.raises(wheel_smoke.WheelSmokeError, match="sdist_config_count:0"):
        wheel_smoke.validate_sdist(missing)

    duplicate = tmp_path / "duplicate.tar.gz"
    _write_sdist(
        duplicate,
        ("octopus-1.1.0/config.yaml", "octopus-1.1.0-copy/config.yaml"),
    )
    with pytest.raises(wheel_smoke.WheelSmokeError, match="sdist_config_count:2"):
        wheel_smoke.validate_sdist(duplicate)


def _completed(
    *,
    returncode: int = 2,
    stdout: str = "",
    stderr: str = "octopus-security[c2] missing fastapi and uvicorn",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


def test_missing_c2_extra_validation_sanitizes_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setenv("PYTHONHOME", "/unsafe/home")
    monkeypatch.setenv("PYTHONPATH", "/unsafe/path")
    monkeypatch.setenv("OCTOPUS_WHEEL_TEST", "kept")

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append({"argv": argv, **kwargs})
        return _completed()

    monkeypatch.setattr(wheel_smoke.subprocess, "run", fake_run)
    wheel_smoke._validate_missing_c2_extra(
        python=tmp_path / "python",
        purelib="/purelib",
        cwd=tmp_path,
    )

    assert captured[0]["argv"][-1] == "/purelib"
    environment = captured[0]["env"]
    assert isinstance(environment, dict)
    assert "PYTHONHOME" not in environment
    assert "PYTHONPATH" not in environment
    assert environment["OCTOPUS_WHEEL_TEST"] == "kept"
    assert captured[0]["check"] is False
    assert captured[0]["timeout"] == 120


@pytest.mark.parametrize(
    "completed",
    (
        _completed(returncode=1),
        _completed(stdout="unexpected output"),
        _completed(stderr="fastapi uvicorn"),
        _completed(stderr="octopus-security[c2] uvicorn"),
        _completed(stderr="octopus-security[c2] fastapi"),
        _completed(stderr="octopus-security[c2] fastapi uvicorn Traceback"),
    ),
)
def test_missing_c2_extra_validation_rejects_each_unclean_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    completed: subprocess.CompletedProcess[str],
) -> None:
    monkeypatch.setattr(wheel_smoke.subprocess, "run", lambda *_args, **_kwargs: completed)

    with pytest.raises(
        wheel_smoke.WheelSmokeError,
        match="installed_missing_extra_output_not_clean:octopus-c2",
    ):
        wheel_smoke._validate_missing_c2_extra(
            python=tmp_path / "python",
            purelib="/purelib",
            cwd=tmp_path,
        )


def test_missing_c2_extra_wraps_process_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        wheel_smoke.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cannot execute")),
    )

    with pytest.raises(wheel_smoke.WheelSmokeError, match="installed_command_failed:octopus-c2"):
        wheel_smoke._validate_missing_c2_extra(
            python=tmp_path / "python",
            purelib="/purelib",
            cwd=tmp_path,
        )


@pytest.mark.parametrize(
    ("require_empty_stderr", "stderr", "raises"),
    ((False, "warning", False), (True, "", False), (True, "warning", True)),
)
def test_run_enforces_optional_stderr_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    require_empty_stderr: bool,
    stderr: str,
    raises: bool,
) -> None:
    captured: list[dict[str, object]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append({"argv": argv, **kwargs})
        return subprocess.CompletedProcess(argv, 0, stdout="output", stderr=stderr)

    monkeypatch.setattr(wheel_smoke.subprocess, "run", fake_run)
    if raises:
        with pytest.raises(wheel_smoke.WheelSmokeError, match="installed_command_stderr_not_clean:tool"):
            wheel_smoke._run(("/bin/tool", "--help"), cwd=tmp_path, require_empty_stderr=True)
    else:
        assert (
            wheel_smoke._run(
                ("/bin/tool", "--help"),
                cwd=tmp_path,
                require_empty_stderr=require_empty_stderr,
            )
            == "output"
        )
    assert captured[0]["argv"] == ["/bin/tool", "--help"]
    assert captured[0]["check"] is True
    assert captured[0]["stdin"] is subprocess.DEVNULL


def test_run_wraps_process_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        wheel_smoke.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.SubprocessError("failed")),
    )

    with pytest.raises(wheel_smoke.WheelSmokeError, match="installed_command_failed:tool"):
        wheel_smoke._run(("/bin/tool",), cwd=tmp_path)


def test_main_reports_success_with_and_without_sdist(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(wheel_smoke, "validate_wheel", lambda _path: {"files": 42, "scenarios": 10})
    monkeypatch.setattr(wheel_smoke, "validate_sdist", lambda _path: {"files": 51, "configs": 1})

    assert wheel_smoke.main(["package.whl"]) == 0
    assert capsys.readouterr().out == "wheel smoke passed: 42 files, 10 scenarios\n"

    assert wheel_smoke.main(["package.whl", "--sdist", "package.tar.gz"]) == 0
    assert capsys.readouterr().out == ("wheel smoke passed: 42 files, 10 scenarios, sdist 51 files\n")


def test_main_reports_validation_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_path: Path) -> dict[str, int]:
        raise wheel_smoke.WheelSmokeError("broken archive")

    monkeypatch.setattr(wheel_smoke, "validate_wheel", fail)
    assert wheel_smoke.main(["package.whl"]) == 1
    assert capsys.readouterr().err == "wheel smoke failed: broken archive\n"


def test_wheel_smoke_script_exits_nonzero_for_missing_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["wheel_smoke.py", str(tmp_path / "missing.whl")])

    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(ROOT / "scripts" / "quality" / "wheel_smoke.py"), run_name="__main__")

    assert raised.value.code == 1
    assert "wheel smoke failed:" in capsys.readouterr().err
