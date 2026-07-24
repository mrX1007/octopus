"""Hermetic contract tests for deterministic dependency locks."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from scripts import lock_requirements

pytestmark = pytest.mark.unit


_HASH = "a" * 64


def _write_inputs(root: Path) -> None:
    requirements = root / "requirements"
    requirements.mkdir(parents=True)
    locks = requirements / "locks"
    locks.mkdir()
    (locks / "EPOCH").write_text(
        f"{lock_requirements.EPOCH}\n",
        encoding="utf-8",
    )
    contents = {
        "runtime.txt": "demo-runtime>=1.0\n",
        "c2.txt": "demo-c2>=1.0\n",
        "reporting.txt": "demo-reporting>=1.0\n",
        "osint-browser.txt": "demo-osint>=1.0\nshodan>=1.0\n",
        "dev.txt": "demo-dev>=1.0\n",
        "mysql.txt": "demo-mysql>=1.0\n",
        "external-tools.txt": "demo-external>=1.0\n",
        "platform.txt": "# Deliberately empty platform profile.\n",
    }
    for filename, content in contents.items():
        (requirements / filename).write_text(content, encoding="utf-8")


def _fake_uv(calls: list[dict[str, Any]]):
    def run(
        argv: Sequence[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        calls.append({"argv": argv, "kwargs": kwargs})
        assert isinstance(argv, list)
        assert kwargs.get("shell") in (None, False)
        if list(argv[1:]) == ["--version"]:
            return subprocess.CompletedProcess(argv, 0, "uv 0.11.28\n", "")

        output = Path(argv[argv.index("--output-file") + 1])
        no_binary = ""
        if "--no-binary" in argv:
            no_binary = f"--no-binary {argv[argv.index('--no-binary') + 1]}\n"
        output_text = no_binary + "--only-binary :all:\n" + "demo-runtime==1.0.0 \\\n" + f"    --hash=sha256:{_HASH}\n"
        output.write_text(
            output_text,
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, "", "")

    return run


def test_update_builds_complete_matrix_with_safe_uv_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_inputs(tmp_path)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(lock_requirements.subprocess, "run", _fake_uv(calls))

    lock_requirements.update_locks(tmp_path, uv_executable="uv")

    manifest_path = tmp_path / "requirements" / "locks" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["epoch"] == "2026-07-24T00:00:00Z"
    assert manifest["resolver"] == {
        "index": "https://pypi.org/simple",
        "name": "uv",
        "version": "0.11.28",
    }
    assert manifest["policy"] == {
        "allow_direct_references": False,
        "require_hashes": True,
        "sdist_policy": {
            "default": "deny",
            "allowlist_by_profile": {
                "c2": [],
                "external-tools": [],
                "full": ["shodan"],
                "mysql": [],
                "osint-browser": ["shodan"],
                "platform": [],
                "reporting": [],
                "runtime": [],
                "test": [],
            },
        },
    }
    assert len(manifest["locks"]) == 27

    expected_paths = {
        f"requirements/locks/linux-x86_64/{python}/{profile}.txt"
        for python in ("cp310", "cp311", "cp312")
        for profile in (
            "runtime",
            "c2",
            "reporting",
            "osint-browser",
            "test",
            "mysql",
            "external-tools",
            "platform",
            "full",
        )
    }
    assert {item["path"] for item in manifest["locks"]} == expected_paths
    for item in manifest["locks"]:
        lock_path = tmp_path / item["path"]
        lock_bytes = lock_path.read_bytes()
        assert item["sha256"] == hashlib.sha256(lock_bytes).hexdigest()
        assert item["input_sha256"]
        assert b"--hash=sha256:" in lock_bytes
        lock_text = lock_bytes.decode("utf-8")
        if item["profile"] in {"osint-browser", "full"}:
            assert lock_text.index("--only-binary :all:") < lock_text.index("--no-binary shodan")

    assert len(calls) == 28
    compile_calls = calls[1:]
    for call in compile_calls:
        argv = call["argv"]
        assert isinstance(argv, list)
        assert argv[:3] == ["uv", "pip", "compile"]
        assert "--generate-hashes" in argv
        assert "--no-build" not in argv
        assert "--only-binary" in argv
        assert "--emit-build-options" in argv
        assert argv[argv.index("--default-index") + 1] == "https://pypi.org/simple"
        assert "@" not in argv[argv.index("--default-index") + 1]
        source_name = Path(argv[3]).name
        if source_name.endswith(("-osint-browser.in", "-full.in")):
            assert argv[argv.index("--no-binary") + 1] == "shodan"
        else:
            assert "--no-binary" not in argv
        assert "--no-header" in argv
        assert argv[argv.index("--python-platform") + 1] == "x86_64-manylinux_2_34"
        assert "--python-implementation" not in argv
        assert call["kwargs"]["check"] is True
        assert call["kwargs"]["text"] is True
        assert call["kwargs"]["capture_output"] is True
        assert call["kwargs"].get("shell") in (None, False)


def test_check_resolves_in_temporary_tree_without_mutating_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_inputs(tmp_path)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(lock_requirements.subprocess, "run", _fake_uv(calls))
    lock_requirements.update_locks(tmp_path)

    lock_requirements.check_locks(tmp_path)
    lock_path = tmp_path / "requirements" / "locks" / "linux-x86_64" / "cp310" / "runtime.txt"
    tampered = lock_path.read_text(encoding="utf-8") + "# local edit\n"
    lock_path.write_text(tampered, encoding="utf-8")

    with pytest.raises(lock_requirements.LockError, match="out of date"):
        lock_requirements.check_locks(tmp_path)

    assert lock_path.read_text(encoding="utf-8") == tampered


@pytest.mark.parametrize(
    "malicious",
    [
        "evil @ https://example.invalid/evil.whl\n",
        "https://example.invalid/evil.whl\n",
        "--extra-index-url https://example.invalid/simple\n",
        "-e git+https://example.invalid/repository.git#egg=evil\n",
        "demo>=1.0; python_version >= '3.9'\n$(touch /tmp/owned)\n",
    ],
)
def test_update_rejects_direct_urls_options_and_shell_payloads_before_resolver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malicious: str,
) -> None:
    _write_inputs(tmp_path)
    (tmp_path / "requirements" / "runtime.txt").write_text(
        malicious,
        encoding="utf-8",
    )

    def unexpected_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise AssertionError("resolver must not run for an unsafe input")

    monkeypatch.setattr(lock_requirements.subprocess, "run", unexpected_run)
    with pytest.raises(lock_requirements.LockError, match="unsafe requirement"):
        lock_requirements.update_locks(tmp_path)


@pytest.mark.parametrize(
    "body",
    [
        "demo==1.0.0\n",
        "demo>=1.0.0 \\\n    --hash=sha256:" + _HASH + "\n",
        "demo @ https://example.invalid/demo.whl \\\n    --hash=sha256:" + _HASH + "\n",
        "--index-url https://example.invalid/simple\ndemo==1.0.0 \\\n    --hash=sha256:" + _HASH + "\n",
        "demo==1.0.0 \\\n    --hash=sha256:not-a-digest\n",
    ],
)
def test_validate_rejects_unhashed_unpinned_direct_or_directive_locks(body: str) -> None:
    text = (
        lock_requirements.render_lock_header(
            target=lock_requirements.TARGETS[0],
            profile="runtime",
            inputs=lock_requirements.PROFILE_INPUTS["runtime"],
        )
        + body
    )

    with pytest.raises(lock_requirements.LockError):
        lock_requirements.validate_lock_text(text, source="test lock")


def test_validate_requires_self_contained_binary_only_policy() -> None:
    header = lock_requirements.render_lock_header(
        target=lock_requirements.TARGETS[0],
        profile="runtime",
        inputs=lock_requirements.PROFILE_INPUTS["runtime"],
    )
    pinned = "demo==1.0.0 \\\n    --hash=sha256:" + _HASH + "\n"

    with pytest.raises(lock_requirements.LockError, match="only-binary"):
        lock_requirements.validate_lock_text(header + pinned, source="missing policy")
    with pytest.raises(lock_requirements.LockError, match="sdist allowlist mismatch"):
        lock_requirements.validate_lock_text(
            header + "--only-binary :all:\n--no-binary demo\n" + pinned,
            source="unsafe policy",
        )

    lock_requirements.validate_lock_text(
        header + "--only-binary :all:\n" + pinned,
        source="valid lock",
    )


def test_validate_allows_only_the_declared_profile_sdist_exception() -> None:
    header = lock_requirements.render_lock_header(
        target=lock_requirements.TARGETS[0],
        profile="osint-browser",
        inputs=lock_requirements.PROFILE_INPUTS["osint-browser"],
    )
    pinned = "shodan==1.31.0 \\\n    --hash=sha256:" + _HASH + "\n"
    valid = header + "--only-binary :all:\n--no-binary shodan\n" + pinned

    lock_requirements.validate_lock_text(
        valid,
        source="external lock",
        sdist_allowlist=("shodan",),
    )
    with pytest.raises(lock_requirements.LockError, match="must precede"):
        lock_requirements.validate_lock_text(
            header + "--no-binary shodan\n--only-binary :all:\n" + pinned,
            source="wrong-order lock",
            sdist_allowlist=("shodan",),
        )
    with pytest.raises(lock_requirements.LockError, match="sdist allowlist mismatch"):
        lock_requirements.validate_lock_text(valid, source="runtime lock")
    with pytest.raises(lock_requirements.LockError, match="sdist allowlist mismatch"):
        lock_requirements.validate_lock_text(
            valid.replace("--no-binary shodan", "--no-binary attacker"),
            source="external lock",
            sdist_allowlist=("shodan",),
        )


def test_validate_detects_manifest_and_lock_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_inputs(tmp_path)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(lock_requirements.subprocess, "run", _fake_uv(calls))
    lock_requirements.update_locks(tmp_path)
    lock_requirements.validate_locks(tmp_path)

    retired_lock = tmp_path / "requirements" / "locks" / "linux-x86_64" / "cp39" / "runtime.txt"
    retired_lock.parent.mkdir(parents=True)
    retired_lock.write_text("retired target\n", encoding="utf-8")
    with pytest.raises(lock_requirements.LockError, match="unexpected lock artifacts"):
        lock_requirements.validate_locks(tmp_path)
    retired_lock.unlink()

    lock_path = tmp_path / "requirements" / "locks" / "linux-x86_64" / "cp312" / "full.txt"
    lock_path.write_text(
        lock_path.read_text(encoding="utf-8").replace(_HASH, "b" * 64),
        encoding="utf-8",
    )

    with pytest.raises(lock_requirements.LockError, match="digest mismatch"):
        lock_requirements.validate_locks(tmp_path)
