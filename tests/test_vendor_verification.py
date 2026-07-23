"""Hermetic contract tests for the vendor/submodule trust manifest."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from scripts.quality import coverage_gate, import_smoke, verify_vendor

pytestmark = pytest.mark.contract


def _git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _write_manifest(root: Path, commit: str, linux_hash: str, windows_hash: str) -> Path:
    manifest_path = root / "quality" / "vendor-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "submodules": [
                    {"path": "vendor/tool", "commit": commit},
                ],
                "artifacts": [
                    {
                        "path": "vendor/tool/bin/linux_amd64/tool",
                        "submodule": "vendor/tool",
                        "platform": {"os": "linux", "arch": "amd64"},
                        "sha256": linux_hash,
                    },
                    {
                        "path": "vendor/tool/bin/windows_amd64/tool.exe",
                        "submodule": "vendor/tool",
                        "platform": {"os": "windows", "arch": "amd64"},
                        "sha256": windows_hash,
                    },
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return manifest_path


@pytest.fixture
def vendor_repo(tmp_path: Path) -> tuple[Path, Path, str]:
    root = tmp_path / "root"
    submodule = root / "vendor" / "tool"
    submodule.mkdir(parents=True)

    _git(submodule, "init", "-q")
    _git(submodule, "config", "user.name", "OCTOPUS tests")
    _git(submodule, "config", "user.email", "tests@localhost")

    linux_binary = submodule / "bin" / "linux_amd64" / "tool"
    windows_binary = submodule / "bin" / "windows_amd64" / "tool.exe"
    linux_binary.parent.mkdir(parents=True)
    windows_binary.parent.mkdir(parents=True)
    linux_binary.write_bytes(b"trusted-linux-binary\n")
    windows_binary.write_bytes(b"trusted-windows-binary\n")
    (submodule / "main.go").write_text("package main\n", encoding="utf-8")
    _git(submodule, "add", ".")
    _git(submodule, "commit", "-q", "-m", "fixture vendor")
    commit = _git(submodule, "rev-parse", "HEAD")

    _git(root, "init", "-q")
    _git(root, "update-index", "--add", "--cacheinfo", f"160000,{commit},vendor/tool")

    manifest_path = _write_manifest(
        root,
        commit,
        hashlib.sha256(linux_binary.read_bytes()).hexdigest(),
        hashlib.sha256(windows_binary.read_bytes()).hexdigest(),
    )
    return root, manifest_path, commit


@pytest.mark.contract
def test_vendor_manifest_accepts_pinned_clean_checkout(vendor_repo):
    root, manifest_path, _commit = vendor_repo

    result = verify_vendor.verify_repository(root, manifest_path, platform_selector="all")

    assert result.submodules_checked == 1
    assert result.artifacts_checked == 2


@pytest.mark.contract
def test_vendor_manifest_rejects_gitlink_change(vendor_repo):
    root, manifest_path, _commit = vendor_repo
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["submodules"][0]["commit"] = "0" * 40
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(verify_vendor.VendorVerificationError, match="gitlink"):
        verify_vendor.verify_repository(root, manifest_path, platform_selector="all")


@pytest.mark.contract
def test_vendor_manifest_rejects_artifact_tampering(vendor_repo):
    root, manifest_path, _commit = vendor_repo
    artifact = root / "vendor" / "tool" / "bin" / "linux_amd64" / "tool"
    artifact.write_bytes(b"tampered\n")

    with pytest.raises(verify_vendor.VendorVerificationError, match="SHA-256"):
        verify_vendor.verify_repository(
            root,
            manifest_path,
            platform_selector="linux/amd64",
            require_clean=False,
        )


@pytest.mark.contract
def test_vendor_manifest_rejects_dirty_submodule(vendor_repo):
    root, manifest_path, _commit = vendor_repo
    (root / "vendor" / "tool" / "main.go").write_text(
        "package main\n// modified\n",
        encoding="utf-8",
    )

    with pytest.raises(verify_vendor.VendorVerificationError, match="not clean"):
        verify_vendor.verify_repository(root, manifest_path, platform_selector="all")


@pytest.mark.contract
def test_platform_selector_checks_only_matching_artifacts(vendor_repo):
    root, manifest_path, _commit = vendor_repo
    windows_artifact = root / "vendor" / "tool" / "bin" / "windows_amd64" / "tool.exe"
    windows_artifact.write_bytes(b"tampered-windows\n")

    result = verify_vendor.verify_repository(
        root,
        manifest_path,
        platform_selector="linux/amd64",
        require_clean=False,
    )
    assert result.artifacts_checked == 1

    with pytest.raises(verify_vendor.VendorVerificationError, match="SHA-256"):
        verify_vendor.verify_repository(
            root,
            manifest_path,
            platform_selector="all",
            require_clean=False,
        )


@pytest.mark.contract
def test_vendor_manifest_rejects_path_traversal(vendor_repo):
    root, manifest_path, _commit = vendor_repo
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["path"] = "../outside/tool"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(verify_vendor.VendorVerificationError, match="relative POSIX path"):
        verify_vendor.verify_repository(root, manifest_path, platform_selector="all")


@pytest.mark.contract
def test_import_smoke_reports_success_and_failure(capsys):
    assert import_smoke.run_import_smoke(["json", "pathlib"]) == []
    assert import_smoke.main(["--module", "json"]) == 0
    assert "import smoke passed" in capsys.readouterr().out

    assert import_smoke.main(["--module", "octopus_module_that_does_not_exist"]) == 1
    assert "ModuleNotFoundError" in capsys.readouterr().err


@pytest.mark.contract
def test_coverage_gate_discovers_every_first_party_python_file(tmp_path: Path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "worker.py").write_text("value = 2\n", encoding="utf-8")
    for excluded in (
        "build",
        "data",
        "tests",
        "vendor",
        "venv",
        ".git",
        "__pycache__",
    ):
        directory = tmp_path / excluded
        directory.mkdir()
        (directory / "ignored.py").write_text("raise AssertionError\n", encoding="utf-8")

    discovered = coverage_gate.discover_first_party_python(tmp_path)

    assert [path.relative_to(tmp_path).as_posix() for path in discovered] == [
        "app.py",
        "core/worker.py",
    ]
