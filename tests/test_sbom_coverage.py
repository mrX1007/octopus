"""Hermetic edge coverage for deterministic SBOM generation."""

from __future__ import annotations

import base64
import hashlib
import json
import runpy
import sys
import warnings
from pathlib import Path

import pytest

from scripts.quality import sbom

pytestmark = pytest.mark.unit


def test_records_ignore_comments_and_reject_unterminated_continuation() -> None:
    digest = "a" * 64
    assert sbom._records(
        f"\n  # generated lock  \nDemo==1.0 --hash=sha256:{digest}\n",
    ) == (f"Demo==1.0 --hash=sha256:{digest}",)

    with pytest.raises(sbom.SbomError, match="unterminated requirement continuation"):
        sbom._records("Demo==1.0 \\")


def test_build_sbom_maps_read_and_inexact_record_errors(tmp_path: Path) -> None:
    with pytest.raises(sbom.SbomError, match="cannot read lock: FileNotFoundError"):
        sbom.build_sbom(tmp_path / "missing.lock")

    lock = tmp_path / "inexact.lock"
    lock.write_text("demo>=1.0\n", encoding="utf-8")
    with pytest.raises(sbom.SbomError, match="lock record is not exact and hashed"):
        sbom.build_sbom(lock)


def test_main_reports_sbom_error_without_writing_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lock = tmp_path / "invalid.lock"
    output = tmp_path / "sbom.json"
    lock.write_text("demo==1.0\n", encoding="utf-8")

    assert sbom.main([str(lock), "--output", str(output)]) == 1
    assert not output.exists()
    assert "SBOM generation failed:" in capsys.readouterr().err


def test_module_entrypoint_generates_sbom(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = tmp_path / "runtime.lock"
    output = tmp_path / "sbom.json"
    lock.write_text(
        f"demo==1.0 --hash=sha256:{'b' * 64}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["sbom", str(lock), "--output", str(output)],
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_module("scripts.quality.sbom", run_name="__main__")

    assert exc_info.value.code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["components"][0]["name"] == "demo"


def _repository_sbom_fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict]:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "fixture-app"\nversion = "2.3.4"\n',
        encoding="utf-8",
    )
    lock = tmp_path / "full.txt"
    lock.write_text(
        f"demo==1.0 --hash=sha256:{'a' * 64}\n",
        encoding="utf-8",
    )
    go_directory = tmp_path / "go"
    go_directory.mkdir(exist_ok=True)
    go_mod = go_directory / "go.mod"
    go_mod.write_text(
        "module example.test/implant\n\ngo 1.21\n\nrequire example.test/module v1.2.3\n",
        encoding="utf-8",
    )
    go_digest = bytes.fromhex("b" * 64)
    (go_directory / "go.sum").write_text(
        f"example.test/module v1.2.3 h1:{base64.b64encode(go_digest).decode()}\n",
        encoding="utf-8",
    )
    resource_directory = tmp_path / "modules"
    resource_directory.mkdir(exist_ok=True)
    (resource_directory / "fixture.txt").write_text("resource\n", encoding="utf-8")
    artifact = tmp_path / "vendor" / "helper.bin"
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_bytes(b"reviewed vendor fixture")
    artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    vendor_manifest = tmp_path / "vendor-manifest.json"
    vendor_manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "submodules": [],
                "artifacts": [
                    {
                        "path": "vendor/helper.bin",
                        "sha256": artifact_digest,
                        "platform": {"os": "linux", "arch": "amd64"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    inventory = {
        "schema_version": "1.0",
        "tools": [
            {
                "name": "passive_fixture",
                "dependencies": {
                    "mode": "all",
                    "items": [
                        {"kind": "binary", "name": "curl"},
                        {"kind": "python", "name": "demo", "import_name": "demo"},
                        {
                            "kind": "resource",
                            "package": "",
                            "path": "modules",
                            "resource_type": "directory",
                        },
                        {"kind": "service", "name": "public-intelligence"},
                        {"kind": "vendor", "path": "vendor/helper.bin"},
                    ],
                },
            }
        ],
    }
    return lock, go_mod, vendor_manifest, inventory


def test_repository_sbom_is_deterministic_and_covers_every_dependency_family(tmp_path: Path) -> None:
    lock, go_mod, vendor_manifest, inventory = _repository_sbom_fixture(tmp_path)

    first = sbom.build_repository_sbom(
        lock,
        tmp_path,
        go_mod=go_mod,
        vendor_manifest=vendor_manifest,
        tool_inventory=inventory,
    )
    second = sbom.build_repository_sbom(
        lock,
        tmp_path,
        go_mod=go_mod,
        vendor_manifest=vendor_manifest,
        tool_inventory=inventory,
    )

    assert first == second
    assert first["metadata"]["component"]["purl"] == "pkg:pypi/fixture-app@2.3.4"
    references = {component["bom-ref"] for component in first["components"]}
    assert "pkg:pypi/demo@1.0" in references
    assert "pkg:golang/example.test/implant@2.3.4" in references
    assert "pkg:golang/example.test/module@v1.2.3" in references
    assert "pkg:generic/curl" in references
    assert "urn:octopus:resource:modules" in references
    assert "urn:octopus:vendor:vendor%2Fhelper.bin" in references
    assert first["services"] == [{"bom-ref": "urn:octopus:service:public-intelligence", "name": "public-intelligence"}]
    properties = {item["name"]: item["value"] for item in first["metadata"]["properties"]}
    assert properties["octopus:tool-dependency:passive_fixture"].startswith('{"items":')
    assert len(properties["octopus:tool-dependency-inventory:sha256"]) == 64
    dependency_rows = {item["ref"]: item["dependsOn"] for item in first["dependencies"]}
    assert dependency_rows["pkg:golang/example.test/implant@2.3.4"] == ["pkg:golang/example.test/module@v1.2.3"]
    assert "urn:octopus:service:public-intelligence" in dependency_rows["pkg:pypi/fixture-app@2.3.4"]


def test_repository_sbom_fails_closed_on_go_vendor_and_inventory_drift(tmp_path: Path) -> None:
    lock, go_mod, vendor_manifest, inventory = _repository_sbom_fixture(tmp_path)
    (go_mod.with_suffix(".sum")).write_text("", encoding="utf-8")
    with pytest.raises(sbom.SbomError, match="missing the module archive checksum"):
        sbom.build_repository_sbom(lock, tmp_path, go_mod=go_mod)

    _lock, go_mod, vendor_manifest, inventory = _repository_sbom_fixture(tmp_path)
    (tmp_path / "vendor" / "helper.bin").write_bytes(b"tampered")
    with pytest.raises(sbom.SbomError, match="digest mismatch"):
        sbom.build_repository_sbom(lock, tmp_path, vendor_manifest=vendor_manifest)

    inventory["tools"][0]["dependencies"] = {"kind": "unknown"}
    with pytest.raises(sbom.SbomError, match="unknown tool dependency kind"):
        sbom.build_repository_sbom(lock, tmp_path, tool_inventory=inventory)


def test_full_repository_cli_uses_canonical_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, go_mod, vendor_manifest, inventory = _repository_sbom_fixture(tmp_path)
    output = tmp_path / "full.cdx.json"
    monkeypatch.setattr(sbom, "load_registered_tool_inventory", lambda _root: inventory)

    assert (
        sbom.main(
            [
                str(lock),
                "--root",
                str(tmp_path),
                "--go-mod",
                str(go_mod),
                "--vendor-manifest",
                str(vendor_manifest),
                "--include-tool-dependencies",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["metadata"]["component"]["name"] == "fixture-app"
    assert payload["services"][0]["name"] == "public-intelligence"
