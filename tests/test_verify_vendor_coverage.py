"""Hermetic branch coverage for vendor manifest verification."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import PurePosixPath

import pytest

from scripts.quality import verify_vendor as vendor

pytestmark = pytest.mark.contract

COMMIT = "a" * 40
DIGEST = "b" * 64


def _manifest_payload():
    return {
        "schema_version": 1,
        "submodules": [{"path": "vendor/tool", "commit": COMMIT}],
        "artifacts": [
            {
                "path": "vendor/tool/bin/tool",
                "submodule": "vendor/tool",
                "platform": {"os": "linux", "arch": "amd64"},
                "sha256": DIGEST,
            }
        ],
    }


def _write_payload(tmp_path, payload):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_exact_keys_and_relative_path_guards():
    with pytest.raises(vendor.VendorVerificationError, match="invalid keys"):
        vendor._require_exact_keys({"a": 1}, {"a", "b"}, "object")
    for value in (None, "", r"vendor\tool", "/vendor/tool", "vendor/./tool"):
        with pytest.raises(vendor.VendorVerificationError, match="relative POSIX path"):
            vendor._relative_posix_path(value, "path")


def test_json_loader_failures(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(vendor.VendorVerificationError, match="cannot read"):
        vendor._load_json(invalid)
    non_object = tmp_path / "list.json"
    non_object.write_text("[]", encoding="utf-8")
    with pytest.raises(vendor.VendorVerificationError, match="root must be"):
        vendor._load_json(non_object)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.pop("artifacts"), "invalid keys"),
        (lambda data: data.update(schema_version=2), "unsupported vendor manifest"),
        (lambda data: data.update(submodules=[]), "submodules must be"),
        (lambda data: data.update(artifacts=[]), "artifacts must be"),
        (lambda data: data.update(submodules=["bad"]), r"submodules\[0\] must be an object"),
        (lambda data: data["submodules"][0].update(commit="BAD"), "40-character Git ID"),
        (lambda data: data["submodules"].append(dict(data["submodules"][0])), "duplicate submodule"),
        (lambda data: data.update(artifacts=["bad"]), r"artifacts\[0\] must be an object"),
        (lambda data: data["artifacts"][0].update(submodule="vendor/other"), "is not declared"),
        (lambda data: data["artifacts"][0].update(path="vendor/other/tool"), "outside its declared"),
        (lambda data: data["artifacts"][0].update(platform="linux"), "platform must be an object"),
        (
            lambda data: data["artifacts"][0]["platform"].update(os="plan9"),
            "platform is unsupported",
        ),
        (lambda data: data["artifacts"][0].update(sha256="BAD"), "lowercase SHA-256"),
        (lambda data: data["artifacts"].append(dict(data["artifacts"][0])), "duplicate artifact"),
    ],
)
def test_manifest_shape_guards(tmp_path, mutate, message):
    payload = _manifest_payload()
    mutate(payload)
    with pytest.raises(vendor.VendorVerificationError, match=message):
        vendor.load_manifest(_write_payload(tmp_path, payload))


def test_git_errors_are_normalized(monkeypatch, tmp_path):
    monkeypatch.setattr(
        vendor.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("git absent")),
    )
    with pytest.raises(vendor.VendorVerificationError, match="git invocation failed"):
        vendor._run_git(tmp_path, "status")

    failed = subprocess.CompletedProcess(["git"], 1, "stdout detail", "")
    monkeypatch.setattr(vendor.subprocess, "run", lambda *_args, **_kwargs: failed)
    with pytest.raises(vendor.VendorVerificationError, match="stdout detail"):
        vendor._run_git(tmp_path, "status")


def test_resolved_path_and_submodule_guards(monkeypatch, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(vendor.VendorVerificationError, match="outside the repository"):
        vendor._resolved_inside(root, PurePosixPath("../outside"), "item")

    spec = vendor.SubmoduleSpec(PurePosixPath("vendor/tool"), COMMIT)
    monkeypatch.setattr(vendor, "_run_git", lambda *_args: "bad index")
    with pytest.raises(vendor.VendorVerificationError, match="not a pinned"):
        vendor._verify_submodule(root, spec, require_clean=False)

    monkeypatch.setattr(vendor, "_run_git", lambda *_args: f"160000 {COMMIT} 0\tvendor/tool")
    with pytest.raises(vendor.VendorVerificationError, match="checkout is missing"):
        vendor._verify_submodule(root, spec, require_clean=False)

    checkout = root / "vendor" / "tool"
    checkout.mkdir(parents=True)
    answers = iter((f"160000 {COMMIT} 0\tvendor/tool", "c" * 40))
    monkeypatch.setattr(vendor, "_run_git", lambda *_args: next(answers))
    with pytest.raises(vendor.VendorVerificationError, match="HEAD mismatch"):
        vendor._verify_submodule(root, spec, require_clean=False)


def test_hash_and_artifact_guards(monkeypatch, tmp_path):
    with pytest.raises(vendor.VendorVerificationError, match="cannot hash"):
        vendor._hash_file(tmp_path)

    root = tmp_path / "root"
    submodule = root / "vendor" / "tool"
    submodule.mkdir(parents=True)
    manifest = vendor.VendorManifest(
        submodules=(vendor.SubmoduleSpec(PurePosixPath("vendor/tool"), COMMIT),),
        artifacts=(),
    )
    missing = vendor.ArtifactSpec(
        PurePosixPath("vendor/tool/bin/tool"),
        PurePosixPath("vendor/tool"),
        "linux",
        "amd64",
        DIGEST,
    )
    with pytest.raises(vendor.VendorVerificationError, match="artifact is missing"):
        vendor._verify_artifact(root, manifest, missing)

    other = root / "vendor" / "other"
    other.mkdir()
    escaped_file = other / "tool"
    escaped_file.write_bytes(b"tool")
    escaped = vendor.ArtifactSpec(
        PurePosixPath("vendor/other/tool"),
        PurePosixPath("vendor/tool"),
        "linux",
        "amd64",
        DIGEST,
    )
    with pytest.raises(vendor.VendorVerificationError, match="escapes its submodule"):
        vendor._verify_artifact(root, manifest, escaped)

    artifact = submodule / "bin" / "tool"
    artifact.parent.mkdir()
    artifact.write_bytes(b"tool")
    monkeypatch.setattr(vendor, "_run_git", lambda *_args: "")
    with pytest.raises(vendor.VendorVerificationError, match="not tracked"):
        vendor._verify_artifact(root, manifest, missing)


def test_platform_normalization_all_auto_explicit_and_errors(monkeypatch):
    assert vendor._normalize_platform_selector("all") == "all"
    monkeypatch.setattr(vendor.sys, "platform", "linux")
    monkeypatch.setattr(vendor.host_platform, "machine", lambda: "x86_64")
    assert vendor._normalize_platform_selector("auto") == "linux/amd64"
    assert vendor._normalize_platform_selector("darwin/arm64") == "darwin/arm64"
    with pytest.raises(vendor.VendorVerificationError, match="platform must be"):
        vendor._normalize_platform_selector("linux/mips")
    monkeypatch.setattr(vendor.sys, "platform", "unknown")
    with pytest.raises(vendor.VendorVerificationError, match="cannot map host platform"):
        vendor._auto_platform()


def test_repository_requires_artifact_for_selected_platform(monkeypatch, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    manifest_path = root / "manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    manifest = vendor.VendorManifest(
        submodules=(vendor.SubmoduleSpec(PurePosixPath("vendor/tool"), COMMIT),),
        artifacts=(
            vendor.ArtifactSpec(
                PurePosixPath("vendor/tool/bin/tool"),
                PurePosixPath("vendor/tool"),
                "linux",
                "amd64",
                DIGEST,
            ),
        ),
    )
    monkeypatch.setattr(vendor, "load_manifest", lambda _path: manifest)
    monkeypatch.setattr(vendor, "_verify_submodule", lambda *_args, **_kwargs: None)
    with pytest.raises(vendor.VendorVerificationError, match="no approved artifacts"):
        vendor.verify_repository(root, manifest_path, platform_selector="windows/arm64")


def test_parser_and_main_success_failure_and_absolute_manifest(monkeypatch, tmp_path, capsys):
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    assert vendor._argument_parser().parse_args([]).platform == "auto"
    result = vendor.VerificationResult(1, 2, "all")
    calls = []
    monkeypatch.setattr(
        vendor,
        "verify_repository",
        lambda *args, **kwargs: calls.append((args, kwargs)) or result,
    )
    assert (
        vendor.main(
            [
                "--root",
                str(tmp_path),
                "--manifest",
                str(manifest),
                "--platform",
                "all",
                "--allow-dirty",
            ]
        )
        == 0
    )
    assert calls[0][0][1] == manifest
    assert calls[0][1]["require_clean"] is False
    assert "verification passed" in capsys.readouterr().out

    monkeypatch.setattr(
        vendor,
        "verify_repository",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(vendor.VendorVerificationError("bad vendor")),
    )
    assert vendor.main(["--root", str(tmp_path), "--manifest", manifest.name]) == 1
    assert "bad vendor" in capsys.readouterr().err


def test_script_entrypoint_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", [vendor.__file__, "--root", str(tmp_path / "missing")])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(vendor.__file__, run_name="__main__")
    assert exc.value.code == 1
