"""Branch-complete hermetic tests for the lockfile quality tooling."""

from __future__ import annotations

import runpy
import subprocess
import sys

import pytest

from scripts import lock_requirements as lock

pytestmark = pytest.mark.unit

HASH = "a" * 64


def test_safe_path_guards(tmp_path):
    with pytest.raises(lock.LockError, match="escapes repository"):
        lock._safe_relative_file(tmp_path, "../outside")
    with pytest.raises(lock.LockError, match="missing or not a file"):
        lock._safe_relative_file(tmp_path, "missing.txt")


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("git+package", "VCS"),
        ("./package", "local paths"),
        ("!unnamed", "named package"),
    ],
)
def test_remaining_unsafe_requirement_reasons(line, reason):
    assert reason in lock._unsafe_requirement_reason(line)


def test_requirement_input_must_be_utf8(monkeypatch, tmp_path):
    requirements = tmp_path / "requirements"
    requirements.mkdir()
    (requirements / "bad.txt").write_bytes(b"\xff")
    monkeypatch.setattr(lock, "PROFILE_INPUTS", {"bad": ("requirements/bad.txt",)})
    with pytest.raises(lock.LockError, match="not UTF-8"):
        lock._read_and_validate_inputs(tmp_path)


def test_build_option_canonicalization_edges():
    with pytest.raises(lock.LockError, match="invalid binary policy"):
        lock._canonicalize_build_options("demo==1\n", sdist_allowlist=(), source="bad")
    with pytest.raises(lock.LockError, match="no packages"):
        lock._canonicalize_build_options("--only-binary :all:\n", sdist_allowlist=(), source="empty")
    rendered = lock._canonicalize_build_options(
        "--only-binary :all:\ndemo==1\n",
        sdist_allowlist=(),
        source="valid",
    )
    assert rendered.endswith("demo==1\n")
    already_terminated = lock._canonicalize_build_options(
        "--only-binary :all:\ndemo==1\n\n",
        sdist_allowlist=(),
        source="terminated",
    )
    assert already_terminated.endswith("demo==1\n")


def test_logical_records_and_lock_validation_edges():
    with pytest.raises(lock.LockError, match="unterminated continuation"):
        lock._logical_lock_records("demo==1 \\", source="bad")
    with pytest.raises(lock.LockError, match="control character"):
        lock.validate_lock_text("\x00", source="bad")
    with pytest.raises(lock.LockError, match="no packages"):
        lock.validate_lock_text("# comments only\n", source="empty")

    pinned = f"demo==1.0 --hash=sha256:{HASH}\n"
    with pytest.raises(lock.LockError, match="must precede packages"):
        lock.validate_lock_text(pinned + "--only-binary :all:\n", source="order")
    with pytest.raises(lock.LockError, match="unsupported installer directive"):
        lock.validate_lock_text(
            "--only-binary :all:\n" + f"demo==1.0 --config=x --hash=sha256:{HASH}\n",
            source="option",
        )


def test_resolver_environment_removes_external_configuration(monkeypatch):
    monkeypatch.setenv("PIP_INDEX_URL", "https://private.invalid")
    monkeypatch.setenv("UV_INDEX", "https://private.invalid")
    environment = lock._resolver_environment()
    assert "PIP_INDEX_URL" not in environment
    assert "UV_INDEX" not in environment
    assert environment["UV_NO_CONFIG"] == "true"


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (FileNotFoundError("missing"), "executable was not found"),
        (OSError("blocked"), "could not be executed safely"),
        (ValueError("bad argv"), "could not be executed safely"),
        (
            subprocess.CalledProcessError(
                2,
                ["uv"],
                stderr="https://user:secret@example.test/simple failed",
            ),
            "[REDACTED]",
        ),
        (subprocess.CalledProcessError(3, ["uv"], stderr=""), "exit code 3"),
    ],
)
def test_resolver_execution_errors_are_normalized(monkeypatch, tmp_path, error, message):
    monkeypatch.setattr(
        lock.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )
    with pytest.raises(lock.LockError, match=message):
        lock._run(["uv", "--version"], root=tmp_path)


def test_uv_version_profile_source_and_epoch_guards(monkeypatch, tmp_path):
    monkeypatch.setattr(
        lock,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "unexpected", ""),
    )
    with pytest.raises(lock.LockError, match="is required"):
        lock._assert_uv_version(tmp_path, "uv")

    assert lock._profile_source("demo", ("a.txt",), {"a.txt": "value"}).endswith("value\n")

    epoch = tmp_path / "requirements" / "locks"
    epoch.mkdir(parents=True)
    (epoch / "EPOCH").write_text("wrong\n", encoding="utf-8")
    with pytest.raises(lock.LockError, match="must contain exactly"):
        lock._validate_epoch(tmp_path)


def test_candidate_requires_resolver_output(monkeypatch, tmp_path):
    destination = tmp_path / "candidate"
    destination.mkdir()
    target = lock.Target("cp310", "3.10")
    monkeypatch.setattr(lock, "TARGETS", (target,))
    monkeypatch.setattr(lock, "PROFILE_INPUTS", {"runtime": ("requirements/runtime.txt",)})
    monkeypatch.setattr(lock, "PROFILE_SDIST_ALLOWLIST", {"runtime": ()})
    monkeypatch.setattr(lock, "_validate_epoch", lambda _root: None)
    monkeypatch.setattr(
        lock,
        "_read_and_validate_inputs",
        lambda _root: ({"requirements/runtime.txt": "demo>=1\n"}, {"requirements/runtime.txt": HASH}),
    )
    monkeypatch.setattr(lock, "_assert_uv_version", lambda *_args: None)
    monkeypatch.setattr(lock, "_run", lambda *_args, **_kwargs: None)
    with pytest.raises(lock.LockError, match="did not produce a UTF-8 lock"):
        lock._build_candidate(tmp_path, destination, uv_executable="uv")


def test_manifest_loader_errors(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(lock.LockError, match="invalid lock manifest"):
        lock._load_manifest(invalid)
    non_object = tmp_path / "list.json"
    non_object.write_text("[]", encoding="utf-8")
    with pytest.raises(lock.LockError, match="must be a JSON object"):
        lock._load_manifest(non_object)


def _minimal_lock_tree(tmp_path, monkeypatch):
    root = tmp_path
    target = lock.Target("cp310", "3.10")
    inputs = ("requirements/runtime.txt",)
    monkeypatch.setattr(lock, "TARGETS", (target,))
    monkeypatch.setattr(lock, "PROFILE_INPUTS", {"runtime": inputs})
    monkeypatch.setattr(lock, "PROFILE_SDIST_ALLOWLIST", {"runtime": ()})

    requirements = root / "requirements"
    locks = requirements / "locks"
    destination = locks / target.platform_id / target.tag
    destination.mkdir(parents=True)
    (locks / "EPOCH").write_text(f"{lock.EPOCH}\n", encoding="utf-8")
    (requirements / "runtime.txt").write_text("demo>=1\n", encoding="utf-8")
    _, hashes = lock._read_and_validate_inputs(root)
    relative = lock._lock_relative_path(target, "runtime")
    text = lock.render_lock_header(target=target, profile="runtime", inputs=inputs)
    text += f"--only-binary :all:\n\ndemo==1.0 --hash=sha256:{HASH}\n"
    lock_path = root / relative
    lock_path.write_text(text, encoding="utf-8")
    entry = {
        "input_sha256": {name: hashes[name] for name in inputs},
        "path": relative,
        "profile": "runtime",
        "sha256": lock._sha256(lock_path.read_bytes()),
        "target": target.tag,
    }
    manifest = lock._manifest_document(hashes, [entry])
    manifest_path = locks / "manifest.json"
    manifest_path.write_bytes(lock._manifest_bytes(manifest))
    return root, lock_path, manifest_path, manifest, entry


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda manifest, _entry: manifest.update(state="pending"), "unresolved"),
        (lambda manifest, _entry: manifest.update(epoch="wrong"), "manifest field"),
        (lambda manifest, _entry: manifest.update(locks={}), "locks must be a list"),
        (lambda manifest, _entry: manifest.update(locks=["bad"]), "invalid lock entry"),
        (lambda manifest, entry: manifest.update(locks=[entry, dict(entry)]), "duplicate lock entry"),
        (lambda manifest, _entry: manifest.update(locks=[]), "matrix is incomplete"),
        (lambda _manifest, entry: entry.update(target="cp999"), "metadata mismatch"),
        (lambda _manifest, entry: entry.update(input_sha256={}), "input digest mismatch"),
        (lambda _manifest, entry: entry.update(sha256="bad"), "lock digest is invalid"),
    ],
)
def test_manifest_validation_guards(monkeypatch, tmp_path, mutation, message):
    root, _lock_path, manifest_path, manifest, entry = _minimal_lock_tree(tmp_path, monkeypatch)
    mutation(manifest, entry)
    manifest_path.write_bytes(lock._manifest_bytes(manifest))
    with pytest.raises(lock.LockError, match=message):
        lock.validate_locks(root)


def test_unexpected_artifact_non_utf8_and_header_guards(monkeypatch, tmp_path):
    first = tmp_path / "unexpected"
    root, _path, _manifest_path, _manifest, _entry = _minimal_lock_tree(first, monkeypatch)
    unexpected = root / "requirements" / "locks" / lock.PLATFORM_ID / "cp999" / "extra.txt"
    unexpected.parent.mkdir(parents=True)
    unexpected.write_text("extra", encoding="utf-8")
    with pytest.raises(lock.LockError, match="unexpected lock artifacts"):
        lock.validate_locks(root)

    second = tmp_path / "non-utf8"
    root, lock_path, manifest_path, manifest, entry = _minimal_lock_tree(second, monkeypatch)
    lock_path.write_bytes(b"\xff")
    entry["sha256"] = lock._sha256(lock_path.read_bytes())
    manifest_path.write_bytes(lock._manifest_bytes(manifest))
    with pytest.raises(lock.LockError, match="lock is not UTF-8"):
        lock.validate_locks(root)

    third = tmp_path / "header"
    root, lock_path, manifest_path, manifest, entry = _minimal_lock_tree(third, monkeypatch)
    lock_path.write_text("wrong header\n", encoding="utf-8")
    entry["sha256"] = lock._sha256(lock_path.read_bytes())
    manifest_path.write_bytes(lock._manifest_bytes(manifest))
    with pytest.raises(lock.LockError, match="header mismatch"):
        lock.validate_locks(root)


def test_parser_main_routes_and_failure(monkeypatch, tmp_path, capsys):
    assert lock._parser().parse_args(["validate", "--root", str(tmp_path)]).command == "validate"
    calls = []
    monkeypatch.setattr(lock, "update_locks", lambda root, uv_executable: calls.append(("update", root, uv_executable)))
    monkeypatch.setattr(lock, "check_locks", lambda root, uv_executable: calls.append(("check", root, uv_executable)))
    monkeypatch.setattr(lock, "validate_locks", lambda root: calls.append(("validate", root)))
    assert lock.main(["update", "--root", str(tmp_path), "--uv", "uv-test"]) == 0
    assert lock.main(["check", "--root", str(tmp_path)]) == 0
    assert lock.main(["validate", "--root", str(tmp_path)]) == 0
    assert [item[0] for item in calls] == ["update", "check", "validate"]

    monkeypatch.setattr(
        lock,
        "validate_locks",
        lambda _root: (_ for _ in ()).throw(lock.LockError("bad locks")),
    )
    assert lock.main(["validate", "--root", str(tmp_path)]) == 1
    assert "bad locks" in capsys.readouterr().err


def test_script_entrypoint_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        sys,
        "argv",
        [lock.__file__, "validate", "--root", str(tmp_path / "missing")],
    )
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(lock.__file__, run_name="__main__")
    assert exc.value.code == 1
