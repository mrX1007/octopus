"""Unit tests for quality check scripts."""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import scripts.quality.c2_builder_enrollment_inventory as builder_inv
import scripts.quality.c2_raw_task_inventory as raw_task_inv
import scripts.quality.dependency_lock_impact_gate as dep_gate
import scripts.quality.mypy_config_inventory as mypy_inv
import scripts.quality.provider_legacy_field_inventory as legacy_inv
import scripts.quality.provider_mount_gate as mount_gate
import scripts.quality.provider_plan_ledger_gate as ledger_gate


@pytest.mark.unit
def test_c2_builder_enrollment_inventory(tmp_path: Path):
    c2_dir = tmp_path / "core" / "c2"
    c2_dir.mkdir(parents=True)
    builder_file = c2_dir / "builder.py"

    # Clean
    builder_file.write_text("# clean builder")
    assert builder_inv.inventory_builder_call_sites(tmp_path) == []
    with patch.object(builder_inv, "inventory_builder_call_sites", return_value=[]):
        assert builder_inv.main() == 0

    # Violation
    builder_file.write_text("EnrollmentAuthority.issue()")
    assert len(builder_inv.inventory_builder_call_sites(tmp_path)) == 1
    with patch.object(builder_inv, "inventory_builder_call_sites", return_value=["violation"]):
        assert builder_inv.main() == 1


@pytest.mark.unit
def test_c2_raw_task_inventory(tmp_path: Path):
    c2_dir = tmp_path / "core" / "c2"
    c2_dir.mkdir(parents=True)
    wire_file = c2_dir / "agent_protocol_v12.py"

    # Clean
    wire_file.write_text("# clean wire")
    assert raw_task_inv.inventory_v12_raw_tasks(tmp_path) == []
    with patch.object(raw_task_inv, "inventory_v12_raw_tasks", return_value=[]):
        assert raw_task_inv.main() == 0

    # Violation
    wire_file.write_text("raw_command: str\n")
    assert len(raw_task_inv.inventory_v12_raw_tasks(tmp_path)) == 1
    with patch.object(raw_task_inv, "inventory_v12_raw_tasks", return_value=["violation"]):
        assert raw_task_inv.main() == 1


@pytest.mark.unit
def test_provider_mount_gate(tmp_path: Path):
    manifest = mount_gate.generate_mount_manifest()
    assert manifest["entry_count"] == 20
    assert len(manifest["entries"]) == 20

    # Main with check
    assert mount_gate.main(["check"]) == 0
    assert mount_gate.main(["invalid_arg"]) == 2

    # Validation errors
    bad_count = copy.deepcopy(manifest)
    bad_count["entries"] = bad_count["entries"][:10]
    with pytest.raises(ValueError, match="provider_mount_manifest_must_match_exact_20_v2_identities"):
        mount_gate._validate_generated_manifest(bad_count)

    bad_available = copy.deepcopy(manifest)
    bad_available["entries"][0]["spec"]["available"] = True
    with pytest.raises(ValueError, match="dynamic_readiness_forbidden"):
        mount_gate._validate_generated_manifest(bad_available)

    bad_revision = copy.deepcopy(manifest)
    bad_revision["entries"][1]["revision"] = bad_revision["entries"][0]["revision"]
    with pytest.raises(ValueError, match="provider_mount_revisions_must_be_unique"):
        mount_gate._validate_generated_manifest(bad_revision)

    bad_digest = copy.deepcopy(manifest)
    bad_digest["entries"][1]["mount_digest"] = bad_digest["entries"][0]["mount_digest"]
    with pytest.raises(ValueError, match="provider_mount_digests_must_be_unique"):
        mount_gate._validate_generated_manifest(bad_digest)

    bad_config = copy.deepcopy(manifest)
    bad_config["entries"][0]["spec"]["configured"] = False
    with pytest.raises(ValueError, match="canonical_v2_provider_must_be_configured"):
        mount_gate._validate_generated_manifest(bad_config)

    bad_typed = copy.deepcopy(manifest)
    bad_typed["entries"][0]["spec"]["typed_action_supported"] = False
    with pytest.raises(ValueError, match="canonical_v2_provider_must_be_typed"):
        mount_gate._validate_generated_manifest(bad_typed)

    bad_raw = copy.deepcopy(manifest)
    bad_raw["entries"][0]["spec"]["raw_command_supported"] = True
    with pytest.raises(ValueError, match="canonical_v2_provider_must_not_support_raw_commands"):
        mount_gate._validate_generated_manifest(bad_raw)

    # Generate mode
    fake_root = tmp_path / "root"
    fake_root.mkdir()
    with patch.object(mount_gate, "PROJECT_ROOT", fake_root):
        assert mount_gate.main(["generate"]) == 0
        assert (fake_root / "quality" / "provider-mounts.json").exists()
        assert mount_gate.main(["check"]) == 0

        # Corrupt file
        (fake_root / "quality" / "provider-mounts.json").write_text("bad json")
        assert mount_gate.main(["check"]) == 1

        # Outdated file
        (fake_root / "quality" / "provider-mounts.json").write_text("{}")
        assert mount_gate.main(["check"]) == 1

        # Missing file
        (fake_root / "quality" / "provider-mounts.json").unlink()
        assert mount_gate.main(["check"]) == 1


@pytest.mark.unit
def test_provider_legacy_field_inventory(tmp_path: Path):
    _unallowed_reads, v2_violations = legacy_inv.audit_repository()
    assert v2_violations == []
    with patch.object(legacy_inv, "audit_repository", return_value=([], [])):
        assert legacy_inv.main() == 0

    with patch.object(legacy_inv, "audit_repository", return_value=(["unallowed"], ["v2_viol"])):
        assert legacy_inv.main() == 1

    # Test AST visitor directly
    test_code = """
ActionDescriptorV2(provider="mock")
x = descriptor.provider
"""
    tree = legacy_inv.ast.parse(test_code)
    visitor = legacy_inv.LegacyFieldVisitor("core/test.py")
    visitor.visit(tree)
    assert len(visitor.v2_constructor_keywords) == 1
    assert len(visitor.v1_reads) == 1


@pytest.mark.unit
def test_dependency_lock_impact_gate(tmp_path: Path):
    # Valid non-impacting changed paths
    dep_gate.validate_changed_path_impact(["README.md", "core/c2/daemon.py"])

    # Path normalization check
    with pytest.raises(dep_gate.DependencyLockImpactError, match="not canonical"):
        dep_gate._normalized_path("/absolute/path")

    # Main runner success
    assert dep_gate.main(["--changed-path", "README.md"]) == 0

    # Main runner failure
    with patch.object(dep_gate, "run_gate", side_effect=dep_gate.DependencyLockImpactError("fail")):
        assert dep_gate.main(["--changed-path", "README.md"]) == 1

    # validate_manifest_input_hashes errors
    missing_root = tmp_path / "missing"
    missing_root.mkdir()
    with pytest.raises(dep_gate.DependencyLockImpactError, match="cannot be read"):
        dep_gate.validate_manifest_input_hashes(missing_root)

    # _working_tree_paths
    with patch("subprocess.run", return_value=SimpleNamespace(stdout=" M file.py\n?? new.txt\nR  old -> new2.txt\n")):
        paths = dep_gate._working_tree_paths(tmp_path)
        assert "file.py" in paths
        assert "new2.txt" in paths


@pytest.mark.unit
def test_provider_plan_ledger_gate(tmp_path: Path):
    # Test main with planning phase
    assert ledger_gate.main(["validate", "--phase", "planning"]) in (0, 1)

    # Test parse error
    with pytest.raises(ValueError):
        ledger_gate._validate_phase("invalid_phase")

    # Test manifest reader
    missing_manifest = tmp_path / "missing.json"
    present, state, err = ledger_gate._read_migration_manifest_state(missing_manifest)
    assert not present

    # Directory manifest
    dir_manifest = tmp_path / "dir_manifest"
    dir_manifest.mkdir()
    present_d, _state_d, err_d = ledger_gate._read_migration_manifest_state(dir_manifest)
    assert present_d
    assert "not a file" in str(err_d)

    # Non-dict manifest
    list_manifest = tmp_path / "list_manifest.json"
    list_manifest.write_text("[]")
    present_l, _state_l, err_l = ledger_gate._read_migration_manifest_state(list_manifest)
    assert present_l
    assert "must be a JSON object" in str(err_l)

    # Corrupt JSON manifest
    bad_manifest = tmp_path / "bad_manifest.json"
    bad_manifest.write_text("{bad")
    present_b, _state_b, err_b = ledger_gate._read_migration_manifest_state(bad_manifest)
    assert present_b
    assert "Unable to read" in str(err_b)

    valid_manifest = tmp_path / "manifest.json"
    valid_manifest.write_text('{"state": "COMPLETE"}')
    present, state, err = ledger_gate._read_migration_manifest_state(valid_manifest)
    assert present
    assert state == "COMPLETE"
    assert err is None

    # _read_head_paths with errors
    (tmp_path / ".git").mkdir(exist_ok=True)
    with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stderr=b"git error")):
        paths, err_head = ledger_gate._read_head_paths(tmp_path)
        assert len(paths) == 0
        assert "Unable to read Git HEAD" in str(err_head)

    # _read_head_declared_create_paths with errors
    with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=b"corrupt plan")):
        paths_c, err_c = ledger_gate._read_head_declared_create_paths(tmp_path)
        assert len(paths_c) == 0
        assert "Unable to parse the plan" in str(err_c)

    # validate_ledger with errors
    errors, _warnings = ledger_gate.validate_ledger(phase="invalid")
    assert len(errors) > 0


@pytest.mark.unit
def test_mypy_config_inventory(tmp_path: Path):
    # Not a directory
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("hello")
    inv = mypy_inv.inventory_repository(not_a_dir)
    assert not inv.ok

    # Normal directory
    refs, _violations = mypy_inv.audit_repository(tmp_path)
    assert isinstance(refs, list)

    # Main CLI
    assert mypy_inv.main(["--root", str(tmp_path)]) in (0, 1)
    assert mypy_inv.main(["--root", str(tmp_path), "--json"]) in (0, 1)
