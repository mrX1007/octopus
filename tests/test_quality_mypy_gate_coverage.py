"""Unit tests for scripts/quality/mypy_gate.py."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import scripts.quality.mypy_gate as mypy_gate

pytestmark = pytest.mark.unit


def test_load_partitions_valid(tmp_path: Path):
    quality_dir = tmp_path / "quality"
    quality_dir.mkdir(parents=True)
    manifest = quality_dir / "mypy-invocation-partitions.json"
    dummy_src = tmp_path / "src.py"
    dummy_src.write_text("x = 1\n")

    manifest.write_text(
        '{"schema_version": 1, "default_partition_id": "default", "singleton_partitions": [{"id": "p1", "path": "src.py"}]}'
    )

    partitions = mypy_gate.load_partitions(tmp_path)
    assert len(partitions) == 1
    assert partitions[0].id == "p1"
    assert partitions[0].path == "src.py"


def test_load_partitions_invalid_schemas(tmp_path: Path):
    quality_dir = tmp_path / "quality"
    quality_dir.mkdir(parents=True)
    manifest = quality_dir / "mypy-invocation-partitions.json"

    # Missing file
    manifest.unlink(missing_ok=True)
    with pytest.raises(mypy_gate.MypyGateError, match="missing"):
        mypy_gate.load_partitions(tmp_path)

    # Invalid JSON
    manifest.write_text("{bad json")
    with pytest.raises(mypy_gate.MypyGateError, match="cannot read partition manifest"):
        mypy_gate.load_partitions(tmp_path)

    # Invalid schema version
    manifest.write_text('{"schema_version": 2, "default_partition_id": "default", "singleton_partitions": []}')
    with pytest.raises(mypy_gate.MypyGateError, match="schema_version must be 1"):
        mypy_gate.load_partitions(tmp_path)


def test_cmd_functions(tmp_path: Path):
    root_dir = tmp_path
    quality_dir = root_dir / "quality"
    quality_dir.mkdir(parents=True)

    args = argparse.Namespace(partition=None)
    assert mypy_gate.cmd_freeze(args, root_dir) == 1
    assert mypy_gate.cmd_authorize_modify(args, root_dir) == 1
    assert mypy_gate.cmd_authorize_stub(args, root_dir) == 1
    assert mypy_gate.cmd_deauthorize(args, root_dir) == 1
    assert mypy_gate.cmd_complete(args, root_dir) == 1

    # cmd_check failure
    with patch(
        "scripts.quality.mypy_gate.inventory_repository",
        return_value=SimpleNamespace(ok=False, violations=["v1"], references=[]),
    ):
        assert mypy_gate.cmd_check(args, root_dir) == 1

    # cmd_inventory
    mock_ref = SimpleNamespace(
        path="src.py",
        line=10,
        kind=SimpleNamespace(value="CONFIG_PATH"),
        classification=SimpleNamespace(value="LIVE_CONSUMER"),
    )
    with patch(
        "scripts.quality.mypy_gate.inventory_repository",
        return_value=SimpleNamespace(ok=False, violations=["v1"], references=[mock_ref]),
    ):
        assert mypy_gate.cmd_inventory(args, root_dir) == 1

    with patch(
        "scripts.quality.mypy_gate.inventory_repository",
        return_value=SimpleNamespace(ok=True, violations=[], references=[mock_ref]),
    ):
        assert mypy_gate.cmd_inventory(args, root_dir) == 0

    # cmd_verify_overrides
    overrides_file = quality_dir / "mypy-overrides.json"
    # Missing
    assert mypy_gate.cmd_verify_overrides(args, root_dir) == 1

    # Corrupt
    overrides_file.write_text("{corrupt json")
    assert mypy_gate.cmd_verify_overrides(args, root_dir) == 1

    # Not a dict
    overrides_file.write_text("[]")
    assert mypy_gate.cmd_verify_overrides(args, root_dir) == 1

    # Valid
    overrides_file.write_text('{"overrides": []}')
    assert mypy_gate.cmd_verify_overrides(args, root_dir) == 0

    # cmd_verify_config_consumers
    with patch(
        "scripts.quality.mypy_gate.inventory_repository",
        return_value=SimpleNamespace(ok=True, violations=[], references=[]),
    ):
        assert mypy_gate.cmd_verify_config_consumers(args, root_dir) == 0

    with patch(
        "scripts.quality.mypy_gate.inventory_repository",
        return_value=SimpleNamespace(ok=False, violations=["bad"], references=[]),
    ):
        assert mypy_gate.cmd_verify_config_consumers(args, root_dir) == 1

    # cmd_finalization_ready
    freeze_path = quality_dir / "mypy-migration-freeze.json"
    # Missing freeze
    with patch(
        "scripts.quality.mypy_gate.inventory_repository",
        return_value=SimpleNamespace(ok=True, violations=[], references=[]),
    ):
        assert mypy_gate.cmd_finalization_ready(args, root_dir) == 1

        # Valid COMPLETE state
        freeze_path.write_text('{"state": "complete"}')
        assert mypy_gate.cmd_finalization_ready(args, root_dir) == 0

        # Corrupt JSON freeze
        freeze_path.write_text("{bad json")
        assert mypy_gate.cmd_finalization_ready(args, root_dir) == 1


def test_main_cli_subcommands():
    with (
        patch(
            "scripts.quality.mypy_gate.inventory_repository",
            return_value=SimpleNamespace(ok=True, violations=[], references=[]),
        ),
        patch("scripts.quality.mypy_gate.run_mypy_check", return_value=0),
    ):
        assert mypy_gate.main(["check"]) == 0
        assert mypy_gate.main(["inventory"]) == 0
        assert mypy_gate.main(["freeze"]) == 1
        assert mypy_gate.main(["authorize-modify", "--path", "test.py"]) == 1
        assert mypy_gate.main(["authorize-stub", "--path", "test.py"]) == 1
        assert mypy_gate.main(["deauthorize", "--path", "test.py"]) == 1
        assert mypy_gate.main(["verify-overrides"]) in (0, 1)
        assert mypy_gate.main(["verify-config-consumers"]) == 0
        assert mypy_gate.main(["finalization-ready"]) in (0, 1)
        assert mypy_gate.main(["complete"]) == 1


def test_run_mypy_check(tmp_path: Path):
    quality_dir = tmp_path / "quality"
    quality_dir.mkdir(parents=True)
    manifest = quality_dir / "mypy-invocation-partitions.json"
    dummy_src = tmp_path / "src.py"
    dummy_src.write_text("x = 1\n")
    manifest.write_text(
        '{"schema_version": 1, "default_partition_id": "default", "singleton_partitions": [{"id": "p1", "path": "src.py"}]}'
    )

    # Missing pyproject.toml
    with pytest.raises(mypy_gate.MypyGateError, match=r"missing pyproject\.toml"):
        mypy_gate.run_mypy_check(tmp_path)

    # Valid pyproject.toml
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.mypy]\n")
    with patch("subprocess.run", return_value=SimpleNamespace(returncode=0)):
        assert mypy_gate.run_mypy_check(tmp_path, partition_id="p1") == 0
        assert mypy_gate.run_mypy_check(tmp_path, partition_id="unknown") == 1
