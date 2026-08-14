"""Tests for fail-closed mypy invocation-partition metadata."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.quality.mypy_gate import MypyGateError, load_partitions

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _write_partition_manifest(root: Path, singletons: list[dict[str, object]]) -> None:
    manifest = root / "quality" / "mypy-invocation-partitions.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "default_partition_id": "default",
                "singleton_partitions": singletons,
            }
        ),
        encoding="utf-8",
    )


def test_existing_duplicate_app_modules_are_isolated_singletons() -> None:
    partitions = load_partitions(ROOT)

    assert [(partition.id, partition.path) for partition in partitions] == [
        ("benchmark-lab-app", "benchmarks/competitors/lab/app.py"),
        ("discovery-lab-v2-app", "benchmarks/competitors/labs/discovery-lab-v2/app.py"),
        ("discovery-lab-v3-app", "benchmarks/competitors/labs/discovery-lab-v3/app.py"),
    ]


def test_partition_manifest_rejects_flags_and_unknown_keys(tmp_path: Path) -> None:
    source = tmp_path / "lab" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("value = 1\n", encoding="utf-8")
    _write_partition_manifest(
        tmp_path,
        [{"id": "lab-app", "path": "lab/app.py", "flags": ["--ignore-missing-imports"]}],
    )

    with pytest.raises(MypyGateError, match="invalid schema"):
        load_partitions(tmp_path)


@pytest.mark.parametrize(
    "singletons, message",
    [
        (
            [
                {"id": "one", "path": "lab/app.py"},
                {"id": "one", "path": "lab/other.py"},
            ],
            "duplicate singleton partition id",
        ),
        (
            [
                {"id": "one", "path": "lab/app.py"},
                {"id": "two", "path": "lab/app.py"},
            ],
            "duplicate singleton partition path",
        ),
        ([{"id": "one", "path": "../app.py"}], "not a normalized Python path"),
    ],
)
def test_partition_manifest_rejects_duplicate_or_unsafe_entries(
    tmp_path: Path,
    singletons: list[dict[str, object]],
    message: str,
) -> None:
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / "app.py").write_text("value = 1\n", encoding="utf-8")
    (lab / "other.py").write_text("value = 2\n", encoding="utf-8")
    _write_partition_manifest(tmp_path, singletons)

    with pytest.raises(MypyGateError, match=message):
        load_partitions(tmp_path)


def test_partition_manifest_missing_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(MypyGateError, match=r"missing quality/mypy-invocation-partitions\.json"):
        load_partitions(tmp_path)
