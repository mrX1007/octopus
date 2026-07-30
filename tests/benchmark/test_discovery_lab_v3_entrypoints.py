"""Hermetic contracts for the standalone discovery-lab v3 entry points."""

from __future__ import annotations

import builtins
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

ROOT = Path(__file__).parents[2]
LAB = ROOT / "benchmarks" / "competitors" / "labs" / "discovery-lab-v3"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _without_repository_path(monkeypatch) -> None:
    repository = str(ROOT)
    monkeypatch.setattr(sys, "path", [item for item in sys.path if item != repository])


def test_server_entrypoint_uses_source_tree_fallback_only_for_missing_core(monkeypatch) -> None:
    _without_repository_path(monkeypatch)
    real_import = builtins.__import__
    attempts = 0

    def import_with_one_missing_core(name, globals=None, locals=None, fromlist=(), level=0):
        nonlocal attempts
        if name == "core.benchmarks.v3.server" and attempts == 0:
            attempts += 1
            raise ModuleNotFoundError("synthetic source-tree import", name="core")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_with_one_missing_core)
    module = _load(LAB / "app.py", "fixture_v3_app_fallback")

    assert attempts == 1
    assert str(ROOT) == sys.path[0]
    assert callable(module.main)

    def import_with_wrong_missing_dependency(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.benchmarks.v3.server":
            raise ModuleNotFoundError("synthetic dependency import", name="fastapi")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_with_wrong_missing_dependency)
    with pytest.raises(ModuleNotFoundError) as exc_info:
        _load(LAB / "app.py", "fixture_v3_app_dependency_failure")
    assert exc_info.value.name == "fastapi"


def test_server_entrypoint_imports_normally_when_package_is_available() -> None:
    module = _load(LAB / "app.py", "fixture_v3_app_normal")
    assert callable(module.main)


def test_generate_entrypoint_writes_private_only_and_full_product_view(monkeypatch, tmp_path) -> None:
    _without_repository_path(monkeypatch)
    module = _load(LAB / "generate.py", "fixture_v3_generate_without_path")
    assert str(ROOT) == sys.path[0]

    # Loading again takes the already-configured path branch.
    module = _load(LAB / "generate.py", "fixture_v3_generate_with_path")
    family = module.SCENARIO_FAMILIES[0]
    calls: list[tuple] = []

    class Variant:
        def write_private_manifest(self, path: Path) -> None:
            calls.append(("private", path))

        def product_view(self, *, base_url: str):
            calls.append(("product", base_url))
            return {"base_url": base_url, "family": family}

    def generate(selected_family: str, *, matched_fixture_seed: int):
        calls.append(("generate", selected_family, matched_fixture_seed))
        return Variant()

    monkeypatch.setattr(module, "generate_fixture_variant", generate)
    private_path = tmp_path / "private.json"
    monkeypatch.setattr(sys, "argv", ["generate.py", family, "41", str(private_path)])
    module.main()

    assert calls == [("generate", family, 41), ("private", private_path)]

    calls.clear()
    product_path = tmp_path / "nested" / "product.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate.py",
            family,
            "42",
            str(private_path),
            "--product-view",
            str(product_path),
            "--base-url",
            "http://lab.internal:8080",
        ],
    )
    module.main()

    assert calls == [
        ("generate", family, 42),
        ("private", private_path),
        ("product", "http://lab.internal:8080"),
    ]
    assert json.loads(product_path.read_text(encoding="utf-8")) == {
        "base_url": "http://lab.internal:8080",
        "family": family,
    }
    assert product_path.read_text(encoding="utf-8").endswith("\n")


def test_reveal_entrypoint_requires_closure_and_publishes_after_ack(monkeypatch, tmp_path) -> None:
    _without_repository_path(monkeypatch)
    module = _load(LAB / "reveal.py", "fixture_v3_reveal_without_path")
    assert str(ROOT) == sys.path[0]
    module = _load(LAB / "reveal.py", "fixture_v3_reveal_with_path")

    private_path = tmp_path / "private.json"
    reveal_path = tmp_path / "reveal.json"
    monkeypatch.setattr(sys, "argv", ["reveal.py", str(private_path), str(reveal_path)])
    with pytest.raises(SystemExit, match="--campaign-closed is required"):
        module.main()

    writes: list[tuple] = []
    variant = SimpleNamespace(
        write_reveal_manifest=lambda path, *, campaign_closed: writes.append((path, campaign_closed))
    )
    loads: list[Path] = []

    def load(path: Path):
        loads.append(path)
        return variant

    monkeypatch.setattr(module, "load_private_fixture", load)
    monkeypatch.setattr(
        sys,
        "argv",
        ["reveal.py", str(private_path), str(reveal_path), "--campaign-closed"],
    )
    module.main()

    assert loads == [private_path]
    assert writes == [(reveal_path, True)]
