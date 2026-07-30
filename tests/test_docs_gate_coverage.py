"""Statement and branch coverage for the documentation quality gate."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest
import yaml

from scripts.quality import docs_gate as gate

pytestmark = pytest.mark.contract


def _docs_root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    return root


def test_markdown_file_inventory(tmp_path):
    root = _docs_root(tmp_path)
    (root / "docs" / "nested").mkdir()
    first = root / "docs" / "a.md"
    second = root / "docs" / "nested" / "b.md"
    first.write_text("a", encoding="utf-8")
    second.write_text("b", encoding="utf-8")
    assert list(gate._markdown_files(root)) == [
        root / "README.md",
        root / "CONTRIBUTING.md",
        first,
        second,
    ]


def test_local_links_success_skips_fences_anchors_and_remote_links(tmp_path):
    root = _docs_root(tmp_path)
    (root / "asset.txt").write_text("asset", encoding="utf-8")
    (root / "README.md").write_text(
        "\n".join(
            [
                "[asset](asset.txt)",
                "[encoded](asset%2Etxt#section)",
                "[anchor](#section)",
                "[remote](https://example.test/path)",
                "```md",
                "[ignored](missing.md)",
                "```",
            ]
        ),
        encoding="utf-8",
    )
    assert gate.validate_local_links(root) == 2


def test_local_links_reports_missing_and_escaping_targets(tmp_path):
    root = _docs_root(tmp_path)
    (root / "README.md").write_text(
        "[missing](missing.md)\n[escape](../outside.md)\n",
        encoding="utf-8",
    )
    with pytest.raises(gate.DocsGateError) as exc:
        gate.validate_local_links(root)
    assert "missing link target" in str(exc.value)
    assert "link escapes repository" in str(exc.value)


def test_json_loader_success_and_failures(tmp_path):
    valid = tmp_path / "valid.json"
    valid.write_text('{"ok": true}', encoding="utf-8")
    assert gate._load_json(valid) == {"ok": True}

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(gate.DocsGateError, match="invalid JSON"):
        gate._load_json(invalid)
    with pytest.raises(gate.DocsGateError, match="invalid JSON"):
        gate._load_json(tmp_path / "missing.json")


def _schema_root(tmp_path: Path) -> Path:
    root = _docs_root(tmp_path)
    (root / "docs" / "schemas").mkdir()
    (root / "benchmarks" / "scenarios").mkdir(parents=True)
    return root


def test_schema_root_must_be_object(tmp_path):
    root = _schema_root(tmp_path)
    (root / "docs" / "schemas" / "benchmark-scenario-v1.schema.json").write_text("[]", encoding="utf-8")
    with pytest.raises(gate.DocsGateError, match="schema root must be an object"):
        gate.validate_schemas(root)


def test_invalid_schema_and_missing_scenario_schema(tmp_path):
    root = _schema_root(tmp_path)
    (root / "docs" / "schemas" / "benchmark-scenario-v1.schema.json").write_text('{"type": 7}', encoding="utf-8")
    with pytest.raises(gate.DocsGateError, match="invalid JSON schema"):
        gate.validate_schemas(root)

    (root / "docs" / "schemas" / "benchmark-scenario-v1.schema.json").unlink()
    (root / "docs" / "schemas" / "other.schema.json").write_text('{"type": "object"}', encoding="utf-8")
    with pytest.raises(gate.DocsGateError, match="scenario schema is missing"):
        gate.validate_schemas(root)


def test_schema_instance_validation_failure_and_success(tmp_path):
    root = _schema_root(tmp_path)
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["name"],
        "properties": {"name": {"type": "string"}},
    }
    schema_path = root / "docs" / "schemas" / "benchmark-scenario-v1.schema.json"
    schema_path.write_text(__import__("json").dumps(schema), encoding="utf-8")
    scenario = root / "benchmarks" / "scenarios" / "demo.json"
    scenario.write_text("{}", encoding="utf-8")
    with pytest.raises(gate.DocsGateError, match=r"demo.json:<root>"):
        gate.validate_schemas(root)

    scenario.write_text('{"name": "demo"}', encoding="utf-8")
    assert gate.validate_schemas(root) == (1, 1)


def _write_manifest(root: Path, payload) -> None:
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs" / "deprecations.yaml").write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def test_deprecation_manifest_parse_and_shape_errors(tmp_path):
    root = _docs_root(tmp_path)
    manifest = root / "docs" / "deprecations.yaml"
    manifest.write_text("[", encoding="utf-8")
    with pytest.raises(gate.DocsGateError, match="invalid deprecations manifest"):
        gate.validate_deprecations(root)

    for payload, message in (
        ([], "unsupported"),
        ({"schema_version": "2.0", "entries": [{}]}, "unsupported"),
        ({"schema_version": "1.0", "entries": []}, "no entries"),
    ):
        _write_manifest(root, payload)
        with pytest.raises(gate.DocsGateError, match=message):
            gate.validate_deprecations(root)


def test_deprecation_entry_failures_are_aggregated(tmp_path):
    root = _docs_root(tmp_path)
    code = root / "code.py"
    code.write_text(
        "VALUE = 1\n"
        "def function():\n    pass\n"
        "async def async_fn():\n    pass\n"
        "class Example:\n    def method(self):\n        pass\n",
        encoding="utf-8",
    )
    (root / "notes.txt").write_text("notes", encoding="utf-8")
    (root / "unreadable.py").write_bytes(b"\xff")
    (root / "no_reference.py").write_text("pass\n", encoding="utf-8")
    entries = [
        "not-a-mapping",
        {"symbol_or_path": "", "internal_callers": []},
        {"symbol_or_path": "code.py", "internal_callers": []},
        {"symbol_or_path": "code.py", "internal_callers": []},
        {"symbol_or_path": "missing.py", "internal_callers": []},
        {"symbol_or_path": "notes.txt:symbol", "internal_callers": []},
        {"symbol_or_path": "code.py:missing", "internal_callers": []},
        {"symbol_or_path": "code.py:function", "internal_callers": "invalid"},
        {"symbol_or_path": "code.py:Example.method", "internal_callers": ["absent.py"]},
        {"symbol_or_path": "code.py:async_fn", "internal_callers": ["unreadable.py"]},
        {"symbol_or_path": "code.py:VALUE", "internal_callers": ["no_reference.py"]},
    ]
    _write_manifest(root, {"schema_version": "1.0", "entries": entries})

    with pytest.raises(gate.DocsGateError) as exc:
        gate.validate_deprecations(root)

    rendered = str(exc.value)
    for message in (
        "is not a mapping",
        "empty or duplicate",
        "target path does not exist",
        "not a Python file",
        "symbol does not exist",
        "internal_callers is not a list",
        "caller does not exist",
        "caller is unreadable",
        "declared caller has no target reference",
    ):
        assert message in rendered


def test_valid_deprecation_symbol_and_path_entries(tmp_path):
    root = _docs_root(tmp_path)
    code = root / "code.py"
    code.write_text(
        "VALUE: int = 1\nobj.attr = 2\ndef function():\n    def nested():\n        pass\n",
        encoding="utf-8",
    )
    folder = root / "folder"
    folder.mkdir()
    caller = root / "caller.py"
    caller.write_text("function()\n# folder\n", encoding="utf-8")
    entries = [
        {"symbol_or_path": "code.py:function", "internal_callers": ["caller.py"]},
        {"symbol_or_path": "folder/", "internal_callers": ["caller.py"]},
    ]
    _write_manifest(root, {"schema_version": "1.0", "entries": entries})
    assert gate.validate_deprecations(root) == 2
    assert {"VALUE", "function", "function.nested"} <= gate._python_symbols(code)


def test_python_symbol_parser_failure(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def invalid(:\n", encoding="utf-8")
    with pytest.raises(gate.DocsGateError, match="cannot inspect"):
        gate._python_symbols(broken)


def test_parser_and_main_success_and_failure(monkeypatch, tmp_path, capsys):
    root = _docs_root(tmp_path)
    assert gate._argument_parser().parse_args(["--root", str(root)]).root == root
    monkeypatch.setattr(gate, "validate_local_links", lambda _root: 2)
    monkeypatch.setattr(gate, "validate_schemas", lambda _root: (3, 4))
    monkeypatch.setattr(gate, "validate_deprecations", lambda _root: 5)
    assert gate.main(["--root", str(root)]) == 0
    assert "docs gate passed" in capsys.readouterr().out

    monkeypatch.setattr(
        gate,
        "validate_local_links",
        lambda _root: (_ for _ in ()).throw(gate.DocsGateError("bad docs")),
    )
    assert gate.main(["--root", str(root)]) == 1
    assert "bad docs" in capsys.readouterr().err


def test_script_entrypoint_reports_invalid_root(monkeypatch, tmp_path):
    missing = tmp_path / "missing"
    monkeypatch.setattr(sys, "argv", [gate.__file__, "--root", str(missing)])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(gate.__file__, run_name="__main__")
    assert exc.value.code == 1
