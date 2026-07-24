"""CI quality-ratchet helper contracts."""

from __future__ import annotations

import configparser
import json
import subprocess
from pathlib import Path

import pytest

from scripts.quality import coverage_gate, docs_gate, format_gate, sbom

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[1]


def test_global_coverage_floor_is_raised_and_synchronized() -> None:
    config = configparser.ConfigParser()
    config.read(ROOT / "quality" / "coverage-ci.ini", encoding="utf-8")
    floor = config.getfloat("report", "fail_under")

    assert floor >= 58.0
    assert coverage_gate._argument_parser().parse_args([]).fail_under == floor
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert f"--fail-under {floor:.2f}" in workflow

    isolated = coverage_gate._argument_parser().parse_args(["--data-file", "isolated.coverage"])
    assert isolated.data_file == Path("isolated.coverage")


def test_mysql_ci_uses_application_environment_contract() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    for name in (
        "OCTOPUS_DB_HOST",
        "OCTOPUS_DB_NAME",
        "OCTOPUS_DB_USER",
        "OCTOPUS_DB_PASS",
    ):
        assert f"          {name}:" in workflow
    assert "          DB_PASSWORD:" not in workflow
    assert "requirements/locks/linux-x86_64/cp310/test.txt \\" in workflow
    assert "requirements/locks/linux-x86_64/cp310/mysql.txt" in workflow


def test_nightly_external_tool_smoke_is_fail_closed() -> None:
    workflow = (ROOT / ".github" / "workflows" / "nightly.yml").read_text(encoding="utf-8")

    assert 'OCTOPUS_REQUIRE_EXTERNAL_TOOLS: "1"' in workflow
    assert "OCTOPUS_STRICT_EXTERNAL_TOOLS" not in workflow


def test_package_threshold_parser_is_bounded() -> None:
    assert coverage_gate._parse_package_threshold("core.ai=42.5") == (
        "core.ai",
        42.5,
    )
    with pytest.raises(coverage_gate.CoverageGateError):
        coverage_gate._parse_package_threshold("core.ai=101")


def test_format_gate_uses_argv_and_contains_changed_paths(tmp_path, monkeypatch) -> None:
    (tmp_path / "core").mkdir()
    changed = tmp_path / "core" / "worker.py"
    changed.write_text("value=1\n", encoding="utf-8")

    def fake_run(argv, **kwargs):
        assert kwargs.get("shell") in (None, False)
        if argv[:2] == ["git", "diff"]:
            return subprocess.CompletedProcess(argv, 0, "core/worker.py\n", "")
        assert argv[:3] == ["ruff", "format", "--check"]
        assert argv[3:] == [str(changed)]
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(format_gate.subprocess, "run", fake_run)

    assert format_gate.run_format_gate(tmp_path, "a" * 40, ruff="ruff") == 0


def test_sbom_is_deterministic_and_contains_every_hash(tmp_path: Path) -> None:
    lock = tmp_path / "runtime.txt"
    lock.write_text(
        f"--only-binary :all:\nExample_Pkg==1.2.3 \\\n  --hash=sha256:{'a' * 64} \\\n  --hash=sha256:{'b' * 64}\n",
        encoding="utf-8",
    )

    first = sbom.build_sbom(lock)
    second = sbom.build_sbom(lock)

    assert first == second
    assert first["components"][0]["purl"] == "pkg:pypi/example-pkg@1.2.3"
    assert len(first["components"][0]["hashes"]) == 2


def test_checked_in_docs_and_portable_scenarios_validate() -> None:
    schema_count, instance_count = docs_gate.validate_schemas(ROOT)

    assert schema_count >= 2
    assert instance_count == 10


def test_sbom_cli_writes_canonical_json(tmp_path: Path) -> None:
    lock = tmp_path / "runtime.txt"
    output = tmp_path / "sbom.json"
    lock.write_text(
        f"--only-binary :all:\ndemo==1.0.0 --hash=sha256:{'c' * 64}\n",
        encoding="utf-8",
    )

    assert sbom.main([str(lock), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"
