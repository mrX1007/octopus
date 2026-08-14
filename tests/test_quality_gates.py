"""CI quality-ratchet helper contracts."""

from __future__ import annotations

import configparser
import json
import subprocess
from pathlib import Path

import pytest
from coverage import Coverage

from scripts.quality import coverage_gate, docs_gate, format_gate, go_coverage_gate, mypy_config_inventory, sbom

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[1]


def test_global_coverage_floor_matches_recorded_baseline() -> None:
    config = configparser.ConfigParser()
    config.read(ROOT / "quality" / "coverage-ci.ini", encoding="utf-8")
    floor = config.getfloat("report", "fail_under")

    assert floor == 94.0
    assert coverage_gate._argument_parser().parse_args([]).fail_under == floor
    assert coverage_gate._argument_parser().parse_args([]).diff_fail_under == 90.0

    package_floors = {
        "core/actions": 95,
        "core/execution": 92,
        "core/benchmarks": 100,
    }

    ci_workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_workflow_path.is_file()
    workflow = ci_workflow_path.read_text(encoding="utf-8")
    assert f"--fail-under {floor:.2f}" in workflow
    assert "--diff-fail-under 90" in workflow
    for package, package_floor in package_floors.items():
        assert f"--package-fail-under {package}={package_floor}" in workflow
    assert "octopus.py octopus_c2.py search.py" in workflow
    assert "Mypy (single repository gate)" in workflow
    assert workflow.count(mypy_config_inventory.CANONICAL_CI_ENTRYPOINT) == 1
    direct_module_command = "python " + "-m mypy"
    assert direct_module_command not in workflow
    assert mypy_config_inventory.LEGACY_CONFIG_PATH not in workflow
    assert "Report risk-heavy killchain coverage" in workflow
    assert "core/killchain/ad/*.py" in workflow
    assert "core/killchain/exploits/*.py" in workflow
    assert "--fail-under=0" in workflow

    coverage_docs = (
        (ROOT / "README.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "quality" / "ci-and-vendor-integrity.md").read_text(encoding="utf-8"),
    )
    for documentation in coverage_docs:
        assert "94.58" not in documentation
        assert "94.00%" in documentation
        assert "95.41%" in documentation
        assert "92.59%" in documentation
        assert "--diff-fail-under 90" in documentation
        for package, package_floor in package_floors.items():
            assert f"--package-fail-under {package}={package_floor}" in documentation

    measured = Coverage(config_file=str(ROOT / "quality" / "coverage-ci.ini"))
    assert measured.get_exclude_list() == []
    assert measured.get_exclude_list("partial") == []
    assert set(config.get("run", "omit").split()) == {
        "build/*",
        "tests/*",
        "vendor/*",
        "venv/*",
    }

    isolated = coverage_gate._argument_parser().parse_args(["--data-file", "isolated.coverage"])
    assert isolated.data_file == Path("isolated.coverage")


def test_mysql_ci_uses_application_environment_contract() -> None:
    wf_path = ROOT / ".github" / "workflows" / "ci.yml"
    if not wf_path.exists():
        pytest.skip("ci.yml not present")
    workflow = wf_path.read_text(encoding="utf-8")

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


def test_go_checks_enforce_offline_graph_and_complete_profile() -> None:
    wf_path = ROOT / ".github" / "workflows" / "ci.yml"
    if not wf_path.exists():
        pytest.skip("ci.yml not present")
    workflow = wf_path.read_text(encoding="utf-8")
    parser = go_coverage_gate._argument_parser()

    args = parser.parse_args(["--profile", "coverage.out"])
    assert args.fail_under == 100.0
    assert "go test\n          -mod=readonly" in workflow
    assert "-covermode=atomic" in workflow
    assert "-coverpkg=./..." in workflow
    assert '-coverprofile="${RUNNER_TEMP}/c2-go.coverage.out"' in workflow
    assert "scripts/quality/go_coverage_gate.py" in workflow
    assert "Validate complete Go source coverage evidence" in workflow
    assert "--root core/c2" in workflow
    assert "--fail-under 0" in workflow
    assert 'GOPROXY: "off"' in workflow
    assert 'GOSUMDB: "off"' in workflow
    assert "go list -mod=readonly -deps ./... > /dev/null" in workflow
    assert "name: coverage-go" in workflow
    assert "if-no-files-found: error" in workflow
    assert "go vet -mod=readonly ./..." in workflow
    assert "go build -mod=readonly -trimpath -buildvcs=false" in workflow
    assert "-ldflags=-buildid=" in workflow
    assert 'CGO_ENABLED: "0"' in workflow
    assert 'GOWORK: "off"' in workflow
    assert "git diff --exit-code -- go.mod go.sum" in workflow
    assert "working-directory: ${{ github.workspace }}" in workflow
    assert "git ls-files -z -- ':(top,glob)**/*.go'" in workflow
    assert 'gofmt -l "${go_files[@]}"' in workflow


def test_nightly_external_tool_smoke_is_fail_closed() -> None:
    wf_path = ROOT / ".github" / "workflows" / "nightly.yml"
    if not wf_path.exists():
        pytest.skip("nightly.yml not present")
    workflow = wf_path.read_text(encoding="utf-8")
    smoke = (ROOT / "tests" / "test_external_tools_smoke.py").read_text(encoding="utf-8")

    assert 'OCTOPUS_REQUIRE_EXTERNAL_TOOLS: "1"' in workflow
    assert "OCTOPUS_STRICT_EXTERNAL_TOOLS" not in workflow
    assert "--yes curl nmap" in workflow
    assert "dispatch_registered_tool" in smoke
    assert 'ThreadingHTTPServer(("127.0.0.1", 0)' in smoke
    assert "subprocess.run" not in smoke


def test_live_ollama_lab_lane_is_opt_in_and_loopback_contained() -> None:
    wf_path = ROOT / ".github" / "workflows" / "ollama-lab-e2e.yml"
    if not wf_path.exists():
        pytest.skip("ollama-lab-e2e.yml not present")
    workflow = wf_path.read_text(encoding="utf-8")
    triggers = workflow.split("\njobs:", maxsplit=1)[0]
    compose = (ROOT / "tests" / "integration" / "ollama_scanner_lab" / "compose.yaml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "tests" / "integration" / "ollama_scanner_lab" / "Dockerfile").read_text(encoding="utf-8")
    test_source = (ROOT / "tests" / "integration" / "test_ollama_scanner_lab_e2e.py").read_text(encoding="utf-8")

    assert "  schedule:" in triggers
    assert "  workflow_dispatch:" in triggers
    assert "  push:" not in triggers
    assert "  pull_request:" not in triggers
    assert 'OLLAMA_VERSION: "0.18.3"' in workflow
    assert 'OLLAMA_LINUX_AMD64_SHA256: "7b3fb22f2e01a17f03ec0ac88a0b070ee2d7481030e735337ac8c02b84b5e66e"' in workflow
    assert "/sha256sum.txt" not in workflow
    assert "${OLLAMA_LINUX_AMD64_SHA256}" in workflow
    assert "sha256sum --check --strict ollama-linux-amd64.sha256" in workflow
    assert 'OCTOPUS_RUN_OLLAMA_LAB_E2E: "1"' in workflow
    assert 'OCTOPUS_E2E_TARGET: "127.0.0.1"' in workflow
    assert '"127.0.0.1:${OCTOPUS_E2E_PORT:-18080}:8080"' in compose
    assert "    read_only: true" in compose
    assert "      - ALL" in compose
    assert "      - no-new-privileges:true" in compose
    assert "\n    volumes:" not in compose
    assert dockerfile.startswith("FROM python:3.12.10-alpine3.21@sha256:")
    assert "@pytest.mark.skipif(" in test_source
    assert 'assert target == "127.0.0.1"' in test_source


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


def test_ci_generates_full_multi_ecosystem_sbom() -> None:
    wf_path = ROOT / ".github" / "workflows" / "ci.yml"
    if not wf_path.exists():
        pytest.skip("ci.yml not present")
    workflow = wf_path.read_text(encoding="utf-8")

    assert "Generate deterministic full-repository CycloneDX SBOM" in workflow
    assert "--go-mod core/c2/go.mod" in workflow
    assert "--vendor-manifest quality/vendor-manifest.json" in workflow
    assert "--include-tool-dependencies" in workflow
    assert "if-no-files-found: error" in workflow


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
