"""Canonical exporter parity and application-version contracts."""

from __future__ import annotations

import ast
import copy
import csv
import json
import re
import stat
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

import export
from core.ai.report_export import (
    MachineReportError,
    extract_machine_report,
    legacy_session_to_machine_report,
    project_machine_report,
)
from core.ai.report_schema import build_evidence_report, validate_evidence_report
from core.version import APPLICATION_VERSION

pytestmark = pytest.mark.contract


def _canonical_report() -> dict:
    return build_evidence_report(
        "scan-export-contract",
        "example.test",
        [
            {
                "id": 1,
                "type": "vulnerability",
                "value": "Verified fixture finding",
                "severity": "HIGH",
                "host": "example.test",
                "source": "fixture",
                "assessment": {
                    "assessment_id": "assessment-1",
                    "status": "verified",
                    "reason": "The bounded fixture check matched.",
                    "evidence_fact_ids": [1],
                    "source_execution_ids": ["execution-1"],
                },
            },
            {
                "id": 2,
                "type": "port_open",
                "value": "443/tcp (https)",
                "host": "example.test",
                "source": "fixture",
            },
            {
                "id": 3,
                "type": "exploit_attempted",
                "value": "Verification attempt",
                "host": "example.test",
                "source": "fixture",
            },
        ],
    )


def test_export_ingress_accepts_only_canonical_envelope_or_explicit_legacy_adapter(
    sample_session_data,
):
    report = _canonical_report()

    assert extract_machine_report(report) == report
    assert extract_machine_report({"machine_report": report, "other": "ignored"}) == report
    adapted = legacy_session_to_machine_report(sample_session_data)
    assert validate_evidence_report(adapted) == ()
    assert adapted["legacy_adapter"]["source_schema"] == "octopus-db-session-v1"
    assert adapted["sections"]["verified_vulnerabilities"] == []
    assert len(adapted["sections"]["hypotheses_candidates"]) == 2
    assert {item["status"] for item in adapted["sections"]["hypotheses_candidates"]} == {"candidate"}

    with pytest.raises(MachineReportError, match="canonical machine_report"):
        extract_machine_report({"invented": "schema"})


def test_legacy_confidence_never_fabricates_verification(tmp_path):
    session = {
        "history": (41, "legacy.test", "today", "complete"),
        "vulns": [
            (
                1,
                41,
                "Stored confirmed label",
                "UNKNOWN",
                "443",
                "https",
                "No current assessment exists.",
                "CONFIRMED",
                "legacy-db",
                "",
                "",
                None,
            )
        ],
        "fixes": [],
        "exploits": [],
        "summary": None,
    }

    report = legacy_session_to_machine_report(session)

    assert report["sections"]["verified_vulnerabilities"] == []
    candidate = report["sections"]["hypotheses_candidates"][0]
    assert candidate["status"] == "candidate"
    assert candidate["assessment_status"] == "observed"
    assert candidate["severity"] == "INFO"
    csv_path = Path(export.export_csv(report, str(tmp_path)))
    with csv_path.open(encoding="utf-8", newline="") as handle:
        assert next(csv.DictReader(handle))["CVSS"] == "0.0"
    serialized = json.dumps(report, sort_keys=True)
    assert "legacy-assessment:" not in serialized
    assert "legacy://" not in serialized

    forged = copy.deepcopy(report)
    forged_candidate = forged["sections"]["hypotheses_candidates"][0]
    forged_candidate["status"] = "verified"
    forged_candidate["assessment_reasons"] = ["forged"]
    forged_candidate["source_execution_ids"] = ["legacy://forged"]
    assert any(error.startswith("legacy_item_cannot_be_verified:") for error in validate_evidence_report(forged))


def test_export_ingress_rejects_malformed_and_unbounded_extensions():
    mutations = []

    section_order = _canonical_report()
    section_order["section_order"] = 1
    mutations.append(section_order)

    summary = _canonical_report()
    summary["summary"] = []
    mutations.append(summary)

    scope = _canonical_report()
    scope["sections"]["verified_vulnerabilities"][0]["scope"] = "example.test"
    mutations.append(scope)

    legacy_adapter = _canonical_report()
    legacy_adapter["legacy_adapter"] = {"source_schema": "octopus-db-session-v1"}
    mutations.append(legacy_adapter)

    legacy_fields = _canonical_report()
    legacy_fields["sections"]["verified_vulnerabilities"][0]["legacy_fields"] = {"payload": "x" * 4_097}
    mutations.append(legacy_fields)

    extension = _canonical_report()
    extension["unversioned_extension"] = ["x"] * 10_000
    mutations.append(extension)

    for report in mutations:
        with pytest.raises(MachineReportError, match="invalid machine_report"):
            extract_machine_report(report)


def test_legacy_adapter_rejects_unbounded_rows_and_text():
    too_many_rows = {
        "history": (1, "target", "today", "complete"),
        "vulns": [(index,) for index in range(257)],
        "fixes": [],
        "exploits": [],
        "summary": None,
    }
    with pytest.raises(MachineReportError, match="supported bound"):
        legacy_session_to_machine_report(too_many_rows)

    oversized_text = {
        "history": (1, "target", "today", "complete"),
        "vulns": [(1, 1, "finding", "LOW", "", "", "x" * 4_097)],
        "fixes": [],
        "exploits": [],
        "summary": None,
    }
    with pytest.raises(MachineReportError, match="text bound"):
        legacy_session_to_machine_report(oversized_text)

    unexpected_extension = {
        "history": (1, "target", "today", "complete"),
        "vulns": [],
        "fixes": [],
        "exploits": [],
        "summary": None,
        "unversioned_extension": ["x"] * 10_000,
    }
    with pytest.raises(MachineReportError, match="unsupported fields"):
        legacy_session_to_machine_report(unexpected_extension)


def test_legacy_adapter_preserves_orphan_rows_and_relational_identity():
    session = {
        "history": (7, "target", "scan-date", "complete"),
        "vulns": [],
        "fixes": [(3, 7, 99, "Apply the orphaned remediation", "operator")],
        "exploits": [(4, 7, "attempt", "tool", "payload", "result", "notes")],
        "summary": (5, 7, "raw", "analysis", "MEDIUM", "generated-at"),
    }

    report = legacy_session_to_machine_report(session)
    orphan = report["sections"]["observations"][0]["legacy_fields"]
    attempt = report["sections"]["attempted_unverified"][0]["legacy_fields"]

    assert orphan == {
        "legacy_id": "99",
        "session_id": "7",
        "remediations": [
            {
                "id": "3",
                "session_id": "7",
                "text": "Apply the orphaned remediation",
                "source": "operator",
            }
        ],
    }
    assert attempt["legacy_id"] == "4"
    assert attempt["session_id"] == "7"
    assert report["legacy_adapter"]["summary_id"] == "5"
    assert report["legacy_adapter"]["summary_session_id"] == "7"
    assert report["legacy_adapter"]["generated_at"] == "generated-at"


def test_plaintext_legacy_secrets_never_reach_any_export(
    monkeypatch,
    sample_session_data,
    tmp_path,
):
    sentinel = "S3cr3t-PASS"
    session = copy.deepcopy(sample_session_data)
    vulnerability = list(session["vulns"][0])
    vulnerability[10] = f"sshpass -p {sentinel} ssh root@example.test"
    session["vulns"][0] = tuple(vulnerability)
    exploit = list(session["exploits"][0])
    exploit[4] = f"alice:{sentinel}"
    exploit[5] = f"password={sentinel}"
    session["exploits"][0] = tuple(exploit)
    monkeypatch.setattr(
        export,
        "CFG",
        {"reporting": {"include_raw_output": True}},
    )

    report = extract_machine_report(session, include_legacy_raw_output=True)
    assert sentinel not in json.dumps(report, sort_keys=True)
    assert sentinel not in json.dumps(project_machine_report(report), sort_keys=True)

    paths = (
        export.export_json(report, str(tmp_path)),
        export.export_csv(report, str(tmp_path)),
        export.export_html(report, str(tmp_path)),
        export.export_pdf(report, str(tmp_path)),
    )
    for path in paths:
        assert sentinel.encode() not in Path(path).read_bytes()


def test_plaintext_typed_secret_is_removed_from_direct_machine_report():
    sentinel = "C4nonical-PASS"
    unsafe = build_evidence_report(
        "scan-secret-contract",
        "secret.test",
        [
            {
                "id": 1,
                "type": "credential",
                "value": f"alice:{sentinel}",
                "host": "secret.test",
                "source": "fixture",
            }
        ],
    )
    assert sentinel in json.dumps(unsafe, sort_keys=True)

    safe = extract_machine_report(unsafe)

    serialized = json.dumps(safe, sort_keys=True)
    assert sentinel not in serialized
    assert "secret://" in serialized


def test_legacy_projection_fields_are_rendered_without_cross_format_loss(
    monkeypatch,
    sample_session_data,
    tmp_path,
):
    monkeypatch.setattr(
        export,
        "CFG",
        {"reporting": {"include_raw_output": True}},
    )
    report = extract_machine_report(
        sample_session_data,
        include_legacy_raw_output=True,
    )
    projected = project_machine_report(report)
    attempt = next(item for item in projected if item["tool"] == "curl")
    finding = next(item for item in projected if item["remediations"])
    assert finding["legacy_session_id"] == "1"

    csv_path = Path(export.export_csv(report, str(tmp_path)))
    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    attempt_row = next(row for row in rows if row["Tool"] == "curl")
    assert attempt_row["Payload"] == attempt["payload"]
    assert attempt_row["Result"] == attempt["result"]
    assert attempt_row["Notes"] == attempt["notes"]
    finding_row = next(row for row in rows if row["Item ID"] == finding["item_id"])
    assert json.loads(finding_row["Remediations"]) == finding["remediations"]

    html_payload = Path(export.export_html(report, str(tmp_path))).read_text(encoding="utf-8")
    for expected in (
        "../../etc/passwd",
        "Success",
        "Root file read achieved",
        "Upgrade Apache to &gt;= 2.4.51",
        "2026-06-15 10:00:00",
        "complete",
        "HIGH",
        "2026-06-15 10:30:00",
    ):
        assert expected in html_payload

    pdf_pairs: list[dict[str, str]] = []
    original_pairs = export._item_detail_pairs

    def capture_pairs(item):
        pairs = original_pairs(item)
        pdf_pairs.append(dict(pairs))
        return pairs

    monkeypatch.setattr(export, "_item_detail_pairs", capture_pairs)
    export.export_pdf(report, str(tmp_path))
    rendered_attempt = next(item for item in pdf_pairs if item.get("Tool") == "curl")
    assert rendered_attempt["Payload"] == attempt["payload"]
    assert rendered_attempt["Result"] == attempt["result"]
    assert rendered_attempt["Notes"] == attempt["notes"]


def test_distinct_snapshots_cannot_collide_on_export_filename(tmp_path):
    first = build_evidence_report(
        "scan-collision-contract",
        "collision.test",
        [
            {
                "id": 1,
                "type": "observation",
                "value": "First snapshot",
                "host": "collision.test",
                "source": "fixture",
            }
        ],
    )
    second = build_evidence_report(
        first["scan_id"],
        first["target"],
        [
            {
                "id": 1,
                "type": "observation",
                "value": "Changed snapshot",
                "host": first["target"],
                "source": "fixture",
            }
        ],
    )

    # Item identity is fact-ID based, so these reports intentionally exercise
    # the historical same-scan/same-report-id collision.
    assert first["report_id"] == second["report_id"]
    first_path = Path(export.export_json(first, str(tmp_path)))
    second_path = Path(export.export_json(second, str(tmp_path)))

    assert first_path != second_path
    assert json.loads(first_path.read_text()) == first
    assert json.loads(second_path.read_text()) == second


def test_all_formats_use_the_same_machine_report_projection(monkeypatch, tmp_path):
    report = _canonical_report()
    expected_ids = tuple(item["item_id"] for item in project_machine_report(report))
    projections: list[tuple[str, tuple[str, ...]]] = []
    original_project = export.project_machine_report

    def capture_projection(current):
        projected = original_project(current)
        projections.append((str(current["report_id"]), tuple(item["item_id"] for item in projected)))
        return projected

    monkeypatch.setattr(export, "project_machine_report", capture_projection)
    paths = {
        "json": Path(export.export_json(report, str(tmp_path))),
        "csv": Path(export.export_csv(report, str(tmp_path))),
        "html": Path(export.export_html(report, str(tmp_path))),
        "pdf": Path(export.export_pdf(report, str(tmp_path))),
    }

    assert all(path.is_file() and path.stat().st_size for path in paths.values())
    assert projections == [(report["report_id"], expected_ids)] * 4

    json_payload = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert json_payload == report
    with paths["csv"].open(encoding="utf-8", newline="") as handle:
        assert tuple(row["Item ID"] for row in csv.DictReader(handle)) == expected_ids
    html_payload = paths["html"].read_text(encoding="utf-8")
    assert all(f"data-item-id='{item_id}'" in html_payload for item_id in expected_ids)


def test_json_direct_report_and_pipeline_envelope_are_identical(tmp_path):
    report = _canonical_report()
    direct = Path(export.export_json(report, str(tmp_path / "direct")))
    envelope = Path(export.export_json({"machine_report": report}, str(tmp_path / "envelope")))

    assert json.loads(direct.read_text(encoding="utf-8")) == json.loads(envelope.read_text(encoding="utf-8"))


def test_every_user_facing_version_comes_from_the_single_owner(tmp_path):
    report = _canonical_report()
    html_payload = Path(export.export_html(report, str(tmp_path))).read_text(encoding="utf-8")
    assert f"OCTOPUS v{APPLICATION_VERSION}" in html_payload

    root = Path(__file__).resolve().parents[1]
    excluded_roots = {
        ".git",
        "benchmarks",
        "build",
        "dist",
        "scripts",
        "tests",
        "venv",
    }
    production_sources = tuple(
        path for path in root.rglob("*.py") if not excluded_roots.intersection(path.relative_to(root).parts)
    )
    owners: list[Path] = []
    dunder_owners: list[Path] = []
    for source_path in production_sources:
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id == "APPLICATION_VERSION":
                    owners.append(source_path)
                if isinstance(target, ast.Name) and target.id == "__version__":
                    dunder_owners.append(source_path)

    assert owners == [root / "core" / "version.py"]
    assert dunder_owners == [root / "core" / "version.py"]

    version_consumers = (
        root / "export.py",
        root / "shodan_module.py",
        root / "core" / "cli" / "application.py",
        root / "core" / "cli" / "main.py",
        root / "core" / "cli" / "presentation.py",
        root / "core" / "recon" / "recon_engine.py",
        root / "core" / "c2" / "builder.py",
        root / "core" / "killchain" / "orchestrator.py",
        root / "core" / "supervisor.py",
    )
    release_literal = re.compile(r"v?\d+\.\d+(?:\.\d+)?")
    for source_path in version_consumers:
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        imported = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "core.version"
            and any(alias.name == "APPLICATION_VERSION" for alias in node.names)
            for node in ast.walk(tree)
        )
        loads = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        hardcoded_releases = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and release_literal.fullmatch(node.value)
        }
        assert imported, source_path
        assert "APPLICATION_VERSION" in loads, source_path
        assert hardcoded_releases == set(), source_path

    stale_banner = re.compile(r"(?is)\bOCTOPUS\b.{0,80}?\bv?\d+\.\d+(?:\.\d+)?\b")
    for source_path in production_sources:
        if source_path == root / "core" / "version.py" or "benchmarks" in source_path.parts:
            continue
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        assert not any(
            stale_banner.search(node.value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ), source_path

    import core
    import octopus

    assert core.APPLICATION_VERSION == APPLICATION_VERSION
    assert core.__version__ == APPLICATION_VERSION
    assert octopus.__version__ == APPLICATION_VERSION
    with (root / "pyproject.toml").open("rb") as handle:
        package_metadata = tomllib.load(handle)
    assert package_metadata["project"]["dynamic"] == ["version"]
    assert "version" not in package_metadata["project"]
    assert package_metadata["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "core.version.__version__"}
    assert stat.S_IMODE((root / "export.py").stat().st_mode) & stat.S_IXUSR
