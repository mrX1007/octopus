"""The checked-in live fixture remains stateless, read-only and deterministic."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

ROOT = Path(__file__).parents[2]
LAB_DIRECTORY = ROOT / "benchmarks" / "competitors" / "lab"
LAB_APP = LAB_DIRECTORY / "app.py"
CAMPAIGN_SCENARIOS = (
    ROOT
    / "benchmarks"
    / "competitors"
    / "campaigns"
    / "linux-blackbox-v1"
    / "scenarios"
    / "authorized-discovery-v1.json",
    ROOT
    / "benchmarks"
    / "competitors"
    / "campaigns"
    / "linux-blackbox-small-model-v1"
    / "scenarios"
    / "authorized-discovery-altered-small-model-stress-v1.json",
)


def _lab_module():
    spec = importlib.util.spec_from_file_location("octobench_fixture", LAB_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("path", "status", "evidence"),
    [
        ("/", 200, "OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080"),
        ("/health?cache=no", 200, "OCTOBENCH_EVIDENCE_ENDPOINT_HEALTH"),
        ("/api/items", 200, "OCTOBENCH_EVIDENCE_ENDPOINT_API_ITEMS"),
        ("/admin/status", 200, "OCTOBENCH_EVIDENCE_ENDPOINT_ADMIN_STATUS"),
        ("/missing", 404, ""),
    ],
)
def test_fixture_routes_are_deterministic(path, status, evidence):
    lab = _lab_module()

    first = lab.route(path)
    second = lab.route(path)

    assert first == second
    assert first[0] == status
    assert evidence.encode() in first[2]
    assert first[3]["Cache-Control"] == "no-store"


def test_openapi_document_exposes_only_read_only_fixture_routes():
    lab = _lab_module()

    status, content_type, body, _headers = lab.route("/openapi.json")
    payload = json.loads(body)

    assert status == 200
    assert content_type == "application/json"
    assert payload["x-octobench-evidence"] == "OCTOBENCH_EVIDENCE_ENDPOINT_OPENAPI"
    assert payload["paths"] == {
        "/api/items": {"get": {"operationId": "listItems"}},
        "/health": {"get": {"operationId": "health"}},
    }


def test_health_contract_is_versioned_and_machine_readable():
    lab = _lab_module()

    status, content_type, body, _headers = lab.route("/__octobench_health")

    assert status == 200
    assert content_type == "application/json"
    assert json.loads(body) == {
        "schema_version": "1.0",
        "status": "healthy",
        "lab_version": "discovery-lab-v1",
        "evidence": "OCTOBENCH_EVIDENCE_ENDPOINT_HEALTH",
    }


@pytest.mark.parametrize("scenario_path", CAMPAIGN_SCENARIOS)
def test_campaign_snapshot_refs_match_the_checked_in_lab_fixture(
    scenario_path: Path,
):
    scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
    fixture_paths = (
        LAB_DIRECTORY / "app.py",
        LAB_DIRECTORY / "Dockerfile",
        LAB_DIRECTORY / "compose.yaml",
    )
    expected_refs = [
        f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        for path in fixture_paths
    ]

    assert scenario["lab"]["snapshot_ref"] == expected_refs[0]
    assert scenario["artifacts"]["input_refs"] == expected_refs


def test_compose_fixture_is_private_read_only_and_has_a_tolerant_healthcheck():
    dockerfile = (LAB_DIRECTORY / "Dockerfile").read_text(encoding="utf-8")
    compose = (LAB_DIRECTORY / "compose.yaml").read_text(encoding="utf-8")

    assert "FROM python:3.12.10-alpine3.21@sha256:" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "--interval=15s --timeout=15s --start-period=5s --retries=8" in dockerfile
    assert '"${OCTOBENCH_LAB_BIND:-127.0.0.1}' in compose
    assert "read_only: true" in compose
    assert "cap_drop:\n      - ALL" in compose
    assert "no-new-privileges:true" in compose
    assert "interval: 15s" in compose
    assert "timeout: 15s" in compose
