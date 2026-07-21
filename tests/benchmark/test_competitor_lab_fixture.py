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
V2_LAB_DIRECTORY = (
    ROOT / "benchmarks" / "competitors" / "labs" / "discovery-lab-v2"
)
V2_LAB_APP = V2_LAB_DIRECTORY / "app.py"
V2_SCENARIO_DIRECTORY = (
    ROOT
    / "benchmarks"
    / "competitors"
    / "campaigns"
    / "linux-blackbox-small-model-v2"
    / "scenarios"
)
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
    *tuple(sorted(V2_SCENARIO_DIRECTORY.glob("*.json"))),
)
V2_SURFACE_REQUESTS = {
    "authorized-linked-navigation-small-model-v2": (
        ("/", "OCTOBENCH_EVIDENCE_V2_LINKED_SERVICE"),
        ("/health", "OCTOBENCH_EVIDENCE_V2_LINKED_HEALTH"),
        ("/openapi.json", "OCTOBENCH_EVIDENCE_V2_LINKED_OPENAPI"),
        ("/api/items", "OCTOBENCH_EVIDENCE_V2_LINKED_ITEMS"),
    ),
    "authorized-openapi-contract-small-model-v2": (
        ("/", "OCTOBENCH_EVIDENCE_V2_CONTRACT_SERVICE"),
        ("/openapi.json", "OCTOBENCH_EVIDENCE_V2_CONTRACT_OPENAPI"),
        ("/api/widgets", "OCTOBENCH_EVIDENCE_V2_CONTRACT_WIDGETS"),
        ("/api/widget/7", "OCTOBENCH_EVIDENCE_V2_CONTRACT_WIDGET_7"),
    ),
    "authorized-relative-redirect-small-model-v2": (
        ("/", "OCTOBENCH_EVIDENCE_V2_REDIRECT_SERVICE"),
        ("/portal", "OCTOBENCH_EVIDENCE_V2_REDIRECT_PORTAL"),
        ("/status", "OCTOBENCH_EVIDENCE_V2_REDIRECT_STATUS"),
    ),
    "authorized-hypermedia-pagination-small-model-v2": (
        ("/", "OCTOBENCH_EVIDENCE_V2_HYPERMEDIA_SERVICE"),
        ("/api/items?page=1", "OCTOBENCH_EVIDENCE_V2_HYPERMEDIA_PAGE_1"),
        ("/api/items?page=2", "OCTOBENCH_EVIDENCE_V2_HYPERMEDIA_PAGE_2"),
        ("/api/items/7", "OCTOBENCH_EVIDENCE_V2_HYPERMEDIA_ITEM_7"),
    ),
}


def _lab_module(path: Path = LAB_APP):
    spec = importlib.util.spec_from_file_location(
        f"octobench_fixture_{path.parent.name}",
        path,
    )
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


@pytest.mark.parametrize(
    ("scenario_id", "requests"),
    V2_SURFACE_REQUESTS.items(),
)
def test_v2_surfaces_are_deterministic_and_scenario_isolated(
    scenario_id: str,
    requests: tuple[tuple[str, str], ...],
) -> None:
    lab = _lab_module(V2_LAB_APP)

    for target, evidence in requests:
        first = lab.route(target, scenario_id=scenario_id)
        second = lab.route(target, scenario_id=scenario_id)
        assert first == second
        assert evidence.encode() in first[2]
        assert first[3]["X-Octobench-Scenario"] == scenario_id

    all_targets = {
        target
        for surface_requests in V2_SURFACE_REQUESTS.values()
        for target, _evidence in surface_requests
    }
    observed = b"\n".join(
        lab.route(target, scenario_id=scenario_id)[2] for target in all_targets
    )
    foreign_evidence = {
        evidence.encode()
        for other_scenario, surface_requests in V2_SURFACE_REQUESTS.items()
        if other_scenario != scenario_id
        for _target, evidence in surface_requests
    }
    assert all(token not in observed for token in foreign_evidence)


def test_v2_health_attests_exact_selected_scenario() -> None:
    lab = _lab_module(V2_LAB_APP)
    scenario_id = "authorized-openapi-contract-small-model-v2"

    status, content_type, body, headers = lab.route(
        "/__octobench_health",
        scenario_id=scenario_id,
    )

    assert status == 200
    assert content_type == "application/json"
    assert headers["Cache-Control"] == "no-store"
    assert json.loads(body) == {
        "evidence": "OCTOBENCH_EVIDENCE_V2_HEALTH",
        "lab_version": "discovery-lab-v2",
        "scenario_id": scenario_id,
        "schema_version": "1.0",
        "status": "healthy",
    }


@pytest.mark.parametrize("scenario_path", CAMPAIGN_SCENARIOS)
def test_campaign_snapshot_refs_match_the_checked_in_lab_fixture(
    scenario_path: Path,
):
    scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
    fixture_directory = (
        V2_LAB_DIRECTORY
        if scenario["lab"]["version"] == "discovery-lab-v2"
        else LAB_DIRECTORY
    )
    fixture_paths = (
        fixture_directory / "app.py",
        fixture_directory / "Dockerfile",
        fixture_directory / "compose.yaml",
    )
    expected_refs = [
        f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        for path in fixture_paths
    ]

    assert scenario["lab"]["snapshot_ref"] == expected_refs[0]
    assert scenario["artifacts"]["input_refs"] == expected_refs


@pytest.mark.parametrize("fixture_directory", (LAB_DIRECTORY, V2_LAB_DIRECTORY))
def test_compose_fixture_is_private_read_only_and_has_a_tolerant_healthcheck(
    fixture_directory: Path,
) -> None:
    dockerfile = (fixture_directory / "Dockerfile").read_text(encoding="utf-8")
    compose = (fixture_directory / "compose.yaml").read_text(encoding="utf-8")

    assert "FROM python:3.12.10-alpine3.21@sha256:" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "--interval=15s --timeout=15s --start-period=5s --retries=8" in dockerfile
    assert '"${OCTOBENCH_LAB_BIND:-127.0.0.1}' in compose
    assert "read_only: true" in compose
    assert "cap_drop:\n      - ALL" in compose
    assert "no-new-privileges:true" in compose
    assert "interval: 15s" in compose
    assert "timeout: 15s" in compose
