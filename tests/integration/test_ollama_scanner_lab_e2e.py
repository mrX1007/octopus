"""Live Octopus + Ollama + Nmap + vulnerable-lab integration contract."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.external_tools,
    pytest.mark.slow,
]

_RUN_E2E = os.environ.get("OCTOPUS_RUN_OLLAMA_LAB_E2E", "").strip() == "1"


def _api_json(url: str, *, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    with urlopen(request, timeout=120) as response:
        assert response.status == 200
        decoded = json.loads(response.read().decode("utf-8"))
    assert isinstance(decoded, dict)
    return decoded


def _ollama_api_root(generate_url: str) -> str:
    parsed = urlsplit(generate_url)
    assert parsed.scheme == "http", "the E2E Ollama endpoint must use loopback HTTP"
    assert parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    assert parsed.path.rstrip("/") == "/api/generate"
    return f"{parsed.scheme}://{parsed.netloc}"


@pytest.mark.skipif(
    not _RUN_E2E,
    reason="set OCTOPUS_RUN_OLLAMA_LAB_E2E=1 after starting the isolated lab and Ollama",
)
def test_live_ollama_nmap_lab_produces_evidence_report(tmp_path: Path) -> None:
    """Exercise every live boundary and preserve the final report as an artifact."""

    target = os.environ.get("OCTOPUS_E2E_TARGET", "127.0.0.1").strip()
    port = int(os.environ.get("OCTOPUS_E2E_PORT", "18080"))
    generate_url = os.environ.get(
        "OCTOPUS_OLLAMA_URL",
        "http://127.0.0.1:11434/api/generate",
    ).strip()
    model = os.environ.get("OCTOPUS_OLLAMA_MODEL", "qwen2.5:0.5b").strip()
    expected_model_id = os.environ.get(
        "OCTOPUS_E2E_MODEL_ID_PREFIX",
        "a8b0c5157701",
    ).strip()

    assert target == "127.0.0.1", "the intentionally vulnerable fixture is loopback-only"
    assert 1024 <= port <= 65535
    assert shutil.which("nmap"), "the opt-in lane requires a real Nmap executable"

    api_root = _ollama_api_root(generate_url)
    version_payload = _api_json(f"{api_root}/api/version")
    expected_ollama_version = os.environ.get("OCTOPUS_E2E_OLLAMA_VERSION", "0.18.3")
    assert version_payload.get("version") == expected_ollama_version

    tags_payload = _api_json(f"{api_root}/api/tags")
    models = tags_payload.get("models") or []
    model_record = next(
        (
            item
            for item in models
            if isinstance(item, dict) and str(item.get("name") or item.get("model") or "") == model
        ),
        None,
    )
    assert model_record is not None, f"Ollama model is not loaded: {model}"
    assert str(model_record.get("digest") or "").removeprefix("sha256:").startswith(expected_model_id)

    generation = _api_json(
        generate_url,
        payload={
            "model": model,
            "prompt": 'Return exactly this JSON object: {"octopus_e2e":"ready"}',
            "stream": False,
            "format": "json",
            "options": {"temperature": 0, "num_ctx": 2048, "num_predict": 32},
        },
    )
    assert not generation.get("error")
    generated_payload = json.loads(str(generation.get("response") or ""))
    assert generated_payload.get("octopus_e2e") == "ready"

    traversal_query = urlencode({"file": "../fixtures/etc/passwd"})
    with urlopen(f"http://{target}:{port}/download?{traversal_query}", timeout=10) as response:
        traversal_body = response.read().decode("utf-8")
        assert response.status == 200
        assert response.headers.get("X-Octopus-Lab-Finding") == "path-traversal"
    assert "OCTOPUS_E2E_PATH_TRAVERSAL" in traversal_body

    from core.execution import CancellationContext, ExecutionContext
    from core.tools.public import dispatch_registered_tool

    scanner_context = ExecutionContext.operator(
        actor="ollama-scanner-lab-e2e",
        approval_id="loopback-fixture",
        target_scope=(target,),
        allow_active_tools=True,
        max_runtime_seconds=120,
        max_output_bytes=2_000_000,
        cancellation=CancellationContext.with_timeout(120),
    )
    scanner_command = f"nmap -Pn -sT -sV --version-light -p {port} {target}"
    nmap_output = dispatch_registered_tool(scanner_command, scanner_context)
    assert not nmap_output.startswith("[!]"), nmap_output
    assert re.search(rf"(?m)^\s*{port}/tcp\s+open\s+", nmap_output), nmap_output

    from core.ai.pipeline import AIPipeline
    from core.ai.report_schema import validate_evidence_report

    scan_id = "ollama-scanner-lab-e2e"
    pipeline = AIPipeline(db_path=str(tmp_path / "facts.db"))
    pipeline.run_scan(
        scan_id,
        target,
        max_iterations=1,
        max_tools=1,
        max_time_minutes=3,
        raw_scan=nmap_output,
        cancellation=CancellationContext.with_timeout(240),
    )
    report = pipeline.trace_report(scan_id, target)
    machine_report = report["machine_report"]

    assert report["schema_version"] == "1.0"
    assert machine_report["schema_version"] == "1.0"
    assert validate_evidence_report(machine_report) == ()
    assert any(
        item.get("fact_type") == "port_open" and str(item.get("fact_value") or "").startswith(f"{port}/tcp")
        for item in machine_report["evidence_index"]
    )
    assert any(
        item.get("kind") == "port_open" and str(item.get("detail") or "").startswith(f"{port}/tcp")
        for item in machine_report["sections"]["observations"]
    )
    assert any(event.get("role") == "director" and event.get("status") == "ok" for event in report["llm_events"]), (
        report["llm_events"]
    )

    artifact_dir = Path(os.environ.get("OCTOPUS_E2E_ARTIFACT_DIR", str(tmp_path / "artifacts")))
    artifact_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifact_dir / "trace-report.json"
    scanner_path = artifact_dir / "nmap-output.txt"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    scanner_path.write_text(nmap_output, encoding="utf-8")
    assert (
        json.loads(report_path.read_text(encoding="utf-8"))["machine_report"]["report_id"]
        == machine_report["report_id"]
    )
