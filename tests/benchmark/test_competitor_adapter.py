"""Product-specific competitor adapter normalization and scope tests."""

from __future__ import annotations

import json
import os
import urllib.request

import pytest

from core.benchmarks.competitors import adapter as adapter_module
from core.benchmarks.competitors.adapter import (
    ProductAdapterError,
    build_product_prompt,
    run_product_adapter,
)
from core.benchmarks.competitors.adapter import (
    main as adapter_main,
)
from core.benchmarks.schema import BenchmarkScenario

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

STRIX_IMAGE = (
    "ghcr.io/usestrix/strix-sandbox@"
    "sha256:2e3a7e63a90428979ce34fbf80a8e83bb375d0d1146597a5d74087a259ee925c"
)


def _scenario(
    *,
    target: str = "http://127.0.0.1:8080",
    findings: list[dict] | None = None,
) -> BenchmarkScenario:
    normalization = findings or [
        {
            "finding_id": "service.http.8080",
            "reported_contains": ["HTTP service on port 8080"],
            "verified_contains": ["OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080"],
        },
        {
            "finding_id": "endpoint.health",
            "reported_contains": ["GET /health"],
            "verified_contains": ["OCTOBENCH_EVIDENCE_ENDPOINT_HEALTH"],
        },
        {
            "finding_id": "service.ssh.22",
            "reported_contains": ["22/tcp open ssh"],
            "verified_contains": ["OCTOBENCH_EVIDENCE_SERVICE_SSH_22"],
        },
    ]
    return BenchmarkScenario.from_dict(
        {
            "schema_version": "1.0",
            "scenario_id": "adapter-contract-v1",
            "name": "Adapter contract fixture",
            "category": "service_discovery_verification",
            "lab": {
                "version": "lab-v1",
                "authorization_ref": "approval-fixture-2026",
                "snapshot_ref": "sha256:lab-fixture",
                "reset_policy": "stateless-healthcheck-before-each-run",
            },
            "target": {
                "version": "target-v1",
                "address": target,
                "scope_ref": "scope-fixture-2026",
            },
            "model": {
                "provider": "system-recommended",
                "name": "system-recommended",
                "parameters": {"temperature": 0},
            },
            "tool_versions": {"adapter-protocol": "1.0"},
            "strategy_config": {
                "objective": "map the authorized service and health endpoint",
                "max_iterations": 2,
            },
            "seed": 7001,
            "budgets": {
                "max_tools": 12,
                "max_seconds": 60,
                "max_output_bytes": 200000,
                "max_model_tokens": 1000,
                "max_cost_usd": 2.0,
                "policy": {
                    "max_tools": "observational",
                    "max_seconds": "hard",
                    "max_output_bytes": "hard",
                    "max_model_tokens": "observational",
                    "max_cost_usd": "observational",
                },
            },
            "allowed_actions": [
                "observe_authorized_target",
                "verify_observed_evidence",
            ],
            "ground_truth": {
                "expected_findings": ["service.http.8080", "endpoint.health"],
                "forbidden_findings": ["service.ssh.22"],
            },
            "artifacts": {
                "normalization": {
                    "schema_version": "1.0",
                    "findings": normalization,
                }
            },
            "repetitions": 5,
            "tags": ["authorized-lab", "adapter-contract"],
        }
    )


def _environment(**updates: str) -> dict[str, str]:
    result = {
        "OCTOBENCH_ACK_AUTHORIZED": "YES",
        "OCTOBENCH_ACK_ISOLATED_HOST": "YES",
        "STRIX_IMAGE": STRIX_IMAGE,
        "PATH": os.environ.get("PATH", ""),
    }
    result.update(updates)
    return result


def _fake_executable(tmp_path, body: str, name: str = "fake-product"):
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_prompt_is_neutral_and_does_not_leak_ground_truth_or_matchers():
    scenario = _scenario()

    prompt = build_product_prompt(scenario, scenario.target["address"])

    assert "map the authorized service" in prompt
    assert "OCTOBENCH_EVIDENCE_" in prompt
    assert "service.http.8080" not in prompt
    assert "endpoint.health" not in prompt
    assert "ground_truth" not in prompt


def test_strix_exit_two_is_success_and_output_is_canonically_normalized(tmp_path):
    executable = _fake_executable(
        tmp_path,
        """
case "$*" in *"--max-budget-usd 2"*) ;; *) exit 64 ;; esac
case "$*" in *"--scan-mode quick"*) ;; *) exit 63 ;; esac
[ "$STRIX_IMAGE" = "ghcr.io/usestrix/strix-sandbox@sha256:2e3a7e63a90428979ce34fbf80a8e83bb375d0d1146597a5d74087a259ee925c" ] || exit 65
[ "$STRIX_TELEMETRY" = "false" ] || exit 66
[ "$STRIX_LLM" = "ollama/qwen3.5:9b" ] || exit 67
[ "$LLM_API_BASE" = "http://127.0.0.1:11434" ] || exit 68
[ -z "$LLM_API_KEY" ] || exit 69
echo 'HTTP service on port 8080'
echo 'OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080'
echo 'GET /health'
echo 'tool_calls: 4'
exit 2
""",
    )

    result = run_product_adapter(
        "strix",
        _scenario(),
        environment=_environment(
            OCTOBENCH_STRIX_BIN=str(executable),
            STRIX_LLM="ollama/qwen3.5:9b",
            LLM_API_BASE="http://127.0.0.1:11434",
        ),
    )

    assert result["status"] == "succeeded"
    assert result["reported_findings"] == ["service.http.8080", "endpoint.health"]
    assert result["verified_findings"] == ["service.http.8080"]
    assert result["coverage_gaps"] == []
    assert result["actions"] == []
    assert result["metrics"]["tool_calls"] == 4.0
    assert result["metrics"]["evidence_completeness"] == 0.5
    assert result["error_class"] == ""
    assert result["artifact_refs"][0].startswith("sha256:")
    serialized = json.dumps(result)
    assert "OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080" not in serialized
    assert str(executable) not in serialized


def test_strix_execution_failure_reports_only_stable_exit_class(tmp_path):
    executable = _fake_executable(
        tmp_path,
        "echo 'provider response may contain sensitive detail'\nexit 1",
    )

    result = run_product_adapter(
        "strix",
        _scenario(),
        environment=_environment(
            OCTOBENCH_STRIX_BIN=str(executable),
            STRIX_LLM="ollama/qwen3.5:9b",
            LLM_API_BASE="http://127.0.0.1:11434",
        ),
    )

    assert result["status"] == "failed"
    assert result["error_class"] == "ProductExitCode1"
    assert result["artifact_refs"][0].startswith("sha256:")
    assert "sensitive detail" not in json.dumps(result)


def test_runtime_target_override_uses_private_lab_address(tmp_path):
    executable = _fake_executable(
        tmp_path,
        """
case "$*" in
  *"--target http://10.20.30.40:8080"*)
    echo 'HTTP service on port 8080'
    echo 'OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080'
    ;;
  *) exit 9 ;;
esac
""",
    )

    result = run_product_adapter(
        "strix",
        _scenario(target="http://octobench-lab.internal:8080"),
        environment=_environment(
            OCTOBENCH_STRIX_BIN=str(executable),
            OCTOBENCH_TARGET_URL="http://10.20.30.40:8080",
        ),
    )

    assert result["status"] == "succeeded"
    assert result["verified_findings"] == ["service.http.8080"]


def test_pentestgpt_receives_the_manifest_model_as_an_explicit_cli_argument(tmp_path):
    executable = _fake_executable(
        tmp_path,
        """
case "$*" in
  *"--target http://127.0.0.1:8080 --model claude-test-model --non-interactive"*) ;;
  *) exit 65 ;;
esac
[ "$PENTESTGPT_AUTH_MODE" = "anthropic" ] || exit 66
echo 'OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080'
""",
    )

    result = run_product_adapter(
        "pentestgpt",
        _scenario(),
        environment=_environment(
            OCTOBENCH_PENTESTGPT_BIN=str(executable),
            OCTOBENCH_PENTESTGPT_MODEL="claude-test-model",
            ANTHROPIC_API_KEY="test-only",
        ),
    )

    assert result["status"] == "succeeded"
    assert result["verified_findings"] == ["service.http.8080"]


def test_adapter_fails_closed_for_authorization_and_public_targets(tmp_path):
    executable = _fake_executable(tmp_path, "exit 0")

    with pytest.raises(ProductAdapterError, match="authorization_ack_required"):
        run_product_adapter(
            "strix",
            _scenario(),
            environment={"OCTOBENCH_STRIX_BIN": str(executable)},
        )
    with pytest.raises(ProductAdapterError, match="isolation_ack_required"):
        run_product_adapter(
            "strix",
            _scenario(),
            environment={
                "OCTOBENCH_ACK_AUTHORIZED": "YES",
                "OCTOBENCH_STRIX_BIN": str(executable),
                "STRIX_IMAGE": STRIX_IMAGE,
            },
        )
    with pytest.raises(ProductAdapterError, match="public_target_rejected"):
        run_product_adapter(
            "strix",
            _scenario(target="https://8.8.8.8"),
            environment=_environment(OCTOBENCH_STRIX_BIN=str(executable)),
        )


def test_adapter_rejects_incomplete_normalization_contract(tmp_path):
    executable = _fake_executable(tmp_path, "exit 0")
    scenario = _scenario(
        findings=[
            {
                "finding_id": "service.http.8080",
                "verified_contains": ["OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080"],
            }
        ]
    )

    with pytest.raises(ProductAdapterError, match="normalization_missing_ground_truth_id"):
        run_product_adapter(
            "strix",
            scenario,
            environment=_environment(OCTOBENCH_STRIX_BIN=str(executable)),
        )


def test_tool_budget_overrun_is_invalid(tmp_path):
    executable = _fake_executable(
        tmp_path,
        "echo 'tool_calls: 99'; exit 0",
    )

    result = run_product_adapter(
        "strix",
        _scenario(),
        environment=_environment(OCTOBENCH_STRIX_BIN=str(executable)),
    )

    assert result["status"] == "invalid"
    assert result["metrics"]["tool_calls"] == 99.0


def test_reported_observational_budget_overrun_is_invalid(tmp_path):
    executable = _fake_executable(
        tmp_path,
        "echo 'total_tokens: 1001'; echo 'api_cost_usd: 2.01'; exit 0",
    )

    result = run_product_adapter(
        "strix",
        _scenario(),
        environment=_environment(OCTOBENCH_STRIX_BIN=str(executable)),
    )

    assert result["status"] == "invalid"
    assert result["metrics"]["model_tokens"] == 1001.0
    assert result["metrics"]["api_cost_usd"] == 2.01


def test_missing_vendor_telemetry_stays_absent_and_prompt_file_cannot_match(tmp_path):
    executable = _fake_executable(tmp_path, "exit 0")

    result = run_product_adapter(
        "strix",
        _scenario(),
        environment=_environment(OCTOBENCH_STRIX_BIN=str(executable)),
    )

    assert result["status"] == "succeeded"
    assert result["reported_findings"] == []
    assert result["verified_findings"] == []
    assert "tool_calls" not in result["metrics"]
    assert "model_tokens" not in result["metrics"]
    assert "api_cost_usd" not in result["metrics"]


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        (
            "http://10.20.30.40:8080/scope?q=1#ignored",
            "http://10.20.30.40:8080/scope?q=1",
        ),
        (
            "https://10.20.30.40/health",
            "https://10.20.30.40:443/health",
        ),
        ("10.20.30.40", "http://10.20.30.40:80/"),
    ],
)
def test_octopus_target_is_an_exact_url_with_explicit_port(target, expected):
    assert adapter_module._octopus_exact_target(target) == expected


def test_octopus_adapter_keeps_exact_scope_and_skips_broad_recon(monkeypatch, tmp_path):
    target = "http://10.20.30.40:8080/scope?q=1"
    observed = {}

    def exact_probe(probe_target, timeout, max_output):
        observed["probe"] = (probe_target, timeout, max_output)
        return f"URL: {probe_target}\n8080/tcp open http\nStatus: 200"

    class FakeFactStore:
        def get_facts(self, scan_id, scan_target):
            observed["facts"] = (scan_id, scan_target)
            return []

    class FakePipeline:
        def __init__(self, database):
            observed["database"] = database
            self.fact_store = FakeFactStore()
            self.tools_run_count = 2

        def run_scan(self, scan_id, scan_target, **kwargs):
            observed["scan"] = (scan_id, scan_target, kwargs)
            return {"status": "done"}

        def trace_report(self, scan_id, scan_target):
            observed["trace"] = (scan_id, scan_target)
            return {}

    def reject_broad_recon(*_args, **_kwargs):
        pytest.fail("Octopus benchmark adapter must not run host-wide recon")

    monkeypatch.setattr(adapter_module, "_octopus_exact_http_probe", exact_probe)
    monkeypatch.setattr("core.ai.pipeline.AIPipeline", FakePipeline)
    monkeypatch.setattr("core.recon.recon_engine.run_async_recon", reject_broad_recon)

    outcome = adapter_module._run_octopus(
        _scenario(target=target),
        target,
        tmp_path,
        timeout=10.0,
        max_output=200_000,
    )

    assert outcome.status == "succeeded"
    assert outcome.metrics["tool_calls"] == 3.0
    assert observed["probe"] == (target, 10.0, 200_000)
    assert observed["scan"][1] == target
    assert observed["scan"][2]["raw_scan"].startswith(f"URL: {target}")
    assert observed["facts"][1] == target
    assert observed["trace"][1] == target


def test_octopus_adapter_cannot_succeed_during_protocol_completion_grace(
    monkeypatch,
    tmp_path,
):
    class FakeFactStore:
        @staticmethod
        def get_facts(_scan_id, _scan_target):
            return []

    class FakePipeline:
        def __init__(self, _database):
            self.fact_store = FakeFactStore()
            self.tools_run_count = 0

        @staticmethod
        def run_scan(_scan_id, _scan_target, **_kwargs):
            return {"status": "done"}

        @staticmethod
        def trace_report(_scan_id, _scan_target):
            return {}

    clock = iter((100.0, 110.1))
    monkeypatch.setattr(adapter_module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(
        adapter_module,
        "_octopus_exact_http_probe",
        lambda *_args: "8080/tcp open http",
    )
    monkeypatch.setattr("core.ai.pipeline.AIPipeline", FakePipeline)

    outcome = adapter_module._run_octopus(
        _scenario(),
        "http://127.0.0.1:8080",
        tmp_path,
        timeout=10.0,
        max_output=200_000,
    )

    assert outcome.status == "timeout"
    assert outcome.duration_seconds == pytest.approx(10.1)


def test_octopus_probe_requests_only_exact_url_without_proxy_or_redirect(monkeypatch):
    target = "http://127.0.0.1:8080/health?deep=1"
    observed = {}

    class FakeResponse:
        def __init__(self):
            self.status = 200
            self.headers = {"Server": "fixture", "Content-Type": "text/plain"}

        def read(self, maximum):
            observed["read_maximum"] = maximum
            return b"OCTOBENCH_EVIDENCE_ENDPOINT_HEALTH"

        def getcode(self):
            return self.status

        def close(self):
            observed["closed"] = True

    class FakeOpener:
        def open(self, request, timeout):
            observed["request"] = request
            observed["timeout"] = timeout
            return FakeResponse()

    def build_opener(*handlers):
        observed["handlers"] = handlers
        return FakeOpener()

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)

    output = adapter_module._octopus_exact_http_probe(target, 9.0, 4_096)

    assert observed["request"].full_url == target
    assert observed["request"].method == "GET"
    assert observed["timeout"] == 9.0
    assert observed["read_maximum"] == 4_096
    assert observed["closed"] is True
    assert any(isinstance(item, urllib.request.ProxyHandler) and not item.proxies for item in observed["handlers"])
    assert any(isinstance(item, adapter_module._NoRedirectHandler) for item in observed["handlers"])
    assert f"URL: {target}" in output
    assert "8080/tcp open http" in output
    assert "OCTOBENCH_EVIDENCE_ENDPOINT_HEALTH" in output


def test_pentagi_graphql_adapter_collects_structured_usage(monkeypatch):
    calls = []

    def graphql_request(endpoint, token, query, variables, **_kwargs):
        calls.append((endpoint, token, variables))
        if "BenchmarkRuntime" in query:
            return {"settings": {"version": "2.1.0"}}
        if "createFlow" in query:
            return {"createFlow": {"id": "17", "status": "created", "title": "test"}}
        if "deleteFlow" in query:
            return {"deleteFlow": "success"}
        return {
            "flow": {
                "id": "17",
                "status": "finished",
                "title": "test",
                "provider": {"name": "openai", "type": "openai"},
            },
            "tasks": [
                {
                    "id": "1",
                    "title": "recon",
                    "status": "finished",
                    "input": "",
                    "result": ("HTTP service on port 8080 OCTOBENCH_EVIDENCE_SERVICE_HTTP_8080 GET /health"),
                }
            ],
            "messageLogs": [],
            "agentLogs": [],
            "toolCallLogs": [
                {
                    "id": "1",
                    "status": "finished",
                    "name": "http_probe",
                    "args": "{}",
                    "result": "ok",
                    "durationSeconds": 1.0,
                }
            ],
            "usageStatsByFlow": {
                "totalUsageIn": 100,
                "totalUsageOut": 50,
                "totalUsageCostIn": 0.1,
                "totalUsageCostOut": 0.2,
            },
            "usageStatsByModelAgentsForFlow": [
                {
                    "model": "benchmark-model",
                    "provider": "openai",
                    "agentTypes": ["primary_agent"],
                    "stats": {
                        "totalUsageIn": 100,
                        "totalUsageOut": 50,
                        "totalUsageCostIn": 0.1,
                        "totalUsageCostOut": 0.2,
                    },
                }
            ],
        }

    monkeypatch.setattr(adapter_module, "_graphql_request", graphql_request)
    result = run_product_adapter(
        "pentagi",
        _scenario(),
        environment=_environment(
            OCTOBENCH_PENTAGI_URL="http://127.0.0.1:8443",
            OCTOBENCH_PENTAGI_TOKEN="test-token",
            OCTOBENCH_PENTAGI_PROVIDER="openai",
            OCTOBENCH_PENTAGI_MODEL="benchmark-model",
        ),
    )

    assert len(calls) == 4
    assert all(item[1] == "test-token" for item in calls)
    assert result["status"] == "succeeded"
    assert result["reported_findings"] == ["service.http.8080", "endpoint.health"]
    assert result["verified_findings"] == ["service.http.8080"]
    assert result["metrics"]["tool_calls"] == 1.0
    assert result["metrics"]["model_tokens"] == 150.0
    assert result["metrics"]["api_cost_usd"] == pytest.approx(0.3)
    assert result["metrics"]["runtime_attested"] == 1.0
    assert result["metrics"]["cleanup_succeeded"] == 1.0


def test_pentagi_base_url_is_a_canonical_origin():
    assert adapter_module._pentagi_base_origin("HTTP://LOCALHOST:80/") == "http://localhost"
    assert (
        adapter_module._pentagi_base_origin("https://127.0.0.1:8443/")
        == "https://127.0.0.1:8443"
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8443/api",
        "http://localhost:8443/?tenant=1",
        "http://localhost:8443/#settings",
    ],
)
def test_pentagi_base_url_rejects_path_query_and_fragment(base_url):
    with pytest.raises(ProductAdapterError, match="invalid_pentagi_base_origin"):
        adapter_module._pentagi_base_origin(base_url)


def test_pentagi_timeout_reserves_cleanup_grace_for_stop_and_delete(monkeypatch):
    class FakeClock:
        def __init__(self):
            self.now = 100.0

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            self.now += seconds

    clock = FakeClock()
    calls = []

    def graphql_request(_endpoint, _token, query, _variables, *, timeout, **_kwargs):
        if "StopBenchmarkFlow" in query:
            label = "stop"
            calls.append((label, clock.now, timeout))
            clock.now += timeout
            return {"stopFlow": True}
        if "DeleteBenchmarkFlow" in query:
            label = "delete"
            calls.append((label, clock.now, timeout))
            clock.now += timeout
            return {"deleteFlow": "success"}
        if "BenchmarkRuntime" in query:
            label = "runtime"
            clock.now += 5.0
            result = {"settings": {"version": "2.1.0"}}
        elif "CreateBenchmarkFlow" in query:
            label = "create"
            clock.now += 5.0
            result = {"createFlow": {"id": "17", "status": "created"}}
        else:
            label = "flow"
            clock.now = 145.0
            result = {"flow": {"id": "17", "status": "running"}}
        calls.append((label, clock.now, timeout))
        return result

    monkeypatch.setattr(adapter_module.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(adapter_module.time, "sleep", clock.sleep)
    monkeypatch.setattr(adapter_module, "_graphql_request", graphql_request)
    monkeypatch.setattr(adapter_module, "_pentagi_ssl_context", lambda _environment: object())

    outcome = adapter_module._run_pentagi(
        _scenario(),
        "http://127.0.0.1:8080",
        "benchmark prompt",
        _environment(
            OCTOBENCH_PENTAGI_URL="http://127.0.0.1:8443",
            OCTOBENCH_PENTAGI_TOKEN="test-token",
            OCTOBENCH_PENTAGI_PROVIDER="openai",
            OCTOBENCH_PENTAGI_MODEL="benchmark-model",
        ),
        timeout=60.0,
        max_output=200_000,
    )

    assert outcome.status == "timeout"
    assert outcome.metrics["cleanup_succeeded"] == 1.0
    assert [item[0] for item in calls] == ["runtime", "create", "flow", "stop", "delete"]
    stop_call = next(item for item in calls if item[0] == "stop")
    delete_call = next(item for item in calls if item[0] == "delete")
    assert stop_call[1:] == (145.0, 7.0)
    assert delete_call[1:] == (152.0, 7.0)
    assert clock.now == 159.0


def test_pentagi_runtime_attestations_fail_closed_on_release_or_model_drift():
    with pytest.raises(ProductAdapterError, match="pentagi_release_mismatch"):
        adapter_module._validate_pentagi_release({"settings": {"version": "2.2.0"}})

    with pytest.raises(ProductAdapterError, match="pentagi_model_mismatch"):
        adapter_module._validate_pentagi_execution(
            {
                "flow": {"provider": {"name": "openai"}},
                "usageStatsByModelAgentsForFlow": [
                    {"model": "different-model", "provider": "openai"}
                ],
            },
            expected_provider="openai",
            expected_model="benchmark-model",
        )


def test_cli_writes_protocol_failure_without_exception_details(tmp_path, monkeypatch):
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(_scenario().to_dict()), encoding="utf-8")
    output = tmp_path / "result.json"
    monkeypatch.delenv("OCTOBENCH_ACK_AUTHORIZED", raising=False)

    return_code = adapter_main(
        [
            "--system",
            "strix",
            "--scenario",
            str(scenario_path),
            "--output",
            str(output),
        ]
    )

    assert return_code == 0
    assert json.loads(output.read_text()) == {
        "status": "failed",
        "actions": [],
        "reported_findings": [],
        "verified_findings": [],
        "coverage_gaps": [],
        "metrics": {},
        "duration_seconds": 0.0,
        "artifact_refs": [],
        "error_class": "ProductAdapterFailure",
    }
