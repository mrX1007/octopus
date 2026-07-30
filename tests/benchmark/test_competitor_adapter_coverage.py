"""Hermetic branch coverage for the competitor adapter boundary."""

from __future__ import annotations

import json
import math
import os
import signal
import ssl
import subprocess
import urllib.error
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from core.benchmarks.competitors import adapter
from core.benchmarks.schema import BenchmarkScenario
from core.execution import ExecutionCancelled

pytestmark = [pytest.mark.benchmark, pytest.mark.unit]

_STRIX_IMAGE = "fixture@sha256:" + "a" * 64


def _scenario(
    *,
    lab_version: str = "lab-v1",
    target: dict[str, Any] | None = None,
    strategy: dict[str, Any] | None = None,
    budgets: dict[str, Any] | None = None,
    ground_truth: dict[str, Any] | None = None,
    artifacts: dict[str, Any] | None = None,
) -> BenchmarkScenario:
    return BenchmarkScenario.from_dict(
        {
            "schema_version": "1.0",
            "scenario_id": "adapter-boundaries-v1",
            "name": "Adapter boundary fixture",
            "category": "service_discovery_verification",
            "lab": {
                "version": lab_version,
                "authorization_ref": "authorized-fixture",
                "snapshot_ref": "sha256:fixture",
                "reset_policy": "reset-before-run",
            },
            "target": target
            or {
                "version": "target-v1",
                "address": "http://127.0.0.1:8080",
                "scope_ref": "scope-fixture",
            },
            "model": {
                "provider": "fixture",
                "name": "fixture",
                "parameters": {},
            },
            "tool_versions": {"adapter": "1.0"},
            "strategy_config": strategy or {"objective": "inspect target"},
            "seed": 7,
            "budgets": budgets
            or {
                "max_tools": 5,
                "max_seconds": 60,
                "max_output_bytes": 4096,
                "max_model_tokens": 100,
                "max_cost_usd": 2,
                "policy": {
                    "max_tools": "observational",
                    "max_seconds": "hard",
                    "max_output_bytes": "hard",
                    "max_model_tokens": "observational",
                    "max_cost_usd": "observational",
                },
            },
            "allowed_actions": ["observe_authorized_target"],
            "ground_truth": ground_truth
            or {
                "expected_findings": ["finding.one"],
                "forbidden_findings": ["finding.bad"],
            },
            "artifacts": artifacts
            or {
                "normalization": {
                    "schema_version": "1.0",
                    "findings": [
                        {
                            "finding_id": "finding.one",
                            "reported_contains": ["reported one"],
                            "verified_contains": ["EVIDENCE_ONE"],
                        },
                        {
                            "finding_id": "finding.bad",
                            "reported_contains": ["reported bad"],
                            "verified_contains": ["EVIDENCE_BAD"],
                        },
                    ],
                }
            },
            "repetitions": 5,
        }
    )


def _environment(**updates: str) -> dict[str, str]:
    result = {
        "OCTOBENCH_ACK_AUTHORIZED": "YES",
        "OCTOBENCH_ACK_ISOLATED_HOST": "YES",
        "STRIX_IMAGE": _STRIX_IMAGE,
        "PATH": os.environ.get("PATH", ""),
    }
    result.update(updates)
    return result


def _outcome(**updates: Any) -> adapter.ProductOutcome:
    values: dict[str, Any] = {
        "status": "succeeded",
        "output_text": "reported one EVIDENCE_ONE",
        "duration_seconds": 1.0,
        "metrics": {},
        "error_class": "",
    }
    values.update(updates)
    return adapter.ProductOutcome(**values)


def _pentagi_payload(*, status: str = "finished") -> dict[str, Any]:
    return {
        "flow": {
            "id": "17",
            "status": status,
            "provider": {"name": "openai"},
        },
        "tasks": [{"result": "reported one EVIDENCE_ONE"}],
        "toolCallLogs": [{"id": "1"}],
        "usageStatsByFlow": {
            "totalUsageIn": 2,
            "totalUsageOut": 3,
            "totalUsageCostIn": 0.1,
            "totalUsageCostOut": 0.2,
        },
        "usageStatsByModelAgentsForFlow": [{"model": "model", "provider": "openai"}],
    }


def test_main_success_v3_failure_and_write_failure(monkeypatch, tmp_path):
    scenario = _scenario()
    output = tmp_path / "out.json"
    monkeypatch.setattr(adapter, "load_scenario", lambda _path: scenario)
    monkeypatch.setattr(adapter, "run_product_adapter", lambda *_args: {"status": "ok"})
    assert adapter.main(["--system", "strix", "--scenario", "x", "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == {"status": "ok"}

    v3 = _scenario(lab_version="discovery-lab-v3")
    monkeypatch.setattr(adapter, "load_scenario", lambda _path: v3)
    monkeypatch.setattr(adapter, "run_product_adapter", lambda *_args: (_ for _ in ()).throw(RuntimeError()))
    assert adapter.main(["--system", "strix", "--scenario", "x", "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["reported_claims"] == []

    monkeypatch.setattr(adapter, "load_scenario", lambda _path: (_ for _ in ()).throw(ValueError()))
    monkeypatch.setattr(adapter, "_atomic_write_json", lambda *_args: (_ for _ in ()).throw(OSError()))
    assert adapter.main(["--system", "strix", "--scenario", "x", "--output", str(output)]) == 2


def test_run_product_adapter_routes_and_normalizes(monkeypatch):
    scenario = _scenario()
    observed: list[str] = []

    def octopus(*_args):
        observed.append("octopus")
        return _outcome(metrics={"tool_calls": 6, "bad": math.nan})

    def pentagi(*_args):
        observed.append("pentagi")
        return _outcome(output_text="")

    def cli(profile, *_args):
        observed.append(profile)
        return _outcome(output_text="reported one", status="invalid")

    monkeypatch.setattr(adapter, "_run_octopus", octopus)
    monkeypatch.setattr(adapter, "_run_pentagi", pentagi)
    monkeypatch.setattr(adapter, "_run_cli_product", cli)

    result = adapter.run_product_adapter(" OCTOPUS ", scenario, environment=_environment())
    assert observed == ["octopus"]
    assert result["status"] == "invalid"
    assert result["error_class"] == "ReportedBudgetOverrun"
    assert "bad" not in result["metrics"]
    assert result["artifact_refs"][0].startswith("sha256:")

    result = adapter.run_product_adapter("pentagi", scenario, environment=_environment())
    assert observed[-1] == "pentagi"
    assert result["artifact_refs"] == []
    assert result["coverage_gaps"] == ["finding.one"]

    result = adapter.run_product_adapter("strix", scenario, environment=_environment())
    assert observed[-1] == "strix"
    assert result["status"] == "invalid"
    assert result["error_class"] == "ReportedBudgetOverrun"

    with pytest.raises(adapter.ProductAdapterError, match="unsupported_system"):
        adapter.run_product_adapter("unknown", scenario, environment=_environment())


def test_run_product_adapter_empty_truth_and_v3_claim_sources(monkeypatch):
    empty_truth = _scenario(
        ground_truth={"expected_findings": [], "forbidden_findings": []},
        artifacts={
            "normalization": {
                "schema_version": "1.0",
                "findings": [
                    {
                        "finding_id": "finding.one",
                        "reported_contains": ["one"],
                    }
                ],
            }
        },
    )
    monkeypatch.setattr(adapter, "_run_cli_product", lambda *_args: _outcome(output_text=""))
    result = adapter.run_product_adapter("strix", empty_truth, environment=_environment())
    assert result["metrics"]["evidence_completeness"] == 1.0

    v3 = _scenario(lab_version="discovery-lab-v3")
    monkeypatch.setattr(
        adapter,
        "_run_cli_product",
        lambda *_args: _outcome(output_text="Claim: token-a", reported_claims=None),
    )
    result = adapter.run_product_adapter("strix", v3, environment=_environment())
    assert result["reported_claims"] == ["token-a"]
    monkeypatch.setattr(
        adapter,
        "_run_cli_product",
        lambda *_args: _outcome(reported_claims=("canonical",)),
    )
    result = adapter.run_product_adapter("strix", v3, environment=_environment())
    assert result["reported_claims"] == ["canonical"]


def test_prompt_modes_default_and_size_limit(monkeypatch):
    scenario = _scenario(strategy={"objective": ""})
    assert "inventory and verify" in adapter.build_product_prompt(scenario, "http://localhost")
    v3 = _scenario(lab_version="discovery-lab-v3")
    assert "Claim: OCTOBENCH_V3_" in adapter.build_product_prompt(v3, "http://localhost")
    monkeypatch.setattr(adapter, "_MAX_PROMPT_BYTES", 1)
    with pytest.raises(adapter.ProductAdapterError, match="prompt_too_large"):
        adapter.build_product_prompt(scenario, "http://localhost")


class _FactStore:
    def __init__(self, value: Any = None, *, fail: bool = False):
        self.value = [] if value is None else value
        self.fail = fail

    def get_facts(self, *_args):
        if self.fail:
            raise RuntimeError("fixture")
        return self.value


class _Pipeline:
    def __init__(self, _database: str, *, run: Any = None):
        self.fact_store = _FactStore([{"detail": "fact"}])
        self.tools_run_count = 2
        self._run = run

    def run_scan(self, *_args, **kwargs):
        if isinstance(self._run, BaseException):
            cancellation = kwargs["cancellation"]
            if isinstance(self._run, ExecutionCancelled):
                cancellation.cancel(self._run.reason_code)
            raise self._run
        return self._run or {"status": "done"}

    def trace_report(self, *_args):
        return {"trace": "ok"}


def test_run_octopus_without_probe_and_v3_claims(monkeypatch, tmp_path):
    scenario = _scenario(
        lab_version="discovery-lab-v3",
        strategy={"adapter_side_http_probe": False, "max_iterations": "bad"},
    )
    pipeline = _Pipeline("")
    pipeline.trace_report = lambda *_args: {"machine_report": {"sections": {"observations": [{"detail": "claim-one"}]}}}
    monkeypatch.setattr("core.ai.pipeline.AIPipeline", lambda _path: pipeline)
    outcome = adapter._run_octopus(
        scenario,
        "127.0.0.1",
        tmp_path,
        timeout=10,
        max_output=4096,
    )
    assert outcome.status == "succeeded"
    assert outcome.metrics == {"tool_calls": 2.0}
    assert outcome.reported_claims == ("claim-one",)


def test_run_octopus_probe_deadline_and_adapter_failures(monkeypatch, tmp_path):
    monkeypatch.setattr("core.ai.pipeline.AIPipeline", _Pipeline)
    scenario = _scenario()
    clock = iter((0.0, 9.0, 10.0))
    monkeypatch.setattr(adapter.time, "monotonic", lambda: next(clock))
    outcome = adapter._run_octopus(scenario, "127.0.0.1", tmp_path, 10, 10)
    assert outcome.status == "timeout"

    monkeypatch.setattr(adapter.time, "monotonic", iter((0.0, 1.0)).__next__)
    monkeypatch.setattr(
        adapter,
        "_octopus_exact_target",
        lambda _target: (_ for _ in ()).throw(adapter.ProductAdapterError()),
    )
    outcome = adapter._run_octopus(scenario, "bad", tmp_path, 10, 10)
    assert outcome.status == "failed"
    assert outcome.error_class == "OctopusAdapterFailure"

    monkeypatch.setattr(adapter.time, "monotonic", iter((0.0, 10.0)).__next__)
    outcome = adapter._run_octopus(scenario, "bad", tmp_path, 10, 10)
    assert outcome.status == "timeout"
    assert outcome.error_class == "ProductTimeout"


@pytest.mark.parametrize(
    ("reason", "expected_status", "expected_error"),
    [
        ("deadline_exceeded", "timeout", "ProductTimeout"),
        ("operator_request", "failed", "ProductCancelled"),
    ],
)
def test_run_octopus_cancellation_paths(
    monkeypatch,
    tmp_path,
    reason,
    expected_status,
    expected_error,
):
    pipeline = _Pipeline("", run=ExecutionCancelled(reason))
    monkeypatch.setattr("core.ai.pipeline.AIPipeline", lambda _path: pipeline)
    monkeypatch.setattr(adapter, "_octopus_exact_http_probe", lambda *_args: "probe")
    outcome = adapter._run_octopus(_scenario(), "127.0.0.1", tmp_path, 10, 4096)
    assert outcome.status == expected_status
    assert outcome.error_class == expected_error


def test_run_octopus_keyboard_interrupt(monkeypatch, tmp_path):
    pipeline = _Pipeline("", run=ExecutionCancelled("keyboard_interrupt"))
    monkeypatch.setattr("core.ai.pipeline.AIPipeline", lambda _path: pipeline)
    monkeypatch.setattr(adapter, "_octopus_exact_http_probe", lambda *_args: "probe")
    with pytest.raises(KeyboardInterrupt):
        adapter._run_octopus(_scenario(), "127.0.0.1", tmp_path, 10, 4096)


def test_octopus_outcome_snapshot_failures_and_statuses(monkeypatch):
    pipeline = SimpleNamespace(
        fact_store=_FactStore(fail=True),
        trace_report=lambda *_args: (_ for _ in ()).throw(RuntimeError()),
        tools_run_count=None,
    )
    monkeypatch.setattr(adapter.time, "monotonic", lambda: 5.0)
    outcome = adapter._octopus_outcome(
        pipeline,
        "scan",
        "target",
        "raw",
        {"state": 1},
        4096,
        1.0,
        probe_completed=True,
        timed_out=False,
        total_timeout=10,
        failure_error_class="Failure",
    )
    assert outcome.status == "failed"
    assert outcome.metrics == {"tool_calls": 1.0}
    outcome = adapter._octopus_outcome(
        None,
        "",
        "",
        "",
        {},
        1,
        10.0,
        probe_completed=False,
        timed_out=False,
        total_timeout=1,
    )
    assert outcome.status == "succeeded"
    assert outcome.duration_seconds == 0.0


def test_octopus_v3_report_projection_boundaries(monkeypatch):
    assert adapter._octopus_v3_reported_claims(None) == ()
    assert adapter._octopus_v3_reported_claims({}) == ()
    assert adapter._octopus_v3_reported_claims({"machine_report": {}}) == ()
    trace = {
        "machine_report": {
            "sections": {
                "verified_vulnerabilities": "bad",
                "access_findings": [None, {}, {"detail": " "}],
                "misconfigurations": [{"detail": "x" * 1025}],
                "observations": [{"detail": "one"}, {"detail": "one"}],
                "hypotheses_candidates": [{"detail": "two"}],
            }
        }
    }
    assert adapter._octopus_v3_reported_claims(trace) == ("one", "two")
    monkeypatch.setattr(adapter, "_MAX_MATCHERS", 1)
    assert adapter._octopus_v3_reported_claims(trace) == ("one",)


@pytest.mark.parametrize("target", ["ftp://host", "http://", "http://host:bad", "http://host:0"])
def test_octopus_exact_target_rejects_invalid_urls(target):
    with pytest.raises(adapter.ProductAdapterError, match="invalid_octopus_target"):
        adapter._octopus_exact_target(target)


def test_octopus_exact_target_formats_ipv6():
    assert adapter._octopus_exact_target("http://[::1]") == "http://[::1]:80/"


class _ProbeResponse:
    def __init__(self, *, body=b"body", status=204, headers=None):
        self.body = body
        self.status = status
        self.headers = {} if headers is None else headers
        self.closed = False

    def read(self, _maximum):
        return self.body

    def getcode(self):
        return self.status

    def close(self):
        self.closed = True


def test_octopus_probe_http_error_and_optional_headers(monkeypatch):
    response = _ProbeResponse(status=302, headers={})
    error = urllib.error.HTTPError("http://x", 302, "redirect", {}, response)
    error.read = response.read
    error.close = response.close
    monkeypatch.setattr(
        adapter.urllib.request,
        "build_opener",
        lambda *_args: SimpleNamespace(open=lambda *_a, **_k: (_ for _ in ()).throw(error)),
    )
    output = adapter._octopus_exact_http_probe("https://localhost:443/x", 99, 100)
    assert "443/tcp open https" in output
    assert "Server:" not in output
    assert response.closed


def test_no_redirect_handler_raises_http_error():
    request = adapter.urllib.request.Request("http://localhost")
    with pytest.raises(urllib.error.HTTPError):
        adapter._NoRedirectHandler().redirect_request(
            request,
            None,
            302,
            "redirect",
            {},
            "http://other",
        )


@pytest.mark.parametrize(
    ("profile", "environment", "expected"),
    [
        ("strix", {}, ["strix-bin", "-n"]),
        (
            "pentestgpt",
            {"OCTOBENCH_PENTESTGPT_MODEL": "model"},
            ["pentestgpt-bin", "--target"],
        ),
        ("shannon", {}, ["npx", "--yes", "@keygraph/shannon@1.9.0"]),
    ],
)
def test_cli_profiles_build_bounded_argv(
    monkeypatch,
    tmp_path,
    profile,
    environment,
    expected,
):
    observed = {}

    def resolve(_configured, default, _environment):
        return "strix-bin" if default == "strix" else "pentestgpt-bin" if default == "pentestgpt" else "npx"

    def run(argv, **kwargs):
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        return 0, False, False, "tool_calls: 3", 1.5

    monkeypatch.setattr(adapter, "_product_environment", lambda *_args: {})
    monkeypatch.setattr(adapter, "_resolve_executable", resolve)
    monkeypatch.setattr(adapter, "_validated_source_path", lambda *_args: tmp_path)
    monkeypatch.setattr(adapter, "_run_bounded_process", run)
    outcome = adapter._run_cli_product(
        profile,
        _scenario(),
        "http://127.0.0.1:8080",
        "prompt",
        _environment(**environment),
        tmp_path,
        10,
        4096,
    )
    assert observed["argv"][: len(expected)] == expected
    assert outcome.status == "succeeded"
    assert outcome.metrics == {"tool_calls": 3.0}


def test_cli_shannon_custom_binary_and_package(monkeypatch, tmp_path):
    observed = {}
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(adapter, "_product_environment", lambda *_args: {})
    monkeypatch.setattr(adapter, "_resolve_executable", lambda *_args: "/fixture/shannon")
    monkeypatch.setattr(adapter, "_validated_source_path", lambda *_args: source)
    monkeypatch.setattr(
        adapter,
        "_run_bounded_process",
        lambda argv, **_kwargs: observed.setdefault("argv", argv) and (0, False, False, "", 0.0),
    )
    outcome = adapter._run_cli_product(
        "shannon",
        _scenario(),
        "http://127.0.0.1:8080",
        "prompt",
        _environment(OCTOBENCH_SHANNON_PACKAGE="custom"),
        tmp_path,
        10,
        4096,
    )
    assert outcome.status == "succeeded"
    assert "--yes" not in observed["argv"]


def test_cli_rejects_missing_model_and_unsupported_profile(monkeypatch, tmp_path):
    monkeypatch.setattr(adapter, "_product_environment", lambda *_args: {})
    monkeypatch.setattr(adapter, "_resolve_executable", lambda *_args: "bin")
    with pytest.raises(adapter.ProductAdapterError, match="missing_pentestgpt_model"):
        adapter._run_cli_product(
            "pentestgpt",
            _scenario(),
            "target",
            "prompt",
            {},
            tmp_path,
            1,
            10,
        )
    with pytest.raises(adapter.ProductAdapterError, match="unsupported_cli_product"):
        adapter._run_cli_product(
            "other",
            _scenario(),
            "target",
            "prompt",
            {},
            tmp_path,
            1,
            10,
        )


@pytest.mark.parametrize(
    ("process_result", "status", "error"),
    [
        ((0, True, False, "", 1), "timeout", "ProductTimeout"),
        ((0, False, True, "", 1), "invalid", "ProductOutputExceeded"),
        ((-9, False, False, "", 1), "failed", "ProductSignal9"),
        ((4, False, False, "", 1), "failed", "ProductExitCode4"),
        ((2, False, False, "", 1), "succeeded", ""),
    ],
)
def test_cli_process_outcome_mapping(
    monkeypatch,
    tmp_path,
    process_result,
    status,
    error,
):
    monkeypatch.setattr(adapter, "_product_environment", lambda *_args: {})
    monkeypatch.setattr(adapter, "_resolve_executable", lambda *_args: "strix")
    monkeypatch.setattr(adapter, "_run_bounded_process", lambda *_args, **_kwargs: process_result)
    outcome = adapter._run_cli_product(
        "strix",
        _scenario(),
        "target",
        "prompt",
        _environment(),
        tmp_path,
        1,
        10,
    )
    assert (outcome.status, outcome.error_class) == (status, error)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ftp://localhost",
        "http://user@localhost",
        "http://localhost/path",
        "http://localhost?x=1",
        "http://localhost#fragment",
        "http://localhost:bad",
        "http://localhost:0",
    ],
)
def test_pentagi_base_origin_rejects_all_ambiguous_forms(value):
    with pytest.raises(adapter.ProductAdapterError, match="invalid_pentagi_base_origin"):
        adapter._pentagi_base_origin(value)


def test_pentagi_base_origin_ipv6_and_active_timeout(monkeypatch):
    assert adapter._pentagi_base_origin("HTTPS://[::1]:443/") == "https://[::1]"
    monkeypatch.setattr(adapter.time, "monotonic", lambda: 5.0)
    assert adapter._pentagi_active_request_timeout(100) == 30.0
    assert adapter._pentagi_active_request_timeout(6) == 1.0
    with pytest.raises(adapter._PentagiDeadlineReached):
        adapter._pentagi_active_request_timeout(5)


class _Clock:
    def __init__(self, now: float = 0.0):
        self.now = now

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


@pytest.mark.parametrize(
    ("terminal_status", "delete_result", "expected"),
    [
        ("finished", True, "succeeded"),
        ("finished", False, "partial"),
        ("failed", True, "failed"),
    ],
)
def test_run_pentagi_terminal_outcomes(
    monkeypatch,
    terminal_status,
    delete_result,
    expected,
):
    clock = _Clock()
    polls = iter(("running", terminal_status))

    def graphql(_endpoint, _token, query, _variables, **_kwargs):
        if "BenchmarkRuntime" in query:
            return {"settings": {"version": "2.1.0-beta"}}
        if "CreateBenchmarkFlow" in query:
            return {"createFlow": {"id": 17}}
        return _pentagi_payload(status=next(polls))

    monkeypatch.setattr(adapter.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(adapter.time, "sleep", clock.sleep)
    monkeypatch.setattr(adapter, "_graphql_request", graphql)
    monkeypatch.setattr(adapter, "_pentagi_ssl_context", lambda _env: object())
    monkeypatch.setattr(adapter, "_pentagi_delete", lambda *_args: delete_result)
    outcome = adapter._run_pentagi(
        _scenario(),
        "http://127.0.0.1:8080",
        "prompt",
        _environment(
            OCTOBENCH_PENTAGI_URL="http://localhost:8443",
            OCTOBENCH_PENTAGI_TOKEN="token",
            OCTOBENCH_PENTAGI_PROVIDER="openai",
            OCTOBENCH_PENTAGI_MODEL="model",
        ),
        60,
        4096,
    )
    assert outcome.status == expected
    assert outcome.metrics["runtime_attested"] == 1.0
    assert outcome.metrics["cleanup_succeeded"] == float(delete_result)


@pytest.mark.parametrize(
    "missing",
    [
        "OCTOBENCH_PENTAGI_URL",
        "OCTOBENCH_PENTAGI_TOKEN",
        "OCTOBENCH_PENTAGI_MODEL",
    ],
)
def test_run_pentagi_requires_configuration(missing):
    environment = _environment(
        OCTOBENCH_PENTAGI_URL="http://localhost",
        OCTOBENCH_PENTAGI_TOKEN="token",
        OCTOBENCH_PENTAGI_PROVIDER="openai",
        OCTOBENCH_PENTAGI_MODEL="model",
    )
    environment[missing] = ""
    with pytest.raises(adapter.ProductAdapterError, match="missing_pentagi_configuration"):
        adapter._run_pentagi(_scenario(), "target", "prompt", environment, 60, 10)
    with pytest.raises(adapter.ProductAdapterError, match="pentagi_timeout_too_short"):
        adapter._run_pentagi(
            _scenario(),
            "target",
            "prompt",
            _environment(
                OCTOBENCH_PENTAGI_URL="http://localhost",
                OCTOBENCH_PENTAGI_TOKEN="token",
                OCTOBENCH_PENTAGI_MODEL="model",
            ),
            15,
            10,
        )


def test_run_pentagi_create_failure_is_protocol_failure(monkeypatch):
    clock = _Clock()

    def graphql(_endpoint, _token, query, _variables, **_kwargs):
        if "BenchmarkRuntime" in query:
            return {"settings": {"version": "2.1.0"}}
        return {"createFlow": None}

    monkeypatch.setattr(adapter.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(adapter, "_graphql_request", graphql)
    monkeypatch.setattr(adapter, "_pentagi_ssl_context", lambda _env: object())
    outcome = adapter._run_pentagi(
        _scenario(),
        "target",
        "prompt",
        _environment(
            OCTOBENCH_PENTAGI_URL="http://localhost",
            OCTOBENCH_PENTAGI_TOKEN="token",
            OCTOBENCH_PENTAGI_MODEL="model",
        ),
        60,
        10,
    )
    assert outcome.status == "failed"
    assert outcome.metrics == {}


@pytest.mark.parametrize("delete_result", [False, True])
def test_run_pentagi_deadline_after_creation_cleans_up(
    monkeypatch,
    delete_result,
):
    clock = _Clock()

    def graphql(_endpoint, _token, query, _variables, **_kwargs):
        if "BenchmarkRuntime" in query:
            return {"settings": {"version": "2.1.0"}}
        if "CreateBenchmarkFlow" in query:
            return {"createFlow": {"id": "17", "status": "created"}}
        clock.now = 46
        return {"flow": {"status": "running"}}

    stops = []
    monkeypatch.setattr(adapter.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(adapter.time, "sleep", clock.sleep)
    monkeypatch.setattr(adapter, "_graphql_request", graphql)
    monkeypatch.setattr(adapter, "_pentagi_ssl_context", lambda _env: object())
    monkeypatch.setattr(adapter, "_pentagi_stop", lambda *_args: stops.append(True))
    monkeypatch.setattr(adapter, "_pentagi_delete", lambda *_args: delete_result)
    outcome = adapter._run_pentagi(
        _scenario(),
        "target",
        "prompt",
        _environment(
            OCTOBENCH_PENTAGI_URL="http://localhost",
            OCTOBENCH_PENTAGI_TOKEN="token",
            OCTOBENCH_PENTAGI_MODEL="model",
        ),
        60,
        10,
    )
    assert outcome.status == "timeout"
    assert outcome.metrics == {"cleanup_succeeded": float(delete_result)}
    assert stops == [True]


def test_run_pentagi_deadline_before_creation_has_no_cleanup(monkeypatch):
    clock = _Clock()

    def graphql(*_args, **_kwargs):
        clock.now = 46
        raise adapter._PentagiDeadlineReached

    monkeypatch.setattr(adapter.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(adapter, "_graphql_request", graphql)
    monkeypatch.setattr(adapter, "_pentagi_ssl_context", lambda _env: object())
    outcome = adapter._run_pentagi(
        _scenario(),
        "target",
        "prompt",
        _environment(
            OCTOBENCH_PENTAGI_URL="http://localhost",
            OCTOBENCH_PENTAGI_TOKEN="token",
            OCTOBENCH_PENTAGI_MODEL="model",
        ),
        60,
        10,
    )
    assert outcome.status == "timeout"
    assert outcome.metrics == {}


@pytest.mark.parametrize(
    ("deadline", "delete_result", "expected_status"),
    [(False, False, "failed"), (True, True, "timeout")],
)
def test_run_pentagi_error_after_creation_cleanup(
    monkeypatch,
    deadline,
    delete_result,
    expected_status,
):
    clock = _Clock()

    def graphql(_endpoint, _token, query, _variables, **_kwargs):
        if "BenchmarkRuntime" in query:
            return {"settings": {"version": "2.1.0"}}
        if "CreateBenchmarkFlow" in query:
            return {"createFlow": {"id": "17"}}
        clock.now = 46 if deadline else 1
        raise OSError("fixture")

    monkeypatch.setattr(adapter.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(adapter, "_graphql_request", graphql)
    monkeypatch.setattr(adapter, "_pentagi_ssl_context", lambda _env: object())
    monkeypatch.setattr(adapter, "_pentagi_stop", lambda *_args: None)
    monkeypatch.setattr(adapter, "_pentagi_delete", lambda *_args: delete_result)
    outcome = adapter._run_pentagi(
        _scenario(),
        "target",
        "prompt",
        _environment(
            OCTOBENCH_PENTAGI_URL="http://localhost",
            OCTOBENCH_PENTAGI_TOKEN="token",
            OCTOBENCH_PENTAGI_MODEL="model",
        ),
        60,
        10,
    )
    assert outcome.status == expected_status
    assert outcome.metrics == {"cleanup_succeeded": float(delete_result)}


class _GraphQLResponse:
    def __init__(self, raw: bytes):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, maximum):
        return self.raw[:maximum]


def _mock_graphql_open(monkeypatch, raw: bytes, observed: dict[str, Any] | None = None):
    captured = {} if observed is None else observed

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return _GraphQLResponse(raw)

    monkeypatch.setattr(adapter.urllib.request, "build_opener", lambda *_args: Opener())
    return captured


def test_graphql_request_success_and_protocol_errors(monkeypatch):
    observed = _mock_graphql_open(
        monkeypatch,
        json.dumps({"data": {"ok": True}}).encode(),
        {},
    )
    assert adapter._graphql_request(
        "http://localhost/graphql",
        "token",
        "query",
        {"x": 1},
        context=ssl.create_default_context(),
        timeout=2,
        max_output=100,
    ) == {"ok": True}
    assert observed["request"].method == "POST"
    assert observed["timeout"] == 2

    _mock_graphql_open(monkeypatch, b"x" * 11)
    with pytest.raises(adapter.ProductAdapterError, match="pentagi_response_too_large"):
        adapter._graphql_request(
            "http://x", "t", "q", {}, context=ssl.create_default_context(), timeout=1, max_output=10
        )

    for raw, error in [
        (b"[]", "pentagi_graphql_error"),
        (b'{"errors":[{"message":"x"}]}', "pentagi_graphql_error"),
        (b'{"data":null}', "pentagi_graphql_missing_data"),
    ]:
        _mock_graphql_open(monkeypatch, raw)
        with pytest.raises(adapter.ProductAdapterError, match=error):
            adapter._graphql_request(
                "http://x", "t", "q", {}, context=ssl.create_default_context(), timeout=1, max_output=100
            )


def test_pentagi_stop_delete_ssl_metrics_and_attestations(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        adapter,
        "_graphql_request",
        lambda *_args, **_kwargs: calls.append(True) or {"deleteFlow": "success"},
    )
    adapter._pentagi_stop("e", "t", "f", ssl.create_default_context())
    assert adapter._pentagi_delete("e", "t", "f", ssl.create_default_context())
    assert len(calls) == 2
    monkeypatch.setattr(adapter, "_graphql_request", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError()))
    adapter._pentagi_stop("e", "t", "f", ssl.create_default_context())
    assert not adapter._pentagi_delete("e", "t", "f", ssl.create_default_context())
    monkeypatch.setattr(adapter, "_graphql_request", lambda *_args, **_kwargs: {"deleteFlow": "no"})
    assert not adapter._pentagi_delete("e", "t", "f", ssl.create_default_context())

    missing = tmp_path / "missing.pem"
    with pytest.raises(adapter.ProductAdapterError, match="pentagi_ca_unavailable"):
        adapter._pentagi_ssl_context({"OCTOBENCH_PENTAGI_CA_FILE": str(missing)})
    ca = tmp_path / "ca.pem"
    ca.write_text("fixture", encoding="utf-8")
    contexts = []
    monkeypatch.setattr(adapter.ssl, "create_default_context", lambda **kwargs: contexts.append(kwargs) or object())
    assert adapter._pentagi_ssl_context({"OCTOBENCH_PENTAGI_CA_FILE": str(ca)})
    assert contexts[-1] == {"cafile": str(ca)}
    assert adapter._pentagi_ssl_context({})
    assert contexts[-1] == {}

    assert adapter._pentagi_metrics({}) == {}
    assert adapter._pentagi_metrics({"toolCallLogs": "bad", "usageStatsByFlow": []}) == {}
    metrics = adapter._pentagi_metrics(_pentagi_payload())
    assert metrics == {"tool_calls": 1.0, "model_tokens": 5.0, "api_cost_usd": pytest.approx(0.3)}
    assert adapter._pentagi_metrics({"usageStatsByFlow": {"totalUsageIn": True}}) == {}

    adapter._validate_pentagi_release({"settings": {"version": "2.1.0"}})
    for payload in ({}, {"settings": {"version": "wrong"}}):
        with pytest.raises(adapter.ProductAdapterError, match="pentagi_release_mismatch"):
            adapter._validate_pentagi_release(payload)

    good = _pentagi_payload()
    adapter._validate_pentagi_execution(good, expected_provider="openai", expected_model="model")
    with pytest.raises(adapter.ProductAdapterError, match="pentagi_provider_mismatch"):
        adapter._validate_pentagi_execution({}, expected_provider="openai", expected_model="model")
    for usage in (None, "bad", []):
        payload = {"flow": {"provider": {"name": "openai"}}, "usageStatsByModelAgentsForFlow": usage}
        with pytest.raises(adapter.ProductAdapterError, match="pentagi_model_attestation_missing"):
            adapter._validate_pentagi_execution(payload, expected_provider="openai", expected_model="model")
    for usage in ([None], [{"model": "other"}]):
        payload = {"flow": {"provider": {"name": "openai"}}, "usageStatsByModelAgentsForFlow": usage}
        with pytest.raises(adapter.ProductAdapterError, match="pentagi_model_mismatch"):
            adapter._validate_pentagi_execution(payload, expected_provider="openai", expected_model="model")


@contextmanager
def _plain_process_context(_process):
    yield


class _FakeProcess:
    def __init__(self, polls, *, returncode=None, wait_error=False):
        self.pid = 123
        self.polls = iter(polls)
        self.returncode = returncode
        self.wait_error = wait_error
        self.terminated = False
        self.killed = False

    def poll(self):
        try:
            value = next(self.polls)
        except StopIteration:
            value = self.returncode
        if value is not None:
            self.returncode = value
        return value

    def wait(self, timeout):
        if self.wait_error:
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self.returncode = -9


def _install_fake_popen(monkeypatch, process, payload=b""):
    def popen(*_args, **kwargs):
        kwargs["stdout"].write(payload)
        kwargs["stdout"].flush()
        return process

    monkeypatch.setattr(adapter.subprocess, "Popen", popen)
    monkeypatch.setattr(adapter, "_kill_product_on_parent_termination", _plain_process_context)


@pytest.mark.parametrize("error", [OSError(), ValueError()])
def test_run_bounded_process_unavailable(monkeypatch, tmp_path, error):
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *_args, **_kwargs: (_ for _ in ()).throw(error))
    with pytest.raises(adapter.ProductAdapterError, match="product_unavailable"):
        adapter._run_bounded_process(["fake"], cwd=tmp_path, environment={}, timeout=1, max_output=10)


def test_run_bounded_process_completed_and_wait_timeout(monkeypatch, tmp_path):
    process = _FakeProcess([0, 0], wait_error=True)
    _install_fake_popen(monkeypatch, process, b"hello")
    clock = iter((1.0, 2.0))
    monkeypatch.setattr(adapter.time, "monotonic", lambda: next(clock))
    result = adapter._run_bounded_process(["fake"], cwd=tmp_path, environment={"X": "1"}, timeout=5, max_output=10)
    assert result == (0, False, False, "hello", 1.0)


@pytest.mark.parametrize("mode", ["timeout", "output"])
def test_run_bounded_process_enforces_limits(monkeypatch, tmp_path, mode):
    process = _FakeProcess([None, None, None], wait_error=True)
    payload = b"01234567890" if mode == "output" else b"ok"
    _install_fake_popen(monkeypatch, process, payload)
    terminations = []
    monkeypatch.setattr(adapter, "_terminate_process", lambda _process: terminations.append(True))
    clock = iter((0.0, 2.0, 3.0)) if mode == "timeout" else iter((0.0, 0.0, 3.0))
    monkeypatch.setattr(adapter.time, "monotonic", lambda: next(clock))
    result = adapter._run_bounded_process(["fake"], cwd=tmp_path, environment={}, timeout=1, max_output=10)
    assert result[1:3] == ((True, False) if mode == "timeout" else (False, True))
    assert len(terminations) == 2


def test_run_bounded_process_ignores_transient_stat_error(monkeypatch, tmp_path):
    process = _FakeProcess([None, 0, 0])
    _install_fake_popen(monkeypatch, process, b"ok")
    original_stat = Path.stat

    def stat(path, *args, **kwargs):
        if path.name == "adapter-stdout.log":
            raise OSError("fixture")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", stat)
    monkeypatch.setattr(adapter.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(adapter.time, "monotonic", iter((0.0, 0.0, 1.0)).__next__)
    result = adapter._run_bounded_process(["fake"], cwd=tmp_path, environment={}, timeout=5, max_output=10)
    assert result[0] == 0


def test_run_bounded_process_continues_below_output_limit(monkeypatch, tmp_path):
    process = _FakeProcess([None, 0, 0])
    _install_fake_popen(monkeypatch, process, b"ok")
    monkeypatch.setattr(adapter.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(adapter.time, "monotonic", iter((0.0, 0.0, 1.0)).__next__)
    result = adapter._run_bounded_process(["fake"], cwd=tmp_path, environment={}, timeout=5, max_output=10)
    assert result[1:3] == (False, False)


def test_product_signal_context_non_posix(monkeypatch):
    monkeypatch.setattr(adapter.os, "name", "nt")
    with adapter._kill_product_on_parent_termination(_FakeProcess([0])):
        pass


def test_product_signal_context_forwards_and_restores(monkeypatch):
    installed = {}
    calls = []

    def set_handler(signum, handler):
        installed[signum] = handler
        calls.append((signum, handler))

    monkeypatch.setattr(adapter.signal, "getsignal", lambda signum: f"old-{signum}")
    monkeypatch.setattr(adapter.signal, "signal", set_handler)
    monkeypatch.setattr(adapter.os, "killpg", lambda pid, signum: calls.append((pid, signum)))
    with (
        adapter._kill_product_on_parent_termination(_FakeProcess([0])),
        pytest.raises(SystemExit, match="143"),
    ):
        installed[signal.SIGTERM](signal.SIGTERM, None)
    assert any(handler == f"old-{signal.SIGTERM}" for _, handler in calls)


def test_product_signal_context_install_failure(monkeypatch):
    calls = []

    def fail_signal(signum, handler):
        calls.append((signum, handler))
        raise ValueError("worker thread")

    monkeypatch.setattr(adapter.signal, "getsignal", lambda _signum: "old")
    monkeypatch.setattr(adapter.signal, "signal", fail_signal)
    with adapter._kill_product_on_parent_termination(_FakeProcess([0])):
        calls.append(("yielded", True))
    assert ("yielded", True) in calls


def test_terminate_process_platform_paths(monkeypatch):
    finished = _FakeProcess([0])
    adapter._terminate_process(finished)

    signals = []
    graceful = _FakeProcess([None, 0, 0])
    monkeypatch.setattr(adapter.os, "killpg", lambda pid, signum: signals.append((pid, signum)))
    adapter._terminate_process(graceful)
    assert signals == [(123, signal.SIGTERM)]

    stubborn = _FakeProcess([None, None, None], wait_error=True)
    adapter._terminate_process(stubborn)
    assert signals[-2:] == [(123, signal.SIGTERM), (123, signal.SIGKILL)]

    monkeypatch.setattr(adapter.os, "name", "nt")
    graceful_non_posix = _FakeProcess([None, 0])
    adapter._terminate_process(graceful_non_posix)
    assert graceful_non_posix.terminated and not graceful_non_posix.killed
    non_posix = _FakeProcess([None, None], wait_error=True)
    adapter._terminate_process(non_posix)
    assert non_posix.terminated and non_posix.killed


def test_product_environment_profiles_and_filtering(tmp_path):
    source = {
        "PATH": "/bin",
        "SECRET": "drop",
        "STRIX_IMAGE": _STRIX_IMAGE,
        "STRIX_LLM": "model",
        "ANTHROPIC_API_KEY": "key",
        "AWS_ACCESS_KEY_ID": "aws",
    }
    workspaces = {name: tmp_path / name for name in ("strix", "pentest", "shannon", "other", "bad")}
    for workspace in workspaces.values():
        workspace.mkdir()
    strix = adapter._product_environment("strix", source, workspaces["strix"])
    assert strix["STRIX_TELEMETRY"] == "false"
    assert strix["HOME"].endswith("/home")
    assert "SECRET" not in strix and "ANTHROPIC_API_KEY" not in strix
    pentest = adapter._product_environment("pentestgpt", source, workspaces["pentest"])
    assert pentest["PENTESTGPT_AUTH_MODE"] == "anthropic"
    assert pentest["ANTHROPIC_API_KEY"] == "key"
    shannon = adapter._product_environment("shannon", source, workspaces["shannon"])
    assert shannon["AWS_ACCESS_KEY_ID"] == "aws"
    other = adapter._product_environment("other", source, workspaces["other"])
    assert other["PATH"] == "/bin"
    with pytest.raises(adapter.ProductAdapterError, match="invalid_strix_image"):
        adapter._product_environment("strix", {"STRIX_IMAGE": "latest"}, workspaces["bad"])


@pytest.mark.parametrize("configured", ["", "bad\x00name"])
def test_resolve_executable_rejects_invalid_name(configured):
    with pytest.raises(adapter.ProductAdapterError, match="invalid_executable"):
        adapter._resolve_executable(configured, "", {})


def test_resolve_executable_paths_and_path_lookup(monkeypatch, tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(adapter.ProductAdapterError, match="product_unavailable"):
        adapter._resolve_executable(str(missing), "default", {})
    executable = tmp_path / "tool"
    executable.write_text("fixture", encoding="utf-8")
    with pytest.raises(adapter.ProductAdapterError, match="product_unavailable"):
        adapter._resolve_executable(str(executable), "default", {})
    executable.chmod(0o700)
    assert adapter._resolve_executable(str(executable), "default", {}) == str(executable)
    monkeypatch.setattr(adapter.shutil, "which", lambda *_args, **_kwargs: None)
    with pytest.raises(adapter.ProductAdapterError, match="product_unavailable"):
        adapter._resolve_executable(None, "tool", {"PATH": "/bin"})
    monkeypatch.setattr(adapter.shutil, "which", lambda *_args, **_kwargs: "/bin/tool")
    assert adapter._resolve_executable(None, "tool", {"PATH": "/bin"}) == "/bin/tool"


class _OutputPath:
    def __init__(
        self,
        name,
        *,
        suffix=".txt",
        data=b"",
        file=True,
        symlink=False,
        error=False,
    ):
        self.name = name
        self.suffix = suffix
        self.data = data
        self.file = file
        self.symlink = symlink
        self.error = error

    def __lt__(self, other):
        return self.name < other.name

    def is_file(self):
        return self.file

    def is_symlink(self):
        return self.symlink

    def read_bytes(self):
        if self.error:
            raise OSError("fixture")
        return self.data


class _OutputRoot:
    def __init__(self, paths):
        self.paths = paths

    def rglob(self, _pattern):
        return self.paths


def test_collect_product_output_filters_and_bounds_files():
    root = _OutputRoot(
        [
            _OutputPath("adapter-stdout.log", data=b"duplicate"),
            _OutputPath("binary.bin", suffix=".bin", data=b"binary"),
            _OutputPath("credentials", suffix="", data=b"secret"),
            _OutputPath("error.log", error=True),
            _OutputPath("result.txt", data=b"result"),
            _OutputPath("secret-report.txt", data=b"secret"),
        ]
    )
    assert adapter._collect_product_output(root, "stdout", 100) == "stdout\nresult"
    stopped = _OutputRoot([_OutputPath("directory", file=False), _OutputPath("z.txt", data=b"no")])
    assert adapter._collect_product_output(stopped, "stdout", 100) == "stdout"
    symlink = _OutputRoot([_OutputPath("link.txt", symlink=True)])
    assert adapter._collect_product_output(symlink, "", 100) == ""
    assert adapter._collect_product_output(root, "full", 4) == "full"


def test_extract_metrics_and_matcher_validation(monkeypatch):
    metrics = adapter._extract_structured_metrics(
        "toolCalls=1 tool_calls: 4 modelCalls:2 totalTokens:9 total_cost_usd:1.25"
    )
    assert metrics == {
        "tool_calls": 4.0,
        "model_calls": 2.0,
        "model_tokens": 9.0,
        "api_cost_usd": 1.25,
    }
    assert adapter._extract_structured_metrics("nothing") == {}

    scenario = _scenario()
    scenario.artifacts["normalization"] = None
    with pytest.raises(adapter.ProductAdapterError, match="missing_normalization_contract"):
        adapter._load_matchers(scenario)
    scenario = _scenario()
    scenario.artifacts["normalization"]["schema_version"] = "2.0"
    with pytest.raises(adapter.ProductAdapterError, match="unsupported_normalization_contract"):
        adapter._load_matchers(scenario)
    scenario = _scenario()
    scenario.artifacts["normalization"]["findings"] = "bad"
    with pytest.raises(adapter.ProductAdapterError, match="invalid_normalization_matchers"):
        adapter._load_matchers(scenario)
    scenario = _scenario()
    scenario.artifacts["normalization"]["findings"] = []
    with pytest.raises(adapter.ProductAdapterError, match="invalid_normalization_matcher_count"):
        adapter._load_matchers(scenario)
    scenario = _scenario()
    scenario.artifacts["normalization"]["findings"] = [None]
    with pytest.raises(adapter.ProductAdapterError, match="invalid_normalization_matcher"):
        adapter._load_matchers(scenario)
    scenario = _scenario()
    scenario.artifacts["normalization"]["findings"] = [{"finding_id": "BAD ID", "reported_contains": ["x"]}]
    with pytest.raises(adapter.ProductAdapterError, match="invalid_normalization_finding_id"):
        adapter._load_matchers(scenario)
    scenario = _scenario(ground_truth={"expected_findings": [], "forbidden_findings": []})
    scenario.artifacts["normalization"]["findings"] = [{"finding_id": "one"}]
    with pytest.raises(adapter.ProductAdapterError, match="empty_normalization_matcher"):
        adapter._load_matchers(scenario)
    scenario = _scenario()
    scenario.ground_truth["expected_findings"] = ["missing"]
    with pytest.raises(adapter.ProductAdapterError, match="normalization_missing_ground_truth_id"):
        adapter._load_matchers(scenario)

    monkeypatch.setattr(adapter, "_MAX_NEEDLES", 1)
    with pytest.raises(adapter.ProductAdapterError, match="too_many_normalization_needles"):
        adapter._needles(["a", "b"])


def test_needles_identifier_and_v3_claim_boundaries(monkeypatch):
    with pytest.raises(adapter.ProductAdapterError, match="invalid_normalization_needles"):
        adapter._needles("bad")
    for value in ([""], ["x" * 1025]):
        with pytest.raises(adapter.ProductAdapterError, match="invalid_normalization_needle"):
            adapter._needles(value)
    assert adapter._needles(["one", "one", "two"]) == ("one", "two")

    output = "prose\n- Claim: one\n* finding: one\n# Finding: \nClaim: " + "x" * 1025 + "\nClaim: two"
    assert adapter._extract_v3_reported_claims(output) == ("one", "two")
    monkeypatch.setattr(adapter, "_MAX_MATCHERS", 1)
    assert adapter._extract_v3_reported_claims(output) == ("one",)

    with pytest.raises(adapter.ProductAdapterError, match="invalid_ground_truth_findings"):
        adapter._identifier_set("bad")
    with pytest.raises(adapter.ProductAdapterError, match="invalid_ground_truth_finding_id"):
        adapter._identifier_set(["BAD ID"])
    assert adapter._identifier_set(["One", "one"]) == {"one"}


def test_authorization_target_and_address_boundaries(monkeypatch):
    scenario = _scenario()
    with pytest.raises(adapter.ProductAdapterError, match="authorization_ack_required"):
        adapter._validate_authorization(scenario, {})
    with pytest.raises(adapter.ProductAdapterError, match="isolation_ack_required"):
        adapter._validate_authorization(scenario, {"OCTOBENCH_ACK_AUTHORIZED": "YES"})
    for field, container in [
        ("authorization_ref", scenario.lab),
        ("scope_ref", scenario.target),
        ("snapshot_ref", scenario.lab),
    ]:
        original = container[field]
        container[field] = "your-target"
        with pytest.raises(adapter.ProductAdapterError, match="incomplete_authorization_contract"):
            adapter._validate_authorization(scenario, _environment())
        container[field] = original
    scenario.lab["reset_policy"] = ""
    with pytest.raises(adapter.ProductAdapterError, match="missing_reset_policy"):
        adapter._validate_authorization(scenario, _environment())

    scenario = _scenario(target={"version": "v1", "url": "http://localhost", "scope_ref": "scope"})
    assert adapter._target_address(scenario, {}) == "http://localhost"
    assert adapter._target_address(scenario, {"OCTOBENCH_TARGET_URL": "http://127.0.0.1"}) == "http://127.0.0.1"
    for value in ("", "your-target", "x" * 4097):
        scenario.target["url"] = value
        with pytest.raises(adapter.ProductAdapterError, match="invalid_target"):
            adapter._target_address(scenario, {})

    with pytest.raises(adapter.ProductAdapterError, match="invalid_target"):
        adapter._validate_authorized_target("http://user@localhost", {})
    with pytest.raises(adapter.ProductAdapterError, match="unsupported_target_scheme"):
        adapter._validate_authorized_target("ftp://localhost", {})
    with pytest.raises(adapter.ProductAdapterError, match="invalid_target_port"):
        adapter._validate_authorized_target("http://localhost:0", {})
    adapter._validate_authorized_target("http://allowed.example", {"OCTOBENCH_ALLOWED_HOSTS": " ALLOWED.EXAMPLE "})
    adapter._validate_authorized_target("http://name.localhost", {})
    adapter._validate_authorized_target("http://fixture.test", {})

    monkeypatch.setattr(adapter.socket, "getaddrinfo", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    with pytest.raises(adapter.ProductAdapterError, match="target_resolution_failed"):
        adapter._validate_authorized_target("http://unknown.example", {})
    monkeypatch.setattr(adapter.socket, "getaddrinfo", lambda *_args, **_kwargs: [])
    with pytest.raises(adapter.ProductAdapterError, match="public_target_rejected"):
        adapter._validate_authorized_target("http://unknown.example", {})
    monkeypatch.setattr(
        adapter.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("127.0.0.1", 0))],
    )
    adapter._validate_authorized_target("http://unknown.example", {})
    monkeypatch.setattr(
        adapter.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("8.8.8.8", 0))],
    )
    with pytest.raises(adapter.ProductAdapterError, match="public_target_rejected"):
        adapter._validate_authorized_target("http://unknown.example", {})
    with pytest.raises(adapter.ProductAdapterError, match="public_target_rejected"):
        adapter._validate_authorized_target("http://8.8.8.8", {})

    assert not adapter._private_address("bad")
    assert adapter._private_address("127.0.0.1")
    assert adapter._target_host("localhost:80") == "localhost"
    with pytest.raises(adapter.ProductAdapterError, match="invalid_target"):
        adapter._target_host("http://")


def test_source_path_workspace_and_scalar_helpers(tmp_path):
    scenario = _scenario()
    with pytest.raises(adapter.ProductAdapterError, match="whitebox_source_required"):
        adapter._validated_source_path(scenario, {})
    root = tmp_path / "root"
    root.mkdir()
    scenario.target["source_path"] = "../outside"
    with pytest.raises(adapter.ProductAdapterError, match="whitebox_source_outside_root"):
        adapter._validated_source_path(scenario, {"OCTOBENCH_SOURCE_ROOT": str(root)})
    scenario.target["source_path"] = "missing"
    with pytest.raises(adapter.ProductAdapterError, match="whitebox_source_unavailable"):
        adapter._validated_source_path(scenario, {"OCTOBENCH_SOURCE_ROOT": str(root)})
    source = root / "source"
    source.mkdir()
    scenario.target["source_path"] = str(source)
    assert adapter._validated_source_path(scenario, {"OCTOBENCH_SOURCE_ROOT": str(root)}) == source
    assert adapter._workspace_name(scenario, {}) == "octobench-adapter-boundaries-v1-0-7"
    assert adapter._workspace_name(
        scenario,
        {"OCTOPUS_BENCHMARK_REPETITION": "A B", "OCTOPUS_BENCHMARK_SEED": "S!"},
    ).endswith("-a-b-s-")
    assert adapter._contains_placeholder("Replace-With value")
    assert not adapter._contains_placeholder("complete")

    for value in (True, "bad", 0):
        with pytest.raises(adapter.ProductAdapterError, match="invalid_positive_integer"):
            adapter._positive_integer(value)
    assert adapter._positive_integer("2") == 2
    for value in (True, "bad", math.inf, 0):
        with pytest.raises(adapter.ProductAdapterError, match="invalid_limit"):
            adapter._positive_number(value, "limit")
    assert adapter._positive_number("2.5", "limit") == 2.5
    assert adapter._bounded_integer("bad", minimum=1, maximum=3) == 1
    assert adapter._bounded_integer(9, minimum=1, maximum=3) == 3
    for value in (True, "bad", -1, math.inf):
        assert adapter._safe_float(value) == 0.0
    assert adapter._safe_float("2.5") == 2.5


def test_metric_budget_text_atomic_and_failed_result(tmp_path):
    assert adapter._reported_metric_sum({}, ("a",)) is None
    assert adapter._reported_metric_sum({"a": True}, ("a",)) is None
    assert adapter._reported_metric_sum({"a": "bad"}, ("a",)) is None
    assert adapter._reported_metric_sum({"a": -1}, ("a",)) is None
    assert adapter._reported_metric_sum({"a": 2, "b": 3}, ("a", "b")) == 5

    assert not adapter._reported_budget_overrun({}, {})
    for limit in ("bad", 0, math.inf):
        with pytest.raises(adapter.ProductAdapterError, match="invalid_budget_limit"):
            adapter._reported_budget_overrun({"max_tools": limit}, {"tool_calls": 1})
    assert adapter._reported_budget_overrun({"max_tools": 1}, {"tool_calls": 2})
    assert not adapter._reported_budget_overrun({"max_tools": 2}, {"tool_calls": 1})

    for value in (True, "bad", -1):
        assert not adapter._valid_metric(value)
    assert adapter._valid_metric(0)
    assert adapter._bounded_text("€", 2) == ""
    output = tmp_path / "nested" / "result.json"
    adapter._atomic_write_json(output, {"b": 2, "a": 1})
    assert output.read_text(encoding="utf-8") == '{"a":1,"b":2}\n'
    assert "reported_claims" not in adapter._failed_result()
    assert adapter._failed_result(include_reported_claims=True)["reported_claims"] == []


def test_run_product_adapter_empty_truth_non_success_has_no_completeness(monkeypatch):
    scenario = _scenario(
        ground_truth={"expected_findings": [], "forbidden_findings": []},
        artifacts={
            "normalization": {
                "schema_version": "1.0",
                "findings": [{"finding_id": "one", "reported_contains": ["one"]}],
            }
        },
    )
    monkeypatch.setattr(adapter, "_run_cli_product", lambda *_args: _outcome(status="failed", output_text=""))
    result = adapter.run_product_adapter("strix", scenario, environment=_environment())
    assert "evidence_completeness" not in result["metrics"]


def test_adapter_module_main_guard(monkeypatch, tmp_path):
    import runpy
    import sys

    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(_scenario().to_dict()), encoding="utf-8")
    output = tmp_path / "output.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "adapter",
            "--system",
            "strix",
            "--scenario",
            str(scenario_path),
            "--output",
            str(output),
        ],
    )
    monkeypatch.delenv("OCTOBENCH_ACK_AUTHORIZED", raising=False)
    with (
        pytest.warns(RuntimeWarning, match="found in sys.modules"),
        pytest.raises(SystemExit, match="0"),
    ):
        runpy.run_module("core.benchmarks.competitors.adapter", run_name="__main__")
    assert output.is_file()
