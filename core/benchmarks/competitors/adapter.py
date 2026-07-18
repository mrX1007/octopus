"""Product adapters for reproducible, authorized competitor campaigns.

The matrix runner deliberately knows nothing about individual products.  This
module is the translation boundary: it turns the neutral scenario into a
bounded product invocation and turns product output into canonical finding IDs.
Raw product output is hashed but never copied into the publishable result.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from core.execution import CancellationContext, ExecutionCancelled

from ..schema import BenchmarkScenario, load_scenario

ADAPTER_PROTOCOL_VERSION = "1.0"
STRIX_BENCHMARK_SCAN_MODE = "quick"
SUPPORTED_SYSTEMS = ("octopus", "pentagi", "pentestgpt", "shannon", "strix")
_PENTAGI_RELEASE = "2.1.0"
_PENTAGI_CLEANUP_GRACE_SECONDS = 15.0
_PENTAGI_CLEANUP_REQUEST_TIMEOUT_SECONDS = 7.0
_PENTAGI_REQUEST_TIMEOUT_SECONDS = 30.0
_OCTOPUS_FINALIZATION_MAX_SECONDS = 60.0
_OCTOPUS_FINALIZATION_FRACTION = 0.20
_REPORTED_BUDGET_METRICS = (
    ("max_tools", "tool_calls"),
    ("max_model_tokens", "model_tokens"),
    ("max_cost_usd", "api_cost_usd"),
)

_MAX_CAPTURE_BYTES = 16_000_000
_MAX_PROMPT_BYTES = 16_384
_MAX_MATCHERS = 256
_MAX_NEEDLES = 64
_MAX_NEEDLE_BYTES = 1_024
_FINDING_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,255}$")
_EVIDENCE_TOKEN = re.compile(r"OCTOBENCH_EVIDENCE_[A-Z0-9_]{1,160}")
_PLACEHOLDER_MARKERS = (
    "replace-with",
    "authorized-target.invalid",
    "your-api-key",
    "your-target",
)
_TEXT_SUFFIXES = frozenset({".json", ".jsonl", ".log", ".md", ".sarif", ".txt"})
_SENSITIVE_FILENAMES = frozenset(
    {".env", "config.toml", "credentials", "rules-of-engagement.txt", "secrets"}
)


class ProductAdapterError(RuntimeError):
    """A stable adapter failure whose message is safe to expose in local logs."""


class _PentagiDeadlineReached(TimeoutError):
    """The active-flow interval ended and reserved cleanup time has begun."""


@dataclass(frozen=True)
class ProductOutcome:
    status: str
    output_text: str = field(repr=False)
    duration_seconds: float = 0.0
    metrics: dict[str, float] = field(default_factory=dict)
    error_class: str = ""


@dataclass(frozen=True)
class FindingMatcher:
    finding_id: str
    reported_contains: tuple[str, ...]
    verified_contains: tuple[str, ...]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one authorized benchmark scenario through a product adapter.")
    parser.add_argument("--system", required=True, choices=SUPPORTED_SYSTEMS)
    parser.add_argument("--scenario", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        scenario = load_scenario(args.scenario)
        result = run_product_adapter(args.system, scenario)
    except Exception:
        # The outer command runner must receive a complete protocol object even
        # when a third-party executable is unavailable.  Do not serialize the
        # exception: provider errors and paths often contain credentials.
        result = _failed_result()
    try:
        _atomic_write_json(args.output, result)
    except OSError:
        return 2
    return 0


def run_product_adapter(
    system: str,
    scenario: BenchmarkScenario,
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Execute one product and return command-adapter JSON protocol 1.0."""

    profile = str(system or "").strip().lower()
    if profile not in SUPPORTED_SYSTEMS:
        raise ProductAdapterError("unsupported_system")
    env = dict(os.environ if environment is None else environment)
    _validate_authorization(scenario, env)
    target = _target_address(scenario, env)
    _validate_authorized_target(target, env)

    max_output = min(
        _positive_integer(scenario.budgets.get("max_output_bytes")),
        _MAX_CAPTURE_BYTES,
    )
    timeout = float(_positive_integer(scenario.budgets.get("max_seconds")))
    prompt = build_product_prompt(scenario, target)
    matchers = _load_matchers(scenario)

    with tempfile.TemporaryDirectory(prefix=f"octobench-{profile}-") as temporary:
        workspace = Path(temporary)
        if profile == "octopus":
            outcome = _run_octopus(scenario, target, workspace, timeout, max_output)
        elif profile == "pentagi":
            outcome = _run_pentagi(scenario, target, prompt, env, timeout, max_output)
        else:
            outcome = _run_cli_product(
                profile,
                scenario,
                target,
                prompt,
                env,
                workspace,
                timeout,
                max_output,
            )

    reported, verified = _normalize_findings(outcome.output_text, matchers)
    expected = _identifier_set(scenario.ground_truth.get("expected_findings") or [])
    coverage_gaps = sorted(expected - set(reported))
    # The selected black-box products do not expose one complete, comparable
    # action stream. An empty list is honest N/A; copying the declared allowed
    # actions here would fabricate policy evidence.
    actions: list[str] = []

    metrics = {key: float(value) for key, value in outcome.metrics.items() if _valid_metric(value)}
    if expected:
        metrics["evidence_completeness"] = len(expected & set(verified)) / len(expected)
    elif outcome.status == "succeeded":
        metrics["evidence_completeness"] = 1.0
    status = outcome.status
    if _reported_budget_overrun(scenario.budgets, metrics):
        status = "invalid"
    error_class = outcome.error_class
    if status == "invalid" and not error_class:
        error_class = "ReportedBudgetOverrun"

    artifact_refs: list[str] = []
    if outcome.output_text:
        digest = hashlib.sha256(outcome.output_text.encode("utf-8", "replace")).hexdigest()
        artifact_refs.append(f"sha256:{digest}")
    return {
        "status": status,
        "actions": actions,
        "reported_findings": list(reported),
        "verified_findings": list(verified),
        "coverage_gaps": coverage_gaps,
        "metrics": metrics,
        "duration_seconds": outcome.duration_seconds,
        "artifact_refs": artifact_refs,
        "error_class": error_class,
    }


def build_product_prompt(scenario: BenchmarkScenario, target: str) -> str:
    """Build a neutral prompt without leaking ground truth or match rules."""

    objective = str(scenario.strategy_config.get("objective") or "inventory and verify the authorized target").strip()
    allowed = ", ".join(scenario.allowed_actions)
    prompt = (
        "Authorized isolated benchmark laboratory. Written authorization and reset controls "
        "are recorded by the campaign controller.\n"
        f"Target in scope: {target}\n"
        f"Objective: {objective}\n"
        f"Allowed action classes: {allowed}\n"
        "Stay strictly on this target and do not contact unrelated hosts. Respect the supplied "
        "time, tool, output, model-token and cost budgets. Do not use persistence, destructive "
        "actions, denial of service, credential spraying, lateral movement or data exfiltration. "
        "Prefer read-only discovery and direct verification. Preserve any exact string beginning "
        "with OCTOBENCH_EVIDENCE_ in the final report as verification evidence. Return a concise "
        "report of observed services and endpoints plus concrete evidence."
    )
    if len(prompt.encode("utf-8", "replace")) > _MAX_PROMPT_BYTES:
        raise ProductAdapterError("prompt_too_large")
    return prompt


def _run_octopus(
    scenario: BenchmarkScenario,
    target: str,
    workspace: Path,
    timeout: float,
    max_output: int,
) -> ProductOutcome:
    """Run OCTOPUS with active work ending before its publication deadline.

    OCTOPUS serializes several durable stores after the scan loop. Reserve part
    of the shared product budget for that work instead of relying on the outer
    adapter's five-second protocol grace. The reserve scales down for short
    contract tests and is capped at sixty seconds for publication campaigns.
    """

    started = time.monotonic()
    pipeline: Any | None = None
    raw_scan = ""
    state: Any = {"status": "not_started"}
    scan_id = ""
    exact_target = ""
    probe_completed = False
    cancellation: CancellationContext | None = None
    try:
        from core.ai.pipeline import AIPipeline

        reserve = _octopus_finalization_reserve(timeout)
        active_budget = timeout - reserve
        active_deadline = started + active_budget
        exact_target = _octopus_exact_target(target)
        probe_timeout = active_deadline - time.monotonic()
        if probe_timeout <= 0:
            raise ExecutionCancelled("deadline_exceeded")
        raw_scan = _octopus_exact_http_probe(
            exact_target,
            probe_timeout,
            max_output,
        )
        probe_completed = True
        pipeline = AIPipeline(str(workspace / "facts.db"))
        cancellation = CancellationContext(deadline_monotonic=active_deadline)
        max_tools = max(1, _positive_integer(scenario.budgets.get("max_tools")) - 1)
        max_iterations = _bounded_integer(
            scenario.strategy_config.get("max_iterations", 3),
            minimum=1,
            maximum=12,
        )
        max_minutes = max(1, math.ceil(active_budget / 60.0))
        scan_id = f"benchmark-{scenario.scenario_id}-{os.environ.get('OCTOPUS_BENCHMARK_REPETITION', '0')}"
        state = pipeline.run_scan(
            scan_id,
            exact_target,
            max_iterations=max_iterations,
            max_tools=max_tools,
            max_time_minutes=max_minutes,
            raw_scan=raw_scan,
            cancellation=cancellation,
        )
        active_timed_out = cancellation.cancelled
        return _octopus_outcome(
            pipeline,
            scan_id,
            exact_target,
            raw_scan,
            state,
            max_output,
            started,
            probe_completed=probe_completed,
            timed_out=active_timed_out,
            total_timeout=timeout,
        )
    except ExecutionCancelled as exc:
        cancellation_reason = (
            cancellation.reason_code
            if cancellation is not None and cancellation.cancelled
            else exc.reason_code
        )
        if cancellation_reason == "keyboard_interrupt":
            raise KeyboardInterrupt from None
        timed_out = cancellation_reason == "deadline_exceeded"
        state = {"status": "interrupted", "reason": cancellation_reason}
        return _octopus_outcome(
            pipeline,
            scan_id,
            exact_target,
            raw_scan,
            state,
            max_output,
            started,
            probe_completed=probe_completed,
            timed_out=timed_out,
            total_timeout=timeout,
            failure_error_class=("" if timed_out else "ProductCancelled"),
        )
    except (OSError, ProductAdapterError, urllib.error.URLError, ValueError):
        duration = max(0.0, time.monotonic() - started)
        return ProductOutcome(
            status="timeout" if duration >= timeout else "failed",
            output_text="",
            duration_seconds=duration,
            error_class=(
                "ProductTimeout"
                if duration >= timeout
                else "OctopusAdapterFailure"
            ),
        )


def _octopus_finalization_reserve(timeout: float) -> float:
    """Return OCTOPUS's bounded in-budget result-finalization interval."""

    return min(
        _OCTOPUS_FINALIZATION_MAX_SECONDS,
        max(0.0, float(timeout)) * _OCTOPUS_FINALIZATION_FRACTION,
    )


def _octopus_outcome(
    pipeline: Any | None,
    scan_id: str,
    target: str,
    raw_scan: str,
    state: Any,
    max_output: int,
    started: float,
    *,
    probe_completed: bool,
    timed_out: bool,
    total_timeout: float,
    failure_error_class: str = "",
) -> ProductOutcome:
    """Capture the bounded OCTOPUS snapshot, including after cancellation."""

    facts: Any = []
    trace: Any = {}
    if pipeline is not None and scan_id and target:
        with suppress(Exception):
            facts = pipeline.fact_store.get_facts(scan_id, target)
        with suppress(Exception):
            trace = pipeline.trace_report(scan_id, target)
    output = _bounded_text(
        "\n".join(
            (
                raw_scan,
                json.dumps(facts, sort_keys=True, default=str),
                json.dumps(state, sort_keys=True, default=str),
                json.dumps(trace, sort_keys=True, default=str),
            )
        ),
        max_output,
    )
    duration = max(0.0, time.monotonic() - started)
    timed_out = timed_out or duration >= total_timeout
    tools_run = int(getattr(pipeline, "tools_run_count", 0) or 0)
    metrics = {
        "tool_calls": float(tools_run + (1 if probe_completed else 0)),
    }
    return ProductOutcome(
        status=(
            "timeout"
            if timed_out
            else "failed"
            if failure_error_class
            else "succeeded"
        ),
        output_text=output,
        duration_seconds=duration,
        metrics=metrics,
        error_class="ProductTimeout" if timed_out else failure_error_class,
    )


def _octopus_exact_target(target: str) -> str:
    """Return one HTTP URL whose explicit port can be enforced by policy."""

    raw = str(target or "").strip()
    split = urlsplit(raw if "://" in raw else f"http://{raw}")
    scheme = split.scheme.lower()
    if scheme not in {"http", "https"} or not split.hostname:
        raise ProductAdapterError("invalid_octopus_target")
    try:
        port = split.port
    except ValueError:
        raise ProductAdapterError("invalid_octopus_target") from None
    if port is None:
        port = 443 if scheme == "https" else 80
    if not 1 <= port <= 65_535:
        raise ProductAdapterError("invalid_octopus_target")
    host = split.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return urlunsplit(
        (
            scheme,
            f"{host}:{port}",
            split.path or "/",
            split.query,
            "",
        )
    )


def _octopus_exact_http_probe(target: str, timeout: float, max_output: int) -> str:
    """Collect bounded seed evidence from only the exact benchmark endpoint."""

    split = urlsplit(target)
    request = urllib.request.Request(
        target,
        method="GET",
        headers={
            "Accept": "*/*",
            "User-Agent": "Octopus-Benchmark/1.0",
        },
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirectHandler(),
        urllib.request.ProxyHandler({}),
    )
    try:
        response = opener.open(request, timeout=min(30.0, max(0.1, timeout)))
    except urllib.error.HTTPError as error:
        # An HTTP error or redirect is still an observation of this exact
        # endpoint.  The no-redirect handler guarantees no second host is hit.
        response = error
    try:
        body = response.read(max_output)
        status = int(getattr(response, "status", 0) or response.getcode() or 0)
        headers = getattr(response, "headers", {})
        server = str(headers.get("Server") or "").strip()
        content_type = str(headers.get("Content-Type") or "").strip()
    finally:
        response.close()

    service = "https" if split.scheme == "https" else "http"
    lines = [
        "[Octopus benchmark exact HTTP probe]",
        f"URL: {target}",
        f"{split.port}/tcp open {service}",
        f"Status: {status}",
    ]
    if server:
        lines.append(f"Server: {server}")
    if content_type:
        lines.append(f"Content-Type: {content_type}")
    lines.extend(("", body.decode("utf-8", "replace")))
    return _bounded_text("\n".join(lines), max_output)


def _run_cli_product(
    profile: str,
    scenario: BenchmarkScenario,
    target: str,
    prompt: str,
    source_environment: Mapping[str, str],
    workspace: Path,
    timeout: float,
    max_output: int,
) -> ProductOutcome:
    prompt_path = workspace / "rules-of-engagement.txt"
    prompt_path.write_text(prompt + "\n", encoding="utf-8")
    product_environment = _product_environment(profile, source_environment, workspace)

    if profile == "strix":
        executable = _resolve_executable(source_environment.get("OCTOBENCH_STRIX_BIN"), "strix", product_environment)
        max_cost_usd = _positive_number(
            scenario.budgets.get("max_cost_usd"),
            "max_cost_usd",
        )
        argv = [
            executable,
            "-n",
            "--target",
            target,
            "--scan-mode",
            STRIX_BENCHMARK_SCAN_MODE,
            "--scope-mode",
            "full",
            "--instruction-file",
            str(prompt_path),
            "--max-budget-usd",
            format(max_cost_usd, ".12g"),
        ]
        accepted = frozenset({0, 2})
    elif profile == "pentestgpt":
        executable = _resolve_executable(
            source_environment.get("OCTOBENCH_PENTESTGPT_BIN"),
            "pentestgpt",
            product_environment,
        )
        model = str(source_environment.get("OCTOBENCH_PENTESTGPT_MODEL") or "").strip()
        if not model:
            raise ProductAdapterError("missing_pentestgpt_model")
        argv = [
            executable,
            "--target",
            target,
            "--model",
            model,
            "--non-interactive",
            "--instruction",
            prompt,
            "--no-telemetry",
        ]
        accepted = frozenset({0})
    elif profile == "shannon":
        source_path = _validated_source_path(scenario, source_environment)
        executable = _resolve_executable(source_environment.get("OCTOBENCH_SHANNON_BIN"), "npx", product_environment)
        argv = [executable]
        if Path(executable).name == "npx":
            package = str(source_environment.get("OCTOBENCH_SHANNON_PACKAGE") or "@keygraph/shannon@1.9.0")
            argv.extend(("--yes", package))
        argv.extend(
            (
                "start",
                "-u",
                target,
                "-r",
                str(source_path),
                "-o",
                str(workspace / "shannon-output"),
                "-w",
                _workspace_name(scenario, source_environment),
            )
        )
        accepted = frozenset({0})
    else:  # pragma: no cover - guarded by caller
        raise ProductAdapterError("unsupported_cli_product")

    exit_code, timed_out, output_exceeded, stdout_text, duration = _run_bounded_process(
        argv,
        cwd=workspace,
        environment=product_environment,
        timeout=timeout,
        max_output=max_output,
    )
    collected = _collect_product_output(workspace, stdout_text, max_output)
    if timed_out:
        status = "timeout"
        error_class = "ProductTimeout"
    elif output_exceeded:
        status = "invalid"
        error_class = "ProductOutputExceeded"
    elif exit_code not in accepted:
        status = "failed"
        error_class = _product_exit_error_class(exit_code)
    else:
        status = "succeeded"
        error_class = ""
    metrics = _extract_structured_metrics(collected)
    return ProductOutcome(
        status=status,
        output_text=collected,
        duration_seconds=duration,
        metrics=metrics,
        error_class=error_class,
    )


def _product_exit_error_class(exit_code: int) -> str:
    if exit_code < 0:
        return f"ProductSignal{abs(exit_code)}"
    return f"ProductExitCode{exit_code}"


def _run_pentagi(
    scenario: BenchmarkScenario,
    target: str,
    prompt: str,
    environment: Mapping[str, str],
    timeout: float,
    max_output: int,
) -> ProductOutcome:
    started = time.monotonic()
    configured_base_url = str(environment.get("OCTOBENCH_PENTAGI_URL") or "").strip()
    token = str(environment.get("OCTOBENCH_PENTAGI_TOKEN") or "")
    provider = str(environment.get("OCTOBENCH_PENTAGI_PROVIDER") or "openai")
    model = str(environment.get("OCTOBENCH_PENTAGI_MODEL") or "").strip()
    if not configured_base_url or not token or not provider or not model:
        raise ProductAdapterError("missing_pentagi_configuration")
    if timeout <= _PENTAGI_CLEANUP_GRACE_SECONDS:
        raise ProductAdapterError("pentagi_timeout_too_short")
    base_url = _pentagi_base_origin(configured_base_url)
    _validate_authorized_target(base_url, environment)
    endpoint = base_url + "/api/v1/graphql"
    context = _pentagi_ssl_context(environment)
    active_deadline = started + timeout - _PENTAGI_CLEANUP_GRACE_SECONDS
    flow_id = ""
    try:
        runtime = _graphql_request(
            endpoint,
            token,
            "query BenchmarkRuntime { settings { version } }",
            {},
            context=context,
            timeout=_pentagi_active_request_timeout(active_deadline),
            max_output=max_output,
        )
        _validate_pentagi_release(runtime)
        created = _graphql_request(
            endpoint,
            token,
            """
            mutation CreateBenchmarkFlow($provider: String!, $input: String!) {
              createFlow(modelProvider: $provider, input: $input) { id status title }
            }
            """,
            {"provider": provider, "input": prompt},
            context=context,
            timeout=_pentagi_active_request_timeout(active_deadline),
            max_output=max_output,
        )
        flow = created.get("createFlow") if isinstance(created, Mapping) else None
        if not isinstance(flow, Mapping) or not flow.get("id"):
            raise ProductAdapterError("pentagi_create_failed")
        flow_id = str(flow["id"])
        final_payload: Mapping[str, Any] = {}
        status = str(flow.get("status") or "created")
        while True:
            final_payload = _graphql_request(
                endpoint,
                token,
                """
                query BenchmarkFlow($id: ID!) {
                  flow(flowId: $id) { id status title provider { name type } }
                  tasks(flowId: $id) { id title status input result }
                  messageLogs(flowId: $id) { id type message result }
                  agentLogs(flowId: $id) { id executor task result }
                  toolCallLogs(flowId: $id) { id status name args result durationSeconds }
                  usageStatsByFlow(flowId: $id) {
                    totalUsageIn totalUsageOut totalUsageCostIn totalUsageCostOut
                  }
                  usageStatsByModelAgentsForFlow(flowId: $id) {
                    model provider agentTypes
                    stats { totalUsageIn totalUsageOut totalUsageCostIn totalUsageCostOut }
                  }
                }
                """,
                {"id": flow_id},
                context=context,
                timeout=_pentagi_active_request_timeout(active_deadline),
                max_output=max_output,
            )
            current_flow = final_payload.get("flow")
            status = str(current_flow.get("status") or status) if isinstance(current_flow, Mapping) else status
            if status in {"finished", "failed"}:
                break
            remaining = active_deadline - time.monotonic()
            if remaining <= 0:
                raise _PentagiDeadlineReached
            time.sleep(min(1.0, remaining))
        _validate_pentagi_execution(
            final_payload,
            expected_provider=provider,
            expected_model=model,
        )
        output = _bounded_text(json.dumps(final_payload, sort_keys=True, default=str), max_output)
        metrics = _pentagi_metrics(final_payload)
        metrics["runtime_attested"] = 1.0
        cleanup_succeeded = _pentagi_delete(endpoint, token, flow_id, context)
        metrics["cleanup_succeeded"] = 1.0 if cleanup_succeeded else 0.0
        outcome_status = "succeeded" if status == "finished" else "failed"
        if outcome_status == "succeeded" and not cleanup_succeeded:
            outcome_status = "partial"
        return ProductOutcome(
            status=outcome_status,
            output_text=output,
            duration_seconds=max(0.0, time.monotonic() - started),
            metrics=metrics,
        )
    except _PentagiDeadlineReached:
        deadline_cleanup_succeeded: bool | None = None
        if flow_id:
            _pentagi_stop(endpoint, token, flow_id, context)
            deadline_cleanup_succeeded = _pentagi_delete(
                endpoint,
                token,
                flow_id,
                context,
            )
        return ProductOutcome(
            status="timeout",
            output_text="",
            duration_seconds=max(0.0, time.monotonic() - started),
            metrics=(
                {
                    "cleanup_succeeded": (
                        1.0 if deadline_cleanup_succeeded else 0.0
                    )
                }
                if deadline_cleanup_succeeded is not None
                else {}
            ),
        )
    except (OSError, ProductAdapterError, urllib.error.URLError, ValueError):
        deadline_reached = time.monotonic() >= active_deadline
        error_cleanup_succeeded: bool | None = None
        if flow_id:
            _pentagi_stop(endpoint, token, flow_id, context)
            error_cleanup_succeeded = _pentagi_delete(
                endpoint,
                token,
                flow_id,
                context,
            )
        return ProductOutcome(
            status="timeout" if deadline_reached else "failed",
            output_text="",
            duration_seconds=max(0.0, time.monotonic() - started),
            metrics=(
                {"cleanup_succeeded": 1.0 if error_cleanup_succeeded else 0.0}
                if error_cleanup_succeeded is not None
                else {}
            ),
        )


def _pentagi_base_origin(value: str) -> str:
    """Canonicalize a PentAGI origin and reject endpoint/path ambiguity."""

    raw = str(value or "").strip()
    split = urlsplit(raw)
    scheme = split.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or not split.hostname
        or split.username
        or split.password
        or split.path not in {"", "/"}
        or split.query
        or split.fragment
    ):
        raise ProductAdapterError("invalid_pentagi_base_origin")
    try:
        port = split.port
    except ValueError:
        raise ProductAdapterError("invalid_pentagi_base_origin") from None
    if port is not None and not 1 <= port <= 65_535:
        raise ProductAdapterError("invalid_pentagi_base_origin")
    host = split.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = 443 if scheme == "https" else 80
    netloc = host if port is None or port == default_port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, "", "", ""))


def _pentagi_active_request_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _PentagiDeadlineReached
    return min(_PENTAGI_REQUEST_TIMEOUT_SECONDS, remaining)


def _graphql_request(
    endpoint: str,
    token: str,
    query: str,
    variables: Mapping[str, Any],
    *,
    context: ssl.SSLContext,
    timeout: float,
    max_output: int,
) -> Mapping[str, Any]:
    payload = json.dumps({"query": query, "variables": dict(variables)}).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _NoRedirectHandler(),
        urllib.request.ProxyHandler({}),
    )
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(max_output + 1)
    if len(raw) > max_output:
        raise ProductAdapterError("pentagi_response_too_large")
    decoded = json.loads(raw.decode("utf-8"))
    if not isinstance(decoded, Mapping) or decoded.get("errors"):
        raise ProductAdapterError("pentagi_graphql_error")
    data = decoded.get("data")
    if not isinstance(data, Mapping):
        raise ProductAdapterError("pentagi_graphql_missing_data")
    return data


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def _pentagi_stop(
    endpoint: str,
    token: str,
    flow_id: str,
    context: ssl.SSLContext,
) -> None:
    with suppress(Exception):
        _graphql_request(
            endpoint,
            token,
            "mutation StopBenchmarkFlow($id: ID!) { stopFlow(flowId: $id) }",
            {"id": flow_id},
            context=context,
            timeout=_PENTAGI_CLEANUP_REQUEST_TIMEOUT_SECONDS,
            max_output=64_000,
        )


def _pentagi_delete(
    endpoint: str,
    token: str,
    flow_id: str,
    context: ssl.SSLContext,
) -> bool:
    try:
        result = _graphql_request(
            endpoint,
            token,
            "mutation DeleteBenchmarkFlow($id: ID!) { deleteFlow(flowId: $id) }",
            {"id": flow_id},
            context=context,
            timeout=_PENTAGI_CLEANUP_REQUEST_TIMEOUT_SECONDS,
            max_output=64_000,
        )
    except Exception:
        return False
    return result.get("deleteFlow") == "success"


def _pentagi_ssl_context(environment: Mapping[str, str]) -> ssl.SSLContext:
    ca_file = str(environment.get("OCTOBENCH_PENTAGI_CA_FILE") or "").strip()
    if ca_file:
        path = Path(ca_file).expanduser().resolve()
        if not path.is_file():
            raise ProductAdapterError("pentagi_ca_unavailable")
        return ssl.create_default_context(cafile=str(path))
    return ssl.create_default_context()


def _pentagi_metrics(payload: Mapping[str, Any]) -> dict[str, float]:
    metrics: dict[str, float] = {}
    tool_logs = payload.get("toolCallLogs")
    if isinstance(tool_logs, Sequence) and not isinstance(tool_logs, (str, bytes)):
        metrics["tool_calls"] = float(len(tool_logs))
    usage = payload.get("usageStatsByFlow")
    if isinstance(usage, Mapping):
        tokens = _reported_metric_sum(usage, ("totalUsageIn", "totalUsageOut"))
        cost = _reported_metric_sum(
            usage,
            ("totalUsageCostIn", "totalUsageCostOut"),
        )
        if tokens is not None:
            metrics["model_tokens"] = tokens
        if cost is not None:
            metrics["api_cost_usd"] = cost
    return metrics


def _validate_pentagi_release(payload: Mapping[str, Any]) -> None:
    settings = payload.get("settings")
    version = str(settings.get("version") or "") if isinstance(settings, Mapping) else ""
    if version != _PENTAGI_RELEASE and not version.startswith(f"{_PENTAGI_RELEASE}-"):
        raise ProductAdapterError("pentagi_release_mismatch")


def _validate_pentagi_execution(
    payload: Mapping[str, Any],
    *,
    expected_provider: str,
    expected_model: str,
) -> None:
    flow = payload.get("flow")
    provider = flow.get("provider") if isinstance(flow, Mapping) else None
    provider_name = str(provider.get("name") or "") if isinstance(provider, Mapping) else ""
    if provider_name != expected_provider:
        raise ProductAdapterError("pentagi_provider_mismatch")
    usage = payload.get("usageStatsByModelAgentsForFlow")
    if not isinstance(usage, Sequence) or isinstance(usage, (str, bytes)) or not usage:
        raise ProductAdapterError("pentagi_model_attestation_missing")
    actual_models = {
        str(item.get("model") or "")
        for item in usage
        if isinstance(item, Mapping)
    }
    if not actual_models or actual_models != {expected_model}:
        raise ProductAdapterError("pentagi_model_mismatch")


def _run_bounded_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    max_output: int,
) -> tuple[int, bool, bool, str, float]:
    started = time.monotonic()
    log_path = cwd / "adapter-stdout.log"
    timed_out = False
    output_exceeded = False
    with log_path.open("wb") as output:
        try:
            process = subprocess.Popen(
                list(argv),
                cwd=str(cwd),
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                shell=False,
                start_new_session=os.name == "posix",
            )
        except (OSError, ValueError):
            raise ProductAdapterError("product_unavailable") from None
        try:
            with _kill_product_on_parent_termination(process):
                deadline = started + timeout
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _terminate_process(process)
                        break
                    with suppress(OSError):
                        if log_path.stat().st_size > max_output:
                            output_exceeded = True
                            _terminate_process(process)
                            break
                    time.sleep(0.05)
        finally:
            if process.poll() is None:
                _terminate_process(process)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1.0)
    with log_path.open("rb") as captured_output:
        raw = captured_output.read(max_output)
    text = raw.decode("utf-8", "replace")
    return (
        int(process.returncode or 0),
        timed_out,
        output_exceeded,
        text,
        max(0.0, time.monotonic() - started),
    )


@contextmanager
def _kill_product_on_parent_termination(
    process: subprocess.Popen[Any],
):
    """Prevent a nested product session surviving its adapter process.

    The outer matrix runner owns a process group for the adapter, while each
    product owns a second group so its own descendants can be bounded. Forward
    SIGTERM/SIGINT synchronously to that nested group before unwinding.
    """

    if os.name != "posix":  # pragma: no cover - live campaigns require Linux
        yield
        return
    previous: dict[int, Any] = {}

    def terminate(signum: int, _frame: Any) -> None:
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGKILL)
        raise SystemExit(128 + signum)

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, terminate)
    except ValueError:
        # Python permits signal handlers only in the main thread. The live
        # adapter runs there; library callers in worker threads retain the
        # ordinary bounded-process cleanup path.
        for saved_signum, handler in previous.items():
            with suppress(ValueError):
                signal.signal(saved_signum, handler)
        yield
        return
    try:
        yield
    finally:
        for saved_signum, handler in previous.items():
            with suppress(ValueError):
                signal.signal(saved_signum, handler)


def _terminate_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGTERM)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.5)
        if process.poll() is None:
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
    else:  # pragma: no cover - Linux is the live campaign target
        process.terminate()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.5)
        if process.poll() is None:
            process.kill()


def _product_environment(
    profile: str,
    source: Mapping[str, str],
    workspace: Path,
) -> dict[str, str]:
    common = {
        "CONTAINER_HOST",
        "DOCKER_CERT_PATH",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "PATH",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "LANG",
        "LC_ALL",
    }
    per_profile = {
        "strix": {
            "LLM_API_BASE",
            "LLM_API_KEY",
            "PERPLEXITY_API_KEY",
            "STRIX_IMAGE",
            "STRIX_LLM",
            "STRIX_REASONING_EFFORT",
        },
        "pentestgpt": {
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "OPENAI_BASE_URL",
            "OPENROUTER_API_KEY",
        },
        "shannon": {
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL",
            "AWS_ACCESS_KEY_ID",
            "AWS_DEFAULT_REGION",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "GOOGLE_APPLICATION_CREDENTIALS",
        },
    }
    names = common | per_profile.get(profile, set())
    result = {name: source[name] for name in names if name in source}
    home = workspace / "home"
    cache = workspace / "cache"
    home.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    result.update(
        {
            "HOME": str(home),
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "PYTHONUNBUFFERED": "1",
            "NO_COLOR": "1",
        }
    )
    if profile == "strix":
        image = str(source.get("STRIX_IMAGE") or "").strip()
        if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-fA-F]{64}", image):
            raise ProductAdapterError("invalid_strix_image")
        result["STRIX_IMAGE"] = image
        # Never emit vendor telemetry outside the declared target/provider
        # paths, regardless of the parent process environment.
        result["STRIX_TELEMETRY"] = "false"
    elif profile == "pentestgpt":
        # PentestGPT v1.0 defaults to manual OAuth and clears an API key unless
        # its explicit Anthropic authentication mode is selected.
        result["PENTESTGPT_AUTH_MODE"] = "anthropic"
    return result


def _resolve_executable(
    configured: str | None,
    default: str,
    environment: Mapping[str, str],
) -> str:
    candidate = str(configured or default).strip()
    if not candidate or "\x00" in candidate:
        raise ProductAdapterError("invalid_executable")
    path = Path(candidate).expanduser()
    if path.is_absolute() or "/" in candidate:
        resolved = path.resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise ProductAdapterError("product_unavailable")
        return str(resolved)
    found = shutil.which(candidate, path=environment.get("PATH"))
    if not found:
        raise ProductAdapterError("product_unavailable")
    return found


def _collect_product_output(root: Path, stdout: str, limit: int) -> str:
    chunks = [stdout]
    used = len(stdout.encode("utf-8", "replace"))
    for path in sorted(root.rglob("*")):
        if used >= limit or not path.is_file() or path.is_symlink():
            break
        if path.name == "adapter-stdout.log":
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        if path.name.lower() in _SENSITIVE_FILENAMES or "secret" in path.name.lower():
            continue
        try:
            raw = path.read_bytes()[: max(0, limit - used)]
        except OSError:
            continue
        text = raw.decode("utf-8", "replace")
        chunks.append(text)
        used += len(raw)
    return _bounded_text("\n".join(chunks), limit)


def _extract_structured_metrics(text: str) -> dict[str, float]:
    metrics: dict[str, float] = {}
    # Product logs differ substantially.  Only accept explicitly named numeric
    # fields; never infer counts or cost from natural-language prose.
    patterns = {
        "tool_calls": r'(?i)["\']?(?:tool_calls|toolCalls)["\']?\s*[:=]\s*(\d+)',
        "model_calls": r'(?i)["\']?(?:model_calls|modelCalls)["\']?\s*[:=]\s*(\d+)',
        "model_tokens": r'(?i)["\']?(?:total_tokens|totalTokens)["\']?\s*[:=]\s*(\d+)',
        "api_cost_usd": r'(?i)["\']?(?:api_cost_usd|total_cost_usd)["\']?\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)',
    }
    for name, pattern in patterns.items():
        values = [_safe_float(item) for item in re.findall(pattern, text[:_MAX_CAPTURE_BYTES])]
        if values:
            metrics[name] = max(values)
    return metrics


def _load_matchers(scenario: BenchmarkScenario) -> tuple[FindingMatcher, ...]:
    normalization = scenario.artifacts.get("normalization")
    if not isinstance(normalization, Mapping):
        raise ProductAdapterError("missing_normalization_contract")
    if str(normalization.get("schema_version") or "") != "1.0":
        raise ProductAdapterError("unsupported_normalization_contract")
    raw_matchers = normalization.get("findings")
    if not isinstance(raw_matchers, Sequence) or isinstance(raw_matchers, (str, bytes)):
        raise ProductAdapterError("invalid_normalization_matchers")
    if not raw_matchers or len(raw_matchers) > _MAX_MATCHERS:
        raise ProductAdapterError("invalid_normalization_matcher_count")
    result: list[FindingMatcher] = []
    seen: set[str] = set()
    for raw in raw_matchers:
        if not isinstance(raw, Mapping):
            raise ProductAdapterError("invalid_normalization_matcher")
        finding_id = str(raw.get("finding_id") or "").strip().lower()
        if not _FINDING_ID.fullmatch(finding_id) or finding_id in seen:
            raise ProductAdapterError("invalid_normalization_finding_id")
        reported = _needles(raw.get("reported_contains") or [])
        verified = _needles(raw.get("verified_contains") or [])
        if not reported and not verified:
            raise ProductAdapterError("empty_normalization_matcher")
        seen.add(finding_id)
        result.append(FindingMatcher(finding_id, reported, verified))
    expected_or_forbidden = _identifier_set(
        tuple(scenario.ground_truth.get("expected_findings") or [])
        + tuple(scenario.ground_truth.get("forbidden_findings") or [])
    )
    if not expected_or_forbidden.issubset(seen):
        raise ProductAdapterError("normalization_missing_ground_truth_id")
    return tuple(result)


def _needles(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ProductAdapterError("invalid_normalization_needles")
    if len(value) > _MAX_NEEDLES:
        raise ProductAdapterError("too_many_normalization_needles")
    result: list[str] = []
    for item in value:
        needle = str(item or "").strip()
        if not needle or len(needle.encode("utf-8", "replace")) > _MAX_NEEDLE_BYTES:
            raise ProductAdapterError("invalid_normalization_needle")
        if needle not in result:
            result.append(needle)
    return tuple(result)


def _normalize_findings(
    output: str,
    matchers: Sequence[FindingMatcher],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    haystack = output.casefold()
    reported: list[str] = []
    verified: list[str] = []
    for matcher in matchers:
        reported_hit = any(item.casefold() in haystack for item in matcher.reported_contains)
        verified_hit = any(item.casefold() in haystack for item in matcher.verified_contains)
        if reported_hit or verified_hit:
            reported.append(matcher.finding_id)
        if verified_hit:
            verified.append(matcher.finding_id)
    return tuple(reported), tuple(verified)


def _validate_authorization(
    scenario: BenchmarkScenario,
    environment: Mapping[str, str],
) -> None:
    if str(environment.get("OCTOBENCH_ACK_AUTHORIZED") or "") != "YES":
        raise ProductAdapterError("authorization_ack_required")
    if str(environment.get("OCTOBENCH_ACK_ISOLATED_HOST") or "") != "YES":
        raise ProductAdapterError("isolation_ack_required")
    authorization_ref = str(scenario.lab.get("authorization_ref") or "").strip()
    scope_ref = str(scenario.target.get("scope_ref") or "").strip()
    snapshot_ref = str(scenario.lab.get("snapshot_ref") or "").strip()
    for value in (authorization_ref, scope_ref, snapshot_ref):
        if not value or _contains_placeholder(value):
            raise ProductAdapterError("incomplete_authorization_contract")
    reset_policy = str(scenario.lab.get("reset_policy") or "").strip()
    if not reset_policy or _contains_placeholder(reset_policy):
        raise ProductAdapterError("missing_reset_policy")


def _target_address(
    scenario: BenchmarkScenario,
    environment: Mapping[str, str],
) -> str:
    target = str(
        environment.get("OCTOBENCH_TARGET_URL")
        or scenario.target.get("address")
        or scenario.target.get("url")
        or scenario.target.get("host")
        or ""
    ).strip()
    if not target or _contains_placeholder(target) or len(target.encode()) > 4_096:
        raise ProductAdapterError("invalid_target")
    return target


def _validate_authorized_target(target: str, environment: Mapping[str, str]) -> None:
    split = urlsplit(target if "://" in target else f"//{target}")
    host = split.hostname
    if not host or split.username or split.password:
        raise ProductAdapterError("invalid_target")
    if split.scheme and split.scheme not in {"http", "https"}:
        raise ProductAdapterError("unsupported_target_scheme")
    if split.port is not None and not 1 <= split.port <= 65_535:
        raise ProductAdapterError("invalid_target_port")
    allowed_names = {
        item.strip().lower()
        for item in str(environment.get("OCTOBENCH_ALLOWED_HOSTS") or "").split(",")
        if item.strip()
    }
    lower = host.rstrip(".").lower()
    if lower in allowed_names or lower == "localhost" or lower.endswith(".localhost"):
        return
    try:
        address = ipaddress.ip_address(lower)
    except ValueError:
        if lower.endswith((".internal", ".test")):
            return
        try:
            resolved = {str(item[4][0]) for item in socket.getaddrinfo(lower, split.port or 0, type=socket.SOCK_STREAM)}
        except OSError:
            raise ProductAdapterError("target_resolution_failed") from None
        if not resolved or any(not _private_address(item) for item in resolved):
            raise ProductAdapterError("public_target_rejected") from None
        return
    if not (address.is_private or address.is_loopback or address.is_link_local):
        raise ProductAdapterError("public_target_rejected")


def _private_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _target_host(target: str) -> str:
    split = urlsplit(target if "://" in target else f"//{target}")
    if not split.hostname:
        raise ProductAdapterError("invalid_target")
    return split.hostname


def _validated_source_path(
    scenario: BenchmarkScenario,
    environment: Mapping[str, str],
) -> Path:
    raw = str(scenario.target.get("source_path") or "").strip()
    root_raw = str(environment.get("OCTOBENCH_SOURCE_ROOT") or "").strip()
    if not raw or not root_raw:
        raise ProductAdapterError("whitebox_source_required")
    root = Path(root_raw).expanduser().resolve()
    candidate = Path(raw).expanduser()
    source = (candidate if candidate.is_absolute() else root / candidate).resolve()
    try:
        source.relative_to(root)
    except ValueError:
        raise ProductAdapterError("whitebox_source_outside_root") from None
    if not source.is_dir():
        raise ProductAdapterError("whitebox_source_unavailable")
    return source


def _workspace_name(
    scenario: BenchmarkScenario,
    environment: Mapping[str, str],
) -> str:
    repetition = str(environment.get("OCTOPUS_BENCHMARK_REPETITION") or "0")
    seed = str(environment.get("OCTOPUS_BENCHMARK_SEED") or scenario.seed)
    raw = f"octobench-{scenario.scenario_id}-{repetition}-{seed}".lower()
    return re.sub(r"[^a-z0-9_.-]+", "-", raw)[:120]


def _identifier_set(values: Any) -> set[str]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ProductAdapterError("invalid_ground_truth_findings")
    result = {str(value or "").strip().lower() for value in values}
    if any(not _FINDING_ID.fullmatch(item) for item in result):
        raise ProductAdapterError("invalid_ground_truth_finding_id")
    return result


def _contains_placeholder(value: str) -> bool:
    lower = str(value or "").lower()
    return any(marker in lower for marker in _PLACEHOLDER_MARKERS)


def _positive_integer(value: Any) -> int:
    if isinstance(value, bool):
        raise ProductAdapterError("invalid_positive_integer")
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise ProductAdapterError("invalid_positive_integer") from None
    if result <= 0:
        raise ProductAdapterError("invalid_positive_integer")
    return result


def _positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ProductAdapterError(f"invalid_{name}")
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ProductAdapterError(f"invalid_{name}") from None
    if not math.isfinite(result) or result <= 0:
        raise ProductAdapterError(f"invalid_{name}")
    return result


def _bounded_integer(value: Any, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = minimum
    return max(minimum, min(maximum, parsed))


def _safe_float(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.0
    return parsed if math.isfinite(parsed) and parsed >= 0 else 0.0


def _reported_metric_sum(
    payload: Mapping[str, Any],
    names: Sequence[str],
) -> float | None:
    values: list[float] = []
    for name in names:
        if name not in payload or isinstance(payload[name], bool):
            return None
        try:
            value = float(payload[name])
        except (TypeError, ValueError):
            return None
        if not math.isfinite(value) or value < 0:
            return None
        values.append(value)
    return sum(values)


def _reported_budget_overrun(
    budgets: Mapping[str, Any],
    metrics: Mapping[str, float],
) -> bool:
    for budget_name, metric_name in _REPORTED_BUDGET_METRICS:
        if budget_name not in budgets or metric_name not in metrics:
            continue
        try:
            limit = float(budgets[budget_name])
        except (TypeError, ValueError):
            raise ProductAdapterError("invalid_budget_limit") from None
        if not math.isfinite(limit) or limit <= 0:
            raise ProductAdapterError("invalid_budget_limit")
        if metrics[metric_name] > limit:
            return True
    return False


def _valid_metric(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return False
    return math.isfinite(parsed) and parsed >= 0


def _bounded_text(value: str, maximum_bytes: int) -> str:
    raw = str(value or "").encode("utf-8", "replace")[:maximum_bytes]
    return raw.decode("utf-8", "ignore")


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _failed_result() -> dict[str, Any]:
    return {
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


if __name__ == "__main__":
    raise SystemExit(main())
