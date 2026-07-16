"""Unified action catalog, adapters, and policy-gated lifecycle contracts."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.actions import (
    ActionAdapter,
    ActionCatalog,
    ActionCheckResult,
    ActionCleanupResult,
    ActionDescriptor,
    ActionExecutor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActionVerificationResult,
    ApplicabilityStatus,
    AttemptStatus,
    CheckStatus,
    CleanupStatus,
    ExploitBaseAdapter,
    MetasploitActionAdapter,
    OutcomeStatus,
    PluginActionAdapter,
    RegisteredToolAdapter,
    VerificationStatus,
)
from core.ai.runtime import PipelineRuntime
from core.execution import ExecutionCancelled, ExecutionContext, ExecutionPolicy
from core.killchain.exploits.base import ExploitBase
from core.plugins.base import CheckResult as PluginCheckResult
from core.plugins.base import PluginResult
from core.secrets import Redactor, SecretStore
from core.tools.registry import ToolDef


def automatic(target: str = "example.com") -> ExecutionContext:
    return ExecutionContext.automatic(
        target_scope=(target,),
        actor="action-test",
        origin="test",
    )


def approved(target: str = "example.com") -> ExecutionContext:
    return ExecutionContext.operator(
        actor="action-test",
        approval_id="approval-1",
        target_scope=(target,),
        allow_active_tools=True,
    )


class RecordingPolicy(ExecutionPolicy):
    def __init__(self, events: list[str]):
        self.events = events

    def authorize_registered(self, invocation, context):
        self.events.append("policy")
        return super().authorize_registered(invocation, context)


class RecordingAdapter(ActionAdapter):
    def __init__(
        self,
        events: list[str],
        *,
        policy_name: str = "nmap",
        cleanup_succeeds: bool = True,
        raises: Exception | None = None,
    ):
        self.events = events
        self.policy_name = policy_name
        self.cleanup_succeeds = cleanup_succeeds
        self.raises = raises
        self.execute_calls = 0
        self.descriptor = ActionDescriptor(
            action_id="test:recording",
            name="recording",
            kind=ActionKind.REGISTERED_TOOL,
            provider="test",
            requirements=ActionRequirements(
                supports_check=True,
                supports_cleanup=True,
                positive_check_required=True,
            ),
        )

    def invocation(self, request, phase):
        return self.registered_invocation(
            f"{self.policy_name} {request.target}",
            self.policy_name,
        )

    def check(self, request):
        self.events.append("check")
        return ActionCheckResult(
            result={"status": "succeeded", "output": "check complete"},
            applicable=True,
            reason="positive check",
        )

    def execute(self, request):
        self.events.append("execute")
        self.execute_calls += 1
        if self.raises:
            raise self.raises
        return {"status": "succeeded", "output": "provider succeeded"}

    def verify(self, request, result):
        self.events.append("verify")
        return ActionVerificationResult(
            verified=True,
            reason="independent evidence",
            evidence_fact_ids=(7,),
            assessment_refs=("fa_verified",),
            source_execution_ids=(result.execution_id,),
        )

    def cleanup(self, request, result):
        self.events.append("cleanup")
        return ActionCleanupResult(
            succeeded=self.cleanup_succeeds,
            reason="cleanup fixture",
        )


def executor_for(adapter: ActionAdapter, *, events: list[str] | None = None) -> ActionExecutor:
    catalog = ActionCatalog()
    catalog.register(adapter)
    return ActionExecutor(catalog, RecordingPolicy(events) if events is not None else ExecutionPolicy())


def test_lifecycle_keeps_candidate_check_attempt_success_verification_and_cleanup_distinct():
    events: list[str] = []
    adapter = RecordingAdapter(events)
    report = executor_for(adapter, events=events).run(
        adapter.descriptor.action_id,
        ActionRequest("example.com", automatic()),
    )

    assert events == ["policy", "check", "policy", "execute", "verify", "cleanup"]
    assert report.lifecycle.candidate is True
    assert report.lifecycle.applicability is ApplicabilityStatus.APPLICABLE
    assert report.lifecycle.check is CheckStatus.COMPLETED
    assert report.lifecycle.check_positive is True
    assert report.lifecycle.attempt is AttemptStatus.ATTEMPTED
    assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED
    assert report.lifecycle.verification is VerificationStatus.VERIFIED
    assert report.lifecycle.cleanup is CleanupStatus.SUCCEEDED
    assert len(report.policy_decision_refs) == 2
    assert all(item.startswith("policy://sha256/") for item in report.policy_decision_refs)


def test_final_policy_denial_blocks_provider_even_after_candidate_selection():
    events: list[str] = []
    adapter = RecordingAdapter(events, policy_name="msf_run")
    adapter.descriptor = ActionDescriptor(
        action_id="test:active",
        name="active",
        kind=ActionKind.METASPLOIT,
        provider="test",
        requirements=ActionRequirements(active=True),
    )
    report = executor_for(adapter, events=events).run(
        "test:active",
        ActionRequest("example.com", automatic()),
    )

    assert events == ["policy"]
    assert adapter.execute_calls == 0
    assert report.lifecycle.applicability is ApplicabilityStatus.APPLICABLE
    assert report.lifecycle.attempt is AttemptStatus.BLOCKED
    assert report.lifecycle.outcome is OutcomeStatus.BLOCKED
    assert report.lifecycle.verification is VerificationStatus.NOT_RUN


def test_cleanup_failure_does_not_relabel_success_or_verification():
    events: list[str] = []
    adapter = RecordingAdapter(events, cleanup_succeeds=False)
    report = executor_for(adapter, events=events).run(
        "test:recording",
        ActionRequest("example.com", automatic()),
    )

    assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED
    assert report.lifecycle.verification is VerificationStatus.VERIFIED
    assert report.lifecycle.cleanup is CleanupStatus.FAILED
    assert report.cleanup_result and report.cleanup_result.succeeded is False


def test_exception_is_redacted_and_cleanup_still_runs():
    events: list[str] = []
    adapter = RecordingAdapter(
        events,
        raises=RuntimeError("password=action-lifecycle-secret"),
    )
    store = SecretStore(":memory:")
    redactor = Redactor(store)
    catalog = ActionCatalog()
    catalog.register(adapter)
    executor = ActionExecutor(
        catalog,
        RecordingPolicy(events),
        redact_text=redactor.redact_text,
        redact_data=redactor.redact_data,
    )

    report = executor.run(
        "test:recording",
        ActionRequest("example.com", automatic()),
    )

    assert report.lifecycle.outcome is OutcomeStatus.FAILED
    assert report.lifecycle.cleanup is CleanupStatus.SUCCEEDED
    assert "action-lifecycle-secret" not in report.execution_result.error_message
    assert "action-lifecycle-secret" not in str(report.to_dict())
    assert events[-1] == "cleanup"


def test_typed_cancellation_preserves_partial_output_and_still_runs_cleanup():
    events: list[str] = []
    adapter = RecordingAdapter(
        events,
        raises=ExecutionCancelled(
            "operator_request",
            stdout="partial provider output",
            returncode=-15,
        ),
    )
    report = executor_for(adapter, events=events).run(
        "test:recording",
        ActionRequest("example.com", automatic()),
    )

    assert report.lifecycle.outcome is OutcomeStatus.CANCELLED
    assert report.lifecycle.cleanup is CleanupStatus.SUCCEEDED
    assert report.execution_result.partial is True
    assert report.execution_result.stdout == "partial provider output"
    assert events[-1] == "cleanup"


def test_registered_tool_adapter_preserves_aliases_and_does_not_equate_success_with_verified():
    calls = []
    tool = ToolDef(
        name="fixture_probe",
        aliases=["fixture_alias"],
        category="recon",
        func=lambda target: target,
        needs_target=True,
    )
    adapter = RegisteredToolAdapter(
        tool,
        lambda command, context: calls.append((command, context.request_id)) or "[+] complete",
    )
    catalog = ActionCatalog()
    catalog.register(adapter)
    executor = ActionExecutor(catalog, ExecutionPolicy())

    report = executor.run(
        "fixture_alias",
        ActionRequest("example.com", automatic()),
    )

    assert catalog.resolve("fixture_alias").canonical_id == "tool:fixture_probe"
    assert calls and calls[0][0] == "fixture_probe example.com"
    assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED
    assert report.lifecycle.verification is VerificationStatus.UNVERIFIED
    assert report.lifecycle.cleanup is CleanupStatus.NOT_REQUIRED


def test_catalog_rejects_alias_collisions():
    first = RegisteredToolAdapter(
        ToolDef(name="first", aliases=["shared"], func=lambda: None, needs_target=False),
        lambda _command, _context: "",
    )
    second = RegisteredToolAdapter(
        ToolDef(name="second", aliases=["shared"], func=lambda: None, needs_target=False),
        lambda _command, _context: "",
    )
    catalog = ActionCatalog()
    catalog.register(first)

    with pytest.raises(ValueError, match="alias collision"):
        catalog.register(second)


def test_candidate_listing_is_read_only():
    events: list[str] = []
    adapter = RecordingAdapter(events)
    catalog = ActionCatalog()
    catalog.register(adapter)

    candidates = catalog.candidates(ActionRequest("example.com", automatic()))

    assert len(candidates) == 1
    assert candidates[0][1].applicable is True
    assert adapter.execute_calls == 0
    assert events == []


def test_pipeline_runtime_exposes_catalog_and_action_execution(tmp_path):
    calls = []
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda command: calls.append(command) or "fixture complete",
    )
    assert runtime.action_catalog.resolve("waf_detect") is not None

    report = runtime.execute_action(
        "waf_detect",
        ActionRequest("example.com", automatic()),
    )

    assert calls == ["waf_detect example.com"]
    assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED
    assert report.lifecycle.verification is VerificationStatus.UNVERIFIED


class FixtureExploit(ExploitBase):
    name = "Fixture Exploit"
    cve = "CVE-2099-12345"

    def check_vulnerable(self, client):
        return True, "independent check marker"

    def run(self, client):
        return True, "provider run completed"


def test_exploit_base_adapter_wraps_check_and_run_without_auto_verification():
    adapter = ExploitBaseAdapter(FixtureExploit())
    report = executor_for(adapter).run(
        adapter.descriptor.action_id,
        ActionRequest("example.com", approved(), handle=object()),
    )

    assert report.lifecycle.check is CheckStatus.COMPLETED
    assert report.lifecycle.check_positive is True
    assert report.lifecycle.attempt is AttemptStatus.ATTEMPTED
    assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED
    assert report.lifecycle.verification is VerificationStatus.UNVERIFIED


def test_metasploit_adapter_has_separate_check_and_execute_modes():
    calls = []

    def runner(module, options, timeout=None, mode="run"):
        calls.append((module, options, timeout, mode))
        return "The target appears to be vulnerable" if mode == "check" else "session opened"

    adapter = MetasploitActionAdapter(
        "exploit/test/fixture_module",
        runner=runner,
        dependency_check=lambda _name: True,
    )
    report = executor_for(adapter).run(
        adapter.descriptor.action_id,
        ActionRequest("example.com", approved()),
    )

    assert [item[3] for item in calls] == ["check", "run"]
    assert all("RHOSTS=example.com" in item[1] for item in calls)
    assert report.lifecycle.check_positive is True
    assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED
    assert report.lifecycle.verification is VerificationStatus.UNVERIFIED
    with pytest.raises(ValueError, match="module identifier"):
        MetasploitActionAdapter("exploit/test;bad", runner=runner)


def test_metasploit_unavailable_is_not_attempted():
    calls = []
    adapter = MetasploitActionAdapter(
        "auxiliary/test/fixture",
        runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        dependency_check=lambda _name: False,
    )
    report = executor_for(adapter).run(
        adapter.descriptor.action_id,
        ActionRequest("example.com", automatic()),
    )

    assert report.lifecycle.applicability is ApplicabilityStatus.NOT_APPLICABLE
    assert report.lifecycle.attempt is AttemptStatus.NOT_ATTEMPTED
    assert calls == []


class FixturePluginManager:
    def __init__(self, *, vulnerable: bool = True, cleanup_failed: bool = False):
        self.vulnerable = vulnerable
        self.cleanup_failed = cleanup_failed
        self.execute_calls = 0
        self.descriptor = SimpleNamespace(
            name="fixture_plugin",
            version="1.2.3",
            plugin_type="exploit",
            description="fixture",
            requires=[],
            python_deps=[],
            capabilities=["network"],
        )

    def get_plugin(self, name):
        return self.descriptor if name == self.descriptor.name else None

    def validate(self, name):
        return []

    def check(self, name, target, timeout=120):
        return PluginCheckResult(
            vulnerable=self.vulnerable,
            confidence=0.9,
            details="checked",
            evidence="fixture evidence",
        )

    def execute(self, name, **kwargs):
        self.execute_calls += 1
        marker = "cleanup failed: fixture" if self.cleanup_failed else "plugin complete"
        return PluginResult(success=True, output=marker)


def test_plugin_adapter_preserves_worker_cleanup_outcome():
    manager = FixturePluginManager(cleanup_failed=True)
    adapter = PluginActionAdapter(manager, "fixture_plugin")
    report = executor_for(adapter).run(
        adapter.descriptor.action_id,
        ActionRequest("example.com", approved()),
    )

    assert manager.execute_calls == 1
    assert report.lifecycle.check_positive is True
    assert report.lifecycle.outcome is OutcomeStatus.SUCCEEDED
    assert report.lifecycle.cleanup is CleanupStatus.FAILED


def test_negative_plugin_check_stays_checked_but_is_not_attempted():
    manager = FixturePluginManager(vulnerable=False)
    adapter = PluginActionAdapter(manager, "fixture_plugin")
    report = executor_for(adapter).run(
        adapter.descriptor.action_id,
        ActionRequest("example.com", approved()),
    )

    assert report.lifecycle.check is CheckStatus.COMPLETED
    assert report.lifecycle.check_positive is False
    assert report.lifecycle.applicability is ApplicabilityStatus.NOT_APPLICABLE
    assert report.lifecycle.attempt is AttemptStatus.NOT_ATTEMPTED
    assert manager.execute_calls == 0
