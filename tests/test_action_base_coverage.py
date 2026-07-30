"""Hermetic branch coverage for the shared action adapter contract."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.actions import base
from core.actions.base import ActionAdapter
from core.actions.models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActiveRiskClass,
)
from core.execution import ExecutionContext, ExecutionResult

pytestmark = pytest.mark.unit


class FixtureAdapter(ActionAdapter):
    def __init__(self, requirements: ActionRequirements | None = None) -> None:
        self.descriptor = ActionDescriptor(
            action_id="fixture:action",
            name="fixture",
            kind=ActionKind.REGISTERED_TOOL,
            provider="fixture",
            requirements=requirements or ActionRequirements(),
        )

    def invocation(self, request: ActionRequest, phase: str):
        del phase
        return self.registered_invocation(
            f"fixture {request.target}",
            "fixture",
        )

    def execute(self, request: ActionRequest):
        return {"target": request.target}


def _request(
    target: str = "example.com",
    *,
    capabilities: frozenset[str] | None = None,
    evidence_fact_ids: tuple[int, ...] = (),
    assessment_refs: tuple[str, ...] = (),
    source_execution_ids: tuple[str, ...] = (),
) -> ActionRequest:
    context = ExecutionContext(
        actor="fixture",
        origin="test",
        target_scope=(target,) if target else (),
        capabilities=(
            frozenset({"present"})
            if capabilities is None
            else capabilities
        ),
        request_id="fixture-request",
        max_output_bytes=321,
    )
    return ActionRequest(
        target,
        context,
        evidence_fact_ids=evidence_fact_ids,
        assessment_refs=assessment_refs,
        source_execution_ids=source_execution_ids,
    )


def test_applicability_reports_each_missing_requirement_and_satisfied_state(
    monkeypatch,
) -> None:
    requirements = ActionRequirements(
        system_dependencies=("available-bin", "missing-bin"),
        python_dependencies=(
            "present-pkg[extra]",
            "missing-pkg",
            "broken-pkg",
        ),
        capabilities=("present", "missing"),
    )
    adapter = FixtureAdapter(requirements)
    monkeypatch.setattr(
        base.shutil,
        "which",
        lambda dependency: "/fixture/bin" if dependency == "available-bin" else None,
    )

    def fake_find_spec(import_name):
        if import_name == "present_pkg":
            return object()
        if import_name == "broken_pkg":
            raise ValueError("invalid import fixture")
        return None

    monkeypatch.setattr(base.importlib.util, "find_spec", fake_find_spec)

    missing = adapter.applicability(_request(""))

    assert missing.applicable is False
    assert missing.reasons == ()
    assert missing.missing_requirements == (
        "target",
        "binary:missing-bin",
        "python:missing-pkg",
        "python:broken-pkg",
        "capability:missing",
    )

    monkeypatch.setattr(base.shutil, "which", lambda _dependency: "/fixture/bin")
    monkeypatch.setattr(base.importlib.util, "find_spec", lambda _name: object())
    satisfied = adapter.applicability(
        _request(
            capabilities=frozenset(
                {"present", "missing"}
            )
        )
    )
    assert satisfied.applicable is True
    assert satisfied.reasons == ("requirements_satisfied",)
    assert satisfied.missing_requirements == ()


def test_default_risk_check_verification_and_cleanup_contracts() -> None:
    request = _request()
    readonly = FixtureAdapter()
    active = FixtureAdapter(ActionRequirements(active=True))

    assert readonly.active_risk_class(request) is ActiveRiskClass.READ_ONLY
    assert active.active_risk_class(request, "check") is ActiveRiskClass.ACTIVE
    with pytest.raises(NotImplementedError, match="fixture:action has no check phase"):
        readonly.check(request)

    unverified = readonly.verify(request, ExecutionResult())
    assert unverified.verified is False
    assert "not independent evidence" in unverified.reason

    evidence_request = _request(
        evidence_fact_ids=(7,),
        assessment_refs=("assessment://verified",),
        source_execution_ids=("execution-1",),
    )
    verified = readonly.verify(evidence_request, ExecutionResult())
    assert verified.verified is True
    assert verified.evidence_fact_ids == (7,)
    assert verified.assessment_refs == ("assessment://verified",)
    assert verified.source_execution_ids == ("execution-1",)

    cleanup = readonly.cleanup(request, None)
    assert cleanup.succeeded is True
    assert cleanup.reason == "No adapter cleanup required."


def test_authorization_and_registered_invocation_forward_typed_values() -> None:
    adapter = FixtureAdapter()
    request = _request()
    decision = object()
    calls = []

    class PolicySpy:
        def authorize_registered(self, invocation, context):
            calls.append((invocation, context))
            return decision

    assert adapter.authorize(PolicySpy(), request, "execute") is decision
    invocation, context = calls[0]
    assert invocation.executable == "fixture"
    assert invocation.argv == ("fixture", "example.com")
    assert invocation.registered_name == "fixture"
    assert context is request.execution_context

    direct = ActionAdapter.registered_invocation("fixture --safe", "registered")
    assert direct.argv == ("fixture", "--safe")
    assert direct.registered_name == "registered"


def test_normalize_result_forwards_redaction_and_resource_boundaries(
    monkeypatch,
) -> None:
    adapter = FixtureAdapter()
    request = _request()
    observed = {}
    normalized = SimpleNamespace(status="normalized")
    redact_text = object()
    redact_data = object()

    def fake_adapt(value, **kwargs):
        observed["value"] = value
        observed.update(kwargs)
        return normalized

    monkeypatch.setattr(base, "adapt_execution_result", fake_adapt)
    raw = {"status": "succeeded", "output": "fixture"}

    assert adapter.normalize_result(
        raw,
        request,
        phase="execute",
        redact_text=redact_text,
        redact_data=redact_data,
    ) is normalized
    assert observed == {
        "value": raw,
        "request_id": "fixture-request",
        "tool_name": "fixture",
        "max_output_bytes": 321,
        "redact_text": redact_text,
        "redact_data": redact_data,
    }
