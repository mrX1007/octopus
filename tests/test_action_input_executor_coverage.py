"""Hermetic branch coverage for typed action inputs and executor contracts."""

from __future__ import annotations

import builtins
from dataclasses import replace

import pytest

from core.actions.base import ActionAdapter
from core.actions.catalog import ActionCatalog
from core.actions.executor import ActionExecutor
from core.actions.input_contracts import (
    ArtifactInput,
    C2ChannelInput,
    CredentialInput,
    PayloadKeyingInput,
    PivotRouteInput,
    RemoteExecInput,
    ScanTarget,
    validate_typed_input,
)
from core.actions.models import (
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
)
from core.execution import ExecutionContext, ExecutionPolicy, ToolInvocation

pytestmark = [pytest.mark.unit, pytest.mark.contract, pytest.mark.security]

TARGET = "192.0.2.10"


class _GuardAdapter(ActionAdapter):
    """Contract-only adapter whose provider boundary must never be reached."""

    def __init__(
        self,
        *,
        input_type: type | None = None,
        required_preconditions: tuple[str, ...] = (),
    ) -> None:
        self.descriptor = ActionDescriptor(
            action_id="fixture:input-executor-coverage",
            name="input_executor_coverage",
            kind=ActionKind.KILLCHAIN,
            provider="fixture:unmounted",
            input_type=input_type,
            required_preconditions=required_preconditions,
            requirements=ActionRequirements(target_required=True),
        )

    def invocation(self, request: ActionRequest, phase: str) -> ToolInvocation:
        del request, phase
        return ToolInvocation(
            executable="input_executor_coverage",
            argv=("input_executor_coverage",),
            registered_name=self.descriptor.name,
        )

    def execute(self, request: ActionRequest) -> object:
        del request
        raise AssertionError("hermetic contract test reached provider execution")


def _context() -> ExecutionContext:
    return ExecutionContext.automatic(
        target_scope=(TARGET,),
        actor="input-executor-coverage",
        origin="test",
    )


def _executor() -> ActionExecutor:
    return ActionExecutor(ActionCatalog(), ExecutionPolicy())


def _fact(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": 1,
        "host": TARGET,
        "type": "confirmed_pivot",
        "assessment_status": "verified",
        "trust_level": "trusted",
    }
    value.update(changes)
    return value


@pytest.mark.parametrize(
    ("value", "expected_type", "request_target", "expected_failures"),
    [
        pytest.param(
            object(),
            CredentialInput,
            TARGET,
            {"blocked_by_input:typed_input:CredentialInput"},
            id="wrong-input-contract",
        ),
        pytest.param(
            CredentialInput(7, TARGET),  # type: ignore[arg-type]
            CredentialInput,
            TARGET,
            {"blocked_by_input:credential_ref"},
            id="non-string-reference",
        ),
        pytest.param(
            CredentialInput("not-a-reference", TARGET),
            CredentialInput,
            TARGET,
            {"blocked_by_input:credential_ref"},
            id="invalid-reference-prefix",
        ),
        pytest.param(
            PivotRouteInput("fact://0", ScanTarget(TARGET)),
            PivotRouteInput,
            TARGET,
            {"blocked_by_input:pivot_route_ref"},
            id="non-canonical-pivot-reference",
        ),
        pytest.param(
            CredentialInput("credential://opaque", 7),  # type: ignore[arg-type]
            CredentialInput,
            TARGET,
            {"blocked_by_input:typed_input_target"},
            id="non-string-typed-target",
        ),
        pytest.param(
            PivotRouteInput(
                "fact://1",
                ScanTarget(7, ports=8, protocol=()),  # type: ignore[arg-type]
            ),
            PivotRouteInput,
            TARGET,
            {
                "blocked_by_input:scan_target.host",
                "blocked_by_input:scan_target.ports",
                "blocked_by_input:scan_target.protocol",
            },
            id="malformed-nested-scan-target",
        ),
        pytest.param(
            PivotRouteInput("fact://1", ScanTarget("")),
            PivotRouteInput,
            TARGET,
            {"blocked_by_input:scan_target.host"},
            id="empty-nested-scan-host",
        ),
        pytest.param(
            PivotRouteInput("fact://1", None),  # type: ignore[arg-type]
            PivotRouteInput,
            TARGET,
            {"blocked_by_input:scan_target"},
            id="missing-nested-scan-target",
        ),
        pytest.param(
            CredentialInput("credential://opaque", TARGET),
            CredentialInput,
            "",
            {"blocked_by_input:request_target_required"},
            id="typed-target-without-request-target",
        ),
        pytest.param(
            CredentialInput("credential://opaque", "198.51.100.7"),
            CredentialInput,
            TARGET,
            {"blocked_by_input:typed_input_target_mismatch"},
            id="typed-target-mismatch",
        ),
        pytest.param(
            ScanTarget(7, ports=8, protocol=()),  # type: ignore[arg-type]
            ScanTarget,
            TARGET,
            {
                "blocked_by_input:host",
                "blocked_by_input:ports",
                "blocked_by_input:protocol",
            },
            id="malformed-direct-scan-target",
        ),
        pytest.param(
            C2ChannelInput(TARGET, "https", callback_endpoint=7),  # type: ignore[arg-type]
            C2ChannelInput,
            TARGET,
            {"blocked_by_input:callback_endpoint"},
            id="non-string-callback",
        ),
        pytest.param(
            C2ChannelInput(TARGET, ""),
            C2ChannelInput,
            TARGET,
            {"blocked_by_input:transport_type"},
            id="empty-transport",
        ),
        pytest.param(
            RemoteExecInput("credential://opaque", TARGET, ""),
            RemoteExecInput,
            TARGET,
            {"blocked_by_input:command"},
            id="empty-remote-command",
        ),
        pytest.param(
            CredentialInput("credential://opaque", TARGET, service=[]),  # type: ignore[arg-type]
            CredentialInput,
            TARGET,
            {"blocked_by_input:service"},
            id="non-string-service",
        ),
        pytest.param(
            ArtifactInput("artifact://opaque", ""),
            ArtifactInput,
            TARGET,
            {"blocked_by_input:artifact_type"},
            id="empty-artifact-type",
        ),
        pytest.param(
            PayloadKeyingInput("artifact://opaque", keying_parameters=[]),  # type: ignore[arg-type]
            PayloadKeyingInput,
            TARGET,
            {"blocked_by_input:keying_parameters"},
            id="non-mapping-keying-parameters",
        ),
    ],
)
def test_typed_input_runtime_shapes_fail_closed(
    value: object,
    expected_type: type,
    request_target: str,
    expected_failures: set[str],
) -> None:
    failures = set(validate_typed_input(value, expected_type, request_target=request_target))

    assert expected_failures <= failures


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("target", None),
        ("arguments", []),
        ("parameters", ()),
        ("command", []),
        ("facts", []),
        ("evidence_fact_ids", []),
        ("assessment_refs", []),
        ("source_execution_ids", []),
        ("provider_commands", []),
        ("precondition_refs", []),
    ],
)
def test_every_action_request_container_shape_fails_closed(
    field_name: str,
    invalid_value: object,
) -> None:
    adapter = _GuardAdapter()
    values: dict[str, object] = {
        "target": TARGET,
        "execution_context": _context(),
        field_name: invalid_value,
    }
    request = ActionRequest(**values)  # type: ignore[arg-type]

    result = _executor()._request_contract_applicability(adapter, request)

    assert result.applicable is False
    assert f"blocked_by_input:request_shape:{field_name}" in result.missing_requirements


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("actor", None),
        ("origin", None),
        ("target_scope", None),
        ("capabilities", None),
        ("approved", "yes"),
        ("approval_id", None),
        ("request_id", None),
        ("max_runtime_seconds", "300"),
        ("max_output_bytes", 1.5),
        ("cancellation", None),
        ("target_scope", (7,)),
        ("capabilities", frozenset({7})),
        ("request_id", "  "),
        ("max_runtime_seconds", True),
        ("max_output_bytes", -1),
    ],
)
def test_every_execution_context_shape_fails_closed(
    field_name: str,
    invalid_value: object,
) -> None:
    adapter = _GuardAdapter()
    context = replace(_context(), **{field_name: invalid_value})
    request = ActionRequest(TARGET, context)

    result = _executor()._request_contract_applicability(adapter, request)

    assert result.applicable is False
    assert f"blocked_by_input:execution_context_shape:{field_name}" in result.missing_requirements


def test_executor_rejects_invalid_top_level_request_types() -> None:
    executor = _executor()

    with pytest.raises(TypeError, match="request must be an ActionRequest"):
        executor.run("missing", object())  # type: ignore[arg-type]

    with pytest.raises(TypeError, match=r"request\.execution_context"):
        executor.run("missing", ActionRequest(TARGET, None))  # type: ignore[arg-type]


def test_request_contract_exception_becomes_not_applicable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _GuardAdapter()
    catalog = ActionCatalog()
    catalog.register(adapter)
    executor = ActionExecutor(catalog, ExecutionPolicy())

    def raise_contract_error(*_args: object, **_kwargs: object) -> object:
        raise ValueError("malformed contract fixture")

    monkeypatch.setattr(executor, "_request_contract_applicability", raise_contract_error)

    report = executor.run(adapter.descriptor.action_id, ActionRequest(TARGET, _context()))

    assert report.applicability is not None
    assert report.applicability.applicable is False
    assert report.applicability.reasons == ("request_contract_error",)
    assert report.applicability.missing_requirements == ("request_contract_error:ValueError",)


@pytest.mark.parametrize(
    ("precondition_refs", "expected_failure"),
    [
        ((7,), "blocked_by_input:precondition_refs"),
        ((), "blocked_by_input:precondition_refs"),
        (("fact://0",), "blocked_by_input:precondition_refs"),
    ],
)
def test_precondition_reference_shapes_fail_closed(
    precondition_refs: tuple[object, ...],
    expected_failure: str,
) -> None:
    adapter = _GuardAdapter(required_preconditions=("confirmed_pivot",))
    request = ActionRequest(
        TARGET,
        _context(),
        facts=(_fact(),),
        precondition_refs=precondition_refs,  # type: ignore[arg-type]
    )

    result = _executor()._request_contract_applicability(adapter, request)

    assert result.applicable is False
    assert expected_failure in result.missing_requirements


def test_preconditions_and_pivot_reference_must_bind_the_same_fact() -> None:
    adapter = _GuardAdapter(
        input_type=PivotRouteInput,
        required_preconditions=("confirmed_pivot",),
    )
    executor = _executor()
    confirmed = _fact(id=1, type="confirmed_pivot")
    unrelated = _fact(id=2, type="web_title")

    missing_route = executor._request_contract_applicability(
        adapter,
        ActionRequest(
            TARGET,
            _context(),
            typed_input=PivotRouteInput("fact://2", ScanTarget(TARGET)),
            facts=(confirmed,),
            precondition_refs=("fact://1",),
        ),
    )
    wrong_route = executor._request_contract_applicability(
        adapter,
        ActionRequest(
            TARGET,
            _context(),
            typed_input=PivotRouteInput("fact://2", ScanTarget(TARGET)),
            facts=(confirmed, unrelated),
            precondition_refs=("fact://1", "fact://2"),
        ),
    )
    valid = executor._request_contract_applicability(
        adapter,
        ActionRequest(
            TARGET,
            _context(),
            typed_input=PivotRouteInput("fact://1", ScanTarget(TARGET)),
            facts=(confirmed,),
            precondition_refs=("fact://1",),
        ),
    )

    assert "blocked_by_input:pivot_route_ref" in missing_route.missing_requirements
    assert "blocked_by_precondition:pivot_route_ref" in wrong_route.missing_requirements
    assert valid.applicable is True
    assert valid.missing_requirements == ()


def test_empty_fact_reference_set_and_fact_import_failure_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = ActionRequest(TARGET, _context(), facts=(_fact(),))

    assert ActionExecutor._decision_facts_by_ref(request, frozenset()) == {}

    original_import = builtins.__import__

    def reject_fact_import(
        name: str,
        globals_: object = None,
        locals_: object = None,
        fromlist: object = (),
        level: int = 0,
    ) -> object:
        if name == "core.ai.evaluated_facts":
            raise ImportError("fact evaluator unavailable")
        return original_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", reject_fact_import)

    assert ActionExecutor._decision_facts_by_ref(request, frozenset({"fact://1"})) == {}


def test_fact_evaluator_exception_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.ai import evaluated_facts

    def raise_evaluation_error(_fact_value: object) -> bool:
        raise ValueError("malformed fact")

    monkeypatch.setattr(evaluated_facts, "fact_is_decision_usable", raise_evaluation_error)
    request = ActionRequest(TARGET, _context(), facts=(_fact(),))

    assert ActionExecutor._decision_facts_by_ref(request, frozenset({"fact://1"})) == {}


@pytest.mark.parametrize(
    "candidate",
    [
        "not-a-fact",
        _fact(freshness_status="stale"),
        _fact(observations={"trust_level": "trusted"}),
        _fact(observations=("malformed",)),
        _fact(trust_level="verified"),
        _fact(assessment_status="observed"),
        _fact(fact_ref="fact://01"),
        _fact(fact_ref="fact://2"),
        _fact(id=2),
        _fact(host="198.51.100.7"),
        _fact(type=""),
    ],
)
def test_malformed_or_unbound_facts_cannot_satisfy_preconditions(candidate: object) -> None:
    request = ActionRequest(TARGET, _context(), facts=(candidate,))  # type: ignore[arg-type]

    facts_by_ref = ActionExecutor._decision_facts_by_ref(request, frozenset({"fact://1"}))

    assert facts_by_ref == {}


def test_only_unique_trusted_verified_target_bound_facts_are_returned() -> None:
    nested_assessment = _fact(
        id=None,
        fact_ref="fact://1",
        assessment_status=None,
        assessment={"status": "verified"},
        trust_level=None,
        observations=({"trust_level": "trusted"},),
    )
    request = ActionRequest(TARGET, _context(), facts=(nested_assessment,))

    assert ActionExecutor._decision_facts_by_ref(request, frozenset({"fact://1"})) == {"fact://1": "confirmed_pivot"}

    duplicate_request = ActionRequest(
        TARGET,
        _context(),
        facts=(
            _fact(type="confirmed_pivot"),
            _fact(type="alternate_type"),
            _fact(type="third_type"),
        ),
    )

    assert ActionExecutor._decision_facts_by_ref(duplicate_request, frozenset({"fact://1"})) == {}
