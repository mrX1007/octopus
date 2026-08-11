"""Pure contracts for inert plugin input-schema metadata and validation."""

from __future__ import annotations

import shlex
from types import SimpleNamespace
from typing import Any

import pytest

from core.actions.adapters import PluginActionAdapter
from core.actions.models import ActionRequest
from core.ai.runtime import PipelineRuntime, _parse_plugin_metadata_arguments
from core.ai.tool_registry import ToolRegistry
from core.execution import ExecutionContext, ExecutionPolicy, ExecutionStatus
from core.plugins import worker
from core.plugins.base import OctopusPlugin, PluginResult
from core.plugins.loader import PluginManager
from core.plugins.schema import empty_input_schema

pytestmark = [pytest.mark.contract, pytest.mark.security]


def _schema(
    properties: dict[str, dict[str, Any]] | None = None,
    *,
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


def _descriptor(
    input_schema: dict[str, Any],
    *,
    supports_check: bool = False,
    supports_run: bool = True,
) -> SimpleNamespace:
    return SimpleNamespace(
        name="synthetic_noop",
        plugin_type="recon",
        description="Synthetic no-op plugin.",
        version="1.0",
        requires=(),
        python_deps=(),
        capabilities=(),
        supports_check=supports_check,
        supports_run=supports_run,
        input_schema=input_schema,
    )


class _NoOpManager:
    def __init__(
        self,
        input_schema: dict[str, Any],
        *,
        supports_check: bool = False,
        supports_run: bool = True,
    ) -> None:
        self.descriptor = _descriptor(
            input_schema,
            supports_check=supports_check,
            supports_run=supports_run,
        )
        self.plugins = {self.descriptor.name: self.descriptor}
        self.skipped_plugins: dict[str, str] = {}
        self.calls: list[dict[str, Any]] = []
        self.check_calls: list[dict[str, Any]] = []
        self.execute_calls: list[dict[str, Any]] = []

    def get_plugin(self, name: str) -> SimpleNamespace | None:
        return self.descriptor if name == self.descriptor.name else None

    @staticmethod
    def validate(_name: str) -> tuple[Any, ...]:
        return ()

    def check(self, _name: str, _target: str, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        self.check_calls.append(kwargs)
        return SimpleNamespace(vulnerable=False, details="noop", evidence="")

    def execute(self, _name: str, **kwargs: Any) -> PluginResult:
        self.calls.append(kwargs)
        self.execute_calls.append(kwargs)
        return PluginResult(success=True, data={"received": kwargs})


def _request(parameters: dict[str, Any]) -> ActionRequest:
    return ActionRequest(
        target="example.test",
        execution_context=ExecutionContext.automatic(target_scope=("example.test",)),
        parameters=parameters,
    )


def test_worker_discovery_and_loader_keep_schema_as_inert_metadata() -> None:
    declared_schema = _schema(
        {
            "artifact_ref": {"type": "string", "format": "artifact-ref"},
            "attempt": {"type": "integer", "description": "Bounded attempt number."},
        },
        required=["artifact_ref"],
    )

    class SyntheticNoOpPlugin(OctopusPlugin):
        name = "synthetic_noop"
        input_schema = declared_schema

        def run(self, **_kwargs: Any) -> PluginResult:
            return PluginResult(success=True)

    raw = worker._metadata(SyntheticNoOpPlugin)
    assert raw["input_schema"] == declared_schema

    manager = object.__new__(PluginManager)
    descriptor = manager._descriptor_from_payload(
        raw,
        "/plugins",
        "/plugins/synthetic.py",
        "synthetic",
    )
    assert descriptor.input_schema == declared_schema
    assert descriptor.input_schema is not declared_schema
    manager.plugins = {descriptor.name: descriptor}
    listed = manager.list_plugins()
    assert listed[0]["input_schema"] == declared_schema
    listed[0]["input_schema"]["required"].clear()
    assert descriptor.input_schema["required"] == ["artifact_ref"]


@pytest.mark.parametrize(
    "schema",
    [
        None,
        {},
        {**empty_input_schema(), "type": "array"},
        {**empty_input_schema(), "additionalProperties": True},
        {**empty_input_schema(), "title": "unsupported"},
        _schema({"value": {"type": "null"}}),
        _schema({"value": {"type": "string", "format": "uri"}}),
        _schema({"value": {"type": "integer", "format": "artifact-ref"}}),
        _schema({"value": {"type": "string", "default": "x"}}),
        _schema({"_private": {"type": "string"}}),
        _schema({"timeout": {"type": "integer"}}),
        _schema({"known": {"type": "string"}}, required=["unknown"]),
        _schema({"known": {"type": "string"}}, required=["known", "known"]),
    ],
)
def test_loader_rejects_non_closed_or_unsupported_schema(schema: Any) -> None:
    manager = object.__new__(PluginManager)
    with pytest.raises(ValueError):
        manager._descriptor_from_payload(
            {"name": "invalid_schema", "input_schema": schema},
            "/plugins",
            "/plugins/invalid.py",
            "invalid",
        )


def test_plugin_action_adapter_rejects_undeclared_missing_and_wrong_typed_fields() -> None:
    schema = _schema(
        {
            "artifact_ref": {"type": "string", "format": "artifact-ref"},
            "attempt": {"type": "integer"},
            "verified": {"type": "boolean"},
        },
        required=["artifact_ref", "attempt"],
    )
    manager = _NoOpManager(schema)
    adapter = PluginActionAdapter(manager, "synthetic_noop")
    policy = ExecutionPolicy()

    undeclared = adapter.authorize(
        policy,
        _request({"action": "scan", "artifact_ref": "artifact://one", "attempt": 1, "extra": "x"}),
        "execute",
    )
    missing = adapter.authorize(
        policy,
        _request({"action": "scan", "artifact_ref": "artifact://one"}),
        "execute",
    )
    wrong_type = adapter.authorize(
        policy,
        _request({"action": "scan", "artifact_ref": "artifact://one", "attempt": "1"}),
        "execute",
    )

    assert undeclared.reason == "plugin_network_parameter_undeclared:extra"
    assert missing.reason == "plugin_input_missing:attempt"
    assert wrong_type.reason == "plugin_input_wrong_type:attempt:expected_integer"
    assert manager.calls == []


def test_plugin_action_adapter_passes_valid_opaque_references_without_resolving_them() -> None:
    schema = _schema(
        {
            "credential_ref": {"type": "string", "format": "credential-ref"},
            "path_ref": {"type": "string", "format": "path-ref"},
        },
        required=["credential_ref", "path_ref"],
    )
    manager = _NoOpManager(schema)
    adapter = PluginActionAdapter(manager, "synthetic_noop")
    request = _request(
        {
            "action": "run",
            "credential_ref": "credential://opaque/not-looked-up",
            "path_ref": "path://opaque/not-opened",
        }
    )

    result = adapter.execute(request)

    assert result.success is True
    assert manager.calls[0]["credential_ref"] == "credential://opaque/not-looked-up"
    assert manager.calls[0]["path_ref"] == "path://opaque/not-opened"
    assert manager.execute_calls == manager.calls
    assert manager.check_calls == []


def test_plugin_action_adapter_rejects_check_when_provider_does_not_support_it() -> None:
    manager = _NoOpManager(_schema({"label": {"type": "string"}}, required=["label"]))
    adapter = PluginActionAdapter(manager, "synthetic_noop")

    with pytest.raises(ValueError, match=r"^plugin_check_unsupported$"):
        adapter.execute(_request({"action": "check", "label": "fixture"}))

    assert manager.calls == []


def test_runtime_blocks_unsupported_check_before_provider_attempt(tmp_path) -> None:
    manager = _NoOpManager(_schema({"label": {"type": "string"}}, required=["label"]))
    runtime = PipelineRuntime(
        str(tmp_path / "unsupported-check.db"),
        runner=lambda *_args, **_kwargs: "unexpected",
        plugin_manager=manager,
    )

    result = runtime.dispatch(
        "plugin synthetic_noop example.test check label=fixture",
        (),
        set(),
        ExecutionContext.automatic(target_scope=("example.test",)),
    )

    assert result.status is ExecutionStatus.BLOCKED
    assert result.error_message == "plugin_check_unsupported"
    assert result.executed is False
    assert result.metadata["provider_attempts"] == 0
    assert manager.calls == []


@pytest.mark.parametrize("metadata_present", [False, True])
def test_runtime_blocks_unsupported_run_before_provider_attempt(tmp_path, metadata_present: bool) -> None:
    manager = _NoOpManager(
        _schema({"label": {"type": "string"}}, required=["label"]),
        supports_check=True,
        supports_run=False,
    )
    if not metadata_present:
        del manager.descriptor.supports_run
    runtime = PipelineRuntime(
        str(tmp_path / "unsupported-run.db"),
        runner=lambda *_args, **_kwargs: "unexpected",
        plugin_manager=manager,
    )
    context = ExecutionContext.operator(
        actor="synthetic-fixture",
        approval_id="synthetic-run-fixture",
        target_scope=("example.test",),
        allow_active_tools=True,
    )

    result = runtime.dispatch(
        "plugin synthetic_noop example.test run label=fixture",
        (),
        set(),
        context,
    )

    assert result.status is ExecutionStatus.BLOCKED
    assert result.error_message == "plugin_run_unsupported"
    assert result.executed is False
    assert result.metadata["provider_attempts"] == 0
    assert manager.calls == []


def test_runtime_parser_accepts_repeated_safe_metadata_and_keeps_refs_opaque() -> None:
    schema = _schema(
        {
            "artifact_ref": {"type": "string", "format": "artifact-ref"},
            "attempt": {"type": "integer"},
            "verified": {"type": "boolean"},
            "label": {"type": "string"},
        }
    )

    parsed = _parse_plugin_metadata_arguments(
        ("artifact_ref=artifact://opaque/one", "attempt=3", "verified=true", "label=sample"),
        schema,
    )

    assert parsed == {
        "artifact_ref": "artifact://opaque/one",
        "attempt": 3,
        "verified": True,
        "label": "sample",
    }


def test_runtime_plugin_command_passes_repeated_typed_metadata_to_noop_manager(tmp_path) -> None:
    schema = _schema(
        {
            "artifact_ref": {"type": "string", "format": "artifact-ref"},
            "credential_ref": {"type": "string", "format": "credential-ref"},
            "label": {"type": "string"},
            "attempt": {"type": "integer"},
            "verified": {"type": "boolean"},
        },
        required=["artifact_ref", "credential_ref", "label", "attempt"],
    )
    manager = _NoOpManager(schema, supports_check=True)

    def forbidden_runner(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("typed plugin commands must stay on the runtime-owned manager")

    runtime = PipelineRuntime(
        str(tmp_path / "typed-plugin.db"),
        runner=forbidden_runner,
        plugin_manager=manager,
    )
    context = ExecutionContext.automatic(
        actor="typed-plugin-test",
        target_scope=("example.test",),
    )

    result = runtime.dispatch(
        "plugin synthetic_noop example.test scan "
        "artifact_ref=artifact://opaque/one "
        "credential_ref=credential://opaque/not-looked-up "
        "label=neutral-fixture attempt=3 verified=true",
        (),
        set(),
        context,
    )

    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.metadata["action_id"] == "plugin:synthetic_noop"
    assert manager.calls == [
        {
            "timeout": context.max_runtime_seconds,
            "artifact_ref": "artifact://opaque/one",
            "credential_ref": "credential://opaque/not-looked-up",
            "label": "neutral-fixture",
            "attempt": 3,
            "verified": True,
        }
    ]
    assert manager.check_calls == manager.calls
    assert manager.execute_calls == []


def test_runtime_typed_metadata_crosses_real_discovery_and_check_worker(tmp_path) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "typed_noop.py").write_text(
        """
from core.plugins.base import CheckResult, OctopusPlugin


class TypedNoOp(OctopusPlugin):
    name = "typed_worker_noop"
    input_schema = {
        "type": "object",
        "properties": {
            "credential_ref": {"type": "string", "format": "credential-ref"},
            "label": {"type": "string"},
        },
        "required": ["credential_ref", "label"],
        "additionalProperties": False,
    }

    def check(self, target, **kwargs):
        matches = (
            target == "example.test"
            and kwargs.get("credential_ref") == "credential://opaque/worker-fixture"
            and kwargs.get("label") == "neutral-fixture"
        )
        return CheckResult(vulnerable=matches, details="typed inputs received")
""",
        encoding="utf-8",
    )
    manager = PluginManager(str(plugin_dir))
    runtime = PipelineRuntime(
        str(tmp_path / "typed-worker.db"),
        runner=lambda *_args, **_kwargs: "unexpected",
        plugin_manager=manager,
    )
    context = ExecutionContext.automatic(
        actor="typed-plugin-worker-test",
        target_scope=("example.test",),
    )

    result = runtime.dispatch(
        "plugin typed_worker_noop example.test check "
        "credential_ref=credential://opaque/worker-fixture label=neutral-fixture",
        (),
        set(),
        context,
    )

    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.metadata["action_id"] == "plugin:typed_worker_noop"
    assert '"vulnerable":true' in result.stdout


def test_runtime_plugin_command_blocks_undeclared_metadata_before_manager_call(tmp_path) -> None:
    manager = _NoOpManager(_schema({"label": {"type": "string"}}), supports_check=True)
    runtime = PipelineRuntime(
        str(tmp_path / "undeclared-plugin-input.db"),
        runner=lambda *_args, **_kwargs: "unexpected",
        plugin_manager=manager,
    )
    context = ExecutionContext.automatic(
        actor="typed-plugin-test",
        target_scope=("example.test",),
    )

    result = runtime.dispatch(
        "plugin synthetic_noop example.test scan label=fixture undeclared=value",
        (),
        set(),
        context,
    )

    assert result.status is ExecutionStatus.BLOCKED
    assert result.error_message == "plugin_network_parameter_undeclared"
    assert manager.calls == []


def test_inventory_metadata_creates_inert_ready_planner_candidate_without_actions() -> None:
    class InventoryOnlyManager:
        def __init__(self) -> None:
            self.inventory_reads = 0

        def list_plugins(self) -> list[dict[str, Any]]:
            self.inventory_reads += 1
            return [
                {
                    "name": "synthetic_noop",
                    "type": "recon",
                    "supports_check": True,
                    "supports_run": True,
                    "input_schema": _schema(
                        {
                            "credential_ref": {
                                "type": "string",
                                "format": "credential-ref",
                            },
                            "label": {"type": "string"},
                        },
                        required=["credential_ref", "label"],
                    ),
                }
            ]

        @staticmethod
        def validate(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("planner candidate discovery must not validate providers")

        check = validate
        execute = validate

    manager = InventoryOnlyManager()
    registry = ToolRegistry(plugin_manager_provider=lambda: manager)
    credential_ref = "credential://opaque/planner-fixture"

    candidate = registry.get_discovered_plugin_action_reachability(
        "example.test",
        {
            "synthetic_noop": {
                "credential_ref": credential_ref,
                "label": "neutral-fixture",
            }
        },
    )[0]

    assert candidate["action_id"] == "plugin:synthetic_noop"
    assert candidate["actions"] == ["check", "run"]
    assert candidate["selected_action"] == "check"
    assert candidate["input_state"] == "ready"
    assert candidate["planner_visible"] is True
    assert candidate["resolved_parameter_names"] == ["credential_ref", "label"]
    assert credential_ref not in str(candidate)
    assert manager.inventory_reads == 1


@pytest.mark.parametrize("action", ["check", "run"])
def test_plugin_command_round_trips_spaces_objects_and_arrays(action: str) -> None:
    schema = _schema(
        {
            "label": {"type": "string"},
            "tags": {"type": "array"},
            "target_info": {"type": "object"},
        },
        required=["label", "tags", "target_info"],
    )
    manager = SimpleNamespace(
        list_plugins=lambda: [
            {
                "name": "synthetic_active",
                "type": "post",
                "supports_check": True,
                "supports_run": True,
                "input_schema": schema,
            }
        ]
    )
    registry = ToolRegistry(plugin_manager_provider=lambda: manager)
    inputs = {
        "plugin_actions": {
            "synthetic_active": {
                "action": action,
                "label": "neutral fixture",
                "tags": ["alpha", "two words"],
                "target_info": {
                    "hostname": "host one",
                    "roles": ["web", "api worker"],
                },
            }
        }
    }

    commands = registry.get_commands_for_task(
        "plugin:synthetic_active",
        "example.test",
        task_inputs=inputs,
    )

    assert len(commands) == 1
    tokens = shlex.split(commands[0])
    assert tokens[:4] == ["plugin", "synthetic_active", "example.test", action]
    assert tokens[4:] == [
        "label=neutral fixture",
        'tags=["alpha","two words"]',
        'target_info={"hostname":"host one","roles":["web","api worker"]}',
    ]
    assert _parse_plugin_metadata_arguments(tokens[4:], schema) == {
        "label": "neutral fixture",
        "tags": ["alpha", "two words"],
        "target_info": {
            "hostname": "host one",
            "roles": ["web", "api worker"],
        },
    }


def test_check_only_plugin_does_not_advertise_or_compile_run() -> None:
    schema = _schema({"label": {"type": "string"}}, required=["label"])
    manager = SimpleNamespace(
        list_plugins=lambda: [
            {
                "name": "check_only",
                "type": "recon",
                "supports_check": True,
                "supports_run": False,
                "input_schema": schema,
            }
        ]
    )
    registry = ToolRegistry(plugin_manager_provider=lambda: manager)
    plugin_inputs = {"check_only": {"action": "run", "label": "fixture"}}

    readiness = registry.get_discovered_plugin_action_reachability("example.test", plugin_inputs)[0]
    commands = registry.get_commands_for_task(
        "plugin:check_only",
        "example.test",
        task_inputs={"plugin_actions": plugin_inputs},
    )

    assert readiness["actions"] == ["check"]
    assert readiness["input_state"] == "blocked_by_action"
    assert readiness["planner_visible"] is False
    assert readiness["action_state"] == "plugin_action_unsupported:run"
    assert commands == []


@pytest.mark.parametrize("include_field", [False, True])
def test_plugin_without_proven_run_support_fails_closed(include_field: bool) -> None:
    record: dict[str, Any] = {
        "name": "actionless",
        "type": "recon",
        "supports_check": False,
        "input_schema": _schema(),
    }
    if include_field:
        record["supports_run"] = False
    manager = SimpleNamespace(list_plugins=lambda: [record])
    registry = ToolRegistry(plugin_manager_provider=lambda: manager)
    plugin_inputs = {"actionless": {"action": "run"}}

    readiness = registry.get_discovered_plugin_action_reachability("example.test", plugin_inputs)[0]

    assert readiness["actions"] == []
    assert readiness["input_state"] == "blocked_by_action"
    assert readiness["planner_visible"] is False
    assert registry.get_provider_statuses_for_task("plugin:actionless") == []
    assert (
        registry.get_commands_for_task(
            "plugin:actionless",
            "example.test",
            task_inputs={"plugin_actions": plugin_inputs},
        )
        == []
    )


@pytest.mark.parametrize(
    ("properties", "parameters", "message"),
    [
        ({"label": {"type": "string"}}, {"label": "line one\nline two"}, "plugin_metadata_unsafe_value:label"),
        ({"label": {"type": "string"}}, {"label": "x" * 4097}, "plugin_metadata_unsafe_value:label"),
        (
            {"password": {"type": "string"}},
            {"password": "plaintext-fixture"},
            "plugin_metadata_secret_material_forbidden:password",
        ),
    ],
)
def test_readiness_and_command_generation_share_runtime_metadata_grammar(
    properties: dict[str, dict[str, Any]],
    parameters: dict[str, Any],
    message: str,
) -> None:
    schema = _schema(properties, required=list(properties))
    manager = SimpleNamespace(
        list_plugins=lambda: [
            {
                "name": "grammar_fixture",
                "type": "recon",
                "supports_check": True,
                "supports_run": True,
                "input_schema": schema,
            }
        ]
    )
    registry = ToolRegistry(plugin_manager_provider=lambda: manager)
    plugin_inputs = {"grammar_fixture": {"action": "check", **parameters}}

    readiness = registry.get_discovered_plugin_action_reachability("example.test", plugin_inputs)[0]
    commands = registry.get_commands_for_task(
        "plugin:grammar_fixture",
        "example.test",
        task_inputs={"plugin_actions": plugin_inputs},
    )

    assert readiness["input_state"] == "blocked_by_input"
    assert readiness["planner_visible"] is False
    assert readiness["validation_error"] == message
    assert commands == []


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (("missing-separator",), "plugin_metadata_invalid_syntax"),
        (("__private=value",), "plugin_metadata_unsafe_key"),
        (("label=one", "label=two"), "plugin_metadata_duplicate:label"),
        (("password=plaintext",), "plugin_metadata_secret_material_forbidden:password"),
    ],
)
def test_runtime_parser_rejects_unsafe_metadata(arguments: tuple[str, ...], message: str) -> None:
    schema = _schema({"label": {"type": "string"}, "password": {"type": "string"}})
    with pytest.raises(ValueError, match=message):
        _parse_plugin_metadata_arguments(arguments, schema)
