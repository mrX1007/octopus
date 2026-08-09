"""Plugin unit boundaries and real production composition contracts."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.actions import ActionKind, ActionRequest, build_action_catalog
from core.ai.runtime import PipelineRuntime
from core.execution import ExecutionContext, ExecutionStatus
from core.plugins import loader as plugin_loader
from core.plugins.base import CheckResult
from core.plugins.loader import PluginManager, default_modules_dir
from core.secrets import get_redactor, reset_default_secret_store_for_tests
from core.tools.registry import ToolDef

pytestmark = [pytest.mark.contract, pytest.mark.security]


def _forbidden_legacy_runner(*_args, **_kwargs):
    raise AssertionError("plugin runtime contracts must not leave the runtime-owned manager")


@pytest.fixture
def isolated_plugin_redactor(tmp_path, monkeypatch):
    reset_default_secret_store_for_tests()
    monkeypatch.setenv("OCTOPUS_SECRET_STORE", str(tmp_path / "runtime-secrets.db"))
    get_redactor()
    yield
    reset_default_secret_store_for_tests()


def _plugin_descriptor(name: str, *, supports_check: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        plugin_type="recon",
        description="Synthetic inert plugin metadata.",
        version="1.0",
        requires=[],
        python_deps=[],
        capabilities=[],
        supports_check=supports_check,
    )


class _InertManager:
    def __init__(self, *names: str) -> None:
        self.plugins = {name: _plugin_descriptor(name) for name in names}
        self.skipped_plugins: dict[str, str] = {}
        self.metadata_reads: list[str] = []

    def get_plugin(self, name: str):
        self.metadata_reads.append(name)
        return self.plugins.get(name)

    def validate(self, _name: str):  # pragma: no cover - must remain inert during composition
        raise AssertionError("catalog composition must not validate plugin providers")

    def check(self, *_args, **_kwargs):  # pragma: no cover - must remain inert during composition
        raise AssertionError("catalog composition must not check plugin providers")

    def execute(self, *_args, **_kwargs):  # pragma: no cover - must remain inert during composition
        raise AssertionError("catalog composition must not execute plugin providers")


class _CheckingManager:
    def __init__(self, *, vulnerable: bool) -> None:
        self.descriptor = _plugin_descriptor("checked_plugin", supports_check=True)
        self.plugins = {self.descriptor.name: self.descriptor}
        self.skipped_plugins: dict[str, str] = {}
        self.vulnerable = vulnerable
        self.check_calls: list[tuple[str, str, int]] = []

    def get_plugin(self, name: str):
        return self.plugins.get(name)

    def validate(self, _name: str):
        return []

    def list_plugins(self):
        return [
            {
                "depends_on": [],
                "name": self.descriptor.name,
                "requires": [],
                "stage": 1,
                "supports_check": True,
                "type": "recon",
                "version": "1.0",
            }
        ]

    def list_skipped_plugins(self):
        return []

    def check(self, name: str, target: str, timeout: int = 120) -> CheckResult:
        self.check_calls.append((name, target, timeout))
        return CheckResult(
            vulnerable=self.vulnerable,
            confidence=0.75,
            details="synthetic check completed",
            evidence="synthetic bounded evidence",
        )

    def execute(self, *_args, **_kwargs):  # pragma: no cover - explicit check must never run
        raise AssertionError("explicit plugin check must not execute run()")


def test_inert_plugin_descriptors_join_catalog_without_stealing_disabled_bare_name() -> None:
    disabled = ToolDef(
        name="payload_keying",
        func=lambda: None,
        enabled=False,
        disabled_reason="synthetic_quarantine",
        needs_target=False,
    )
    manager = _InertManager("payload_keying", "synthetic_plugin")

    catalog = build_action_catalog(
        lambda _command, _context: "unused",
        tool_defs=(disabled,),
        plugin_manager=manager,
    )

    plugin_descriptors = tuple(
        descriptor for descriptor in catalog.descriptors() if descriptor.kind is ActionKind.PLUGIN
    )
    assert len(plugin_descriptors) == 2
    assert {descriptor.action_id for descriptor in plugin_descriptors} == {
        "plugin:payload_keying",
        "plugin:synthetic_plugin",
    }
    assert catalog.require("payload_keying").canonical_id == "tool:payload_keying"
    assert catalog.require("plugin:payload_keying").canonical_id == "plugin:payload_keying"
    assert catalog.require("synthetic_plugin").canonical_id == "plugin:synthetic_plugin"
    assert manager.metadata_reads == ["payload_keying", "synthetic_plugin"]


def test_plugin_display_name_cannot_shadow_an_enabled_registry_owner() -> None:
    enabled = ToolDef(name="shared_name", func=lambda: None, needs_target=False)
    manager = _InertManager("shared_name")

    with pytest.raises(ValueError, match=r"^Action alias collision: shared_name"):
        build_action_catalog(
            lambda _command, _context: "unused",
            tool_defs=(enabled,),
            plugin_manager=manager,
        )


@pytest.mark.parametrize("gateway", ["plugin", "run_plugin", "octopus_plugin"])
@pytest.mark.parametrize("vulnerable", [False, True])
def test_supported_plugin_check_uses_one_manager_call_and_keeps_evidence(
    tmp_path,
    gateway: str,
    vulnerable: bool,
) -> None:
    manager = _CheckingManager(vulnerable=vulnerable)
    runtime = PipelineRuntime(
        str(tmp_path / f"{gateway}-{vulnerable}.db"),
        runner=_forbidden_legacy_runner,
        plugin_manager=manager,
    )
    target = "192.0.2.30"
    command = f"{gateway} checked_plugin {target} check"
    context = ExecutionContext.automatic(actor="supported-plugin-check", target_scope=(target,))

    result = runtime.dispatch(
        command,
        (),
        set(),
        context,
    )

    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.metadata["action_id"] == "plugin:checked_plugin"
    assert result.metadata["plugin_action"] == "check"
    assert manager.check_calls == [("checked_plugin", target, context.max_runtime_seconds)]
    assert json.loads(result.stdout) == {
        "action": "check",
        "confidence": 0.75,
        "details": "synthetic check completed",
        "evidence": "synthetic bounded evidence",
        "plugin": "checked_plugin",
        "supports_check": True,
        "version": "",
        "vulnerable": vulnerable,
    }
    checks = [
        json.loads(item["value"]) for item in runtime.parse_output(command, result) if item["type"] == "check_result"
    ]
    assert len(checks) == 1
    assert checks[0]["status"] == "completed"
    assert checks[0]["summary"] == {
        "check_supported": True,
        "confidence": 0.75,
        "plugin": "checked_plugin",
        "vulnerable": vulnerable,
    }


def test_plugin_gateway_rejects_extra_arguments_before_provider_call(tmp_path) -> None:
    manager = _CheckingManager(vulnerable=False)
    runtime = PipelineRuntime(
        str(tmp_path / "invalid-plugin-command.db"),
        runner=_forbidden_legacy_runner,
        plugin_manager=manager,
    )
    target = "192.0.2.30"

    result = runtime.dispatch(
        f"octopus_plugin checked_plugin {target} check extra",
        (),
        set(),
        ExecutionContext.automatic(actor="invalid-plugin-command", target_scope=(target,)),
    )

    assert result.status is ExecutionStatus.BLOCKED
    assert result.executed is False
    assert result.error_message == "plugin_command_invalid_arity"
    assert result.metadata["policy_denial"]["phase"] == "action_request"
    assert manager.check_calls == []


@pytest.mark.parametrize("gateway", ["plugin", "run_plugin", "octopus_plugin"])
def test_runtime_catalog_does_not_publish_legacy_plugin_gateway(
    tmp_path,
    gateway: str,
) -> None:
    manager = _CheckingManager(vulnerable=False)
    runtime = PipelineRuntime(
        str(tmp_path / f"direct-{gateway}.db"),
        runner=_forbidden_legacy_runner,
        plugin_manager=manager,
    )
    target = "192.0.2.30"
    context = ExecutionContext.automatic(actor="direct-plugin-gateway", target_scope=(target,))

    assert runtime.action_catalog.resolve(gateway) is None
    with pytest.raises(KeyError, match=r"Unknown action:"):
        runtime.execute_action(
            gateway,
            ActionRequest(
                target=target,
                execution_context=context,
                parameters={"action": "check"},
                command=f"{gateway} checked_plugin {target} check",
            ),
            run_check=False,
        )
    assert manager.check_calls == []


@pytest.mark.parametrize("alias", ["plugin_inventory", "plugin_list", "list_plugins"])
def test_plugin_inventory_alias_rejects_arguments_before_legacy_runner(
    tmp_path,
    alias: str,
) -> None:
    manager = _CheckingManager(vulnerable=False)
    runtime = PipelineRuntime(
        str(tmp_path / f"invalid-{alias}.db"),
        runner=_forbidden_legacy_runner,
        plugin_manager=manager,
    )

    result = runtime.dispatch(
        f"{alias} extra",
        (),
        set(),
        ExecutionContext.automatic(actor="invalid-plugin-inventory"),
    )

    assert result.status is ExecutionStatus.BLOCKED
    assert result.executed is False
    assert result.error_message == "plugin_inventory_invalid_arity"
    assert result.metadata["action_id"] == "tool:plugin_inventory"
    assert manager.check_calls == []


@pytest.mark.parametrize("alias", ["plugin_inventory", "plugin_list", "list_plugins"])
def test_direct_plugin_inventory_action_uses_runtime_manager_and_rejects_arguments(
    tmp_path,
    alias: str,
) -> None:
    manager = _CheckingManager(vulnerable=False)
    runtime = PipelineRuntime(
        str(tmp_path / f"direct-{alias}.db"),
        runner=_forbidden_legacy_runner,
        plugin_manager=manager,
    )
    context = ExecutionContext.automatic(actor="direct-plugin-inventory")

    valid = runtime.execute_action(
        alias,
        ActionRequest(target="", execution_context=context, command=alias),
        run_check=False,
        cleanup=False,
    )
    assert valid.execution_result is not None
    assert valid.execution_result.status is ExecutionStatus.SUCCEEDED
    assert json.loads(valid.execution_result.stdout) == {
        "plugins": manager.list_plugins(),
        "skipped": manager.list_skipped_plugins(),
    }

    invalid = runtime.execute_action(
        alias,
        ActionRequest(target="", execution_context=context, command=f"{alias} extra"),
        run_check=False,
        cleanup=False,
    )
    assert invalid.execution_result is not None
    assert invalid.execution_result.status is ExecutionStatus.FAILED
    assert invalid.execution_result.error_message == "plugin_inventory_invalid_arity"
    assert manager.check_calls == []


@pytest.mark.integration
def test_real_discovery_catalog_and_parser_complete_without_plugin_actions(
    tmp_path,
    monkeypatch,
    isolated_plugin_redactor,
) -> None:
    monkeypatch.chdir(tmp_path)
    runtime = PipelineRuntime(str(tmp_path / "facts.db"), runner=_forbidden_legacy_runner)

    assert runtime._plugin_manager is None
    manager = runtime.plugin_manager
    modules_root = Path(default_modules_dir()).resolve()
    assert type(manager) is PluginManager
    assert Path(manager.modules_dir).resolve() == modules_root
    assert manager.skipped_plugins == {}
    assert {"payload_keying", "systemd"}.issubset(manager.plugins)
    assert Path(manager.plugins["payload_keying"].path).resolve() == modules_root / "evasion" / "payload_keying.py"
    assert Path(manager.plugins["systemd"].path).resolve() == modules_root / "persistence" / "systemd.py"

    def forbidden_action(*_args, **_kwargs):
        raise AssertionError("plugin check/run must not execute during inventory assessment")

    def forbidden_second_discovery(*_args, **_kwargs):
        raise AssertionError("runtime inventory must reuse the catalog's discovered manager")

    monkeypatch.setattr(PluginManager, "check", forbidden_action)
    monkeypatch.setattr(PluginManager, "execute", forbidden_action)
    monkeypatch.setattr(manager, "_invoke_worker", forbidden_action)
    monkeypatch.setattr(plugin_loader, "PluginManager", forbidden_second_discovery)
    catalog = runtime.action_catalog

    assert catalog.require("plugin:payload_keying").adapter.manager is manager
    assert catalog.require("plugin:systemd").adapter.manager is manager
    assert catalog.require("plugin:payload_keying").adapter.descriptor.requirements.supports_check is False
    assert catalog.require("plugin:systemd").adapter.descriptor.requirements.supports_check is False
    assert catalog.require("plugin_inventory").canonical_id == "tool:plugin_inventory"
    assert catalog.require("systemd").canonical_id == "plugin:systemd"
    assert all(catalog.resolve(gateway) is None for gateway in ("plugin", "run_plugin", "octopus_plugin"))

    context = ExecutionContext.automatic(actor="plugin-inventory-contract")
    result = runtime.dispatch(
        "plugin_inventory",
        (),
        set(),
        context,
    )
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.executed is True
    assert result.metadata["action_catalog"] is True
    assert result.metadata["action_id"] == "tool:plugin_inventory"
    assert result.metadata["provider_attempts"] == 1
    discovered = json.loads(result.stdout)
    assert discovered == {
        "plugins": manager.list_plugins(),
        "skipped": manager.list_skipped_plugins(),
    }
    assert {item["name"] for item in discovered["plugins"]} >= {"payload_keying", "systemd"}

    for gateway in ("plugin", "run_plugin", "octopus_plugin"):
        gateway_command = f"{gateway} list"
        gateway_result = runtime.dispatch(
            gateway_command,
            (),
            set(),
            context,
        )
        assert gateway_result.status is ExecutionStatus.SUCCEEDED
        assert gateway_result.metadata["action_id"] == "tool:plugin_inventory"
        assert gateway_result.metadata["provider_attempts"] == 1
        assert json.loads(gateway_result.stdout) == discovered
        assert runtime.parse_output(gateway_command, gateway_result)

    stored = runtime.ingest_output(
        "real-plugin-inventory",
        "local-plugin-catalog",
        "plugin_inventory",
        result,
    )
    checks = [json.loads(item["value"]) for item in stored if item["type"] == "check_result"]
    inventory = [json.loads(item["value"]) for item in stored if item["type"] == "plugin_inventory"]
    assert len(checks) == 1
    assert checks[0]["kind"] == "plugin_assessment"
    assert checks[0]["status"] == "completed"
    assert checks[0]["summary"]["skipped_count"] == 0
    assert {item["name"] for item in inventory} >= {"payload_keying", "systemd"}
    assert all(item["trust_level"] == "trusted" for item in stored)
    assert runtime.action_catalog is catalog


@pytest.mark.integration
def test_real_plugin_commands_use_runtime_manager_and_fail_closed_before_side_effects(
    tmp_path,
    monkeypatch,
    isolated_plugin_redactor,
) -> None:
    monkeypatch.chdir(tmp_path)
    runtime = PipelineRuntime(str(tmp_path / "facts.db"), runner=_forbidden_legacy_runner)
    catalog = runtime.action_catalog
    manager = runtime.plugin_manager
    modules_root = Path(default_modules_dir()).resolve()
    targets = {
        "systemd": "192.0.2.10",
        "payload_keying": "192.0.2.11",
    }
    expected_errors = {
        "systemd": "Requires target plus serializable SSH credentials",
        "payload_keying": "payload bytes or string are required",
    }
    context = ExecutionContext.operator(
        actor="real-plugin-worker-contract",
        approval_id="safe-fail-closed-inputs",
        target_scope=tuple(targets.values()),
        allow_active_tools=True,
        max_runtime_seconds=15,
    )
    # Establish the runtime-owned stores before taking the side-effect snapshot.
    # Dispatch records provider telemetry and decision traces by design; the
    # assertion below is specifically about files created by plugin check/run.
    _ = runtime.provider_telemetry
    _ = runtime.decision_trace
    files_before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}

    for plugin_name, target in targets.items():
        action_id = f"plugin:{plugin_name}"
        adapter = catalog.require(action_id).adapter
        assert adapter.manager is manager
        assert adapter.descriptor.requirements.supports_check is False
        expected_relative_path = {
            "systemd": Path("persistence/systemd.py"),
            "payload_keying": Path("evasion/payload_keying.py"),
        }[plugin_name]
        assert Path(manager.plugins[plugin_name].path).resolve() == modules_root / expected_relative_path

        check_command = f"plugin {plugin_name} {target} check"
        check_result = runtime.dispatch(
            check_command,
            (),
            set(),
            context,
        )
        assert check_result.status is ExecutionStatus.SUCCEEDED
        assert check_result.metadata["action_id"] == action_id
        assert check_result.metadata["plugin_action"] == "check"
        assert check_result.metadata["plugin_run_invoked"] is False
        assert check_result.metadata["action_lifecycle"]["attempt"] == "attempted"
        assert check_result.metadata["action_lifecycle"]["outcome"] == "succeeded"
        check_payload = json.loads(check_result.stdout)
        assert check_payload == {
            "action": "check",
            "confidence": 0.0,
            "details": "check() not implemented",
            "evidence": "",
            "plugin": plugin_name,
            "supports_check": False,
            "version": "",
            "vulnerable": False,
        }

        stored = runtime.ingest_output(
            "real-plugin-check",
            target,
            check_command,
            check_result,
        )
        parsed_checks = [json.loads(item["value"]) for item in stored if item["type"] == "check_result"]
        assert len(parsed_checks) == 1
        assert parsed_checks[0]["status"] == "partial"
        assert parsed_checks[0]["summary"] == {
            "check_supported": False,
            "confidence": 0.0,
            "plugin": plugin_name,
            "vulnerable": False,
        }
        assert all(item["trust_level"] == "trusted" for item in stored)

        run_command = f"plugin {plugin_name} {target} run"
        run_result = runtime.dispatch(
            run_command,
            (),
            set(),
            context,
        )
        assert run_result.status is ExecutionStatus.FAILED
        assert run_result.metadata["action_id"] == action_id
        assert run_result.metadata["action_lifecycle"]["attempt"] == "attempted"
        assert run_result.metadata["action_lifecycle"]["outcome"] == "failed"
        assert run_result.error_message == expected_errors[plugin_name]
        assert run_result.stdout == ""
        assert run_result.artifact_refs == ()
        assert run_result.metadata["data"] == {}
        assert run_result.metadata["credentials"] == []
        assert run_result.metadata["sessions"] == []
        assert runtime.parse_output(run_command, run_result) == []

    files_after = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}
    assert files_after == files_before


def test_pipeline_runtime_uses_injected_manager_without_default_discovery(
    tmp_path,
    monkeypatch,
) -> None:
    manager = _InertManager("injected_metadata_fixture")

    def unexpected_default_manager(_modules_dir: str):
        raise AssertionError("injected manager must bypass default discovery")

    monkeypatch.setattr(plugin_loader, "PluginManager", unexpected_default_manager)
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda _command: "unused",
        plugin_manager=manager,
    )

    assert runtime.plugin_manager is manager
    assert runtime.action_catalog.require("plugin:injected_metadata_fixture").adapter.manager is manager
    assert manager.metadata_reads == ["injected_metadata_fixture"]


def test_pipeline_runtime_fails_closed_when_default_plugin_root_is_missing(
    tmp_path,
    monkeypatch,
) -> None:
    missing = tmp_path / "missing-modules"
    monkeypatch.setattr(PipelineRuntime, "_default_plugin_root", staticmethod(lambda: str(missing)))
    runtime = PipelineRuntime(str(tmp_path / "facts.db"), runner=lambda _command: "unused")

    with pytest.raises(RuntimeError, match=r"^plugin_catalog_root_missing:"):
        _ = runtime.action_catalog


def test_pipeline_runtime_fails_closed_when_default_metadata_catalog_is_empty(
    tmp_path,
    monkeypatch,
) -> None:
    modules_dir = tmp_path / "modules"
    modules_dir.mkdir()

    class EmptyManager(_InertManager):
        def __init__(self, _modules_dir: str) -> None:
            super().__init__()
            self.skipped_plugins = {"broken": "synthetic discovery failure"}

    monkeypatch.setattr(PipelineRuntime, "_default_plugin_root", staticmethod(lambda: str(modules_dir)))
    monkeypatch.setattr(plugin_loader, "PluginManager", EmptyManager)
    runtime = PipelineRuntime(str(tmp_path / "facts.db"), runner=lambda _command: "unused")

    with pytest.raises(RuntimeError, match=r"^plugin_catalog_empty:skipped=1$"):
        _ = runtime.action_catalog


def test_pipeline_runtime_reports_default_discovery_failure(
    tmp_path,
    monkeypatch,
) -> None:
    modules_dir = tmp_path / "modules"
    modules_dir.mkdir()

    def broken_manager(_modules_dir: str):
        raise OSError("synthetic provider detail must not cross the diagnostic boundary")

    monkeypatch.setattr(PipelineRuntime, "_default_plugin_root", staticmethod(lambda: str(modules_dir)))
    monkeypatch.setattr(plugin_loader, "PluginManager", broken_manager)
    runtime = PipelineRuntime(str(tmp_path / "facts.db"), runner=lambda _command: "unused")

    with pytest.raises(RuntimeError, match=r"^plugin_catalog_discovery_failed:OSError$"):
        _ = runtime.action_catalog


def test_pipeline_runtime_rejects_invalid_default_manager_contract(
    tmp_path,
    monkeypatch,
) -> None:
    modules_dir = tmp_path / "modules"
    modules_dir.mkdir()

    class InvalidManager:
        plugins = ("not", "a", "mapping")

        def __init__(self, _modules_dir: str) -> None:
            pass

    monkeypatch.setattr(PipelineRuntime, "_default_plugin_root", staticmethod(lambda: str(modules_dir)))
    monkeypatch.setattr(plugin_loader, "PluginManager", InvalidManager)
    runtime = PipelineRuntime(str(tmp_path / "facts.db"), runner=lambda _command: "unused")

    with pytest.raises(RuntimeError, match=r"^plugin_catalog_invalid:plugins_not_mapping$"):
        _ = runtime.action_catalog
