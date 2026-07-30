"""Hermetic boundary coverage for the pipeline facade.

These tests deliberately exercise compatibility and malformed-input seams that
are difficult to reach through a normal scan, while keeping tool execution and
network access fully stubbed.
"""

from __future__ import annotations

import builtins
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.ai.pipeline as pipeline_module
from core.ai.command_scheduler import CommandDecision
from core.ai.pipeline import AIPipeline
from core.execution import ExecutionContext, ExecutionResult, ExecutionStatus

pytestmark = pytest.mark.contract


def _bare_pipeline() -> AIPipeline:
    pipeline = AIPipeline.__new__(AIPipeline)
    pipeline._reset_runtime_state()
    return pipeline


def _command_result(
    command: str,
    *,
    facts: list[dict] | None = None,
    parsed: int = 0,
    new: int = 0,
    provider_attempts: tuple[str, ...] = (),
) -> dict:
    return {
        "facts": list(facts or []),
        "parsed_facts": parsed,
        "new_facts": new,
        "command_result": {"command": command},
        "_provider_fallback_attempt_action_ids": list(provider_attempts),
    }


def _post_result(
    *,
    facts: list[dict] | None = None,
    parsed: int = 0,
    new: int = 0,
    commands: list[dict] | None = None,
) -> dict:
    return {
        "facts": list(facts or []),
        "parsed_facts": parsed,
        "new_facts": new,
        "commands": list(commands or []),
    }


def test_import_fallback_properties_and_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def reject_tools(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.tools.public":
            raise ImportError("fixture has no tool runtime")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", reject_tools)
    namespace = runpy.run_path(
        str(Path(pipeline_module.__file__)),
        run_name="pipeline_fallback_fixture",
    )
    with pytest.raises(FileNotFoundError, match="tool runtime is unavailable"):
        namespace["run_arbitrary_cmd"]("probe host")

    pipeline = _bare_pipeline()
    markers = {name: object() for name in (
        "action_catalog",
        "action_executor",
        "provider_telemetry",
        "provider_selector",
        "provider_fallback_executor",
        "decision_trace",
    )}
    pipeline.runtime = SimpleNamespace(**markers)

    assert pipeline.action_catalog is markers["action_catalog"]
    assert pipeline.action_executor is markers["action_executor"]
    assert pipeline.provider_telemetry is markers["provider_telemetry"]
    assert pipeline.provider_selector is markers["provider_selector"]
    assert pipeline.provider_fallback_executor is markers["provider_fallback_executor"]
    assert pipeline.decision_trace is markers["decision_trace"]
    assert pipeline.cancel("boundary") is True


def test_run_task_commands_handles_failed_and_repeated_fallback_resolution() -> None:
    pipeline = _bare_pipeline()
    executed: list[str] = []

    class Catalog:
        def resolve(self, tool: str):
            if tool == "second":
                raise LookupError("malformed provider candidate")
            return SimpleNamespace(canonical_id="fallback.action")

    pipeline.runtime = SimpleNamespace(action_catalog=Catalog())
    pipeline._expand_command_with_context = lambda command, _scan, _target: [command]
    pipeline._augment_command_with_context = lambda command, _scan, _target: command
    pipeline._task_provider_commands = lambda *_args, **_kwargs: ()

    def execute(_scan, _target, command, *_args, **_kwargs):
        executed.append(command)
        attempts = ("fallback.action",) if command == "first" else ()
        return _command_result(command, provider_attempts=attempts)

    pipeline._execute_pipeline_command = execute
    pipeline._active_commands_from_facts = lambda _facts: []
    pipeline._run_controlled_post_access_followups = lambda *_args: _post_result()
    pipeline._run_fact_driven_actions = lambda *_args: _post_result()
    pipeline._followup_commands_from_facts = lambda _facts: []
    pipeline._command_result_reason = lambda *_args: "fixture"

    result = pipeline._run_task_commands(
        "scan",
        "host",
        ["first", "second", "third"],
        "Fact",
    )

    assert executed == ["first", "second"]
    assert result["reason"] == "fixture"


def test_task_provider_commands_rejects_bad_profiles_and_bounds_candidates() -> None:
    pipeline = _bare_pipeline()
    pipeline.mission_id = "mission"
    profile: object = None

    class Registry:
        @staticmethod
        def canonical_task(task: str) -> str:
            return task

        @staticmethod
        def task_profile(_task: str):
            return profile

    class Catalog:
        @staticmethod
        def resolve(tool: str):
            if tool == "broken":
                raise LookupError("unresolvable action")
            return SimpleNamespace(canonical_id="excluded" if tool == "skip" else tool)

    pipeline.tool_registry = Registry()
    pipeline.runtime = SimpleNamespace(action_catalog=Catalog())
    pipeline._expand_command_with_context = lambda command, _scan, _target: [command]
    pipeline._augment_command_with_context = lambda command, _scan, _target: command

    assert pipeline._task_provider_commands("current", ["other"], "scan", "host") == ()

    profile = {"risk": "safe"}
    pipeline._max_tools_budget = None
    candidates = pipeline._task_provider_commands(
        "current",
        ["broken", "skip", "keep"],
        "scan",
        "host",
        excluded_action_ids={"excluded"},
    )
    assert candidates == ("current", "broken", "keep")

    pipeline._max_tools_budget = 2
    pipeline.tools_run_count = 1
    assert pipeline._task_provider_commands(
        "current",
        ["keep"],
        "scan",
        "host",
    ) == ("current",)


def test_retry_command_without_durable_grant_is_skipped() -> None:
    pipeline = _bare_pipeline()
    decision = CommandDecision("probe host", "probe host", "execute", "retry", retry=True)
    pipeline.runtime = SimpleNamespace(decide=lambda *_args: decision)
    pipeline.mission_id = "mission"
    pipeline._active_task_id = "task"
    pipeline._active_task_agent = "DiscoveryAgent"
    pipeline._active_task_name = "probe"
    pipeline.mission_store = SimpleNamespace(consume_retry_command=lambda *_args, **_kwargs: False)
    pipeline._execution_context = lambda *_args: ExecutionContext.automatic(target_scope=("host",))
    pipeline._accepted_task_decision_facts = lambda *_args: []
    traces: list[dict] = []
    pipeline._record_command_trace = lambda audit, result: traces.append({**audit, "result": result})

    result = pipeline._execute_pipeline_command(
        "scan",
        "host",
        "probe host",
        "Fact",
        "[Running]",
    )

    assert result["command_result"]["skip_reason"] == "retry_command_grant_unavailable"
    assert traces[-1]["action"] == "skip"


def test_execute_command_without_execution_id_skips_source_attachment(tmp_path: Path) -> None:
    pipeline = AIPipeline(str(tmp_path / "no-execution-id.db"))
    decision = CommandDecision("probe host", "probe host", "execute", "fixture")
    pipeline.runtime.decide = lambda *_args: decision
    pipeline.runtime.execute = lambda *_args: ExecutionResult(
        status=ExecutionStatus.SUCCEEDED,
        tool_name="probe",
        stdout="",
        metadata={"provider_attempts": 1},
    )
    synced: list[list[dict]] = []
    pipeline._sync_runtime_credentials_from_facts = (
        lambda _target, facts: synced.append(list(facts))
    )

    result = pipeline._execute_pipeline_command(
        "scan",
        "host",
        "probe host",
        "Fact",
        "[Running]",
    )

    assert result["command_result"]["check_status"] == "completed_empty"
    assert synced


def test_task_snapshot_guards_and_runtime_signature_compatibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = _bare_pipeline()
    task = SimpleNamespace(task_id="task", evaluated_snapshot_ref="snapshot")
    snapshot = SimpleNamespace(scan_id="other", decision_facts=lambda: ({"type": "fact"},))
    pipeline.mission_id = "mission"
    pipeline._active_task_id = "task"
    pipeline.mission_store = SimpleNamespace(
        snapshot=lambda _mission: SimpleNamespace(tasks=(task,)),
        resolve_evaluated_fact_snapshot=lambda *_args: snapshot,
    )
    pipeline.fact_store = SimpleNamespace(get_facts=lambda *_args: [{"type": "fallback"}])

    with pytest.raises(RuntimeError, match="different scan"):
        pipeline._accepted_task_decision_facts("scan", "host")

    pipeline.mission_store.resolve_evaluated_fact_snapshot = lambda *_args: None
    assert pipeline._accepted_task_decision_facts("scan", "host") == [{"type": "fallback"}]

    calls: list[tuple] = []
    pipeline.runtime = SimpleNamespace(
        execute=lambda *args, **kwargs: calls.append((args, kwargs)) or "result"
    )
    monkeypatch.setattr(pipeline_module.inspect, "signature", lambda _callable: (_ for _ in ()).throw(ValueError()))
    assert pipeline._execute_runtime_compatibly(
        object(),
        object(),
        facts=(),
        capability="probe",
    ) == "result"
    assert calls[-1][1] == {}

    def accepts_everything(*args, **kwargs):
        calls.append((args, kwargs))
        return "keywords"

    pipeline.runtime.execute = accepts_everything
    monkeypatch.undo()
    assert pipeline._execute_runtime_compatibly(
        object(),
        object(),
        facts=({"type": "fact"},),
        capability="probe",
        provider_commands=("probe host",),
        partial_result_ingest=object(),
    ) == "keywords"
    assert set(calls[-1][1]) == {
        "facts",
        "capability",
        "provider_commands",
        "partial_result_ingest",
    }


def test_check_result_boundary_helpers_cover_internal_scopes_and_kinds() -> None:
    pipeline = _bare_pipeline()
    parsed = [
        {"type": "port_open", "value": "80/tcp (http)"},
        {"type": "internal_service", "value": "malformed"},
        {"type": "internal_service", "value": "10.0.0.8:445/tcp (smb)"},
    ]

    results = pipeline._command_end_check_results(
        "internal_service_probe host",
        "host",
        "internal_service_probe host",
        "completed",
        "",
        parsed,
    )

    assert len(results) == 2
    assert pipeline._output_fingerprint(" a\n b ") == pipeline._output_fingerprint("a b")
    assert pipeline._internal_service_scope_value("10.0.0.8:445/tcp (smb)")
    expected = {
        "jwt_analyze token": "web_app_deep_testing",
        "nikto http://host": "web_vulnerability",
        "graphql_check http://host/graphql": "api_security",
        "network_recon host": "internal_network_recon",
        "internal_service_probe host": "internal_service_discovery",
    }
    assert {command: pipeline._command_check_kind(command) for command in expected} == expected
    assert pipeline._command_check_mode("msf_check auxiliary/scanner/ssh/ssh_login", "skipped") == (
        "login_check_missing_creds"
    )


def test_store_fact_preserves_secret_refs_and_deduplicates_derived_facts() -> None:
    pipeline = _bare_pipeline()
    calls = 0

    def add_fact(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return calls, calls == 1

    pipeline.fact_store = SimpleNamespace(
        redactor=SimpleNamespace(
            redact_fact=lambda _fact_type, _value: ("[REDACTED]", ("secret-ref",))
        ),
        add_fact_with_status=add_fact,
    )
    pipeline.runtime = SimpleNamespace(project_fact_ids=lambda _ids: None)
    pipeline._scope_normalized_fact = lambda _target, fact: fact
    pipeline._derived_facts_from_fact = lambda *_args: [
        {"type": "web_endpoint", "value": "http://host/", "confidence": 80}
    ]

    result = pipeline._store_fact(
        "scan",
        "host",
        {"type": "credential", "value": "secret", "confidence": 90},
        "fixture",
    )

    assert result["fact"]["secret_refs"] == ["secret-ref"]
    assert result["new_facts"] == 1


def test_endpoint_and_graph_parsers_reject_malformed_or_hostless_values() -> None:
    pipeline = _bare_pipeline()

    assert pipeline._endpoint_from_port_fact("host", "malformed") == ""
    assert pipeline._endpoint_from_port_fact("", "8080/tcp (http)") == ""
    assert pipeline._endpoint_from_command_source("probe without a URL") == ""
    assert pipeline._network_graph_facts("", "internal_host", "10.0.0.8") == []
    assert pipeline._network_graph_facts("host", "port_open", "malformed") == []


def test_verification_followup_filters_and_limit() -> None:
    pipeline = _bare_pipeline()
    pipeline.executed_followup_commands = set()
    pipeline.tool_registry = SimpleNamespace(_is_tool_available=lambda tool: tool != "msf_check")
    pipeline._strategy_limit = lambda key, default=None: 1
    facts = [
        {"type": "verification_command", "value": ""},
        {"type": "verification_command", "value": "not-a-followup"},
        {"type": "verification_command", "value": "msf_check auxiliary/scanner/ssh/ssh_version"},
        {"type": "verification_command", "value": "plugin demo exploit"},
        {"type": "verification_command", "value": "searchsploit openssh"},
        {"type": "verification_command", "value": "searchsploit nginx"},
    ]

    assert pipeline._followup_commands_from_facts(facts) == ["searchsploit openssh"]


def test_fact_driven_action_execution_reaches_active_and_post_access_paths() -> None:
    pipeline = _bare_pipeline()
    pipeline._fact_action_max_depth = lambda: None
    pipeline._fact_action_max_commands = lambda: None
    pipeline._fact_driven_action_commands = (
        lambda _scan, _target, facts: ["root"] if facts and facts[0].get("stage") == "initial" else []
    )
    execution_results = {
        "root": _command_result(
            "root",
            facts=[{"stage": "root", "type": "active_command", "value": "msf_run exploit/demo"}],
            parsed=1,
            new=1,
        ),
        "verify": _command_result("verify", facts=[{"stage": "verified"}], parsed=3, new=1),
        "active": _command_result("active", facts=[{"stage": "active"}], parsed=4, new=1),
        "active-with-post": _command_result(
            "active-with-post",
            facts=[{"stage": "active-with-post"}],
            parsed=4,
            new=1,
        ),
    }
    pipeline._execute_pipeline_command = lambda _scan, _target, command, *_args: execution_results[command]
    pipeline._active_commands_from_facts = lambda facts: ["candidate"] if facts[0].get("stage") == "root" else []
    pipeline._followup_commands_from_facts = lambda facts: ["verify"] if facts[0].get("stage") == "root" else []
    pipeline._active_followups_after_verification = lambda *_args: ["active", "active-with-post"]

    def post_access(_scan, _target, facts):
        stage = facts[0].get("stage")
        return _post_result(
            parsed=2 if stage == "root" else 5,
            new=1,
            commands=[] if stage == "active" else [{"command": f"post-{stage}"}],
        )

    pipeline._run_controlled_post_access_followups = post_access

    result = pipeline._run_fact_driven_actions(
        "scan",
        "host",
        [{"stage": "initial"}],
    )

    assert [item["command"] for item in result["commands"]] == [
        "root",
        "post-root",
        "verify",
        "post-verified",
        "active",
        "active-with-post",
        "post-active-with-post",
    ]
    assert result["parsed_facts"] == 29


def test_fact_driven_action_limits_cover_each_early_exit() -> None:
    def make_pipeline(maximum: int, *, active: bool = False) -> AIPipeline:
        pipeline = _bare_pipeline()
        pipeline._fact_action_max_depth = lambda: 0
        pipeline._fact_action_max_commands = lambda: maximum
        pipeline._fact_driven_action_commands = lambda *_args: ["root", "second"]
        pipeline._execute_pipeline_command = lambda _scan, _target, command, *_args: _command_result(
            command,
            facts=[{"stage": command}],
            parsed=1,
            new=1,
        )
        pipeline._active_commands_from_facts = lambda _facts: ["candidate"] if active else []
        pipeline._run_controlled_post_access_followups = lambda *_args: _post_result()
        pipeline._followup_commands_from_facts = lambda _facts: ["verify"]
        pipeline._active_followups_after_verification = lambda *_args: ["active"]
        return pipeline

    one = make_pipeline(1)
    assert len(one._run_fact_driven_actions("scan", "host", [{"stage": "initial"}])["commands"]) == 1

    two = make_pipeline(2, active=True)
    commands = two._run_fact_driven_actions("scan", "host", [{"stage": "initial"}])["commands"]
    assert [item["command"] for item in commands] == ["root", "verify"]


@pytest.mark.parametrize("method_name", ["_fact_action_max_depth", "_fact_action_max_commands"])
def test_fact_action_config_parsing_and_import_fallback(
    method_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import config

    pipeline = _bare_pipeline()
    original_import = builtins.__import__

    def reject_config(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "config":
            raise ImportError("fixture config missing")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", reject_config)
    assert getattr(pipeline, method_name)() is None
    monkeypatch.setattr(builtins, "__import__", original_import)

    key = "fact_action_max_depth" if method_name.endswith("depth") else "fact_action_max_commands"
    for raw, expected in (("invalid", None), (-2, None), (2, 2)):
        monkeypatch.setattr(config, "CFG", {"strategy": {key: raw}})
        assert getattr(pipeline, method_name)() == expected


def test_fact_action_mapping_and_service_intelligence_boundaries() -> None:
    pipeline = _bare_pipeline()
    pipeline.fact_store = SimpleNamespace(get_facts=lambda *_args: [])
    pipeline.executed_fact_action_commands = set()
    pipeline.service_intelligence_evidence_seen = set()
    pipeline._post_access_inventory_seen = lambda _pairs: False
    pipeline._facts_include_cached_ssh_credential = lambda _facts: True
    pipeline._facts_confirm_ssh_access = lambda _facts: False
    pipeline._auto_ssh_inventory_enabled = lambda: True
    pipeline._facts_indicate_cpanel_surface = lambda _facts: False
    pipeline._cpanel_already_verified = lambda _pairs: False
    pipeline._service_intelligence_commands = lambda *_args: ["exploit_select host"]
    pipeline._service_action_commands = lambda *_args: []
    pipeline._web_path_action_commands = lambda *_args: []
    pipeline._web_link_action_commands = lambda *_args: []
    pipeline._web_surface_action_commands = lambda *_args: []
    pipeline._augment_command_with_context = lambda command, *_args: command
    pipeline._strategy_limit = lambda key, default=None: 1 if key == "fact_action_batch_commands" else default

    assert pipeline._fact_driven_action_commands("scan", "host", [{"type": "credential"}]) == [
        "ssh_inventory host"
    ]
    assert AIPipeline._facts_include_cached_ssh_credential(
        pipeline,
        [{"type": "credential", "value": "ssh_key_available:key-1"}]
    )

    pipeline._service_intelligence_evidence_key = lambda fact: str(fact.get("key", ""))
    pipeline._searchsploit_queries_from_facts = lambda _facts: ["one", "two"]
    pipeline._searchsploit_query_seen = lambda _pairs, _query: False
    pipeline.tool_registry = SimpleNamespace(_is_tool_available=lambda _tool: True)
    pipeline._strategy_limit = lambda key, default=None: 2 if key == "searchsploit_followup_queries" else default
    assert AIPipeline._service_intelligence_commands(
        pipeline,
        "scan",
        "host",
        [{"key": "fresh"}],
        set(),
    ) == ["exploit_select host", "searchsploit one"]


def test_service_evidence_and_search_query_edge_cases() -> None:
    pipeline = _bare_pipeline()
    pipeline._web_link_looks_interesting = lambda _value: False

    assert pipeline._service_intelligence_evidence_key({"type": "unknown", "value": "value"}) == ""
    assert pipeline._service_intelligence_evidence_key({"type": "web_link", "value": "http://host/"}) == ""
    pipeline._fact_is_external_service_evidence = lambda _fact: True
    assert pipeline._service_intelligence_evidence_key({"type": "port_open", "value": ""}) == ""
    del pipeline._fact_is_external_service_evidence
    assert pipeline._facts_include_service_evidence([{"type": "port_open", "value": "80/tcp (http)"}])
    assert not pipeline._fact_is_external_service_evidence({"type": "port_open", "value": ""})
    assert not pipeline._fact_is_external_service_evidence(
        {"type": "port_open", "value": "80/tcp (http)", "source": "ssh_inventory host"}
    )
    assert not pipeline._fact_is_external_service_evidence(
        {"type": "port_open", "value": "80/tcp (http)", "source": "derived:ssh_inventory host"}
    )

    pipeline._fact_is_external_service_evidence = lambda _fact: True
    queries = pipeline._searchsploit_queries_from_facts(
        [
            {"type": "port_open", "value": "malformed"},
            {"type": "service_version", "value": "odd-version"},
            {"type": "web_title", "value": "Apache landing"},
            {"type": "web_title", "value": "WordPress landing"},
            {"type": "potential_vulnerability", "value": "CVE-2024-12345 CVE-2024-12345"},
        ]
    )
    assert queries == ["odd-version", "http", "apache", "wordpress", "CVE-2024-12345"]
    assert pipeline._service_name_for_common_port("3306") == "mysql"
    assert pipeline._service_name_for_common_port("1") == ""
    assert pipeline._query_from_manifest_path("/srv/package.json") == "nodejs"
    assert pipeline._query_from_manifest_path("/srv/unknown") == ""
    assert pipeline._query_from_config_path("/srv/wp-config.php") == "wordpress"
    assert pipeline._query_from_config_path("/srv/unknown") == ""


def test_inventory_cpanel_and_service_seen_boundaries() -> None:
    pipeline = _bare_pipeline()

    assert pipeline._post_access_inventory_seen(
        {("post_exploit_stage", "post_access_inventory_completed")}
    )
    assert pipeline._post_access_inventory_seen({("service_status", "ssh_inventory_completed")})
    assert not pipeline._facts_indicate_cpanel_surface(
        [{"type": "application_access", "value": "cpanel authenticated"}]
    )
    assert pipeline._cpanel_already_verified({("application_access", "cpanel_whm_authenticated:user")})
    assert pipeline._cpanel_already_verified({("vulnerability", "cpanel_auth_bypass")})
    assert pipeline._cpanel_already_verified({("credential", "whm_session:ref")})
    assert pipeline._open_service_ports(
        [
            {"type": "port_open", "value": "malformed"},
            {"type": "port_open", "value": "21/tcp (ftp)"},
        ]
    ) == [("21", "ftp", "21/tcp (ftp)")]
    assert pipeline._service_status_seen(
        [
            ("port_open", "21/tcp (ftp)"),
            ("service_status", "unrelated"),
            ("service_status", "ftp_anonymous_allowed:host:21"),
        ],
        ("ftp_anonymous_allowed",),
        "21",
    )
    assert pipeline._database_inventory_seen(
        [
            ("port_open", "5432/tcp (postgresql)"),
            ("service_status", "unrelated"),
            ("service_status", "db_inventory_completed:host:postgresql:5432"),
        ],
        "postgresql",
        "5432",
    )


def test_web_surface_command_limits_cover_each_stage() -> None:
    pipeline = _bare_pipeline()
    pipeline._facts_include_web_surface = lambda _facts: True
    pipeline._web_endpoints_from_facts = lambda *_args: ["http://host/"]
    pipeline._strategy_limit = lambda key, default=None: 1 if key == "web_surface_followup_commands" else default
    pipeline._nuclei_seen = lambda *_args: False
    pipeline._web_endpoint_absent_seen = lambda *_args: True
    pipeline._browser_render_seen = lambda *_args: False
    pipeline._crawl_seen = lambda *_args: False
    pipeline.tool_registry = SimpleNamespace(_is_tool_available=lambda _tool: True)
    assert pipeline._web_surface_action_commands("scan", "host", [{}], set()) == []

    pipeline._web_endpoint_absent_seen = lambda *_args: False
    assert pipeline._web_surface_action_commands("scan", "host", [{}], set()) == [
        "browser_surface_analysis http://host/"
    ]

    pipeline._browser_render_seen = lambda *_args: True
    assert pipeline._web_surface_action_commands("scan", "host", [{}], set()) == [
        "security_headers_check http://host/"
    ]

    availability = {"cors_check"}
    pipeline.tool_registry = SimpleNamespace(_is_tool_available=lambda tool: tool in availability)
    assert pipeline._web_surface_action_commands("scan", "host", [{}], set()) == ["cors_check http://host/"]

    availability.clear()
    assert pipeline._web_surface_action_commands("scan", "host", [{}], set()) == ["scrapling_crawl http://host/"]

    pipeline._crawl_seen = lambda *_args: True
    availability.add("nuclei_safe")
    assert pipeline._web_surface_action_commands("scan", "host", [{}], set()) == ["nuclei_safe http://host/"]

    availability.clear()
    availability.add("katana_crawl")
    assert pipeline._web_surface_action_commands("scan", "host", [{}], set()) == ["katana_crawl http://host/"]


def test_nuclei_and_active_command_seen_boundaries() -> None:
    pipeline = _bare_pipeline()
    endpoint = "http://host/"

    assert pipeline._nuclei_seen(
        [],
        {("service_status", "nuclei_scan_completed:http://host")},
        endpoint,
    )
    assert pipeline._nuclei_seen(
        [{"type": "service_status", "value": "nuclei_scan_completed:http://host"}],
        set(),
        endpoint,
    )
    assert pipeline._nuclei_seen(
        [
            {"type": "other", "value": "ignored"},
            {"type": "service_status", "value": "other"},
            {
                "type": "service_status",
                "value": "tool_timeout:nuclei_safe",
                "source": "nuclei_safe http://else/",
            },
            {
                "type": "service_status",
                "value": "tool_timeout:nuclei_safe",
                "source": "nuclei_safe http://else/",
                "observations": [
                    "invalid",
                    {"source": "nuclei_safe http://host/"},
                ],
            },
        ],
        set(),
        endpoint,
    )

    assert pipeline._active_commands_from_facts(
        [
            {"type": "other", "value": "msf_run ignored"},
            {"type": "active_command", "value": "not-msf"},
            {"type": "active_command", "value": "msf_run exploit/demo"},
            {"type": "active_command", "value": "msf_run exploit/demo"},
        ]
    ) == ["msf_run exploit/demo"]


def test_active_config_import_fallback_and_policy_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    import config

    pipeline = _bare_pipeline()
    original_import = builtins.__import__

    def reject_config(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "config":
            raise ImportError("fixture config missing")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", reject_config)
    assert not pipeline._active_msf_allowed("host")
    assert pipeline._max_active_msf_runs() == 1
    monkeypatch.setattr(builtins, "__import__", original_import)

    monkeypatch.setattr(config, "CFG", {"strategy": {"allow_active_msf": True}})
    assert not pipeline._active_msf_allowed("host")
    monkeypatch.setattr(
        config,
        "CFG",
        {
            "strategy": {
                "allow_active_msf": True,
                "active_authorized": True,
                "authorized_targets": ["host"],
            }
        },
    )
    assert pipeline._active_msf_allowed("host")


def test_expansion_and_jmx_endpoint_boundaries() -> None:
    pipeline = _bare_pipeline()
    assert pipeline._expand_command_with_context("single", "scan", "host") == ["single"]

    pipeline._jmx_or_tomcat_endpoints = lambda *_args: ["http://host:8080/"]
    pipeline._has_jmx_or_tomcat_evidence = lambda *_args: False
    assert pipeline._expand_command_with_context("jmx2rce_scan host", "scan", "host") == []

    facts = [
        {"type": "service_status", "value": "jmx2rce_not_vulnerable:host"},
        {"type": "port_open", "value": "tomcat malformed"},
        {"type": "service_version", "value": "tomcat:bad:version"},
        {"type": "service_version", "value": "tomcat:8443:TLS"},
        {"type": "service_version", "value": "tomcat:8443:TLS"},
        {"type": "web_endpoint", "value": "http://external.test/ tomcat"},
        {"type": "web_title", "value": "Tomcat Manager"},
    ]
    pipeline.fact_store = SimpleNamespace(get_facts=lambda *_args: facts)
    endpoints = AIPipeline._jmx_or_tomcat_endpoints(pipeline, "scan", "host")
    assert endpoints == ["https://host:8443"]

    pipeline.fact_store.get_facts = lambda *_args: [{"type": "web_title", "value": "Tomcat Manager"}]
    pipeline._web_endpoints_from_facts = lambda *_args: ["http://host/"]
    assert AIPipeline._jmx_or_tomcat_endpoints(pipeline, "scan", "host") == ["http://host/"]

    pipeline.fact_store.get_facts = lambda *_args: [
        {"type": "service_status", "value": "jmx2rce_not_vulnerable:host"},
        {"type": "web_title", "value": "Tomcat"},
    ]
    assert AIPipeline._has_jmx_or_tomcat_evidence(pipeline, "scan", "host")
    pipeline.fact_store.get_facts = lambda *_args: [{"type": "service_status", "value": "ordinary"}]
    assert not AIPipeline._has_jmx_or_tomcat_evidence(pipeline, "scan", "host")


def test_web_endpoint_compact_context_and_cpanel_boundaries() -> None:
    pipeline = _bare_pipeline()
    pipeline.fact_store = SimpleNamespace(
        get_facts=lambda *_args: [
            {"type": "web_endpoint", "value": ""},
            {"type": "port_open", "value": "malformed"},
        ]
    )
    assert pipeline._web_endpoints_from_facts("scan", "host") == []

    facts = [
        {"type": "other", "value": ""},
        {"type": "port_open", "value": "malformed"},
        {"type": "port_open", "value": "host:53/udp (dns) [banner]"},
        {"type": "port_open", "value": "host:53/udp (dns) [banner]"},
        {"type": "internal_service", "value": "malformed"},
        {"type": "internal_service", "value": "10.0.0.8:445/tcp (smb)"},
        {"type": "internal_service", "value": "10.0.0.8:445/tcp (smb)"},
        {"type": "system_access", "value": "uid=0"},
        {"type": "system_access", "value": "ordinary-user"},
        {"type": "service_status", "value": "ssh_authenticated"},
        {"type": "service_status", "value": "unrelated"},
        {"type": "credential", "value": "unrelated"},
        {"type": "credential", "value": "ssh_login_success:ref"},
    ]
    context = pipeline._exploit_select_compact_context(facts)
    assert context["open_ports"] == [
        {"port": 53, "proto": "udp", "service": "dns", "host": "host", "banner": "banner"}
    ]
    assert len(context["internal_services"]) == 1
    assert context["access"] == ["root", "ssh_authenticated", "ssh_login_success"]
    assert pipeline._parse_port_fact_for_context("malformed") == {}
    assert pipeline._parse_port_fact_for_context("53/tcp (dns)") == {
        "port": 53,
        "proto": "tcp",
        "service": "dns",
    }
    assert pipeline._parse_internal_service_for_context("malformed") == {}

    assert not pipeline._web_fact_in_target_scope("", "host")
    assert pipeline._web_fact_in_target_scope("http://host/path", "host")
    assert pipeline._web_fact_in_target_scope("/relative", "host")
    pipeline._endpoint_url_from_value = lambda _value: ""
    assert not pipeline._web_fact_in_target_scope("http://external.test/path", "host")
    assert pipeline._web_fact_in_target_scope("relative", "host")

    pipeline._best_cpanel_port = lambda *_args: ""
    assert pipeline._augment_cpanel_command("plugin demo host scan", "scan", "host") == "plugin demo host scan"
    pipeline._best_cpanel_port = lambda *_args: "2087"
    assert pipeline._augment_cpanel_command("plugin demo host scan", "scan", "host") == "plugin demo host scan"
    assert pipeline._augment_cpanel_command(
        "plugin cpanel_auth_bypass host scan",
        "scan",
        "host",
    ) == "plugin cpanel_auth_bypass host:2087 scan"
    assert pipeline._augment_cpanel_command(
        "cpanel_exploit host scan",
        "scan",
        "host",
    ) == "cpanel_exploit host:2087 scan"

    pipeline.fact_store.get_facts = lambda *_args: [
        {"type": "other", "value": "2087/tcp (https)"},
        {"type": "port_open", "value": "80/tcp (http)"},
    ]
    assert AIPipeline._best_cpanel_port(pipeline, "scan", "host") == ""


def test_exploit_context_augmentation_covers_empty_and_compact_context() -> None:
    pipeline = _bare_pipeline()
    stored_facts: list[dict] = []
    pipeline.fact_store = SimpleNamespace(get_facts=lambda *_args: stored_facts)
    pipeline._strategy_limit = lambda _key, default=None: default

    assert pipeline._augment_command_with_context("exploit_select host", "scan", "host") == (
        "exploit_select host"
    )

    stored_facts.append({"type": "port_open", "value": "80/tcp (http)"})
    augmented = pipeline._augment_command_with_context("exploit_select host", "scan", "host")
    assert "port_open -> 80/tcp (http)" in augmented
    assert "compact_state ->" in augmented
