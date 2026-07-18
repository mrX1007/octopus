#!/usr/bin/env python3
"""Director, planner, and bounded LLM decision contracts."""

import pytest

pytestmark = pytest.mark.contract

def test_post_exploit_goal_forces_verification_plan():
    import config
    from core.ai.pipeline import AIPipeline

    old_strategy = dict(config.CFG.get("strategy", {}))
    config.CFG.setdefault("strategy", {}).update({"auto_data_exfil": True})
    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    try:
        context = {
            "state": "root_access_confirmed",
            "services": ["ssh", "http"],
            "open_questions": ["data_exfiltration_pending"],
            "automation_policy": {"auto_data_exfil": True},
        }
        noisy_plan = [
            {"agent": "DiscoveryAgent", "task": "directory_bruteforce"},
            {"agent": "AnalysisAgent", "task": "analyze_services"},
        ]

        optimized = pipeline._optimize_plan(noisy_plan, "data_exfiltration", context)
    finally:
        config.CFG["strategy"] = old_strategy

    assert optimized == [{"agent": "VerificationAgent", "task": "exfiltrate_data"}]


def test_vulnerability_plan_gets_context_web_enrichment():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    pipeline.tool_registry.task_has_available_tools = lambda task: task == "web_application_mapping"
    context = {
        "state": "recon_completed",
        "services": ["http"],
        "open_questions": ["web_vulnerabilities_unknown"],
    }
    base_plan = [
        {"agent": "DiscoveryAgent", "task": "vulnerability_assessment"},
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]

    optimized = pipeline._optimize_plan(base_plan, "vulnerability_assessment", context)
    tasks = [step["task"] for step in optimized]

    assert tasks == [
        "vulnerability_assessment",
        "web_application_mapping",
        "analyze_vulnerabilities",
    ]


def test_director_validation_inserts_internal_recon_before_exfil():
    from core.ai.director import DirectorLLM

    context = {
        "state": "persistence_established",
        "services": ["ssh"],
        "open_questions": ["internal_network_recon_pending"],
    }

    goal = DirectorLLM()._validate_goal("data_exfiltration", context, [])

    assert goal == "internal_reconnaissance"


def test_director_does_not_advance_to_persistence_without_root():
    from core.ai.director import DirectorLLM

    context = {
        "state": "credentials_found",
        "services": ["ssh"],
        "open_questions": ["privilege_escalation_path_unknown"],
    }

    goal = DirectorLLM()._validate_goal(
        "privilege_escalation",
        context,
        ["service_discovery", "vulnerability_assessment", "credential_harvesting", "privilege_escalation"],
    )

    assert goal == "conclude"


def test_director_rejects_post_exploit_goal_without_root():
    from core.ai.director import DirectorLLM

    context = {
        "state": "credentials_found",
        "services": ["ssh"],
        "open_questions": ["privilege_escalation_path_unknown"],
    }

    goal = DirectorLLM()._validate_goal("data_exfiltration", context, [])

    assert goal == "privilege_escalation"


def test_director_does_not_drift_from_vuln_assessment_to_post_exploit_without_creds():
    from core.ai.director import DirectorLLM

    context = {
        "state": "vulnerabilities_found",
        "services": ["http", "https"],
        "open_questions": ["vulnerability_verification_needed", "jmx_exposure_unknown"],
    }

    goal = DirectorLLM()._validate_goal(
        "vulnerability_assessment",
        context,
        ["vulnerability_assessment", "credential_harvesting"],
    )

    assert goal == "conclude"


def test_exploit_selector_maps_service_banner_to_msf_payload_plan():
    from core.exploits.selector import select_exploits

    output = select_exploits(
        "10.0.0.5",
        "80/tcp open http Apache httpd 2.4.49",
        run_probe=False,
    )

    assert "exploit/multi/http/apache_normalize_path_rce" in output
    assert "Payload recommendation:" in output
    assert "MSF check: msf_check 10.0.0.5" in output
    assert "RPORT=80" in output


def test_cpanel_enrichment_takes_priority_in_short_vuln_plan():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_cpanel.db")
    pipeline.tool_registry.task_has_available_tools = lambda task: task in {
        "cpanel_assessment",
        "web_application_mapping",
        "web_vulnerability_testing",
    }
    context = {
        "state": "recon_completed",
        "services": ["http", "https", "cpanel"],
        "open_questions": ["web_vulnerabilities_unknown", "cpanel_auth_bypass_unknown"],
    }
    base_plan = [
        {"agent": "DiscoveryAgent", "task": "vulnerability_assessment"},
        {"agent": "DiscoveryAgent", "task": "web_application_mapping"},
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]

    optimized = pipeline._optimize_plan(base_plan, "vulnerability_assessment", context)
    tasks = [step["task"] for step in optimized]

    assert "cpanel_assessment" in tasks
    assert len(tasks) == 3


def test_ollama_json_extractor_recovers_valid_json_after_unclosed_think():
    from core.ai.ollama_client import _extract_json

    raw = '<think>reasoning started but never closed\n{"goal": "internal_reconnaissance", "thought": "facts require it"}'

    assert _extract_json(raw) == '{"goal": "internal_reconnaissance", "thought": "facts require it"}'


def test_vulnerability_plan_gets_ad_enrichment_for_ldap_surface():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    pipeline.tool_registry.task_has_available_tools = lambda task: task == "active_directory_enumeration"
    context = {
        "state": "recon_completed",
        "services": ["ldap", "kerberos"],
        "open_questions": ["active_directory_exposure_unknown"],
    }
    base_plan = [
        {"agent": "DiscoveryAgent", "task": "vulnerability_assessment"},
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]

    optimized = pipeline._optimize_plan(base_plan, "vulnerability_assessment", context)
    tasks = [step["task"] for step in optimized]

    assert tasks == [
        "vulnerability_assessment",
        "active_directory_enumeration",
        "analyze_vulnerabilities",
    ]


def test_director_next_required_capability_overrides_llm_suggestion():
    from core.ai.director import DirectorLLM

    context = {
        "state": "recon_completed",
        "services": ["http"],
        "open_questions": ["web_vulnerabilities_unknown"],
        "next_required_capability": "vulnerability_assessment",
        "automation_policy": {},
    }

    assert DirectorLLM()._validate_goal("credential_harvesting", context, []) == "vulnerability_assessment"


def test_nested_planner_json_tasks_are_normalized_without_failing():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_nested_plan.db")
    plan_res = {
        "plan": {
            "director_goal": "internal_reconnaissance",
            "tasks": [
                {
                    "name": "internal_services",
                    "tool": "internal_service_probe",
                    "command": "internal_service_probe 10.0.0.5",
                    "mode": "check_only",
                },
                {
                    "action": "verify_redis_replication",
                    "tool": "msf_check",
                    "target": "10.0.0.5:6379",
                },
            ],
        }
    }

    raw_steps = pipeline._extract_plan_steps(plan_res)
    normalized = pipeline._normalize_plan(raw_steps, "internal_reconnaissance")

    assert [step["task"] for step in normalized] == [
        "internal_service_discovery",
        "metasploit_verification",
    ]
    assert all(step["agent"] == "VerificationAgent" for step in normalized)


def test_planner_abstract_action_names_are_mapped_to_capabilities():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_planner_action_aliases.db")
    raw_steps = pipeline._extract_plan_steps({
        "steps": [
            {"name": "prioritize_high_value_targets"},
            {"name": "execute_vulnerability_checks"},
            {"name": "validate_findings"},
            {"name": "map_attack_paths"},
        ],
    })
    normalized = pipeline._normalize_plan(raw_steps, "vulnerability_assessment")

    assert [step["task"] for step in normalized] == [
        "analyze_vulnerabilities",
        "vulnerability_assessment",
        "metasploit_verification",
        "exploit_selection",
    ]
    assert normalized[0]["agent"] == "AnalysisAgent"


def test_planner_accepts_json_array_as_plan(monkeypatch):
    import core.ai.planner as planner_mod
    from core.ai.planner import MissionPlanner

    monkeypatch.setattr(
        planner_mod,
        "ask_ollama",
        lambda *_args, **_kwargs: '[{"agent": "DiscoveryAgent", "task": "service_discovery"}]',
    )

    result = MissionPlanner().create_plan("service_discovery", {"state": "initial_recon"}, [])

    assert result["llm_status"] == "ok"
    assert result["plan"] == [{"agent": "DiscoveryAgent", "task": "service_discovery"}]


def test_vulnerability_plan_enriches_safe_categories_from_surface_state():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_plan_surface_enrichment.db")
    available = {
        "asm_discovery",
        "web_application_mapping",
        "web_app_deep_testing",
        "template_verification",
        "api_security_testing",
        "active_directory_enumeration",
        "ad_security_review",
    }
    pipeline.tool_registry.task_has_available_tools = lambda task: task in available
    context = {
        "host": "app.example.com",
        "state": "recon_completed",
        "services": ["http", "https", "ldap"],
        "open_questions": ["web_vulnerabilities_unknown", "active_directory_exposure_unknown"],
        "automation_policy": {},
        "surface_states": {"asm": "unknown", "api": "unknown", "web": "confirmed_present"},
        "target_model": {
            "surface_states": {"asm": "unknown", "api": "unknown", "web": "confirmed_present"},
            "assets": {"domains": ["app.example.com"], "urls": ["https://app.example.com"]},
        },
    }

    optimized = pipeline._optimize_plan(
        [{"agent": "DiscoveryAgent", "task": "vulnerability_assessment"}],
        "vulnerability_assessment",
        context,
    )
    tasks = [step["task"] for step in optimized]

    assert "asm_discovery" in tasks
    assert "web_app_deep_testing" in tasks
    assert "template_verification" in tasks
    assert "api_security_testing" in tasks
    assert "ad_security_review" in tasks


def test_llm_context_compaction_keeps_state_but_drops_raw_fact_noise():
    from core.ai.llm_context import compact_context_for_llm

    raw_fact = "x" * 5000
    context = {
        "host": "10.0.0.5",
        "state": "root_access_confirmed",
        "services": ["ssh", "http"],
        "open_questions": ["internal_network_recon_pending"],
        "stage_gates": {"root": True, "internal_recon": False},
        "target_model": {
            "access": {"root_confirmed": True},
            "services": [{"port": 22, "service": "ssh"}],
            "endpoints": [{"url": "http://10.0.0.5/"}],
            "typed_facts": {"raw_noise": [raw_fact], "port_open": ["22/tcp (ssh)"]},
        },
        "network_graph": {"nodes": [{"id": i} for i in range(40)], "edges": []},
    }

    compact = compact_context_for_llm(context, role="director")

    assert compact["state"] == "root_access_confirmed"
    assert compact["target_model"]["access"]["root_confirmed"] is True
    assert compact["target_model"]["typed_fact_counts"] == {"raw_noise": 1, "port_open": 1}
    assert raw_fact not in str(compact)
    assert compact["network_graph"]["nodes_count"] == 40
    assert len(compact["network_graph"]["sample_nodes"]) < 10


def test_director_uses_compact_llm_context(monkeypatch):
    import core.ai.director as director_mod

    captured = {}
    raw_fact = "x" * 6000

    def fake_ask(prompt, json_mode=False):
        captured["prompt"] = prompt
        captured["json_mode"] = json_mode
        return '{"thought":"done","goal":"conclude"}'

    monkeypatch.setattr(director_mod, "ask_ollama", fake_ask)
    result = director_mod.DirectorLLM().decide_goal(
        {
            "host": "10.0.0.5",
            "state": "root_access_confirmed",
            "services": ["ssh"],
            "open_questions": [],
            "target_model": {"typed_facts": {"raw_noise": [raw_fact]}},
        },
        [],
    )

    assert result["goal"] == "conclude"
    assert captured["json_mode"] is True
    assert raw_fact not in captured["prompt"]
    assert "typed_fact_counts" in captured["prompt"]


def test_ollama_json_mode_disables_thinking_and_uses_structured_json(monkeypatch):
    import json as jsonlib

    import core.ai.ollama_client as ollama

    assert ollama._config_bool("false", True) is False
    assert ollama._config_bool("true", False) is True

    calls = []

    class FakeResponse:
        status_code = 200
        text = ""

        def iter_lines(self):
            yield jsonlib.dumps({"response": '{"goal":"conclude"}'}).encode()

        def raise_for_status(self):
            return None

    def fake_post(_url, json=None, stream=None, timeout=None):
        calls.append(json)
        return FakeResponse()

    monkeypatch.setattr(ollama.requests, "post", fake_post)
    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", 1)
    monkeypatch.setattr(ollama, "JSON_FORMAT", True)
    monkeypatch.setattr(ollama, "JSON_THINK", False)

    result = ollama.ask_ollama("Return JSON", json_mode=True)

    assert result == '{"goal":"conclude"}'
    assert calls[0]["think"] is False
    assert calls[0]["format"] == "json"
    assert calls[0]["options"]["temperature"] == 0
    assert calls[0]["prompt"].startswith("Machine JSON mode.")


def test_ollama_optional_shared_endpoint_key_is_sent_as_bearer(monkeypatch):
    import json as jsonlib

    import core.ai.ollama_client as ollama

    observed = {}

    class FakeResponse:
        status_code = 200
        text = ""

        def iter_lines(self):
            yield jsonlib.dumps({"response": "ready"}).encode()

        def raise_for_status(self):
            return None

    def fake_post(_url, **kwargs):
        observed.update(kwargs)
        return FakeResponse()

    monkeypatch.setenv("LLM_API_KEY", "private-ollama-key-93824")
    monkeypatch.setattr(ollama.requests, "post", fake_post)
    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", 1)

    assert ollama.ask_ollama("ready") == "ready"
    assert observed["headers"] == {
        "Authorization": "Bearer private-ollama-key-93824"
    }


def test_ollama_json_mode_retries_relaxed_when_strict_controls_are_unsupported(monkeypatch):
    import json as jsonlib

    import core.ai.ollama_client as ollama

    calls = []

    class BadResponse:
        status_code = 400
        text = "unknown field think"

        def raise_for_status(self):
            raise AssertionError("strict response should be retried before raise_for_status")

    class GoodResponse:
        status_code = 200
        text = ""

        def iter_lines(self):
            yield jsonlib.dumps({"response": '{"plan":[]}'}).encode()

        def raise_for_status(self):
            return None

    def fake_post(_url, json=None, stream=None, timeout=None):
        calls.append(json)
        return BadResponse() if len(calls) == 1 else GoodResponse()

    monkeypatch.setattr(ollama.requests, "post", fake_post)
    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", 1)
    monkeypatch.setattr(ollama, "JSON_FORMAT", True)
    monkeypatch.setattr(ollama, "JSON_THINK", False)

    result = ollama.ask_ollama("Return JSON", json_mode=True)

    assert result == '{"plan":[]}'
    assert calls[0]["format"] == "json"
    assert calls[0]["think"] is False
    assert "format" not in calls[1]
    assert "think" not in calls[1]


def test_bound_ollama_deadline_limits_request_and_suppresses_retry(monkeypatch):
    import core.ai.ollama_client as ollama
    from core.execution import CancellationContext

    calls = []
    cancellation = CancellationContext.with_timeout(10.0)

    def fake_post(_url, json=None, stream=None, timeout=None):
        calls.append(timeout)
        cancellation.cancel("deadline_exceeded")
        raise ollama.requests.exceptions.Timeout("bounded fixture")

    monkeypatch.setattr(ollama.requests, "post", fake_post)
    monkeypatch.setattr(ollama, "OLLAMA_TIMEOUT", 180)
    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", 2)
    monkeypatch.setattr(
        ollama.time,
        "sleep",
        lambda _seconds: pytest.fail("bound retries must not sleep past cancellation"),
    )

    with ollama.bind_ollama_cancellation(cancellation):
        result = ollama.ask_ollama("Return JSON", json_mode=True)

    assert result == "[!] Ollama request cancelled: deadline_exceeded."
    assert len(calls) == 1
    assert 0 < calls[0] <= 10.0


@pytest.mark.parametrize(
    "failure_kind",
    ("timeout", "connection", "unexpected"),
)
def test_bound_ollama_final_exception_preserves_cancellation(
    monkeypatch,
    failure_kind,
):
    import core.ai.ollama_client as ollama
    from core.execution import CancellationContext

    cancellation = CancellationContext.with_timeout(10.0)

    def fake_post(_url, json=None, stream=None, timeout=None):
        cancellation.cancel("deadline_exceeded")
        if failure_kind == "timeout":
            raise ollama.requests.exceptions.Timeout("closed at deadline")
        if failure_kind == "connection":
            raise ollama.requests.exceptions.ConnectionError("closed at deadline")
        raise RuntimeError("closed at deadline")

    monkeypatch.setattr(ollama.requests, "post", fake_post)
    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", 1)

    with ollama.bind_ollama_cancellation(cancellation):
        result = ollama.ask_ollama("Return JSON", json_mode=True)

    assert result == "[!] Ollama request cancelled: deadline_exceeded."


def test_unbound_ollama_keeps_configured_timeout(monkeypatch):
    import json as jsonlib

    import core.ai.ollama_client as ollama

    observed = {}

    class FakeResponse:
        status_code = 200
        text = ""

        @staticmethod
        def iter_lines():
            yield jsonlib.dumps({"response": '{"goal":"conclude"}'}).encode()

        @staticmethod
        def raise_for_status():
            return None

    def fake_post(_url, json=None, stream=None, timeout=None):
        observed["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(ollama.requests, "post", fake_post)
    monkeypatch.setattr(ollama, "OLLAMA_TIMEOUT", 37)
    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", 1)

    result = ollama.ask_ollama("Return JSON", json_mode=True)

    assert result == '{"goal":"conclude"}'
    assert observed["timeout"] == 37


def test_bound_ollama_stream_stops_when_scan_is_cancelled(monkeypatch):
    import json as jsonlib

    import core.ai.ollama_client as ollama
    from core.execution import CancellationContext

    cancellation = CancellationContext.with_timeout(10.0)
    observed = {"closed": False}

    class FakeResponse:
        status_code = 200

        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def iter_lines():
            yield jsonlib.dumps({"response": "first"}).encode()
            cancellation.cancel("deadline_exceeded")
            yield jsonlib.dumps({"response": "late"}).encode()

        @staticmethod
        def close():
            observed["closed"] = True

    def fake_post(_url, json=None, stream=None, timeout=None):
        observed["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(ollama.requests, "post", fake_post)
    monkeypatch.setattr(ollama, "OLLAMA_TIMEOUT", 180)

    with ollama.bind_ollama_cancellation(cancellation):
        chunks = list(ollama.ask_ollama_stream("stream"))

    assert chunks == ["first", "[!] Ollama request cancelled: deadline_exceeded."]
    assert observed["closed"] is True
    assert 0 < observed["timeout"] <= 10.0


def test_bound_ollama_stalled_stream_is_closed_on_early_cancellation(monkeypatch):
    import threading

    import core.ai.ollama_client as ollama
    from core.execution import CancellationContext

    cancellation = CancellationContext()
    stream_started = threading.Event()
    stream_released = threading.Event()
    response_closed = threading.Event()

    class FakeResponse:
        status_code = 200

        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def iter_lines():
            stream_started.set()
            if not stream_released.wait(2.0):
                raise AssertionError("cancellation did not release stalled stream")
            raise ollama.requests.exceptions.ConnectionError("response closed")
            yield b""  # pragma: no cover - keeps this a generator fixture

        @staticmethod
        def close():
            response_closed.set()
            stream_released.set()

    monkeypatch.setattr(
        ollama.requests,
        "post",
        lambda *_args, **_kwargs: FakeResponse(),
    )
    monkeypatch.setattr(ollama, "OLLAMA_TIMEOUT", 180)

    def cancel_stalled_stream():
        assert stream_started.wait(1.0)
        cancellation.cancel("operator_request")

    canceller = threading.Thread(target=cancel_stalled_stream)
    canceller.start()
    try:
        with ollama.bind_ollama_cancellation(cancellation):
            chunks = list(ollama.ask_ollama_stream("stream"))
    finally:
        stream_released.set()
        canceller.join(timeout=1.0)

    assert chunks == ["[!] Ollama request cancelled: operator_request."]
    assert response_closed.wait(1.0)
    assert not canceller.is_alive()
