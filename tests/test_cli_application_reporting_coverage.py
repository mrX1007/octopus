"""Hermetic coverage for CLI result adaptation, persistence, and edit menus."""

from __future__ import annotations

from unittest.mock import MagicMock, call

import pytest

from core.cli import application as app

pytestmark = [pytest.mark.unit, pytest.mark.contract]


@pytest.fixture(autouse=True)
def quiet_cli(monkeypatch: pytest.MonkeyPatch):
    for name in (
        "divider",
        "error",
        "export_menu",
        "info",
        "print_results_table",
        "print_history",
        "print_session",
        "success",
        "warn",
    ):
        monkeypatch.setattr(app, name, MagicMock())


class Redactor:
    def __init__(self):
        self.values = []

    def redact_data(self, value):
        self.values.append(value)
        return value


class FactStoreFixture:
    def __init__(self, facts, *, command_reader=True, redactor=True):
        self.facts = facts
        self.redactor = Redactor() if redactor else None
        self.get_command_results = (
            (lambda _scan_id, _target: [{"status": "succeeded"}])
            if command_reader
            else None
        )

    def get_facts(self, _scan_id, _target):
        return self.facts

    def get_hypotheses(self, _scan_id, _target):
        return [{"claim": "fixture"}]


def patch_reporting(monkeypatch: pytest.MonkeyPatch):
    import core.ai.reporting

    enrich = MagicMock(side_effect=lambda result, *_args, **_kwargs: result)
    monkeypatch.setattr(core.ai.reporting, "enrich_result_with_reporting", enrich)
    return enrich


def fact(ftype: str, value: str, **overrides):
    payload = {
        "id": overrides.pop("id", 1),
        "type": ftype,
        "value": value,
        "confidence": overrides.pop("confidence", 90),
        "source": overrides.pop("source", "fixture"),
    }
    payload.update(overrides)
    return payload


def test_adapt_state_projects_every_fact_class_and_risk_level(monkeypatch):
    enrich = patch_reporting(monkeypatch)
    rich_facts = [
        fact("exploit_success", "generic exploit", confidence=95, source="runner"),
        fact("potential_vulnerability", "candidate-one"),
        fact("exploit_attempted", "attempt-success", confidence=90),
        fact("exploit_attempted", "attempt-low", confidence=10),
        fact("credential", "user:password (cached)"),
        fact("check_result", "internal"),
    ]
    rich_store = FactStoreFixture(rich_facts)
    result = app._adapt_state_to_result(
        {"root_access_confirmed": True, "credentials_found": True},
        rich_store,
        "scan",
        "host",
        "raw",
    )
    assert result["risk_level"] == "CRITICAL"
    assert len(result["exploits"]) == 3
    assert not any(item["vuln_name"] == "candidate-one" for item in result["vulnerabilities"])
    assert any("potential_vulnerability: 1 candidates" in item for item in result["confirmed_facts"])
    assert any("internal_noise" in item for item in result["confirmed_facts"])
    assert enrich.call_args.kwargs["command_results"] == [{"status": "succeeded"}]

    high_store = FactStoreFixture([fact("vulnerability", "generic confirmed")])
    assert app._adapt_state_to_result({}, high_store, "scan", "host", "raw")["risk_level"] == (
        "HIGH"
    )

    medium_store = FactStoreFixture(
        [fact("potential_vulnerability", "candidate")],
        command_reader=False,
        redactor=False,
    )
    fallback_redactor = Redactor()
    import core.secrets

    monkeypatch.setattr(core.secrets, "get_redactor", lambda: fallback_redactor)
    medium = app._adapt_state_to_result(
        {"credentials_found": True},
        medium_store,
        "scan",
        "host",
        "raw",
    )
    assert medium["risk_level"] == "MEDIUM"
    assert medium["vulnerabilities"][0]["confidence"] == "POSSIBLE"
    assert fallback_redactor.values

    low_store = FactStoreFixture([])
    original_summary = app._build_outcome_summary
    monkeypatch.setattr(app, "_build_outcome_summary", lambda _facts, _state: [])
    low = app._adapt_state_to_result({}, low_store, "scan", "host", "raw")
    assert low["risk_level"] == "LOW"
    assert "OUTCOME SUMMARY" not in low["summary"]
    monkeypatch.setattr(app, "_build_outcome_summary", original_summary)


def test_adapt_state_bounds_confirmed_facts_and_potential_examples(monkeypatch):
    patch_reporting(monkeypatch)
    facts = [
        fact("vulnerability", "confirmed"),
        *(fact("potential_vulnerability", f"candidate-{index}", id=10 + index) for index in range(10)),
        *(fact("port_open", f"{index}/tcp (http)", id=100 + index) for index in range(70)),
    ]
    result = app._adapt_state_to_result({}, FactStoreFixture(facts), "scan", "host", "raw")
    assert len(result["confirmed_facts"]) == 62
    assert any("+2 more" in item for item in result["confirmed_facts"])
    assert any("internal_noise" in item for item in result["confirmed_facts"])


def test_secret_fact_state_and_unique_value_helpers():
    masked = app._mask_secret_value(
        "whm_session:abcdefgh user:supersecret (cached) ssh_credential:bob@example"
    )
    assert "abcd***" in masked
    assert "user:su*** (cached)" in masked
    assert app._mask_secret_value(None) == ""

    assert app._should_display_confirmed_fact({"type": "check_result", "value": "x"}) is False
    assert app._should_display_confirmed_fact(
        {"type": "service_status", "value": "ssh_authenticated:user"}
    ) is True
    assert app._should_display_confirmed_fact(
        {"type": "service_status", "value": "routine"}
    ) is False
    assert app._should_display_confirmed_fact(
        {"type": "nuclei_finding", "value": "INFO: banner"}
    ) is False
    assert app._should_display_confirmed_fact(
        {"type": "nuclei_finding", "value": "HIGH: issue"}
    ) is True
    assert app._should_display_confirmed_fact({"type": "unknown", "value": "x"}) is False
    assert app._format_confirmed_fact({"type": "credential", "value": "user:secret (cached)"})

    assert app._state_summary({}) == "state unavailable"
    summary = app._state_summary({"recon_completed": 1, "open_ports": [80, 443]})
    assert "recon_completed=True" in summary
    assert "open_ports=2" in summary
    assert "open_ports" not in app._state_summary({"open_ports": []})

    facts = [
        {"type": "other", "value": "skip"},
        {"type": "wanted", "value": ""},
        {"type": "wanted", "value": "one"},
        {"type": "wanted", "value": "one"},
        {"type": "wanted", "value": "two"},
        {"type": "wanted", "value": "three"},
    ]
    assert app._unique_fact_values(facts, {"wanted"}, limit=2) == ["one", "two"]


def test_outcome_summary_covers_present_absent_duplicate_and_bounded_sections():
    assert app._build_outcome_summary([], {}) == [
        "Stage gates: recon=no, credentials=no, root=no, post-access=no, "
        "persistence=no, internal recon=no, exfiltration=no, cleanup=no"
    ]
    facts = [
        fact("credential", "user:secret (cached)"),
        fact("application_access", "admin authenticated"),
        fact("system_access", "root access"),
        fact("post_exploit_stage", "inventory complete"),
        fact("other", "ignored"),
        fact("service_status", "routine"),
        *(fact("service_status", f"tool_timeout:{index}") for index in range(9)),
        fact("service_status", "tool_timeout:0"),
        fact("port_open", "443/tcp (https)"),
        fact("web_title", "Admin"),
        fact("internal_host", "10.0.0.2"),
        fact("stage_status", "exploit blocked by policy"),
        fact("stage_status", "exploit blocked by policy"),
    ]
    lines = app._build_outcome_summary(
        facts,
        {
            "recon_completed": True,
            "credentials_found": True,
            "root_access_confirmed": True,
            "post_access_inventory_completed": True,
            "persistence_established": True,
            "internal_recon_completed": True,
            "exfiltration_completed": True,
            "cleanup_completed": True,
        },
    )
    joined = "\n".join(lines)
    for expected in (
        "Credentials/access material",
        "Access/status",
        "Tool/status signals",
        "Open services",
        "Web surface",
        "Internal/post-access findings",
        "Blocked stages",
    ):
        assert expected in joined
    assert joined.count("tool_timeout:0") == 1
    duplicate_lines = app._build_outcome_summary(
        [
            fact("service_status", "tool_timeout:same"),
            fact("service_status", "tool_timeout:same"),
        ],
        {},
    )
    assert "tool_timeout:same" in "\n".join(duplicate_lines)


@pytest.mark.parametrize(
    ("item", "related", "expected"),
    (
        ({"source": "cpanel_sniper"}, [], True),
        ({"source": "cpanel_exploit"}, [], True),
        ({"value": "CVE-2026-41940"}, [], True),
        ({"value": "cPanel/WHM issue"}, [], True),
        ({}, [{"value": "cpanel_auth_bypass_session"}], True),
        ({}, [{"value": "whm_session:token"}], True),
        ({}, [{"type": "service_version", "value": "cpanel"}], True),
        ({"source": "other", "value": "other"}, [], False),
    ),
)
def test_cpanel_evidence_short_circuit_terms(item, related, expected):
    assert app._is_cpanel_evidence(item, related) is expected


@pytest.mark.parametrize(
    ("item", "related", "expected"),
    (
        ({"value": "PwnKit"}, [], True),
        ({"value": "CVE-2021-4034"}, [], True),
        ({"value": "other"}, [{"type": "privesc_vector", "value": "suid_pkexec"}], True),
        ({"value": "other"}, [], False),
    ),
)
def test_pwnkit_evidence_short_circuit_terms(item, related, expected):
    assert app._is_pwnkit_evidence(item, related) is expected


def test_service_endpoint_and_vulnerability_metadata_boundaries(monkeypatch):
    facts = [
        fact("other", "49153/tcp (redis)"),
        fact("port_open", "not a service line"),
        fact("port_open", "49153/tcp (redis) [Redis]"),
    ]
    assert app._service_for_port(facts, "") == "unknown"
    assert app._service_for_port(facts, "49153") == "redis"
    assert app._service_for_port(facts, "80") == "unknown"

    unrelated = fact("vulnerability", "ordinary")
    assert app._endpoint_metadata_for_vulnerability(unrelated, facts) == {}
    msf = fact("vulnerability", "msf_check_positive:exploit/linux/redis/test")
    msf_facts = [
        msf,
        fact("other", "msf_check_positive:exploit/linux/redis/test:1"),
        fact("vulnerability_endpoint", "different:1"),
        fact("vulnerability_endpoint", "msf_check_positive:exploit/linux/redis/test:49153"),
        *facts,
    ]
    endpoint = app._endpoint_metadata_for_vulnerability(msf, msf_facts)
    assert endpoint["port"] == "49153"
    assert endpoint["service"] == "redis"
    assert app._endpoint_metadata_for_vulnerability(msf, [fact("other", "none")]) == {}

    tomcat = fact("vulnerability", "tomcat_jmx_proxy_exposed")
    tomcat_facts = [
        fact("other", "tomcat_jmx_proxy_exposed:http://ignored"),
        fact("vulnerability_endpoint", "other"),
        fact("vulnerability_endpoint", "tomcat_jmx_proxy_exposed:https://host:8443/jmxproxy"),
        fact("port_open", "8443/tcp (https)"),
    ]
    assert app._endpoint_metadata_for_vulnerability(tomcat, tomcat_facts)["port"] == "8443"
    default_http = app._endpoint_metadata_for_vulnerability(
        tomcat,
        [fact("vulnerability_endpoint", "tomcat_jmx_proxy_exposed:http://host/path")],
    )
    assert default_http["port"] == "80"
    default_https = app._endpoint_metadata_for_vulnerability(
        tomcat,
        [fact("vulnerability_endpoint", "tomcat_jmx_proxy_exposed:https://host/path")],
    )
    assert default_https["port"] == "443"
    assert app._endpoint_metadata_for_vulnerability(tomcat, []) == {}

    cpanel = app._vulnerability_metadata(fact("vulnerability", "cPanel/WHM"), [], {})
    assert cpanel["service"] == "cPanel/WHM"
    pwnkit = app._vulnerability_metadata(fact("vulnerability", "PwnKit"), [], {})
    assert pwnkit["port"] == "local"
    assert app._vulnerability_metadata(msf, msf_facts, {})["confidence"] == "VERIFIED"
    assert app._vulnerability_metadata(unrelated, [], {})["service"] == "unknown"

    monkeypatch.setattr(
        app,
        "_endpoint_metadata_for_vulnerability",
        lambda *_args: {"port": "7"},
    )
    defaults = app._vulnerability_metadata(unrelated, [], {})
    assert defaults["service"] == "unknown"
    assert defaults["description"] == "Confirmed vulnerability"


def test_exploit_success_metadata_provider_and_fallback_variants():
    cpanel_with_source = app._exploit_success_metadata(
        fact("exploit_success", "cPanel/WHM", source="custom"),
        [],
        {},
    )
    assert cpanel_with_source["evidence_tool"] == "custom"
    cpanel_default = app._exploit_success_metadata(
        fact("exploit_success", "cPanel/WHM", source=""),
        [],
        {},
    )
    assert cpanel_default["evidence_tool"] == "cpanel_sniper"

    pwnkit_high = app._exploit_success_metadata(
        fact("exploit_success", "PwnKit", source=""),
        [],
        {},
    )
    assert pwnkit_high["severity"] == "HIGH"
    assert pwnkit_high["evidence_tool"] == "killchain_privesc"
    assert app._exploit_success_metadata(
        fact("exploit_success", "PwnKit", source="tool"),
        [],
        {"root_access_confirmed": True},
    )["severity"] == "CRITICAL"

    default_high = app._exploit_success_metadata(
        fact("exploit_success", "generic", source=""),
        [],
        {},
    )
    assert default_high["tool_used"] == "auto_exploit"
    default_critical = app._exploit_success_metadata(
        fact("exploit_success", "generic", source="runner"),
        [],
        {"root_access_confirmed": True},
    )
    assert default_critical["severity"] == "CRITICAL"
    assert default_critical["tool_used"] == "runner"


def test_save_and_show_results_persists_fixes_exploits_and_optional_actions(monkeypatch):
    save_vulnerability = MagicMock(side_effect=(101, 102, 103))
    save_fix = MagicMock()
    save_exploit = MagicMock()
    save_summary = MagicMock()
    edit = MagicMock()
    export = MagicMock()
    monkeypatch.setattr(app, "save_vulnerability", save_vulnerability)
    monkeypatch.setattr(app, "save_fix", save_fix)
    monkeypatch.setattr(app, "save_exploit", save_exploit)
    monkeypatch.setattr(app, "save_summary", save_summary)
    monkeypatch.setattr(app, "get_session", lambda _sl: {"history": (7,)})
    monkeypatch.setattr(app, "edit_delete_menu", edit)
    monkeypatch.setattr(app, "export_menu", export)
    monkeypatch.setattr(app, "_auto_export_session", lambda _data: False)
    monkeypatch.setattr(app, "confirm", MagicMock(side_effect=(True, True)))
    result = {
        "vulnerabilities": [
            {
                "vuln_name": "direct",
                "severity": "HIGH",
                "port": "1",
                "service": "svc",
                "description": "desc",
                "confidence": "CONFIRMED",
                "evidence_tool": "tool",
                "evidence_snippet": "proof",
                "fix": "direct fix",
            },
            {
                "vuln_name": "matching finding",
                "severity": "HIGH",
                "port": "2",
                "service": "svc2",
                "description": "desc",
            },
            {
                "vuln_name": "no remediation",
                "severity": "LOW",
                "port": "3",
                "service": "svc3",
                "description": "desc",
            },
        ],
        "remediations": [
            {"finding": "matching finding", "recommendation": "deterministic fix"},
        ],
        "exploits": [
            {
                "exploit_name": "exploit",
                "tool_used": "tool",
                "payload": "payload",
                "result": "Success",
                "notes": "notes",
            }
        ],
        "raw_scan": "raw",
        "full_response": "response",
        "risk_level": "HIGH",
    }
    app._save_and_show_results(7, result, "00:00:01")
    assert save_fix.call_args_list == [
        call(7, 101, "direct fix", source="ai"),
        call(7, 102, "deterministic fix", source="deterministic"),
    ]
    save_exploit.assert_called_once()
    save_summary.assert_called_once_with(7, "raw", "response", "HIGH")
    export.assert_called_once_with({"history": (7,)})
    edit.assert_called_once_with(7)

    save_summary.side_effect = RuntimeError("duplicate")
    monkeypatch.setattr(app, "_auto_export_session", lambda _data: True)
    monkeypatch.setattr(app, "confirm", MagicMock(return_value=False))
    empty = {
        "vulnerabilities": [],
        "exploits": [],
        "raw_scan": "raw",
        "full_response": "response",
        "risk_level": "LOW",
    }
    app._save_and_show_results(8, empty)
    app.warn.assert_called_with("Summary save skipped (may already exist): duplicate")

    save_summary.side_effect = None
    monkeypatch.setattr(app, "_auto_export_session", lambda _data: False)
    monkeypatch.setattr(app, "confirm", MagicMock(side_effect=(False, False)))
    app._save_and_show_results(9, empty)


def test_remediation_matching_and_fallback_paths():
    vulnerability = {"vuln_name": "redis issue", "service": "redis"}
    assert app._remediation_for_vulnerability(
        vulnerability,
        [
            {"finding": "ignored", "recommendation": ""},
            {"finding": "redis", "recommendation": "by finding"},
        ],
    ) == "by finding"
    assert app._remediation_for_vulnerability(
        vulnerability,
        [{"finding": "prefix redis issue suffix", "recommendation": "reverse finding"}],
    ) == "reverse finding"
    for service in ("redis", "redis service", "red"):
        assert app._remediation_for_vulnerability(
            vulnerability,
            [{"service": service, "recommendation": "by service"}],
        ) == "by service"
    assert app._remediation_for_vulnerability(
        vulnerability,
        [{"finding": "other", "service": "http", "recommendation": "no"}],
    ) == ""


def test_view_history_empty_invalid_missing_and_optional_actions(monkeypatch):
    monkeypatch.setattr(app, "get_all_history", list)
    app.view_history()
    app.warn.assert_called_with("No scans in database yet.")

    monkeypatch.setattr(app, "get_all_history", lambda: [(7, "host")])
    for answer in ("", "bad"):
        monkeypatch.setattr(app, "prompt", lambda _text, answer=answer: answer)
        app.view_history()
    app.error.assert_called_with("Invalid SL#.")

    monkeypatch.setattr(app, "prompt", lambda _text: "7")
    monkeypatch.setattr(app, "get_session", lambda _sl: {"history": None})
    app.view_history()
    app.error.assert_called_with("SL# 7 not found.")

    data = {"history": (7, "host")}
    monkeypatch.setattr(app, "get_session", lambda _sl: data)
    edit = MagicMock()
    monkeypatch.setattr(app, "edit_delete_menu", edit)
    monkeypatch.setattr(app, "confirm", MagicMock(side_effect=(True, True)))
    app.view_history()
    app.export_menu.assert_called_with(data)
    edit.assert_called_once_with(7)

    monkeypatch.setattr(app, "confirm", MagicMock(side_effect=(False, False)))
    app.view_history()


def test_edit_delete_menu_exercises_every_validation_and_operation(monkeypatch):
    vulnerability = (7, 1, "vuln", "HIGH", "443", "https")
    fix = (8, 1, 7, "fix text")
    exploit = (9, 1, "exploit", "tool", "payload", "Success")
    monkeypatch.setattr(
        app,
        "get_vulnerabilities",
        MagicMock(side_effect=([], [vulnerability], [vulnerability], [], [vulnerability], [vulnerability], [vulnerability])),
    )
    monkeypatch.setattr(
        app,
        "get_fixes",
        MagicMock(side_effect=([], [fix], [fix], [], [fix], [fix], [fix])),
    )
    monkeypatch.setattr(
        app,
        "get_exploits",
        MagicMock(side_effect=([], [exploit], [exploit], [], [exploit], [exploit], [exploit])),
    )
    prompts = iter(
        (
            "1",
            "1", "bad",
            "1", "7", "severity", "HIGH",
            "2",
            "2", "bad",
            "2", "8", "new fix",
            "3",
            "3", "bad",
            "3", "9", "result", "Success",
            "4", "invalid",
            "4", "high",
            "5",
            "5", "bad",
            "5", "7",
            "5", "7",
            "6",
            "6", "bad",
            "6", "8",
            "6", "8",
            "7",
            "7", "bad",
            "7", "9",
            "7", "9",
            "8",
            "invalid",
            "9",
        )
    )
    monkeypatch.setattr(app, "prompt", lambda _text: next(prompts))
    monkeypatch.setattr(
        app,
        "confirm",
        MagicMock(side_effect=(False, True, False, True, False, True, False)),
    )
    operations = {
        name: MagicMock()
        for name in (
            "delete_exploit",
            "delete_fix",
            "delete_full_session",
            "delete_vulnerability",
            "edit_exploit",
            "edit_fix",
            "edit_summary_risk",
            "edit_vulnerability",
        )
    }
    for name, operation in operations.items():
        monkeypatch.setattr(app, name, operation)
    app.edit_delete_menu(1)

    operations["edit_vulnerability"].assert_called_once_with(7, "severity", "HIGH")
    operations["edit_fix"].assert_called_once_with(8, "new fix")
    operations["edit_exploit"].assert_called_once_with(9, "result", "Success")
    operations["edit_summary_risk"].assert_called_once_with(1, "HIGH")
    operations["delete_vulnerability"].assert_called_once_with(7)
    operations["delete_fix"].assert_called_once_with(8)
    operations["delete_exploit"].assert_called_once_with(9)
    operations["delete_full_session"].assert_not_called()

    monkeypatch.setattr(app, "prompt", lambda _text: "8")
    monkeypatch.setattr(app, "confirm", lambda _text: True)
    app.edit_delete_menu(1)
    operations["delete_full_session"].assert_called_once_with(1)


def test_checkpoint_count_uses_configured_path(monkeypatch):
    monkeypatch.setattr(app, "CFG", {"paths": {"checkpoints": "/fixture"}})
    glob = MagicMock(return_value=["a", "b"])
    monkeypatch.setattr(app.glob, "glob", glob)
    assert app._check_pending_checkpoints() == 2
    glob.assert_called_once_with("/fixture/octopus_checkpoint_*.json")
