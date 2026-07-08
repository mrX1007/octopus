#!/usr/bin/env python3
"""Regression tests for legacy UI result adaptation."""


def _adapt_state_to_result():
    """Import octopus adapter without optional CLI/database dependencies."""
    import importlib
    import sys
    import types

    if "octopus" in sys.modules:
        return sys.modules["octopus"]._adapt_state_to_result

    export_stub = types.ModuleType("export")
    export_stub.export_menu = lambda *args, **kwargs: None
    sys.modules["export"] = export_stub

    db_stub = types.ModuleType("db")
    for name in (
        "get_connection", "create_session", "update_session_status",
        "save_vulnerability", "save_fix", "save_exploit", "save_summary",
        "get_all_history", "get_session", "get_vulnerabilities", "get_fixes",
        "get_exploits", "edit_vulnerability", "edit_fix", "edit_exploit",
        "edit_summary_risk", "delete_vulnerability", "delete_exploit",
        "delete_fix", "delete_full_session", "print_history", "print_session",
    ):
        setattr(db_stub, name, lambda *args, **kwargs: None)
    sys.modules["db"] = db_stub

    tools_stub = types.ModuleType("tools")
    tools_stub.interactive_tool_run = lambda *args, **kwargs: ""
    tools_stub.format_recon_for_llm = lambda data: str(data)
    tools_stub.run_default_recon = lambda target: {}
    sys.modules["tools"] = tools_stub

    return importlib.import_module("octopus")._adapt_state_to_result


class _FakeFactStore:
    def __init__(self, facts):
        self._facts = facts

    def get_facts(self, scan_id, host):
        return self._facts

    def get_hypotheses(self, scan_id, host):
        return []


def test_pwnkit_exploit_success_is_not_reported_as_cpanel():
    adapt_state_to_result = _adapt_state_to_result()

    facts = [
        {
            "id": 1,
            "type": "exploit_success",
            "value": "CVE-2021-4034 PwnKit root access",
            "confidence": 100,
            "source": "manual_run",
            "session_id": "33",
        },
        {
            "id": 2,
            "type": "vulnerability",
            "value": "CVE-2021-4034",
            "confidence": 100,
            "source": "manual_run",
            "session_id": "33",
        },
        {
            "id": 3,
            "type": "privesc_vector",
            "value": "suid_pkexec",
            "confidence": 100,
            "source": "manual_run",
            "session_id": "33",
        },
        {
            "id": 4,
            "type": "system_access",
            "value": "root_access_confirmed",
            "confidence": 100,
            "source": "manual_run",
            "session_id": "33",
        },
    ]

    result = adapt_state_to_result(
        {"root_access_confirmed": True},
        _FakeFactStore(facts),
        "33",
        "83.166.241.164",
        "",
    )

    vuln_services = {v["service"] for v in result["vulnerabilities"]}
    exploit_tools = {e["tool_used"] for e in result["exploits"]}

    assert "cPanel/WHM" not in vuln_services
    assert "cpanel_sniper" not in exploit_tools
    assert "Linux local privilege escalation" in vuln_services
    assert "pwnkit" in exploit_tools


def test_cpanel_exploit_success_keeps_cpanel_metadata():
    adapt_state_to_result = _adapt_state_to_result()

    facts = [
        {
            "id": 1,
            "type": "exploit_success",
            "value": "CVE-2026-41940 -- cPanel/WHM auth bypass",
            "confidence": 100,
            "source": "cpanel_sniper",
            "session_id": "44",
        },
        {
            "id": 2,
            "type": "credential",
            "value": "whm_session:cpsess123",
            "confidence": 100,
            "source": "cpanel_sniper",
            "session_id": "44",
        },
    ]

    result = adapt_state_to_result(
        {"root_access_confirmed": False},
        _FakeFactStore(facts),
        "44",
        "203.0.113.10",
        "",
    )

    assert result["vulnerabilities"][0]["service"] == "cPanel/WHM"
    assert result["vulnerabilities"][0]["port"] == "2087"
    assert result["exploits"][0]["tool_used"] == "cpanel_sniper"
