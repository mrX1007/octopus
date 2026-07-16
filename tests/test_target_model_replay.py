#!/usr/bin/env python3
"""Replay, target-model, and graph read-model contracts."""

import pytest

pytestmark = pytest.mark.replay

def test_replay_outputs_builds_target_model_and_snapshot_actions():
    import uuid

    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_replay_target_model_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-replay"
    target = "10.0.0.5"

    result = pipeline.replay_outputs(scan_id, target, [
        {
            "tool": "nmap",
            "output": """
Nmap scan report for 10.0.0.5
PORT      STATE SERVICE VERSION
43117/tcp open  ssl/http Golang net/http server
49153/tcp open  redis    Redis key-value store 6.2
""",
        },
        {
            "tool": "scrapling https://10.0.0.5:43117/",
            "output": """
URL: https://10.0.0.5:43117/
Status: 200
Title: Admin
Forms: 1
Links:
  /login
""",
        },
    ])

    model = result["context"]["target_model"]
    actions = [item["command"] for item in result["snapshot_actions"]]

    assert result["parsed_facts"] > 0
    assert any(service["port"] == 43117 and "http" in service["service"] for service in model["services"])
    assert any(endpoint["url"] == "https://10.0.0.5:43117/" for endpoint in model["endpoints"])
    assert model["unknowns"]["web_surface"] == "confirmed_present"
    assert any(command.startswith("scrapling https://10.0.0.5:43117/login") for command in actions)
    assert any(command.startswith("exploit_select 10.0.0.5") for command in actions)


def test_real_app_replay_ssh_only_log_builds_state_without_web_or_msf_noise():
    import pathlib
    import uuid

    from core.ai.pipeline import AIPipeline

    fixture = pathlib.Path(__file__).parent / "fixtures" / "replay_ssh_only_real_app.log"
    raw_log = fixture.read_text()
    db_path = f"/tmp/octopus_real_replay_ssh_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-real-ssh"
    target = "83.166.241.164"

    result = pipeline.replay_outputs(scan_id, target, [{"tool": "manual_recon", "output": raw_log}])
    facts = pipeline.fact_store.get_facts(scan_id, target)
    pairs = {(fact["type"], fact["value"]) for fact in facts}
    context = result["context"]
    model = context["target_model"]

    assert ("port_open", "22/tcp (ssh) [OpenSSH 7.4 (protocol 2.0)]") in pairs
    credential_values = [value for fact_type, value in pairs if fact_type == "credential"]
    assert any(value.startswith("support:secret://") and value.endswith(" (cached)") for value in credential_values)
    assert "fixture-password-123" not in repr(credential_values)
    assert ("service_status", "ssh_user_enum_unreliable_or_patched") in pairs
    assert ("service_status", "msf_check_invalid_options:auxiliary/scanner/ssh/ssh_login") in pairs
    assert not any(ftype == "web_endpoint" for ftype, _value in pairs)
    assert not any(ftype == "module_name" for ftype, _value in pairs)
    assert context["state"] == "credentials_found"
    assert context["next_required_capability"] == "credential_harvesting"
    assert model["unknowns"]["web_surface"] == "unknown"
    assert any(service["service"] == "ssh" and service["port"] == 22 for service in model["services"])


def test_target_model_exposes_typed_check_results_and_endpoint_coverage():
    import json
    import uuid

    from core.ai.fact_store import FactStore
    from core.ai.target_model import TargetModel

    store = FactStore(f"/tmp/octopus_typed_coverage_{uuid.uuid4().hex}.db")
    scan_id = "scan-typed"
    target = "10.0.0.5"
    endpoint = json.dumps({
        "url": "http://10.0.0.5/",
        "scheme": "http",
        "host": "10.0.0.5",
        "port": "80",
        "path": "/",
    }, sort_keys=True)
    check = json.dumps({
        "tool": "nuclei_safe",
        "command_key": "nuclei_safe:http://10.0.0.5",
        "command": "nuclei_safe http://10.0.0.5",
        "kind": "template_verification",
        "mode": "check_only",
        "scope": {"type": "endpoint", "value": "http://10.0.0.5"},
        "status": "timeout",
    }, sort_keys=True)
    store.add_fact(scan_id, target, "web_endpoint", endpoint, "derived:nmap")
    store.add_fact(scan_id, target, "check_result", check, "nuclei_safe http://10.0.0.5")

    model = TargetModel.from_facts(scan_id, target, store.get_facts(scan_id, target)).to_dict()
    endpoint_coverage = model["coverage"]["web_endpoints"][0]

    assert model["typed_facts"]["Endpoint"][0]["url"] == "http://10.0.0.5/"
    assert model["typed_facts"]["CheckResult"][0]["kind"] == "template_verification"
    assert endpoint_coverage["checks"]["template_verification"]["status"] == "timeout"
    assert any(
        gap["surface"] == "endpoint"
        and gap["check"] == "template_verification"
        and gap["status"] == "timeout"
        for gap in model["coverage"]["gaps"]
    )


def test_target_model_exposes_assets_api_and_security_findings():
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_target_model_asm_{uuid.uuid4().hex}.db")
    scan_id = "scan-asm"
    target = "example.com"
    for fact_type, value in (
        ("asset_domain", "app.example.com"),
        ("asset_ip", "203.0.113.10"),
        ("asset_url", "https://app.example.com"),
        ("technology", "nginx,React"),
        ("api_endpoint", "GET:/users:auth=unknown_or_none"),
        ("api_security_note", "auth_unknown_or_none:GET:/users"),
        ("nuclei_finding", "medium:exposed-panel:https://app.example.com/admin"),
        ("secret_finding", "generic-api-key:app/.env:unvalidated:rotation_required"),
        ("code_finding", "high:CVE-2024-0001:requirements.txt"),
        ("cloud_finding", "high:s3_bucket_public_access:bucket-1"),
        ("ad_domain", "CORP.LOCAL"),
        ("ad_attack_path", "domain_admin_paths:3"),
        ("ad_adcs_issue", "ESC1:vulnerable template"),
        ("ad_password_policy", "lockout_threshold:0"),
    ):
        pipeline.fact_store.add_fact(scan_id, target, fact_type, value, "test")

    model = pipeline.context_builder.build_context(scan_id, target)["target_model"]

    assert "app.example.com" in model["assets"]["domains"]
    assert "203.0.113.10" in model["assets"]["ips"]
    assert model["api"]["endpoints"][0]["method"] == "GET"
    assert model["unknowns"]["api_surface"] == "confirmed_present"
    assert model["unknowns"]["secrets"] == "confirmed_present"
    assert model["security_findings"]["nuclei"]
    assert model["security_findings"]["secrets"]
    assert model["security_findings"]["secrets"][0]["secret_type"] == "generic-api-key"
    assert model["security_findings"]["secrets"][0]["rotation_required"] == "yes"
    assert model["security_findings"]["code"]
    assert model["security_findings"]["cloud"]
    assert model["security_findings"]["cloud"][0]["provider"] == "aws"
    assert model["active_directory"]["domains"][0]["value"] == "CORP.LOCAL"
    assert model["active_directory"]["attack_paths"][0]["value"] == "domain_admin_paths:3"
    assert model["active_directory"]["adcs_issues"][0]["value"] == "ESC1:vulnerable template"
    assert model["unknowns"]["active_directory"] == "confirmed_present"
    assert model["unknowns"]["cloud"] == "confirmed_present"
    assert model["unknowns"]["code_security"] == "confirmed_present"


def test_target_model_exposes_web_app_security_layer():
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_target_model_webapp_{uuid.uuid4().hex}.db")
    scan_id = "scan-webapp"
    target = "app.example.com"
    for fact_type, value in (
        ("web_security_note", "missing_hsts"),
        ("web_security_note", "cors_credentials_allowed"),
        ("js_route", "/api/users/{id}"),
        ("proxy_finding", "Medium Cookie No HttpOnly Flag"),
        ("jwt_metadata", "alg:none"),
    ):
        pipeline.fact_store.add_fact(scan_id, target, fact_type, value, "test")

    model = pipeline.context_builder.build_context(scan_id, target)["target_model"]

    assert model["unknowns"]["web_security_notes"] == "confirmed_present"
    assert any(item["value"] == "missing_hsts" for item in model["web_app"]["security_notes"])
    assert any(item["value"] == "/api/users/{id}" for item in model["web_app"]["js_routes"])
    assert any("Cookie No HttpOnly" in item["value"] for item in model["web_app"]["proxy_findings"])
    assert any(item["value"] == "alg:none" for item in model["web_app"]["jwt"])


def test_asset_graph_models_interface_subnet_endpoint_and_secret():
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_asset_graph_{uuid.uuid4().hex}.db")
    scan_id = "scan-graph"
    host = "10.0.0.5"
    for fact_type, value in (
        ("internal_subnet", "172.25.0.5/16"),
        ("internal_host", "172.25.0.23"),
        ("web_endpoint", "https://10.0.0.5:8443/admin"),
        ("secret_finding", "aws-access-key:app/.env:validated:rotation_required"),
    ):
        pipeline._store_fact(scan_id, host, {"type": fact_type, "value": value, "confidence": 90}, "test")

    graph = pipeline.context_builder.build_context(scan_id, host)["asset_graph"]
    kinds = {node["kind"] for node in graph["nodes"]}
    edge_types = {edge["type"] for edge in graph["edges"]}

    assert {"host", "interface", "subnet", "endpoint", "service", "secret"}.issubset(kinds)
    assert "has_interface" in edge_types
    assert "attached_to_subnet" in edge_types
    assert "member_of_subnet" in edge_types
    assert "exposes_endpoint" in edge_types


def test_surface_state_and_policy_filter_confirmed_absent_tasks():
    from core.ai.policy import DeterministicPolicy
    from core.ai.surface_state import SurfaceState

    facts = [{"type": "service_status", "value": "web_content_discovery_skipped:no_http_response:https://10.0.0.5/"}]
    states = SurfaceState(facts).to_dict()
    context = {
        "state": "recon_completed",
        "automation_policy": {},
        "target_model": {"surface_states": states},
    }
    plan = [
        {"agent": "DiscoveryAgent", "task": "web_application_mapping"},
        {"agent": "DiscoveryAgent", "task": "api_security_testing"},
    ]

    filtered = DeterministicPolicy().validate_plan(plan, context)

    assert states["web"] == "confirmed_absent"
    assert [step["task"] for step in filtered] == ["api_security_testing"]


def test_target_model_risk_analysis_correlates_ad_cloud_secret_and_code():
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_risk_analysis_{uuid.uuid4().hex}.db")
    scan_id = "scan-risk"
    target = "app.example.com"
    for fact_type, value in (
        ("web_endpoint", "https://app.example.com/"),
        ("ad_attack_path", "domain_admin_paths:2"),
        ("ad_adcs_issue", "ESC1:vulnerable template"),
        ("cloud_finding", "high:s3_bucket_public_access:bucket-1"),
        ("secret_finding", "aws-access-key:app/.env:validated:rotation_required"),
        ("code_finding", "critical:CVE-2025-0001:requirements.txt"),
    ):
        pipeline.fact_store.add_fact(scan_id, target, fact_type, value, "test")

    model = pipeline.context_builder.build_context(scan_id, target)["target_model"]
    risk = model["risk_analysis"]

    assert any(item["kind"] == "adcs" and item["severity"] == "critical" for item in risk["ad_attack_paths"])
    assert "aws" in risk["cloud_posture"]
    assert risk["secret_rotation"][0]["priority"] == "urgent"
    assert risk["code_reachability"][0]["exposed_surface_present"] is True


def test_replay_snapshot_asserts_facts_actions_and_surface_states():
    import uuid

    from core.ai.replay_snapshot import ReplaySnapshot

    snapshot = ReplaySnapshot(f"/tmp/octopus_replay_snapshot_{uuid.uuid4().hex}.db")
    result = snapshot.assert_ok({
        "scan_id": "scan-snapshot",
        "target": "10.0.0.5",
        "outputs": [
            {
                "tool": "nmap",
                "output": "80/tcp open http nginx",
            },
            {
                "tool": "scrapling http://10.0.0.5",
                "output": "URL: http://10.0.0.5/\nTitle: Home\nLinks:\n  /api/users\n",
            },
        ],
        "expected_facts": [
            ("port_open", "80/tcp (http) [nginx]"),
            ("web_title", "Home"),
        ],
        "expected_fact_prefixes": [
            ("web_endpoint", "{\"host\": \"10.0.0.5\""),
        ],
        "expected_actions": [
            "scrapling http://10.0.0.5/api/users",
            "exploit_select 10.0.0.5",
        ],
        "expected_surface_states": {
            "web": "confirmed_present",
        },
    })

    assert result["ok"]
    assert any(action.startswith("exploit_select 10.0.0.5") for action in result["actions"])


def test_replay_snapshot_fixture_file_web_api():
    import pathlib
    import uuid

    from core.ai.replay_snapshot import ReplaySnapshot

    fixture = pathlib.Path(__file__).parent / "fixtures" / "replay_snapshot_web_api.json"
    snapshot = ReplaySnapshot(f"/tmp/octopus_replay_snapshot_file_{uuid.uuid4().hex}.db")
    result = snapshot.assert_file_ok(str(fixture))

    assert result["surface_states"]["web"] == "confirmed_present"
    assert result["surface_states"]["api"] == "confirmed_present"
