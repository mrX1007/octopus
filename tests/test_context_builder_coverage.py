"""Focused branch coverage for context construction and gap inference."""

from __future__ import annotations

import builtins
import runpy
from types import SimpleNamespace

import pytest

from core.ai.context_builder import ContextBuilder
from core.ai.evaluated_facts import EvaluatedFactSnapshot

pytestmark = pytest.mark.unit


class _CapabilityResolver:
    @staticmethod
    def resolve(*_args, **_kwargs):
        return SimpleNamespace(to_dict=lambda: {"status": "available"})


def _builder():
    return ContextBuilder(
        SimpleNamespace(get_facts=lambda *_args: []),
        SimpleNamespace(resolve_state=lambda *_args: {}),
        capability_resolver=_CapabilityResolver(),
    )


def test_config_import_fallback_is_executable(monkeypatch):
    import core.ai.context_builder as module

    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "config":
            raise ImportError("config unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    namespace = runpy.run_path(module.__file__, run_name="context_builder_without_config")

    assert namespace["CFG"] == {}


def test_build_context_covers_cleanup_state_and_execution_factory():
    snapshot = EvaluatedFactSnapshot.build("scan", "host", [])
    execution = object()
    resolver = SimpleNamespace(
        resolve_snapshot=lambda _snapshot: {
            "cleanup_completed": True,
            "recon_completed": True,
            "open_ports": [],
        }
    )
    builder = ContextBuilder(
        SimpleNamespace(get_facts=lambda *_args: []),
        resolver,
        capability_resolver=_CapabilityResolver(),
        execution_context_factory=lambda _scan, _host: execution,
    )

    context = builder.build_context("scan", "host", evaluated_fact_snapshot=snapshot)

    assert context["state"] == "cleanup_completed"
    assert context["next_required_capability"] == "conclude"
    assert context["capability_assessment"] == {"status": "available"}


def test_snapshot_validation_rejects_wrong_scan_and_scope():
    builder = _builder()

    with pytest.raises(ValueError, match="different scan"):
        builder._validate_evaluated_fact_snapshot(
            EvaluatedFactSnapshot.build("other", "host", []),
            "scan",
            "host",
        )
    with pytest.raises(ValueError, match="requested host"):
        builder._validate_evaluated_fact_snapshot(
            EvaluatedFactSnapshot.build("scan", "other", []),
            "scan",
            "host",
        )


def test_port_text_and_network_graph_cover_invalid_and_duplicate_records():
    builder = _builder()

    assert builder._service_text_from_port_fact("custom banner") == "custom banner"
    graph = builder._network_graph(
        [
            {"type": "ignored", "value": "{}"},
            {"type": "network_node", "value": "{"},
            {"type": "network_node", "value": '{"id":"a"}'},
            {"type": "network_node", "value": '{"id":"a"}'},
            {"type": "network_edge", "value": '{"from":"a","to":"b"}'},
            {"type": "network_edge", "value": '{"from":"a","to":"b"}'},
        ]
    )

    assert graph == {
        "nodes": [{"id": "a"}],
        "edges": [{"from": "a", "to": "b"}],
    }


def test_post_access_state_questions_cover_all_terminal_transitions():
    builder = _builder()
    enabled = {"auto_data_exfil", "auto_cleanup"}
    builder._strategy_enabled = lambda key, default=False: key in enabled

    assert builder._infer_open_questions(
        {"post_access_inventory_completed": True},
        [],
        "persistence_established",
    ) == ["data_exfiltration_pending"]
    assert (
        builder._infer_open_questions(
            {"post_access_inventory_completed": True, "exfiltration_completed": True},
            [],
            "persistence_established",
        )
        == []
    )
    assert builder._infer_open_questions({}, [], "internal_recon_completed") == ["post_access_inventory_needed"]
    assert builder._infer_open_questions(
        {"post_access_inventory_completed": True},
        [],
        "internal_recon_completed",
    ) == ["data_exfiltration_pending"]
    assert (
        builder._infer_open_questions(
            {"post_access_inventory_completed": True, "exfiltration_completed": True},
            [],
            "internal_recon_completed",
        )
        == []
    )
    assert builder._infer_open_questions({"cleanup_completed": False}, [], "exfiltration_completed") == [
        "cleanup_needed"
    ]
    builder._strategy_enabled = lambda *_args, **_kwargs: False
    assert builder._infer_open_questions({}, [], "exfiltration_completed") == []
    assert builder._infer_open_questions({}, [], "cleanup_completed") == []


def test_vulnerability_and_credential_state_questions_cover_surface_variants():
    builder = _builder()

    vulnerability_questions = builder._infer_open_questions(
        {"recon_completed": False},
        ["http", "jmx"],
        "vulnerabilities_found",
    )
    assert {
        "service_discovery_needed",
        "jmx_exposure_unknown",
    } <= set(vulnerability_questions)

    credential_questions = builder._infer_open_questions(
        {"recon_completed": False},
        ["http", "ssh"],
        "credentials_found",
        [{"type": "credential", "value": "ssh_login_success:root"}],
    )
    assert "service_discovery_needed" in credential_questions
    assert "privilege_escalation_path_unknown" in credential_questions


def test_generic_open_questions_cover_every_service_and_state_branch():
    builder = _builder()
    services = [
        "http",
        "jmx",
        "ftp",
        "smtp",
        "postgres",
        "smb",
        "ldap",
        "ssh",
    ]
    questions = builder._infer_open_questions(
        {},
        services,
        "recon_completed",
        [{"type": "web_input", "value": "password:login"}],
    )
    assert {
        "jmx_exposure_unknown",
        "ftp_anonymous_access_unknown",
        "smtp_open_relay_unknown",
        "database_auth_unknown",
        "smb_null_session_unknown",
        "active_directory_exposure_unknown",
        "ssh_credentials_unknown",
        "ftp_credentials_unknown",
        "web_credentials_unknown",
    } <= set(questions)

    assert builder._infer_open_questions({}, [], "recon_completed") == ["general_vulnerability_scan_needed"]
    assert builder._infer_open_questions({"vulnerabilities_found": True}, [], "recon_completed") == []
    assert "privilege_escalation_path_unknown" in builder._infer_open_questions(
        {"credentials_found": True},
        [],
        "recon_completed",
        [{"value": "ssh_authenticated"}],
    )


def test_coverage_gaps_skip_completed_web_checks_and_enable_late_stages():
    builder = _builder()
    facts = [
        {"source": "whatweb"},
        {"sources": ["security_headers_check"]},
        {"observations": [None, {"source": "ffuf"}]},
        {"type": "nuclei_finding"},
        {"source": "openapi_import"},
    ]
    gaps = builder._coverage_gaps(
        {"recon_completed": True},
        ["http"],
        "recon_completed",
        facts,
        {},
        {"web": "confirmed_present", "api": "unknown"},
    )
    assert "web_mapping_pending" not in gaps
    assert "web_app_deep_testing_pending" not in gaps
    assert "web_content_discovery_pending" not in gaps
    assert "template_verification_pending" not in gaps
    assert "api_security_testing_pending" not in gaps

    builder._strategy_enabled = lambda key, default=False: (
        key
        in {
            "auto_data_exfil",
            "auto_cleanup",
        }
    )
    assert "data_exfiltration_pending" in builder._coverage_gaps(
        {"recon_completed": True, "internal_recon_completed": True},
        [],
        "internal_recon_completed",
        [],
        {},
        {},
    )
    assert "cleanup_needed" in builder._coverage_gaps(
        {"recon_completed": True, "exfiltration_completed": True},
        [],
        "exfiltration_completed",
        [],
        {},
        {},
    )


def test_source_detection_reads_direct_aggregate_and_observation_sources():
    builder = _builder()

    assert builder._source_seen([{"source": "WhatWeb:run"}], ("whatweb",)) is True
    assert (
        builder._source_seen(
            [
                {
                    "sources": ["other"],
                    "observations": [None, {"source": "ffuf:run"}],
                }
            ],
            ("ffuf",),
        )
        is True
    )
    assert builder._source_seen([{"observations": [None]}], ("missing",)) is False


@pytest.mark.parametrize(
    ("state", "questions", "expected"),
    [
        ("any", ["data_exfiltration_pending"], "data_exfiltration"),
        ("any", ["privilege_escalation_path_unknown"], "privilege_escalation"),
        ("cleanup_completed", [], "conclude"),
        ("anything", [], "conclude"),
    ],
)
def test_remaining_next_capability_routes(state, questions, expected):
    assert _builder()._next_required_capability(state, questions) == expected


def test_internal_vulnerability_gap_skips_untyped_entries_before_match():
    target_model = {
        "coverage": {
            "gaps": [
                "legacy",
                {"surface": "other", "check": "other"},
                {
                    "surface": "internal_service",
                    "check": "internal_vulnerability_assessment",
                },
            ]
        }
    }

    assert _builder()._internal_vulnerability_gaps_seen(target_model) is True
