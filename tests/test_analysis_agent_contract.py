"""Contracts for bounded AnalysisAgent LLM responses."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import core.ai.task_agents as task_agents

pytestmark = pytest.mark.contract


def _agent() -> task_agents.AnalysisAgent:
    context_builder = SimpleNamespace(
        build_context=lambda _scan_id, host: {
            "host": host,
            "state": "recon",
            "services": [],
        }
    )
    return task_agents.AnalysisAgent(None, context_builder)


def test_empty_hypotheses_is_a_valid_success(monkeypatch):
    monkeypatch.setattr(
        task_agents,
        "ask_ollama",
        lambda *_args, **_kwargs: '{"hypotheses":[]}',
    )

    result = _agent().analyze("scan-clean", "10.0.0.5")

    assert result == {"hypotheses": [], "llm_status": "ok"}


def test_valid_hypotheses_are_normalized(monkeypatch):
    response = {
        "hypotheses": [
            {
                "claim": "  ssh_service_active  ",
            }
        ]
    }
    monkeypatch.setattr(
        task_agents,
        "ask_ollama",
        lambda *_args, **_kwargs: json.dumps(response),
    )

    result = _agent().analyze("scan-valid", "10.0.0.5")

    assert result == {
        "hypotheses": [
            {
                "claim": "ssh_service_active",
            }
        ],
        "llm_status": "ok",
    }
    assert "required_evidence" not in _agent().system_prompt


def test_binding_mission_contract_reaches_analysis_prompt(monkeypatch):
    captured = {}

    def fake_ask(prompt, **_kwargs):
        captured["prompt"] = prompt
        return '{"hypotheses":[]}'

    monkeypatch.setattr(task_agents, "ask_ollama", fake_ask)
    agent = _agent()
    agent.mission_contract = {
        "objective": "verify the authorized fixture",
        "allowed_actions": ["observe_authorized_target"],
        "constraints": ["read-only discovery only"],
        "output_contract": "emit each exact OCTOBENCH_V3_* claim",
    }

    assert agent.analyze("scan-contract", "10.0.0.5")["llm_status"] == "ok"
    assert "Caller mission instructions" in captured["prompt"]
    assert "within deterministic execution policy" in captured["prompt"]
    assert "verify the authorized fixture" in captured["prompt"]
    assert "read-only discovery only" in captured["prompt"]
    assert "emit each exact OCTOBENCH_V3_* claim" in captured["prompt"]


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ([], "response_not_object"),
        ({}, "unexpected_top_level_fields"),
        ({"hypotheses": [], "comment": "extra"}, "unexpected_top_level_fields"),
        ({"hypotheses": {}}, "hypotheses_not_list"),
        ({"hypotheses": ["claim"]}, "hypothesis_not_object"),
        (
            {"hypotheses": [{"claim": ""}]},
            "claim_not_nonempty_string",
        ),
        (
            {"hypotheses": [{"claim": "x", "required_evidence": ["port_open"]}]},
            "unexpected_hypothesis_fields",
        ),
    ],
)
def test_malformed_schema_is_a_controlled_failure(monkeypatch, payload, error):
    monkeypatch.setattr(
        task_agents,
        "ask_ollama",
        lambda *_args, **_kwargs: json.dumps(payload),
    )

    result = _agent().analyze("scan-invalid", "10.0.0.5")

    assert result == {
        "hypotheses": [],
        "llm_status": "failed",
        "llm_error": f"invalid_schema:{error}",
    }


@pytest.mark.parametrize(
    ("response", "error"),
    [
        ("not-json", "invalid_json"),
        ("[!] Ollama unavailable", "ollama_error"),
        (None, "invalid_response_type"),
    ],
)
def test_transport_and_parse_errors_are_controlled(monkeypatch, response, error):
    monkeypatch.setattr(
        task_agents,
        "ask_ollama",
        lambda *_args, **_kwargs: response,
    )

    result = _agent().analyze("scan-error", "10.0.0.5")

    assert result == {
        "hypotheses": [],
        "llm_status": "failed",
        "llm_error": error,
    }
