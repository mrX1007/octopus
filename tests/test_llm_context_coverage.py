"""Focused boundary coverage for bounded LLM context serialization."""

from __future__ import annotations

import builtins

import pytest

from core.ai import llm_context

pytestmark = pytest.mark.unit


def test_compaction_accepts_non_mapping_and_surface_state_contexts():
    assert llm_context.compact_context_for_llm("raw") == {"context": "raw"}
    compact = llm_context.compact_context_for_llm({"host": "host", "surface_states": {"web": "confirmed_present"}})
    assert compact["surface_states"] == {"web": "confirmed_present"}


def test_summary_budget_handles_missing_config_and_invalid_value(monkeypatch):
    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "config":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    assert llm_context._summary_budget() == 8000
    monkeypatch.setattr(builtins, "__import__", real_import)

    import config

    monkeypatch.setattr(
        config,
        "CFG",
        {"ollama": {"summarize_threshold": object()}},
    )
    assert llm_context._summary_budget() == 8000


def test_summary_budget_keeps_priority_sections_and_reports_omissions(monkeypatch):
    monkeypatch.setattr(llm_context, "_summary_budget", lambda: 512)
    compact = {
        "host": "host",
        "state": "state",
        "services": "x" * 1000,
        "extra": "y" * 1000,
    }

    fitted = llm_context._fit_summary_budget(compact)

    assert fitted["context_compacted"] is True
    assert fitted["host"] == "host"
    assert fitted["state"] == "state"
    assert fitted["omitted_sections"] == ["services", "extra"]


def test_mission_contract_uses_a_non_lossy_preamble_outside_compaction(monkeypatch):
    contract = {
        "objective": "verify every advertised read-only route",
        "allowed_actions": ["observe_authorized_target"],
        "constraints": ["read-only discovery only"],
        "output_contract": "emit each exact OCTOBENCH_V3_* claim",
    }
    monkeypatch.setattr(llm_context, "_summary_budget", lambda: 512)

    compact = llm_context.compact_context_for_llm(
        {
            "host": "h" * 2_000,
            "mission_contract": contract,
            "services": ["s" * 2_000],
        },
        role="director",
    )
    preamble = llm_context.mission_contract_preamble(contract)

    assert "mission_contract" not in compact
    assert contract["objective"] in preamble
    assert contract["constraints"][0] in preamble
    assert contract["output_contract"] in preamble


def test_mission_contract_preamble_revalidates_direct_callers():
    with pytest.raises(ValueError, match="invalid_mission_contract"):
        llm_context.mission_contract_preamble({"objective": {"ground_truth": "private"}})
    with pytest.raises(ValueError, match="invalid_mission_contract"):
        llm_context.mission_contract_preamble({"objective": "x" * 4_097})


def test_target_model_compaction_covers_all_optional_shapes():
    model = {
        "target": "host",
        "services": {"legacy": True},
        "endpoints": [{"url": f"/{index}"} for index in range(20)],
        "internal_services": [],
        "security_findings": {"critical": [{"id": 1}], "empty": []},
        "web_app": {"routes": ["/a"], "metadata": {"ignored": True}, "empty": []},
        "coverage": {"gaps": ["g"], "checked": ["c"]},
        "typed_facts": {"ports": [1, 2], "scalar": "x", "empty": []},
    }

    compact = llm_context._compact_target_model(model, "director")

    assert compact["services"] == {"legacy": True}
    assert compact["endpoints"][-1] == {"omitted_items": 12}
    assert compact["security_findings"] == {"critical": [{"id": 1}]}
    assert compact["web_app"] == {"routes": ["/a"]}
    assert compact["coverage"] == {"gaps": ["g"], "checked": ["c"]}
    assert compact["typed_fact_counts"] == {"ports": 2, "scalar": 1}
    assert llm_context._compact_target_model({}, "generic") == {}


def test_graph_compaction_handles_lists_and_non_graph_metadata():
    compact = llm_context._compact_graph(
        {"nodes": [1, 2], "edges": "legacy", "label": "graph"},
        "director",
    )

    assert compact == {
        "nodes_count": 2,
        "sample_nodes": [1, 2],
        "label": "graph",
    }


def test_trim_helpers_cover_non_list_long_list_large_mapping_and_objects():
    marker = object()

    assert llm_context._trim_list("value", "generic") == "value"
    assert llm_context._trim_list([1, 2, 3], "generic", 2) == [
        1,
        2,
        {"omitted_items": 1},
    ]
    large = {str(index): index for index in range(42)}
    trimmed = llm_context._trim_value(large, "generic")
    assert trimmed["omitted_keys"] == 2
    assert llm_context._trim_value(marker, "generic") == str(marker)
