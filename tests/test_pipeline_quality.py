#!/usr/bin/env python3
"""Regression tests for AI pipeline planning quality gates."""


def test_post_exploit_goal_forces_verification_plan():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    context = {
        "state": "root_access_confirmed",
        "services": ["ssh", "http"],
        "open_questions": ["persistence_needed"],
    }
    noisy_plan = [
        {"agent": "DiscoveryAgent", "task": "directory_bruteforce"},
        {"agent": "AnalysisAgent", "task": "analyze_services"},
    ]

    optimized = pipeline._optimize_plan(noisy_plan, "data_exfiltration", context)

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


def test_tooldef_python_dependency_gate():
    from core.tools.registry import ToolDef

    assert ToolDef(name="ok", requires=["python:sys"]).is_available()
    assert not ToolDef(name="missing", requires=["python:octopus_missing_module"]).is_available()


def test_persistence_state_requests_internal_recon_before_exfil():
    from core.ai.director import DirectorLLM

    context = {
        "state": "persistence_established",
        "services": ["ssh"],
        "open_questions": ["internal_network_recon_pending"],
    }

    goal = DirectorLLM()._fallback_logic(context, []).get("goal")

    assert goal == "internal_reconnaissance"


def test_director_validation_inserts_internal_recon_before_exfil():
    from core.ai.director import DirectorLLM

    context = {
        "state": "persistence_established",
        "services": ["ssh"],
        "open_questions": ["internal_network_recon_pending"],
    }

    goal = DirectorLLM()._validate_goal("data_exfiltration", context, [])

    assert goal == "internal_reconnaissance"


def test_internal_recon_goal_forces_single_network_task():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    noisy_plan = [
        {"agent": "DiscoveryAgent", "task": "service_discovery"},
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]
    context = {
        "state": "persistence_established",
        "services": ["ssh"],
        "open_questions": ["internal_network_recon_pending"],
    }

    optimized = pipeline._optimize_plan(noisy_plan, "internal_reconnaissance", context)

    assert optimized == [{"agent": "VerificationAgent", "task": "internal_network_recon"}]
