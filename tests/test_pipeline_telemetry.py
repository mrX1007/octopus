import json

from core.ai.pipeline_telemetry import (
    append_command_trace,
    append_goal_trace,
    persist_llm_health,
    print_efficiency_report,
)


def test_goal_and_command_events_append_in_call_order_with_legacy_shapes():
    goal_trace = []
    command_trace = []
    first_goal = append_goal_trace(
        goal_trace,
        1,
        {
            "state": "recon_completed",
            "next_required_capability": "vulnerability_assessment",
            "stage_gates": {"recon": True},
            "open_questions": ["web_vulnerabilities_unknown"],
        },
        {
            "goal": "vulnerability_assessment",
            "thought": "verify exposed services",
            "llm_status": "ok",
        },
    )
    second_goal = append_goal_trace(
        goal_trace,
        2,
        {"state": "vulnerability_confirmed"},
        {},
    )
    first_command = append_command_trace(
        command_trace,
        {
            "command": "nmap 10.0.0.5",
            "key": "nmap 10.0.0.5",
            "action": "execute",
            "reason": "state_changed_or_unseen",
            "prerequisite": "",
        },
        {
            "failed": False,
            "output_hash": "abc",
            "duplicate_output": False,
            "parsed_facts": 2,
            "new_facts": 1,
            "check_status": "completed",
            "fact_pairs": [("port_open", "80/tcp (http)")],
        },
    )
    second_command = append_command_trace(
        command_trace,
        {
            "command": "nmap 10.0.0.5",
            "key": "nmap 10.0.0.5",
            "action": "skip",
            "reason": "duplicate_command_key",
        },
    )

    assert goal_trace == [first_goal, second_goal]
    assert first_goal == {
        "loop": 1,
        "goal": "vulnerability_assessment",
        "thought": "verify exposed services",
        "llm_status": "ok",
        "state": "recon_completed",
        "next_required_capability": "vulnerability_assessment",
        "stage_gates": {"recon": True},
        "open_questions": ["web_vulnerabilities_unknown"],
    }
    assert second_goal == {
        "loop": 2,
        "goal": "conclude",
        "thought": "",
        "llm_status": "",
        "state": "vulnerability_confirmed",
        "next_required_capability": None,
        "stage_gates": {},
        "open_questions": [],
    }
    assert command_trace == [first_command, second_command]
    assert first_command["facts"] == [("port_open", "80/tcp (http)")]
    assert second_command == {
        "command": "nmap 10.0.0.5",
        "key": "nmap 10.0.0.5",
        "action": "skip",
        "reason": "duplicate_command_key",
        "prerequisite": "",
    }


def test_llm_health_emission_is_ordered_and_invalid_status_is_a_noop():
    calls = []

    def store_fact(scan_id, target, fact, source):
        calls.append((scan_id, target, fact, source))

    failed = persist_llm_health(
        store_fact,
        "scan-1",
        "10.0.0.5",
        "director",
        {
            "llm_status": " FAILED ",
            "llm_error": "No JSON found",
            "fallback": True,
            "goal": "service_discovery",
            "plan": [{"task": "port_scan"}, {"task": "service_scan"}],
            "hypotheses": "2",
        },
        1,
    )
    skipped = persist_llm_health(
        store_fact,
        "scan-1",
        "10.0.0.5",
        "planner",
        {"llm_status": "skipped", "fallback": True, "plan": []},
        1,
    )
    invalid = persist_llm_health(
        store_fact,
        "scan-1",
        "10.0.0.5",
        "analysis",
        {"llm_status": "degraded"},
        1,
    )

    assert invalid is None
    assert [call[3] for call in calls] == ["llm:director", "llm:planner"]
    assert calls[0][2] is failed
    assert calls[1][2] is skipped
    assert failed["confidence"] == 95
    assert skipped["confidence"] == 80
    assert json.loads(failed["value"]) == {
        "error": "No JSON found",
        "fallback": True,
        "goal": "service_discovery",
        "hypotheses": 2,
        "loop": 1,
        "plan_steps": 2,
        "role": "director",
        "status": "failed",
    }
    assert json.loads(skipped["value"])["plan_steps"] == 0


def test_efficiency_report_uses_injected_state_and_preserves_output_order():
    lines = []
    fact_queries = []

    def get_facts(scan_id, target):
        fact_queries.append((scan_id, target))
        return [{"id": 1}, {"id": 2}, {"id": 3}]

    outcomes = [
        {"task": "blocked-task", "status": "blocked", "reason": "no_available_tools"},
        {"task": "failed-task", "status": "failed", "reason": "all_commands_failed"},
        {"task": "quiet-task", "status": "no_new_facts", "reason": "commands_ran_but_no_facts"},
        {"task": "done-task", "status": "completed", "reason": "1_new_facts"},
    ]
    goals = [
        {
            "goal": "service_discovery",
            "state": "recon_completed",
            "next_required_capability": "vulnerability_assessment",
        }
    ]
    commands = [
        {"action": "execute"},
        {"action": "skip"},
        {"action": "execute"},
    ]

    print_efficiency_report(
        "scan-1",
        "10.0.0.5",
        12.34,
        get_facts=get_facts,
        task_outcomes=outcomes,
        total_new_facts=7,
        goal_trace=goals,
        command_trace=commands,
        emit=lines.append,
    )

    assert fact_queries == [("scan-1", "10.0.0.5")]
    assert lines == [
        "[*] Efficiency report: tasks=4, new_facts=7, total_facts=3, failed=1, blocked=1, no_fact=1, elapsed=12.3s",
        "    Blocked tasks: blocked-task(no_available_tools)",
        "    Failed tasks: failed-task",
        "    No-fact tasks: quiet-task",
        "    Last goal trace: goal=service_discovery state=recon_completed next=vulnerability_assessment",
        "    Command trace: decisions=3, skipped=1",
    ]

