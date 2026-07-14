from dataclasses import FrozenInstanceError

import pytest

from core.ai.outcomes import (
    InMemoryTaskOutcomeStore,
    TaskOutcome,
    classify_task_result,
    command_result_reason,
    has_blocked_stage_fact,
)


def _command(*, failed=False, skipped=False, reason="", fact_pairs=None, name="tool target"):
    result = {
        "command": name,
        "failed": failed,
        "fact_pairs": list(fact_pairs or []),
    }
    if skipped:
        result["skipped"] = True
    if reason:
        result["skip_reason"] = reason
    return result


@pytest.mark.parametrize(
    ("command_results", "expected"),
    [
        ([], False),
        ([_command(fact_pairs=[("stage_status", "root:completed")])], False),
        (
            [_command(fact_pairs=[("stage_status", "persistence:blocked_missing_credentials")])],
            True,
        ),
        (
            [
                _command(fact_pairs=[("observation", "blocked_missing_credentials")]),
                _command(fact_pairs=[("stage_status", "ssh:blocked_missing_credentials")]),
            ],
            True,
        ),
    ],
)
def test_has_blocked_stage_fact_matches_legacy_suffix_rule(command_results, expected):
    assert has_blocked_stage_fact(command_results) is expected


@pytest.mark.parametrize(
    ("commands", "parsed_facts", "expected"),
    [
        (
            [_command(fact_pairs=[("stage_status", "root:blocked_missing_credentials")])],
            4,
            "blocked",
        ),
        (
            [
                _command(skipped=True, reason="duplicate_command_key"),
                _command(skipped=True, reason="already_completed:nuclei_scan"),
            ],
            0,
            "skipped",
        ),
        ([_command(failed=True), _command(failed=True)], 0, "failed"),
        ([_command(failed=True), _command(failed=False)], 0, "no_new_facts"),
        ([], 0, "no_new_facts"),
        ([_command(failed=True)], 1, "completed"),
    ],
)
def test_classify_task_result_preserves_exact_status_truth_table(
    commands, parsed_facts, expected
):
    task_result = {
        "commands": commands,
        "parsed_facts": parsed_facts,
        "new_facts": 0,
    }

    assert classify_task_result(task_result) == expected


@pytest.mark.parametrize(
    ("commands", "parsed_facts", "new_facts", "expected"),
    [
        ([], 0, 0, "no_commands"),
        (
            [_command(fact_pairs=[("stage_status", "root:blocked_missing_credentials")])],
            2,
            2,
            "missing_credentials_or_manual_gate",
        ),
        (
            [
                _command(skipped=True, reason="zeta"),
                _command(skipped=True, reason="beta"),
                _command(skipped=True, reason="alpha"),
                _command(skipped=True, reason="delta"),
                _command(skipped=True, reason="gamma"),
                _command(skipped=True, reason="alpha"),
            ],
            0,
            0,
            "all_commands_skipped:alpha,beta,delta",
        ),
        ([_command(failed=True), _command(failed=True)], 0, 0, "all_commands_failed"),
        (
            [_command(failed=True), _command(failed=False)],
            0,
            0,
            "commands_ran_but_no_facts",
        ),
        ([_command()], 3, 0, "facts_seen_but_already_known"),
        ([_command()], 3, 2, "2_new_facts"),
    ],
)
def test_command_result_reason_preserves_exact_reason_strings(
    commands, parsed_facts, new_facts, expected
):
    assert command_result_reason(commands, parsed_facts, new_facts) == expected


def test_task_outcome_is_immutable_and_round_trips_the_legacy_shape():
    outcome = TaskOutcome(
        agent="DiscoveryAgent",
        task="service_discovery",
        status="completed",
        reason="2_new_facts",
        new_facts=2,
        parsed_facts=3,
        commands=(_command(name="nmap 10.0.0.5"),),
        duration=1.25,
    )

    expected = {
        "agent": "DiscoveryAgent",
        "task": "service_discovery",
        "status": "completed",
        "reason": "2_new_facts",
        "new_facts": 2,
        "parsed_facts": 3,
        "commands": [_command(name="nmap 10.0.0.5")],
        "duration": 1.25,
    }
    first = outcome.to_legacy_dict()
    second = outcome.to_legacy_dict()

    assert first == expected
    assert second == expected
    assert first is not second
    assert first["commands"] is not second["commands"]
    with pytest.raises(FrozenInstanceError):
        outcome.status = "failed"
    with pytest.raises(TypeError):
        outcome.commands[0]["failed"] = True


def test_in_memory_store_appends_legacy_dicts_and_updates_indexes_exactly():
    task_outcomes = []
    failed_commands = []
    no_fact_tasks = []
    store = InMemoryTaskOutcomeStore(
        task_outcomes,
        failed_commands,
        no_fact_tasks,
    )
    failed = TaskOutcome(
        agent="DiscoveryAgent",
        task="service_discovery",
        status="failed",
        reason="all_commands_failed",
        new_facts=0,
        parsed_facts=0,
        commands=(
            _command(failed=True, name="nmap 10.0.0.5"),
            _command(failed=False, name="curl_headers http://10.0.0.5"),
        ),
        duration=2.0,
    )
    no_facts = TaskOutcome(
        agent="VerificationAgent",
        task="web_vulnerability_testing",
        status="no_new_facts",
        reason="commands_ran_but_no_facts",
        new_facts=0,
        parsed_facts=0,
        commands=(_command(name="nuclei_safe http://10.0.0.5"),),
        duration=3.0,
    )
    completed = TaskOutcome(
        agent="AnalysisAgent",
        task="hypothesis_analysis",
        status="completed",
        reason="1_hypotheses_accepted",
        new_facts=1,
        parsed_facts=1,
        commands=(),
        duration=0.5,
    )

    first = store.record(failed)
    second = store.append(no_facts)
    third = store.append(completed)

    assert store.task_outcomes is task_outcomes
    assert store.failed_commands is failed_commands
    assert store.no_fact_tasks is no_fact_tasks
    assert task_outcomes == [first, second, third]
    assert failed_commands == ["nmap 10.0.0.5"]
    assert no_fact_tasks == ["web_vulnerability_testing"]

