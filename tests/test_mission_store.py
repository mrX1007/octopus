"""Contract tests for the durable mission/task/attempt lifecycle."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.ai import mission_store
from core.ai.outcomes import TaskOutcome
from core.secrets import Redactor, SecretStore

MissionStore = mission_store.MissionStore
pytestmark = pytest.mark.contract


def _outcome(
    *,
    agent: str = "DiscoveryAgent",
    task: str = "service_discovery",
    status: str = "completed",
    reason: str = "1_new_facts",
    command: str = "nmap 10.0.0.5",
) -> TaskOutcome:
    return TaskOutcome(
        agent=agent,
        task=task,
        status=status,
        reason=reason,
        new_facts=1 if status == "completed" else 0,
        parsed_facts=1 if status == "completed" else 0,
        commands=(
            {
                "command": command,
                "failed": status == "failed",
                "fact_pairs": [("port_open", "22/tcp ssh")],
            },
        ),
        duration=1.25,
    )


def _only(items):
    values = tuple(items)
    assert len(values) == 1
    return values[0]


def test_open_mission_is_stable_across_store_instances_and_scan_id_is_unique(tmp_path):
    db_path = tmp_path / "missions.db"
    first_store = MissionStore(str(db_path))
    created = first_store.open_mission("scan-stable", "10.0.0.5")

    assert created.scan_id == "scan-stable"
    assert created.target == "10.0.0.5"
    assert created.status == "running"

    reopened_store = MissionStore(str(db_path))
    reopened = reopened_store.open_mission(
        "scan-stable",
        "10.0.0.5",
        recover=True,
    )
    looked_up = reopened_store.get_mission_by_scan_id("scan-stable")

    assert reopened.mission_id == created.mission_id
    assert looked_up is not None
    assert looked_up.mission_id == created.mission_id
    assert looked_up.scan_id == "scan-stable"
    assert looked_up.target == "10.0.0.5"

    with pytest.raises(ValueError):
        reopened_store.open_mission("scan-stable", "10.0.0.6")


def test_task_registration_and_running_attempt_creation_are_idempotent(tmp_path):
    store = MissionStore(str(tmp_path / "missions.db"))
    mission = store.open_mission("scan-register", "10.0.0.5")
    prerequisite = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    dependent = store.register_task(
        mission.mission_id,
        "VerificationAgent",
        "vulnerability_assessment",
        depends_on=(prerequisite.task_id,),
    )
    repeated = store.register_task(
        mission.mission_id,
        "VerificationAgent",
        "vulnerability_assessment",
        depends_on=(prerequisite.task_id,),
    )

    assert prerequisite.status == "pending"
    assert dependent.task_id == repeated.task_id
    assert dependent.depends_on == (prerequisite.task_id,)

    first_attempt = store.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    repeated_attempt = store.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )

    assert first_attempt.attempt_id == repeated_attempt.attempt_id
    assert first_attempt.task_id == prerequisite.task_id
    assert first_attempt.attempt_number == 1
    assert first_attempt.status == "running"
    snapshot = store.snapshot(mission.mission_id)
    assert len(snapshot.tasks) == 2
    assert len(snapshot.attempts) == 1

    with pytest.raises(ValueError):
        store.register_task(
            mission.mission_id,
            "VerificationAgent",
            "vulnerability_assessment",
            depends_on=(),
        )


def test_dependencies_are_order_independent_and_cycles_fail_closed(tmp_path):
    store = MissionStore(str(tmp_path / "missions.db"))
    mission = store.open_mission("scan-dependencies", "10.0.0.5")
    first = store.register_task(mission.mission_id, "DiscoveryAgent", "first")
    second = store.register_task(mission.mission_id, "DiscoveryAgent", "second")
    dependent = store.register_task(
        mission.mission_id,
        "AnalysisAgent",
        "dependent",
        depends_on=(second.task_id, first.task_id),
    )
    repeated = store.register_task(
        mission.mission_id,
        "AnalysisAgent",
        "dependent",
        depends_on=(first.task_id, second.task_id),
    )

    assert repeated.task_id == dependent.task_id
    assert repeated.depends_on == tuple(sorted((first.task_id, second.task_id)))

    child = store.register_task(
        mission.mission_id,
        "VerificationAgent",
        "child",
        depends_on=(first.task_id,),
    )
    with pytest.raises(ValueError, match="cycle"):
        store.register_task(
            mission.mission_id,
            "DiscoveryAgent",
            "first",
            depends_on=(child.task_id,),
        )


def test_reopen_recovers_running_work_and_next_attempt_number_is_monotonic(tmp_path):
    db_path = tmp_path / "missions.db"
    crashed_store = MissionStore(str(db_path))
    mission = crashed_store.open_mission("scan-recovery", "10.0.0.5")
    task = crashed_store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    abandoned = crashed_store.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    del crashed_store

    recovery_store = MissionStore(str(db_path))
    reopened = recovery_store.open_mission(
        "scan-recovery",
        "10.0.0.5",
        recover=True,
    )
    recovered = recovery_store.snapshot(reopened.mission_id)
    recovered_task = next(item for item in recovered.tasks if item.task_id == task.task_id)
    recovered_attempt = next(
        item for item in recovered.attempts if item.attempt_id == abandoned.attempt_id
    )

    assert reopened.mission_id == mission.mission_id
    assert reopened.status == "running"
    assert recovered_task.status == "interrupted"
    assert recovered_attempt.status == "interrupted"
    assert recovered_attempt.reason

    with pytest.raises(ValueError):
        recovery_store.complete_attempt(abandoned.attempt_id, _outcome())

    retry = recovery_store.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    assert retry.attempt_id != abandoned.attempt_id
    assert retry.task_id == task.task_id
    assert retry.attempt_number == 2
    assert retry.status == "running"
    retried_snapshot = recovery_store.snapshot(mission.mission_id)
    assert next(
        item for item in retried_snapshot.tasks if item.task_id == task.task_id
    ).status == "running"


def test_attempt_completion_is_exactly_once_and_hydrates_outcome_and_provenance(tmp_path):
    db_path = tmp_path / "missions.db"
    store = MissionStore(str(db_path))
    mission = store.open_mission("scan-outcome", "10.0.0.5")
    task = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    attempt = store.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    outcome = _outcome()

    with pytest.raises(ValueError, match="identity"):
        store.complete_attempt(
            attempt.attempt_id,
            _outcome(task="different_task"),
        )

    completed = store.complete_attempt(
        attempt.attempt_id,
        outcome,
        execution_ids=("exec-1", "exec-2"),
        fact_ids=(7, 11),
    )
    repeated = store.complete_attempt(
        attempt.attempt_id,
        outcome,
        execution_ids=("exec-1", "exec-2"),
        fact_ids=(7, 11),
    )

    assert completed.attempt_id == repeated.attempt_id == attempt.attempt_id
    assert completed.status == "completed"
    assert completed.outcome is not None
    assert completed.outcome.to_legacy_dict() == outcome.to_legacy_dict()
    assert completed.execution_ids == ("exec-1", "exec-2")
    assert completed.fact_ids == (7, 11)

    hydrated = MissionStore(str(db_path)).snapshot(mission.mission_id)
    hydrated_task = next(item for item in hydrated.tasks if item.task_id == task.task_id)
    hydrated_attempt = _only(hydrated.attempts)
    assert hydrated_task.status == "completed"
    assert hydrated_attempt.outcome is not None
    assert hydrated_attempt.outcome.to_legacy_dict() == outcome.to_legacy_dict()
    assert hydrated_attempt.execution_ids == ("exec-1", "exec-2")
    assert hydrated_attempt.fact_ids == (7, 11)

    with pytest.raises(ValueError):
        store.complete_attempt(
            attempt.attempt_id,
            _outcome(reason="different_terminal_result"),
            execution_ids=("exec-1", "exec-2"),
            fact_ids=(7, 11),
        )
    with pytest.raises(ValueError):
        store.complete_attempt(
            attempt.attempt_id,
            outcome,
            execution_ids=("different-execution",),
            fact_ids=(7, 11),
        )


def test_explicit_interrupt_resume_and_terminal_mission_transitions(tmp_path):
    store = MissionStore(str(tmp_path / "missions.db"))
    mission = store.open_mission("scan-transitions", "10.0.0.5")
    task = store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    first_attempt = store.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )

    store.interrupt_mission(mission.mission_id, "operator_requested")
    store.interrupt_mission(mission.mission_id, "operator_requested")
    interrupted = store.snapshot(mission.mission_id)

    assert interrupted.mission.status == "interrupted"
    assert interrupted.mission.reason == "operator_requested"
    assert next(item for item in interrupted.tasks if item.task_id == task.task_id).status == "interrupted"
    assert next(
        item for item in interrupted.attempts if item.attempt_id == first_attempt.attempt_id
    ).status == "interrupted"

    resumed = store.open_mission("scan-transitions", "10.0.0.5")
    retry = store.begin_attempt(
        resumed.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    store.complete_attempt(retry.attempt_id, _outcome())
    store.complete_mission(mission.mission_id, "goal_reached")
    store.complete_mission(mission.mission_id, "goal_reached")

    completed = store.snapshot(mission.mission_id)
    assert completed.mission.status == "completed"
    assert completed.mission.reason == "goal_reached"
    assert retry.attempt_number == 2

    with pytest.raises(ValueError):
        store.complete_mission(mission.mission_id, "conflicting_reason")
    with pytest.raises(ValueError):
        store.interrupt_mission(mission.mission_id, "too_late")
    with pytest.raises(ValueError):
        store.begin_attempt(
            mission.mission_id,
            "DiscoveryAgent",
            "service_discovery",
        )


def test_attempt_payload_is_redacted_before_sqlite_persistence(tmp_path):
    db_path = tmp_path / "missions.db"
    secret_store = SecretStore(":memory:", key=b"mission-store-test-key")
    store = MissionStore(str(db_path), redactor=Redactor(secret_store))
    target_password = "TargetPassword_24680"
    raw_target = f"https://admin:{target_password}@10.0.0.5/"
    mission = store.open_mission("scan-redaction", raw_target)
    assert target_password not in mission.target
    assert "secret://" in mission.target
    store.register_task(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    attempt = store.begin_attempt(
        mission.mission_id,
        "DiscoveryAgent",
        "service_discovery",
    )
    token = "MISSIONTOKEN_A1B2C3D4E5F6"
    password = "MissionPassword_987654"
    outcome = _outcome(
        reason=f"password={password}",
        command=f"curl -H 'Authorization: Bearer {token}' https://10.0.0.5/",
    )

    completed = store.complete_attempt(attempt.attempt_id, outcome)
    assert completed.outcome is not None
    rendered = json.dumps(completed.outcome.to_legacy_dict(), sort_keys=True)
    assert token not in rendered
    assert password not in rendered
    assert "secret://" in rendered
    assert token in outcome.commands[0]["command"]
    assert password in outcome.reason

    persisted_bytes = b"".join(
        path.read_bytes()
        for path in tmp_path.glob("missions.db*")
        if path.is_file()
    )
    assert token.encode() not in persisted_bytes
    assert password.encode() not in persisted_bytes
    assert target_password.encode() not in persisted_bytes
    secret_store.close()


def test_two_store_instances_create_one_task_and_one_running_attempt_under_race(tmp_path):
    db_path = tmp_path / "missions.db"
    setup_store = MissionStore(str(db_path))
    mission = setup_store.open_mission("scan-concurrent", "10.0.0.5")

    registration_barrier = threading.Barrier(2)

    def register_from_fresh_store():
        contender = MissionStore(str(db_path), owner_id=setup_store.owner_id)
        registration_barrier.wait(timeout=5)
        return contender.register_task(
            mission.mission_id,
            "DiscoveryAgent",
            "service_discovery",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        registered = tuple(pool.map(lambda _index: register_from_fresh_store(), range(2)))

    assert registered[0].task_id == registered[1].task_id
    assert len(setup_store.snapshot(mission.mission_id).tasks) == 1

    attempt_barrier = threading.Barrier(2)

    def begin_from_fresh_store():
        contender = MissionStore(str(db_path), owner_id=setup_store.owner_id)
        attempt_barrier.wait(timeout=5)
        return contender.begin_attempt(
            mission.mission_id,
            "DiscoveryAgent",
            "service_discovery",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = tuple(pool.map(lambda _index: begin_from_fresh_store(), range(2)))

    assert attempts[0].attempt_id == attempts[1].attempt_id
    assert attempts[0].attempt_number == attempts[1].attempt_number == 1
    concurrent_snapshot = setup_store.snapshot(mission.mission_id)
    assert len(concurrent_snapshot.attempts) == 1
    assert concurrent_snapshot.attempts[0].status == "running"
