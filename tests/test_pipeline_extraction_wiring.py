"""Contracts proving extracted pipeline seams are used by production facades."""

from __future__ import annotations

from core.ai.credential_sync import CredentialSeedResult
from core.ai.outcomes import InMemoryTaskOutcomeStore
from core.ai.pipeline import AIPipeline


def test_runtime_reset_rebinds_outcome_store_to_fresh_legacy_views(tmp_path):
    pipeline = AIPipeline(str(tmp_path / "reset.db"))
    old_store = pipeline.task_outcome_store
    old_outcomes = pipeline.task_outcomes
    pipeline.task_outcomes.append({"status": "stale"})

    pipeline._reset_runtime_state()

    assert isinstance(pipeline.task_outcome_store, InMemoryTaskOutcomeStore)
    assert pipeline.task_outcome_store is not old_store
    assert pipeline.task_outcomes is not old_outcomes
    assert pipeline.task_outcome_store.task_outcomes is pipeline.task_outcomes
    assert pipeline.task_outcome_store.failed_commands is pipeline.failed_commands
    assert pipeline.task_outcome_store.no_fact_tasks is pipeline.no_fact_tasks
    assert pipeline.task_outcomes == []


def test_task_outcome_facade_preserves_legacy_shape_and_indexes(tmp_path):
    pipeline = AIPipeline(str(tmp_path / "outcome.db"))
    command = {
        "command": "fixture target",
        "failed": True,
        "fact_pairs": [],
    }

    recorded = pipeline._record_task_outcome(
        "DiscoveryAgent",
        "service_discovery",
        "failed",
        "all_commands_failed",
        0,
        0,
        [command],
        1.5,
    )

    assert recorded == {
        "agent": "DiscoveryAgent",
        "task": "service_discovery",
        "status": "failed",
        "reason": "all_commands_failed",
        "new_facts": 0,
        "parsed_facts": 0,
        "commands": [command],
        "duration": 1.5,
    }
    assert pipeline.task_outcomes == [recorded]
    assert pipeline.failed_commands == ["fixture target"]


def test_credential_facades_delegate_and_preserve_seed_accounting(
    tmp_path,
    capsys,
):
    pipeline = AIPipeline(str(tmp_path / "credentials.db"))
    calls = []

    class SynchronizerSpy:
        def sync_from_facts(self, target, facts):
            calls.append(("sync", target, facts))

        def known_for_target(self, target):
            calls.append(("known", target))
            return {"ssh": [("root", "secret://fixture")]}

        def seed_known_credentials(self, scan_id, target, fact_store, credentials):
            calls.append(("seed", scan_id, target, fact_store, credentials))
            return CredentialSeedResult(
                seeded=1,
                announcements=("ssh://root@10.0.0.5",),
            )

    pipeline.credential_synchronizer = SynchronizerSpy()
    facts = [{"type": "credential", "value": "root:secret://fixture (cached)"}]

    pipeline._sync_runtime_credentials_from_facts("10.0.0.5", facts)
    known = pipeline._known_credentials_for_target("10.0.0.5")
    seeded = pipeline._seed_known_credentials("scan-1", "10.0.0.5")

    assert known == {"ssh": [("root", "secret://fixture")]}
    assert seeded == pipeline.total_new_facts == 1
    assert calls[0] == ("sync", "10.0.0.5", facts)
    assert calls[1] == ("known", "10.0.0.5")
    assert calls[2] == ("known", "10.0.0.5")
    assert calls[3][0:3] == ("seed", "scan-1", "10.0.0.5")
    assert calls[3][3] is pipeline.fact_store
    assert calls[3][4] == known
    assert "Known Credential: ssh://root@10.0.0.5" in capsys.readouterr().out


def test_telemetry_facades_call_extracted_helpers(tmp_path, monkeypatch):
    pipeline = AIPipeline(str(tmp_path / "telemetry.db"))
    calls = []

    monkeypatch.setattr(
        "core.ai.pipeline_observability.append_goal_trace",
        lambda trace, loop, context, decision: calls.append(
            ("goal", trace, loop, context, decision)
        ),
    )
    monkeypatch.setattr(
        "core.ai.pipeline_observability.persist_llm_health",
        lambda store, scan_id, target, role, result, loop: calls.append(
            ("health", store, scan_id, target, role, result, loop)
        ),
    )
    monkeypatch.setattr(
        "core.ai.pipeline_observability.append_command_trace",
        lambda trace, decision, result: calls.append(
            ("command", trace, decision, result)
        ),
    )
    monkeypatch.setattr(
        "core.ai.pipeline_observability.print_efficiency_report",
        lambda scan_id, target, elapsed, **kwargs: calls.append(
            ("efficiency", scan_id, target, elapsed, kwargs)
        ),
    )

    context = {"state": "initial_recon"}
    decision = {"goal": "service_discovery"}
    result = {"llm_status": "ok"}
    command = {"command": "fixture"}
    command_result = {"failed": False}
    pipeline._record_goal_trace(2, context, decision)
    pipeline._record_llm_health("scan-1", "10.0.0.5", "director", result, 2)
    pipeline._record_command_trace(command, command_result)
    pipeline._print_efficiency_report("scan-1", "10.0.0.5", 3.5)

    assert calls[0] == ("goal", pipeline.goal_trace, 2, context, decision)
    assert calls[1][0] == "health"
    assert calls[1][1].__self__ is pipeline
    assert calls[1][2:] == (
        "scan-1",
        "10.0.0.5",
        "director",
        result,
        2,
    )
    assert calls[2] == (
        "command",
        pipeline.command_trace,
        command,
        command_result,
    )
    assert calls[3][0:4] == ("efficiency", "scan-1", "10.0.0.5", 3.5)
    assert calls[3][4]["get_facts"].__self__ is pipeline.fact_store
    assert calls[3][4]["task_outcomes"] is pipeline.task_outcomes
