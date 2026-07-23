"""Regression contracts for post-execution assessment graph synchronization."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from pathlib import Path

import pytest

from core.ai.fact_assessment import AssessmentStatus
from core.ai.fact_store import FactStore
from core.ai.runtime import PipelineRuntime
from core.knowledge import GraphProjectionService, KnowledgeGraph
from core.knowledge.identity import canonical_asset, canonical_service
from core.knowledge.models import EdgeType
from core.secrets import SecretStore

pytestmark = [pytest.mark.contract, pytest.mark.replay]


def _runtime(tmp_path: Path) -> PipelineRuntime:
    return PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=lambda _command: "",
    )


def _service_edge(graph: KnowledgeGraph) -> dict:
    asset_id = canonical_asset("10.0.0.5").entity_id
    service_id = canonical_service("10.0.0.5", 443, "tcp").entity_id
    edges = graph.get_edges_from(asset_id, EdgeType.RUNS_SERVICE)
    return next(edge for edge in edges if edge["dst"] == service_id)


def _serialized_graph_properties(graph: KnowledgeGraph) -> str:
    with sqlite3.connect(graph.db_path) as conn:
        rows = conn.execute(
            """
            SELECT properties FROM nodes
            UNION ALL
            SELECT properties FROM edges
            """
        ).fetchall()
    return "\n".join(str(row[0]) for row in rows)


def _record_success(
    runtime: PipelineRuntime,
    execution_id: str,
) -> tuple[int, bool]:
    return runtime.facts.add_command_result(
        "scan",
        "10.0.0.5",
        f"probe:{execution_id}",
        "probe 10.0.0.5:443",
        f"output:{execution_id}",
        status="succeeded",
        execution_id=execution_id,
        idempotency_key=f"execution:{execution_id}",
    )


def test_automatic_assessment_refreshes_graph_and_replay_is_idempotent(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    fact_id = runtime.facts.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "probe-a",
        source_execution_ids=("exec-a",),
    )
    duplicate_id = runtime.facts.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "probe-b",
        source_execution_ids=("exec-b",),
    )
    assert duplicate_id == fact_id

    runtime.project_fact_ids([fact_id])
    observed = runtime.facts.assessments.current_for_fact(fact_id)
    assert observed is not None and observed.status is AssessmentStatus.OBSERVED
    assert _service_edge(runtime.knowledge_graph)["properties"][
        "current_assessment_refs"
    ] == [observed.assessment_id]

    _record_success(runtime, "exec-a")
    result_id, unique = _record_success(runtime, "exec-b")

    current = runtime.facts.assessments.current_for_fact(fact_id)
    assert current is not None and current.status is AssessmentStatus.VERIFIED
    assert unique is True
    edge = _service_edge(runtime.knowledge_graph)
    assert edge["properties"]["assessment_status"] == "verified"
    assert edge["properties"]["current_assessment_refs"] == [current.assessment_id]
    assert edge["properties"]["provenance"][str(fact_id)]["assessment_id"] == (
        current.assessment_id
    )
    assert runtime.knowledge_graph.projection_record(
        fact_id,
        current.assessment_id,
    ) is not None

    before_stats = runtime.knowledge_graph.stats()
    before_edge = _service_edge(runtime.knowledge_graph)
    before_history = runtime.facts.assessments.history(fact_id)

    replayed_id, replayed_unique = _record_success(runtime, "exec-b")

    assert replayed_id == result_id
    assert replayed_unique is False
    assert runtime.knowledge_graph.stats() == before_stats
    assert _service_edge(runtime.knowledge_graph) == before_edge
    assert runtime.facts.assessments.history(fact_id) == before_history


def test_manual_assessment_transitions_refresh_graph_via_durable_outbox(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    fact_id = runtime.facts.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "manual-observation",
    )
    runtime.project_fact_ids([fact_id])

    verified, verified_created = runtime.facts.assessments.assess_fact(
        fact_id,
        AssessmentStatus.VERIFIED,
        confidence=95,
        reason="Manual verifier confirmed the service.",
        assessor="test.manual_verifier",
        evidence_fact_ids=(fact_id,),
    )

    verified_edge = _service_edge(runtime.knowledge_graph)
    assert verified_created is True
    assert verified_edge["properties"]["assessment_status"] == "verified"
    assert verified_edge["properties"]["current_assessment_refs"] == [
        verified.assessment_id
    ]
    assert runtime.facts.pending_assessment_projections() == []

    contradicted, contradicted_created = runtime.facts.assessments.assess_fact(
        fact_id,
        AssessmentStatus.CONTRADICTED,
        confidence=95,
        reason="Manual verifier invalidated the prior observation.",
        assessor="test.manual_verifier",
        evidence_fact_ids=(fact_id,),
    )

    contradicted_edge = _service_edge(runtime.knowledge_graph)
    assert contradicted_created is True
    assert contradicted_edge["properties"]["assessment_status"] == "contradicted"
    assert contradicted_edge["properties"]["current_assessment_refs"] == [
        contradicted.assessment_id
    ]
    assert runtime.facts.pending_assessment_projections() == []


def test_late_assessment_redaction_replaces_current_graph_provenance(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    fact_id = runtime.facts.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "manual-observation",
    )
    runtime.project_fact_ids([fact_id])
    secret = "late-learned-assessment-value"
    reason = f"Manual verification used {secret}."
    execution_id = f"exec-{secret}"
    first, first_created = runtime.facts.assessments.assess_fact(
        fact_id,
        AssessmentStatus.VERIFIED,
        confidence=95,
        reason=reason,
        assessor="test.manual_verifier",
        evidence_fact_ids=(fact_id,),
        source_execution_ids=(execution_id,),
    )
    assert first_created is True
    assert secret in _serialized_graph_properties(runtime.knowledge_graph)

    runtime.facts.secret_store.store(secret, kind="learned_assessment_value")
    second, second_created = runtime.facts.assessments.assess_fact(
        fact_id,
        AssessmentStatus.VERIFIED,
        confidence=95,
        reason=reason,
        assessor="test.manual_verifier",
        evidence_fact_ids=(fact_id,),
        source_execution_ids=(execution_id,),
    )

    assert second_created is False
    assert second.assessment_id == first.assessment_id
    assert secret not in second.reason
    assert all(secret not in item for item in second.source_execution_ids)
    assert secret not in _serialized_graph_properties(runtime.knowledge_graph)
    assert runtime.facts.pending_assessment_projections() == []


def test_startup_redaction_enqueues_and_repairs_current_graph_provenance(
    tmp_path: Path,
) -> None:
    facts_path = tmp_path / "redaction-facts.db"
    graph_path = tmp_path / "redaction-graph.db"
    secret_store = SecretStore(":memory:", key=b"graph-redaction-startup-key")
    runtime = PipelineRuntime(
        str(facts_path),
        runner=lambda _command: "",
        fact_store=FactStore(str(facts_path), secret_store=secret_store),
        knowledge_graph=KnowledgeGraph(str(graph_path)),
    )
    fact_id = runtime.facts.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "manual-observation",
    )
    runtime.project_fact_ids([fact_id])
    secret = "startup-learned-assessment-value"
    reason = f"Manual verification used {secret}."
    execution_id = f"exec-{secret}"
    original, created = runtime.facts.assessments.assess_fact(
        fact_id,
        AssessmentStatus.VERIFIED,
        confidence=95,
        reason=reason,
        assessor="test.manual_verifier",
        evidence_fact_ids=(fact_id,),
        source_execution_ids=(execution_id,),
    )
    assert created is True
    assert secret in _serialized_graph_properties(runtime.knowledge_graph)
    assert runtime.facts.pending_assessment_projections() == []

    secret_store.store(secret, kind="learned_assessment_value")
    reopened_store = FactStore(str(facts_path), secret_store=secret_store)
    pending = reopened_store.pending_assessment_projections()
    assert [(item["fact_id"], item["assessment_id"]) for item in pending] == [
        (fact_id, original.assessment_id)
    ]

    recovered = PipelineRuntime(
        str(facts_path),
        runner=lambda _command: "",
        fact_store=reopened_store,
        knowledge_graph=KnowledgeGraph(str(graph_path)),
    )
    current = recovered.facts.assessments.current_for_fact(fact_id)
    assert current is not None
    assert current.assessment_id == original.assessment_id
    assert secret not in current.reason
    assert all(secret not in item for item in current.source_execution_ids)
    assert secret not in _serialized_graph_properties(recovered.knowledge_graph)
    assert recovered.facts.pending_assessment_projections() == []


def test_startup_backfill_enqueues_current_head_for_graph_projection(
    tmp_path: Path,
) -> None:
    facts_path = tmp_path / "backfill-facts.db"
    graph_path = tmp_path / "backfill-graph.db"
    FactStore(str(facts_path))
    with sqlite3.connect(facts_path) as conn:
        fact_id = int(
            conn.execute(
                """
                INSERT INTO facts(scan_id, host, type, value, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "scan",
                    "10.0.0.5",
                    "port_open",
                    "443/tcp (https) [nginx]",
                    "legacy-import",
                    1.0,
                ),
            ).lastrowid
        )

    reopened_store = FactStore(str(facts_path))
    current = reopened_store.assessments.current_for_fact(fact_id)
    assert current is not None
    pending = reopened_store.pending_assessment_projections()
    assert [(item["fact_id"], item["assessment_id"]) for item in pending] == [
        (fact_id, current.assessment_id)
    ]

    recovered = PipelineRuntime(
        str(facts_path),
        runner=lambda _command: "",
        fact_store=reopened_store,
        knowledge_graph=KnowledgeGraph(str(graph_path)),
    )
    edge = _service_edge(recovered.knowledge_graph)
    assert edge["properties"]["current_assessment_refs"] == [
        current.assessment_id
    ]
    assert recovered.facts.pending_assessment_projections() == []


def test_replay_repairs_a_post_commit_projection_failure(tmp_path: Path) -> None:
    store = FactStore(str(tmp_path / "repair-facts.db"))
    graph = KnowledgeGraph(str(tmp_path / "repair-graph.db"))
    projector = GraphProjectionService(store, graph)
    fact_id = store.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "probe-a",
        source_execution_ids=("exec-a",),
    )
    store.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "probe-b",
        source_execution_ids=("exec-b",),
    )
    projector.project_fact_ids([fact_id])
    observed_id = store.assessments.current_for_fact(fact_id).assessment_id

    store.add_command_result(
        "scan",
        "10.0.0.5",
        "probe:exec-a",
        "probe 10.0.0.5:443",
        "output:exec-a",
        status="succeeded",
        execution_id="exec-a",
        idempotency_key="execution:exec-a",
    )
    calls = 0

    def flaky_projection(fact_ids: Sequence[int]) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated graph outage after assessment commit")
        projector.project_fact_ids(fact_ids)

    store.register_assessment_projection_handler(flaky_projection)
    result_id, unique = store.add_command_result(
        "scan",
        "10.0.0.5",
        "probe:exec-b",
        "probe 10.0.0.5:443",
        "output:exec-b",
        status="succeeded",
        execution_id="exec-b",
        idempotency_key="execution:exec-b",
    )

    current = store.assessments.current_for_fact(fact_id)
    assert current is not None and current.status is AssessmentStatus.VERIFIED
    assert unique is True
    assert _service_edge(graph)["properties"]["current_assessment_refs"] == [
        observed_id
    ]
    assert graph.projection_record(fact_id, current.assessment_id) is None
    pending = store.pending_assessment_projections()
    assert len(pending) == 1
    assert pending[0]["assessment_id"] == current.assessment_id
    assert pending[0]["attempt_count"] == 1
    assert pending[0]["last_attempt_at"] is not None

    replayed_id, replayed_unique = store.add_command_result(
        "scan",
        "10.0.0.5",
        "probe:exec-b",
        "probe 10.0.0.5:443",
        "output:exec-b",
        status="succeeded",
        execution_id="exec-b",
        idempotency_key="execution:exec-b",
    )

    assert replayed_id == result_id
    assert replayed_unique is False
    assert calls == 2
    repaired_edge = _service_edge(graph)
    assert repaired_edge["properties"]["assessment_status"] == "verified"
    assert repaired_edge["properties"]["current_assessment_refs"] == [
        current.assessment_id
    ]
    assert store.pending_assessment_projections() == []

    before_stats = graph.stats()
    before_history = store.assessments.history(fact_id)
    store.add_command_result(
        "scan",
        "10.0.0.5",
        "probe:exec-b",
        "probe 10.0.0.5:443",
        "output:exec-b",
        status="succeeded",
        execution_id="exec-b",
        idempotency_key="execution:exec-b",
    )
    assert calls == 3
    assert graph.stats() == before_stats
    assert store.assessments.history(fact_id) == before_history
    assert store.pending_assessment_projections() == []


def test_new_runtime_drains_durable_outbox_without_replaying_execution(
    tmp_path: Path,
) -> None:
    facts_path = tmp_path / "crash-facts.db"
    graph_path = tmp_path / "crash-graph.db"
    store = FactStore(str(facts_path))
    graph = KnowledgeGraph(str(graph_path))
    projector = GraphProjectionService(store, graph)
    fact_id = store.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "probe-a",
        source_execution_ids=("exec-a",),
    )
    store.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "probe-b",
        source_execution_ids=("exec-b",),
    )
    projector.project_fact_ids([fact_id])
    observed = store.assessments.current_for_fact(fact_id)
    assert observed is not None and observed.status is AssessmentStatus.OBSERVED

    for execution_id in ("exec-a", "exec-b"):
        store.add_command_result(
            "scan",
            "10.0.0.5",
            f"probe:{execution_id}",
            "probe 10.0.0.5:443",
            f"output:{execution_id}",
            status="succeeded",
            execution_id=execution_id,
            idempotency_key=f"execution:{execution_id}",
        )

    current = store.assessments.current_for_fact(fact_id)
    assert current is not None and current.status is AssessmentStatus.VERIFIED
    assert _service_edge(graph)["properties"]["current_assessment_refs"] == [
        observed.assessment_id
    ]
    pending = store.pending_assessment_projections()
    assert len(pending) == 1
    assert pending[0]["fact_id"] == fact_id
    assert pending[0]["assessment_id"] == current.assessment_id
    assert pending[0]["attempt_count"] == 0
    assert pending[0]["last_attempt_at"] is None
    before_history = store.assessments.history(fact_id)
    before_results = store.get_command_results("scan", "10.0.0.5")
    executed: list[str] = []

    recovered = PipelineRuntime(
        str(facts_path),
        runner=lambda command: executed.append(command) or "",
        fact_store=FactStore(str(facts_path)),
        knowledge_graph=KnowledgeGraph(str(graph_path)),
    )

    assert executed == []
    assert recovered.facts.pending_assessment_projections() == []
    repaired_edge = _service_edge(recovered.knowledge_graph)
    assert repaired_edge["properties"]["assessment_status"] == "verified"
    assert repaired_edge["properties"]["current_assessment_refs"] == [
        current.assessment_id
    ]
    assert recovered.facts.get_command_results("scan", "10.0.0.5") == before_results
    assert recovered.facts.assessments.history(fact_id) == before_history

    before_stats = recovered.knowledge_graph.stats()
    before_edge = repaired_edge
    restarted = PipelineRuntime(
        str(facts_path),
        runner=lambda command: executed.append(command) or "",
        fact_store=FactStore(str(facts_path)),
        knowledge_graph=KnowledgeGraph(str(graph_path)),
    )
    assert executed == []
    assert restarted.facts.pending_assessment_projections() == []
    assert restarted.knowledge_graph.stats() == before_stats
    assert _service_edge(restarted.knowledge_graph) == before_edge


def test_outbox_enqueue_failure_rolls_back_result_and_assessment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FactStore(str(tmp_path / "atomic-outbox.db"))
    fact_id = store.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "probe-a",
        source_execution_ids=("exec-a",),
    )
    store.add_fact(
        "scan",
        "10.0.0.5",
        "port_open",
        "443/tcp (https) [nginx]",
        "probe-b",
        source_execution_ids=("exec-b",),
    )
    store.register_assessment_projection_handler(lambda _fact_ids: None)
    store.add_command_result(
        "scan",
        "10.0.0.5",
        "probe:exec-a",
        "probe 10.0.0.5:443",
        "output:exec-a",
        status="succeeded",
        execution_id="exec-a",
        idempotency_key="execution:exec-a",
    )
    assert store.pending_assessment_projections() == []

    def fail_enqueue(*_args, **_kwargs):
        raise RuntimeError("simulated outbox write failure")

    monkeypatch.setattr(
        store,
        "_enqueue_assessment_projections_in_connection",
        fail_enqueue,
    )
    with pytest.raises(RuntimeError, match="outbox write failure"):
        store.add_command_result(
            "scan",
            "10.0.0.5",
            "probe:exec-b",
            "probe 10.0.0.5:443",
            "output:exec-b",
            status="succeeded",
            execution_id="exec-b",
            idempotency_key="execution:exec-b",
        )

    current = store.assessments.current_for_fact(fact_id)
    assert current is not None and current.status is AssessmentStatus.OBSERVED
    assert len(store.get_command_results("scan", "10.0.0.5")) == 1
    assert store.pending_assessment_projections() == []


def test_automatic_contradiction_refreshes_the_other_facts_projection(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    positive_id = runtime.facts.add_fact(
        "scan",
        "10.0.0.5",
        "service_status",
        "ssh:confirmed_present",
        "probe-positive",
        source_execution_ids=("exec-positive",),
    )
    negative_id = runtime.facts.add_fact(
        "scan",
        "10.0.0.5",
        "service_status",
        "ssh:confirmed_absent",
        "probe-negative",
        source_execution_ids=("exec-negative",),
    )
    runtime.project_fact_ids([positive_id, negative_id])

    _record_success(runtime, "exec-positive")
    _record_success(runtime, "exec-negative")

    positive = runtime.facts.assessments.current_for_fact(positive_id)
    assert positive is not None and positive.status is AssessmentStatus.CONTRADICTED
    asset = runtime.knowledge_graph.get_node(canonical_asset("10.0.0.5").entity_id)
    assert asset is not None
    positive_provenance = asset["properties"]["provenance"][str(positive_id)]
    assert positive_provenance["assessment_id"] == positive.assessment_id
    assert positive_provenance["assessment_status"] == "contradicted"
    assert runtime.knowledge_graph.projection_record(
        positive_id,
        positive.assessment_id,
    ) is not None

    before_asset = asset
    before_stats = runtime.knowledge_graph.stats()
    before_history = runtime.facts.assessments.history(positive_id)
    _record_success(runtime, "exec-negative")
    assert runtime.knowledge_graph.get_node(asset["id"]) == before_asset
    assert runtime.knowledge_graph.stats() == before_stats
    assert runtime.facts.assessments.history(positive_id) == before_history
