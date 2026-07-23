"""One immutable evaluated-fact view drives every decision projection."""

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core.ai.context_builder import ContextBuilder
from core.ai.evaluated_facts import EvaluatedFactSnapshot
from core.ai.fact_assessment import FreshnessPolicy
from core.ai.fact_store import FactStore
from core.ai.report_schema import build_evidence_report
from core.ai.state_resolver import StateResolver

pytestmark = pytest.mark.contract


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8::1",
            "2001:db8::1",
        ),
        ("HOST.Example.", "host.example", "host.example"),
        (
            "HTTPS://HOST.Example:443/a/../b/%7euser#fragment",
            "https://host.example/b/~user",
            "https://host.example/b/~user",
        ),
    ],
)
def test_snapshot_scope_aliases_use_graph_identity_normalization(
    left: str,
    right: str,
    expected: str,
) -> None:
    first = EvaluatedFactSnapshot.build(
        "scan",
        left,
        [],
        evaluated_at=123.0,
    )
    second = EvaluatedFactSnapshot.build(
        "scan",
        right,
        [],
        evaluated_at=123.0,
    )

    assert first.canonical_scope == second.canonical_scope == (expected,)
    assert first.snapshot_ref == second.snapshot_ref
    assert EvaluatedFactSnapshot.from_payload(first.to_payload()) == first


def _stale_store(path: Path) -> FactStore:
    policy = FreshnessPolicy(
        default_max_age_seconds=1.0,
        max_age_by_type=(("port_open", 1.0), ("system_access", 1.0)),
    )
    return FactStore(
        str(path),
        assessment_policy=policy,
        assessment_clock=lambda: 100.0,
    )


def _age_fact(store: FactStore, fact_id: int) -> None:
    with store._get_conn() as conn:
        conn.execute("UPDATE facts SET timestamp = 0 WHERE id = ?", (fact_id,))
        conn.execute(
            "UPDATE fact_observations SET timestamp = 0 WHERE fact_id = ?",
            (fact_id,),
        )


def test_stale_access_and_service_facts_remain_history_but_do_not_close_gates(
    tmp_path: Path,
) -> None:
    store = _stale_store(tmp_path / "facts.db")
    root_id = store.add_fact(
        "scan",
        "HOST.EXAMPLE",
        "system_access",
        "root_access_confirmed",
        "ssh_inventory",
    )
    port_id = store.add_fact(
        "scan",
        "HOST.EXAMPLE",
        "port_open",
        "22/tcp (ssh)",
        "nmap",
    )
    _age_fact(store, root_id)
    _age_fact(store, port_id)

    resolver = StateResolver(store)
    state = resolver.resolve_state("scan", "HOST.EXAMPLE")
    context = ContextBuilder(store, resolver).build_context("scan", "HOST.EXAMPLE")
    history = store.get_facts("scan", "HOST.EXAMPLE")

    assert {fact["freshness_status"] for fact in history} == {"stale"}
    assert state["root_access_confirmed"] is False
    assert state["recon_completed"] is False
    assert context["stage_gates"]["root"] is False
    assert context["stage_gates"]["recon"] is False
    assert context["target_model"]["access"]["root_confirmed"] is False
    assert context["target_model"]["services"] == []
    assert context["evaluated_fact_snapshot"]["canonical_scope"] == ["host.example"]
    assert context["evaluated_fact_snapshot"]["historical_fact_count"] == 2
    assert context["evaluated_fact_snapshot"]["decision_fact_count"] == 0


def test_degraded_timeout_observation_is_unknown_not_positive_service_evidence(
    tmp_path: Path,
) -> None:
    store = FactStore(str(tmp_path / "facts.db"))
    fact_id = store.add_fact(
        "scan",
        "host",
        "port_open",
        "443/tcp (https)",
        "nmap",
        source_execution_ids=("exec-timeout",),
    )
    store.add_command_result(
        "scan",
        "host",
        "nmap",
        "nmap host",
        "f" * 64,
        status="timeout",
        execution_id="exec-timeout",
    )

    fact = store.get_facts("scan", "host")[0]
    context = ContextBuilder(store, StateResolver(store)).build_context("scan", "host")

    assert fact["id"] == fact_id
    assert fact["freshness_status"] == "unknown"
    assert fact["coverage_status"] == "degraded"
    assert context["stage_gates"]["recon"] is False
    assert context["target_model"]["services"] == []


def test_context_build_reads_one_fact_snapshot(tmp_path: Path) -> None:
    class CountingFactStore(FactStore):
        reads = 0

        def get_facts(self, *args, **kwargs):
            self.reads += 1
            return super().get_facts(*args, **kwargs)

    store = CountingFactStore(str(tmp_path / "facts.db"))
    store.add_fact("scan", "host", "port_open", "80/tcp (http)", "nmap")

    context = ContextBuilder(store, StateResolver(store)).build_context("scan", "host")

    assert store.reads == 1
    assert context["evaluated_fact_snapshot"]["snapshot_ref"].startswith(
        "evaluated-facts://sha256/"
    )


@pytest.mark.parametrize("reader", ["scan", "ids"])
def test_fact_batch_uses_one_freshness_evaluation_time(
    tmp_path: Path,
    reader: str,
) -> None:
    clock_calls: list[float] = []

    def stepping_clock() -> float:
        value = 100.0 + 2.0 * len(clock_calls)
        clock_calls.append(value)
        return value

    store = FactStore(
        str(tmp_path / f"{reader}.db"),
        assessment_policy=FreshnessPolicy(default_max_age_seconds=1.0),
        assessment_clock=stepping_clock,
    )
    fact_ids = [
        store.add_fact("scan", "host", "observation", value, "probe")
        for value in ("first", "second")
    ]
    with store._get_conn() as conn:
        conn.executemany(
            "UPDATE facts SET timestamp = 99.5 WHERE id = ?",
            ((fact_id,) for fact_id in fact_ids),
        )
        conn.executemany(
            "UPDATE fact_observations SET timestamp = 99.5 WHERE fact_id = ?",
            ((fact_id,) for fact_id in fact_ids),
        )

    facts = (
        store.get_facts("scan", "host")
        if reader == "scan"
        else store.get_facts_by_ids(fact_ids)
    )

    assert clock_calls == [100.0]
    assert {fact["freshness"]["evaluated_at"] for fact in facts} == {100.0}
    assert {fact["freshness_status"] for fact in facts} == {"fresh"}


@pytest.mark.parametrize("reader", ["scan", "ids"])
def test_fact_read_does_not_mix_concurrent_assessment_and_outcome(
    tmp_path: Path,
    monkeypatch,
    reader: str,
) -> None:
    db_path = tmp_path / f"coherent-{reader}.db"
    store = FactStore(str(db_path))
    fact_id = store.add_fact(
        "scan",
        "host",
        "service_version",
        "ssh:22:OpenSSH",
        "probe-a",
        source_execution_ids=("exec-a",),
        source_identity="scanner-a",
        observation_method="banner-grab",
    )
    store.add_command_result(
        "scan",
        "host",
        "probe-a",
        "probe-a host",
        "a" * 64,
        status="succeeded",
        execution_id="exec-a",
    )
    with store._get_conn() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
    writer = FactStore(str(db_path))
    observations_read = threading.Event()
    release_reader = threading.Event()
    original = store._get_observations_for_facts

    def pause_after_observations(cursor, fact_ids):
        observations = original(cursor, fact_ids)
        observations_read.set()
        if not release_reader.wait(timeout=10):
            raise TimeoutError("writer did not release coherent fact reader")
        return observations

    monkeypatch.setattr(store, "_get_observations_for_facts", pause_after_observations)

    def read_facts():
        return (
            store.get_facts("scan", "host")
            if reader == "scan"
            else store.get_facts_by_ids((fact_id,))
        )

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(read_facts)
        assert observations_read.wait(timeout=10)
        try:
            writer.add_fact(
                "scan",
                "host",
                "service_version",
                "ssh:22:OpenSSH",
                "probe-b",
                source_execution_ids=("exec-b",),
                source_identity="scanner-b",
                observation_method="banner-grab",
            )
            writer.add_command_result(
                "scan",
                "host",
                "probe-b",
                "probe-b host",
                "b" * 64,
                status="timeout",
                execution_id="exec-b",
            )
        finally:
            release_reader.set()
        facts = future.result(timeout=10)

    assert len(facts) == 1
    fact = facts[0]
    assert [item["source_identity"] for item in fact["observations"]] == [
        "scanner-a"
    ]
    assert fact["assessment"]["source_execution_ids"] == ["exec-a"]
    assert fact["freshness_status"] == "fresh"
    assert fact["coverage_status"] == "complete"


def test_snapshot_prefers_explicit_observation_provenance(tmp_path: Path) -> None:
    store = FactStore(str(tmp_path / "facts.db"))
    store.add_fact(
        "scan",
        "host",
        "port_open",
        "443/tcp (https)",
        "generic-adapter",
        source_identity="TLS Sensor A",
        observation_method="tls-handshake",
    )

    context = ContextBuilder(store, StateResolver(store)).build_context("scan", "host")
    snapshot = context["evaluated_fact_snapshot"]

    assert snapshot["source_identities"] == ["tls_sensor_a"]
    assert snapshot["observation_methods"] == ["tls-handshake"]


def test_stale_verified_access_is_reported_as_observation_not_current_access() -> None:
    fact = {
        "id": 1,
        "scan_id": "scan",
        "host": "host",
        "type": "system_access",
        "value": "uid=0",
        "timestamp": 1.0,
        "freshness_status": "stale",
        "coverage_status": "complete",
        "assessment_status": "verified",
        "assessment": {
            "assessment_id": "fa-1",
            "status": "verified",
            "reason": "Two independent current observations.",
            "evidence_fact_ids": [1],
            "source_execution_ids": ["exec-a", "exec-b"],
        },
    }

    report = build_evidence_report("scan", "host", [fact])

    assert report["sections"]["access_findings"] == []
    assert report["sections"]["observations"][0]["kind"] == "access_observation"
