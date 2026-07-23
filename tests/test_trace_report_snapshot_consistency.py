"""Context and reports must share one immutable evaluated-fact view."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.ai.context_builder import ContextBuilder
from core.ai.fact_store import FactStore
from core.ai.state_resolver import StateResolver
from core.ai.trace_report import TraceReporter

pytestmark = pytest.mark.contract


def test_report_reuses_context_snapshot_after_fact_store_mutation(
    tmp_path: Path,
) -> None:
    store = FactStore(str(tmp_path / "facts.db"))
    scan_id = "scan-consistent-report"
    target = "HOST.EXAMPLE"
    store.add_fact(
        scan_id,
        target,
        "port_open",
        "80/tcp (http)",
        "initial-discovery",
    )
    builder = ContextBuilder(store, StateResolver(store))
    snapshot = builder.build_evaluated_fact_snapshot(scan_id, target)
    context = builder.build_context(
        scan_id,
        target,
        evaluated_fact_snapshot=snapshot,
    )

    # This fact exists in history by report time, but not in the decision view
    # that produced the context and stage gates.
    store.add_fact(
        scan_id,
        target,
        "potential_vulnerability",
        "CVE-2099-0001 version match only",
        "late-version-matcher",
    )
    report = TraceReporter(store).build(
        scan_id,
        target,
        context=context,
        evaluated_fact_snapshot=snapshot,
    )

    assert len(store.get_facts(scan_id, target)) == 2
    assert report["evaluated_fact_snapshot_ref"] == snapshot.snapshot_ref
    assert report["evaluated_fact_snapshot"] == context["evaluated_fact_snapshot"]
    assert report["summary"]["facts"] == 1
    assert report["evaluated_fact_snapshot"]["historical_fact_count"] == 1
    assert all(
        "CVE-2099-0001" not in str(item)
        for section in report["machine_report"]["sections"].values()
        for item in section
    )


def test_report_rejects_context_from_another_snapshot(tmp_path: Path) -> None:
    store = FactStore(str(tmp_path / "facts.db"))
    builder = ContextBuilder(store, StateResolver(store))
    first = builder.build_evaluated_fact_snapshot("scan", "host")
    context = builder.build_context(
        "scan",
        "host",
        evaluated_fact_snapshot=first,
    )
    store.add_fact("scan", "host", "port_open", "443/tcp (https)", "discovery")
    second = builder.build_evaluated_fact_snapshot("scan", "host")

    with pytest.raises(ValueError, match="different evaluated fact snapshots"):
        TraceReporter(store).build(
            "scan",
            "host",
            context=context,
            evaluated_fact_snapshot=second,
        )


def test_report_rejects_stale_context_when_snapshot_is_implicit(
    tmp_path: Path,
) -> None:
    store = FactStore(str(tmp_path / "facts.db"))
    builder = ContextBuilder(store, StateResolver(store))
    first = builder.build_evaluated_fact_snapshot("scan", "host")
    context = builder.build_context(
        "scan",
        "host",
        evaluated_fact_snapshot=first,
    )
    store.add_fact("scan", "host", "port_open", "443/tcp (https)", "discovery")

    with pytest.raises(ValueError, match="different evaluated fact snapshots"):
        TraceReporter(store).build(
            "scan",
            "host",
            context=context,
        )
