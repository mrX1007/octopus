"""Tests for ExecutionResultStoreV2."""
import pytest
from core.actions.execution_result_store import DefaultExecutionResultStoreV2
from core.actions.execution_results_v2 import ExecutionResultV2, ExecutionStatusV2

@pytest.mark.unit
def test_result_store_draft_and_commit():
    store = DefaultExecutionResultStoreV2()
    res = ExecutionResultV2(
        schema_version="2.0",
        execution_id="exec-res-1",
        action_id="plugin:payload_keying",
        status=ExecutionStatusV2.SUCCEEDED,
        reason_codes=(),
        artifact_refs=(),
        credential_refs=(),
        session_refs=(),
        route_refs=(),
        c2_refs=(),
        fact_refs=(),
        audit_ref="aud:1",
        decision_trace_ref="trace:1",
        linked_result_refs=(),
        provenance_chain=(),
    )
    draft_ref = store.stage_draft(res, "tx-res-1")
    assert draft_ref.draft_id.startswith("draft-")
    binding = store.commit("tx-res-1", 1, "mark:1", "sha256:mark")
    assert binding.commit_state == "committed"
