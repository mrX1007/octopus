"""Tests for ExecutionCreationStoreV2."""
import pytest
from core.actions.execution_creation_store import DefaultExecutionCreationStoreV2, ExecutionCreationStoreV2

@pytest.mark.unit
def test_creation_store():
    store = DefaultExecutionCreationStoreV2()
    assert isinstance(store, ExecutionCreationStoreV2)
    receipt = store.begin_root(
        execution_id="exec-1",
        action_id="plugin:payload_keying",
        transaction_id="tx-1",
        idempotency_key="idemp-1",
    )
    assert receipt.execution_id == "exec-1"
    fetched = store.require(receipt.creation_ref)
    assert fetched == receipt
