"""Tests for sensitive ingestion staging."""

import pytest

from core.actions.sensitive_transactions import SensitiveStagingTransactionV2


@pytest.mark.unit
def test_sensitive_staging():
    st = SensitiveStagingTransactionV2("tx-sens-1")
    assert st.transaction_id == "tx-sens-1"
