"""Memory-connection and idempotent-close coverage for MissionStore."""

import pytest

from core.ai.mission_store import MissionStore

pytestmark = pytest.mark.contract


def test_memory_connection_is_reused_and_close_is_idempotent():
    store = MissionStore(":memory:")
    memory_connection = store._memory_conn
    owned_secret_store = store._owned_secret_store
    assert memory_connection is not None
    assert owned_secret_store is not None

    with store._connection() as connection:
        assert connection is memory_connection
        assert connection.execute("SELECT 1").fetchone()[0] == 1

    store.close()
    assert store._memory_conn is None
    assert store._owned_secret_store is None
    store.close()
