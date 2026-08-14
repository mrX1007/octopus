from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_ad_remote_execution_router_e2e() -> None:
    pytest.skip("Integration environment not configured")
