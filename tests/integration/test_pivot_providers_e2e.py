from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

def test_pivot_providers_e2e() -> None:
    pytest.skip("Integration environment not configured")
