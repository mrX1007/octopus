"""Tests for execution graphs."""

import pytest

from core.auth.execution_graphs import ExecutionGraphRegistry


@pytest.mark.unit
def test_execution_graph_registry():
    reg = ExecutionGraphRegistry()
    assert reg is not None
