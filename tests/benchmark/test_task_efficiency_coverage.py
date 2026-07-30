"""Final denominator edge for task-efficiency replay metrics."""

import pytest

from core.benchmarks.task_efficiency import _relative_reduction

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def test_relative_reduction_with_empty_baseline_is_zero():
    assert _relative_reduction(0.0, 1.0) == 0.0
