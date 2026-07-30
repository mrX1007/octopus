"""Hermetic branch coverage for cooperative execution cancellation."""

from __future__ import annotations

import pytest

from core.execution import cancellation

pytestmark = pytest.mark.unit


def test_reason_codes_and_typed_partial_output_are_bounded() -> None:
    assert cancellation.cancellation_reason_code(" operator request=secret ") == ("operator")
    assert cancellation.cancellation_reason_code("   ") == "cancelled"
    assert cancellation.cancellation_reason_code("a" * 200) == "a" * 128

    error = cancellation.ExecutionCancelled(
        "provider cancelled=private",
        stdout=b"partial stdout",
        stderr="partial stderr",
        returncode=-15,
    )
    assert error.args == ("provider",)
    assert error.reason_code == "provider"
    assert error.stdout == error.output == b"partial stdout"
    assert error.stderr == "partial stderr"
    assert error.returncode == -15


def test_manual_cancellation_is_idempotent_and_checkpointed() -> None:
    context = cancellation.CancellationContext()
    assert context.cancelled is False
    assert context.reason_code == ""
    assert context.remaining_seconds() is None
    context.checkpoint()

    assert context.cancel("operator request=private") is True
    assert context.cancel("second") is False
    assert context.cancelled is True
    assert context.reason_code == "operator"
    assert context.wait() is True
    with pytest.raises(cancellation.ExecutionCancelled) as exc_info:
        context.checkpoint()
    assert exc_info.value.reason_code == "operator"

    event_only = cancellation.CancellationContext()
    event_only._event.set()
    assert event_only.reason_code == "cancelled"


def test_deadline_expiration_uses_fixed_monotonic_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cancellation.time, "monotonic", lambda: 100.0)
    expired = cancellation.CancellationContext.with_timeout(0)

    assert expired.cancelled is True
    assert expired.reason_code == "deadline_exceeded"
    assert expired.remaining_seconds() == 0.0


def test_wait_uses_deadline_bounds_without_sleeping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cancellation.time, "monotonic", lambda: 100.0)

    immediate_waits: list[float | None] = []
    immediate = cancellation.CancellationContext()
    monkeypatch.setattr(
        immediate._event,
        "wait",
        lambda timeout: immediate_waits.append(timeout) or True,
    )
    assert immediate.wait(2.5) is True
    assert immediate_waits == [2.5]

    bounded_waits: list[float | None] = []
    bounded = cancellation.CancellationContext(deadline_monotonic=105.0)
    monkeypatch.setattr(
        bounded._event,
        "wait",
        lambda timeout: bounded_waits.append(timeout) or False,
    )
    assert bounded.remaining_seconds() == 5.0
    assert bounded.wait() is False
    assert bounded.wait(-3.0) is False
    assert bounded_waits == [5.0, 0.0]
