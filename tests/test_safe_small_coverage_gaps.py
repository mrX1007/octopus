"""Hermetic checks for small protocol and generator completion boundaries."""

from __future__ import annotations

import pytest

from core.ai import ollama_client as ollama
from core.benchmarks.competitors.campaign import LabController
from core.benchmarks.harness import BenchmarkRunner

pytestmark = [pytest.mark.unit, pytest.mark.contract]


def test_protocol_stub_methods_have_no_runtime_side_effects() -> None:
    """The typing-only protocol bodies remain safe if inspected at runtime."""

    receiver = object()

    assert BenchmarkRunner.__call__(receiver, object(), 1, 2) is None
    assert LabController.reset_and_health(receiver, object()) is None
    assert LabController.cleanup(receiver, object()) is None


def test_cancelled_generic_stream_exception_finishes_cleanly(monkeypatch) -> None:
    """A cancellation raised with a generic transport error terminates the stream."""

    class Cancellation:
        cancelled = False
        reason_code = ""

        @staticmethod
        def remaining_seconds():
            return None

        @staticmethod
        def wait(_seconds):
            return False

    cancellation = Cancellation()

    def cancelled_request(_payload):
        cancellation.cancelled = True
        cancellation.reason_code = "operator"
        raise RuntimeError("transport closed during cancellation")

    monkeypatch.setattr(ollama, "_post_ollama", cancelled_request)

    with ollama.bind_ollama_cancellation(cancellation):
        assert list(ollama.ask_ollama_stream("prompt")) == [
            "[!] Ollama request cancelled: operator."
        ]
