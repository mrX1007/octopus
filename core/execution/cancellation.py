"""Cooperative cancellation shared by execution and process boundaries."""

from __future__ import annotations

import re
import threading
import time

_REASON_CODE = re.compile(r"[^a-zA-Z0-9_.:-]+")


def cancellation_reason_code(value: object) -> str:
    """Return a bounded reason code that cannot retain free-form secrets."""

    raw = str(value or "cancelled").strip().split("=", 1)[0]
    raw = raw.split(maxsplit=1)[0] if raw else "cancelled"
    return _REASON_CODE.sub("_", raw)[:128] or "cancelled"


class ExecutionCancelled(BaseException):
    """Typed cancellation carrying optional partial output outside ``args``."""

    def __init__(
        self,
        reason: object = "cancelled",
        *,
        stdout: object = "",
        stderr: object = "",
        returncode: int | None = None,
    ) -> None:
        self.reason_code = cancellation_reason_code(reason)
        self.stdout = stdout
        self.output = stdout
        self.stderr = stderr
        self.returncode = returncode
        super().__init__(self.reason_code)


class CancellationContext:
    """Thread-safe cancellation token with an optional monotonic deadline."""

    def __init__(self, *, deadline_monotonic: float | None = None) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._reason_code = ""
        self._deadline_monotonic = (
            float(deadline_monotonic) if deadline_monotonic is not None else None
        )

    @classmethod
    def with_timeout(cls, timeout_seconds: float) -> CancellationContext:
        timeout = max(0.0, float(timeout_seconds))
        return cls(deadline_monotonic=time.monotonic() + timeout)

    def cancel(self, reason: object = "cancelled") -> bool:
        reason_code = cancellation_reason_code(reason)
        with self._lock:
            if self._event.is_set():
                return False
            self._reason_code = reason_code
            self._event.set()
            return True

    def _expire_deadline(self) -> None:
        deadline = self._deadline_monotonic
        if deadline is not None and time.monotonic() >= deadline:
            self.cancel("deadline_exceeded")

    @property
    def cancelled(self) -> bool:
        self._expire_deadline()
        return self._event.is_set()

    @property
    def reason_code(self) -> str:
        self._expire_deadline()
        return self._reason_code or ("cancelled" if self._event.is_set() else "")

    def remaining_seconds(self) -> float | None:
        deadline = self._deadline_monotonic
        if deadline is None:
            return None
        return max(0.0, deadline - time.monotonic())

    def wait(self, timeout: float | None = None) -> bool:
        if self.cancelled:
            return True
        remaining = self.remaining_seconds()
        if remaining is not None:
            timeout = remaining if timeout is None else min(max(0.0, timeout), remaining)
        triggered = self._event.wait(timeout)
        return triggered or self.cancelled

    def checkpoint(self) -> None:
        if self.cancelled:
            raise ExecutionCancelled(self.reason_code)


__all__ = [
    "CancellationContext",
    "ExecutionCancelled",
    "cancellation_reason_code",
]
