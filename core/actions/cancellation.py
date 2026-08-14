"""Executor cancellation controller and tokens."""

from __future__ import annotations

import threading
from typing import NoReturn, Protocol, runtime_checkable


@runtime_checkable
class CancellationToken(Protocol):
    @property
    def token_id(self) -> str: ...
    @property
    def cancelled_at(self) -> float | None: ...
    @property
    def reason_code(self) -> str | None: ...
    def is_cancelled(self) -> bool: ...
    def raise_if_cancelled(self) -> None: ...
    def wait(self, timeout_seconds: float | None) -> bool: ...


class _CancellationStateV2:
    def __init__(self, token_id: str) -> None:
        self.token_id = token_id
        self.condition = threading.Condition()
        self.cancelled_at: float | None = None
        self.reason_code: str | None = None


class _ExecutorCancellationToken:
    """Private concrete read-only token backed by one controller-owned condition."""

    def __init__(self, state: _CancellationStateV2, *, _factory_key: object) -> None:
        if _factory_key is not ExecutorCancellationController._FACTORY_KEY:
            raise TypeError("cancellation tokens are issued only by ExecutorCancellationController")
        self._state = state

    @property
    def token_id(self) -> str:
        return self._state.token_id

    @property
    def cancelled_at(self) -> float | None:
        return self._state.cancelled_at

    @property
    def reason_code(self) -> str | None:
        return self._state.reason_code

    def is_cancelled(self) -> bool:
        return self._state.cancelled_at is not None

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled():
            raise CancelledException(self.token_id, self.reason_code)

    def wait(self, timeout_seconds: float | None) -> bool:
        with self._state.condition:
            if self._state.cancelled_at is not None:
                return True
            self._state.condition.wait(timeout=timeout_seconds)
            return self._state.cancelled_at is not None

    def __reduce__(self) -> NoReturn:
        raise TypeError("executor cancellation tokens are non-serializable")


class CancelledException(RuntimeError):
    def __init__(self, token_id: str, reason_code: str | None) -> None:
        self.token_id = token_id
        self.reason_code_value = reason_code
        super().__init__(f"Execution cancelled: {token_id} reason={reason_code}")


class ExecutorCancellationController:
    """The only production cancellation source/controller."""

    _FACTORY_KEY = object()

    def __init__(self, token_id: str) -> None:
        self._state = _CancellationStateV2(token_id)
        self._token = _ExecutorCancellationToken(self._state, _factory_key=self._FACTORY_KEY)

    @property
    def token(self) -> CancellationToken:
        return self._token

    def cancel(self, *, reason_code: str, cancelled_at: float | None = None) -> bool:
        import time

        with self._state.condition:
            if self._state.cancelled_at is not None:
                return False
            self._state.cancelled_at = cancelled_at if cancelled_at is not None else time.time()
            self._state.reason_code = reason_code
            self._state.condition.notify_all()
        return True


# Backward compatibility aliases
ExecutorCancellationToken = _ExecutorCancellationToken


__all__ = [
    "CancellationToken",
    "CancelledException",
    "ExecutorCancellationController",
    "ExecutorCancellationToken",
]
