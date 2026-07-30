"""Network-free statement and branch coverage for the Ollama client."""

from __future__ import annotations

import builtins
import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from core.ai import ollama_client as ollama

pytestmark = [pytest.mark.unit, pytest.mark.contract]


class Cancellation:
    def __init__(
        self,
        *,
        cancelled: bool = False,
        reason: str = "",
        remaining=None,
        wait_effects=(),
    ) -> None:
        self.cancelled = cancelled
        self.reason_code = reason
        self.remaining = remaining
        self.wait_effects = list(wait_effects)
        self.waits = []

    def remaining_seconds(self):
        return self.remaining

    def wait(self, seconds):
        self.waits.append(seconds)
        effect = self.wait_effects.pop(0) if self.wait_effects else False
        if callable(effect):
            return effect()
        if effect:
            self.cancelled = True
            if not self.reason_code:
                self.reason_code = "deadline_exceeded"
        return effect


class Response:
    def __init__(
        self,
        *,
        status=200,
        lines=(),
        text="",
        text_error: BaseException | None = None,
        raise_error: BaseException | None = None,
        iteration_error: BaseException | None = None,
        on_iteration_end=None,
        close_error: BaseException | None = None,
    ) -> None:
        self.status_code = status
        self.lines = list(lines)
        self._text = text
        self.text_error = text_error
        self.raise_error = raise_error
        self.iteration_error = iteration_error
        self.on_iteration_end = on_iteration_end
        self.close_error = close_error
        self.closed = 0

    @property
    def text(self):
        if self.text_error is not None:
            raise self.text_error
        return self._text

    def iter_lines(self):
        yield from self.lines
        if self.on_iteration_end is not None:
            self.on_iteration_end()
        if self.iteration_error is not None:
            raise self.iteration_error

    def raise_for_status(self) -> None:
        if self.raise_error is not None:
            raise self.raise_error

    def close(self) -> None:
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


def encoded(*payloads):
    return [json.dumps(payload).encode() for payload in payloads]


def configure_ask(monkeypatch, responses, *, retries=1):
    queue = list(responses)
    payloads = []

    def post(payload):
        payloads.append(payload)
        effect = queue.pop(0)
        if isinstance(effect, BaseException):
            raise effect
        return effect

    monkeypatch.setattr(ollama, "_post_ollama", post)
    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", retries)
    monkeypatch.setattr(ollama, "_bound_response_deadline", lambda _response: nullcontext())
    return payloads


def test_config_bool_and_import_fallback(monkeypatch) -> None:
    assert ollama._config_bool(None, True) is True
    assert ollama._config_bool(True, False) is True
    assert ollama._config_bool(" yes ", False) is True
    assert ollama._config_bool("disabled", True) is False
    assert ollama._config_bool(1, False) is True
    assert ollama._config_bool(0, True) is False

    source = Path(ollama.__file__).read_text(encoding="utf-8")
    original_import = builtins.__import__

    def without_config(name, *args, **kwargs):
        if name == "config":
            raise ImportError("config unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_config)
    namespace = {"__name__": "ollama_without_config", "__file__": ollama.__file__}
    exec(compile(source, ollama.__file__, "exec"), namespace)
    assert namespace["MODEL_NAME"] == "octopus-qwen"


def test_cancellation_binding_errors_and_request_timeout(monkeypatch) -> None:
    assert ollama._cancellation_error() == ""
    monkeypatch.setattr(ollama, "OLLAMA_TIMEOUT", 20)
    assert ollama._request_timeout() == 20

    active = Cancellation(cancelled=False, remaining=None)
    with ollama.bind_ollama_cancellation(active) as yielded:
        assert yielded is active
        assert ollama._cancellation_error() == ""
        assert ollama._request_timeout() == 20
    assert ollama._ACTIVE_CANCELLATION.get() is None

    active.remaining = 5
    with ollama.bind_ollama_cancellation(active):
        assert ollama._request_timeout() == 5
    active.remaining = 50
    with ollama.bind_ollama_cancellation(active):
        assert ollama._request_timeout() == 20
    active.remaining = 0
    with ollama.bind_ollama_cancellation(active):
        assert ollama._request_timeout() == 0.001

    active.cancelled = True
    active.reason_code = ""
    with ollama.bind_ollama_cancellation(active):
        assert ollama._cancellation_error().endswith("cancelled.")
    active.reason_code = "operator"
    with ollama.bind_ollama_cancellation(active):
        assert ollama._cancellation_error().endswith("operator.")


def test_post_headers_and_wait_modes(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(ollama.requests, "post", lambda *args, **kwargs: calls.append((args, kwargs)) or "ok")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    assert ollama._post_ollama({"x": 1}) == "ok"
    assert "headers" not in calls[-1][1]
    monkeypatch.setenv("LLM_API_KEY", " secret-key ")
    ollama._post_ollama({"x": 2})
    assert calls[-1][1]["headers"] == {"Authorization": "Bearer secret-key"}

    sleeps = []
    monkeypatch.setattr(ollama.time, "sleep", sleeps.append)
    assert ollama._wait_before_retry(2) is False
    assert sleeps == [2]
    cancellation = Cancellation(wait_effects=[True])
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama._wait_before_retry(3) is True
    assert cancellation.waits == [3]


class ImmediateThread:
    def __init__(self, *, target, **_kwargs) -> None:
        self.target = target
        self.started = False

    def start(self) -> None:
        self.started = True
        self.target()


class Event:
    def __init__(self, *, initially_set=False) -> None:
        self.value = initially_set

    def is_set(self) -> bool:
        return self.value

    def set(self) -> None:
        self.value = True


def test_bound_response_deadline_unbound_close_variants_and_stopped_loop(monkeypatch) -> None:
    response = Response()
    with ollama._bound_response_deadline(response):
        pass
    assert response.closed == 0

    monkeypatch.setattr(ollama.threading, "Thread", ImmediateThread)
    cancellation = Cancellation(wait_effects=[True])
    with ollama.bind_ollama_cancellation(cancellation), ollama._bound_response_deadline(response):
        pass
    assert response.closed == 1

    cancellation = Cancellation(wait_effects=[False, True])
    with ollama.bind_ollama_cancellation(cancellation), ollama._bound_response_deadline(response):
        pass
    assert cancellation.waits == [ollama._CANCELLATION_POLL_SECONDS] * 2

    broken = Response(close_error=RuntimeError("close failed"))
    cancellation = Cancellation(wait_effects=[True])
    with ollama.bind_ollama_cancellation(cancellation), ollama._bound_response_deadline(broken):
        pass
    assert broken.closed == 1

    no_close = SimpleNamespace(close=None)
    cancellation = Cancellation(wait_effects=[True])
    with ollama.bind_ollama_cancellation(cancellation), ollama._bound_response_deadline(no_close):
        pass

    monkeypatch.setattr(ollama.threading, "Event", lambda: Event(initially_set=True))
    cancellation = Cancellation()
    with ollama.bind_ollama_cancellation(cancellation), ollama._bound_response_deadline(response):
        pass


def test_stream_response_colors_invalid_lines_errors_and_long_logging(monkeypatch, capsys) -> None:
    response = Response(
        lines=[
            b"",
            b"not-json",
            *encoded(
                {"response": "<thought>"},
                {"response": "hidden"},
                {"response": "</thought>"},
                {"response": "<think>"},
                {"response": "inside"},
                {"response": "</think>"},
                {"response": "visible"},
            ),
        ]
    )
    payloads = configure_ask(monkeypatch, [response])
    monkeypatch.setattr(ollama, "NUM_GPU", 2)
    result = ollama.ask_ollama("prompt")
    assert result == "visible"
    assert payloads[0]["options"]["num_gpu"] == 2
    assert "visible" in capsys.readouterr().out

    long = Response(lines=encoded({"response": "x" * 501}))
    configure_ask(monkeypatch, [long])
    assert ollama.ask_ollama("long") == "x" * 501

    error = Response(lines=encoded({"response": "partial", "error": "model failed"}))
    configure_ask(monkeypatch, [error])
    assert ollama.ask_ollama("error") == "[!] Ollama error: model failed"


def test_empty_and_json_stream_recovery_paths(monkeypatch) -> None:
    configure_ask(monkeypatch, [Response(lines=encoded({"response": "<think>only"}))])
    assert "empty response" in ollama.ask_ollama("empty")

    configure_ask(
        monkeypatch,
        [Response(lines=encoded({"response": '<think>{"ok": true}'}))],
    )
    assert ollama.ask_ollama("recover", json_mode=True) == '{"ok": true}'

    configure_ask(monkeypatch, [Response(lines=encoded({"response": "<think>nothing"}))])
    assert "empty response" in ollama.ask_ollama("bad", json_mode=True)

    configure_ask(
        monkeypatch,
        [Response(lines=encoded({"response": 'prefix {"ok": true} suffix'}))],
    )
    assert ollama.ask_ollama("json", json_mode=True) == '{"ok": true}'

    configure_ask(monkeypatch, [Response(lines=encoded({"response": "plain text"}))])
    assert ollama.ask_ollama("invalid", json_mode=True).startswith("[!]")


def test_stream_cancellation_inside_after_and_close_boundaries(monkeypatch) -> None:
    cancellation = Cancellation(cancelled=True, reason="operator")
    response = Response(lines=encoded({"response": "never"}))
    configure_ask(monkeypatch, [response])
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("cancelled") == "[!] Ollama request cancelled: operator."

    cancellation = Cancellation()

    def cancel_after_iteration():
        cancellation.cancelled = True
        cancellation.reason_code = "deadline"

    response = Response(lines=[], on_iteration_end=cancel_after_iteration)
    configure_ask(monkeypatch, [response])
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("late") == "[!] Ollama request cancelled: deadline."

    cancellation = Cancellation()

    def cancel_before_line():
        cancellation.cancelled = True
        cancellation.reason_code = "stream"
        yield from encoded({"response": "never"})

    response = Response()
    response.iter_lines = cancel_before_line
    configure_ask(monkeypatch, [response])
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("during") == "[!] Ollama request cancelled: stream."
    assert response.closed == 1

    cancellation = Cancellation()

    def cancel_without_close():
        cancellation.cancelled = True
        cancellation.reason_code = "no-close"
        yield from encoded({"response": "never"})

    no_close = Response()
    no_close.close = None
    no_close.iter_lines = cancel_without_close
    configure_ask(monkeypatch, [no_close])
    with ollama.bind_ollama_cancellation(cancellation):
        assert "no-close" in ollama.ask_ollama("no close")


def test_options_minimal_and_disabled_optional_fields(monkeypatch) -> None:
    monkeypatch.setattr(ollama, "NUM_CTX", 0)
    monkeypatch.setattr(ollama, "NUM_THREAD", 0)
    monkeypatch.setattr(ollama, "NUM_BATCH", 0)
    monkeypatch.setattr(ollama, "NUM_GPU", None)
    monkeypatch.setattr(ollama, "JSON_FORMAT", False)
    payloads = configure_ask(
        monkeypatch,
        [Response(status=500), Response(lines=encoded({"response": '{"ok": true}'}))],
        retries=2,
    )
    monkeypatch.setattr(ollama, "_wait_before_retry", lambda _seconds: False)
    assert ollama.ask_ollama("prompt", json_mode=True) == '{"ok": true}'
    assert "num_ctx" not in payloads[0]["options"]
    assert "num_thread" not in payloads[0]["options"]
    assert "num_batch" not in payloads[1]["options"]
    assert "format" not in payloads[0]
    assert "minimal mode" in "minimal mode"

    monkeypatch.setattr(ollama, "NUM_BATCH", 512)
    payloads = configure_ask(
        monkeypatch,
        [Response(status=500), Response(lines=encoded({"response": "ok"}))],
        retries=2,
    )
    monkeypatch.setattr(ollama, "_wait_before_retry", lambda _seconds: False)
    assert ollama.ask_ollama("prompt") == "ok"
    assert payloads[1]["options"]["num_batch"] == 128


@pytest.mark.parametrize("status", [400, 422])
@pytest.mark.parametrize("text_error", [None, RuntimeError("text unavailable")])
def test_strict_json_relaxes_controls(monkeypatch, status, text_error, capsys) -> None:
    strict = Response(status=status, text="detail", text_error=text_error)
    relaxed = Response(lines=encoded({"response": '{"ok": true}'}))
    payloads = configure_ask(monkeypatch, [strict, relaxed])
    assert ollama.ask_ollama("json", json_mode=True) == '{"ok": true}'
    assert "think" in payloads[0] and "format" in payloads[0]
    assert "think" not in payloads[1] and "format" not in payloads[1]
    output = capsys.readouterr().out
    assert ("Detail:" in output) is (text_error is None)


def test_strict_json_cancellation_before_relaxed_request(monkeypatch) -> None:
    cancellation = Cancellation()

    class CancellingResponse(Response):
        @property
        def text(self):
            cancellation.cancelled = True
            cancellation.reason_code = "operator"
            return ""

    configure_ask(monkeypatch, [CancellingResponse(status=400)])
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("json", json_mode=True).endswith("operator.")


def test_http_500_detail_retry_final_cancel_and_wait_cancel(monkeypatch, capsys) -> None:
    configure_ask(monkeypatch, [Response(status=500, text="detail"), Response(status=500)], retries=2)
    monkeypatch.setattr(ollama, "_wait_before_retry", lambda _seconds: False)
    assert "after 2 retries" in ollama.ask_ollama("fail")
    assert "Detail:" in capsys.readouterr().out

    configure_ask(
        monkeypatch,
        [Response(status=500, text_error=RuntimeError("no text")), Response(lines=encoded({"response": "ok"}))],
        retries=2,
    )
    monkeypatch.setattr(ollama, "_wait_before_retry", lambda _seconds: False)
    assert ollama.ask_ollama("retry") == "ok"

    cancellation = Cancellation(wait_effects=[True])
    configure_ask(monkeypatch, [Response(status=500)], retries=2)
    monkeypatch.setattr(ollama, "_wait_before_retry", cancellation.wait)
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("cancel").endswith("deadline_exceeded.")

    cancellation = Cancellation()

    class Cancelling500(Response):
        @property
        def text(self):
            cancellation.cancelled = True
            cancellation.reason_code = "deadline"
            return ""

    configure_ask(monkeypatch, [Cancelling500(status=500)], retries=2)
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("cancel before retry").endswith("deadline.")


def test_http_404_empty_retry_and_zero_attempts(monkeypatch) -> None:
    configure_ask(monkeypatch, [Response(status=404)])
    assert "not found" in ollama.ask_ollama("missing")

    configure_ask(
        monkeypatch,
        [Response(lines=[]), Response(lines=encoded({"response": "ok"}))],
        retries=2,
    )
    monkeypatch.setattr(ollama, "_wait_before_retry", lambda _seconds: False)
    assert ollama.ask_ollama("empty retry") == "ok"

    cancellation = Cancellation(wait_effects=[True])
    configure_ask(monkeypatch, [Response(lines=[])], retries=2)
    monkeypatch.setattr(ollama, "_wait_before_retry", cancellation.wait)
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("empty cancel").endswith("deadline_exceeded.")

    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", 0)
    assert ollama.ask_ollama("none") == "[!] Ollama failed after all attempts."


def test_timeout_connection_and_generic_exception_retry_boundaries(monkeypatch) -> None:
    configure_ask(
        monkeypatch,
        [requests.exceptions.Timeout(), requests.exceptions.Timeout()],
        retries=2,
    )
    monkeypatch.setattr(ollama, "_wait_before_retry", lambda _seconds: False)
    assert "timed out after all retries" in ollama.ask_ollama("timeout")

    cancellation = Cancellation(wait_effects=[True])
    configure_ask(monkeypatch, [requests.exceptions.Timeout()], retries=2)
    monkeypatch.setattr(ollama, "_wait_before_retry", cancellation.wait)
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("timeout cancel").endswith("deadline_exceeded.")

    cancellation = Cancellation(cancelled=True, reason="deadline")
    configure_ask(monkeypatch, [requests.exceptions.Timeout()])
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("pre-cancel").endswith("deadline.")

    configure_ask(monkeypatch, [requests.exceptions.ConnectionError()])
    assert "Cannot connect" in ollama.ask_ollama("offline")
    cancellation = Cancellation()

    def cancel_connection(_payload):
        cancellation.cancelled = True
        cancellation.reason_code = "connection"
        raise requests.exceptions.ConnectionError()

    monkeypatch.setattr(ollama, "_post_ollama", cancel_connection)
    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", 1)
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("offline cancel").endswith("connection.")

    configure_ask(monkeypatch, [RuntimeError("boom"), RuntimeError("again")], retries=2)
    monkeypatch.setattr(ollama, "_wait_before_retry", lambda _seconds: False)
    assert "Unexpected error after 2 retries: again" in ollama.ask_ollama("error")

    cancellation = Cancellation(wait_effects=[True])
    configure_ask(monkeypatch, [RuntimeError("boom")], retries=2)
    monkeypatch.setattr(ollama, "_wait_before_retry", cancellation.wait)
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("error cancel").endswith("deadline_exceeded.")

    cancellation = Cancellation()

    def cancel_generic(_payload):
        cancellation.cancelled = True
        cancellation.reason_code = "generic"
        raise RuntimeError("boom")

    monkeypatch.setattr(ollama, "_post_ollama", cancel_generic)
    monkeypatch.setattr(ollama, "OLLAMA_RETRIES", 1)
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama("generic cancel").endswith("generic.")


def test_extract_json_fences_boundaries_escapes_and_failures() -> None:
    assert ollama._extract_json('```json\n{"x": 1}\n```') == '{"x": 1}'
    assert ollama._extract_json('```\n[1, 2]\n```') == "[1, 2]"
    assert ollama._extract_json("no json").startswith("[!]")
    assert ollama._extract_json("prefix {invalid} suffix") == "{invalid}"
    assert ollama._extract_json('prefix {"quoted": "} [ \\""} suffix')
    assert ollama._extract_json(r"prefix {bad\} still}") == r"{bad\} still}"
    assert ollama._extract_json("prefix {{invalid}} suffix") == "{{invalid}}"
    assert ollama._extract_json('prefix {"unterminated }') == '{"unterminated }'
    assert ollama._extract_json("prefix { no close").startswith("[!] Incomplete")
    assert ollama._extract_json("prefix [ no close").startswith("[!] Incomplete")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('prose {"x": [1, {"y": "z"}]} tail', '{"x": [1, {"y": "z"}]}'),
        ('bad {] then [1,2]', "[1,2]"),
        ('bad {invalid} then {"ok":true}', '{"ok":true}'),
        ('{"escaped":"a\\\"b"}', '{"escaped":"a\\\"b"}'),
        ('text only', ""),
        ('{"open": [1,2}', ""),
    ],
)
def test_first_valid_json_scanner(text, expected) -> None:
    assert ollama._extract_first_valid_json(text) == expected


def test_structured_success_partial_errors_retries_and_exhaustion(monkeypatch) -> None:
    responses = iter(('{"a": 1}', '{"a": 1, "b": 2}'))
    monkeypatch.setattr(ollama, "ask_ollama", lambda *_args, **_kwargs: next(responses))
    assert ollama.ask_ollama_structured("prompt", {"a": "", "b": ""}) == {"a": 1}

    responses = iter(("not json", '{"a": 1}'))
    monkeypatch.setattr(ollama, "ask_ollama", lambda *_args, **_kwargs: next(responses))
    assert ollama.ask_ollama_structured("prompt", {"a": ""}, max_retries=2) == {"a": 1}

    monkeypatch.setattr(ollama, "ask_ollama", lambda *_args, **_kwargs: "not json")
    result = ollama.ask_ollama_structured("prompt", {"a": ""}, max_retries=1)
    assert "Invalid JSON" in result["error"] and result["raw_response"] == "not json"

    responses = iter(("[!] first", "[!] final"))
    monkeypatch.setattr(ollama, "ask_ollama", lambda *_args, **_kwargs: next(responses))
    assert ollama.ask_ollama_structured("prompt", {}, max_retries=2) == {"error": "[!] final"}
    assert ollama.ask_ollama_structured("prompt", {}, max_retries=0) == {
        "error": "Structured query exhausted all retries"
    }

    cancellation = Cancellation(cancelled=True, reason="operator")
    monkeypatch.setattr(ollama, "ask_ollama", lambda *_args, **_kwargs: "[!] cancelled")
    with ollama.bind_ollama_cancellation(cancellation):
        assert ollama.ask_ollama_structured("prompt", {}, max_retries=2) == {
            "error": "[!] cancelled"
        }


def test_stream_generator_options_lines_done_and_error(monkeypatch) -> None:
    monkeypatch.setattr(ollama, "NUM_CTX", 10)
    monkeypatch.setattr(ollama, "NUM_THREAD", 2)
    monkeypatch.setattr(ollama, "NUM_BATCH", 3)
    monkeypatch.setattr(ollama, "NUM_GPU", 4)
    response = Response(
        lines=[
            b"",
            b"invalid",
            *encoded({"response": "first"}, {"response": "", "done": True}),
        ]
    )
    payloads = configure_ask(monkeypatch, [response])
    assert list(ollama.ask_ollama_stream("stream")) == ["first"]
    assert payloads[0]["options"]["num_gpu"] == 4

    response = Response(lines=encoded({"error": "broken"}))
    configure_ask(monkeypatch, [response])
    assert list(ollama.ask_ollama_stream("stream")) == ["\n[!] Error: broken"]

    monkeypatch.setattr(ollama, "NUM_CTX", 0)
    monkeypatch.setattr(ollama, "NUM_THREAD", 0)
    monkeypatch.setattr(ollama, "NUM_BATCH", 0)
    monkeypatch.setattr(ollama, "NUM_GPU", None)
    payloads = configure_ask(monkeypatch, [Response(lines=[])])
    assert list(ollama.ask_ollama_stream("empty")) == []
    assert payloads[0]["options"] == {
        "num_predict": ollama.MAX_TOKENS,
        "temperature": ollama.TEMPERATURE,
        "top_p": ollama.TOP_P,
        "top_k": ollama.TOP_K,
        "repeat_penalty": ollama.REPEAT_PENALTY,
    }


def test_stream_generator_cancellation_and_exception_paths(monkeypatch) -> None:
    cancellation = Cancellation(cancelled=True, reason="before")
    with ollama.bind_ollama_cancellation(cancellation):
        assert list(ollama.ask_ollama_stream("stream")) == [
            "[!] Ollama request cancelled: before."
        ]

    cancellation = Cancellation()

    def cancel_lines():
        cancellation.cancelled = True
        cancellation.reason_code = "during"
        yield from encoded({"response": "never"})

    response = Response()
    response.iter_lines = cancel_lines
    configure_ask(monkeypatch, [response])
    with ollama.bind_ollama_cancellation(cancellation):
        assert list(ollama.ask_ollama_stream("stream")) == [
            "[!] Ollama request cancelled: during."
        ]
    assert response.closed == 1

    cancellation = Cancellation()

    def cancel_without_close():
        cancellation.cancelled = True
        cancellation.reason_code = "no-close"
        yield from encoded({"response": "never"})

    response = Response()
    response.close = None
    response.iter_lines = cancel_without_close
    configure_ask(monkeypatch, [response])
    with ollama.bind_ollama_cancellation(cancellation):
        assert "no-close" in next(ollama.ask_ollama_stream("stream"))

    configure_ask(monkeypatch, [requests.exceptions.RequestException("offline")])
    assert "Connection failed" in next(ollama.ask_ollama_stream("stream"))

    cancellation = Cancellation()

    def cancelled_request(_payload):
        cancellation.cancelled = True
        cancellation.reason_code = "request"
        raise requests.exceptions.RequestException("closed")

    monkeypatch.setattr(ollama, "_post_ollama", cancelled_request)
    with ollama.bind_ollama_cancellation(cancellation):
        assert "request" in next(ollama.ask_ollama_stream("stream"))

    configure_ask(monkeypatch, [RuntimeError("unexpected")])
    with pytest.raises(RuntimeError, match="unexpected"):
        list(ollama.ask_ollama_stream("stream"))

    cancellation = Cancellation()

    def cancelled_generic(_payload):
        cancellation.cancelled = True
        cancellation.reason_code = "generic"
        raise RuntimeError("closed")

    monkeypatch.setattr(ollama, "_post_ollama", cancelled_generic)
    with ollama.bind_ollama_cancellation(cancellation):
        assert "generic" in next(ollama.ask_ollama_stream("stream"))
