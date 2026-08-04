"""Hermetic edge coverage for the private diagnostic worker."""

from __future__ import annotations

import runpy
import stat
import sys
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.benchmarks import schema as benchmark_schema
from core.benchmarks.competitors import adapter, diagnostic_worker

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


def _arguments(tmp_path: Path) -> list[str]:
    return [
        "--system",
        "octopus",
        "--scenario",
        str(tmp_path / "scenario.json"),
        "--output",
        str(tmp_path / "result.json"),
    ]


def test_main_success_failure_and_output_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    product_log = tmp_path / "product.log"
    scenario = object()
    result = {"status": "succeeded"}
    writes: list[tuple[Path, object]] = []
    monkeypatch.setattr(
        diagnostic_worker,
        "_initialize_private_log",
        lambda _value: product_log,
    )
    monkeypatch.setattr(diagnostic_worker, "load_scenario", lambda _path: scenario)
    monkeypatch.setattr(
        diagnostic_worker,
        "_run_with_private_capture",
        lambda system, selected, destination: (
            result
            if (system, selected, destination) == ("octopus", scenario, product_log)
            else pytest.fail("unexpected worker inputs")
        ),
    )
    monkeypatch.setattr(
        adapter,
        "_atomic_write_json",
        lambda path, payload: writes.append((path, payload)),
    )

    assert diagnostic_worker.main(_arguments(tmp_path)) == 0
    assert writes == [(tmp_path / "result.json", result)]

    def unavailable_log(_value):
        raise diagnostic_worker.DiagnosticWorkerError("private_log_required")

    failed = {"status": "failed"}
    writes.clear()
    monkeypatch.setattr(diagnostic_worker, "_initialize_private_log", unavailable_log)
    monkeypatch.setattr(adapter, "_failed_result", lambda: failed)
    assert diagnostic_worker.main(_arguments(tmp_path)) == 0
    assert writes == [(tmp_path / "result.json", failed)]
    assert "DiagnosticWorkerError" in capsys.readouterr().err

    def failed_write(_path, _payload) -> None:
        raise OSError("unavailable")

    monkeypatch.setattr(
        diagnostic_worker,
        "_initialize_private_log",
        lambda _value: product_log,
    )
    monkeypatch.setattr(adapter, "_atomic_write_json", failed_write)
    assert diagnostic_worker.main(_arguments(tmp_path)) == 2


def test_module_entrypoint_runs_with_patched_product_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    product_log = private / "product.log"
    captured: list[tuple[Path, object]] = []
    monkeypatch.setenv(
        "OCTOBENCH_DIAGNOSTIC_PRODUCT_LOG",
        str(product_log),
    )
    monkeypatch.setattr(benchmark_schema, "load_scenario", lambda _path: object())
    monkeypatch.setattr(
        adapter,
        "run_product_adapter",
        lambda _system, _scenario: {"status": "succeeded"},
    )
    monkeypatch.setattr(
        adapter,
        "_atomic_write_json",
        lambda path, payload: captured.append((path, payload)),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["diagnostic-worker", *_arguments(tmp_path)],
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_module(
                "core.benchmarks.competitors.diagnostic_worker",
                run_name="__main__",
            )

    assert exc_info.value.code == 0
    assert product_log.is_file()
    assert stat.S_IMODE(product_log.stat().st_mode) == 0o600
    assert captured == [(tmp_path / "result.json", {"status": "succeeded"})]


def test_capture_skips_missing_workspace_log_and_restores_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = {"status": "failed"}

    def bounded(*_args, **_kwargs):
        return outcome

    def product(_system, _scenario):
        return adapter._run_bounded_process(
            ["unused"],
            cwd=tmp_path,
            environment={},
            timeout=1.0,
            max_output=32,
        )

    monkeypatch.setattr(adapter, "_run_bounded_process", bounded)
    monkeypatch.setattr(adapter, "run_product_adapter", product)

    assert (
        diagnostic_worker._run_with_private_capture(
            "octopus",
            object(),
            tmp_path / "product.log",
        )
        is outcome
    )
    assert adapter._run_bounded_process is bounded
    process_log = tmp_path / "process.log"
    assert process_log.read_bytes() == b""
    assert stat.S_IMODE(process_log.stat().st_mode) == 0o600


def test_capture_records_bounded_octopus_outcome_without_changing_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    product_log = diagnostic_worker._initialize_private_log(str(private / "product.log"))
    outcome = adapter.ProductOutcome(
        status="succeeded",
        output_text="private-octopus-outcome",
        duration_seconds=1.0,
    )
    result = {"status": "succeeded", "artifact_refs": ["sha256:fixture"]}

    def run_octopus(*_args, **_kwargs):
        return outcome

    def run_product(system, scenario):
        assert system == "octopus"
        assert scenario is selected_scenario
        observed = adapter._run_octopus(
            scenario,
            "http://127.0.0.1:8080",
            tmp_path,
            1.0,
            7,
        )
        assert observed is outcome
        return result

    selected_scenario = object()
    monkeypatch.setattr(adapter, "_run_octopus", run_octopus)
    monkeypatch.setattr(adapter, "run_product_adapter", run_product)

    captured = diagnostic_worker._run_with_private_capture(
        "octopus",
        selected_scenario,
        product_log,
    )

    assert captured is result
    assert product_log.read_bytes() == b"private"
    assert stat.S_IMODE(product_log.stat().st_mode) == 0o600
    process_log = private / "process.log"
    assert process_log.read_bytes() == b""
    assert stat.S_IMODE(process_log.stat().st_mode) == 0o600
    assert adapter._run_octopus is run_octopus


def test_capture_restores_all_hooks_when_octopus_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    product_log = diagnostic_worker._initialize_private_log(str(private / "product.log"))

    def bounded(*_args, **_kwargs):
        return 0, False, False, "", 0.0

    def run_octopus(*_args, **_kwargs):
        raise RuntimeError("private product failure")

    def run_product(_system, scenario):
        return adapter._run_octopus(
            scenario,
            "http://127.0.0.1:8080",
            tmp_path,
            1.0,
            7,
        )

    monkeypatch.setattr(adapter, "_run_bounded_process", bounded)
    monkeypatch.setattr(adapter, "_run_octopus", run_octopus)
    monkeypatch.setattr(adapter, "run_product_adapter", run_product)
    original_cli = adapter._run_cli_product

    with pytest.raises(RuntimeError, match="private product failure"):
        diagnostic_worker._run_with_private_capture(
            "octopus",
            object(),
            product_log,
        )

    assert adapter._run_bounded_process is bounded
    assert adapter._run_octopus is run_octopus
    assert adapter._run_cli_product is original_cli


def test_capture_restores_all_hooks_when_cli_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    product_log = diagnostic_worker._initialize_private_log(str(private / "product.log"))

    def bounded(*_args, **_kwargs):
        return 0, False, False, "", 0.0

    def run_octopus(*_args, **_kwargs):
        return adapter.ProductOutcome(
            status="failed",
            output_text="",
            duration_seconds=0.0,
        )

    def run_cli(*_args, **_kwargs):
        raise RuntimeError("private cli failure")

    def run_product(_system, scenario):
        return adapter._run_cli_product(
            "strix",
            scenario,
            "http://127.0.0.1:8080",
            "prompt",
            {},
            tmp_path,
            1.0,
            32,
        )

    monkeypatch.setattr(adapter, "_run_bounded_process", bounded)
    monkeypatch.setattr(adapter, "_run_octopus", run_octopus)
    monkeypatch.setattr(adapter, "_run_cli_product", run_cli)
    monkeypatch.setattr(adapter, "run_product_adapter", run_product)

    with pytest.raises(RuntimeError, match="private cli failure"):
        diagnostic_worker._run_with_private_capture(
            "strix",
            object(),
            product_log,
        )

    assert adapter._run_bounded_process is bounded
    assert adapter._run_octopus is run_octopus
    assert adapter._run_cli_product is run_cli


@pytest.mark.parametrize("raw_limit", (True, "32", 0, None))
def test_capture_limit_rejects_nonpositive_or_noninteger_values(raw_limit: object) -> None:
    with pytest.raises(
        diagnostic_worker.DiagnosticWorkerError,
        match="private_capture_limit_invalid",
    ):
        diagnostic_worker._capture_limit(
            (),
            {} if raw_limit is None else {"max_output": raw_limit},
            positional_index=0,
        )


def test_private_log_requires_absolute_path_and_supports_missing_os_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        diagnostic_worker.DiagnosticWorkerError,
        match="private_log_required",
    ):
        diagnostic_worker._initialize_private_log(None)

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    destination = private / "product.log"
    with monkeypatch.context() as scoped:
        scoped.delattr(diagnostic_worker.os, "O_DIRECTORY", raising=False)
        scoped.delattr(diagnostic_worker.os, "O_NOFOLLOW", raising=False)
        initialized = diagnostic_worker._initialize_private_log(str(destination))
        diagnostic_worker._append_private_bytes(initialized, b"diagnostic")

    assert destination.read_bytes() == b"diagnostic"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_private_log_initialization_maps_nonregular_and_parent_open_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "private" / "product.log"
    descriptors = iter((31, 32))
    closed: list[int] = []

    def metadata(descriptor: int):
        mode = stat.S_IFDIR | 0o700 if descriptor == 31 else stat.S_IFIFO | 0o600
        return SimpleNamespace(st_mode=mode)

    with monkeypatch.context() as scoped:
        scoped.setattr(diagnostic_worker.os, "open", lambda *_args, **_kwargs: next(descriptors))
        scoped.setattr(diagnostic_worker.os, "fstat", metadata)
        scoped.setattr(diagnostic_worker.os, "fchmod", lambda *_args: None)
        scoped.setattr(diagnostic_worker.os, "close", closed.append)
        with pytest.raises(
            diagnostic_worker.DiagnosticWorkerError,
            match="private_log_not_regular",
        ):
            diagnostic_worker._initialize_private_log(str(candidate))
    assert closed == [32, 31]

    def unavailable_open(*_args, **_kwargs):
        raise OSError("unavailable")

    with monkeypatch.context() as scoped:
        scoped.setattr(diagnostic_worker.os, "open", unavailable_open)
        with pytest.raises(
            diagnostic_worker.DiagnosticWorkerError,
            match="private_log_unavailable",
        ):
            diagnostic_worker._initialize_private_log(str(candidate))

    descriptors_with_no_parent = iter((None, 33))
    closed.clear()

    def metadata_without_parent(descriptor):
        mode = stat.S_IFDIR | 0o700 if descriptor is None else stat.S_IFREG | 0o600
        return SimpleNamespace(st_mode=mode)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            diagnostic_worker.os,
            "open",
            lambda *_args, **_kwargs: next(descriptors_with_no_parent),
        )
        scoped.setattr(diagnostic_worker.os, "fstat", metadata_without_parent)
        scoped.setattr(diagnostic_worker.os, "fchmod", lambda *_args: None)
        scoped.setattr(diagnostic_worker.os, "close", closed.append)
        assert diagnostic_worker._initialize_private_log(str(candidate)) == candidate
    assert closed == [33]


def test_private_append_rejects_changed_log_and_zero_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "product.log"
    closed: list[int] = []

    with monkeypatch.context() as scoped:
        scoped.setattr(diagnostic_worker.os, "open", lambda *_args: 41)
        scoped.setattr(
            diagnostic_worker.os,
            "fstat",
            lambda _descriptor: SimpleNamespace(st_mode=stat.S_IFREG | 0o644),
        )
        scoped.setattr(diagnostic_worker.os, "close", closed.append)
        with pytest.raises(
            diagnostic_worker.DiagnosticWorkerError,
            match="private_log_changed",
        ):
            diagnostic_worker._append_private_bytes(destination, b"x")
    assert closed == [41]

    closed.clear()
    with monkeypatch.context() as scoped:
        scoped.setattr(diagnostic_worker.os, "open", lambda *_args: 42)
        scoped.setattr(
            diagnostic_worker.os,
            "fstat",
            lambda _descriptor: SimpleNamespace(st_mode=stat.S_IFREG | 0o600),
        )
        scoped.setattr(diagnostic_worker.os, "write", lambda *_args: 0)
        scoped.setattr(diagnostic_worker.os, "close", closed.append)
        with pytest.raises(
            diagnostic_worker.DiagnosticWorkerError,
            match="private_log_write_failed",
        ):
            diagnostic_worker._append_private_bytes(destination, b"x")
    assert closed == [42]
