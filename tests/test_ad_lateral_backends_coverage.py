"""Test coverage for AD lateral movement backend implementations."""

from __future__ import annotations

import pytest

from core.execution.remote_operation_models import (
    RemoteOperationBackendRequestV1,
    RemoteOperationEffectDispositionV1,
)
from core.providers.ad_lateral_backends import (
    DCOMBackend,
    SMBExecBackend,
    WinRMBackend,
)


@pytest.mark.unit
def test_ad_lateral_backends_dispatch_and_probe():
    req = RemoteOperationBackendRequestV1(
        attempt_id="att-test-1234",
        idempotency_key="idem-key-1",
        plan_ref={"command": "whoami"},
        plan_digest="sha256:" + "a" * 64,
        absolute_deadline_monotonic=1000.0,
    )

    for backend_cls in [SMBExecBackend, WinRMBackend, DCOMBackend]:
        backend = backend_cls()

        # Dispatch
        receipt = backend.dispatch(req)
        assert receipt.attempt_id == "att-test-1234"
        assert receipt.disposition == RemoteOperationEffectDispositionV1.CONFIRMED
        assert receipt.output.hostname == "DC.CONTOSO.LOCAL"
        assert receipt.receipt_digest.startswith("sha256:")

        # Probe
        probe = backend.probe(req)
        assert probe.attempt_id == "att-test-1234"
        assert probe.disposition == RemoteOperationEffectDispositionV1.CONFIRMED
        assert probe.probe_digest.startswith("sha256:")


@pytest.mark.unit
def test_ad_lateral_backends_validation_errors():
    for backend_cls in [SMBExecBackend, WinRMBackend, DCOMBackend]:
        backend = backend_cls()
        with pytest.raises(ValueError, match="Invalid backend request"):
            backend.dispatch(None)  # type: ignore[arg-type]

        empty_req = RemoteOperationBackendRequestV1(
            attempt_id="",
            idempotency_key="key",
            plan_ref=None,
            plan_digest="",
            absolute_deadline_monotonic=1000.0,
        )
        with pytest.raises(ValueError, match="missing attempt_id"):
            backend.dispatch(empty_req)

        with pytest.raises(ValueError, match="Invalid backend request"):
            backend.probe(None)  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="missing attempt_id"):
            backend.probe(empty_req)
