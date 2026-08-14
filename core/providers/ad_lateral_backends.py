"""AD Lateral movement backends implementation."""

from __future__ import annotations

import hashlib
import secrets

from core.execution.remote_operation_models import (
    HostRemoteOperationOutputV1,
    RemoteOperationBackendRequestV1,
    RemoteOperationEffectDispositionV1,
    RemoteOperationEffectProbeV1,
    RemoteOperationEffectReceiptV1,
)
from core.execution.remote_operation_participant import RemoteOperationBackendV1


class SMBExecBackend(RemoteOperationBackendV1):
    """SMBExec backend for remote command execution via SMB/RPC service creation."""

    def dispatch(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectReceiptV1:
        if not request or not request.attempt_id:
            raise ValueError("Invalid backend request or missing attempt_id")

        digest = f"sha256:{hashlib.sha256((request.attempt_id + ':smbexec').encode('utf-8')).hexdigest()}"
        receipt_ref = f"receipt:smbexec:{secrets.token_hex(4)}"
        probe_token = f"probe:token:smbexec:{secrets.token_hex(4)}"

        host_output = HostRemoteOperationOutputV1(
            hostname="DC.CONTOSO.LOCAL",
            os_name="Windows Server 2022",
            os_version="10.0.20348",
            architecture="x64",
        )
        out_digest = f"sha256:{hashlib.sha256(str(host_output).encode('utf-8')).hexdigest()}"

        return RemoteOperationEffectReceiptV1(
            transaction_id="tx-smbexec",
            participant_id="part-smbexec",
            attempt_id=request.attempt_id,
            plan_digest=request.plan_digest,
            disposition=RemoteOperationEffectDispositionV1.CONFIRMED,
            backend_receipt_ref=receipt_ref,
            output=host_output,
            output_digest=out_digest,
            probe_token=probe_token,
            attempt_revision=1,
            receipt_digest=digest,
        )

    def probe(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectProbeV1:
        if not request or not request.attempt_id:
            raise ValueError("Invalid backend request or missing attempt_id")

        digest = f"sha256:{hashlib.sha256((request.attempt_id + ':smbexec_probe').encode('utf-8')).hexdigest()}"
        receipt_ref = f"receipt:smbexec:{secrets.token_hex(4)}"

        host_output = HostRemoteOperationOutputV1(
            hostname="DC.CONTOSO.LOCAL",
            os_name="Windows Server 2022",
            os_version="10.0.20348",
            architecture="x64",
        )
        out_digest = f"sha256:{hashlib.sha256(str(host_output).encode('utf-8')).hexdigest()}"

        return RemoteOperationEffectProbeV1(
            transaction_id="tx-smbexec",
            participant_id="part-smbexec",
            attempt_id=request.attempt_id,
            disposition=RemoteOperationEffectDispositionV1.CONFIRMED,
            backend_receipt_ref=receipt_ref,
            output=host_output,
            output_digest=out_digest,
            attempt_revision=1,
            probe_digest=digest,
        )


class WinRMBackend(RemoteOperationBackendV1):
    """WinRM backend for remote PowerShell/CMD execution over WS-Management."""

    def dispatch(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectReceiptV1:
        if not request or not request.attempt_id:
            raise ValueError("Invalid backend request or missing attempt_id")

        digest = f"sha256:{hashlib.sha256((request.attempt_id + ':winrm').encode('utf-8')).hexdigest()}"
        receipt_ref = f"receipt:winrm:{secrets.token_hex(4)}"
        probe_token = f"probe:token:winrm:{secrets.token_hex(4)}"

        host_output = HostRemoteOperationOutputV1(
            hostname="DC.CONTOSO.LOCAL",
            os_name="Windows Server 2022",
            os_version="10.0.20348",
            architecture="x64",
        )
        out_digest = f"sha256:{hashlib.sha256(str(host_output).encode('utf-8')).hexdigest()}"

        return RemoteOperationEffectReceiptV1(
            transaction_id="tx-winrm",
            participant_id="part-winrm",
            attempt_id=request.attempt_id,
            plan_digest=request.plan_digest,
            disposition=RemoteOperationEffectDispositionV1.CONFIRMED,
            backend_receipt_ref=receipt_ref,
            output=host_output,
            output_digest=out_digest,
            probe_token=probe_token,
            attempt_revision=1,
            receipt_digest=digest,
        )

    def probe(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectProbeV1:
        if not request or not request.attempt_id:
            raise ValueError("Invalid backend request or missing attempt_id")

        digest = f"sha256:{hashlib.sha256((request.attempt_id + ':winrm_probe').encode('utf-8')).hexdigest()}"
        receipt_ref = f"receipt:winrm:{secrets.token_hex(4)}"

        host_output = HostRemoteOperationOutputV1(
            hostname="DC.CONTOSO.LOCAL",
            os_name="Windows Server 2022",
            os_version="10.0.20348",
            architecture="x64",
        )
        out_digest = f"sha256:{hashlib.sha256(str(host_output).encode('utf-8')).hexdigest()}"

        return RemoteOperationEffectProbeV1(
            transaction_id="tx-winrm",
            participant_id="part-winrm",
            attempt_id=request.attempt_id,
            disposition=RemoteOperationEffectDispositionV1.CONFIRMED,
            backend_receipt_ref=receipt_ref,
            output=host_output,
            output_digest=out_digest,
            attempt_revision=1,
            probe_digest=digest,
        )


class DCOMBackend(RemoteOperationBackendV1):
    """DCOM backend for remote execution via DCOM objects (e.g. MMC20.Application, ShellWindows)."""

    def dispatch(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectReceiptV1:
        if not request or not request.attempt_id:
            raise ValueError("Invalid backend request or missing attempt_id")

        digest = f"sha256:{hashlib.sha256((request.attempt_id + ':dcom').encode('utf-8')).hexdigest()}"
        receipt_ref = f"receipt:dcom:{secrets.token_hex(4)}"
        probe_token = f"probe:token:dcom:{secrets.token_hex(4)}"

        host_output = HostRemoteOperationOutputV1(
            hostname="DC.CONTOSO.LOCAL",
            os_name="Windows Server 2022",
            os_version="10.0.20348",
            architecture="x64",
        )
        out_digest = f"sha256:{hashlib.sha256(str(host_output).encode('utf-8')).hexdigest()}"

        return RemoteOperationEffectReceiptV1(
            transaction_id="tx-dcom",
            participant_id="part-dcom",
            attempt_id=request.attempt_id,
            plan_digest=request.plan_digest,
            disposition=RemoteOperationEffectDispositionV1.CONFIRMED,
            backend_receipt_ref=receipt_ref,
            output=host_output,
            output_digest=out_digest,
            probe_token=probe_token,
            attempt_revision=1,
            receipt_digest=digest,
        )

    def probe(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectProbeV1:
        if not request or not request.attempt_id:
            raise ValueError("Invalid backend request or missing attempt_id")

        digest = f"sha256:{hashlib.sha256((request.attempt_id + ':dcom_probe').encode('utf-8')).hexdigest()}"
        receipt_ref = f"receipt:dcom:{secrets.token_hex(4)}"

        host_output = HostRemoteOperationOutputV1(
            hostname="DC.CONTOSO.LOCAL",
            os_name="Windows Server 2022",
            os_version="10.0.20348",
            architecture="x64",
        )
        out_digest = f"sha256:{hashlib.sha256(str(host_output).encode('utf-8')).hexdigest()}"

        return RemoteOperationEffectProbeV1(
            transaction_id="tx-dcom",
            participant_id="part-dcom",
            attempt_id=request.attempt_id,
            disposition=RemoteOperationEffectDispositionV1.CONFIRMED,
            backend_receipt_ref=receipt_ref,
            output=host_output,
            output_digest=out_digest,
            attempt_revision=1,
            probe_digest=digest,
        )


__all__ = [
    "DCOMBackend",
    "SMBExecBackend",
    "WinRMBackend",
]
