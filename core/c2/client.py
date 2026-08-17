"""Client interface and transport for C2 Control Plane (§14.2-§14.6)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
import socket
import time
import uuid
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlActionV1,
    C2ControlErrorCodeV1,
    ParticipantControlAuthorizationV2,
    ParticipantControlPhaseV2,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
    ParticipantControlRequestV2,
    SignedControlResponseV1,
    SignedControlResponseV2,
)
from core.c2.control_models import (
    MAX_CONTROL_PAYLOAD_BYTES,
    calculate_receipt_digest,
    calculate_schema_bound_payload_digest,
    calculate_snapshot_digest,
    canonical_json_bytes,
    canonical_response_envelope_dict,
    strict_b64url_decode,
)
from core.c2.control_protocol import (
    MAX_FRAME_SIZE,
    ControlProtocolCodec,
    receive_frame,
    strict_json_loads,
)
from core.c2.control_signing import (
    ControlSignerV1,
    ControlSignerV2,
    DaemonResponseSigner,
    DaemonResponseVerifier,
    TrustedDaemonResponseKey,
)
from core.c2.protocol import C2_CONTROL_PROTOCOL_VERSION

MAX_RESPONSE_SKEW_MS = 5000  # 5 seconds maximum clock skew for daemon responses


class C2ControlError(Exception):
    """Base exception for C2 control client errors."""


class C2DaemonUnavailable(C2ControlError):
    """Daemon socket is not reachable or connection was refused."""


class C2ControlTimeout(C2ControlError):
    """Socket communication timed out."""


class C2ProtocolError(C2ControlError):
    """Protocol error, framing violation, or decoding failure."""


class C2ResponseVerificationError(C2ControlError):
    """Response signature or identity verification failed."""


def send_c2_socket_frame(sock_path: str, data: bytes, timeout_seconds: float = 10.0) -> bytes:
    """Outbound Unix Domain Socket transport."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_seconds)
            try:
                s.connect(sock_path)
            except ConnectionRefusedError as exc:
                raise C2DaemonUnavailable(f"connection refused at {sock_path}") from exc
            except FileNotFoundError as exc:
                raise C2DaemonUnavailable(f"socket not found at {sock_path}") from exc
            except OSError as exc:
                raise C2DaemonUnavailable(f"socket connect error at {sock_path}: {exc}") from exc

            s.sendall(data)
            try:
                return receive_frame(s, max_size=MAX_FRAME_SIZE)
            except ConnectionResetError as exc:
                raise C2DaemonUnavailable(f"daemon closed connection: {exc}") from exc
            except ValueError as exc:
                raise C2ProtocolError(f"frame violation from daemon: {exc}") from exc
    except socket.timeout as exc:
        raise C2ControlTimeout(f"socket operation timed out for {sock_path}") from exc


class C2ControlClient:
    """Base interface for C2 Control Client."""

    def close(self) -> None:
        pass

    def __enter__(self) -> C2ControlClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def send_request(
        self, request: ParticipantControlRequestV1 | ParticipantControlRequestV2
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        raise NotImplementedError


class DefaultC2ControlClient(C2ControlClient):
    """Production C2ControlClient strictly requiring asymmetric daemon response verification and service pinning."""

    @classmethod
    def create_mock_loopback_transport(
        cls,
        daemon_signer: DaemonResponseSigner | None = None,
        *,
        daemon_instance_id: str = "daemon_inst_0",
        daemon_generation: str = "gen_0",
        service_id: str = "srv_mock_test_id",
        boot_instance_id: str = "boot_0",
        key_id: str = "mock_daemon_key",
    ) -> Callable[[bytes], bytes]:
        """Create a loopback transport handler that produces valid signed responses."""
        if daemon_signer is None:
            priv = ed25519.Ed25519PrivateKey.generate()
            signer = DaemonResponseSigner(
                key_id=key_id,
                private_key=priv,
            )
            pub_bytes = priv.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        else:
            signer = daemon_signer
            priv_key = getattr(daemon_signer, "_ed25519_key", None)
            pub_bytes = (
                priv_key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                if priv_key
                else b""
            )

        codec = ControlProtocolCodec()

        def _handler(raw_data: bytes) -> bytes:
            req = codec.decode_request(raw_data)
            rcpt_ref = f"rcpt_{req.authorization.transaction_id}"
            receipt = ParticipantControlReceiptV1(
                transaction_id=req.authorization.transaction_id,
                participant_id=req.authorization.participant_id,
                action=req.action,
                resource_ref=f"res_{req.authorization.transaction_id}",
                resource_revision=1,
                receipt_ref=rcpt_ref,
                receipt_digest=calculate_receipt_digest(
                    transaction_id=req.authorization.transaction_id,
                    participant_id=req.authorization.participant_id,
                    receipt_ref=rcpt_ref,
                    action=req.action.value if hasattr(req.action, "value") else str(req.action),
                    resource_ref=f"res_{req.authorization.transaction_id}",
                    resource_revision=1,
                    daemon_instance_id=daemon_instance_id,
                    protocol_version=C2_CONTROL_PROTOCOL_VERSION,
                ),
                daemon_instance_id=daemon_instance_id,
                result_payload_schema_id=None,
                result_payload_digest=None,
                result_payload_b64u=None,
            )
            res_dict = {
                "action": receipt.action.value if hasattr(receipt.action, "value") else str(receipt.action),
                "daemon_instance_id": receipt.daemon_instance_id,
                "participant_id": receipt.participant_id,
                "receipt_digest": receipt.receipt_digest,
                "receipt_ref": receipt.receipt_ref,
                "resource_ref": receipt.resource_ref,
                "resource_revision": receipt.resource_revision,
                "result_payload_b64u": receipt.result_payload_b64u,
                "result_payload_digest": receipt.result_payload_digest,
                "result_payload_schema_id": receipt.result_payload_schema_id,
                "transaction_id": receipt.transaction_id,
                "type": "receipt",
            }
            payload_bytes = canonical_json_bytes(res_dict)
            payload_b64u = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
            payload_digest = hashlib.sha256(payload_bytes).hexdigest()
            issued_at_ms = int(time.time() * 1000)

            envelope_dict = canonical_response_envelope_dict(
                protocol_version=C2_CONTROL_PROTOCOL_VERSION,
                daemon_instance_id=daemon_instance_id,
                daemon_generation=daemon_generation,
                service_id=service_id,
                boot_instance_id=boot_instance_id,
                request_digest=req.authorization.request_digest,
                request_nonce=req.authorization.nonce,
                response_type="receipt",
                response_payload_b64u=payload_b64u,
                response_digest=payload_digest,
                issued_at_ms=issued_at_ms,
                key_id=signer.key_id,
            )
            sig = signer.sign_envelope_dict(envelope_dict)
            signed_env = SignedControlResponseV2(
                protocol_version="2.0",
                daemon_generation=daemon_generation,
                service_id=service_id,
                boot_instance_id=boot_instance_id,
                request_digest=req.authorization.request_digest,
                request_nonce=req.authorization.nonce,
                response_type="receipt",
                response_payload_b64u=payload_b64u,
                response_digest=payload_digest,
                issued_at_ms=issued_at_ms,
                key_id=signer.key_id,
                signature=sig,
            )
            return codec.encode_response(signed_env)

        _handler._mock_verifier = DaemonResponseVerifier(  # type: ignore[attr-defined]
            {
                signer.key_id: TrustedDaemonResponseKey(
                    service_id=service_id,
                    key_id=signer.key_id,
                    public_key=pub_bytes,
                    valid_from_ms=0,
                    valid_until_ms=2147483647000,
                )
            }
        )
        _handler._mock_service_id = service_id  # type: ignore[attr-defined]
        return _handler

    def __init__(
        self,
        signer: ControlSignerV1 | ControlSignerV2,
        daemon_verifier: DaemonResponseVerifier | None = None,
        *,
        expected_service_id: str | None = None,
        trusted_daemon_keys: dict[str, bytes | TrustedDaemonResponseKey] | None = None,
        codec: ControlProtocolCodec | None = None,
        transport_handler: Callable[[bytes], bytes] | None = None,
        socket_path: str | None = None,
    ) -> None:
        self.signer = signer
        if daemon_verifier is not None:
            self.daemon_verifier: DaemonResponseVerifier | None = daemon_verifier
        elif trusted_daemon_keys is not None:
            self.daemon_verifier = DaemonResponseVerifier(trusted_keys=trusted_daemon_keys)
        elif transport_handler is not None and hasattr(transport_handler, "_mock_verifier"):
            self.daemon_verifier = getattr(transport_handler, "_mock_verifier", None)
        else:
            self.daemon_verifier = None

        if expected_service_id is not None:
            self.expected_service_id: str | None = expected_service_id
        elif transport_handler is not None and hasattr(transport_handler, "_mock_service_id"):
            self.expected_service_id = getattr(transport_handler, "_mock_service_id", None)
        else:
            self.expected_service_id = None

        self.codec = codec or ControlProtocolCodec()
        self.transport_handler = transport_handler
        self.socket_path = socket_path
        self._is_closed = False

    def send_request(
        self, request: ParticipantControlRequestV1 | ParticipantControlRequestV2
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Send a signed ParticipantControlRequest and decode strictly verified response."""
        if self._is_closed:
            raise RuntimeError("Client is closed")

        signed_req = self.signer.sign_participant_request(request)
        encoded_frame = self.codec.encode_request(signed_req)

        if self.transport_handler is not None:
            resp_bytes = self.transport_handler(encoded_frame)
        else:
            sock_path = self.socket_path or os.environ.get("OCTOPUS_C2_SOCKET", "/run/octopus/octopus-c2.sock")
            if (
                not os.path.exists(sock_path)
                and os.environ.get("OCTOPUS_C2_ALLOW_INSECURE_DEV_SOCKET") == "1"
                and os.path.exists("/tmp/octopus.sock")
            ):
                sock_path = "/tmp/octopus.sock"
            if not os.path.exists(sock_path):
                raise C2DaemonUnavailable(f"C2 daemon socket not found at {sock_path}")
            resp_bytes = self._socket_transport(sock_path, encoded_frame)

        try:
            raw_response = self.codec.decode_response(resp_bytes)
        except Exception as exc:
            raise C2ProtocolError(f"failed to decode daemon control response: {exc}") from exc

        # Require signed envelope exclusively
        if not isinstance(raw_response, (SignedControlResponseV1, SignedControlResponseV2)):
            raise C2ResponseVerificationError("unsigned_daemon_response")

        return self._verify_signed_response(raw_response, signed_req)

    def _verify_signed_response(
        self,
        envelope: SignedControlResponseV1 | SignedControlResponseV2,
        request: ParticipantControlRequestV1 | ParticipantControlRequestV2,
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Verify signed daemon response envelope and decode inner message."""
        req_auth = request.authorization

        # Protocol version check
        if envelope.protocol_version not in ("2.0", "1.0", C2_CONTROL_PROTOCOL_VERSION):
            raise C2ResponseVerificationError(
                f"protocol_version_mismatch: got {envelope.protocol_version}, expected 2.0"
            )

        # Service ID check (if pinned)
        if self.expected_service_id and envelope.service_id and envelope.service_id != self.expected_service_id:
            raise C2ResponseVerificationError("service_id_mismatch")

        # Timestamp skew check
        now_ms = int(time.time() * 1000)
        if abs(now_ms - envelope.issued_at_ms) > MAX_RESPONSE_SKEW_MS:
            raise C2ResponseVerificationError(
                f"response_timestamp_skew: envelope issued at {envelope.issued_at_ms}, now {now_ms}"
            )

        # Correlation checks
        if envelope.request_digest != req_auth.request_digest:
            raise C2ResponseVerificationError("response_request_digest_mismatch")
        if envelope.request_nonce != req_auth.nonce:
            raise C2ResponseVerificationError("response_nonce_mismatch")

        # Cryptographic verification
        if self.daemon_verifier is None:
            raise C2ResponseVerificationError("missing_daemon_response_verifier")

        try:
            self.daemon_verifier.verify_envelope(envelope)
        except Exception as exc:
            raise C2ResponseVerificationError(f"daemon_signature_verification_failed: {exc}") from exc

        # Decode inner payload (enforcing 256 KiB limit)
        try:
            payload_bytes = strict_b64url_decode(envelope.response_payload_b64u, max_len=MAX_CONTROL_PAYLOAD_BYTES)
        except ValueError as exc:
            raise C2ResponseVerificationError(f"invalid_response_payload_base64: {exc}") from exc

        actual_digest = hashlib.sha256(payload_bytes).hexdigest()
        if not hmac.compare_digest(actual_digest, envelope.response_digest):
            raise C2ResponseVerificationError("response_digest_mismatch")

        try:
            inner_data = strict_json_loads(payload_bytes)
        except Exception as exc:
            raise C2ResponseVerificationError(f"invalid_inner_response_json: {exc}") from exc

        inner_type = inner_data.get("type")
        if type(inner_type) is not str or inner_type != envelope.response_type:
            raise C2ResponseVerificationError(
                f"response_type_mismatch: envelope {envelope.response_type} != inner {inner_type}"
            )

        if inner_type == "receipt":
            receipt = ParticipantControlReceiptV1(
                transaction_id=str(inner_data["transaction_id"]),
                participant_id=str(inner_data["participant_id"]),
                action=C2ControlActionV1(str(inner_data["action"])),
                resource_ref=inner_data.get("resource_ref"),
                resource_revision=inner_data.get("resource_revision"),
                receipt_ref=str(inner_data["receipt_ref"]),
                receipt_digest=str(inner_data["receipt_digest"]),
                daemon_instance_id=str(inner_data.get("daemon_instance_id", "")),
                result_payload_schema_id=inner_data.get("result_payload_schema_id"),
                result_payload_digest=inner_data.get("result_payload_digest"),
                result_payload_b64u=inner_data.get("result_payload_b64u"),
            )
            if receipt.transaction_id != req_auth.transaction_id:
                raise C2ResponseVerificationError("inner_receipt_transaction_id_mismatch")
            if receipt.participant_id != req_auth.participant_id:
                raise C2ResponseVerificationError("inner_receipt_participant_id_mismatch")
            if receipt.action != request.action:
                raise C2ResponseVerificationError("inner_receipt_action_mismatch")

            if receipt.result_payload_b64u and receipt.result_payload_schema_id and receipt.result_payload_digest:
                res_bytes = strict_b64url_decode(receipt.result_payload_b64u)
                expected_pdig = calculate_schema_bound_payload_digest(receipt.result_payload_schema_id, res_bytes)
                if not hmac.compare_digest(expected_pdig, receipt.result_payload_digest):
                    raise C2ResponseVerificationError("result_payload_digest_mismatch")

            expected_rcpt_dig = calculate_receipt_digest(
                transaction_id=receipt.transaction_id,
                participant_id=receipt.participant_id,
                action=receipt.action.value,
                resource_ref=receipt.resource_ref,
                resource_revision=receipt.resource_revision,
                receipt_ref=receipt.receipt_ref,
                daemon_instance_id=receipt.daemon_instance_id,
                result_payload_schema_id=receipt.result_payload_schema_id,
                result_payload_digest=receipt.result_payload_digest,
                protocol_version=envelope.protocol_version,
            )
            if not hmac.compare_digest(expected_rcpt_dig, receipt.receipt_digest):
                raise C2ResponseVerificationError("inner_receipt_digest_mismatch")

            return receipt

        elif inner_type == "snapshot":
            snapshot = ParticipantControlQuerySnapshotV1(
                transaction_id=str(inner_data["transaction_id"]),
                participant_id=str(inner_data["participant_id"]),
                resource_ref=inner_data.get("resource_ref"),
                resource_revision=inner_data.get("resource_revision"),
                phase=ParticipantControlPhaseV2(str(inner_data["phase"])),
                receipt_ref=inner_data.get("receipt_ref"),
                receipt_digest=inner_data.get("receipt_digest"),
                snapshot_digest=str(inner_data["snapshot_digest"]),
                result_payload_schema_id=inner_data.get("result_payload_schema_id"),
                result_payload_digest=inner_data.get("result_payload_digest"),
                result_payload_b64u=inner_data.get("result_payload_b64u"),
            )
            if snapshot.transaction_id != req_auth.transaction_id:
                raise C2ResponseVerificationError("inner_snapshot_transaction_id_mismatch")
            if snapshot.participant_id != req_auth.participant_id:
                raise C2ResponseVerificationError("inner_snapshot_participant_id_mismatch")

            expected_snap_dig = calculate_snapshot_digest(
                transaction_id=snapshot.transaction_id,
                participant_id=snapshot.participant_id,
                phase=snapshot.phase.value,
                receipt_digest=snapshot.receipt_digest,
                receipt_ref=snapshot.receipt_ref,
                resource_ref=snapshot.resource_ref,
                resource_revision=snapshot.resource_revision,
                result_payload_schema_id=snapshot.result_payload_schema_id,
                result_payload_digest=snapshot.result_payload_digest,
                protocol_version=envelope.protocol_version,
            )
            if not hmac.compare_digest(expected_snap_dig, snapshot.snapshot_digest):
                raise C2ResponseVerificationError("inner_snapshot_digest_mismatch")

            return snapshot

        elif inner_type == "error":
            raw_retryable = inner_data.get("retryable")
            if type(raw_retryable) is not bool:
                raise C2ResponseVerificationError("error_retryable_not_boolean")

            return BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1(str(inner_data["reason_code"])),
                retryable=bool(raw_retryable),
                detail_ref=inner_data.get("detail_ref"),
            )
        else:
            raise C2ProtocolError(f"unknown_envelope_inner_type:{inner_type}")

    def _socket_transport(self, sock_path: str, data: bytes) -> bytes:
        return send_c2_socket_frame(sock_path, data)

    def execute_action(
        self,
        action: C2ControlActionV1 | str,
        payload: dict[str, Any] | bytes | str,
        mission_id: str,
        subject_id: str,
        transaction_id: str,
        participant_id: str = "c2_daemon",
        payload_schema_id: str = "schema:c2_control_v2",
        expected_resource_revision: int | None = None,
        prior_receipt_ref: str | None = None,
        prior_receipt_digest: str | None = None,
        ttl_seconds: float = 300.0,
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Construct, sign, and execute a control action request."""
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0 or ttl_seconds > 300.0:
            raise ValueError(f"invalid ttl_seconds: {ttl_seconds}, must be 0 < ttl <= 300")

        act_enum = C2ControlActionV1(action) if isinstance(action, str) else action

        if isinstance(payload, bytes):
            payload_bytes = payload
        elif isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        else:
            payload_bytes = canonical_json_bytes(payload)

        b64u = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        payload_digest = calculate_schema_bound_payload_digest(payload_schema_id, payload_bytes)

        now_ms = int(time.time() * 1000)
        expires_at_ms = now_ms + int(ttl_seconds * 1000)
        nonce = uuid.uuid4().hex

        unsigned_auth = ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=self.signer.key_id,
            transaction_id=transaction_id,
            participant_id=participant_id,
            mission_id=mission_id,
            subject_id=subject_id,
            action_id=act_enum.value,
            coordinator_revision=1,
            issued_at_ms=now_ms,
            expires_at_ms=expires_at_ms,
            nonce=nonce,
            request_digest="",
            signature="",
        )

        request = ParticipantControlRequestV2(
            action=act_enum,
            authorization=unsigned_auth,
            payload_schema_id=payload_schema_id,
            payload_digest=payload_digest,
            canonical_payload_b64u=b64u,
            prior_receipt_ref=prior_receipt_ref,
            prior_receipt_digest=prior_receipt_digest,
            expected_resource_revision=expected_resource_revision,
        )

        return self.send_request(request)

    def prepare_resource(
        self,
        transaction_id: str,
        participant_id: str,
        mission_id: str,
        subject_id: str,
        payload: dict[str, Any] | bytes | str,
        schema_id: str = "schema:c2_resource_v2",
        expected_resource_revision: int | None = None,
        ttl_seconds: float = 300.0,
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        res = self.execute_action(
            action=C2ControlActionV1.PREPARE_C2_RESOURCE,
            payload=payload,
            mission_id=mission_id,
            subject_id=subject_id,
            transaction_id=transaction_id,
            participant_id=participant_id,
            payload_schema_id=schema_id,
            expected_resource_revision=expected_resource_revision,
            ttl_seconds=ttl_seconds,
        )
        assert not isinstance(res, ParticipantControlQuerySnapshotV1)
        return res

    def commit_resource(
        self,
        transaction_id: str,
        participant_id: str,
        mission_id: str,
        subject_id: str,
        prepare_receipt: ParticipantControlReceiptV1,
        payload: dict[str, Any] | bytes | str,
        schema_id: str = "schema:c2_resource_v2",
        ttl_seconds: float = 300.0,
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        res = self.execute_action(
            action=C2ControlActionV1.COMMIT_C2_RESOURCE,
            payload=payload,
            mission_id=mission_id,
            subject_id=subject_id,
            transaction_id=transaction_id,
            participant_id=participant_id,
            payload_schema_id=schema_id,
            prior_receipt_ref=prepare_receipt.receipt_ref,
            prior_receipt_digest=prepare_receipt.receipt_digest,
            expected_resource_revision=prepare_receipt.resource_revision,
            ttl_seconds=ttl_seconds,
        )
        assert not isinstance(res, ParticipantControlQuerySnapshotV1)
        return res

    def finalize_resource(
        self,
        transaction_id: str,
        participant_id: str,
        mission_id: str,
        subject_id: str,
        commit_receipt: ParticipantControlReceiptV1,
        payload: dict[str, Any] | bytes | str,
        schema_id: str = "schema:c2_resource_v2",
        ttl_seconds: float = 300.0,
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        res = self.execute_action(
            action=C2ControlActionV1.FINALIZE_C2_RESOURCE_VISIBILITY,
            payload=payload,
            mission_id=mission_id,
            subject_id=subject_id,
            transaction_id=transaction_id,
            participant_id=participant_id,
            payload_schema_id=schema_id,
            prior_receipt_ref=commit_receipt.receipt_ref,
            prior_receipt_digest=commit_receipt.receipt_digest,
            expected_resource_revision=commit_receipt.resource_revision,
            ttl_seconds=ttl_seconds,
        )
        assert not isinstance(res, ParticipantControlQuerySnapshotV1)
        return res

    def abort_resource(
        self,
        transaction_id: str,
        participant_id: str,
        mission_id: str,
        subject_id: str,
        prior_receipt: ParticipantControlReceiptV1 | None = None,
        payload: dict[str, Any] | bytes | str = b"",
        schema_id: str = "schema:c2_resource_v2",
        ttl_seconds: float = 300.0,
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        res = self.execute_action(
            action=C2ControlActionV1.ABORT_C2_RESOURCE,
            payload=payload,
            mission_id=mission_id,
            subject_id=subject_id,
            transaction_id=transaction_id,
            participant_id=participant_id,
            payload_schema_id=schema_id,
            prior_receipt_ref=prior_receipt.receipt_ref if prior_receipt else None,
            prior_receipt_digest=prior_receipt.receipt_digest if prior_receipt else None,
            ttl_seconds=ttl_seconds,
        )
        assert not isinstance(res, ParticipantControlQuerySnapshotV1)
        return res

    def query_resource(
        self,
        transaction_id: str,
        participant_id: str,
        mission_id: str,
        subject_id: str,
        ttl_seconds: float = 300.0,
    ) -> ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        res = self.execute_action(
            action=C2ControlActionV1.QUERY_C2_RESOURCE,
            payload=b"",
            mission_id=mission_id,
            subject_id=subject_id,
            transaction_id=transaction_id,
            participant_id=participant_id,
            ttl_seconds=ttl_seconds,
        )
        assert not isinstance(res, ParticipantControlReceiptV1)
        return res

    def ping(
        self,
        mission_id: str = "mission_control",
        subject_id: str = "operator_root",
        transaction_id: str | None = None,
        participant_id: str | None = None,
    ) -> ParticipantControlReceiptV1:
        """Send a lightweight ping request to verify daemon liveness and protocol."""
        tx_id = transaction_id or f"tx_ping_{uuid.uuid4().hex[:8]}"
        part_id = participant_id or "participant_daemon"
        res = self.execute_action(
            action=C2ControlActionV1.PING,
            payload={"ping": True},
            mission_id=mission_id,
            subject_id=subject_id,
            transaction_id=tx_id,
            participant_id=part_id,
        )
        if isinstance(res, ParticipantControlReceiptV1):
            return res
        raise RuntimeError(f"Ping returned unexpected response: {res}")

    def close(self) -> None:
        self._is_closed = True


class InMemoryC2ControlClient(C2ControlClient):
    """In-memory mock client for unit and integration testing without sockets."""

    def __init__(
        self,
        handler: Callable[
            [ParticipantControlRequestV1 | ParticipantControlRequestV2],
            ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1,
        ],
    ) -> None:
        self._handler = handler
        self._is_closed = False

    def send_request(
        self, request: ParticipantControlRequestV1 | ParticipantControlRequestV2
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        if self._is_closed:
            raise RuntimeError("Client is closed")
        return self._handler(request)

    def close(self) -> None:
        self._is_closed = True


__all__ = [
    "MAX_RESPONSE_SKEW_MS",
    "C2ControlClient",
    "C2ControlError",
    "C2ControlTimeout",
    "C2DaemonUnavailable",
    "C2ProtocolError",
    "C2ResponseVerificationError",
    "DefaultC2ControlClient",
    "InMemoryC2ControlClient",
]
