"""C2 control client."""
from __future__ import annotations

import base64
import time
import uuid
from typing import Any, Dict, Optional
from core.c2.control_commands import (
    C2ControlActionV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlRequestV1,
    ParticipantControlReceiptV1,
    ParticipantControlQuerySnapshotV1,
    BoundedControlErrorV1,
)
from core.c2.control_models import calculate_payload_digest, calculate_request_digest
from core.c2.control_protocol import ControlProtocolCodec
from core.c2.control_signing import ControlSignerV1, ControlVerifierV1


class C2ControlClient:
    """Base interface / abstract class for C2 Control Client."""

    def close(self) -> None:
        pass

    def __enter__(self) -> C2ControlClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class DefaultC2ControlClient(C2ControlClient):
    """Default production implementation of C2ControlClient."""

    def __init__(
        self,
        signer: ControlSignerV1,
        verifier: Optional[ControlVerifierV1] = None,
        codec: Optional[ControlProtocolCodec] = None,
        transport_handler: Any = None,
    ) -> None:
        self.signer = signer
        self.verifier = verifier
        self.codec = codec or ControlProtocolCodec()
        self.transport_handler = transport_handler
        self._is_closed = False

    def send_request(
        self, request: ParticipantControlRequestV1
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Send a signed ParticipantControlRequestV1 and decode response."""
        if self._is_closed:
            raise RuntimeError("Client is closed")

        signed_req = self.signer.sign_participant_request(request)

        encoded_frame = self.codec.encode_request(signed_req)

        if self.transport_handler is not None:
            resp_bytes = self.transport_handler(encoded_frame)
        else:
            # Default in-memory loopback response simulation if no transport provided
            resp_bytes = self._simulated_loopback(signed_req)

        response = self.codec.decode_response(resp_bytes)
        return response

    def execute_action(
        self,
        action: C2ControlActionV1 | str,
        payload: dict | bytes | str,
        mission_id: str,
        subject_id: str,
        transaction_id: str,
        participant_id: str,
        ttl_seconds: float = 300.0,
    ) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Construct, sign, and execute a control action request."""
        act_enum = C2ControlActionV1(action) if isinstance(action, str) else action
        payload_digest = calculate_payload_digest(payload)

        if isinstance(payload, bytes):
            b64u = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
        elif isinstance(payload, str):
            b64u = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8").rstrip("=")
        else:
            import json
            raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
            b64u = base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")

        nonce = uuid.uuid4().hex
        req_digest = calculate_request_digest(
            action=act_enum.value,
            payload_digest=payload_digest,
            mission_id=mission_id,
            subject_id=subject_id,
            nonce=nonce,
        )

        expires_at = time.time() + ttl_seconds
        unsigned_auth = ParticipantControlAuthorizationV1(
            key_id=self.signer.key_id,
            transaction_id=transaction_id,
            participant_id=participant_id,
            mission_id=mission_id,
            subject_id=subject_id,
            action_id=act_enum.value,
            coordinator_revision=1,
            request_digest=req_digest,
            expires_at=expires_at,
            nonce=nonce,
            signature="",
        )

        request = ParticipantControlRequestV1(
            action=act_enum,
            authorization=unsigned_auth,
            payload_schema_id="schema:c2_control_v1",
            payload_digest=payload_digest,
            canonical_payload_b64u=b64u,
        )

        return self.send_request(request)

    def ping(self, mission_id: str, subject_id: str) -> ParticipantControlReceiptV1:
        """Send a PING control request and return receipt."""
        tx_id = f"tx_ping_{uuid.uuid4().hex[:8]}"
        part_id = "participant_daemon"
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

    def _simulated_loopback(self, request: ParticipantControlRequestV1) -> bytes:
        receipt = ParticipantControlReceiptV1(
            transaction_id=request.authorization.transaction_id,
            participant_id=request.authorization.participant_id,
            action=request.action,
            resource_ref=f"ref:{request.authorization.participant_id}",
            resource_revision=1,
            receipt_ref=f"rcpt_{uuid.uuid4().hex[:8]}",
            receipt_digest="digest_ok",
            daemon_instance_id="daemon_inst_0",
            result_payload_schema_id=request.payload_schema_id,
            result_payload_digest=request.payload_digest,
            result_payload_b64u=request.canonical_payload_b64u,
        )
        return self.codec.encode_response(receipt)

