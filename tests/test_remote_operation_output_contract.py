from __future__ import annotations

import pytest

from core.execution.remote_operation_models import (
    IdentityRemoteOperationOutputV1,
    HostRemoteOperationOutputV1,
    NetworkRemoteOperationOutputV1,
    NetworkInterfaceOutputV1,
    ServiceRemoteOperationOutputV1,
    ServiceStatusOutputV1,
    RemoteOperationOutputReservationRefV1,
)
from core.execution.remote_operation_store import DefaultRemoteOperationStoreV1

pytestmark = pytest.mark.unit


def test_remote_operation_output_dataclasses() -> None:
    identity = IdentityRemoteOperationOutputV1(
        principal_name="admin",
        domain_name="corp.local",
        machine_name="dc01",
    )
    assert identity.principal_name == "admin"
    assert identity.domain_name == "corp.local"
    assert identity.machine_name == "dc01"

    host = HostRemoteOperationOutputV1(
        hostname="srv01",
        os_name="Windows Server",
        os_version="2022",
        architecture="x64",
    )
    assert host.hostname == "srv01"
    assert host.architecture == "x64"

    net_if = NetworkInterfaceOutputV1(name="eth0", addresses=("192.168.1.50",))
    net = NetworkRemoteOperationOutputV1(
        interfaces=(net_if,),
        routes=("0.0.0.0/0 via 192.168.1.1",),
        connections=("192.168.1.50:445 -> 192.168.1.10:49152",),
    )
    assert len(net.interfaces) == 1
    assert net.interfaces[0].addresses[0] == "192.168.1.50"

    svc_status = ServiceStatusOutputV1(service_name="LanmanServer", state="Running", start_mode="Auto")
    svc = ServiceRemoteOperationOutputV1(services=(svc_status,))
    assert svc.services[0].service_name == "LanmanServer"


def test_remote_operation_store_reserve() -> None:
    store = DefaultRemoteOperationStoreV1()

    ref1 = store.reserve_output_schema(
        transaction_id="tx-101",
        operation_id="op-201",
        schema_id="host_schema_v1",
    )
    assert isinstance(ref1, RemoteOperationOutputReservationRefV1)
    assert ref1.transaction_id == "tx-101"
    assert ref1.operation_id == "op-201"
    assert ref1.output_schema_id == "host_schema_v1"
    assert ref1.reservation_revision == 1
    assert len(ref1.reservation_digest) > 0

    # Reserve again for same transaction and operation -> revision increments
    ref2 = store.reserve_output_schema(
        transaction_id="tx-101",
        operation_id="op-201",
        schema_id="host_schema_v1",
    )
    assert ref2.reservation_revision == 2
    assert ref2.reservation_digest != ref1.reservation_digest


def test_remote_operation_store_validation_and_get() -> None:
    store = DefaultRemoteOperationStoreV1()
    ref = store.reserve_output_schema("tx-102", "op-202", "schema_net")

    retrieved = store.get_reservation("tx-102", "op-202")
    assert retrieved == ref
    assert store.validate_reservation(ref) is True

    # Tampered ref
    tampered_ref = RemoteOperationOutputReservationRefV1(
        reference=ref.reference,
        transaction_id=ref.transaction_id,
        operation_id=ref.operation_id,
        output_schema_id=ref.output_schema_id,
        reservation_revision=99,
        reservation_digest=ref.reservation_digest,
    )
    assert store.validate_reservation(tampered_ref) is False


def test_remote_operation_store_record_and_get_output() -> None:
    store = DefaultRemoteOperationStoreV1()
    ref = store.reserve_output_schema("tx-103", "op-203", "schema_identity")

    output_payload = {"principal": "admin", "machine": "target01"}
    output_digest = "sha256-payload-digest-123"

    success = store.record_output(ref, output_payload, output_digest)
    assert success is True

    stored_output = store.get_output("tx-103", "op-203")
    assert stored_output is not None
    assert stored_output["output"] == output_payload
    assert stored_output["output_digest"] == output_digest

    # Try recording output for invalid ref
    fake_ref = RemoteOperationOutputReservationRefV1(
        reference="fake",
        transaction_id="tx-999",
        operation_id="op-999",
        output_schema_id="fake_schema",
        reservation_revision=1,
        reservation_digest="fake-digest",
    )
    assert store.record_output(fake_ref, output_payload, output_digest) is False


def test_remote_operation_store_invalid_inputs_and_clear() -> None:
    store = DefaultRemoteOperationStoreV1()

    with pytest.raises(ValueError):
        store.reserve_output_schema("", "op-1", "schema-1")

    with pytest.raises(ValueError):
        store.reserve_output_schema("tx-1", "", "schema-1")

    with pytest.raises(ValueError):
        store.reserve_output_schema("tx-1", "op-1", "")

    ref = store.reserve_output_schema("tx-104", "op-204", "schema_svc")
    store.clear()
    assert store.get_reservation("tx-104", "op-204") is None
    assert store.get_output("tx-104", "op-204") is None
    assert store.validate_reservation(ref) is False
