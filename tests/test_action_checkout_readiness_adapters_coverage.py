"""Unit tests for action checkout models, readiness probes, commit, provider call boundary, and remaining adapter classes."""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from core.actions.adapters_ad_credential import (
    ADDumpLsassAdapter,
    ADPassTheTicketAdapter,
    ADSamDumpAdapter,
    PassTheHashAdapter,
)
from core.actions.adapters_ad_lateral import (
    ADDcomExecAdapter,
    ADRemoteExecutionCapabilityAdapter,
    ADSmbexecAdapter,
    ADWinrmExecAdapter,
)
from core.actions.adapters_evasion import (
    PayloadKeyingAdapter,
)
from core.actions.adapters_kerberos import (
    KerberosCrackTicketsAdapter,
    KerberosExtractTicketsAdapter,
)
from core.actions.adapters_pivot import (
    PivotProxyScanAdapter,
    PivotRemoteForwardAdapter,
    PivotSSHChainAdapter,
)
from core.actions.checkout_models import (
    ApprovalCheckoutRequest,
    ExecutionAttemptGroup,
    ExecutorCheckoutRequestBundle,
    FactCheckoutRequest,
    IngressSessionCheckoutRequest,
    MissionCheckoutRequest,
    PrincipalCheckoutRequest,
    ReferenceAccessMode,
    ReferenceCheckoutRequest,
    ReferenceKind,
)
from core.actions.execution_commit import (
    ExecutionCommitCoordinator,
)
from core.actions.execution_commit_participants import (
    ExecutionCommitParticipant,
    ParticipantCommitReceiptV2,
    ParticipantFinalizeReceiptV2,
    ParticipantPrepareResultV2,
    ParticipantStateV2,
)
from core.actions.provider_call_boundary import (
    BoundProviderInvocationContext,
    ProviderCallBoundary,
    _ProviderExecutePhaseLeaseControllerV2,
)
from core.actions.provider_mounts import ProviderMountSnapshotV2
from core.actions.readiness import DependencyStateV2
from core.actions.readiness_probes import (
    BinaryProbe,
    CompositeLeafProbe,
    DaemonProtocolProbe,
    DaemonProtocolStatus,
    PlatformProbe,
    PythonImportProbe,
)
from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeRule,
    TargetScopeSnapshot,
)

pytestmark = pytest.mark.unit


def test_action_adapters_methods_execution():
    adapters = [
        ADPassTheTicketAdapter(),
        PassTheHashAdapter(),
        ADDumpLsassAdapter(),
        ADSamDumpAdapter(),
        ADDcomExecAdapter(),
        ADRemoteExecutionCapabilityAdapter(),
        ADSmbexecAdapter(),
        ADWinrmExecAdapter(),
        PayloadKeyingAdapter(),
        KerberosExtractTicketsAdapter(),
        KerberosCrackTicketsAdapter(),
        PivotProxyScanAdapter(),
        PivotRemoteForwardAdapter(),
        PivotSSHChainAdapter(),
    ]

    for adapter in adapters:
        assert adapter.adapter_api_version == 2
        # Verify bound checks (fail-closed)
        assert adapter.check_bound(None) is False
        assert adapter.verify_bound(None) is False
        with pytest.raises(Exception):
            adapter.execute_bound(None)


def test_checkout_models():
    target = ExtractedActionTarget(
        kind=TargetKind.IPV4,
        role=TargetRole.PRIMARY,
        normalized_value="10.0.0.1",
    )
    ref_req = ReferenceCheckoutRequest(
        reference="cred://1",
        expected_kind=ReferenceKind.CREDENTIAL,
        expected_metadata_revision=1,
        expected_authorization_revision=1,
        required_action_id="c1",
        required_capability="cap1",
        targets=(target,),
        access_mode=ReferenceAccessMode.METADATA_ONLY,
    )
    assert ref_req.reference == "cred://1"

    ingress_req = IngressSessionCheckoutRequest(
        lease_id="l1",
        lease_revision=1,
        bound_request_id="req1",
        ingress_session_ref="sess://1",
        expected_session_revision=1,
        principal_ref="p1",
        expected_principal_revision=1,
        transport_instance_id="t1",
        transport_binding_digest="sha256:d",
    )
    assert ingress_req.lease_id == "l1"

    p_req = PrincipalCheckoutRequest(
        principal_ref="p1",
        expected_revision=1,
        subject_id="s1",
    )
    assert p_req.principal_ref == "p1"

    m_req = MissionCheckoutRequest(
        mission_ref="m1",
        expected_revision=1,
        subject_id="s1",
    )
    assert m_req.mission_ref == "m1"

    app_req = ApprovalCheckoutRequest(
        approval_ref="app1",
        expected_revision=1,
        approval_graph_lease_id="g1",
        execution_graph_id="graph1",
        root_action_id="r1",
        concrete_action_id="c1",
    )
    assert app_req.approval_ref == "app1"

    fact_req = FactCheckoutRequest(
        fact_ref="fact://1",
        expected_revision=1,
        expected_payload_digest="sha256:f",
        required_fact_type="host_info",
        target=target,
    )
    assert fact_req.fact_ref == "fact://1"

    attempt_group = ExecutionAttemptGroup(
        attempt_group_id="att1",
        root_execution_id="root1",
        execution_graph_id="graph1",
    )
    assert attempt_group.attempt_group_id == "att1"

    bundle = ExecutorCheckoutRequestBundle(
        references=(ref_req,),
        ingress_session=ingress_req,
        principal=p_req,
        mission=m_req,
        approval=app_req,
        facts=(fact_req,),
        targets=(target,),
        attempt_group=attempt_group,
    )
    assert bundle.attempt_group.attempt_group_id == "att1"


def test_readiness_probes():
    from core.actions.provider_mounts import DefaultProviderMountRegistry

    reg = DefaultProviderMountRegistry()
    mount = reg.require_v2("killchain:ad_dump_lsass")

    # PythonImportProbe
    py_probe = PythonImportProbe(
        probe_id=mount.spec.readiness_probe_id,
        action_id="killchain:ad_dump_lsass",
        module_names=("sys", "os"),
    )
    obs = py_probe.inspect()
    assert obs.available is True

    snap = py_probe.evaluate(mount)
    assert snap.action_id == "killchain:ad_dump_lsass"
    assert snap.mount_digest == mount.mount_digest

    # BinaryProbe
    bin_probe = BinaryProbe(
        probe_id=mount.spec.readiness_probe_id,
        action_id="killchain:ad_dump_lsass",
        binary_names=("sh",),
    )
    obs_bin = bin_probe.inspect()
    assert obs_bin.available is True

    # PlatformProbe
    plat_probe = PlatformProbe(
        probe_id=mount.spec.readiness_probe_id,
        action_id="killchain:ad_dump_lsass",
        supported_platforms=("darwin", "linux", "win32"),
    )
    obs_plat = plat_probe.inspect()
    assert obs_plat.available is True

    # DaemonProtocolProbe
    def status_cb():
        return DaemonProtocolStatus(
            reachable=True,
            protocol_version="1.0",
            daemon_instance_id="inst1",
            provider_generation="1",
        )

    daemon_probe = DaemonProtocolProbe(
        probe_id=mount.spec.readiness_probe_id,
        action_id="killchain:ad_dump_lsass",
        required_protocol_version="1.0",
        status_supplier=status_cb,
    )
    obs_daemon = daemon_probe.inspect()
    assert obs_daemon.available is True
    assert obs_daemon.daemon_instance_id == "inst1"

    # CompositeLeafProbe
    comp_probe = CompositeLeafProbe(
        probe_id=mount.spec.readiness_probe_id,
        action_id="killchain:ad_dump_lsass",
        leaf_probes=(py_probe, bin_probe),
    )
    obs_comp = comp_probe.inspect()
    assert obs_comp.available is True


def test_commit_coordinator_and_provider_boundary():
    coordinator = ExecutionCommitCoordinator(transaction_id="tx-123")
    assert coordinator.transaction_id == "tx-123"

    mock_part = MagicMock(spec=ExecutionCommitParticipant)
    mock_part.participant_id = "p1"
    mock_part.prepare.return_value = ParticipantPrepareResultV2(
        participant_id="p1",
        state=ParticipantStateV2.PREPARED,
        can_commit=True,
        prepared_digest="sha256:d",
    )
    mock_part.commit_hidden.return_value = ParticipantCommitReceiptV2(
        participant_id="p1",
        committed_digest="sha256:d",
    )
    mock_part.finalize_visibility.return_value = ParticipantFinalizeReceiptV2(
        participant_id="p1",
        finalized_digest="sha256:d",
    )

    coordinator.register_participant(mock_part)
    res = coordinator.execute_commit_protocol()
    assert res is True

    # ProviderCallBoundary
    boundary = ProviderCallBoundary()
    ctx = BoundProviderInvocationContext(
        execution_id="e1",
        action_id="a1",
        transaction_id="tx-123",
        input_dto={"key": "val"},
        materials=(),
    )
    mock_prov = MagicMock()
    mock_prov.verify_bound.return_value = True
    assert boundary.invoke_verify(ctx, mock_prov, {"result": 1}) is True
