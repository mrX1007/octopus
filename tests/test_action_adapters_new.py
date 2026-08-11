"""Unit tests for newly added action adapters: AD lateral, C2, and evasion."""

from __future__ import annotations

import pytest

from core.actions.adapters_ad_lateral import (
    ADDcomExecAdapter,
    ADRemoteExecutionCapabilityAdapter,
    ADSmbexecAdapter,
    ADWinrmExecAdapter,
)
from core.actions.adapters_c2 import (
    C2ChannelCreateAdapter,
    C2CleanupAdapter,
    C2DeployAdapter,
    C2EnrollAdapter,
    C2TaskAdapter,
    DNSC2ChannelAdapter,
)
from core.actions.adapters_evasion import PayloadKeyingAdapter
from core.actions.input_contracts import C2ChannelInput, PayloadKeyingInput, RemoteExecInput

pytestmark = [pytest.mark.contract, pytest.mark.security]


def test_ad_lateral_adapters() -> None:
    smb = ADSmbexecAdapter()
    assert smb.descriptor.name == "ad_smbexec"
    assert smb.input_type is RemoteExecInput
    assert smb.capability_class == "lateral_movement"
    assert smb.risk_class == "critical"
    assert "confirmed_ad_access" in smb.required_preconditions
    assert "smb_service_available" in smb.required_preconditions
    assert smb.killchain_stage == "lateral_movement"

    winrm = ADWinrmExecAdapter()
    assert winrm.descriptor.name == "ad_winrm_exec"
    assert winrm.input_type is RemoteExecInput
    assert winrm.capability_class == "lateral_movement"
    assert winrm.risk_class == "critical"
    assert "confirmed_ad_access" in winrm.required_preconditions
    assert "winrm_service_available" in winrm.required_preconditions
    assert winrm.killchain_stage == "lateral_movement"

    dcom = ADDcomExecAdapter()
    assert dcom.descriptor.name == "ad_dcom_exec"
    assert dcom.input_type is RemoteExecInput
    assert dcom.capability_class == "lateral_movement"
    assert dcom.risk_class == "critical"
    assert "confirmed_ad_access" in dcom.required_preconditions
    assert "dcom_service_available" in dcom.required_preconditions
    assert dcom.killchain_stage == "lateral_movement"

    remote_exec = ADRemoteExecutionCapabilityAdapter()
    assert remote_exec.descriptor.name == "ad_remote_execution"
    assert remote_exec.capability_class == "lateral_movement"
    assert remote_exec.risk_class == "critical"

    for adapter in (smb, winrm, dcom, remote_exec):
        assert adapter.descriptor.manual_gate is True
        assert adapter.descriptor.provider_mounted is False


def test_c2_adapters() -> None:
    dns_c2 = DNSC2ChannelAdapter()
    assert dns_c2.descriptor.name == "dns_c2_channel"
    assert dns_c2.input_type is C2ChannelInput
    assert dns_c2.capability_class == "c2"
    assert dns_c2.risk_class == "critical"
    assert dns_c2.killchain_stage == "command_and_control"

    enroll = C2EnrollAdapter()
    assert enroll.descriptor.name == "c2_enroll"
    assert enroll.capability_class == "c2"
    assert enroll.risk_class == "critical"

    deploy = C2DeployAdapter()
    assert deploy.descriptor.name == "c2_deploy"
    assert deploy.capability_class == "c2"
    assert deploy.risk_class == "critical"

    channel_create = C2ChannelCreateAdapter()
    assert channel_create.descriptor.name == "c2_channel_create"
    assert channel_create.capability_class == "c2"
    assert channel_create.risk_class == "critical"

    task = C2TaskAdapter()
    assert task.descriptor.name == "c2_task"
    assert task.capability_class == "c2"
    assert task.risk_class == "high"

    cleanup = C2CleanupAdapter()
    assert cleanup.descriptor.name == "c2_cleanup"
    assert cleanup.capability_class == "c2"
    assert cleanup.risk_class == "medium"

    for adapter in (dns_c2, enroll, deploy, channel_create, task, cleanup):
        assert adapter.descriptor.manual_gate is True
        assert adapter.descriptor.provider_mounted is False


def test_evasion_adapters() -> None:
    keying = PayloadKeyingAdapter()
    assert keying.descriptor.name == "payload_keying"
    assert keying.input_type is PayloadKeyingInput
    assert keying.capability_class == "evasion"
    assert keying.risk_class == "high"
    assert keying.killchain_stage == "weaponization"
    assert keying.descriptor.manual_gate is True
    assert keying.descriptor.provider_mounted is False
