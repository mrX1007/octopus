"""Exact values and ownership of supporting V2 enums."""

from __future__ import annotations

import pytest

from core.actions.operation_catalog import RemoteExecService
from core.c2.deployment_profiles import (
    C2DeploymentMethod,
    C2DeploymentProfileId,
    C2TargetArch,
    C2TargetOS,
)
from core.c2.resource_types import C2CleanupReason
from core.c2.transport_catalog import C2Transport, DNSRecordType

pytestmark = pytest.mark.unit


def test_remote_exec_service_enum_exact_values_and_single_owner() -> None:
    assert [item.value for item in RemoteExecService] == ["smb", "winrm", "dcom"]


def test_c2_deployment_profile_method_enum_exact_values_and_single_owner() -> None:
    assert [item.value for item in C2DeploymentProfileId] == [
        "deployment://go-agent",
        "deployment://python-agent",
        "deployment://powershell-stager",
    ]
    assert [item.value for item in C2DeploymentMethod] == ["ssh-session"]


def test_dns_record_type_enum_exact_values_and_single_owner() -> None:
    assert [item.value for item in DNSRecordType] == ["TXT", "A"]
    assert [item.value for item in C2Transport] == ["dns"]


def test_c2_cleanup_reason_enum_exact_values_and_single_owner() -> None:
    assert [item.value for item in C2CleanupReason] == [
        "operator-request",
        "mission-teardown",
        "expired",
        "reconciliation",
    ]


def test_c2_target_os_arch_enum_exact_values_and_single_owner() -> None:
    assert [item.value for item in C2TargetOS] == ["linux", "windows", "darwin"]
    assert [item.value for item in C2TargetArch] == ["amd64", "arm64"]
