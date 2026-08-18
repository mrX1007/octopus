"""Unit tests for AD, Kerberos, and Pivot action adapters and providers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import core.actions.adapters_ad_credential as ad_cred_adapters
import core.actions.adapters_ad_lateral as ad_lat_adapters
import core.actions.adapters_evasion as evasion_adapters
import core.actions.adapters_kerberos as krb_adapters
import core.actions.adapters_pivot as pivot_adapters
import core.providers.ad_credentials as prov_ad_creds
import core.providers.ad_lateral as prov_ad_lat
import core.providers.c2_cleanup as prov_c2_cleanup
import core.providers.c2_deploy as prov_c2_deploy
import core.providers.c2_task as prov_c2_task
import core.providers.kerberos as prov_krb
import core.providers.payload_keying as prov_payload_keying
import core.providers.pivot as prov_pivot


@pytest.mark.unit
def test_ad_credential_adapters_instantiation():
    adapters = [
        ad_cred_adapters.ADPassTheTicketAdapter(),
        ad_cred_adapters.PassTheHashAdapter(),
        ad_cred_adapters.ADDumpLsassAdapter(),
        ad_cred_adapters.ADSamDumpAdapter(),
    ]
    for adapter in adapters:
        assert adapter.action_id.startswith("killchain:")
        assert adapter.descriptor.action_id == adapter.action_id
        assert adapter.adapter_api_version == 2


@pytest.mark.unit
def test_ad_lateral_adapters_instantiation():
    adapters = [
        ad_lat_adapters.ADSmbexecAdapter(),
        ad_lat_adapters.ADWinrmExecAdapter(),
        ad_lat_adapters.ADDcomExecAdapter(),
        ad_lat_adapters.ADRemoteExecutionCapabilityAdapter(),
    ]
    for adapter in adapters:
        assert adapter.action_id.startswith("killchain:")
        assert adapter.descriptor.action_id == adapter.action_id


@pytest.mark.unit
def test_kerberos_adapters_instantiation():
    adapters = [
        krb_adapters.KerberosExtractTicketsAdapter(),
        krb_adapters.KerberosCrackTicketsAdapter(),
    ]
    for adapter in adapters:
        assert adapter.action_id.startswith("killchain:")
        assert adapter.descriptor.action_id == adapter.action_id


@pytest.mark.unit
def test_evasion_and_pivot_adapters_instantiation():
    evasion_ad = evasion_adapters.PayloadKeyingAdapter()
    assert evasion_ad.action_id == "plugin:payload_keying"

    pivot_adapters_list = [
        pivot_adapters.PivotRemoteForwardAdapter(),
        pivot_adapters.PivotSSHChainAdapter(),
        pivot_adapters.PivotProxyScanAdapter(),
    ]
    for adapter in pivot_adapters_list:
        assert adapter.action_id.startswith("killchain:")


@pytest.mark.unit
def test_provider_classes_methods():
    # Test AD Lateral providers
    lat_providers = [
        prov_ad_lat.ADSmbexecAdapter(),
        prov_ad_lat.ADWinRMExecAdapter(),
        prov_ad_lat.ADDComExecAdapter(),
    ]
    for lp in lat_providers:
        assert lp.check_bound("invalid") is False
        assert lp.verify_bound(MagicMock()) is False
        with pytest.raises(prov_ad_lat.ProviderUnavailableError):
            lp.execute_bound(MagicMock())

    router = prov_ad_lat.ADRemoteExecutionRouter()
    assert router.check_bound("invalid") is False
    assert router.verify_bound(MagicMock()) is False
    with pytest.raises(prov_ad_lat.ProviderUnavailableError):
        router.execute_bound(MagicMock())

    # Test AD Credentials providers
    cred_providers = [
        prov_ad_creds.ADPassTheTicketAdapter(),
        prov_ad_creds.PassTheHashAdapter(),
        prov_ad_creds.ADDumpLsassAdapter(),
        prov_ad_creds.ADSamDumpAdapter(),
    ]
    for cp in cred_providers:
        assert cp.verify_bound(MagicMock()) is False
        with pytest.raises(prov_ad_creds.ProviderUnavailableError):
            cp.execute_bound(MagicMock())

    # Test Kerberos providers
    krb_providers = [
        prov_krb.KerberosExtractAdapter(),
        prov_krb.KerberosCrackAdapter(),
    ]
    for kp in krb_providers:
        assert kp.verify_bound(MagicMock()) is False
        with pytest.raises(prov_krb.ProviderUnavailableError):
            kp.execute_bound(MagicMock())

    # Test Pivot providers
    pivot_provs = [
        prov_pivot.PivotRemoteForwardAdapter(),
        prov_pivot.PivotSSHChainAdapter(),
        prov_pivot.PivotProxyScanAdapter(),
    ]
    for pp in pivot_provs:
        assert pp.verify_bound(MagicMock()) is False
        with pytest.raises(prov_pivot.ProviderUnavailableError):
            pp.execute_bound(MagicMock())

    # Test C2 lifecycle providers
    c2_cleanup = prov_c2_cleanup.C2CleanupProvider()
    assert c2_cleanup.check_readiness() is True
    assert c2_cleanup.validate_input({"mission_id": "m1"}) is True
    assert c2_cleanup.validate_input({}) is False
    clean_res = c2_cleanup.execute({"mission_id": "m1"})
    assert clean_res["status"] == "cleaned"

    c2_deploy = prov_c2_deploy.C2DeployProvider()
    assert c2_deploy.check_readiness() is True
    assert c2_deploy.validate_input({}) is False

    c2_task = prov_c2_task.C2TaskProvider()
    assert c2_task.check_readiness() is True
    assert c2_task.validate_input({}) is False
    task_res = c2_task.execute({"agent_ref": "a1", "operation_id": "op1"})
    assert task_res["status"] == "dispatched"

    pk = prov_payload_keying.PayloadKeyingAdapter()
    assert pk.verify_bound(MagicMock()) is False


@pytest.mark.unit
def test_c2_adapters_methods():
    import core.actions.adapters_c2 as c2_adapters

    adapters = [
        c2_adapters.DNSC2ChannelAdapter(),
        c2_adapters.C2EnrollAdapter(),
        c2_adapters.C2DeployAdapter(),
        c2_adapters.C2ChannelCreateAdapter(),
        c2_adapters.C2TaskAdapter(),
        c2_adapters.C2CleanupAdapter(),
    ]
    for adapter in adapters:
        assert adapter.action_id.startswith("c2:")
        assert adapter.check_bound(None) is False
        assert adapter.verify_bound(None, None) is False
        assert adapter.active_risk_class(MagicMock()) is not None
        with pytest.raises(c2_adapters.ProviderUnavailableError, match="provider_unavailable"):
            adapter.execute_bound(None)
