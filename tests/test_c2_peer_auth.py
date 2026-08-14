"""Peer identity is server-observed and requires an exact UID/GID pair."""

from __future__ import annotations

from dataclasses import fields

import pytest

from core.c2.control_peer import PeerPrincipal

pytestmark = pytest.mark.unit


def test_peer_principal_exact_fields() -> None:
    assert [item.name for item in fields(PeerPrincipal)] == ["pid", "uid", "gid"]


@pytest.mark.parametrize(
    ("pid", "uid", "gid"),
    [(-1, 0, 0), (1, -1, 0), (1, 0, -1), (True, 0, 0)],
)
def test_peer_principal_rejects_invalid_kernel_credentials(
    pid: int,
    uid: int,
    gid: int,
) -> None:
    with pytest.raises(ValueError):
        PeerPrincipal(pid=pid, uid=uid, gid=gid)
