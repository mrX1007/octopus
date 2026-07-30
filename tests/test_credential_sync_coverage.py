"""Remaining optional-boundary coverage for credential synchronization."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import core.credentials as credentials_module
from core.ai.credential_sync import RuntimeCredentialSynchronizer
from core.credentials import CredentialRef

pytestmark = [pytest.mark.contract, pytest.mark.security]


def test_default_register_and_lookup_dependencies_are_loaded_lazily(monkeypatch):
    register = MagicMock()
    lookup = MagicMock(return_value={})
    monkeypatch.setattr(credentials_module, "register_credential", register)
    monkeypatch.setattr(
        credentials_module,
        "get_all_credential_refs_for_target",
        lookup,
    )
    synchronizer = RuntimeCredentialSynchronizer()

    assert synchronizer._register_credential() is register
    assert synchronizer._lookup_credentials() is lookup
    assert synchronizer.known_for_target("https://host.example/path") == {}
    lookup.assert_called_once_with("host.example")


def test_sync_dependency_failure_is_logged_and_ignored(monkeypatch):
    logger = MagicMock()
    synchronizer = RuntimeCredentialSynchronizer(logger=logger)

    def unavailable():
        raise RuntimeError("register unavailable")

    monkeypatch.setattr(synchronizer, "_register_credential", unavailable)

    synchronizer.sync_from_facts("host", [])

    logger.debug.assert_called_once()


def test_seed_skips_non_references_and_empty_usernames():
    logger = MagicMock()
    fact_store = MagicMock()
    synchronizer = RuntimeCredentialSynchronizer(logger=logger)
    empty_user = CredentialRef(
        handle="credential://empty",
        service="ssh",
        target="host",
        username="",
    )

    result = synchronizer.seed_known_credentials(
        "scan",
        "host",
        fact_store,
        {"ssh": [object(), empty_user]},
    )

    assert result.seeded == 0
    assert result.announcements == ()
    logger.warning.assert_called_once()
    fact_store.add_fact_with_status.assert_not_called()
