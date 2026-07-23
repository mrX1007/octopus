"""Characterization tests for the pipeline credential synchronization seam."""

import pytest

from core.ai.credential_sync import RuntimeCredentialSynchronizer
from core.credential_ranking import KEY_AUTH_MARKER
from core.credentials import SSH_KEY_AUTH_REF, CredentialRef

pytestmark = [pytest.mark.contract, pytest.mark.security]

HOST = "10.0.0.5"
SSH_PASSWORD_REF = "secret://ssh-password-reference"
MYSQL_PASSWORD_REF = "secret://mysql-password-reference"


def _credential_ref(
    service: str,
    username: str,
    secret_ref: str,
    *,
    auth_kind: str = "password",
) -> CredentialRef:
    return CredentialRef(
        handle=f"credential://{service}-{username}",
        service=service,
        target=HOST,
        username=username,
        secret_ref=secret_ref,
        auth_kind=auth_kind,
    )


def test_runtime_credential_sync_preserves_legacy_fact_rules():
    calls = []
    sync = RuntimeCredentialSynchronizer(register=lambda *args: calls.append(args))

    sync.sync_from_facts(
        f"https://{HOST}:8443/admin",
        [
            {"type": "credential", "value": f"ssh_key_available:root@{HOST}"},
            {"type": "credential", "value": "ssh_key_available:wrong@10.0.0.6"},
            {"type": "credential", "value": f"support:{SSH_PASSWORD_REF} (cached)"},
            {"type": "credential", "value": "ignored:fixture-password (cached)"},
            {"type": "credential", "value": "whm_session:token (cached)"},
            {"type": "service_status", "value": "support:ignored (cached)"},
        ],
    )

    assert calls == [
        ("ssh", HOST, "root", KEY_AUTH_MARKER),
        ("ssh", HOST, "support", SSH_PASSWORD_REF),
    ]


def test_runtime_credential_lookup_normalizes_target_and_degrades_to_empty():
    seen = []
    credential = _credential_ref(
        "ssh",
        "root",
        SSH_KEY_AUTH_REF,
        auth_kind="ssh_key",
    )
    sync = RuntimeCredentialSynchronizer(
        lookup=lambda host: seen.append(host) or {"ssh": [credential]}
    )
    assert sync.known_for_target("https://example.test:443/a") == {"ssh": [credential]}
    assert seen == ["example.test"]

    unavailable = RuntimeCredentialSynchronizer(lookup=lambda _host: (_ for _ in ()).throw(RuntimeError("down")))
    assert unavailable.known_for_target("10.0.0.5") == {}


class _FactStoreSpy:
    def __init__(self):
        self.calls = []
        self._seen = set()

    def add_fact_with_status(self, *args, **kwargs):
        key = args[2:5]
        created = key not in self._seen
        self._seen.add(key)
        self.calls.append((args, kwargs))
        return len(self.calls), created


def test_runtime_credential_seed_preserves_projection_shape_and_idempotence():
    store = _FactStoreSpy()
    sync = RuntimeCredentialSynchronizer()
    credentials = {
        "ssh": [
            _credential_ref(
                "ssh",
                "root",
                SSH_KEY_AUTH_REF,
                auth_kind="ssh_key",
            ),
            _credential_ref("ssh", "support", SSH_PASSWORD_REF),
        ],
        "mysql": [_credential_ref("mysql", "app", MYSQL_PASSWORD_REF)],
    }

    first = sync.seed_known_credentials("scan-1", HOST, store, credentials)
    second = sync.seed_known_credentials("scan-1", HOST, store, credentials)

    assert first.seeded == 3
    assert second.seeded == 0
    projected = [(call[0][2], call[0][3]) for call in store.calls[:3]]
    assert projected == [
        ("credential", f"ssh_key_available:root@{HOST}"),
        ("credential", f"ssh_credential_available:support@{HOST}"),
        ("credential", f"mysql_credential:app@{HOST}"),
    ]
    assert first.announcements == (
        f"ssh://root@{HOST}",
        f"ssh://support@{HOST}",
        f"mysql://app@{HOST}",
    )
    assert SSH_PASSWORD_REF not in repr(store.calls)
    assert MYSQL_PASSWORD_REF not in repr(store.calls)
