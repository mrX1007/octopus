"""Characterization tests for the pipeline credential synchronization seam."""

from core.ai.credential_sync import RuntimeCredentialSynchronizer


def test_runtime_credential_sync_preserves_legacy_fact_rules():
    calls = []
    sync = RuntimeCredentialSynchronizer(register=lambda *args: calls.append(args))

    sync.sync_from_facts(
        "https://10.0.0.5:8443/admin",
        [
            {"type": "credential", "value": "ssh_key_available:root@10.0.0.5"},
            {"type": "credential", "value": "ssh_key_available:wrong@10.0.0.6"},
            {"type": "credential", "value": "support:fixture-password (cached)"},
            {"type": "credential", "value": "whm_session:token (cached)"},
            {"type": "service_status", "value": "support:ignored (cached)"},
        ],
    )

    assert calls == [
        ("ssh", "10.0.0.5", "root", "__KEY_AUTH__"),
        ("ssh", "10.0.0.5", "support", "fixture-password"),
    ]


def test_runtime_credential_lookup_normalizes_target_and_degrades_to_empty():
    seen = []
    sync = RuntimeCredentialSynchronizer(
        lookup=lambda host: seen.append(host) or {"ssh": [("root", "__KEY_AUTH__")]}
    )
    assert sync.known_for_target("https://example.test:443/a") == {
        "ssh": [("root", "__KEY_AUTH__")]
    }
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
        "ssh": [("root", "__KEY_AUTH__"), ("support", "fixture-password")],
        "mysql": [("app", "db-secret")],
    }

    first = sync.seed_known_credentials("scan-1", "10.0.0.5", store, credentials)
    second = sync.seed_known_credentials("scan-1", "10.0.0.5", store, credentials)

    assert first.seeded == 3
    assert second.seeded == 0
    projected = [(call[0][2], call[0][3]) for call in store.calls[:3]]
    assert projected == [
        ("credential", "ssh_key_available:root@10.0.0.5"),
        ("credential", "support:fixture-password (cached)"),
        ("credential", "mysql_credential:app@10.0.0.5"),
    ]
    assert first.announcements == (
        "ssh://root@10.0.0.5",
        "ssh://support@10.0.0.5",
        "mysql://app@10.0.0.5",
    )
