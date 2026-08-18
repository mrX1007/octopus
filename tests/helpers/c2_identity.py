"""Identity and key generator test helpers."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def create_test_keypair() -> tuple[ed25519.Ed25519PrivateKey, bytes, bytes]:
    """Generate a test Ed25519 keypair and return (priv_key, raw_seed_32, pub_bytes_32)."""
    priv = ed25519.Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return priv, seed, pub
