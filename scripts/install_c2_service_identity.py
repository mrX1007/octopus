#!/usr/bin/env python3
"""Installs unique per-install Ed25519 keypair for C2 service identity (§14.2)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    ed25519 = None  # type: ignore


def install_service_identity(
    priv_path: Path = Path("/var/lib/octopus/control-identity/server-ed25519.key"),
    pub_path: Path = Path("/etc/octopus/control-server-ed25519.pub"),
) -> int:
    if ed25519 is None:
        print("cryptography package is required for Ed25519 key generation", file=sys.stderr)
        return 1

    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)

    if priv_path.exists() and pub_path.exists():
        print(f"Service identity already exists at {priv_path}")
        return 0

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_bytes)
    os.chmod(priv_path, 0o600)

    pub_path.write_bytes(pub_bytes)
    os.chmod(pub_path, 0o644)

    print(f"Successfully installed C2 service identity pinned public key to {pub_path}")
    return 0


def main() -> int:
    return install_service_identity()


if __name__ == "__main__":
    sys.exit(main())
