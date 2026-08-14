"""Control server identity and Ed25519 challenge signing/verification (§14.2, §14.3)."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN_SEPARATOR = "OCTOPUS-C2-SERVER-CHALLENGE-V1"


def compute_server_challenge_transcript(
    daemon_instance_id: str,
    server_nonce: str,
    listener_st_dev: int,
    listener_st_ino: int,
    boot_id: str,
) -> bytes:
    """Compute domain-separated transcript for server challenge signing."""
    transcript = f"{DOMAIN_SEPARATOR}:{daemon_instance_id}:{server_nonce}:{listener_st_dev}:{listener_st_ino}:{boot_id}"
    return transcript.encode("utf-8")


def generate_server_identity_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 server identity keypair (private_raw, public_raw)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def sign_server_challenge(
    private_key_bytes: bytes,
    daemon_instance_id: str,
    server_nonce: str,
    listener_st_dev: int,
    listener_st_ino: int,
    boot_id: str,
) -> str:
    """Sign the server challenge transcript and return base64url signature."""
    priv = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    transcript = compute_server_challenge_transcript(
        daemon_instance_id=daemon_instance_id,
        server_nonce=server_nonce,
        listener_st_dev=listener_st_dev,
        listener_st_ino=listener_st_ino,
        boot_id=boot_id,
    )
    sig = priv.sign(transcript)
    return base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


def verify_server_challenge(
    public_key_bytes: bytes,
    signature_b64u: str,
    daemon_instance_id: str,
    server_nonce: str,
    listener_st_dev: int,
    listener_st_ino: int,
    boot_id: str,
) -> bool:
    """Verify the server challenge signature using pinned public key."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        transcript = compute_server_challenge_transcript(
            daemon_instance_id=daemon_instance_id,
            server_nonce=server_nonce,
            listener_st_dev=listener_st_dev,
            listener_st_ino=listener_st_ino,
            boot_id=boot_id,
        )
        # Pad base64url string if needed
        padding = "=" * ((4 - len(signature_b64u) % 4) % 4)
        sig_bytes = base64.urlsafe_b64decode(signature_b64u + padding)
        pub.verify(sig_bytes, transcript)
        return True
    except Exception:
        return False
