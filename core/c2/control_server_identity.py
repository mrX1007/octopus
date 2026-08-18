"""Control server identity, persistence, and Ed25519 challenge signing/verification (§14.2, §14.3)."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import re
import stat
import uuid
from contextlib import suppress
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from core.c2.control_models import strict_b64url_decode, strict_decode_signature_v2

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
    if len(private_key_bytes) != 32:
        raise ValueError(f"private_key_bytes must be exactly 32 bytes, got {len(private_key_bytes)}")
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
        if len(public_key_bytes) != 32:
            return False
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        transcript = compute_server_challenge_transcript(
            daemon_instance_id=daemon_instance_id,
            server_nonce=server_nonce,
            listener_st_dev=listener_st_dev,
            listener_st_ino=listener_st_ino,
            boot_id=boot_id,
        )
        sig_bytes = strict_decode_signature_v2(signature_b64u)
        pub.verify(sig_bytes, transcript)
        return True
    except Exception:
        return False


def validate_trusted_parent_directory(path: str) -> None:
    """Validate that the parent directory exists, is not a symlink, and has secure permissions."""
    if os.path.islink(path):
        raise RuntimeError(f"symlink parent directory forbidden: {path}")
    parent = Path(path)
    if not parent.exists():
        os.makedirs(parent, mode=0o700, exist_ok=True)
    if os.path.islink(parent):
        raise RuntimeError(f"symlink parent directory forbidden: {parent}")
    if not parent.is_dir():
        raise RuntimeError(f"parent path is not a directory: {parent}")
    st = os.stat(parent)
    # Check permissions: no group/world write
    if st.st_mode & 0o022 != 0:
        raise RuntimeError(f"insecure parent directory permissions: {oct(st.st_mode)}")


def parse_env_daemon_key(val: str) -> bytes:
    """Parse configured environment key into exact 32 bytes without hashing or normalization."""
    stripped = val.strip()
    if len(stripped) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", stripped):
        raw = bytes.fromhex(stripped)
    else:
        try:
            raw = strict_b64url_decode(stripped)
        except Exception as exc:
            raise ValueError("invalid_configured_daemon_key_encoding") from exc
    if len(raw) != 32:
        raise ValueError(f"OCTOPUS_C2_DAEMON_SECRET must decode to exactly 32 bytes, got {len(raw)}")
    return raw


def load_or_persist_service_id(file_path: str) -> str:
    """Load existing service ID or atomically persist a new one fail-closed."""
    parent_dir = os.path.dirname(os.path.abspath(file_path))
    validate_trusted_parent_directory(parent_dir)

    if os.path.islink(file_path):
        raise RuntimeError(f"symlink not allowed for service_id: {file_path}")

    if os.path.exists(file_path):
        st = os.stat(file_path)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"service_id must be a regular file: {file_path}")
        if st.st_mode & 0o077 != 0:
            raise RuntimeError(f"insecure service_id file permissions: {oct(st.st_mode)}")
        with open(file_path, encoding="utf-8") as handle:
            val = handle.read().strip()
        if not val or len(val) < 8 or len(val) > 256 or not re.fullmatch(r"srv_[a-zA-Z0-9_\-]+", val):
            raise RuntimeError("corrupted service_id file")
        return val

    new_id = f"srv_{uuid.uuid4().hex}"
    temp_file = os.path.join(parent_dir, f".tmp_srv_{uuid.uuid4().hex}")
    try:
        fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(new_id)
            handle.flush()
            os.fsync(handle.fileno())

        # Validate temporary file
        st_tmp = os.stat(temp_file)
        if not stat.S_ISREG(st_tmp.st_mode) or st_tmp.st_size == 0:
            raise RuntimeError("temporary service_id validation failed")

        os.replace(temp_file, file_path)

        # Fsync parent directory
        dir_fd = os.open(parent_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        # Reopen and validate final file
        with open(file_path, encoding="utf-8") as handle:
            verified_val = handle.read().strip()
        if verified_val != new_id:
            raise RuntimeError("persisted service_id verification mismatch")
        return new_id
    except Exception as exc:
        if os.path.exists(temp_file):
            with contextlib.suppress(OSError):
                os.unlink(temp_file)
        raise RuntimeError(f"service_id persistence failed: {exc}") from exc


def load_or_persist_daemon_response_key(
    file_path: str,
    env_secret: str | None = None,
    key_id: str = "daemon_resp_key_1",
) -> tuple[str, Ed25519PrivateKey, bytes]:
    """Load or generate Ed25519 response private key and return (key_id, priv_key, pub_bytes)."""
    if env_secret:
        raw_bytes = parse_env_daemon_key(env_secret)
        priv_key = Ed25519PrivateKey.from_private_bytes(raw_bytes)
        pub_bytes = priv_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return key_id, priv_key, pub_bytes

    parent_dir = os.path.dirname(os.path.abspath(file_path))
    validate_trusted_parent_directory(parent_dir)

    if os.path.islink(file_path):
        raise RuntimeError(f"symlink not allowed for daemon key: {file_path}")

    if os.path.exists(file_path):
        st = os.stat(file_path)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"daemon response key must be a regular file: {file_path}")
        if st.st_mode & 0o077 != 0:
            raise RuntimeError(f"insecure daemon response key permissions: {oct(st.st_mode)}")

        with open(file_path, "rb") as handle:
            raw_data = handle.read()

        if len(raw_data) == 32:
            raw_bytes = raw_data
        elif raw_data.startswith(b"OCTOPUS_KEY_V1\n"):
            parts = raw_data.split(b"\n")
            if len(parts) >= 4:
                raw_bytes = base64.b64decode(parts[2])
                checksum = parts[3].decode("ascii")
                if hashlib.sha256(raw_bytes).hexdigest() != checksum:
                    raise RuntimeError("corrupted daemon response key checksum")
            else:
                raise RuntimeError("corrupted daemon response key envelope")
        else:
            raise RuntimeError("corrupted daemon response key file")

        if len(raw_bytes) != 32:
            raise RuntimeError("invalid daemon response key length")

        priv_key = Ed25519PrivateKey.from_private_bytes(raw_bytes)
        pub_bytes = priv_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return key_id, priv_key, pub_bytes

    priv_key = Ed25519PrivateKey.generate()
    raw_bytes = priv_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    temp_file = os.path.join(parent_dir, f".tmp_key_{uuid.uuid4().hex}")
    try:
        fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw_bytes)
            handle.flush()
            os.fsync(handle.fileno())

        st_tmp = os.stat(temp_file)
        if not stat.S_ISREG(st_tmp.st_mode) or st_tmp.st_size != 32:
            raise RuntimeError("temporary daemon response key validation failed")

        os.replace(temp_file, file_path)

        dir_fd = os.open(parent_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        with open(file_path, "rb") as handle:
            verified_bytes = handle.read()
        if verified_bytes != raw_bytes:
            raise RuntimeError("persisted daemon response key verification mismatch")

        pub_bytes = priv_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return key_id, priv_key, pub_bytes
    except Exception as exc:
        if os.path.exists(temp_file):
            with contextlib.suppress(OSError):
                os.unlink(temp_file)
        raise RuntimeError(f"daemon response key persistence failed: {exc}") from exc
