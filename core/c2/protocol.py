"""Explicit C2 wire/API protocol identities.

These are compatibility versions, not the installable application release.
Changing one requires its own migration and wire-vector review.
"""

C2_PROTOCOL_VERSION = "11.0"
C2_SESSION_KDF_CONTEXT = b"octopus-session-v10"

__all__ = ["C2_PROTOCOL_VERSION", "C2_SESSION_KDF_CONTEXT"]
