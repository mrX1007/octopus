#!/usr/bin/env python3
"""Credential ranking helpers shared by runtime credential caches."""

from typing import Optional, Sequence, Tuple


KEY_AUTH_MARKER = "__KEY_AUTH__"
Credential = Tuple[str, str]


def credential_rank_key(credential: Credential) -> tuple:
    """Sort key for preferring usable secrets over auth-state markers."""
    user, secret = credential
    username = (user or "").lower()
    secret_value = secret or ""
    is_root = username == "root"
    is_key_marker = secret_value == KEY_AUTH_MARKER
    has_secret = bool(secret_value)

    if is_root and has_secret and not is_key_marker:
        rank = 0
    elif has_secret and not is_key_marker:
        rank = 1
    elif is_root and is_key_marker:
        rank = 2
    elif is_key_marker:
        rank = 3
    elif has_secret:
        rank = 4
    else:
        rank = 5
    return (rank, username, secret_value)


def rank_credentials(credentials: Sequence[Credential]) -> list:
    return sorted(credentials, key=credential_rank_key)


def best_credential(credentials: Sequence[Credential]) -> Tuple[Optional[str], Optional[str]]:
    ranked = rank_credentials(credentials)
    return ranked[0] if ranked else (None, None)
