#!/usr/bin/env python3
"""Remove only artifacts explicitly registered for a target."""

from __future__ import annotations

import re
import shlex
from typing import Any

from core.killchain.ssh_helpers import _ssh_connect, _ssh_exec
from core.opsec.artifact_mgr import ArtifactManager

_SUCCESS_SENTINEL = "__OCTOPUS_ARTIFACT_REMOVED__"
_FAILURE_SENTINEL = "__OCTOPUS_ARTIFACT_REMOVE_FAILED__"
_SAFE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")


def _safe_text(value: Any, *, max_length: int = 1024) -> str:
    text = str(value or "")
    if not text or len(text) > max_length or any(character in text for character in ("\x00", "\r", "\n")):
        return ""
    return text


def _home_file(path: str, artifact_user: str, session_user: str) -> str:
    """Resolve the two home-relative files that persistence can register."""

    if path != "~/.bashrc" or artifact_user != session_user:
        return ""
    return '"$HOME/.bashrc"'


def _authorized_keys_path(artifact_user: str, session_user: str) -> str:
    if artifact_user == session_user:
        return '"$HOME/.ssh/authorized_keys"'
    if artifact_user == "root" and session_user == "root":
        return "/root/.ssh/authorized_keys"
    return ""


def _filter_line_command(path: str, marker: str, artifact_id: int) -> str:
    temporary = shlex.quote(f"/tmp/.octopus-artifact-cleanup-{artifact_id}")
    needle = shlex.quote(marker)
    return (
        f"if [ -f {path} ]; then "
        f"awk -v needle={needle} 'index($0, needle) == 0' {path} > {temporary} "
        f"&& cat {temporary} > {path} && rm -f -- {temporary}; "
        "else true; fi"
    )


def _artifact_command(artifact: dict[str, Any], session_user: str) -> tuple[str, str]:
    """Return one exact cleanup command and a non-secret description."""

    artifact_id = int(artifact.get("artifact_id") or 0)
    artifact_type = _safe_text(artifact.get("artifact_type") or artifact.get("type"), max_length=32)
    path = _safe_text(artifact.get("path"))
    marker = _safe_text(artifact.get("marker"), max_length=256)
    artifact_user = _safe_text(artifact.get("user"), max_length=64) or session_user

    if artifact_id <= 0:
        return "", "artifact without a stable id"
    if artifact_user and not _SAFE_USER.fullmatch(artifact_user):
        return "", f"artifact {artifact_id}: invalid user"

    if artifact_type == "file" and path:
        return f"rm -f -- {shlex.quote(path)}", f"file {path}"

    if artifact_type == "file_line" and marker:
        remote_path = _home_file(path, artifact_user, session_user)
        if remote_path:
            return _filter_line_command(remote_path, marker, artifact_id), f"registered line in {path}"

    if artifact_type == "ssh_key" and marker:
        remote_path = _authorized_keys_path(artifact_user, session_user)
        if remote_path:
            return _filter_line_command(remote_path, marker, artifact_id), f"registered SSH key for {artifact_user}"

    if artifact_type == "cron" and marker and artifact_user == session_user:
        needle = shlex.quote(marker)
        command = (
            "(crontab -l 2>/dev/null || true) "
            f"| awk -v needle={needle} 'index($0, needle) == 0' | crontab -"
        )
        return command, f"registered crontab line for {artifact_user}"

    if artifact_type == "process" and marker.isdecimal() and int(marker) > 1:
        pid = int(marker)
        command = f"if kill -0 {pid} 2>/dev/null; then kill -- {pid}; else true; fi"
        return command, f"registered process {pid}"

    return "", f"artifact {artifact_id}: unsupported or incomplete {artifact_type!r} record"


def _run_exact_cleanup(client: Any, command: str) -> tuple[bool, str]:
    wrapped = (
        f"({command}) && printf '\\n{_SUCCESS_SENTINEL}\\n' "
        f"|| printf '\\n{_FAILURE_SENTINEL}\\n'"
    )
    result = _ssh_exec(client, wrapped, timeout=10)
    return _SUCCESS_SENTINEL in result and _FAILURE_SENTINEL not in result, result


def stealth_cleanup(host: str, user: str, password: str, port: int = 22) -> str:
    """Clean target-scoped registered artifacts without broad anti-forensics."""

    manager = ArtifactManager(target_ip=host)
    pending = manager.get_pending_cleanups()
    heading = f"[REGISTERED ARTIFACT CLEANUP — {user}@{host}:{port}]"
    if not pending:
        return f"{heading}\n[*] No registered artifacts require cleanup.\n"

    client, error = _ssh_connect(host, user, password, port)
    if not client:
        return f"{heading}\n[!] SSH connection failed: {error}\n"

    cleaned: list[str] = []
    failed: list[str] = []
    try:
        for artifact in pending:
            artifact_id = int(artifact.get("artifact_id") or 0)
            command, description = _artifact_command(artifact, user)
            if not command:
                failed.append(description)
                continue
            succeeded, _result = _run_exact_cleanup(client, command)
            if succeeded:
                manager.mark_cleaned_by_id(artifact_id)
                cleaned.append(description)
            else:
                failed.append(description)
    finally:
        client.close()

    lines = [heading, f"[+] Cleaned registered artifacts: {len(cleaned)}"]
    lines.extend(f"  - {item}" for item in cleaned)
    if failed:
        lines.append(f"[!] Still pending: {len(failed)}")
        lines.extend(f"  - {item}" for item in failed)
    return "\n".join(lines) + "\n"
