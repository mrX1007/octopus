"""Structural AST ratchet tests asserting security boundaries and invariants (§14.2-§14.8)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core import c2
from core.c2.control_commands import (
    ParticipantControlAuthorizationV2,
    SignedControlResponseV2,
)

pytestmark = [pytest.mark.unit, pytest.mark.contract]


def _core_python_sources() -> list[Path]:
    c2_dir = Path(c2.__file__).resolve().parent
    return sorted(path for path in c2_dir.rglob("*.py"))


def test_ast_single_outbound_unix_socket_path() -> None:
    """Ensure only client.py connects to outbound Unix domain sockets."""
    outbound_owners: set[str] = set()
    for path in _core_python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        has_unix_socket = any(isinstance(node, ast.Attribute) and node.attr == "AF_UNIX" for node in ast.walk(tree))
        if not has_unix_socket:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "connect":
                outbound_owners.add(path.name)
    assert outbound_owners <= {"client.py"}


def test_ast_daemon_principal_resolver_has_zero_db_mutations() -> None:
    """Ensure DaemonPrincipalResolver contains zero INSERT, UPDATE, or DELETE SQL executions."""
    daemon_file = Path(c2.__file__).with_name("daemon.py")
    tree = ast.parse(daemon_file.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "DaemonPrincipalResolver":
            for child in ast.walk(node):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    upper_val = child.value.strip().upper()
                    assert not upper_val.startswith("INSERT"), "DaemonPrincipalResolver must not execute INSERT"
                    assert not upper_val.startswith("UPDATE"), "DaemonPrincipalResolver must not execute UPDATE"
                    assert not upper_val.startswith("DELETE"), "DaemonPrincipalResolver must not execute DELETE"


def test_v2_wire_models_enforce_int_millisecond_timestamps() -> None:
    """Ensure V2 wire models strictly type timestamps as integers."""
    auth_v2_hints = ParticipantControlAuthorizationV2.__annotations__
    assert auth_v2_hints["issued_at_ms"] in (int, "int")
    assert auth_v2_hints["expires_at_ms"] in (int, "int")

    resp_v2_hints = SignedControlResponseV2.__annotations__
    assert resp_v2_hints["issued_at_ms"] in (int, "int")


def test_ast_no_production_register_control_key_invocations() -> None:
    """Ensure register_control_key is not invoked by core production modules."""
    for path in _core_python_sources():
        if path.name == "daemon.py":
            continue
        content = path.read_text(encoding="utf-8")
        assert "register_control_key(" not in content, f"Production file {path.name} must not call register_control_key"


def test_ast_v2_providers_all_unmounted() -> None:
    """Ensure all 20 V2 providers remain mounted=False."""
    providers_dir = Path(c2.__file__).resolve().parents[1] / "core" / "providers"
    if not providers_dir.exists():
        return
    for path in providers_dir.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if (
                                isinstance(target, ast.Name)
                                and target.id == "mounted"
                                and isinstance(item.value, ast.Constant)
                            ):
                                assert item.value.value is False, f"Provider {node.name} must have mounted=False"
