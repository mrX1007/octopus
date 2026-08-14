"""Static ownership checks for the single outbound C2 IPC path (§14.8)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core import c2

pytestmark = [pytest.mark.unit, pytest.mark.contract]


def _python_sources() -> list[Path]:
    roots = (Path(c2.__file__).resolve().parent, Path(c2.__file__).resolve().parents[1] / "cli")
    return sorted(path for root in roots for path in root.rglob("*.py"))


def test_ast_single_outbound_unix_socket_path() -> None:
    outbound_owners: set[Path] = set()
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        has_unix_socket = any(
            isinstance(node, ast.Attribute) and node.attr == "AF_UNIX" for node in ast.walk(tree)
        )
        if not has_unix_socket:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "connect":
                outbound_owners.add(path)
    assert outbound_owners <= {Path(c2.__file__).with_name("client.py")}


def test_single_c2_ipc_path() -> None:
    client = Path(c2.__file__).with_name("client.py")
    assert client in _python_sources()
