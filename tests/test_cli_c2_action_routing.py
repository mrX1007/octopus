"""Static routing checks for the CLI C2 boundary (§14.8)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from core.cli import application

pytestmark = [pytest.mark.unit, pytest.mark.contract]


def _application_tree() -> ast.Module:
    return ast.parse(Path(application.__file__).read_text(encoding="utf-8"))


def test_cli_has_no_send_to_daemon() -> None:
    names = {node.name for node in ast.walk(_application_tree()) if isinstance(node, ast.FunctionDef)}
    assert "_send_to_daemon" not in names


def test_cli_queue_task_cannot_call_client_directly() -> None:
    tree = _application_tree()
    forbidden = {"queue_task", "issue_enrollment", "create_channel", "deploy", "cleanup"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in forbidden


def test_cli_c2_action_routing() -> None:
    source = ast.unparse(_application_tree())
    assert "Command:" not in source
    assert "core/c2/builder.py" not in source
    assert "subprocess.Popen" not in source[source.find("def c2_management_menu") :]
