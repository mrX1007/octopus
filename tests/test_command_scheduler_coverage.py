"""Residual loop-exit branches for negative-fact command scheduling."""

from __future__ import annotations

import pytest

from core.ai.command_scheduler import CommandScheduler

pytestmark = pytest.mark.unit


def test_nuclei_key_without_a_target_falls_back_to_the_original_command():
    scheduler = CommandScheduler()

    assert scheduler.command_key("nuclei --silent") == "nuclei --silent"


@pytest.mark.parametrize(
    ("command", "fact"),
    [
        (
            "nuclei -u http://host.example",
            {
                "type": "service_status",
                "value": "tool_timeout:nuclei",
                "source": "nuclei http://other.example",
            },
        ),
        (
            "nikto -h http://host.example",
            {
                "type": "service_status",
                "value": "tool_timeout:nikto",
                "source": "nikto http://other.example",
            },
        ),
        (
            "sqlmap --url=http://host.example",
            {
                "type": "service_status",
                "value": "sqlmap_no_get_parameters_found",
                "source": "sqlmap http://other.example",
            },
        ),
    ],
)
def test_nonmatching_negative_fact_sources_exhaust_the_fact_loop(command, fact):
    assert CommandScheduler()._negative_fact_block(command, [fact]) == ""


@pytest.mark.parametrize(
    "command",
    [
        "nikto -h http://host.example",
        "sqlmap --url=http://host.example",
    ],
)
def test_empty_fact_sets_fall_through_each_tool_specific_loop(command):
    assert CommandScheduler()._negative_fact_block(command, []) == ""
