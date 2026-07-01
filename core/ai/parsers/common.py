#!/usr/bin/env python3

from typing import Any, Dict, List


Fact = Dict[str, Any]


def fact(fact_type: str, value: str, confidence: int, session_id: str) -> Fact:
    return {
        "type": fact_type,
        "value": str(value)[:500],
        "confidence": confidence,
        "session_id": session_id,
    }


def tool_lower(tool_name: str) -> str:
    return (tool_name or "").strip().lower()


def raw_lower(raw_output: str) -> str:
    return (raw_output or "").lower()


class BaseParser:
    family = "base"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Fact]:
        return []
