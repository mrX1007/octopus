#!/usr/bin/env python3
"""Canonical evidence-first AI pipeline API."""

from .fact_store import FactStore
from .ollama_client import ask_ollama
from .pipeline import AIPipeline
from .runtime import DispatchResult, PipelineRuntime

__all__ = [
    "AIPipeline",
    "DispatchResult",
    "FactStore",
    "PipelineRuntime",
    "ask_ollama",
]
