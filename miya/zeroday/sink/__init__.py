"""Sink bounded context — vulnerability classification and exploitability assessment."""

from .agent import create_agent
from .domain import Exploitability, SinkAnalysis, SinkPattern
from .ports import SinkClassifierPort
from .service import SinkService

__all__ = [
    "Exploitability",
    "SinkAnalysis",
    "SinkClassifierPort",
    "SinkPattern",
    "SinkService",
    "create_agent",
]
