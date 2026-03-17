"""0-day mission — API call chain for autonomous vulnerability discovery.

Bounded contexts:
  entrypoint → dataflow → sink → poc

Each context has domain.py (aggregates/entities/VOs), service.py (domain service),
ports.py (driven-side interfaces), and agent.py (Claude sub-agent definition).

The ACL (acl.py) translates between contexts at their boundaries.
"""

from . import dataflow, entrypoint, poc, sink
from .acl import (
    confirmed_sinks_to_poc_projects,
    entry_point_to_source_patterns,
    entry_points_to_taint_session,
    input_vector_to_taint_source,
    sink_analysis_to_poc_project,
    taint_path_to_sink_analysis,
    taint_paths_to_sink_analyses,
)

__all__ = [
    # Sub-packages
    "dataflow",
    "entrypoint",
    "poc",
    "sink",
    # ACL translators
    "confirmed_sinks_to_poc_projects",
    "entry_point_to_source_patterns",
    "entry_points_to_taint_session",
    "input_vector_to_taint_source",
    "sink_analysis_to_poc_project",
    "taint_path_to_sink_analysis",
    "taint_paths_to_sink_analyses",
]
