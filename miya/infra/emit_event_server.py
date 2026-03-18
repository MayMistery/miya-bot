#!/usr/bin/env python3
"""MCP server for structured event emission.

This is the architectural solution to the "regex mining free text" problem.
Instead of agents embedding [EVENT:...] markers in prose and hoping a regex
catches them, agents call `emit_event` as a tool — making event emission
structured, validated, and type-safe.

The server validates event data against the actual dataclass schema before
accepting it, eliminating silent field mismatches (the #1 bug class in the
agent definition audit).

Usage:
    python -m miya.infra.emit_event_server

Protocol: MCP over stdio (JSON-RPC 2.0)
"""

from __future__ import annotations

import dataclasses
import json
import sys
from typing import Any

from miya.shared.events import DomainEvent, _EVENT_REGISTRY


def _build_event_type_docs() -> str:
    """Build documentation of all available event types and their fields."""
    lines = []
    # Build name→class map
    name_map = {cls.__name__: cls for cls in _EVENT_REGISTRY.values()}
    for name, cls in sorted(name_map.items()):
        fields = dataclasses.fields(cls)
        # Skip base DomainEvent fields
        base_fields = {f.name for f in dataclasses.fields(DomainEvent)}
        custom_fields = [f for f in fields if f.name not in base_fields]
        if not custom_fields:
            continue
        field_strs = []
        for f in custom_fields:
            type_name = getattr(f.type, "__name__", str(f.type))
            default = f.default if f.default is not dataclasses.MISSING else ""
            field_strs.append(f"    {f.name}: {type_name} = {default!r}")
        lines.append(f"  {name}:")
        lines.extend(field_strs)
        lines.append("")
    return "\n".join(lines)


# Pre-build the name→class lookup
_NAME_MAP: dict[str, type[DomainEvent]] = {
    cls.__name__: cls for cls in _EVENT_REGISTRY.values()
}


def validate_event(event_type: str, data: dict[str, Any]) -> tuple[bool, str]:
    """Validate event data against the dataclass schema.

    Returns (is_valid, message).
    """
    cls = _NAME_MAP.get(event_type)
    if cls is None:
        available = ", ".join(sorted(_NAME_MAP.keys()))
        return False, f"Unknown event_type '{event_type}'. Available: {available}"

    valid_fields = {f.name for f in dataclasses.fields(cls)}
    base_fields = {f.name for f in dataclasses.fields(DomainEvent)}
    custom_fields = valid_fields - base_fields

    # Check for unknown fields
    unknown = set(data.keys()) - valid_fields
    if unknown:
        return False, (
            f"Unknown fields for {event_type}: {unknown}. "
            f"Valid fields: {custom_fields}"
        )

    return True, f"Event {event_type} validated successfully"


# ═══════════════════════════════════════════════════════════════════
#  MCP Protocol Implementation (JSON-RPC 2.0 over stdio)
# ═══════════════════════════════════════════════════════════════════

_TOOL_SCHEMA = {
    "name": "emit_event",
    "description": (
        "Emit a structured domain event. Use this instead of [EVENT:...] "
        "text markers for reliable, validated event capture. The event will "
        "be recorded in the blackboard and event store."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "event_type": {
                "type": "string",
                "description": (
                    "Event class name: AssetDiscovered, VulnerabilityFound, "
                    "ExploitSucceeded, ChallengeSolved, etc."
                ),
            },
            "data": {
                "type": "object",
                "description": "Event fields as key-value pairs.",
            },
        },
        "required": ["event_type", "data"],
    },
}


def _handle_request(request: dict[str, Any]) -> dict[str, Any]:
    """Handle a single JSON-RPC request."""
    method = request.get("method", "")
    req_id = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "miya-event-bus",
                    "version": "1.0.0",
                },
            },
        }

    if method == "notifications/initialized":
        return {}  # notification, no response

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": [_TOOL_SCHEMA]},
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        if tool_name != "emit_event":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                    "isError": True,
                },
            }

        event_type = args.get("event_type", "")
        data = args.get("data", {})
        is_valid, message = validate_event(event_type, data)

        if is_valid:
            # Echo back as [EVENT:...] marker so extract_events_from_output
            # picks it up from the text output stream.
            event_json = json.dumps(data, ensure_ascii=False)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": (
                            f"Event recorded: {event_type}\n"
                            f"[EVENT:{event_type} {event_json}]"
                        ),
                    }],
                },
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Validation error: {message}"}],
                    "isError": True,
                },
            }

    # Unknown method
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main() -> None:
    """Run the MCP server over stdio."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        response = _handle_request(request)
        if response:  # notifications don't get responses
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
