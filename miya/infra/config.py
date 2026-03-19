"""Persistent configuration for Miya.

Two-tier config:
    1. Project-level: .miya.toml in CWD (tracked per-project)
    2. Global:        ~/.config/miya/config.toml

Project config overrides global. ``set -g`` writes to global.

Supported keys:
    model      — default LLM model (opus / sonnet / haiku)
    topology   — default topology (ooda / attack_graph / fanout)
    verbose    — log level (info / debug / trace / warning / error)
    api_key    — ANTHROPIC_API_KEY (stored in global only for safety)
    base_url   — ANTHROPIC_BASE_URL
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PROJECT_FILE = ".miya.toml"
_GLOBAL_DIR = Path.home() / ".config" / "miya"
_GLOBAL_FILE = _GLOBAL_DIR / "config.toml"

# Valid keys and their allowed values (None = any string)
_VALID_KEYS: dict[str, tuple[str, ...] | None] = {
    "model": ("opus", "sonnet", "haiku"),
    "topology": ("ooda", "attack_graph", "fanout"),
    "verbose": ("info", "debug", "trace", "warning", "error"),
    "unlimited": ("true", "false"),
    "api_key": None,
    "base_url": None,
}


def _read_toml(path: Path) -> dict[str, str]:
    """Read a simple TOML file (flat key = "value" pairs only)."""
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip().lower()
            val = val.strip().strip('"').strip("'")
            if key in _VALID_KEYS:
                result[key] = val
    except Exception:
        logger.debug("Failed to read config %s", path, exc_info=True)
    return result


def _write_toml(path: Path, data: dict[str, str]) -> None:
    """Write a simple TOML file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Miya configuration\n"]
    for key, val in sorted(data.items()):
        # Don't write api_key to project config
        lines.append(f'{key} = "{val}"\n')
    path.write_text("".join(lines), encoding="utf-8")


def load_config() -> dict[str, str]:
    """Load merged config: global ← project (project wins)."""
    global_cfg = _read_toml(_GLOBAL_FILE)
    project_cfg = _read_toml(Path.cwd() / _PROJECT_FILE)
    merged = {**global_cfg, **project_cfg}
    return merged


def save_config(key: str, value: str, *, is_global: bool = False) -> str:
    """Save a single config key.

    Args:
        is_global: Write to ~/.config/miya/config.toml instead of .miya.toml

    Returns:
        Human-readable confirmation message.
    """
    key = key.lower()
    if key not in _VALID_KEYS:
        valid = ", ".join(_VALID_KEYS.keys())
        return f"Unknown key '{key}'. Valid: {valid}"

    allowed = _VALID_KEYS[key]
    if allowed is not None and value.lower() not in allowed:
        return f"Invalid value '{value}' for {key}. Use: {', '.join(allowed)}"

    value = value.strip()

    # Secrets always go to global
    if key in ("api_key", "base_url"):
        is_global = True

    if is_global:
        path = _GLOBAL_FILE
        label = "global"
    else:
        path = Path.cwd() / _PROJECT_FILE
        label = "project"

    existing = _read_toml(path)
    existing[key] = value
    _write_toml(path, existing)

    return f"{key} → {value} (saved to {label}: {path})"


def apply_config(cfg_dict: dict[str, Any]) -> dict[str, str]:
    """Apply persisted config to the runtime cfg dict.

    Saved values unconditionally override defaults in cfg_dict.
    Also applies api_key/base_url to environment and sets log level.

    Returns the loaded persistent config.
    """
    saved = load_config()

    for key in ("model", "topology", "verbose"):
        if key in saved:
            cfg_dict[key] = saved[key]

    if "unlimited" in saved:
        cfg_dict["unlimited"] = saved["unlimited"].lower() == "true"

    # Apply verbose level
    if "verbose" in saved:
        _level_map = {
            "info": logging.INFO,
            "debug": logging.DEBUG,
            "warning": logging.WARNING,
            "error": logging.ERROR,
        }
        level = _level_map.get(saved["verbose"])
        if level is not None:
            logging.getLogger("miya").setLevel(level)

    # Apply env vars
    if "api_key" in saved and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = saved["api_key"]
    if "base_url" in saved and not os.environ.get("ANTHROPIC_BASE_URL"):
        os.environ["ANTHROPIC_BASE_URL"] = saved["base_url"]

    return saved
