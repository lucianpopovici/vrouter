"""
modules/common.py — shared project-wide settings.

Manages project_config.json, which is read by all C daemons at startup
for settings that apply across modules (currently: SOCK_DIR).
"""

import json
import os

_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_FILE = os.path.join(_DIR, "project_config.json")

_SCHEMA = {
    "SOCK_DIR": {
        "type":        "str",
        "description": "Directory for Unix socket files — shared by all modules. "
                       "Change this to run multiple instances without conflicts.",
        "default":     "/tmp",
        "mandatory":   False,
        "group":       "IPC",
    },
}


class CommonAdapter:

    @property
    def version(self) -> str:
        return "—"

    @property
    def active(self) -> bool:
        return False   # no daemon to ping

    # ── Internal ──────────────────────────────────────────────

    def _load(self) -> dict:
        if not os.path.exists(_CONFIG_FILE):
            return {}
        try:
            with open(_CONFIG_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, data: dict):
        with open(_CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)

    # ── ModuleConfigShell protocol ────────────────────────────

    def schema_rows(self) -> list:
        overrides = self._load()
        rows = []
        for k, e in _SCHEMA.items():
            default = e["default"]
            val     = overrides.get(k, default)
            rows.append({
                "group":       e.get("group", ""),
                "key":         k,
                "value":       val,
                "type":        e["type"],
                "description": e["description"],
                "min":         e.get("min"),
                "max":         e.get("max"),
                "mandatory":   e.get("mandatory", False),
                "default":     default,
            })
        return rows

    def get(self, key: str):
        key = key.upper()
        if key not in _SCHEMA:
            raise KeyError(f"Unknown key '{key}'")
        return self._load().get(key, _SCHEMA[key]["default"])

    def set(self, key: str, value):
        key = key.upper()
        if key not in _SCHEMA:
            raise KeyError(f"Unknown key '{key}'")
        data = self._load()
        data[key] = value
        self._save(data)
        return value

    def reset(self, key: str):
        key = key.upper()
        if key not in _SCHEMA:
            raise KeyError(f"Unknown key '{key}'")
        data = self._load()
        data.pop(key, None)
        self._save(data)
