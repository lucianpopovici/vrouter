"""
modules/base.py — FileBasedAdapter and ModuleAdapter base class.

Any language's daemon qualifies as long as it writes a schema JSON file
with this structure:
  {
    "module": "...",
    "version": "1.0.0",
    "keys": {
      "KEY_NAME": {
        "type": "int"|"str"|"bool",
        "description": "...",
        "default": <value>,
        "min": <int>,        # optional
        "max": <int>,        # optional
        "mandatory": false,
        "group": "..."
      }
    }
  }
"""

import json
import os
import socket as _sock
from collections import defaultdict


class FileBasedAdapter:
    """
    Reads a schema JSON file and a runtime config JSON file.
    Compatible with ModuleConfigShell's expected interface.
    """

    def __init__(self, base_dir: str, schema_file: str, runtime_file: str,
                 keys: list = None):
        self._base         = base_dir
        self._schema_path  = os.path.join(base_dir, schema_file)
        self._runtime_path = os.path.join(base_dir, runtime_file)
        self._key_filter   = {k.upper() for k in keys} if keys is not None else None
        self._schema       = self._load_schema()

    # ── Internal helpers ──────────────────────────────────────

    def _load_schema(self) -> dict:
        if not os.path.exists(self._schema_path):
            return {}
        with open(self._schema_path) as f:
            data = json.load(f)
        all_keys = data.get("keys", {})
        if self._key_filter is None:
            return all_keys
        return {k: v for k, v in all_keys.items() if k in self._key_filter}

    def _load_runtime(self) -> dict:
        if not os.path.exists(self._runtime_path):
            return {}
        try:
            with open(self._runtime_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_runtime(self, data: dict):
        with open(self._runtime_path, "w") as f:
            json.dump(data, f, indent=2)

    def _coerce(self, key: str, value):
        entry = self._schema.get(key, {})
        typ   = entry.get("type", "str")
        if typ == "int":
            value = int(value)
            lo = entry.get("min")
            hi = entry.get("max")
            if lo is not None and value < lo:
                raise ValueError(f"'{key}' minimum is {lo}, got {value}")
            if hi is not None and value > hi:
                raise ValueError(f"'{key}' maximum is {hi}, got {value}")
        elif typ == "bool":
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                if value.lower() in ("true", "1", "yes", "on"):
                    return True
                if value.lower() in ("false", "0", "no", "off"):
                    return False
            raise ValueError(f"Cannot convert {value!r} to bool")
        return value

    # ── Public interface (ModuleConfigShell protocol) ─────────

    @property
    def version(self) -> str:
        if not os.path.exists(self._schema_path):
            return "unknown"
        try:
            with open(self._schema_path) as f:
                return json.load(f).get("version", "unknown")
        except Exception:
            return "unknown"

    @property
    def active(self) -> bool:
        return False  # override in subclass for daemon ping

    def schema_rows(self) -> list:
        overrides    = self._load_runtime()
        group_order  = list(dict.fromkeys(
            e.get("group", "Other") for e in self._schema.values()
        ))
        groups: dict = defaultdict(list)
        for k, e in self._schema.items():
            groups[e.get("group", "Other")].append(k)

        rows = []
        for group in group_order:
            for k in groups[group]:
                e       = self._schema[k]
                default = e.get("default")
                val     = overrides.get(k, default)
                try:
                    val = self._coerce(k, val) if val is not None else default
                except Exception:
                    pass
                rows.append({
                    "group":       group,
                    "key":         k,
                    "value":       val,
                    "type":        e.get("type", "str"),
                    "description": e.get("description", ""),
                    "min":         e.get("min"),
                    "max":         e.get("max"),
                    "mandatory":   e.get("mandatory", False),
                    "default":     default,
                })
        return rows

    def get(self, key: str):
        key       = key.upper()
        overrides = self._load_runtime()
        if key in overrides:
            return overrides[key]
        entry = self._schema.get(key)
        if entry is None:
            raise KeyError(f"Unknown key '{key}'")
        return entry.get("default")

    def set(self, key: str, value):
        key   = key.upper()
        entry = self._schema.get(key)
        if entry is None:
            raise KeyError(f"Unknown key '{key}'")
        coerced   = self._coerce(key, value)
        overrides = self._load_runtime()
        overrides[key] = coerced
        self._save_runtime(overrides)
        return coerced

    def reset(self, key: str):
        key       = key.upper()
        if key not in self._schema:
            raise KeyError(f"Unknown key '{key}'")
        overrides = self._load_runtime()
        overrides.pop(key, None)
        self._save_runtime(overrides)

    # ── IPC ping helper for subclasses ────────────────────────

    def _ping_unix_socket(self, path: str) -> bool:
        try:
            s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
            s.settimeout(1)
            s.connect(path)
            s.sendall(b'{"cmd": "ping"}')
            s.recv(256)
            s.close()
            return True
        except OSError:
            return False


class ModeAwareAdapter(FileBasedAdapter):
    """
    FileBasedAdapter with mode-dependent key visibility.

    Parameters
    ----------
    base_keys        : always-visible keys (including the mode key itself)
    mode_key         : key whose value controls visibility (e.g. "STP_MODE")
    conditional_keys : {mode_value: [extra_keys]}  — keys unlocked per mode

    Keys not in the visible set are hidden from info/show and blocked from
    get/set/reset with a clear error message.
    """

    def __init__(self, base_dir: str, schema_file: str, runtime_file: str,
                 base_keys: list, mode_key: str,
                 conditional_keys: dict):
        all_keys = list(base_keys) + [
            k for ks in conditional_keys.values() for k in ks
        ]
        super().__init__(base_dir, schema_file, runtime_file, keys=all_keys)
        self._base_keys        = [k.upper() for k in base_keys]
        self._mode_key         = mode_key.upper()
        self._conditional_keys = {
            m.lower(): [k.upper() for k in ks]
            for m, ks in conditional_keys.items()
        }

    def _visible_keys(self) -> set:
        mode  = str(self._load_runtime().get(self._mode_key, "")).lower()
        extra = self._conditional_keys.get(mode, [])
        return set(self._base_keys) | set(extra)

    def _check_visible(self, key: str):
        if key not in self._visible_keys():
            mode = self._load_runtime().get(self._mode_key, "?")
            raise KeyError(
                f"'{key}' is not available in mode '{mode}'. "
                f"Set {self._mode_key} to a mode that exposes it."
            )

    def schema_rows(self) -> list:
        visible = self._visible_keys()
        return [r for r in super().schema_rows() if r["key"] in visible]

    def get(self, key: str):
        key = key.upper()
        self._check_visible(key)
        return super().get(key)

    def set(self, key: str, value):
        key = key.upper()
        # Allow setting the mode key itself; re-check visibility for others
        if key != self._mode_key:
            self._check_visible(key)
        return super().set(key, value)

    def reset(self, key: str):
        key = key.upper()
        self._check_visible(key)
        return super().reset(key)


# Aliases so external code can import either name
ModuleAdapter = FileBasedAdapter
