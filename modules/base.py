"""
modules/base.py — ModuleAdapter base class

All C-daemon adapters inherit from this.  The project-cli's
ModuleConfigShell calls only these four methods:

    schema_rows() → list[dict]   all keys + metadata + current value
    get(key)      → any          current value
    set(key, val)                persist new value
    reset(key)                   restore default

The base class bridges project-cli's interface to our C daemons'
plain-JSON IPC: {"cmd":"get","key":"X"} / {"cmd":"set","key":"X","value":"V"}
"""

from __future__ import annotations
import json
import os
import socket as _sock


def _default_sock_dir() -> str:
    """
    Return SOCK_DIR from project_config.json if present, else /tmp.
    Mirrors the same lookup the C daemons do at startup.
    """
    import json as _j
    for candidate in [os.getcwd(),
                      os.path.dirname(os.path.abspath(__file__))]:
        cfg = os.path.join(candidate, "project_config.json")
        if os.path.exists(cfg):
            try:
                d = _j.load(open(cfg)).get("SOCK_DIR")
                if d:
                    return d
            except Exception:
                pass
    return "/tmp"


class ModuleAdapter:
    """
    Base adapter: talks to one or more Unix sockets using our
    plain-JSON protocol, and presents the project-cli interface.

    Sub-classes set:
        SCHEMA_FILE  str           path to the schema JSON written by the daemon
        SOCKETS      dict[str,str] label → socket filename (relative to sock_dir)
        CONFIG_SOCK  str           which label to use for get/set commands
    """

    SCHEMA_FILE: str = "schema.json"
    SOCKETS: dict = {}
    CONFIG_SOCK: str = ""
    VERSION: str = "1.0.0"

    def __init__(self, sock_dir: str | None = None):
        self._sock_dir = sock_dir or _default_sock_dir()
        self._schema_cache: list | None = None

    # ── IPC helpers ────────────────────────────────────────────

    def _sock_path(self, label: str) -> str:
        fname = self.SOCKETS.get(label, label)
        return os.path.join(self._sock_dir, fname)

    def _send(self, label: str, cmd: dict) -> dict:
        """Send one JSON command to a socket, return parsed response."""
        path = self._sock_path(label)
        try:
            s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
            s.settimeout(3)
            s.connect(path)
            s.sendall((json.dumps(cmd, separators=(',', ':')) + "\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data or b"}" in data:
                    break
            s.close()
            return json.loads(data.decode().strip())
        except (OSError, json.JSONDecodeError) as e:
            return {"status": "error", "msg": str(e)}

    def _config_send(self, cmd: dict) -> dict:
        return self._send(self.CONFIG_SOCK, cmd)

    # ── Schema ─────────────────────────────────────────────────

    def _load_schema(self) -> dict:
        """Load the JSON schema file written by the daemon at startup."""
        path = os.path.join(self._sock_dir, self.SCHEMA_FILE)
        # Also try CWD
        if not os.path.exists(path):
            path = self.SCHEMA_FILE
        if not os.path.exists(path):
            return {}
        with open(path) as f:
            data = json.load(f)
        return data.get("keys", {})

    def schema_rows(self) -> list[dict]:
        """Return schema + current values for ModuleConfigShell."""
        if self._schema_cache is not None:
            return self._schema_cache

        schema = self._load_schema()
        rows = []
        for key, meta in schema.items():
            # Try to get live value from daemon; fall back to default
            try:
                val = self.get(key)
            except Exception:
                val = meta.get("default")

            rows.append({
                "group":       meta.get("group", "General"),
                "key":         key,
                "value":       val,
                "type":        meta.get("type", "str"),
                "description": meta.get("description", ""),
                "min":         meta.get("min"),
                "max":         meta.get("max"),
                "mandatory":   meta.get("mandatory", False),
                "default":     meta.get("default"),
            })

        self._schema_cache = rows
        return rows

    def _invalidate(self):
        self._schema_cache = None

    # ── Config ops (translate to C daemon protocol) ─────────────

    def get(self, key: str):
        resp = self._config_send({"cmd": "get", "key": key.upper()})
        if resp.get("status") == "ok":
            return resp.get("value")
        raise KeyError(f"{key}: {resp.get('msg', resp)}")

    def set(self, key: str, value: str):
        resp = self._config_send({
            "cmd": "set", "key": key.upper(), "value": str(value)
        })
        self._invalidate()
        if resp.get("status") != "ok":
            raise ValueError(f"{key}: {resp.get('msg', resp)}")

    def reset(self, key: str):
        """Reset to default by looking it up in the schema."""
        schema = self._load_schema()
        entry = schema.get(key.upper())
        if entry is None:
            raise KeyError(f"Unknown key '{key}'")
        default = entry.get("default")
        if default is None:
            raise ValueError(f"No default defined for '{key}'")
        self.set(key, str(default))

    def op(self, cmd: str, **kwargs) -> dict:
        """Send an arbitrary operational command to the daemon's config socket."""
        payload = {"cmd": cmd}
        payload.update(kwargs)
        return self._send(self.CONFIG_SOCK, payload)

    # ── Liveness ───────────────────────────────────────────────

    @property
    def active(self) -> bool:
        """True if the primary config socket is reachable."""
        resp = self._send(self.CONFIG_SOCK, {"cmd": "ping"})
        return resp.get("status") == "ok"

    @property
    def version(self) -> str:
        return self.VERSION


# ── FileBasedAdapter ────────────────────────────────────────────────────────

class FileBasedAdapter:
    """
    File-based adapter: reads schema from a JSON file and persists runtime
    overrides to another JSON file. No live daemon connection required.

    Constructor args:
        base_dir      directory containing schema_file and runtime_file
        schema_file   filename of the JSON schema (relative to base_dir)
        runtime_file  filename for persisted overrides (relative to base_dir)
        keys          optional whitelist of key names to expose
    """

    def __init__(self, base_dir: str, schema_file: str, runtime_file: str,
                 keys=None):
        self._base_dir = base_dir
        self._schema_path = os.path.join(base_dir, schema_file)
        self._runtime_path = os.path.join(base_dir, runtime_file)
        self._keys_filter = [k.upper() for k in keys] if keys is not None else None
        self._schema_data_cache = None

    # ── internal helpers ────────────────────────────────────────────

    def _load_schema_data(self) -> dict:
        if self._schema_data_cache is not None:
            return self._schema_data_cache
        if not os.path.exists(self._schema_path):
            self._schema_data_cache = {}
            return {}
        with open(self._schema_path) as f:
            data = json.load(f)
        self._schema_data_cache = data
        return data

    def _schema_keys(self) -> dict:
        return self._load_schema_data().get("keys", {})

    def _load_runtime(self) -> dict:
        if not os.path.exists(self._runtime_path):
            return {}
        with open(self._runtime_path) as f:
            return json.load(f)

    def _save_runtime(self, runtime: dict):
        with open(self._runtime_path, "w") as f:
            json.dump(runtime, f)

    def _resolve_key(self, key: str) -> str:
        """Normalize key to uppercase and validate it is accessible."""
        key = key.upper()
        if key not in self._schema_keys():
            raise KeyError(key)
        if self._keys_filter is not None and key not in self._keys_filter:
            raise KeyError(key)
        return key

    def _coerce(self, key: str, value):
        meta = self._schema_keys().get(key, {})
        typ = meta.get("type", "str")
        if typ == "int":
            value = int(value)
            mn = meta.get("min")
            mx = meta.get("max")
            if mn is not None and value < mn:
                raise ValueError(f"{key}: {value} is below minimum {mn}")
            if mx is not None and value > mx:
                raise ValueError(f"{key}: {value} is above maximum {mx}")
        elif typ == "bool":
            if not isinstance(value, bool):
                value = str(value).lower() in ("true", "1", "yes")
        else:
            value = str(value)
        return value

    # ── public interface ────────────────────────────────────────────

    def get(self, key: str):
        key = self._resolve_key(key)
        runtime = self._load_runtime()
        if key in runtime:
            return runtime[key]
        return self._schema_keys()[key].get("default")

    def set(self, key: str, value):
        key = self._resolve_key(key)
        coerced = self._coerce(key, value)
        runtime = self._load_runtime()
        runtime[key] = coerced
        self._save_runtime(runtime)
        return coerced

    def reset(self, key: str):
        key = self._resolve_key(key)
        runtime = self._load_runtime()
        runtime.pop(key, None)
        self._save_runtime(runtime)

    def schema_rows(self) -> list:
        rows = []
        for key, meta in self._schema_keys().items():
            if self._keys_filter is not None and key not in self._keys_filter:
                continue
            try:
                val = self.get(key)
            except Exception:
                val = meta.get("default")
            rows.append({
                "group":       meta.get("group", "General"),
                "key":         key,
                "value":       val,
                "type":        meta.get("type", "str"),
                "description": meta.get("description", ""),
                "min":         meta.get("min"),
                "max":         meta.get("max"),
                "mandatory":   meta.get("mandatory", False),
                "default":     meta.get("default"),
            })
        return rows

    @property
    def version(self) -> str:
        return self._load_schema_data().get("version", "unknown")


# ── ModeAwareAdapter ────────────────────────────────────────────────────────

class ModeAwareAdapter(FileBasedAdapter):
    """
    Extends FileBasedAdapter with mode-conditional key visibility.

    Some keys are always visible (base_keys); others are only exposed when
    the value of mode_key matches a specific mode (conditional_keys).

    Constructor extra args:
        base_keys        keys always visible
        mode_key         key whose value selects the active mode
        conditional_keys dict mapping mode string → list of extra visible keys
    """

    def __init__(self, base_dir: str, schema_file: str, runtime_file: str,
                 base_keys, mode_key: str, conditional_keys: dict):
        super().__init__(base_dir=base_dir, schema_file=schema_file,
                         runtime_file=runtime_file)
        self._base_keys = [k.upper() for k in base_keys]
        self._mode_key = mode_key.upper()
        self._conditional_keys = {
            mode: [k.upper() for k in ks]
            for mode, ks in conditional_keys.items()
        }

    def _current_mode(self) -> str:
        try:
            key = self._mode_key
            runtime = self._load_runtime()
            if key in runtime:
                return str(runtime[key])
            return str(self._schema_keys().get(key, {}).get("default", ""))
        except Exception:
            return ""

    def _visible_keys(self) -> list:
        mode = self._current_mode()
        return self._base_keys + self._conditional_keys.get(mode, [])

    def _resolve_key(self, key: str) -> str:
        key = key.upper()
        if key not in self._schema_keys():
            raise KeyError(key)
        if key not in self._visible_keys():
            raise KeyError(f"{key}: not available in current mode")
        return key

    def schema_rows(self) -> list:
        rows = []
        for key in self._visible_keys():
            meta = self._schema_keys().get(key, {})
            try:
                val = self.get(key)
            except Exception:
                val = meta.get("default")
            rows.append({
                "group":       meta.get("group", "General"),
                "key":         key,
                "value":       val,
                "type":        meta.get("type", "str"),
                "description": meta.get("description", ""),
                "min":         meta.get("min"),
                "max":         meta.get("max"),
                "mandatory":   meta.get("mandatory", False),
                "default":     meta.get("default"),
            })
        return rows
