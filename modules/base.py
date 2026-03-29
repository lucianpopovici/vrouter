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

    # ── Liveness ───────────────────────────────────────────────

    @property
    def active(self) -> bool:
        """True if the primary config socket is reachable."""
        resp = self._send(self.CONFIG_SOCK, {"cmd": "ping"})
        return resp.get("status") == "ok"

    @property
    def version(self) -> str:
        return self.VERSION
