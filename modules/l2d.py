"""modules/l2d.py — adapter for l2d (L2 daemon, 9 modules)."""
from .base import ModuleAdapter, _default_sock_dir
import json, os


class L2dAdapter(ModuleAdapter):
    """
    Single adapter that exposes all 9 L2 sub-modules.
    get/set/reset route to the appropriate socket based on the key's group.
    """
    SCHEMA_FILE = "l2d_schema.json"
    SOCKETS = {
        "fdb":     "fdb.sock",
        "l2rib":   "rib.sock",
        "stp":     "stp.sock",
        "vlan":    "vlan.sock",
        "portsec": "portsec.sock",
        "storm":   "storm.sock",
        "igmp":    "igmp.sock",
        "arp":     "arp.sock",
        "lacp":    "lacp.sock",
    }
    # Mapping: schema group → which socket handles get/set for that group
    _GROUP_SOCK = {
        "FDB": "fdb",
        "STP": "stp",
        "MST": "stp",
    }
    CONFIG_SOCK = "stp"   # default fallback
    VERSION = "1.0.0"

    def _sock_for_key(self, key: str) -> str:
        """Return the socket label that owns this config key."""
        schema = self._load_schema()
        entry = schema.get(key.upper(), {})
        group = entry.get("group", "")
        return self._GROUP_SOCK.get(group, "stp")

    def get(self, key: str):
        sock = self._sock_for_key(key)
        resp = self._send(sock, {"cmd": "get", "key": key.upper()})
        if resp.get("status") == "ok":
            return resp.get("value")
        raise KeyError(f"{key}: {resp.get('msg', resp)}")

    def set(self, key: str, value: str):
        sock = self._sock_for_key(key)
        resp = self._send(sock, {"cmd": "set", "key": key.upper(), "value": str(value)})
        self._invalidate()
        if resp.get("status") != "ok":
            raise ValueError(f"{key}: {resp.get('msg', resp)}")

    @property
    def active(self) -> bool:
        resp = self._send("fdb", {"cmd": "ping"})
        return resp.get("status") == "ok"
