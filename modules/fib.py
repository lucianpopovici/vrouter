"""modules/fib.py — adapters for fibd (L3 FIB + RIB daemon)."""
from __future__ import annotations
from .base import ModuleAdapter


class FibAdapter(ModuleAdapter):
    """
    FIB configuration adapter.
    Reads schema.json written by fibd; get/set go to fibd.sock.
    """
    SCHEMA_FILE = "schema.json"
    SOCKETS     = {"fib": "fibd.sock", "rib": "ribd.sock"}
    CONFIG_SOCK = "fib"
    VERSION     = "1.0.0"


class RibAdapter(ModuleAdapter):
    """
    RIB stats/info adapter.

    The RIB socket exposes operational stats (prefixes, pool, load factor)
    but has no configurable keys — configuration lives on the FIB side.
    We synthesise a read-only schema from the live stats response so the
    project-cli info/show commands display useful information.
    """
    SCHEMA_FILE = "schema.json"   # not used for schema_rows — see below
    SOCKETS     = {"fib": "fibd.sock", "rib": "ribd.sock"}
    CONFIG_SOCK = "rib"
    VERSION     = "1.0.0"

    # The RIB has no settable keys — all values are read-only operational stats
    _RIB_STATS_SCHEMA = [
        {"key": "prefixes",    "group": "RIB State", "type": "int",
         "description": "Number of prefixes in the RIB",
         "mandatory": True, "default": None, "min": None, "max": None},
        {"key": "pool_used",   "group": "RIB State", "type": "int",
         "description": "Pool entries in use",
         "mandatory": True, "default": None, "min": None, "max": None},
        {"key": "pool_size",   "group": "RIB State", "type": "int",
         "description": "Total pool capacity",
         "mandatory": True, "default": None, "min": None, "max": None},
        {"key": "load_factor", "group": "RIB State", "type": "str",
         "description": "Hash table load factor",
         "mandatory": True, "default": None, "min": None, "max": None},
        {"key": "added",       "group": "RIB Counters", "type": "int",
         "description": "Routes added since startup",
         "mandatory": True, "default": None, "min": None, "max": None},
        {"key": "deleted",     "group": "RIB Counters", "type": "int",
         "description": "Routes deleted since startup",
         "mandatory": True, "default": None, "min": None, "max": None},
        {"key": "fib_updates", "group": "RIB Counters", "type": "int",
         "description": "FIB installs/withdrawals triggered",
         "mandatory": True, "default": None, "min": None, "max": None},
        {"key": "collisions",  "group": "RIB Counters", "type": "int",
         "description": "Hash bucket collisions",
         "mandatory": True, "default": None, "min": None, "max": None},
    ]

    def schema_rows(self) -> list[dict]:
        """Return live stats as read-only schema rows."""
        # Fetch current stats from the RIB
        resp = self._send("rib", {"cmd": "stats"})
        rows = []
        for meta in self._RIB_STATS_SCHEMA:
            val = resp.get(meta["key"], "n/a") if resp.get("status") == "ok" else "n/a"
            rows.append({**meta, "value": val})
        return rows

    def get(self, key: str):
        resp = self._send("rib", {"cmd": "stats"})
        if resp.get("status") == "ok" and key.lower() in resp:
            return resp[key.lower()]
        raise KeyError(f"'{key}' is not a RIB stat key")

    def set(self, key: str, value: str):
        raise ValueError("RIB has no configurable keys — use 'fib' to change FIB settings")

    def reset(self, key: str):
        raise ValueError("RIB has no configurable keys")
