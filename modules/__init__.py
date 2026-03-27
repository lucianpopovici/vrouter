"""
modules/__init__.py — module registry for project-cli.

Each REGISTRY entry carries:
  - description   (str)
  - adapter_cls   callable that returns an adapter instance
  - sockets       socket basenames to probe in SOCK_DIR for discovery
  - schema_file   schema filename to look for in the project root
  - python_pkg    Python package to try importing for discovery
"""

import json
import os

_DIR           = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_COMMON_CONFIG = os.path.join(_DIR, "project_config.json")

_L2_SCHEMA  = "l2d_schema.json"
_L2_RUNTIME = "l2d_runtime_config.json"
_L3_SCHEMA  = "schema.json"
_L3_RUNTIME = "runtime_config.json"
_LLDP_SCHEMA  = "lldp_schema.json"
_LLDP_RUNTIME = "lldp_runtime_config.json"


def _read_sock_dir() -> str:
    try:
        with open(_COMMON_CONFIG) as f:
            return json.load(f).get("SOCK_DIR", "/tmp")
    except (OSError, json.JSONDecodeError):
        return "/tmp"


# ── Adapter factory helpers ────────────────────────────────────

def _l3_adapter(keys, sock_names, schema=_L3_SCHEMA, runtime=_L3_RUNTIME):
    """Return a FileBasedAdapter for an L2 sub-module."""
    from modules.base import FileBasedAdapter

    class _Impl(FileBasedAdapter):
        _socks = sock_names

        @property
        def active(self):
            d = _read_sock_dir()
            return any(
                self._ping_unix_socket(os.path.join(d, s))
                for s in self._socks
            )

    return _Impl(_DIR, _L2_SCHEMA, _L2_RUNTIME, keys=keys)


def _l3_adapter(keys, sock_names):
    """Return a FileBasedAdapter for an L3 sub-module."""
    from modules.base import FileBasedAdapter

    class _Impl(FileBasedAdapter):
        _socks = sock_names

        @property
        def active(self):
            d = _read_sock_dir()
            return any(
                self._ping_unix_socket(os.path.join(d, s))
                for s in self._socks
            )

    return _Impl(_DIR, schema, runtime, keys=keys)


def _bfd_adapter():
    """Return a FileBasedAdapter for the BFD module.

    Schema: read from the project root (bfd_schema.json, committed alongside code).
    Runtime overrides: read/written to /tmp/bfd_runtime_config.json (written by daemon).
    """
    from modules.base import FileBasedAdapter

    class _Impl(FileBasedAdapter):
        @property
        def active(self):
            return self._ping_unix_socket(
                os.path.join(_read_sock_dir(), "bfd.sock")
            )

    # Pass the schema as an absolute path so FileBasedAdapter's os.path.join
    # ignores base_dir ("/tmp") for the schema and only uses it for runtime config.
    return _Impl("/tmp", os.path.join(_DIR, "bfd_schema.json"), "bfd_runtime_config.json")


def _stp_adapter():
    """Return a ModeAwareAdapter for STP/RSTP/MST."""
    from modules.base import ModeAwareAdapter

    class _Impl(ModeAwareAdapter):
        @property
        def active(self):
            return self._ping_unix_socket(
                os.path.join(_read_sock_dir(), "l2stp.sock")
            )

    return _Impl(
        _DIR, _L2_SCHEMA, _L2_RUNTIME,
        base_keys=["STP_MODE", "STP_PRIORITY", "STP_HELLO",
                   "STP_MAX_AGE", "STP_FWD_DELAY"],
        mode_key="STP_MODE",
        conditional_keys={"mst": ["MST_REGION", "MST_REVISION"]},
    )


# ── Registry ──────────────────────────────────────────────────
#
# L2 key assignments (sourced from l2d_schema.json groups):
#   fdb       → FDB group
#   stp       → STP/RSTP/MST merged (STP_MODE controls visible keys)
#   rib       → no config keys
#   vlan      → no config keys
#   igmp      → no config keys
#   lacp      → no config keys
#   arp       → no config keys
#   interface → no config keys  (PortSec + Storm)
#
# L3 key assignments (sourced from schema.json):
#   fib       → all keys

REGISTRY = {
    # ── always present ─────────────────────────────────────────
    "common": {
        "description": "Shared project settings (SOCK_DIR, …)",
        "adapter_cls": None,     # CommonAdapter loaded directly in get_adapter
    },

    # ── L2 subsystems ──────────────────────────────────────────
    "fdb": {
        "description": "Forwarding Database — MAC learning & ageing",
        "adapter_cls": lambda: _l2_adapter(
            keys=["FDB_AGE_SEC", "FDB_MAX_ENTRIES"],
            sock_names=["l2fdb.sock"],
        ),
        "sockets":     ["l2fdb.sock"],
        "schema_file": _L2_SCHEMA,
    },
    "rib": {
        "description": "L2 Routing Information Base",
        "adapter_cls": lambda: _l2_adapter(keys=[], sock_names=["l2rib.sock"]),
        "sockets":     ["l2rib.sock"],
        "schema_file": _L2_SCHEMA,
    },
    "stp": {
        "description": "Spanning Tree (STP/RSTP/MST) — mode selects active parameters",
        "adapter_cls": _stp_adapter,
        "sockets":     ["l2stp.sock"],
        "schema_file": _L2_SCHEMA,
    },
    "vlan": {
        "description": "VLAN database",
        "adapter_cls": lambda: _l2_adapter(keys=[], sock_names=["l2vlan.sock"]),
        "sockets":     ["l2vlan.sock"],
        "schema_file": _L2_SCHEMA,
    },
    "igmp": {
        "description": "IGMP snooping",
        "adapter_cls": lambda: _l2_adapter(keys=[], sock_names=["l2igmp.sock"]),
        "sockets":     ["l2igmp.sock"],
        "schema_file": _L2_SCHEMA,
    },
    "lacp": {
        "description": "Link Aggregation Control Protocol",
        "adapter_cls": lambda: _l2_adapter(keys=[], sock_names=["l2lacp.sock"]),
        "sockets":     ["l2lacp.sock"],
        "schema_file": _L2_SCHEMA,
    },
    "arp": {
        "description": "ARP snooping",
        "adapter_cls": lambda: _l2_adapter(keys=[], sock_names=["l2arp.sock"]),
        "sockets":     ["l2arp.sock"],
        "schema_file": _L2_SCHEMA,
    },
    "interface": {
        "description": "Interface policies — Port Security & Storm Control",
        "adapter_cls": lambda: _l2_adapter(
            keys=[],
            sock_names=["l2portsec.sock", "l2storm.sock"],
        ),
        "sockets":     ["l2portsec.sock", "l2storm.sock"],
        "schema_file": _L2_SCHEMA,
    },

    # ── L3 subsystems ──────────────────────────────────────────
    "fib": {
        "description": "Forwarding & Routing Information Base",
        "adapter_cls": lambda: _l3_adapter(
            keys=["MAX_ROUTES", "DEFAULT_METRIC", "LOG_LEVEL"],
            sock_names=["fibd.sock", "ribd.sock"],
        ),
        "sockets":     ["fibd.sock", "ribd.sock"],
        "schema_file": _L3_SCHEMA,
    },

    # ── LLDP ───────────────────────────────────────────────────
    "lldp": {
        "description":  "IEEE 802.1AB Link Layer Discovery Protocol",
        "adapter_cls":  lambda: _l3_adapter(
            keys=None, # Load all keys from schema.json
            sock_names=["lldpd.sock"],
            schema=_LLDP_SCHEMA,
            runtime=_LLDP_RUNTIME
        ),
        "sockets":      ["lldpd.sock"],
        "python_pkg":   "lldp",
    },

    # ── BFD ────────────────────────────────────────────────────
    "bfd": {
        "description": "Bidirectional Forwarding Detection (RFC 5880)",
        "adapter_cls": _bfd_adapter,
        "sockets":     ["bfd.sock"],
        "python_pkg":  "bfd",
    },
}


def discover(sock_dir: str = None) -> dict:
    """
    Return the subset of REGISTRY that is present in this environment.

    A module is discoverable if ANY of the following is true:
      - It has no discovery hints ('common') → always included
      - At least one of its socket files exists in sock_dir
      - Its schema_file exists in the project root
      - Its python_pkg is importable
    """
    if sock_dir is None:
        sock_dir = _read_sock_dir()

    found = {}
    for name, entry in REGISTRY.items():
        has_hints = any(k in entry for k in ("sockets", "schema_file", "python_pkg"))
        if not has_hints:
            found[name] = entry
            continue

        for sock in entry.get("sockets", []):
            if os.path.exists(os.path.join(sock_dir, sock)):
                found[name] = entry
                break
        else:
            sf = entry.get("schema_file")
            if sf and os.path.exists(os.path.join(_DIR, sf)):
                found[name] = entry
                continue
            pkg = entry.get("python_pkg")
            if pkg:
                try:
                    __import__(pkg)
                    found[name] = entry
                except ImportError:
                    pass

    return found


def get_adapter(name: str):
    """Return an initialised adapter for *name*, or raise KeyError/ImportError."""
    if name == "common":
        from modules.common import CommonAdapter
        return CommonAdapter()

    entry = REGISTRY.get(name)
    if entry is None:
        raise KeyError(f"Unknown module '{name}'")
    cls = entry.get("adapter_cls")
    if cls is None:
        raise ImportError(
            f"Module '{name}' has no generic adapter "
            f"(it uses its own import path)."
        )
    return cls()
