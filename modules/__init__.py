"""
modules/__init__.py — Module registry for project-cli.

Provides discover() and get_adapter() used by ConfigShell and
ModuleConfigShell to enumerate and instantiate module adapters.
"""
from __future__ import annotations
import os

from .base import ModuleAdapter, _default_sock_dir
from .fib import FibAdapter, RibAdapter
from .l2d import L2dAdapter
from .overlay import IpAdapter, VrfAdapter, EvpnAdapter, VxlanAdapter

# ── Registry ──────────────────────────────────────────────────
REGISTRY: dict[str, dict] = {
    "fib": {
        "class":       FibAdapter,
        "description": "Forwarding Information Base (LPM lookup, route install)",
    },
    "rib": {
        "class":       RibAdapter,
        "description": "Routing Information Base — live stats (read-only)",
    },
    "l2d": {
        "class":       L2dAdapter,
        "description": "L2 daemon — FDB, STP/RSTP/MST, VLAN, LACP, IGMP, ARP/ND",
    },
    "ip": {
        "class":       IpAdapter,
        "description": "IPv4/IPv6 address management + ECMP forwarding",
    },
    "vrf": {
        "class":       VrfAdapter,
        "description": "VRF instances with ECMP + inter-VRF route leaking",
    },
    "evpn": {
        "class":       EvpnAdapter,
        "description": "BGP EVPN control plane (Type 2/3/4/5)",
    },
    "vxlan": {
        "class":       VxlanAdapter,
        "description": "VXLAN data plane (VNI, FDB, flood lists)",
    },
    # lldp and bfd are Python modules — project-cli handles them via
    # its built-in _Adapter / LldpConfigShell path; they appear here
    # so discover() includes them in 'show modules'.
    "lldp": {
        "class":       None,   # handled natively by project-cli
        "description": "IEEE 802.1AB Link Layer Discovery Protocol",
    },
    "bfd": {
        "class":       None,   # handled natively by project-cli
        "description": "Bidirectional Forwarding Detection (RFC 5880)",
    },
}


def discover() -> dict[str, dict]:
    """Return the full registry (name → metadata)."""
    return {k: {"description": v["description"]} for k, v in REGISTRY.items()}


def get_adapter(name: str, sock_dir: str | None = None) -> ModuleAdapter:
    """
    Instantiate and return the adapter for the given module name.

    Raises:
        KeyError:  Unknown module name.
        TypeError: Module is handled natively by project-cli (lldp, bfd).
    """
    entry = REGISTRY.get(name)
    if entry is None:
        raise KeyError(
            f"Unknown module '{name}'. "
            f"Available: {', '.join(REGISTRY)}"
        )
    if entry["class"] is None:
        # Signal to _enter_module that this module has native handling
        raise TypeError(f"native:{name}")
    return entry["class"](sock_dir=sock_dir or _default_sock_dir())
