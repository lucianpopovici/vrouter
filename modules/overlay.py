"""modules/overlay.py — adapters for ip, vrf, evpn, vxlan daemons."""
from __future__ import annotations
from .base import ModuleAdapter

_READ_ONLY = "read-only: use daemon startup flags to change this parameter"


class IpAdapter(ModuleAdapter):
    """IPv4/IPv6 address management + ECMP forwarding daemon."""
    SCHEMA_FILE = "ip_schema.json"
    SOCKETS     = {"ip": "ip.sock"}
    CONFIG_SOCK = "ip"
    VERSION     = "1.0.0"


class VrfAdapter(ModuleAdapter):
    """VRF instances with ECMP + inter-VRF route leaking daemon."""
    SCHEMA_FILE = "vrf_schema.json"
    SOCKETS     = {"vrf": "vrf.sock"}
    CONFIG_SOCK = "vrf"
    VERSION     = "1.0.0"


class EvpnAdapter(ModuleAdapter):
    """BGP EVPN control plane daemon (Type 2/3/4/5)."""
    SCHEMA_FILE = "evpn_schema.json"
    SOCKETS     = {"evpn": "evpn.sock"}
    CONFIG_SOCK = "evpn"
    VERSION     = "1.0.0"

    def set(self, key: str, value: str):
        raise ValueError(_READ_ONLY)

    def reset(self, key: str):
        raise ValueError(_READ_ONLY)


class VxlanAdapter(ModuleAdapter):
    """VXLAN data plane daemon (VNI, FDB, flood lists)."""
    SCHEMA_FILE = "vxlan_schema.json"
    SOCKETS     = {"vxlan": "vxlan.sock"}
    CONFIG_SOCK = "vxlan"
    VERSION     = "1.0.0"

    def set(self, key: str, value: str):
        raise ValueError(_READ_ONLY)

    def reset(self, key: str):
        raise ValueError(_READ_ONLY)
