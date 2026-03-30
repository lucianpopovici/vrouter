# lldp/helpers.py
# Network utilities and TLV encoding/decoding (IEEE 802.1AB).
# Covers: mandatory TLVs, basic optional TLVs,
#         IEEE 802.1 / IEEE 802.3 / LLDP-MED org-specific TLVs.

import socket
import struct
import fcntl
from .security import sanitize_str

# ── Constants ─────────────────────────────────

LLDP_MULTICAST_MAC = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E])
LLDP_ETHERTYPE     = 0x88CC
ETH_P_ALL          = 0x0003

# Standard TLV type codes
TLV_END          = 0
TLV_CHASSIS_ID   = 1
TLV_PORT_ID      = 2
TLV_TTL          = 3
TLV_PORT_DESC    = 4
TLV_SYS_NAME     = 5
TLV_SYS_DESC     = 6
TLV_CAPABILITIES = 7
TLV_MGMT_ADDR    = 8
TLV_ORG_SPECIFIC = 127

# Org-specific OUIs
OUI_8021   = b"\x00\x80\xC2"   # IEEE 802.1
OUI_8023   = b"\x00\x12\x0F"   # IEEE 802.3
OUI_MEDEXT = b"\x00\x12\xBB"   # LLDP-MED (TIA-1057)

# System capability bitmasks
CAPABILITIES = {
    0x0001: "Other",
    0x0002: "Repeater",
    0x0004: "Bridge",
    0x0008: "WLAN AP",
    0x0010: "Router",
    0x0020: "Telephone",
    0x0040: "DOCSIS Cable Device",
    0x0080: "Station Only",
}

# LLDP-MED device class
MED_DEVICE_CLASS = {
    0: "Not Defined",
    1: "Endpoint Class I",
    2: "Endpoint Class II",
    3: "Endpoint Class III",
    4: "Network Connectivity Device",
}

# LLDP-MED capability bitmasks
MED_CAPABILITIES = {
    0x0001: "LLDP-MED Capabilities",
    0x0002: "Network Policy",
    0x0004: "Location Identification",
    0x0008: "Extended Power via MDI (PSE)",
    0x0010: "Extended Power via MDI (PD)",
    0x0020: "Inventory",
}

# 802.3 MAU types (partial — most common)
MAU_TYPES = {
    0x000F: "100BASE-TX FD",
    0x0010: "100BASE-TX HD",
    0x001E: "1000BASE-T FD",
    0x001F: "1000BASE-T HD",
    0x0024: "10GBASE-R",
}

# ── Network helpers ───────────────────────────

def get_mac(interface: str) -> bytes:
    """Return the MAC address of an interface as 6 bytes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927,
                           struct.pack("256s", interface[:15].encode()))
        return info[18:24]
    finally:
        s.close()


def get_ip(interface: str) -> bytes:
    """Return the IPv4 address of an interface as 4 bytes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8915,
                           struct.pack("256s", interface[:15].encode()))
        return info[20:24]
    except OSError:
        return b"\x00\x00\x00\x00"
    finally:
        s.close()


def mac_to_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def ip_to_str(ip: bytes) -> str:
    return socket.inet_ntoa(ip)


def safe_str(b: bytes, max_len: int = 256) -> str:
    """Decode bytes to str, sanitize non-printable chars, cap length. (#3, #7)"""
    raw = b.decode("utf-8", errors="replace").strip()
    return sanitize_str(raw, max_len=max_len)


# ── TLV encoding ─────────────────────────────

def build_tlv(tlv_type: int, value: bytes) -> bytes:
    """Encode one TLV: 7-bit type | 9-bit length | value."""
    header = (tlv_type << 9) | len(value)
    return struct.pack("!H", header) + value


# ── Org-specific TLV parsers ─────────────────

def _parse_8021(subtype: int, data: bytes, info: dict):
    """IEEE 802.1 org-specific TLVs."""

    if subtype == 1 and len(data) >= 2:
        # Port VLAN ID
        pvid = struct.unpack("!H", data[:2])[0]
        info["dot1_port_vlan_id"] = str(pvid) if pvid != 0 else "Not supported"

    elif subtype == 2 and len(data) >= 3:
        # Port & Protocol VLAN ID
        flags  = data[0]
        pvid   = struct.unpack("!H", data[1:3])[0]
        supported = bool(flags & 0x02)
        enabled   = bool(flags & 0x04)
        info["dot1_proto_vlan_id"] = (
            f"{pvid} (supported={supported}, enabled={enabled})"
        )

    elif subtype == 3:
        # VLAN Name
        if len(data) >= 3:
            vlan_id   = struct.unpack("!H", data[:2])[0]
            name_len  = data[2]
            vlan_name = safe_str(data[3: 3 + name_len])
            existing  = info.get("dot1_vlan_names", [])
            existing.append(f"{vlan_id}={vlan_name}")
            info["dot1_vlan_names"] = existing

    elif subtype == 4:
        # Protocol Identity
        if len(data) >= 1:
            proto_len = data[0]
            proto_id  = data[1: 1 + proto_len].hex()
            info["dot1_protocol_identity"] = proto_id


def _parse_8023(subtype: int, data: bytes, info: dict):
    """IEEE 802.3 org-specific TLVs."""

    if subtype == 1 and len(data) >= 3:
        # MAC/PHY Configuration & Status
        autoneg_support = bool(data[0] & 0x01)
        autoneg_enabled = bool(data[0] & 0x02)
        mau_type        = struct.unpack("!H", data[1:3])[0]
        mau_name        = MAU_TYPES.get(mau_type, f"0x{mau_type:04X}")
        info["dot3_mac_phy"] = (
            f"autoneg_support={autoneg_support}, "
            f"autoneg_enabled={autoneg_enabled}, "
            f"MAU={mau_name}"
        )

    elif subtype == 2 and len(data) >= 4:
        # Power via MDI
        mdi_power_support = data[0]
        pse_power_pair    = data[1]
        power_class       = data[2]
        port_class        = "PSE" if mdi_power_support & 0x01 else "PD"
        poe_supported     = bool(mdi_power_support & 0x02)
        poe_enabled       = bool(mdi_power_support & 0x04)
        pairs_controllable= bool(mdi_power_support & 0x08)
        info["dot3_poe"] = (
            f"port_class={port_class}, supported={poe_supported}, "
            f"enabled={poe_enabled}, pairs_ctrl={pairs_controllable}, "
            f"pair={pse_power_pair}, class={power_class}"
        )

    elif subtype == 3 and len(data) >= 3:
        # Link Aggregation
        agg_status    = data[0]
        agg_capable   = bool(agg_status & 0x01)
        agg_enabled   = bool(agg_status & 0x02)
        agg_port_id   = struct.unpack("!I", data[1:5])[0] if len(data) >= 5 else 0
        info["dot3_link_aggregation"] = (
            f"capable={agg_capable}, enabled={agg_enabled}, "
            f"port_id={agg_port_id}"
        )

    elif subtype == 4 and len(data) >= 2:
        # Maximum Frame Size
        max_frame = struct.unpack("!H", data[:2])[0]
        info["dot3_max_frame_size"] = f"{max_frame} bytes"


def _parse_med(subtype: int, data: bytes, info: dict):
    """LLDP-MED (TIA-1057) org-specific TLVs."""

    if subtype == 1 and len(data) >= 3:
        # MED Capabilities
        caps       = struct.unpack("!H", data[:2])[0]
        dev_class  = data[2]
        cap_names  = [n for b, n in MED_CAPABILITIES.items() if caps & b]
        info["med_capabilities"]  = ", ".join(cap_names) if cap_names else "None"
        info["med_device_class"]  = MED_DEVICE_CLASS.get(dev_class, f"Unknown ({dev_class})")

    elif subtype == 2 and len(data) >= 4:
        # Network Policy
        policy    = struct.unpack("!I", data[:4])[0]
        app_type  = (policy >> 24) & 0xFF
        unknown   = bool((policy >> 23) & 0x01)
        tagged    = bool((policy >> 22) & 0x01)
        vlan_id   = (policy >> 9) & 0x0FFF
        dscp      = policy & 0x3F
        info["med_network_policy"] = (
            f"app_type={app_type}, unknown={unknown}, "
            f"tagged={tagged}, vlan={vlan_id}, dscp={dscp}"
        )

    elif subtype == 3 and len(data) >= 1:
        # Location Identification
        loc_format = data[0]
        loc_formats = {1: "Coordinate-based", 2: "Civic address", 3: "ECS ELIN"}
        fmt_name   = loc_formats.get(loc_format, f"Unknown ({loc_format})")
        location   = safe_str(data[1:]) if loc_format == 3 else data[1:].hex()
        info["med_location"] = f"{fmt_name}: {location}"

    elif subtype == 4 and len(data) >= 3:
        # Extended Power via MDI
        power_type    = (data[0] >> 6) & 0x03
        power_source  = (data[0] >> 4) & 0x03
        power_priority = data[0] & 0x0F
        power_value   = struct.unpack("!H", data[1:3])[0] * 0.1  # in Watts
        type_names    = {0: "PSE Device", 1: "PD Device", 2: "PSE (802.3at)", 3: "PD (802.3at)"}
        src_names     = {0: "Unknown", 1: "Primary", 2: "Backup", 3: "Reserved"}
        pri_names     = {0: "Unknown", 1: "Critical", 2: "High", 3: "Low"}
        info["med_poe_ext"] = (
            f"type={type_names.get(power_type, power_type)}, "
            f"source={src_names.get(power_source, power_source)}, "
            f"priority={pri_names.get(power_priority, power_priority)}, "
            f"power={power_value:.1f}W"
        )

    elif subtype == 5:
        info["med_hw_revision"]  = safe_str(data)
    elif subtype == 6:
        info["med_fw_revision"]  = safe_str(data)
    elif subtype == 7:
        info["med_sw_revision"]  = safe_str(data)
    elif subtype == 8:
        info["med_serial_number"]= safe_str(data)
    elif subtype == 9:
        info["med_manufacturer"] = safe_str(data)
    elif subtype == 10:
        info["med_model_name"]   = safe_str(data)
    elif subtype == 11:
        info["med_asset_id"]     = safe_str(data)


# ── Main TLV decoder ─────────────────────────

def parse_tlvs(payload: bytes) -> dict:
    """
    Walk a full TLV chain and return a decoded field dict.
    Covers: mandatory, basic optional, 802.1, 802.3, LLDP-MED.
    """
    info = {}

    offset = 0
    while offset + 2 <= len(payload):
        header   = struct.unpack_from("!H", payload, offset)[0]
        tlv_type = (header >> 9) & 0x7F
        tlv_len  = header & 0x01FF
        offset  += 2

        if tlv_type == TLV_END:
            break
        if offset + tlv_len > len(payload):
            break

        value   = payload[offset: offset + tlv_len]
        offset += tlv_len

        # ── Mandatory ──────────────────────────
        if tlv_type == TLV_CHASSIS_ID and tlv_len > 1:
            info["chassis_id"] = (mac_to_str(value[1:])
                                  if value[0] == 4 else safe_str(value[1:]))

        elif tlv_type == TLV_PORT_ID and tlv_len > 1:
            info["port_id"] = safe_str(value[1:])

        elif tlv_type == TLV_TTL and tlv_len == 2:
            info["ttl"] = str(struct.unpack("!H", value)[0]) + "s"

        # ── Basic optional ─────────────────────
        elif tlv_type == TLV_PORT_DESC:
            info["port_description"] = safe_str(value)

        elif tlv_type == TLV_SYS_NAME:
            info["system_name"] = safe_str(value)

        elif tlv_type == TLV_SYS_DESC:
            info["system_description"] = safe_str(value)

        elif tlv_type == TLV_CAPABILITIES and tlv_len == 4:
            sys_caps = struct.unpack("!H", value[0:2])[0]
            ena_caps = struct.unpack("!H", value[2:4])[0]
            sys_names = [n for b, n in CAPABILITIES.items() if sys_caps & b]
            ena_names = [n for b, n in CAPABILITIES.items() if ena_caps & b]
            info["system_capabilities"] = ", ".join(sys_names) if sys_names else "None"
            info["enabled_capabilities"]= ", ".join(ena_names) if ena_names else "None"

        elif tlv_type == TLV_MGMT_ADDR and tlv_len >= 6:
            addr_len = value[0]
            subtype  = value[1]
            if subtype == 1 and addr_len == 5:    # IPv4
                info["management_address"] = ip_to_str(value[2:6])
            elif subtype == 2 and addr_len == 17: # IPv6
                info["management_address"] = socket.inet_ntop(
                    socket.AF_INET6, value[2:18])

        # ── Org-specific (type 127) ────────────
        elif tlv_type == TLV_ORG_SPECIFIC and tlv_len >= 4:
            oui     = value[0:3]
            subtype = value[3]
            data    = value[4:]

            if oui == OUI_8021:
                _parse_8021(subtype, data, info)
            elif oui == OUI_8023:
                _parse_8023(subtype, data, info)
            elif oui == OUI_MEDEXT:
                _parse_med(subtype, data, info)

    return info


# ── Custom TLV storage (appended to existing parser) ─────────────────────────
# The parse_tlvs function above silently drops unknown OUIs.
# Re-export a patched version that stores them.

_orig_parse_tlvs = parse_tlvs

def parse_tlvs(payload: bytes) -> dict:  # noqa: F811
    """
    Extended parse_tlvs: captures unknown org-specific TLVs
    into info["custom_tlvs"] as a list of dicts with
    keys oui, subtype, data (hex string).
    """
    info = _orig_parse_tlvs(payload)

    # Re-walk to catch unknown OUI entries that the original dropped
    offset = 0
    while offset + 2 <= len(payload):
        header   = struct.unpack_from("!H", payload, offset)[0]
        tlv_type = (header >> 9) & 0x7F
        tlv_len  = header & 0x01FF
        offset  += 2
        if tlv_type == TLV_END:
            break
        if offset + tlv_len > len(payload):
            break
        value   = payload[offset: offset + tlv_len]
        offset += tlv_len

        if tlv_type == TLV_ORG_SPECIFIC and tlv_len >= 4:
            oui = value[0:3]
            if oui not in (OUI_8021, OUI_8023, OUI_MEDEXT):
                custom = info.setdefault("custom_tlvs", [])
                custom.append({
                    "oui":     oui.hex().upper(),
                    "subtype": value[3],
                    "data":    value[4:].hex(),
                })

    return info
