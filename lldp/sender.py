# lldp/sender.py
# Builds and sends LLDP frames.
# Reads config.TTL and config.SEND_INTERVAL live each loop iteration
# so runtime changes take effect without restarting.

import os
import re
import socket
import struct
import threading
import time
import random
from datetime import datetime

from . import config
from .helpers import (
    LLDP_MULTICAST_MAC, LLDP_ETHERTYPE,
    OUI_8021, OUI_8023, OUI_MEDEXT,
    TLV_CHASSIS_ID, TLV_PORT_ID, TLV_TTL, TLV_PORT_DESC,
    TLV_SYS_NAME, TLV_SYS_DESC, TLV_CAPABILITIES,
    TLV_MGMT_ADDR, TLV_ORG_SPECIFIC, TLV_END,
    build_tlv, get_mac, get_ip,
)

# ── Sysfs helpers ─────────────────────────────

def _sysfs(path: str, default: str = "") -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def _get_port_description(iface: str) -> str:
    alias = _sysfs(f"/sys/class/net/{iface}/ifalias")
    if alias:
        return alias
    driver = _sysfs(f"/sys/class/net/{iface}/device/uevent")
    m = re.search(r"DRIVER=(\S+)", driver)
    return f"{iface} ({m.group(1) if m else 'unknown'})"


def _get_if_index(iface: str) -> int:
    return int(_sysfs(f"/sys/class/net/{iface}/ifindex", "1"))


def _get_mtu(iface: str) -> int:
    return int(_sysfs(f"/sys/class/net/{iface}/mtu", "1500"))


def _get_speed_duplex(iface: str) -> tuple:
    speed  = int(_sysfs(f"/sys/class/net/{iface}/speed",  "0") or "0")
    duplex = _sysfs(f"/sys/class/net/{iface}/duplex", "unknown")
    return speed, duplex, speed > 0


def _speed_duplex_to_mau(speed: int, duplex: str) -> int:
    return {
        (10,    "full"): 0x000C, (10,    "half"): 0x000B,
        (100,   "full"): 0x000F, (100,   "half"): 0x0010,
        (1000,  "full"): 0x001E, (1000,  "half"): 0x001F,
        (10000, "full"): 0x0024,
    }.get((speed, duplex), 0x0000)


def _get_vlans(iface: str) -> list:
    vlans = []
    try:
        with open("/proc/net/vlan/config") as f:
            for line in f:
                m = re.match(
                    r"(\S+)\s+\|\s+(\d+)\s+\|.*\|\s*" + re.escape(iface), line)
                if m:
                    vlans.append((int(m.group(2)), m.group(1)))
    except OSError:
        pass
    return vlans


def _get_aggregation(iface: str) -> tuple:
    bond_master = _sysfs(f"/sys/class/net/{iface}/master/ifindex", "")
    capable     = bool(bond_master)
    agg_port_id = int(bond_master) if bond_master else 0
    return capable, capable, agg_port_id


def _detect_capabilities() -> int:
    caps = 0x0080
    if _sysfs("/proc/sys/net/ipv4/ip_forward") == "1":
        caps |= 0x0010
    if os.path.isdir("/sys/class/net") and any(
            os.path.isdir(f"/sys/class/net/{d}/bridge")
            for d in os.listdir("/sys/class/net")):
        caps |= 0x0004
    if os.path.isdir("/sys/class/net") and any(
            os.path.isdir(f"/sys/class/net/{d}/wireless")
            for d in os.listdir("/sys/class/net")):
        caps |= 0x0008
    return caps


def _get_ipv6(iface: str):
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[5] == iface:
                    addr = bytes.fromhex(parts[0])
                    if addr != b'\x00' * 15 + b'\x01':
                        return addr
    except OSError:
        pass
    return None


def _get_os_info() -> dict:
    info = {"sw_revision": "", "hw_revision": "", "fw_revision": "",
            "serial": "", "manufacturer": "", "model": "", "asset": ""}
    info["sw_revision"] = os.uname().release
    dmi = "/sys/class/dmi/id"
    if os.path.isdir(dmi):
        info["manufacturer"] = _sysfs(f"{dmi}/sys_vendor")
        info["model"]        = _sysfs(f"{dmi}/product_name")
        info["serial"]       = _sysfs(f"{dmi}/product_serial")
        info["hw_revision"]  = _sysfs(f"{dmi}/product_version")
        info["fw_revision"]  = _sysfs(f"{dmi}/bios_version")
        info["asset"]        = _sysfs(f"{dmi}/chassis_asset_tag")
    return info


# ── Org TLV helper ────────────────────────────

def _org(oui: bytes, subtype: int, data: bytes) -> bytes:
    return build_tlv(TLV_ORG_SPECIFIC, oui + bytes([subtype]) + data)


# ── 802.1 TLV builders ────────────────────────

def _build_8021_tlvs(iface: str) -> bytes:
    c     = config
    tlvs  = b""
    vlans = _get_vlans(iface)

    if c.TLV_DOT1_PVID_ENABLED:
        pvid = vlans[0][0] if vlans else 0
        tlvs += _org(OUI_8021, 1, struct.pack("!H", pvid))

    if c.TLV_DOT1_PPVID_ENABLED:
        ppvid = vlans[0][0] if vlans else 0
        flags = 0x06 if vlans else 0x00
        tlvs += _org(OUI_8021, 2, struct.pack("!BH", flags, ppvid))

    if c.TLV_DOT1_VLAN_NAME_ENABLED:
        for vid, name in vlans:
            nb = name.encode()[:32]
            tlvs += _org(OUI_8021, 3, struct.pack("!HB", vid, len(nb)) + nb)

    if c.TLV_DOT1_PROTO_ENABLED:
        tlvs += _org(OUI_8021, 4, bytes([2, 0x81, 0x00]))

    return tlvs


# ── 802.3 TLV builders ────────────────────────

def _build_8023_tlvs(iface: str) -> bytes:
    c    = config
    tlvs = b""
    speed, duplex, autoneg = _get_speed_duplex(iface)

    if c.TLV_DOT3_MAC_PHY_ENABLED:
        mau   = _speed_duplex_to_mau(speed, duplex)
        abyte = 0x03 if autoneg else 0x00
        tlvs += _org(OUI_8023, 1, struct.pack("!BH", abyte, mau))

    if c.TLV_DOT3_POE_ENABLED:
        p       = c.DOT3_POE
        pc_bit  = 0x01 if p["port_class"] == "PSE" else 0x00
        sup_bit = 0x02 if p["poe_supported"]       else 0x00
        ena_bit = 0x04 if p["poe_enabled"]          else 0x00
        ctl_bit = 0x08 if p["pairs_controllable"]   else 0x00
        mdi     = pc_bit | sup_bit | ena_bit | ctl_bit
        tlvs += _org(OUI_8023, 2,
                     struct.pack("!BBB", mdi, p["power_pair"], p["power_class"]))

    if c.TLV_DOT3_AGG_ENABLED:
        capable, enabled, agg_id = _get_aggregation(iface)
        status = (0x01 if capable else 0x00) | (0x02 if enabled else 0x00)
        tlvs += _org(OUI_8023, 3, struct.pack("!BI", status, agg_id))

    if c.TLV_DOT3_MTU_ENABLED:
        tlvs += _org(OUI_8023, 4, struct.pack("!H", _get_mtu(iface)))

    return tlvs


# ── LLDP-MED location encoding ────────────────

def _encode_med_location(loc: dict):
    """
    Encode MED location per TIA-1057 sect 10.2.4.
    Returns bytes or None.
    """
    fmt = loc.get("format")

    if fmt == "elin":
        elin = loc.get("elin", "")[:25].encode()
        return bytes([3]) + elin

    if fmt == "coordinate":
        # TIA-1057 Annex P / RFC 3825 fixed-point encoding
        # Latitude : 34-bit 2's complement, resolution 6-bit, total 40 bits
        # Longitude: same
        # Altitude : 4-bit type + 30-bit value
        # Datum    : 1 byte
        lat   = float(loc.get("latitude",   0.0))
        lon   = float(loc.get("longitude",  0.0))
        alt   = float(loc.get("altitude_m", 0.0))
        datum = int(loc.get("datum", 1)) & 0xFF

        def _fixed34(deg: float) -> int:
            """Convert degrees to 34-bit 2's complement (units = 1/2^25 deg)."""
            val = int(deg * (1 << 25))
            if val < 0:
                val = val & 0x3FFFFFFFF  # 34-bit mask
            return val & 0x3FFFFFFFF

        lat_val = _fixed34(lat)
        lon_val = _fixed34(lon)
        alt_val = int(alt * 256) & 0x3FFFFFFF   # 30-bit, units 1/256 m

        # Resolution fields: use max resolution (34 for lat/lon, 30 for alt)
        lat_res = 34
        lon_res = 34
        alt_res = 30

        # Pack into 16 bytes per TIA-1057 Table 13
        # [lat_res(6) | lat(34)] [lon_res(6) | lon(34)] [alt_type(4)|alt_res(6)|alt(24)] [datum(8)]
        lat_word = ((lat_res & 0x3F) << 34) | (lat_val & 0x3FFFFFFFF)
        lon_word = ((lon_res & 0x3F) << 34) | (lon_val & 0x3FFFFFFFF)
        alt_word = (1 << 30) | ((alt_res & 0x3F) << 24) | (alt_val >> 6)
        # final byte: low 6 bits of alt_val + datum
        alt_low  = alt_val & 0x3F

        b  = struct.pack("!Q", lat_word)[-5:]  # 40 bits
        b += struct.pack("!Q", lon_word)[-5:]  # 40 bits
        b += struct.pack("!I", alt_word)       # 32 bits
        b += struct.pack("!BB", alt_low, datum)# 16 bits → total 16 bytes
        return bytes([1]) + b

    if fmt == "civic":
        CIVIC_CA = {
            "language": 0, "country_subdivision": 1, "county": 2,
            "city": 3, "city_division": 4, "block": 5, "street": 6,
            "direction": 7, "street_suffix": 9, "number": 10,
            "landmark": 21, "additional": 22, "name": 23, "zip": 24,
            "building": 25, "unit": 26, "floor": 27, "room": 28,
            "place_type": 29,
        }
        country = loc.get("country", "US").encode()[:2]
        body    = b""
        for field, code in CIVIC_CA.items():
            val = loc.get(field)
            if val:
                vb = str(val).encode()[:255]
                body += struct.pack("!BB", code, len(vb)) + vb
        inner = bytes([2]) + country + body   # what=2 (Client Location)
        return bytes([2]) + struct.pack("!B", len(inner)) + inner

    return None


# ── LLDP-MED TLV builders ─────────────────────

def _build_med_tlvs(iface: str, os_info: dict, caps: int) -> bytes:
    c    = config
    tlvs = b""

    if c.TLV_MED_CAPS_ENABLED:
        med_caps = 0x0001
        if c.TLV_MED_POLICY_ENABLED:    med_caps |= 0x0002
        if c.TLV_MED_LOCATION_ENABLED:  med_caps |= 0x0004
        if c.TLV_MED_POE_ENABLED:       med_caps |= 0x0008
        if c.TLV_MED_INVENTORY_ENABLED: med_caps |= 0x0020
        tlvs += _org(OUI_MEDEXT, 1, struct.pack("!HB", med_caps, c.MED_DEVICE_CLASS))

    if c.TLV_MED_POLICY_ENABLED:
        for p in c.MED_NETWORK_POLICIES:
            policy = (
                (p["app_type"]       << 21) |
                (int(p["unknown"])   << 20) |
                (int(p["tagged"])    << 19) |
                (p["vlan_id"]        <<  7) |
                (p["priority"]       <<  4) |
                (p["dscp"]           <<  0)
            )
            tlvs += _org(OUI_MEDEXT, 2, struct.pack("!I", policy)[1:])

    if c.TLV_MED_LOCATION_ENABLED and c.MED_LOCATION:
        encoded = _encode_med_location(c.MED_LOCATION)
        if encoded:
            tlvs += _org(OUI_MEDEXT, 3, encoded)

    if c.TLV_MED_POE_ENABLED:
        p  = c.MED_POE
        mw = int(p["power_mw"] / 100)
        b0 = (((p["power_type"]   & 0x03) << 6) |
              ((p["power_source"] & 0x03) << 4) |
              ((p["priority"]     & 0x0F)))
        tlvs += _org(OUI_MEDEXT, 4, struct.pack("!BH", b0, mw))

    if c.TLV_MED_INVENTORY_ENABLED:
        for subtype, value in {
            5:  os_info["hw_revision"],  6: os_info["fw_revision"],
            7:  os_info["sw_revision"],  8: os_info["serial"],
            9:  os_info["manufacturer"], 10: os_info["model"],
            11: os_info["asset"],
        }.items():
            if value:
                tlvs += _org(OUI_MEDEXT, subtype, value.encode()[:32])

    return tlvs


# ── Custom TLV builder ────────────────────────

def _build_custom_tlvs() -> bytes:
    tlvs = b""
    for entry in config.CUSTOM_TLVS:
        try:
            oui  = bytes.fromhex(entry["oui"])
            sub  = int(entry["subtype"])
            data = bytes.fromhex(entry.get("data", ""))
            tlvs += _org(oui, sub, data)
        except Exception as e:
            print(f"[SEND] Skipping malformed custom TLV {entry}: {e}")
    return tlvs


# ── Frame builder ─────────────────────────────

def build_lldp_frame(interface: str, ttl: int) -> bytes:
    c = config
    src_mac   = get_mac(interface)
    
    # Management Address selection: Config override vs Interface IP
    try:
        mgmt_ip = socket.inet_aton(c.MGMT_IPV4) if c.MGMT_IPV4 else get_ip(interface)
        mgmt_ip6 = socket.inet_pton(socket.AF_INET6, c.MGMT_IPV6) if c.MGMT_IPV6 else _get_ipv6(interface)
    except socket.error:
        mgmt_ip = get_ip(interface)
        mgmt_ip6 = _get_ipv6(interface)

    hostname  = socket.gethostname()
    uname     = os.uname()
    caps      = _detect_capabilities()
    os_info   = _get_os_info()
    if_index  = _get_if_index(interface)
    port_desc = _get_port_description(interface)
    sys_desc  = (f"{uname.sysname} {uname.nodename} {uname.release} "
                 f"{uname.version} {uname.machine}")

    # Chassis ID Logic
    c_id_type = c.CHASSIS_ID_SUBTYPE
    c_id_val  = c.CHASSIS_ID.encode() if c.CHASSIS_ID else src_mac
    if not c.CHASSIS_ID and c_id_type == 4:
        c_id_val = bytes([4]) + src_mac
    else:
        c_id_val = bytes([c_id_type]) + c_id_val

    tlvs = (
        build_tlv(TLV_CHASSIS_ID, c_id_val)
        + build_tlv(TLV_PORT_ID,  bytes([c.PORT_ID_SUBTYPE]) + interface.encode())
        + build_tlv(TLV_TTL,      struct.pack("!H", ttl))
    )

    if c.TLV_PORT_DESC_ENABLED:
        tlvs += build_tlv(TLV_PORT_DESC, port_desc.encode()[:255])
    if c.TLV_SYS_NAME_ENABLED:
        tlvs += build_tlv(TLV_SYS_NAME,  hostname.encode()[:255])
    if c.TLV_SYS_DESC_ENABLED:
        tlvs += build_tlv(TLV_SYS_DESC,  sys_desc.encode()[:255])
    if c.TLV_CAPABILITIES_ENABLED:
        tlvs += build_tlv(TLV_CAPABILITIES, struct.pack("!HH", caps, caps))

    # Management Address (Only send if address is non-zero)
    if c.TLV_MGMT_ADDR_ENABLED and mgmt_ip != b"\x00\x00\x00\x00":
        tlvs += build_tlv(TLV_MGMT_ADDR,
                          struct.pack("!BB", 5, 1) + mgmt_ip
                          + struct.pack("!BIB", 2, if_index, 0))
    if c.TLV_MGMT_ADDR_IPV6_ENABLED and mgmt_ip6 and mgmt_ip6 != b"\x00" * 16:
        tlvs += build_tlv(TLV_MGMT_ADDR,
                          struct.pack("!BB", 17, 2) + mgmt_ip6
                          + struct.pack("!BIB", 2, if_index, 0))

    if any([c.TLV_DOT1_PVID_ENABLED, c.TLV_DOT1_PPVID_ENABLED,
            c.TLV_DOT1_VLAN_NAME_ENABLED, c.TLV_DOT1_PROTO_ENABLED]):
        tlvs += _build_8021_tlvs(interface)

    if any([c.TLV_DOT3_MAC_PHY_ENABLED, c.TLV_DOT3_POE_ENABLED,
            c.TLV_DOT3_AGG_ENABLED,      c.TLV_DOT3_MTU_ENABLED]):
        tlvs += _build_8023_tlvs(interface)

    if any([c.TLV_MED_CAPS_ENABLED,     c.TLV_MED_POLICY_ENABLED,
            c.TLV_MED_LOCATION_ENABLED, c.TLV_MED_POE_ENABLED,
            c.TLV_MED_INVENTORY_ENABLED]):
        tlvs += _build_med_tlvs(interface, os_info, caps)

    if c.CUSTOM_TLVS:
        tlvs += _build_custom_tlvs()

    tlvs += build_tlv(TLV_END, b"")
    return LLDP_MULTICAST_MAC + src_mac + struct.pack("!H", LLDP_ETHERTYPE) + tlvs


# ── Thread entry point ────────────────────────

def run(interface: str, stop_event: threading.Event = None):
    """
    Send LLDP frames on *interface*.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((interface, LLDP_ETHERTYPE))
    
    # IEEE 802.1AB 9.2.2.1: Fast Start Mechanism
    fast_count = getattr(config, "TX_FAST_INIT", 4)
    
    print(f"[SEND] [{interface}] Started (FastStart={fast_count} frames)")
    
    while not (stop_event and stop_event.is_set()):
        # Determine interval: 1s during fast start, otherwise config.SEND_INTERVAL
        current_ttl = config.TTL
        if fast_count > 0:
            interval = 1
            fast_count -= 1
        else:
            interval = config.SEND_INTERVAL

        try:
            sock.send(build_lldp_frame(interface, current_ttl))
            print(f"[SEND] [{interface}] {datetime.now().strftime('%H:%M:%S')} "
                  f"frame sent (TTL={current_ttl}s interval={interval}s)")
        except OSError as e:
            print(f"[SEND] [{interface}] Error: {e}")
            break

        # IEEE 802.1AB 9.2.2: Transmission Jitter
        # Add up to 10% random jitter to the interval
        jitter = interval * 0.1 * random.random()
        total_wait = interval + jitter

        # Wait for interval or stop signal
        if stop_event:
            if stop_event.wait(timeout=total_wait):
                break
        else:
            time.sleep(total_wait)

    # IEEE 802.1AB 9.2.2: Shutdown LLDPDU
    try:
        print(f"[SEND] [{interface}] Sending shutdown LLDPDU (TTL=0)")
        sock.send(build_lldp_frame(interface, 0))
    except OSError:
        pass
    finally:
        sock.close()
