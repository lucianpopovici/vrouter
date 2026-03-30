# lldp/config_manager.py
# Runtime configuration manager.
# Scalar settings  → config_manager.set/get/reset/show
# Custom TLVs      → custom_tlv_add/remove/list
# MED Network Policy → med_policy_add/remove/list
# MED Location     → med_location_set/clear
# MED PoE          → med_poe_set
# 802.3 PoE        → dot3_poe_set

import json
import os
import time
import threading

from . import config

# ── Scalar schema ─────────────────────────────
# key -> (type, description)

SCHEMA: dict = {
    # key -> (type, description, min, max)   None = no bound
    # Timing
    "SEND_INTERVAL":             (int,  "Seconds between LLDP advertisements",           5,    3600),
    "TTL":                       (int,  "TTL advertised in frames (seconds)",             10,  65535),
    "DISPLAY_INTERVAL":          (int,  "Seconds between neighbor table prints",          5,    3600),
    "WATCH_INTERVAL":            (int,  "Seconds between file-change polls",              2,     300),
    "REINIT_DELAY":              (int,  "Delay before re-initializing an interface",      1,     10),
    "TX_FAST_INIT":              (int,  "Number of fast-start LLDPDUs to send",           1,     10),
    # Basic TLVs
    "TLV_PORT_DESC_ENABLED":     (bool, "Advertise Port Description TLV",                None, None),
    "TLV_SYS_NAME_ENABLED":      (bool, "Advertise System Name TLV",                     None, None),
    "TLV_SYS_DESC_ENABLED":      (bool, "Advertise System Description TLV",              None, None),
    "TLV_CAPABILITIES_ENABLED":  (bool, "Advertise System Capabilities TLV",             None, None),
    "TLV_MGMT_ADDR_ENABLED":     (bool, "Advertise Management Address (IPv4)",           None, None),
    "TLV_MGMT_ADDR_IPV6_ENABLED":(bool, "Advertise Management Address (IPv6)",           None, None),
    "CHASSIS_ID":                (str,  "Override Chassis ID",                           None, None),
    "CHASSIS_ID_SUBTYPE":        (int,  "Chassis ID Subtype (4=MAC, 7=Local)",           1,       7),
    "PORT_ID_SUBTYPE":           (int,  "Port ID Subtype (5=Iface, 7=Local)",            1,       7),
    "MGMT_IPV4":                 (str,  "Override Management IPv4 address",              None, None),
    "MGMT_IPV6":                 (str,  "Override Management IPv6 address",              None, None),
    # 802.1 TLVs
    "TLV_DOT1_PVID_ENABLED":     (bool, "Advertise Port VLAN ID TLV",                    None, None),
    "TLV_DOT1_PPVID_ENABLED":    (bool, "Advertise Port & Protocol VLAN ID TLV",         None, None),
    "TLV_DOT1_VLAN_NAME_ENABLED":(bool, "Advertise VLAN Name TLVs",                      None, None),
    "TLV_DOT1_PROTO_ENABLED":    (bool, "Advertise Protocol Identity TLV",               None, None),
    # 802.3 TLVs
    "TLV_DOT3_MAC_PHY_ENABLED":  (bool, "Advertise MAC/PHY TLV",                         None, None),
    "TLV_DOT3_POE_ENABLED":      (bool, "Advertise 802.3 PoE TLV",                       None, None),
    "TLV_DOT3_AGG_ENABLED":      (bool, "Advertise Link Aggregation TLV",                None, None),
    "TLV_DOT3_MTU_ENABLED":      (bool, "Advertise Max Frame Size TLV",                  None, None),
    # LLDP-MED TLVs
    "TLV_MED_CAPS_ENABLED":      (bool, "Advertise LLDP-MED Capabilities TLV",           None, None),
    "TLV_MED_POLICY_ENABLED":    (bool, "Advertise LLDP-MED Network Policy TLV(s)",      None, None),
    "TLV_MED_LOCATION_ENABLED":  (bool, "Advertise LLDP-MED Location TLV",               None, None),
    "TLV_MED_POE_ENABLED":       (bool, "Advertise LLDP-MED Extended PoE TLV",           None, None),
    "TLV_MED_INVENTORY_ENABLED": (bool, "Advertise LLDP-MED Inventory TLVs",             None, None),
    "MED_DEVICE_CLASS":          (int,  "LLDP-MED Device Class (1-4)",                   1,       4),
    # Security
    "MAX_NEIGHBORS_PER_INTERFACE":(int, "Max neighbors accepted per interface",           1,    1024),
}

_lock = threading.Lock()


# ── Internal helpers ──────────────────────────

def _coerce(key: str, value) -> object:
    """Cast value to schema type and enforce min/max bounds. (#5)"""
    entry = SCHEMA[key]
    expected, _, lo, hi = entry[0], entry[1], entry[2] if len(entry)>2 else None, entry[3] if len(entry)>3 else None
    if expected is bool:
        if isinstance(value, bool):  return value
        if isinstance(value, str):
            if value.lower() in ("true",  "1", "yes", "on"):  return True
            if value.lower() in ("false", "0", "no",  "off"): return False
        if isinstance(value, int):   return bool(value)
        raise ValueError(f"Cannot convert {value!r} to bool")
    if expected is int:
        v = int(value)
        if lo is not None and v < lo:
            raise ValueError(f"'{key}' minimum is {lo}, got {v}")
        if hi is not None and v > hi:
            raise ValueError(f"'{key}' maximum is {hi}, got {v}")
        return v
    return expected(value)


def _load_runtime() -> dict:
    path = config.RUNTIME_CONFIG
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[CONFIG] Warning: could not read {path}: {e}")
        return {}


def _save_runtime(data: dict):
    try:
        with open(config.RUNTIME_CONFIG, "w") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        print(f"[CONFIG] Warning: could not write {config.RUNTIME_CONFIG}: {e}")


def _apply_scalars(data: dict):
    for key, raw in data.items():
        if key not in SCHEMA:
            continue
        try:
            setattr(config, key, _coerce(key, raw))
        except (ValueError, TypeError) as e:
            print(f"[CONFIG] Invalid value for '{key}': {e}")


def _apply_structured(data: dict):
    """Restore structured values (lists/dicts) from persisted JSON."""
    if "CUSTOM_TLVS" in data:
        config.CUSTOM_TLVS = data["CUSTOM_TLVS"]
    if "MED_NETWORK_POLICIES" in data:
        config.MED_NETWORK_POLICIES = data["MED_NETWORK_POLICIES"]
    if "MED_LOCATION" in data:
        config.MED_LOCATION = data["MED_LOCATION"]
    if "MED_POE" in data:
        config.MED_POE = data["MED_POE"]
    if "DOT3_POE" in data:
        config.DOT3_POE = data["DOT3_POE"]


# ── Scalar API ────────────────────────────────

def load():
    """Apply runtime_config.json at startup."""
    with _lock:
        data = _load_runtime()
        if data:
            _apply_scalars(data)
            _apply_structured(data)
            print(f"[CONFIG] Loaded {len(data)} entry/entries from "
                  f"{config.RUNTIME_CONFIG}")


def get(key: str):
    """Return the current live value for a scalar key."""
    key = key.upper()
    if key not in SCHEMA:
        raise KeyError(f"Unknown key '{key}'. Valid: {', '.join(SCHEMA)}")
    return getattr(config, key)


def set(key: str, value):
    """Update a scalar key live and persist it."""
    key = key.upper()
    if key not in SCHEMA:
        raise KeyError(f"Unknown key '{key}'. Valid: {', '.join(SCHEMA)}")
    with _lock:
        coerced = _coerce(key, value)
        setattr(config, key, coerced)
        data = _load_runtime()
        data[key] = coerced
        _save_runtime(data)
        print(f"[CONFIG] {key} = {coerced!r}")
        # #10 Warn if TTL < 2 * SEND_INTERVAL (spec guidance)
        ttl      = getattr(config, "TTL",           coerced if key == "TTL"           else 120)
        interval = getattr(config, "SEND_INTERVAL", coerced if key == "SEND_INTERVAL" else 30)
        if ttl < 2 * interval:
            print(f"[CONFIG] WARNING: TTL ({ttl}s) < 2 × SEND_INTERVAL "
                  f"({interval}s). Peers may expire us before next frame.")


def _read_defaults() -> dict:
    """
    Parse config.py with ast to read default scalar values
    without reloading the module (which would wipe live state).
    """
    import ast as _ast
    path = os.path.join(os.path.dirname(__file__), "config.py")
    result = {}
    with open(path) as f:
        tree = _ast.parse(f.read())
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Assign):
            for target in node.targets:
                if isinstance(target, _ast.Name) and target.id in SCHEMA:
                    try:
                        result[target.id] = _ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        pass
    return result


def reset(key: str = None):
    """
    Reset one scalar key (or all) to config.py defaults.
    Uses ast to read defaults — does NOT reload the module,
    so other live config values are untouched.
    """
    defaults = _read_defaults()
    with _lock:
        if key:
            key = key.upper()
            if key not in SCHEMA:
                raise KeyError(f"Unknown key '{key}'")
            default = defaults.get(key)
            if default is not None:
                setattr(config, key, _coerce(key, default))
            data = _load_runtime()
            data.pop(key, None)
            _save_runtime(data)
            print(f"[CONFIG] Reset '{key}' to default: {default!r}")
        else:
            for k, default in defaults.items():
                try:
                    setattr(config, k, _coerce(k, default))
                except Exception:
                    pass
            data = _load_runtime()
            data = {k: v for k, v in data.items() if k not in SCHEMA}
            _save_runtime(data)
            print("[CONFIG] All runtime scalar overrides cleared.")


def show():
    """Print a formatted config table."""
    col = 32
    print(f"\n{'─' * 70}")
    print(f"  {'Key':<{col}} {'Value':<12}  Description")
    print(f"{'─' * 70}")
    groups = {
        "Timing":            ["SEND_INTERVAL", "TTL", "DISPLAY_INTERVAL", "WATCH_INTERVAL"],
        "Basic TLVs":        ["TLV_PORT_DESC_ENABLED", "TLV_SYS_NAME_ENABLED",
                              "TLV_SYS_DESC_ENABLED", "TLV_CAPABILITIES_ENABLED",
                              "TLV_MGMT_ADDR_ENABLED", "TLV_MGMT_ADDR_IPV6_ENABLED"],
        "IEEE 802.1 TLVs":   ["TLV_DOT1_PVID_ENABLED", "TLV_DOT1_PPVID_ENABLED",
                              "TLV_DOT1_VLAN_NAME_ENABLED", "TLV_DOT1_PROTO_ENABLED"],
        "IEEE 802.3 TLVs":   ["TLV_DOT3_MAC_PHY_ENABLED", "TLV_DOT3_POE_ENABLED",
                              "TLV_DOT3_AGG_ENABLED", "TLV_DOT3_MTU_ENABLED"],
        "LLDP-MED TLVs":     ["TLV_MED_CAPS_ENABLED", "TLV_MED_POLICY_ENABLED",
                              "TLV_MED_LOCATION_ENABLED", "TLV_MED_POE_ENABLED",
                              "TLV_MED_INVENTORY_ENABLED"],
    }
    overrides = _load_runtime()
    for group, keys in groups.items():
        print(f"\n  [{group}]")
        for k in keys:
            val  = getattr(config, k)
            desc = SCHEMA[k][1]
            mark = " *" if k in overrides else ""
            print(f"  {k:<{col}} {str(val):<12}  {desc}{mark}")
    # Structured
    print(f"\n  [Structured]")
    print(f"  {'CUSTOM_TLVS':<{col}} {len(config.CUSTOM_TLVS)} entries   "
          f"(use custom_tlv_list() to view)")
    print(f"  {'MED_NETWORK_POLICIES':<{col}} {len(config.MED_NETWORK_POLICIES)} entries")
    print(f"  {'MED_LOCATION':<{col}} {config.MED_LOCATION.get('format', 'not set')}")
    print(f"  {'MED_POE':<{col}} power_type={config.MED_POE.get('power_type','?')}, "
          f"{config.MED_POE.get('power_mw','?')}mW")
    print(f"  {'DOT3_POE':<{col}} class={config.DOT3_POE.get('port_class','?')}")
    if overrides:
        print(f"\n  * = overridden in {config.RUNTIME_CONFIG}")
    print(f"{'─' * 70}\n")


# ── Custom TLV API ────────────────────────────

def custom_tlv_add(oui: str, subtype: int, data_hex: str = "") -> int:
    """
    Add a custom TLV to outgoing frames.

    Args:
        oui       : OUI as "AA:BB:CC" or "AABBCC"
        subtype   : 0-255
        data_hex  : hex string of payload bytes e.g. "01020304"

    Returns: index of the new entry

    Example:
        custom_tlv_add("00:12:34", 1, "deadbeef")
    """
    oui_clean = oui.replace(":", "").upper()
    if len(oui_clean) != 6:
        raise ValueError(f"OUI must be 3 bytes, got '{oui}'")
    try:
        bytes.fromhex(oui_clean)
        bytes.fromhex(data_hex)
    except ValueError as e:
        raise ValueError(f"Invalid hex value: {e}")
    if not 0 <= subtype <= 255:
        raise ValueError(f"subtype must be 0-255, got {subtype}")
    MAX_CUSTOM_DATA = 507  # max org-specific payload (511 - 3 OUI - 1 subtype) (#8)
    if len(data_hex) // 2 > MAX_CUSTOM_DATA:
        raise ValueError(
            f"Custom TLV data too large: {len(data_hex)//2} bytes, "
            f"max {MAX_CUSTOM_DATA}"
        )

    entry = {"oui": oui_clean, "subtype": subtype, "data": data_hex.lower()}
    with _lock:
        config.CUSTOM_TLVS.append(entry)
        _persist_structured()
        idx = len(config.CUSTOM_TLVS) - 1
        print(f"[CONFIG] Custom TLV #{idx} added: OUI={oui_clean} "
              f"subtype={subtype} data={data_hex or '(empty)'}")
        return idx


def custom_tlv_remove(index: int):
    """Remove a custom TLV by index (see custom_tlv_list())."""
    with _lock:
        if not 0 <= index < len(config.CUSTOM_TLVS):
            raise IndexError(f"No custom TLV at index {index}")
        removed = config.CUSTOM_TLVS.pop(index)
        _persist_structured()
        print(f"[CONFIG] Custom TLV #{index} removed: {removed}")


def custom_tlv_list():
    """Print all configured custom TLVs."""
    if not config.CUSTOM_TLVS:
        print("[CONFIG] No custom TLVs configured.")
        return
    print(f"\n  {'#':<4} {'OUI':<8} {'Sub':<5} Data")
    print(f"  {'─'*40}")
    for i, t in enumerate(config.CUSTOM_TLVS):
        print(f"  {i:<4} {t['oui']:<8} {t['subtype']:<5} {t['data'] or '(empty)'}")


# ── MED Network Policy API ────────────────────

APP_TYPES = {
    1: "Voice", 2: "Voice Signaling", 3: "Guest Voice",
    4: "Guest Voice Signaling", 5: "Softphone Voice",
    6: "Video Conferencing", 7: "Streaming Video", 8: "Video Signaling",
}

def med_policy_add(app_type: int, vlan_id: int = 0, priority: int = 0,
                   dscp: int = 0, tagged: bool = False,
                   unknown: bool = False) -> int:
    """
    Add a LLDP-MED Network Policy.
    Also sets TLV_MED_POLICY_ENABLED = True.

    Example:
        med_policy_add(1, vlan_id=100, priority=5, dscp=46, tagged=True)
    """
    if app_type not in APP_TYPES:
        raise ValueError(f"app_type must be 1-8, got {app_type}")
    if not 0 <= vlan_id <= 4094:
        raise ValueError(f"vlan_id must be 0-4094")
    if not 0 <= priority <= 7:
        raise ValueError(f"priority must be 0-7")
    if not 0 <= dscp <= 63:
        raise ValueError(f"dscp must be 0-63")

    entry = {"app_type": app_type, "unknown": unknown, "tagged": tagged,
             "vlan_id": vlan_id, "priority": priority, "dscp": dscp}
    with _lock:
        config.MED_NETWORK_POLICIES.append(entry)
        config.TLV_MED_POLICY_ENABLED = True
        _persist_structured()
        idx = len(config.MED_NETWORK_POLICIES) - 1
        print(f"[CONFIG] MED policy #{idx} added: "
              f"{APP_TYPES[app_type]} VLAN={vlan_id} DSCP={dscp}")
        return idx


def med_policy_remove(index: int):
    """Remove a MED Network Policy by index."""
    with _lock:
        if not 0 <= index < len(config.MED_NETWORK_POLICIES):
            raise IndexError(f"No MED policy at index {index}")
        removed = config.MED_NETWORK_POLICIES.pop(index)
        if not config.MED_NETWORK_POLICIES:
            config.TLV_MED_POLICY_ENABLED = False
        _persist_structured()
        print(f"[CONFIG] MED policy #{index} removed: {removed}")


def med_policy_list():
    """Print all configured MED Network Policies."""
    if not config.MED_NETWORK_POLICIES:
        print("[CONFIG] No MED network policies configured.")
        return
    for i, p in enumerate(config.MED_NETWORK_POLICIES):
        app = APP_TYPES.get(p["app_type"], f"type {p['app_type']}")
        print(f"  #{i}: {app}, VLAN={p['vlan_id']}, tagged={p['tagged']}, "
              f"priority={p['priority']}, dscp={p['dscp']}, unknown={p['unknown']}")


# ── MED Location API ─────────────────────────

def med_location_set(fmt: str, **kwargs):
    """
    Set LLDP-MED location. Also sets TLV_MED_LOCATION_ENABLED = True.

    Formats:
        med_location_set("elin", elin="911")
        med_location_set("coordinate",
                         latitude=48.856, longitude=2.201,
                         altitude_m=117.0, datum=1)
        med_location_set("civic",
                         country="US", city="Roseville",
                         street="Commercial Road", zip="95678")
    """
    if fmt not in ("coordinate", "civic", "elin"):
        raise ValueError("fmt must be 'coordinate', 'civic', or 'elin'")
    loc = {"format": fmt}
    loc.update(kwargs)
    with _lock:
        config.MED_LOCATION = loc
        config.TLV_MED_LOCATION_ENABLED = True
        _persist_structured()
        print(f"[CONFIG] MED location set: {fmt} {kwargs}")


def med_location_clear():
    """Clear MED location and disable the TLV."""
    with _lock:
        config.MED_LOCATION = {}
        config.TLV_MED_LOCATION_ENABLED = False
        _persist_structured()
        print("[CONFIG] MED location cleared.")


# ── MED PoE API ───────────────────────────────

def med_poe_set(power_type: int = 0, power_source: int = 1,
                priority: int = 2, power_mw: int = 15400):
    """
    Configure LLDP-MED Extended PoE. Also sets TLV_MED_POE_ENABLED = True.

    power_type  : 0=PSE, 1=PD, 2=PSE(802.3at), 3=PD(802.3at)
    power_source: 0=Unknown, 1=Primary/PSE, 2=Backup/Local
    priority    : 0=Unknown, 1=Critical, 2=High, 3=Low
    power_mw    : milliwatts

    Example:
        med_poe_set(power_type=0, power_source=1, priority=1, power_mw=30000)
    """
    with _lock:
        config.MED_POE = {
            "power_type": power_type, "power_source": power_source,
            "priority": priority, "power_mw": power_mw,
        }
        config.TLV_MED_POE_ENABLED = True
        _persist_structured()
        print(f"[CONFIG] MED PoE set: type={power_type} source={power_source} "
              f"priority={priority} power={power_mw}mW")


# ── 802.3 PoE API ─────────────────────────────

def dot3_poe_set(port_class: str = "PSE", poe_supported: bool = True,
                 poe_enabled: bool = True, pairs_controllable: bool = False,
                 power_pair: int = 1, power_class: int = 0):
    """
    Configure IEEE 802.3 PoE. Also sets TLV_DOT3_POE_ENABLED = True.

    port_class        : "PSE" or "PD"
    power_pair        : 1=Signal, 2=Spare
    power_class       : 0-4 (802.3af/at class)

    Example:
        dot3_poe_set(port_class="PSE", poe_supported=True,
                     poe_enabled=True, power_class=3)
    """
    if port_class not in ("PSE", "PD"):
        raise ValueError("port_class must be 'PSE' or 'PD'")
    with _lock:
        config.DOT3_POE = {
            "port_class": port_class, "poe_supported": poe_supported,
            "poe_enabled": poe_enabled, "pairs_controllable": pairs_controllable,
            "power_pair": power_pair, "power_class": power_class,
        }
        config.TLV_DOT3_POE_ENABLED = True
        _persist_structured()
        print(f"[CONFIG] 802.3 PoE set: {port_class} class={power_class}")


# ── Persistence helper ────────────────────────

def _persist_structured():
    """Merge structured config objects into runtime_config.json."""
    data = _load_runtime()
    data["CUSTOM_TLVS"]          = config.CUSTOM_TLVS
    data["MED_NETWORK_POLICIES"] = config.MED_NETWORK_POLICIES
    data["MED_LOCATION"]         = config.MED_LOCATION
    data["MED_POE"]              = config.MED_POE
    data["DOT3_POE"]             = config.DOT3_POE
    _save_runtime(data)


# ── Background file watcher ───────────────────

def _watch_runtime_config():
    last_mtime = None
    while True:
        try:
            mtime = os.path.getmtime(config.RUNTIME_CONFIG)
            if mtime != last_mtime:
                last_mtime = mtime
                with _lock:
                    data = _load_runtime()
                    _apply_scalars(data)
                    _apply_structured(data)
                print(f"[CONFIG] Reloaded {config.RUNTIME_CONFIG}")
        except FileNotFoundError:
            pass
        time.sleep(config.WATCH_INTERVAL)


def start_watcher():
    t = threading.Thread(target=_watch_runtime_config,
                         daemon=True, name="config-watcher")
    t.start()
