# lldp/display.py
# Formats and prints neighbor info and the periodic neighbor table.
# Reads config.DISPLAY_INTERVAL live each iteration.

import time
from datetime import datetime

from . import config

FIELD_GROUPS = {
    "General": ["interface", "last_seen"],
    "Mandatory": ["chassis_id", "port_id", "ttl"],
    "Basic Info": [
        "port_description", "system_name", "system_description",
        "system_capabilities", "enabled_capabilities", "management_address",
    ],
    "IEEE 802.1": [
        "dot1_port_vlan_id", "dot1_proto_vlan_id",
        "dot1_vlan_names", "dot1_protocol_identity",
    ],
    "IEEE 802.3": [
        "dot3_mac_phy", "dot3_poe",
        "dot3_link_aggregation", "dot3_max_frame_size",
    ],
    "LLDP-MED": [
        "med_capabilities", "med_device_class",
        "med_network_policy", "med_location", "med_poe_ext",
        "med_hw_revision", "med_fw_revision", "med_sw_revision",
        "med_serial_number", "med_manufacturer", "med_model_name",
        "med_asset_id",
    ],
}


def print_neighbor(mac: str, info: dict):
    """Print a single neighbor entry grouped by TLV category."""
    print(f"  {'MAC Address':<30}: {mac}")
    for group, fields in FIELD_GROUPS.items():
        lines = []
        for key in fields:
            val = info.get(key)
            if val is None:
                continue
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            lines.append(
                f"  {key.replace('_', ' ').title():<30}: {val}")
        if lines:
            print(f"  -- {group} --")
            for line in lines:
                print(line)

    custom = info.get("custom_tlvs")
    if custom:
        print("  -- Custom TLVs --")
        for i, t in enumerate(custom):
            print(f"  #{i:<4} OUI={t['oui']}  sub={t['subtype']:<4}"
                  f"  data={t['data'] or '(empty)'}")


def run(neighbors: dict, lock):
    """
    Periodically print the full neighbor table.
    Reads config.DISPLAY_INTERVAL live so runtime changes take effect.
    """
    while True:
        # Read interval live — runtime changes take effect next sleep
        time.sleep(config.DISPLAY_INTERVAL)
        ts = datetime.now().strftime("%H:%M:%S")
        with lock:
            print("\n" + "=" * 60)
            print(f"  LLDP NEIGHBOR TABLE  ({ts})")
            print("=" * 60)
            if not neighbors:
                print("  No neighbors discovered yet.")
            else:
                for mac, info in neighbors.items():
                    print_neighbor(mac, info)
                    print("-" * 60)
