# lldp/_config_groups.py
# Single source of truth for config key groupings.
# Imported by both config_manager.py and ipc.py to avoid drift.

CONFIG_GROUPS = {
    "Timing": [
        "SEND_INTERVAL", "TTL", "DISPLAY_INTERVAL", "WATCH_INTERVAL",
    ],
    "Basic TLVs": [
        "TLV_PORT_DESC_ENABLED",    "TLV_SYS_NAME_ENABLED",
        "TLV_SYS_DESC_ENABLED",     "TLV_CAPABILITIES_ENABLED",
        "TLV_MGMT_ADDR_ENABLED",    "TLV_MGMT_ADDR_IPV6_ENABLED",
    ],
    "IEEE 802.1 TLVs": [
        "TLV_DOT1_PVID_ENABLED",    "TLV_DOT1_PPVID_ENABLED",
        "TLV_DOT1_VLAN_NAME_ENABLED","TLV_DOT1_PROTO_ENABLED",
    ],
    "IEEE 802.3 TLVs": [
        "TLV_DOT3_MAC_PHY_ENABLED",  "TLV_DOT3_POE_ENABLED",
        "TLV_DOT3_AGG_ENABLED",      "TLV_DOT3_MTU_ENABLED",
    ],
    "LLDP-MED TLVs": [
        "TLV_MED_CAPS_ENABLED",      "TLV_MED_POLICY_ENABLED",
        "TLV_MED_LOCATION_ENABLED",  "TLV_MED_POE_ENABLED",
        "TLV_MED_INVENTORY_ENABLED",
    ],
}
