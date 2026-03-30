# lldp/config.py
# ─────────────────────────────────────────────
# Default configuration.
# Scalar values: updated via config_manager.set() or runtime_config.json.
# Structured values (MED policies/location/PoE, custom TLVs):
#   managed via dedicated config_manager helpers.
# ─────────────────────────────────────────────

# ── Files ─────────────────────────────────────

INTERFACES_FILE   = "interfaces.txt"
RUNTIME_CONFIG    = "lldp_runtime_config.json"

# ── Timing ────────────────────────────────────

SEND_INTERVAL     = 30
TTL               = 120
DISPLAY_INTERVAL  = 30
WATCH_INTERVAL    = 5
REINIT_DELAY      = 2
TX_FAST_INIT      = 4

# ── Basic optional TLV toggles ────────────────

TLV_PORT_DESC_ENABLED      = True
TLV_SYS_NAME_ENABLED       = True
TLV_SYS_DESC_ENABLED       = True
TLV_CAPABILITIES_ENABLED   = True
TLV_MGMT_ADDR_ENABLED      = True
TLV_MGMT_ADDR_IPV6_ENABLED = True
CHASSIS_ID                 = ""    # Empty = use interface MAC
CHASSIS_ID_SUBTYPE         = 4     # 4: MAC, 7: Locally Assigned
PORT_ID_SUBTYPE            = 5     # 5: Interface Name, 7: Locally Assigned
MGMT_IPV4                  = ""
MGMT_IPV6                  = ""

# ── IEEE 802.1 TLV toggles ────────────────────

TLV_DOT1_PVID_ENABLED      = True
TLV_DOT1_PPVID_ENABLED     = True
TLV_DOT1_VLAN_NAME_ENABLED = True
TLV_DOT1_PROTO_ENABLED     = True

# ── IEEE 802.3 TLV toggles ────────────────────

TLV_DOT3_MAC_PHY_ENABLED   = True
TLV_DOT3_POE_ENABLED       = False
TLV_DOT3_AGG_ENABLED       = True
TLV_DOT3_MTU_ENABLED       = True

# ── LLDP-MED TLV toggles ─────────────────────

TLV_MED_CAPS_ENABLED       = True
TLV_MED_POLICY_ENABLED     = False
TLV_MED_LOCATION_ENABLED   = False
TLV_MED_POE_ENABLED        = False
TLV_MED_INVENTORY_ENABLED  = True
MED_DEVICE_CLASS           = 4  # 1-3: Endpoint, 4: Network Connectivity

# ── IEEE 802.3 PoE configuration ─────────────
# Used when TLV_DOT3_POE_ENABLED = True
DOT3_POE = {
    "port_class":         "PSE",
    "poe_supported":       True,
    "poe_enabled":         True,
    "pairs_controllable":  False,
    "power_pair":          1,
    "power_class":         0,
}

# ── LLDP-MED Network Policies ─────────────────
# List of dicts. Used when TLV_MED_POLICY_ENABLED = True.
# Keys: app_type(1-8), unknown(bool), tagged(bool),
#       vlan_id(0-4094), priority(0-7), dscp(0-63)
MED_NETWORK_POLICIES = []

# ── LLDP-MED Location ─────────────────────────
# Used when TLV_MED_LOCATION_ENABLED = True.
# format: "coordinate" | "civic" | "elin"
# coordinate: latitude, longitude, altitude_m, datum(1-3)
# civic: country + any address fields
# elin: elin (string)
MED_LOCATION = {}

# ── LLDP-MED Extended PoE ─────────────────────
# Used when TLV_MED_POE_ENABLED = True.
MED_POE = {
    "power_type":   0,
    "power_source": 1,
    "priority":     2,
    "power_mw":     15400,
}

# ── Security ─────────────────────────────────────────────
# Max LLDP neighbors accepted per interface (#1 — memory exhaustion guard)
# lldpd default is 32. Set to 0 to disable the limit (not recommended).
MAX_NEIGHBORS_PER_INTERFACE = 32

# Allowed UIDs for IPC connections (#6 — authentication).
# None = allow any local user (same as before).
# [0, 1000] = allow root and UID 1000 only.
# Set to [os.getuid()] to restrict to the daemon's own user.
IPC_ALLOWED_UIDS = None   # restrict with e.g. [0, 0]

# ── Custom TLVs ───────────────────────────────
# Injected into every outgoing frame.
# Each entry: {"oui": "AA:BB:CC", "subtype": N, "data": "hex"}
# Managed via config_manager.custom_tlv_add/remove/list()
CUSTOM_TLVS = []
