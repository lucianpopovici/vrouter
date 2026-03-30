"""
Shared config key groupings for BFD.
Used by config_manager and startup for schema export and display.
"""

# Keys shown in 'bfd config show'
DISPLAY_GROUPS = {
    "Timers": [
        "DESIRED_MIN_TX_US",
        "REQUIRED_MIN_RX_US",
        "DETECT_MULT",
    ],
    "Session": [
        "MAX_SESSIONS",
        "DEFAULT_AUTH_TYPE",
        "ECHO_ENABLED",
    ],
    "Logging": [
        "LOG_LEVEL",
        "LOG_STATE_CHANGES",
    ],
}

# Keys that are safe to expose via IPC (no secrets)
PUBLIC_KEYS = [
    "DESIRED_MIN_TX_US",
    "REQUIRED_MIN_RX_US",
    "DETECT_MULT",
    "MAX_SESSIONS",
    "ECHO_ENABLED",
    "LOG_LEVEL",
    "LOG_STATE_CHANGES",
]

# Keys requiring restart to take effect
RESTART_REQUIRED_KEYS = [
    "MAX_SESSIONS",
]
