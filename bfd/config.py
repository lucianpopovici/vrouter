"""
BFD configuration defaults and structured config.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULTS = {
    # Timers (microseconds)
    "DESIRED_MIN_TX_US":   300000,   # 300 ms
    "REQUIRED_MIN_RX_US":  300000,   # 300 ms
    "DETECT_MULT":         3,        # detection time multiplier

    # Session
    "MAX_SESSIONS":        64,
    "DEFAULT_AUTH_TYPE":   "none",   # none | md5 | sha1
    "ECHO_ENABLED":        False,

    # Logging
    "LOG_LEVEL":           "INFO",   # DEBUG | INFO | WARNING | ERROR
    "LOG_STATE_CHANGES":   True,
}

VALID_AUTH_TYPES = {"none", "md5", "sha1"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}

# ── Validators ────────────────────────────────────────────────────────────────

def validate(key: str, value) -> tuple[bool, str]:
    """Return (ok, error_message). error_message is '' when ok."""
    key = key.upper()

    if key in ("DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US"):
        try:
            v = int(value)
        except (TypeError, ValueError):
            return False, f"{key} must be an integer (microseconds)"
        if v < 10000 or v > 60000000:
            return False, f"{key} must be between 10000 and 60000000 µs"
        return True, ""

    if key == "DETECT_MULT":
        try:
            v = int(value)
        except (TypeError, ValueError):
            return False, "DETECT_MULT must be an integer"
        if v < 1 or v > 255:
            return False, "DETECT_MULT must be between 1 and 255"
        return True, ""

    if key == "MAX_SESSIONS":
        try:
            v = int(value)
        except (TypeError, ValueError):
            return False, "MAX_SESSIONS must be an integer"
        if v < 1 or v > 1024:
            return False, "MAX_SESSIONS must be between 1 and 1024"
        return True, ""

    if key == "DEFAULT_AUTH_TYPE":
        if str(value).lower() not in VALID_AUTH_TYPES:
            return False, f"DEFAULT_AUTH_TYPE must be one of: {', '.join(sorted(VALID_AUTH_TYPES))}"
        return True, ""

    if key == "ECHO_ENABLED":
        if str(value).lower() not in ("true", "false", "1", "0"):
            return False, "ECHO_ENABLED must be true or false"
        return True, ""

    if key == "LOG_LEVEL":
        if str(value).upper() not in VALID_LOG_LEVELS:
            return False, f"LOG_LEVEL must be one of: {', '.join(sorted(VALID_LOG_LEVELS))}"
        return True, ""

    if key == "LOG_STATE_CHANGES":
        if str(value).lower() not in ("true", "false", "1", "0"):
            return False, "LOG_STATE_CHANGES must be true or false"
        return True, ""

    return False, f"Unknown config key: {key}"


def coerce(key: str, value) -> object:
    """Coerce value to the correct Python type for key."""
    key = key.upper()
    if key in ("DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US", "DETECT_MULT", "MAX_SESSIONS"):
        return int(value)
    if key in ("ECHO_ENABLED", "LOG_STATE_CHANGES"):
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1")
    if key == "DEFAULT_AUTH_TYPE":
        return str(value).lower()
    if key == "LOG_LEVEL":
        return str(value).upper()
    return value


# ── Structured config ─────────────────────────────────────────────────────────

@dataclass
class BFDConfig:
    desired_min_tx_us:   int   = field(default=DEFAULTS["DESIRED_MIN_TX_US"])
    required_min_rx_us:  int   = field(default=DEFAULTS["REQUIRED_MIN_RX_US"])
    detect_mult:         int   = field(default=DEFAULTS["DETECT_MULT"])
    max_sessions:        int   = field(default=DEFAULTS["MAX_SESSIONS"])
    default_auth_type:   str   = field(default=DEFAULTS["DEFAULT_AUTH_TYPE"])
    echo_enabled:        bool  = field(default=DEFAULTS["ECHO_ENABLED"])
    log_level:           str   = field(default=DEFAULTS["LOG_LEVEL"])
    log_state_changes:   bool  = field(default=DEFAULTS["LOG_STATE_CHANGES"])

    @classmethod
    def from_dict(cls, d: dict) -> "BFDConfig":
        mapping = {
            "DESIRED_MIN_TX_US":  "desired_min_tx_us",
            "REQUIRED_MIN_RX_US": "required_min_rx_us",
            "DETECT_MULT":        "detect_mult",
            "MAX_SESSIONS":       "max_sessions",
            "DEFAULT_AUTH_TYPE":  "default_auth_type",
            "ECHO_ENABLED":       "echo_enabled",
            "LOG_LEVEL":          "log_level",
            "LOG_STATE_CHANGES":  "log_state_changes",
        }
        kwargs = {}
        for upper_key, attr in mapping.items():
            if upper_key in d:
                kwargs[attr] = coerce(upper_key, d[upper_key])
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "DESIRED_MIN_TX_US":  self.desired_min_tx_us,
            "REQUIRED_MIN_RX_US": self.required_min_rx_us,
            "DETECT_MULT":        self.detect_mult,
            "MAX_SESSIONS":       self.max_sessions,
            "DEFAULT_AUTH_TYPE":  self.default_auth_type,
            "ECHO_ENABLED":       self.echo_enabled,
            "LOG_LEVEL":          self.log_level,
            "LOG_STATE_CHANGES":  self.log_state_changes,
        }
