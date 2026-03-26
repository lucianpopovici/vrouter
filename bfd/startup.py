"""
BFD startup helpers.
- export_schema():       writes bfd_schema.json for project-cli discovery
- load_startup_config(): applies a startup config file to the config manager
Mirrors lldp/startup.py patterns.
"""

import json
import logging
import os
from typing import Optional

from .config import DEFAULTS, validate
from ._config_groups import DISPLAY_GROUPS, RESTART_REQUIRED_KEYS

logger = logging.getLogger(__name__)

SCHEMA_PATH         = os.environ.get("BFD_SCHEMA_PATH",  "/tmp/bfd_schema.json")
STARTUP_CONFIG_PATH = os.environ.get("BFD_STARTUP_CONFIG", "/etc/bfd/startup_config.json")


# ── Schema export ─────────────────────────────────────────────────────────────

def export_schema(path: str = SCHEMA_PATH) -> bool:
    """
    Write bfd_schema.json so project-cli can discover BFD config keys,
    their defaults, types, and groupings.
    """
    schema = {
        "module":  "bfd",
        "version": "1.0.0",
        "socket":  os.environ.get("BFD_SOCK_PATH", "/tmp/bfd.sock"),
        "groups":  DISPLAY_GROUPS,
        "keys":    {},
    }

    type_map = {
        "DESIRED_MIN_TX_US":   "int",
        "REQUIRED_MIN_RX_US":  "int",
        "DETECT_MULT":         "int",
        "MAX_SESSIONS":        "int",
        "DEFAULT_AUTH_TYPE":   "str",
        "ECHO_ENABLED":        "bool",
        "LOG_LEVEL":           "str",
        "LOG_STATE_CHANGES":   "bool",
    }

    desc_map = {
        "DESIRED_MIN_TX_US":   "Desired minimum TX interval in microseconds",
        "REQUIRED_MIN_RX_US":  "Required minimum RX interval in microseconds",
        "DETECT_MULT":         "Detection time multiplier (1-255)",
        "MAX_SESSIONS":        "Maximum number of BFD sessions (restart required)",
        "DEFAULT_AUTH_TYPE":   "Default authentication type: none | md5 | sha1",
        "ECHO_ENABLED":        "Enable BFD echo function",
        "LOG_LEVEL":           "Log verbosity: DEBUG | INFO | WARNING | ERROR",
        "LOG_STATE_CHANGES":   "Log every session state change",
    }

    for key, default in DEFAULTS.items():
        schema["keys"][key] = {
            "default":          default,
            "type":             type_map.get(key, "str"),
            "description":      desc_map.get(key, ""),
            "restart_required": key in RESTART_REQUIRED_KEYS,
        }

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
        with open(path, "w") as f:
            json.dump(schema, f, indent=2)
        logger.debug("BFD schema exported to %s", path)
        return True
    except Exception as e:
        logger.warning("Could not export BFD schema: %s", e)
        return False


# ── Startup config loader ─────────────────────────────────────────────────────

def load_startup_config(config_manager, path: Optional[str] = None) -> int:
    """
    Apply a startup config JSON file to the config manager.
    Returns the number of keys successfully applied.
    """
    path = path or STARTUP_CONFIG_PATH
    if not os.path.exists(path):
        logger.debug("No BFD startup config found at %s", path)
        return 0

    try:
        with open(path) as f:
            cfg = json.load(f)
    except Exception as e:
        logger.error("Could not read BFD startup config %s: %s", path, e)
        return 0

    applied = 0
    for key, value in cfg.items():
        result = config_manager.set(key, value)
        if result["ok"]:
            logger.info("Startup config applied: %s = %s", key.upper(), value)
            applied += 1
        else:
            logger.warning("Startup config ignored: %s = %s (%s)", key, value, result.get("error"))

    logger.info("BFD startup config: %d/%d keys applied from %s", applied, len(cfg), path)
    return applied
