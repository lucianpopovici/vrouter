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

    key_meta = {
        "DESIRED_MIN_TX_US":  {
            "type": "int",  "description": "Desired minimum TX interval in microseconds",
            "min": 10000,   "max": 60000000, "mandatory": True,  "group": "Timers",
        },
        "REQUIRED_MIN_RX_US": {
            "type": "int",  "description": "Required minimum RX interval in microseconds",
            "min": 10000,   "max": 60000000, "mandatory": True,  "group": "Timers",
        },
        "DETECT_MULT":        {
            "type": "int",  "description": "Detection time multiplier (missed packets before session Down)",
            "min": 1,       "max": 255,      "mandatory": True,  "group": "Timers",
        },
        "MAX_SESSIONS":       {
            "type": "int",  "description": "Maximum number of concurrent BFD sessions (restart required)",
            "min": 1,       "max": 1024,     "mandatory": False, "group": "Session",
        },
        "DEFAULT_AUTH_TYPE":  {
            "type": "str",  "description": "Default authentication type: none | md5 | sha1",
            "mandatory": False, "group": "Session",
        },
        "ECHO_ENABLED":       {
            "type": "bool", "description": "Enable BFD echo function",
            "mandatory": False, "group": "Session",
        },
        "LOG_LEVEL":          {
            "type": "str",  "description": "Log verbosity: DEBUG | INFO | WARNING | ERROR",
            "mandatory": False, "group": "Logging",
        },
        "LOG_STATE_CHANGES":  {
            "type": "bool", "description": "Log every session state change",
            "mandatory": False, "group": "Logging",
        },
    }

    for key, default in DEFAULTS.items():
        meta = key_meta.get(key, {})
        entry = {
            "default":          default,
            "type":             meta.get("type", "str"),
            "description":      meta.get("description", ""),
            "mandatory":        meta.get("mandatory", False),
            "group":            meta.get("group", "Other"),
            "restart_required": key in RESTART_REQUIRED_KEYS,
        }
        if "min" in meta:
            entry["min"] = meta["min"]
        if "max" in meta:
            entry["max"] = meta["max"]
        schema["keys"][key] = entry

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
