"""
BFD runtime config manager.
Handles get / set / reset with persistence to bfd_runtime_config.json.
Mirrors lldp/config_manager.py patterns.
"""

import json
import logging
import os
import threading
from typing import Any, Optional

from .config import DEFAULTS, BFDConfig, validate, coerce
from ._config_groups import RESTART_REQUIRED_KEYS

logger = logging.getLogger(__name__)

RUNTIME_CONFIG_PATH = os.environ.get("BFD_RUNTIME_CONFIG", "/tmp/bfd_runtime_config.json")


class BFDConfigManager:
    """Thread-safe runtime config manager for BFD."""

    def __init__(self, path: str = RUNTIME_CONFIG_PATH):
        self._path = path
        self._lock = threading.RLock()
        self._cfg: dict[str, Any] = dict(DEFAULTS)
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self):
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path) as f:
                saved = json.load(f)
            for k, v in saved.items():
                k_up = k.upper()
                if k_up in DEFAULTS:
                    ok, _ = validate(k_up, v)
                    if ok:
                        self._cfg[k_up] = coerce(k_up, v)
            logger.debug("Loaded BFD runtime config from %s", self._path)
        except Exception as e:
            logger.warning("Could not load BFD runtime config: %s", e)

    def _save(self):
        try:
            with open(self._path, "w") as f:
                json.dump(self._cfg, f, indent=2)
        except Exception as e:
            logger.warning("Could not save BFD runtime config: %s", e)

    # ── Public API ────────────────────────────────────────────────────────────

    def get(self, key: Optional[str] = None) -> dict | Any:
        """Get one key or all config."""
        with self._lock:
            if key is None:
                return dict(self._cfg)
            k = key.upper()
            if k not in self._cfg:
                raise KeyError(f"Unknown config key: {k}")
            return self._cfg[k]

    def set(self, key: str, value: Any) -> dict:
        """
        Set a config key.
        Returns {"ok": True, "key": k, "value": v, "restart_required": bool}
        or      {"ok": False, "error": str}
        """
        k = key.upper()
        ok, err = validate(k, value)
        if not ok:
            return {"ok": False, "error": err}
        with self._lock:
            self._cfg[k] = coerce(k, value)
            self._save()
        restart = k in RESTART_REQUIRED_KEYS
        logger.info("Config set: %s = %s (restart_required=%s)", k, self._cfg[k], restart)
        return {"ok": True, "key": k, "value": self._cfg[k], "restart_required": restart}

    def reset(self, key: Optional[str] = None) -> dict:
        """
        Reset one key or all keys to defaults.
        Returns {"ok": True, "reset": [list of keys]}
        """
        with self._lock:
            if key is None:
                self._cfg = dict(DEFAULTS)
                self._save()
                return {"ok": True, "reset": list(DEFAULTS.keys())}
            k = key.upper()
            if k not in DEFAULTS:
                return {"ok": False, "error": f"Unknown config key: {k}"}
            self._cfg[k] = DEFAULTS[k]
            self._save()
            return {"ok": True, "reset": [k]}

    def as_bfd_config(self) -> BFDConfig:
        with self._lock:
            return BFDConfig.from_dict(self._cfg)
