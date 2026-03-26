"""
BFD session manager.
Thread-safe registry: add / remove / lookup sessions.
Persists session config to bfd_sessions.json for restart recovery.
"""

import json
import logging
import os
import threading
from typing import Callable, Dict, Optional

from .session import BFDSession, BFDState, BFDSessionInfo
from .config import BFDConfig

logger = logging.getLogger(__name__)

SESSIONS_FILE = os.environ.get("BFD_SESSIONS_FILE", "/tmp/bfd_sessions.json")


class BFDSessionManager:
    """Registry of all BFD sessions."""

    def __init__(
        self,
        cfg: BFDConfig,
        on_state_change: Optional[Callable[[BFDSession, BFDState, BFDState], None]] = None,
        sessions_file: str = SESSIONS_FILE,
    ):
        self._cfg             = cfg
        self._on_state_change = on_state_change
        self._sessions_file   = sessions_file
        self._lock            = threading.Lock()
        self._sessions: Dict[str, BFDSession] = {}

    # ── Session CRUD ──────────────────────────────────────────────────────────

    def add(
        self,
        peer_ip:            str,
        local_ip:           str  = "0.0.0.0",
        desired_min_tx_us:  Optional[int] = None,
        required_min_rx_us: Optional[int] = None,
        detect_mult:        Optional[int] = None,
    ) -> dict:
        """
        Add and start a BFD session.
        Returns {"ok": True, "peer_ip": ..., "local_disc": ...}
             or {"ok": False, "error": ...}
        """
        with self._lock:
            if peer_ip in self._sessions:
                return {"ok": False, "error": f"Session to {peer_ip} already exists"}
            if len(self._sessions) >= self._cfg.max_sessions:
                return {"ok": False, "error": f"Max sessions ({self._cfg.max_sessions}) reached"}

            sess = BFDSession(
                peer_ip            = peer_ip,
                local_ip           = local_ip,
                desired_min_tx_us  = desired_min_tx_us  or self._cfg.desired_min_tx_us,
                required_min_rx_us = required_min_rx_us or self._cfg.required_min_rx_us,
                detect_mult        = detect_mult        or self._cfg.detect_mult,
                on_state_change    = self._on_state_change,
            )
            sess.start()
            self._sessions[peer_ip] = sess
            self._persist()
            logger.info("Added BFD session to %s (local=%s)", peer_ip, local_ip)
            return {"ok": True, "peer_ip": peer_ip, "local_disc": sess.local_disc}

    def remove(self, peer_ip: str) -> dict:
        """
        Stop and remove a session.
        Returns {"ok": True} or {"ok": False, "error": ...}
        """
        with self._lock:
            sess = self._sessions.pop(peer_ip, None)
            if sess is None:
                return {"ok": False, "error": f"No session to {peer_ip}"}
            self._persist()
        sess.stop(admin_down=True)
        logger.info("Removed BFD session to %s", peer_ip)
        return {"ok": True, "peer_ip": peer_ip}

    def get(self, peer_ip: str) -> Optional[BFDSession]:
        with self._lock:
            return self._sessions.get(peer_ip)

    def all_info(self) -> list[BFDSessionInfo]:
        with self._lock:
            return [s.info() for s in self._sessions.values()]

    def info(self, peer_ip: str) -> Optional[BFDSessionInfo]:
        with self._lock:
            s = self._sessions.get(peer_ip)
            return s.info() if s else None

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist(self):
        """Save session configs (not state) for restart recovery."""
        data = {}
        for peer_ip, s in self._sessions.items():
            data[peer_ip] = {
                "local_ip":           s.local_ip,
                "desired_min_tx_us":  s.desired_min_tx_us,
                "required_min_rx_us": s.required_min_rx_us,
                "detect_mult":        s.detect_mult,
            }
        try:
            with open(self._sessions_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning("Could not persist sessions: %s", e)

    def restore(self):
        """Re-create sessions from persisted config on daemon restart."""
        if not os.path.exists(self._sessions_file):
            return
        try:
            with open(self._sessions_file) as f:
                data = json.load(f)
            for peer_ip, params in data.items():
                result = self.add(peer_ip, **params)
                if result["ok"]:
                    logger.info("Restored BFD session to %s", peer_ip)
                else:
                    logger.warning("Could not restore session to %s: %s", peer_ip, result.get("error"))
        except Exception as e:
            logger.warning("Could not restore sessions: %s", e)

    def stop_all(self):
        """Stop all sessions (called on daemon shutdown)."""
        with self._lock:
            peers = list(self._sessions.keys())
        for peer_ip in peers:
            self.remove(peer_ip)
