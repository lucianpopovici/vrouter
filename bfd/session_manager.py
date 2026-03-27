"""
BFD session manager.
Thread-safe registry: add / remove / lookup sessions.
Persists session config to bfd_sessions.json for restart recovery.

Shared RX socket (RFC 5880 §6.3 / RFC 5881 §4):
  A single UDP socket bound to port 3784 receives all BFD packets.
  Packets are dispatched to sessions by Your Discriminator (if non-zero)
  or by source IP (for the initial Down exchange).
  TTL of incoming packets is validated to be 255 (RFC 5881 §4).
"""

import json
import logging
import os
import random
import socket
import struct
import threading
from typing import Callable, Dict, Optional

from .packet import BFDPacket, BFD_CONTROL_PORT
from .session import BFDSession, BFDState, BFDSessionInfo
from .config import BFDConfig

logger = logging.getLogger(__name__)

SESSIONS_FILE = os.environ.get("BFD_SESSIONS_FILE", "/tmp/bfd_sessions.json")


class BFDSessionManager:
    """Registry of all BFD sessions with a shared RX socket."""

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

        # Discriminator → session index for fast demultiplexing (RFC 5880 §6.3)
        self._by_disc: Dict[int, BFDSession] = {}

        # Shared RX socket
        self._rx_sock:   Optional[socket.socket]  = None
        self._rx_thread: Optional[threading.Thread] = None
        self._rx_stop    = threading.Event()

    # ── Shared RX socket ──────────────────────────────────────────────────────

    def start_rx(self, bind_ip: str = "") -> None:
        """
        Bind the shared RX socket to UDP port 3784 and start the dispatch thread.
        Call this once before adding sessions (or after restore()).
        """
        if self._rx_thread is not None and self._rx_thread.is_alive():
            return  # already running

        self._rx_stop.clear()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # RFC 5881 §4: enable receiving TTL so we can validate it equals 255
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTTL, 1)
            except OSError:
                pass
            sock.settimeout(1.0)
            sock.bind((bind_ip, BFD_CONTROL_PORT))
            self._rx_sock = sock
        except OSError as e:
            logger.error("BFDSessionManager: cannot bind shared RX socket: %s", e)
            return

        self._rx_thread = threading.Thread(
            target=self._rx_loop, name="bfd-rx-shared", daemon=True
        )
        self._rx_thread.start()
        logger.info("BFDSessionManager: shared RX socket started on port %d", BFD_CONTROL_PORT)

    def stop_rx(self) -> None:
        """Stop the shared RX thread."""
        self._rx_stop.set()
        if self._rx_sock:
            try:
                self._rx_sock.close()
            except OSError:
                pass
            self._rx_sock = None
        if self._rx_thread:
            self._rx_thread.join(timeout=2)
            self._rx_thread = None

    def _rx_loop(self) -> None:
        """Receive BFD packets and dispatch to the correct session."""
        sock = self._rx_sock
        cmsg_buf = socket.CMSG_SPACE(struct.calcsize("i"))

        while not self._rx_stop.is_set():
            try:
                data, ancdata, _flags, addr = sock.recvmsg(1024, cmsg_buf)

                # RFC 5881 §4: discard packets with TTL != 255
                ttl = None
                for cmsg_level, cmsg_type, cmsg_data in ancdata:
                    if cmsg_level == socket.IPPROTO_IP and cmsg_type == socket.IP_TTL:
                        ttl = struct.unpack("i", cmsg_data[:4])[0]
                        break
                if ttl is not None and ttl != 255:
                    logger.debug("BFD RX: drop from %s: TTL=%d (expected 255)", addr[0], ttl)
                    continue

                pkt = BFDPacket.decode(data)
                if pkt is None:
                    continue

                # RFC 5880 §6.3: demultiplex by Your Discriminator first, then source IP
                sess = None
                with self._lock:
                    if pkt.your_discriminator != 0:
                        sess = self._by_disc.get(pkt.your_discriminator)
                    else:
                        sess = self._sessions.get(addr[0])

                if sess is not None:
                    sess.rx_packet(pkt)
                else:
                    logger.debug(
                        "BFD RX: no session for src=%s your_disc=%#x",
                        addr[0], pkt.your_discriminator,
                    )

            except socket.timeout:
                continue
            except OSError:
                break

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

            # RFC 5880 §6.8.1: discriminator must be locally unique (10.2)
            while sess.local_disc in self._by_disc:
                logger.debug(
                    "BFD: discriminator collision %#010x for %s, regenerating",
                    sess.local_disc, peer_ip,
                )
                sess.local_disc = random.randint(1, 0xFFFFFFFF)

            # Start TX only — shared RX socket (if running) handles reception
            rx = self._rx_thread is None or not self._rx_thread.is_alive()
            sess.start(rx=rx)

            self._sessions[peer_ip]        = sess
            self._by_disc[sess.local_disc] = sess
            self._persist()
            logger.info("Added BFD session to %s (local=%s, disc=%#010x)", peer_ip, local_ip, sess.local_disc)
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
            self._by_disc.pop(sess.local_disc, None)
            self._persist()
        sess.stop(admin_down=True)
        logger.info("Removed BFD session to %s", peer_ip)
        return {"ok": True, "peer_ip": peer_ip}

    def get(self, peer_ip: str) -> Optional[BFDSession]:
        with self._lock:
            return self._sessions.get(peer_ip)

    def get_by_disc(self, local_disc: int) -> Optional[BFDSession]:
        """Look up a session by its local discriminator."""
        with self._lock:
            return self._by_disc.get(local_disc)

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
        """Stop all sessions and the shared RX socket (called on daemon shutdown)."""
        self.stop_rx()
        with self._lock:
            peers = list(self._sessions.keys())
        for peer_ip in peers:
            self.remove(peer_ip)
