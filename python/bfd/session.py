"""
BFD session state machine (RFC 5880 §6.8).
Single-hop (RFC 5881) over UDP port 3784.

States:  AdminDown → Down → Init → Up
"""

import logging
import os
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional

from .packet import BFDPacket, BFD_CONTROL_PORT, STATE, DIAG

logger = logging.getLogger(__name__)


class BFDState(IntEnum):
    ADMIN_DOWN = 0
    DOWN       = 1
    INIT       = 2
    UP         = 3


# ── Session dataclass (snapshot for display / IPC) ────────────────────────────

@dataclass
class BFDSessionInfo:
    peer_ip:            str
    local_ip:           str
    state:              str
    local_disc:         int
    remote_disc:        int
    desired_min_tx_us:  int
    required_min_rx_us: int
    detect_mult:        int
    remote_detect_mult: int
    negotiated_tx_us:   int
    detect_time_us:     int
    last_rx:            Optional[float]
    last_state_change:  float
    up_since:           Optional[float]
    diag:               int
    remote_diag:        int


# ── BFD Session ───────────────────────────────────────────────────────────────

class BFDSession:
    """
    A single BFD session toward one peer (RFC 5880/5881).
    Runs TX timer in a background thread; call rx_packet() on incoming packets.
    """

    def __init__(
        self,
        peer_ip:            str,
        local_ip:           str            = "0.0.0.0",
        desired_min_tx_us:  int            = 300_000,
        required_min_rx_us: int            = 300_000,
        detect_mult:        int            = 3,
        active_role:        bool           = True,
        on_state_change:    Optional[Callable[["BFDSession", BFDState, BFDState], None]] = None,
    ):
        self.peer_ip            = peer_ip
        self.local_ip           = local_ip
        self.desired_min_tx_us  = desired_min_tx_us
        self.required_min_rx_us = required_min_rx_us
        self.detect_mult        = detect_mult
        self.on_state_change    = on_state_change

        # RFC 5880 §6.8.1 – local discriminator is non-zero, locally unique
        self.local_disc:  int = random.randint(1, 0xFFFFFFFF)
        self.remote_disc: int = 0

        # State
        self._state      = BFDState.DOWN
        self._diag       = 0          # local diagnostic code
        self._remote_diag = 0

        # Negotiated values
        self.remote_desired_min_tx_us:  int = 1_000_000
        self.remote_required_min_rx_us: int = 1_000_000
        self.remote_detect_mult:        int = 3

        # Timestamps
        self._last_rx:          Optional[float] = None
        self._last_state_change: float          = time.monotonic()
        self._up_since:         Optional[float] = None

        # Poll sequence
        self._poll        = False
        self._final       = False
        self._poll_active = False                   # True while we're waiting for a Final

        # Active/Passive role (RFC 5880 §6.1)
        self._active_role = active_role

        # Locked TX interval during an active Poll Sequence (RFC 5880 §6.8.3)
        self._scheduled_tx_us: Optional[int] = None

        # RFC 5880 §6.6: suppress periodic TX when remote asserts Demand mode
        self._remote_demand: bool = False

        # RFC 5881 §5: TX source port, set after socket bind
        self._tx_src_port: Optional[int] = None

        # Threading
        self._lock      = threading.Lock()
        self._stop_evt  = threading.Event()
        self._tx_thread: Optional[threading.Thread] = None
        self._rx_thread: Optional[threading.Thread] = None
        self._sock:      Optional[socket.socket]    = None

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def state(self) -> BFDState:
        return self._state

    @property
    def negotiated_tx_us(self) -> int:
        """Actual TX interval: max(desired_min_tx, remote_required_min_rx)."""
        return max(self.desired_min_tx_us, self.remote_required_min_rx_us)

    @property
    def detect_time_us(self) -> int:
        """
        Local detection time (RFC 5880 §6.8.4):
          remote_detect_mult × max(remote_desired_min_tx_us, required_min_rx_us)

        This is the rate the remote will actually TX at (both sides agree),
        multiplied by how many missed packets trigger a failure.
        """
        remote_tx_us = max(self.remote_desired_min_tx_us, self.required_min_rx_us)
        return self.remote_detect_mult * remote_tx_us

    # ── State machine ─────────────────────────────────────────────────────────

    def _transition(self, new_state: BFDState, diag: int = 0):
        old_state = self._state
        if old_state == new_state:
            return
        self._state             = new_state
        self._diag              = diag
        self._last_state_change = time.monotonic()
        if new_state == BFDState.UP:
            self._up_since = time.monotonic()
        elif old_state == BFDState.UP:
            self._up_since        = None
            # Any in-progress Poll Sequence is abandoned when leaving Up
            self._poll            = False
            self._poll_active     = False
            self._scheduled_tx_us = None
        logger.info(
            "[BFD %s] %s → %s (diag: %s)",
            self.peer_ip, STATE[old_state], STATE[new_state], DIAG.get(diag, diag)
        )
        if self.on_state_change:
            try:
                self.on_state_change(self, old_state, new_state)
            except Exception:
                logger.exception("on_state_change callback raised")

    def rx_packet(self, pkt: BFDPacket):
        """Process an incoming BFD control packet (RFC 5880 §6.8.6)."""
        with self._lock:
            # ── Mandatory discard rules (RFC 5880 §6.8.6) ────────────────────

            # Rule 4: auth bit must match local auth state; we support no auth
            if pkt.auth_present:
                logger.debug("[BFD %s] drop: auth_present but auth not configured", self.peer_ip)
                return

            # Rule 6: multipoint bit must be zero
            if pkt.multipoint:
                logger.debug("[BFD %s] drop: multipoint bit set", self.peer_ip)
                return

            # Rule 7: My Discriminator must be nonzero
            if pkt.my_discriminator == 0:
                logger.debug("[BFD %s] drop: my_discriminator is zero", self.peer_ip)
                return

            # RFC 5880 §6.5: Poll and Final must not both be set
            if pkt.poll and pkt.final:
                logger.debug("[BFD %s] drop: both Poll and Final bits set", self.peer_ip)
                return

            # Rule 8: session selection by Your Discriminator
            if pkt.your_discriminator != 0 and pkt.your_discriminator != self.local_disc:
                return  # addressed to a different session

            # Rule 8 (continued): Your Discriminator of zero is only valid when
            # the remote is in Down or AdminDown state
            remote_state = BFDState(pkt.state)
            if pkt.your_discriminator == 0 and remote_state not in (
                BFDState.ADMIN_DOWN, BFDState.DOWN
            ):
                logger.debug(
                    "[BFD %s] drop: your_discriminator=0 with remote state=%s",
                    self.peer_ip, remote_state.name,
                )
                return

            # ── Update remote tracking state ──────────────────────────────────
            self._last_rx                  = time.monotonic()
            self.remote_disc               = pkt.my_discriminator
            self._remote_diag              = pkt.diag
            self.remote_desired_min_tx_us  = pkt.desired_min_tx_us
            self.remote_required_min_rx_us = pkt.required_min_rx_us
            self.remote_detect_mult        = pkt.detect_mult
            self._remote_demand            = pkt.demand  # RFC 5880 §6.6

            # ── Final flag: completes our own Poll Sequence (RFC 5880 §6.5) ───
            if pkt.final and self._poll_active:
                self._poll            = False
                self._poll_active     = False
                self._scheduled_tx_us = None
                logger.debug("[BFD %s] Poll Sequence completed (Final received)", self.peer_ip)

            # ── RFC 5880 §6.8.6 state machine ─────────────────────────────────
            if self._state == BFDState.ADMIN_DOWN:
                return

            if remote_state == BFDState.ADMIN_DOWN:
                if self._state != BFDState.DOWN:
                    self._transition(BFDState.DOWN, diag=3)  # Neighbor Signaled Session Down
                return

            if self._state == BFDState.DOWN:
                if remote_state == BFDState.DOWN:
                    self._transition(BFDState.INIT)
                elif remote_state == BFDState.INIT:
                    self._transition(BFDState.UP)

            elif self._state == BFDState.INIT:
                if remote_state in (BFDState.INIT, BFDState.UP):
                    self._transition(BFDState.UP)

            elif self._state == BFDState.UP:
                if remote_state == BFDState.DOWN:
                    self._transition(BFDState.DOWN, diag=3)

            # ── Poll flag: queue a Final in the next outgoing packet ───────────
            if pkt.poll:
                self._final = True

    # ── Timer update / Poll Sequence ──────────────────────────────────────────

    def update_timers(
        self,
        desired_min_tx_us:  Optional[int] = None,
        required_min_rx_us: Optional[int] = None,
    ) -> None:
        """
        Update session timer parameters (RFC 5880 §6.8.3).

        When the session is Up, a Poll Sequence is initiated so the remote can
        adjust before we change our actual TX rate.  When not Up the new values
        take effect immediately (no poll needed).
        """
        with self._lock:
            changed    = False
            needs_poll = self._state == BFDState.UP and not self._poll_active

            if desired_min_tx_us is not None and desired_min_tx_us != self.desired_min_tx_us:
                if needs_poll:
                    # Capture current effective interval before changing desired value
                    self._scheduled_tx_us = self.negotiated_tx_us
                self.desired_min_tx_us = desired_min_tx_us
                changed = True

            if required_min_rx_us is not None and required_min_rx_us != self.required_min_rx_us:
                self.required_min_rx_us = required_min_rx_us
                changed = True

            if changed and needs_poll:
                self._poll        = True
                self._poll_active = True
                logger.debug("[BFD %s] Poll Sequence initiated for timer update", self.peer_ip)

    # ── Socket factories (override in tests) ──────────────────────────────────

    def _make_tx_socket(self) -> socket.socket:
        """Create and configure the TX socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # RFC 5881 §5: TTL must be 255
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
        # RFC 5881 §5: source port must be in 49152–65535
        bind_ip   = self.local_ip if self.local_ip != "0.0.0.0" else ""
        src_port  = random.randint(49152, 65535)
        try:
            sock.bind((bind_ip, src_port))
            self._tx_src_port = src_port
        except OSError as e:
            logger.warning("[BFD %s] TX bind (port %d) failed: %s", self.peer_ip, src_port, e)
        return sock

    def _make_rx_socket(self) -> socket.socket:
        """Create and configure the RX socket. Raises OSError on bind failure."""
        rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # RFC 5881 §4: enable receiving TTL so we can validate it is 255
        try:
            rx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTTL, 1)
        except OSError:
            pass  # not available on all platforms
        rx_sock.settimeout(1.0)
        bind_ip = self.local_ip if self.local_ip != "0.0.0.0" else ""
        rx_sock.bind((bind_ip, BFD_CONTROL_PORT))
        return rx_sock

    # ── TX thread ─────────────────────────────────────────────────────────────

    def _tx_loop(self):
        """Send BFD control packets at the negotiated interval."""
        sock = self._make_tx_socket()
        self._sock = sock

        while not self._stop_evt.is_set():
            pkt_to_send = None

            with self._lock:
                # RFC 5880 §6.8.7: passive role must not TX until first packet received
                # RFC 5880 §6.8.7: must not TX if remote requires no packets (min-rx = 0)
                # RFC 5880 §6.6: suppress periodic TX when remote is in Demand mode,
                #   unless we have an active Poll Sequence (poll=True)
                should_tx = (
                    (self._active_role or self._last_rx is not None)
                    and self.remote_required_min_rx_us != 0
                    and (not self._remote_demand or self._poll)
                )

                if should_tx:
                    pkt_to_send = BFDPacket(
                        state              = int(self._state),
                        diag               = self._diag,
                        poll               = self._poll,
                        final              = self._final,
                        detect_mult        = self.detect_mult,
                        my_discriminator   = self.local_disc,
                        your_discriminator = self.remote_disc,
                        desired_min_tx_us  = self.desired_min_tx_us,
                        required_min_rx_us = self.required_min_rx_us,
                        required_min_echo  = 0,
                    )
                    self._final = False

                # RFC 5880 §6.8.3: use locked interval during an active Poll Sequence
                base_us = (
                    self._scheduled_tx_us
                    if self._scheduled_tx_us is not None
                    else self.negotiated_tx_us
                )

                # RFC 5880 §6.8.3: floor of 1 s when not Up
                if self._state != BFDState.UP:
                    base_us = max(base_us, 1_000_000)

                # RFC 5880 §6.8.7: jitter — reduce by 0–25%; max 10% when detect_mult==1
                hi = 0.90 if self.detect_mult == 1 else 1.00
                tx_interval_s = (base_us / 1_000_000) * random.uniform(0.75, hi)

                # Detect timeout in Up and Init states (3.1, 3.2)
                if (
                    self._state in (BFDState.UP, BFDState.INIT)
                    and self._last_rx is not None
                    and (time.monotonic() - self._last_rx) > (self.detect_time_us / 1_000_000)
                ):
                    self._transition(BFDState.DOWN, diag=1)  # Control Detection Time Expired

            if pkt_to_send is not None:
                had_final = pkt_to_send.final
                try:
                    sock.sendto(pkt_to_send.encode(), (self.peer_ip, BFD_CONTROL_PORT))
                except OSError as e:
                    logger.debug("[BFD %s] TX error: %s", self.peer_ip, e)
                    # 7.2: Final flag was already cleared under the lock; restore it so
                    # the next TX attempt will still deliver the Final to the remote.
                    if had_final:
                        with self._lock:
                            self._final = True

            self._stop_evt.wait(timeout=tx_interval_s)

        sock.close()

    # ── RX thread ─────────────────────────────────────────────────────────────

    def _rx_loop(self):
        """Listen for BFD control packets from peer."""
        try:
            rx_sock = self._make_rx_socket()
        except OSError as e:
            logger.error("[BFD %s] Cannot bind RX socket: %s", self.peer_ip, e)
            return

        # CMSG buffer large enough for an int (TTL)
        cmsg_buf = socket.CMSG_SPACE(struct.calcsize("i"))

        while not self._stop_evt.is_set():
            try:
                data, ancdata, _flags, addr = rx_sock.recvmsg(1024, cmsg_buf)
                if addr[0] != self.peer_ip:
                    continue

                # RFC 5881 §4: discard packets whose TTL is not 255
                ttl = None
                for cmsg_level, cmsg_type, cmsg_data in ancdata:
                    if cmsg_level == socket.IPPROTO_IP and cmsg_type == socket.IP_TTL:
                        ttl = struct.unpack("i", cmsg_data[:4])[0]
                        break
                if ttl is not None and ttl != 255:
                    logger.debug(
                        "[BFD %s] drop: TTL=%d (expected 255)", self.peer_ip, ttl
                    )
                    continue

                pkt = BFDPacket.decode(data)
                if pkt:
                    self.rx_packet(pkt)
            except socket.timeout:
                continue
            except OSError:
                break

        rx_sock.close()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, rx: bool = True):
        """Start TX thread and optionally the per-session RX thread.

        Pass rx=False when a shared RX socket (e.g. in BFDSessionManager) will
        dispatch received packets via rx_packet() instead.
        """
        self._stop_evt.clear()
        self._tx_thread = threading.Thread(
            target=self._tx_loop, name=f"bfd-tx-{self.peer_ip}", daemon=True
        )
        self._tx_thread.start()
        if rx:
            self._rx_thread = threading.Thread(
                target=self._rx_loop, name=f"bfd-rx-{self.peer_ip}", daemon=True
            )
            self._rx_thread.start()
        logger.info("[BFD %s] Session started (disc=%#010x)", self.peer_ip, self.local_disc)

    def resume(self) -> bool:
        """Re-enable a session that was administratively shut down (RFC 5880 §6.2).

        Transitions from ADMIN_DOWN back to DOWN and restarts the threads.
        Returns True if the session was resumed, False if not in ADMIN_DOWN.
        """
        with self._lock:
            if self._state != BFDState.ADMIN_DOWN:
                return False
            self._state             = BFDState.DOWN
            self._diag              = 0
            self._last_state_change = time.monotonic()
        self._stop_evt.clear()
        self._tx_thread = threading.Thread(
            target=self._tx_loop, name=f"bfd-tx-{self.peer_ip}", daemon=True
        )
        self._rx_thread = threading.Thread(
            target=self._rx_loop, name=f"bfd-rx-{self.peer_ip}", daemon=True
        )
        self._tx_thread.start()
        self._rx_thread.start()
        logger.info("[BFD %s] Session resumed", self.peer_ip)
        return True

    def stop(self, admin_down: bool = True):
        """Stop the session gracefully."""
        with self._lock:
            if admin_down:
                self._transition(BFDState.ADMIN_DOWN, diag=7)  # Administratively Down
        self._stop_evt.set()
        if self._tx_thread:
            self._tx_thread.join(timeout=2)
        if self._rx_thread:
            self._rx_thread.join(timeout=2)
        logger.info("[BFD %s] Session stopped", self.peer_ip)

    # ── Snapshot ──────────────────────────────────────────────────────────────

    def info(self) -> BFDSessionInfo:
        with self._lock:
            return BFDSessionInfo(
                peer_ip            = self.peer_ip,
                local_ip           = self.local_ip,
                state              = STATE[int(self._state)],
                local_disc         = self.local_disc,
                remote_disc        = self.remote_disc,
                desired_min_tx_us  = self.desired_min_tx_us,
                required_min_rx_us = self.required_min_rx_us,
                detect_mult        = self.detect_mult,
                remote_detect_mult = self.remote_detect_mult,
                negotiated_tx_us   = self.negotiated_tx_us,
                detect_time_us     = self.detect_time_us,
                last_rx            = self._last_rx,
                last_state_change  = self._last_state_change,
                up_since           = self._up_since,
                diag               = self._diag,
                remote_diag        = self._remote_diag,
            )
