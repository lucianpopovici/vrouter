"""
BFD control packet encoding / decoding.
RFC 5880 (base), RFC 5881 (IP/UDP single-hop).

Control packet wire format (24 bytes mandatory header):

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                       My Discriminator                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      Your Discriminator                       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Desired Min TX Interval                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                   Required Min RX Interval                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                 Required Min Echo RX Interval                 |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

import struct
from dataclasses import dataclass
from typing import Optional

# UDP ports (RFC 5881)
BFD_CONTROL_PORT = 3784
BFD_ECHO_PORT    = 3785

# BFD version
BFD_VERSION = 1

# Mandatory header size (bytes)
BFD_HDR_LEN = 24

# Diagnostic codes (RFC 5880 §4.1)
DIAG = {
    0: "No Diagnostic",
    1: "Control Detection Time Expired",
    2: "Echo Function Failed",
    3: "Neighbor Signaled Session Down",
    4: "Forwarding Plane Reset",
    5: "Path Down",
    6: "Concatenated Path Down",
    7: "Administratively Down",
    8: "Reverse Concatenated Path Down",
}

# State codes
STATE = {
    0: "AdminDown",
    1: "Down",
    2: "Init",
    3: "Up",
}
STATE_BY_NAME = {v: k for k, v in STATE.items()}


@dataclass
class BFDPacket:
    version:            int   = BFD_VERSION
    diag:               int   = 0
    state:              int   = 1          # Down
    poll:               bool  = False
    final:              bool  = False
    ctrl_plane_indep:   bool  = False
    auth_present:       bool  = False
    demand:             bool  = False
    multipoint:         bool  = False
    detect_mult:        int   = 3
    my_discriminator:   int   = 0
    your_discriminator: int   = 0
    desired_min_tx_us:  int   = 300000
    required_min_rx_us: int   = 300000
    required_min_echo:  int   = 0

    # ── Encode ────────────────────────────────────────────────────────────────

    def encode(self) -> bytes:
        byte0 = ((self.version & 0x07) << 5) | (self.diag & 0x1F)

        flags = (self.state & 0x03) << 6
        if self.poll:           flags |= 0x20
        if self.final:          flags |= 0x10
        if self.ctrl_plane_indep: flags |= 0x08
        if self.auth_present:   flags |= 0x04
        if self.demand:         flags |= 0x02
        if self.multipoint:     flags |= 0x01

        return struct.pack(
            "!BBBBIIIII",
            byte0,
            flags,
            self.detect_mult,
            BFD_HDR_LEN,
            self.my_discriminator,
            self.your_discriminator,
            self.desired_min_tx_us,
            self.required_min_rx_us,
            self.required_min_echo,
        )

    # ── Decode ────────────────────────────────────────────────────────────────

    @classmethod
    def decode(cls, data: bytes) -> Optional["BFDPacket"]:
        if len(data) < BFD_HDR_LEN:
            return None
        try:
            (byte0, flags, detect_mult, length,
             my_disc, your_disc,
             desired_tx, required_rx, required_echo) = struct.unpack_from("!BBBBIIIII", data)
        except struct.error:
            return None

        version = (byte0 >> 5) & 0x07
        if version != BFD_VERSION:
            return None

        # RFC 5880 §6.8.6 rule 2-3: length field must be ≥ 24 and ≤ buffer size
        if length < BFD_HDR_LEN or length > len(data):
            return None

        # RFC 5880 §6.8.6 rule 5: Detect Mult must be nonzero
        if detect_mult == 0:
            return None

        pkt = cls(
            version            = version,
            diag               = byte0 & 0x1F,
            state              = (flags >> 6) & 0x03,
            poll               = bool(flags & 0x20),
            final              = bool(flags & 0x10),
            ctrl_plane_indep   = bool(flags & 0x08),
            auth_present       = bool(flags & 0x04),
            demand             = bool(flags & 0x02),
            multipoint         = bool(flags & 0x01),
            detect_mult        = detect_mult,
            my_discriminator   = my_disc,
            your_discriminator = your_disc,
            desired_min_tx_us  = desired_tx,
            required_min_rx_us = required_rx,
            required_min_echo  = required_echo,
        )
        return pkt

    # ── Repr ──────────────────────────────────────────────────────────────────

    def __str__(self) -> str:
        state_name = STATE.get(self.state, "?")
        diag_name  = DIAG.get(self.diag, "?")
        return (
            f"BFDPacket(state={state_name}, diag={diag_name}, "
            f"myDisc={self.my_discriminator:#010x}, "
            f"yourDisc={self.your_discriminator:#010x}, "
            f"tx={self.desired_min_tx_us}µs, rx={self.required_min_rx_us}µs, "
            f"mult={self.detect_mult})"
        )
