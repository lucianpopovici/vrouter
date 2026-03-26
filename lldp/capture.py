# lldp/capture.py
# Captures and parses incoming LLDP frames.
#
# Security hardening applied:
#   #1 Per-interface neighbor limit (config.MAX_NEIGHBORS_PER_INTERFACE)
#   #2 Per-source rate limiting     (security.RateLimiter)
#   #4 TTL=0 immediate removal      (IEEE 802.1AB sect 10.5.3.3)

import socket
import struct
import threading
import time
from datetime import datetime

from .helpers import (
    LLDP_MULTICAST_MAC, LLDP_ETHERTYPE, ETH_P_ALL,
    mac_to_str, parse_tlvs,
)
from .display import print_neighbor
from .security import RateLimiter
from . import config

# One rate-limiter shared across all capture threads.
# Default: burst=10, sustained=1 frame/sec per source MAC.
# Spec says one frame per tx-interval (30s) — this is already generous.
_rate_limiter = RateLimiter(rate=1.0, burst=10)
_rl_lock      = threading.Lock()
_rl_last_evict = 0.0
_RL_EVICT_INTERVAL = 300  # evict stale buckets every 5 min


def run(interface: str, neighbors: dict, lock):
    """Capture LLDP frames on *interface* and populate *neighbors*."""
    from .ipc import broadcaster

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    sock.bind((interface, 0))

    print(f"[CAPTURE] [{interface}] Listening for LLDP frames "
          f"(max {config.MAX_NEIGHBORS_PER_INTERFACE} neighbors/iface)")

    global _rl_last_evict

    while True:
        frame, _ = sock.recvfrom(65535)

        if len(frame) < 14:
            continue

        dst_mac   = frame[0:6]
        src_mac   = frame[6:12]
        ethertype = struct.unpack("!H", frame[12:14])[0]

        if ethertype != LLDP_ETHERTYPE or dst_mac != LLDP_MULTICAST_MAC:
            continue

        src_str = mac_to_str(src_mac)

        # ── #2  Rate limit per source MAC ─────────────────────
        if not _rate_limiter.allow(src_str):
            print(f"[CAPTURE] [{interface}] Rate limit exceeded "
                  f"for {src_str} — frame dropped")
            continue

        # Periodic bucket eviction
        now = time.monotonic()
        if now - _rl_last_evict > _RL_EVICT_INTERVAL:
            evicted = _rate_limiter.evict_stale()
            _rl_last_evict = now
            if evicted:
                print(f"[CAPTURE] Rate limiter: evicted {evicted} stale bucket(s)")

        # ── Parse frame ───────────────────────────────────────
        info    = parse_tlvs(frame[14:])
        info["interface"] = interface
        info["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── #4  TTL=0 means immediate removal ─────────────────
        raw_ttl = info.get("ttl", "")
        try:
            ttl_val = int(str(raw_ttl).rstrip("s"))
        except (ValueError, AttributeError):
            ttl_val = config.TTL

        if ttl_val == 0:
            with lock:
                if src_str in neighbors:
                    del neighbors[src_str]
                    print(f"[CAPTURE] [{interface}] TTL=0 received — "
                          f"removed neighbor {src_str}")
                    broadcaster.emit("neighbor.expired", {
                        "mac":       src_str,
                        "interface": interface,
                        "system_name": info.get("system_name", "?"),
                        "reason":    "ttl_zero",
                    })
            continue

        # ── #1  Per-interface neighbor limit ──────────────────
        with lock:
            is_new = msap_key not in neighbors

            if is_new:
                # Count how many neighbors we already have on this iface
                iface_count = sum(
                    1 for nb in neighbors.values()
                    if nb.get("interface") == interface
                )
                limit = config.MAX_NEIGHBORS_PER_INTERFACE
                if iface_count >= limit:
                    print(f"[CAPTURE] [{interface}] Neighbor limit "
                          f"({limit}) reached — {src_str} dropped")
                    continue

            neighbors[msap_key] = info

        event_type = "neighbor.discovered" if is_new else "neighbor.updated"
        broadcaster.emit(event_type, {"mac": src_str, "msap": msap_key, "info": info})

        print(f"\n[RECV] [{interface}] {info['last_seen']} "
              f"— {'New' if is_new else 'Updated'} neighbor: {msap_key} (via {src_str})")
        print_neighbor(msap_key, info)
