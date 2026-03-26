# lldp/reaper.py
# Neighbor TTL reaper — IEEE 802.1AB sect 10.5.
#
# Walks the neighbor table every REAPER_INTERVAL seconds.
# A neighbor is expired when:
#   now - last_seen > ttl_seconds  (parsed from the neighbor's TTL TLV)
#
# On expiry:
#   - removes the entry from the neighbors dict
#   - emits a "neighbor.expired" IPC event
#   - prints a log line

import time
import threading
from datetime import datetime

from . import config

# How often the reaper scans the table (seconds).
# Finer than the shortest possible TTL (1s min per spec).
REAPER_INTERVAL = 5


def _parse_ttl(info: dict) -> int:
    """
    Extract TTL in seconds from the neighbor info dict.
    The TTL field is stored as e.g. "120s" by parse_tlvs.
    Falls back to config.TTL if missing or unparseable.
    """
    raw = info.get("ttl", "")
    try:
        return int(str(raw).rstrip("s"))
    except (ValueError, AttributeError):
        return config.TTL


def _parse_last_seen(info: dict):
    """Return last_seen as a float (epoch seconds)."""
    raw = info.get("last_seen", "")
    try:
        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


def run(neighbors: dict, lock: threading.Lock):
    """
    Reaper loop. Runs as a daemon thread.
    Checks every REAPER_INTERVAL seconds and removes expired neighbors.
    """
    # Late import to avoid circular dependency at module load time
    from .ipc import broadcaster

    print(f"[REAPER] Started (scan every {REAPER_INTERVAL}s)")

    while True:
        time.sleep(REAPER_INTERVAL)
        now     = time.time()
        expired = []

        with lock:
            for msap, info in list(neighbors.items()):
                ttl_s     = _parse_ttl(info)
                last_seen = _parse_last_seen(info)
                if now - last_seen > ttl_s:
                    expired.append((msap, info.get("interface", "?"),
                                    info.get("system_name", "?")))
            for msap, *_ in expired:
                del neighbors[msap]

        for msap, iface, name in expired:
            print(f"[REAPER] [{iface}] Neighbor expired: {msap} ({name})")
            broadcaster.emit("neighbor.expired", {
                "msap":      msap,
                "interface": iface,
                "system_name": name,
            })
