# lldp/watcher.py
# Watches interfaces.txt for changes and starts/stops
# sender + capture threads dynamically.
# Also restarts sender threads when TTL or SEND_INTERVAL changes,
# since those values are now read live by sender.run() — no restart needed
# for those. Watcher only needs to manage interface add/remove.
# Creates interfaces.txt with a default comment if it doesn't exist.

import os
import threading
import time
import logging

from . import config
from .sender  import run as send_run
from .capture import run as capture_run


# ── File helpers ──────────────────────────────
log = logging.getLogger("lldp.watcher")

def read_interfaces(path: str) -> list:
    """Parse an interface list file, ignoring blank lines and comments."""
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def _ensure_file(path: str):
    """Create interfaces.txt with a header comment if it doesn't exist."""
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(
                "# interfaces.txt\n"
                "# One interface per line. Lines starting with # are ignored.\n"
                "# Edit this file at any time — changes are picked up automatically.\n"
                "# Example:\n"
                "# eth0\n"
                "# eth1\n"
            )
        print(f"[WATCH] Created '{path}' — add interface names to start LLDP")


# ── Thread management ─────────────────────────

def _start_interface(iface: str, active: dict,
                     neighbors: dict, lock):
    """
    Spawn send + capture threads for *iface*.
    """
    stop_event = threading.Event()
    t_send = threading.Thread(
        target=send_run,
        args=(iface, stop_event),
        daemon=True,
        name=f"send-{iface}",
    )
    t_capture = threading.Thread(
        target=capture_run,
        args=(iface, neighbors, lock),
        daemon=True,
        name=f"capture-{iface}",
    )
    t_send.start()
    t_capture.start()
    active[iface] = (t_send, t_capture, stop_event)
    print(f"[WATCH] Started LLDP on '{iface}'")


def _stop_interface(iface: str, active: dict,
                    neighbors: dict, lock):
    """
    Retire threads for *iface* and purge its neighbors.
    """
    data = active.pop(iface, None)
    if data:
        t_send, t_capture, stop_event = data
        stop_event.set() # Trigger shutdown LLDPDU
        log.info("[WATCH] Stopping LLDP on %s", iface)

    with lock:
        removed = [mac for mac, info in neighbors.items()
                   if info.get("interface") == iface]
        for mac in removed:
            del neighbors[mac]
    print(f"[WATCH] Stopped LLDP on '{iface}' "
          f"({len(removed)} neighbor(s) removed)")


# ── Main watcher loop ─────────────────────────

def run(neighbors: dict, lock):
    """
    Poll interfaces.txt every WATCH_INTERVAL seconds.
    - Creates the file if missing.
    - Starts threads for newly added interfaces.
    - Stops threads for removed interfaces.
    TTL / SEND_INTERVAL changes are handled automatically by sender threads
    (they read config live), so no thread restart is needed for those.
    """
    _ensure_file(config.INTERFACES_FILE)

    active: dict = {}
    last_mtime   = None

    print(f"[WATCH] Monitoring '{config.INTERFACES_FILE}' "
          f"every {config.WATCH_INTERVAL}s")

    while True:
        try:
            mtime = os.path.getmtime(config.INTERFACES_FILE)
        except FileNotFoundError:
            # File was deleted — stop all interfaces
            mtime = None

        if mtime != last_mtime:
            last_mtime = mtime
            wanted  = set(read_interfaces(config.INTERFACES_FILE)
                          if mtime else [])
            current = set(active.keys())

            for iface in current - wanted:
                _stop_interface(iface, active, neighbors, lock)

            for iface in wanted - current:
                # IEEE 802.1AB 10.5.3: reinitDelay
                reinit_delay = getattr(config, "REINIT_DELAY", 2)
                if current: # only delay if we were already running
                    time.sleep(reinit_delay)
                _start_interface(iface, active, neighbors, lock)

            if (wanted - current) or (current - wanted):
                active_list = ", ".join(sorted(active)) or "none"
                print(f"[WATCH] Active interfaces: {active_list}")

        time.sleep(config.WATCH_INTERVAL)
