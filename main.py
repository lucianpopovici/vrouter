#!/usr/bin/env python3
"""
project-cli daemon entry point.
Starts LLDP and BFD subsystems.
"""

import argparse
import logging
import os
import signal
import sys
import time

# ── Logging setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt = "%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("main")


def parse_args():
    p = argparse.ArgumentParser(description="project-cli daemon (LLDP + BFD)")
    p.add_argument("--no-lldp",     action="store_true", help="Disable LLDP subsystem")
    p.add_argument("--no-bfd",      action="store_true", help="Disable BFD subsystem")
    p.add_argument("--lldp-sock",   default=os.environ.get("LLDP_SOCK_PATH", "/tmp/lldp.sock"))
    p.add_argument("--bfd-sock",    default=os.environ.get("BFD_SOCK_PATH",  "/tmp/bfd.sock"))
    p.add_argument("--bfd-startup", default=os.environ.get("BFD_STARTUP_CONFIG", ""))
    p.add_argument("--log-level",   default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"])
    return p.parse_args()


def main():
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    lldp_ipc = None
    bfd_ipc  = None
    bfd_sm   = None

    # ── BFD subsystem ─────────────────────────────────────────────────────────
    if not args.no_bfd:
        try:
            os.environ["BFD_SOCK_PATH"] = args.bfd_sock

            from bfd.config_manager import BFDConfigManager
            from bfd.session_manager import BFDSessionManager
            from bfd.ipc import BFDIPCServer
            from bfd.startup import export_schema, load_startup_config

            bfd_cm = BFDConfigManager()
            if args.bfd_startup:
                load_startup_config(bfd_cm, args.bfd_startup)
            else:
                load_startup_config(bfd_cm)

            bfd_cfg = bfd_cm.as_bfd_config()

            def on_bfd_state_change(sess, old_state, new_state):
                logger.info(
                    "[BFD EVENT] %s: %s → %s",
                    sess.peer_ip, old_state.name, new_state.name
                )

            bfd_sm  = BFDSessionManager(bfd_cfg, on_state_change=on_bfd_state_change)
            bfd_sm.restore()

            bfd_ipc = BFDIPCServer(bfd_sm, bfd_cm, sock_path=args.bfd_sock)
            bfd_ipc.start()
            export_schema()
            logger.info("BFD subsystem started (socket: %s)", args.bfd_sock)
        except Exception:
            logger.exception("Failed to start BFD subsystem")

    # ── LLDP subsystem ────────────────────────────────────────────────────────
    if not args.no_lldp:
        try:
            from lldp.ipc import LLDPIPCServer          # type: ignore
            from lldp.startup import export_schema as lldp_export_schema  # type: ignore
            # Add your existing LLDP startup here (unchanged from original main.py)
            logger.info("LLDP subsystem started")
        except ImportError:
            logger.debug("LLDP module not found, skipping")

    # ── Signal handling ───────────────────────────────────────────────────────
    def shutdown(sig, frame):
        logger.info("Shutting down (signal %d)…", sig)
        if bfd_ipc:
            bfd_ipc.stop()
        if bfd_sm:
            bfd_sm.stop_all()
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("project-cli daemon running. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
