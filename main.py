import argparse
import logging
import os
import signal
import sys
import time
from typing import Dict, Any

logger = logging.getLogger("vrouter")

# -------------------------
# Service Abstractions
# -------------------------

class Service:
    def start(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError

    def health_check(self) -> bool:
        return True


class ServiceManager:
    def __init__(self):
        self.services: Dict[str, Service] = {}
        self.running = False

    def register(self, name: str, service: Service):
        self.services[name] = service

    def start_all(self):
        logger.info("Starting services...")
        for name, svc in self.services.items():
            try:
                logger.info(f"Starting {name}")
                svc.start()
            except Exception:
                logger.exception(f"Failed to start service: {name}")
                self.stop_all()
                sys.exit(1)

        self.running = True
        logger.info("All services started")

    def stop_all(self):
        logger.info("Stopping services...")
        for name, svc in reversed(self.services.items()):
            try:
                logger.info(f"Stopping {name}")
                svc.stop()
            except Exception:
                logger.exception(f"Error stopping service: {name}")

        self.running = False

    def monitor(self, interval=2):
        logger.info("Entering health monitoring loop")
        while self.running:
            for name, svc in self.services.items():
                try:
                    if not svc.health_check():
                        logger.error(f"Health check failed: {name}")
                except Exception:
                    logger.exception(f"Health check error: {name}")
            time.sleep(interval)


# -------------------------
# Concrete Services
# -------------------------

class BFDService(Service):
    def __init__(self, config_file=None):
        from bfd.config_manager import BFDConfigManager
        from bfd.ipc import BFDIPCServer
        from bfd.session_manager import BFDSessionManager

        self.config_file = config_file
        self.config_mgr = BFDConfigManager()
        self.ipc = BFDIPCServer(self.config_mgr)
        self.sm = BFDSessionManager()

    def start(self):
        if self.config_file:
            self.config_mgr.load_config(self.config_file)

        self.ipc.start()
        self.sm.start()

    def stop(self):
        self.ipc.stop()
        self.sm.stop_all()

    def health_check(self):
        return True  # extend with real checks


class LLDPService(Service):
    def __init__(self):
        from lldp.ipc import LLDPIPCServer
        self.ipc = LLDPIPCServer()

    def start(self):
        self.ipc.start()

    def stop(self):
        self.ipc.stop()

    def health_check(self):
        return True


# -------------------------
# Dependency Validation
# -------------------------

def validate_dependencies():
    required_modules = [
        "bfd.config_manager",
        "bfd.ipc",
        "bfd.session_manager",
        "lldp.ipc",
    ]

    for module in required_modules:
        try:
            __import__(module)
        except ImportError as e:
            logger.error(f"Missing dependency: {module}")
            raise


# -------------------------
# CLI
# -------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="vRouter Control Plane")

    parser.add_argument("--sock-dir", default=os.environ.get("SOCK_DIR", "/tmp"))
    parser.add_argument("--config-dir", default=os.environ.get("CONFIG_DIR", "/etc/vrouter"))
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"))

    parser.add_argument("--no-bfd", action="store_true")
    parser.add_argument("--no-lldp", action="store_true")
    parser.add_argument("--bfd-config")

    return parser.parse_args()


# -------------------------
# Main
# -------------------------

def main():
    args = parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    validate_dependencies()

    manager = ServiceManager()

    if not args.no_bfd:
        manager.register("bfd", BFDService(config_file=args.bfd_config))

    if not args.no_lldp:
        manager.register("lldp", LLDPService())

    def shutdown(signum, frame):
        logger.info(f"Received signal {signum}, shutting down")
        manager.stop_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    manager.start_all()
    manager.monitor()


if __name__ == "__main__":
    main()