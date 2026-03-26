# lldp/client.py
# Thin client for the LLDP IPC server.
# Zero external dependencies — stdlib only.
#
# Usage:
#   from lldp.client import LLDPClient
#
#   with LLDPClient() as c:
#       print(c.neighbors_list())
#       print(c.config_show())
#       c.config_set("TTL", 60)
#       c.interfaces_add("eth2")
#
#   # Real-time event streaming
#   with LLDPClient() as c:
#       for event in c.subscribe():
#           print(event)   # {"event": "neighbor.updated", "data": {...}}

import json
import socket
import threading

from .ipc import SOCKET_PATH


class LLDPClient:
    """
    JSON-over-UDS client.

    Can be used as a context manager or standalone.
    Thread-safe for commands; subscribe() is a blocking generator.
    """

    def __init__(self, socket_path: str = SOCKET_PATH):
        self._path   = socket_path
        self._sock   = None
        self._lock   = threading.Lock()
        self._buf    = b""
        self._seq    = 0

    # ── Connection lifecycle ───────────────────

    def connect(self):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(self._path)
        return self

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *_):
        self.close()

    # ── Low-level send / recv ──────────────────

    def _send(self, cmd: str, params: dict = None) -> dict:
        self._seq += 1
        req = json.dumps({"id": self._seq, "cmd": cmd,
                          "params": params or {}}) + "\n"
        with self._lock:
            self._sock.sendall(req.encode())
            resp = self._readline()
        data = json.loads(resp)
        if not data.get("ok"):
            raise RuntimeError(f"IPC error [{cmd}]: {data.get('error')}")
        return data.get("result")

    def _readline(self) -> str:
        """Read one newline-terminated line from the socket."""
        while b"\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("Server closed connection")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line.decode()

    # ── Neighbor commands ──────────────────────

    def neighbors_list(self) -> dict:
        """Return the full neighbor table as {mac: info_dict}."""
        return self._send("neighbors.list")

    # ── Interface commands ─────────────────────

    def interfaces_list(self) -> list:
        """Return the list of active interface names."""
        return self._send("interfaces.list")

    def interfaces_add(self, name: str) -> dict:
        """Add an interface to the active list."""
        return self._send("interfaces.add", {"name": name})

    def interfaces_remove(self, name: str) -> dict:
        """Remove an interface from the active list."""
        return self._send("interfaces.remove", {"name": name})

    # ── Config commands ────────────────────────

    def config_get(self, key: str):
        """Get a scalar config value."""
        return self._send("config.get", {"key": key})["value"]

    def config_set(self, key: str, value) -> dict:
        """Set a scalar config value."""
        return self._send("config.set", {"key": key, "value": value})

    def config_show(self) -> list:
        """Return the full config table as a list of dicts."""
        return self._send("config.show")

    # ── Custom TLV commands ────────────────────

    def custom_tlv_add(self, oui: str, subtype: int,
                       data_hex: str = "") -> int:
        """Add a custom TLV. Returns its index."""
        return self._send("custom_tlv.add",
                          {"oui": oui, "subtype": subtype,
                           "data": data_hex})["index"]

    def custom_tlv_remove(self, index: int):
        """Remove a custom TLV by index."""
        return self._send("custom_tlv.remove", {"index": index})

    def custom_tlv_list(self) -> list:
        """Return all custom TLVs."""
        return self._send("custom_tlv.list")

    # ── MED Policy commands ────────────────────

    def med_policy_add(self, app_type: int, vlan_id: int = 0,
                       priority: int = 0, dscp: int = 0,
                       tagged: bool = False, unknown: bool = False) -> int:
        return self._send("med_policy.add", {
            "app_type": app_type, "vlan_id": vlan_id,
            "priority": priority, "dscp": dscp,
            "tagged": tagged, "unknown": unknown,
        })["index"]

    def med_policy_remove(self, index: int):
        return self._send("med_policy.remove", {"index": index})

    def med_policy_list(self) -> list:
        return self._send("med_policy.list")

    # ── MED Location commands ──────────────────

    def med_location_set(self, fmt: str, **kwargs):
        return self._send("med_location.set", {"format": fmt, **kwargs})

    def med_location_clear(self):
        return self._send("med_location.clear")

    # ── MED / 802.3 PoE commands ───────────────

    def med_poe_set(self, power_type: int = 0, power_source: int = 1,
                    priority: int = 2, power_mw: int = 15400):
        return self._send("med_poe.set", {
            "power_type": power_type, "power_source": power_source,
            "priority": priority, "power_mw": power_mw,
        })

    def dot3_poe_set(self, port_class: str = "PSE",
                     poe_supported: bool = True,
                     poe_enabled: bool = True,
                     pairs_controllable: bool = False,
                     power_pair: int = 1,
                     power_class: int = 0):
        return self._send("dot3_poe.set", {
            "port_class": port_class, "poe_supported": poe_supported,
            "poe_enabled": poe_enabled,
            "pairs_controllable": pairs_controllable,
            "power_pair": power_pair, "power_class": power_class,
        })

    # ── Event subscription ─────────────────────

    def subscribe(self, retry: bool = True,
                  retry_delay: float = 3.0,
                  max_retries: int = None):
        """
        Subscribe to real-time neighbor events.
        Returns a blocking generator of event dicts:

            {"event": "neighbor.discovered", "data": {mac, info}}
            {"event": "neighbor.updated",    "data": {mac, info}}
            {"event": "neighbor.expired",    "data": {mac}}

        Args:
            retry       : Reconnect automatically if the server drops the
                          connection (default True).
            retry_delay : Seconds to wait between reconnect attempts.
            max_retries : Maximum reconnect attempts (None = unlimited).

        Example:
            with LLDPClient() as c:
                for event in c.subscribe():
                    print(event["event"], event["data"])

            # Or without context manager (manages its own connection):
            client = LLDPClient()
            for event in client.subscribe():
                print(event)
        """
        import time as _time

        attempts = 0
        while True:
            # Ensure we have a live connection
            if self._sock is None:
                try:
                    self.connect()
                except OSError as e:
                    if not retry:
                        raise
                    if max_retries is not None and attempts >= max_retries:
                        raise ConnectionError(
                            f"Could not reconnect after {attempts} attempts"
                        ) from e
                    attempts += 1
                    _time.sleep(retry_delay)
                    continue

            try:
                self._send("events.subscribe")
                attempts = 0   # reset on successful subscribe
                while True:
                    line = self._readline()
                    if not line:
                        continue
                    msg = json.loads(line)
                    if "event" in msg:
                        yield msg
            except (OSError, ConnectionError, json.JSONDecodeError):
                self.close()
                if not retry:
                    return
                if max_retries is not None and attempts >= max_retries:
                    return
                attempts += 1
                _time.sleep(retry_delay)
