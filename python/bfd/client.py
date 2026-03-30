"""
BFD IPC client.
Sends JSON commands to the BFD daemon over the Unix socket.
Mirrors lldp/client.py patterns.
"""

import json
import os
import socket
from typing import Any, Optional

BFD_SOCK_PATH = os.environ.get("BFD_SOCK_PATH", "/tmp/bfd.sock")


class BFDClientError(Exception):
    pass


class BFDClient:
    """Thin synchronous client for the BFD IPC socket."""

    def __init__(self, sock_path: str = BFD_SOCK_PATH, timeout: float = 5.0):
        self._sock_path = sock_path
        self._timeout   = timeout

    # ── Raw transport ─────────────────────────────────────────────────────────

    def _send(self, payload: dict) -> dict:
        if not os.path.exists(self._sock_path):
            raise BFDClientError(
                f"BFD daemon not running (socket not found: {self._sock_path})\n"
                "Start with: sudo python3 main.py"
            )
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            sock.connect(self._sock_path)
            sock.sendall((json.dumps(payload) + "\n").encode())
            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            return json.loads(data.decode().strip())
        except socket.timeout:
            raise BFDClientError("Timeout waiting for BFD daemon response")
        except json.JSONDecodeError as e:
            raise BFDClientError(f"Invalid JSON from daemon: {e}")
        finally:
            sock.close()

    # ── High-level API ────────────────────────────────────────────────────────

    def ping(self) -> dict:
        return self._send({"cmd": "ping"})

    def session_add(
        self,
        peer_ip:            str,
        local_ip:           str            = "0.0.0.0",
        desired_min_tx_us:  Optional[int]  = None,
        required_min_rx_us: Optional[int]  = None,
        detect_mult:        Optional[int]  = None,
    ) -> dict:
        req: dict[str, Any] = {"cmd": "session.add", "peer_ip": peer_ip, "local_ip": local_ip}
        if desired_min_tx_us  is not None: req["desired_min_tx_us"]  = desired_min_tx_us
        if required_min_rx_us is not None: req["required_min_rx_us"] = required_min_rx_us
        if detect_mult        is not None: req["detect_mult"]         = detect_mult
        return self._send(req)

    def session_del(self, peer_ip: str) -> dict:
        return self._send({"cmd": "session.del", "peer_ip": peer_ip})

    def session_show(self, peer_ip: Optional[str] = None) -> dict:
        req: dict[str, Any] = {"cmd": "session.show"}
        if peer_ip:
            req["peer_ip"] = peer_ip
        return self._send(req)

    def config_get(self, key: Optional[str] = None) -> dict:
        req: dict[str, Any] = {"cmd": "config.get"}
        if key:
            req["key"] = key
        return self._send(req)

    def config_set(self, key: str, value: Any) -> dict:
        return self._send({"cmd": "config.set", "key": key, "value": value})

    def config_reset(self, key: Optional[str] = None) -> dict:
        req: dict[str, Any] = {"cmd": "config.reset"}
        if key:
            req["key"] = key
        return self._send(req)
