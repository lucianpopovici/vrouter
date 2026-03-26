"""
BFD IPC server.
Listens on a Unix socket, accepts JSON commands, returns JSON responses.
Mirrors lldp/ipc.py patterns.

Protocol:
  Request:  {"cmd": "<command>", ...args}
  Response: {"ok": true|false, ...payload}

Commands:
  session add    {"cmd":"session.add","peer_ip":"...","local_ip":"...","desired_min_tx_us":300000,"required_min_rx_us":300000,"detect_mult":3}
  session del    {"cmd":"session.del","peer_ip":"..."}
  session show   {"cmd":"session.show"}                    → all sessions
  session show   {"cmd":"session.show","peer_ip":"..."}    → one session
  config get     {"cmd":"config.get"}
  config get     {"cmd":"config.get","key":"LOG_LEVEL"}
  config set     {"cmd":"config.set","key":"LOG_LEVEL","value":"DEBUG"}
  config reset   {"cmd":"config.reset"}
  config reset   {"cmd":"config.reset","key":"LOG_LEVEL"}
  ping           {"cmd":"ping"}
"""

import dataclasses
import json
import logging
import os
import socket
import threading
from typing import Any

logger = logging.getLogger(__name__)

BFD_SOCK_PATH = os.environ.get("BFD_SOCK_PATH", "/tmp/bfd.sock")
RECV_BUF      = 65536


class BFDIPCServer:
    """Unix-socket IPC server for the BFD daemon."""

    def __init__(self, session_manager, config_manager, sock_path: str = BFD_SOCK_PATH):
        self._sm        = session_manager
        self._cm        = config_manager
        self._sock_path = sock_path
        self._server:   Any           = None
        self._thread:   threading.Thread | None = None
        self._running   = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if os.path.exists(self._sock_path):
            os.unlink(self._sock_path)
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self._sock_path)
        self._server.listen(16)
        self._server.settimeout(1.0)
        self._running = True
        self._thread  = threading.Thread(target=self._accept_loop, name="bfd-ipc", daemon=True)
        self._thread.start()
        logger.info("BFD IPC listening on %s", self._sock_path)

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        if os.path.exists(self._sock_path):
            try:
                os.unlink(self._sock_path)
            except Exception:
                pass
        logger.info("BFD IPC stopped")

    # ── Accept loop ───────────────────────────────────────────────────────────

    def _accept_loop(self):
        while self._running:
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            t.start()

    def _handle(self, conn: socket.socket):
        try:
            data = b""
            while True:
                chunk = conn.recv(RECV_BUF)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            if not data:
                return
            request = json.loads(data.decode().strip())
            response = self._dispatch(request)
            conn.sendall((json.dumps(response) + "\n").encode())
        except json.JSONDecodeError:
            conn.sendall((json.dumps({"ok": False, "error": "Invalid JSON"}) + "\n").encode())
        except Exception as e:
            logger.exception("IPC handler error")
            try:
                conn.sendall((json.dumps({"ok": False, "error": str(e)}) + "\n").encode())
            except Exception:
                pass
        finally:
            conn.close()

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def _dispatch(self, req: dict) -> dict:
        cmd = req.get("cmd", "")

        if cmd == "ping":
            return {"ok": True, "pong": True, "sessions": self._sm.count()}

        # ── Session commands ──────────────────────────────────────────────────

        if cmd == "session.add":
            return self._sm.add(
                peer_ip            = req.get("peer_ip", ""),
                local_ip           = req.get("local_ip", "0.0.0.0"),
                desired_min_tx_us  = req.get("desired_min_tx_us"),
                required_min_rx_us = req.get("required_min_rx_us"),
                detect_mult        = req.get("detect_mult"),
            )

        if cmd == "session.del":
            peer_ip = req.get("peer_ip", "")
            if not peer_ip:
                return {"ok": False, "error": "peer_ip required"}
            return self._sm.remove(peer_ip)

        if cmd == "session.show":
            peer_ip = req.get("peer_ip")
            if peer_ip:
                info = self._sm.info(peer_ip)
                if info is None:
                    return {"ok": False, "error": f"No session to {peer_ip}"}
                return {"ok": True, "sessions": [dataclasses.asdict(info)]}
            else:
                sessions = self._sm.all_info()
                return {"ok": True, "sessions": [dataclasses.asdict(s) for s in sessions]}

        # ── Config commands ───────────────────────────────────────────────────

        if cmd == "config.get":
            key = req.get("key")
            try:
                result = self._cm.get(key)
                if key:
                    return {"ok": True, "key": key.upper(), "value": result}
                return {"ok": True, "config": result}
            except KeyError as e:
                return {"ok": False, "error": str(e)}

        if cmd == "config.set":
            key   = req.get("key", "")
            value = req.get("value")
            if not key:
                return {"ok": False, "error": "key required"}
            if value is None:
                return {"ok": False, "error": "value required"}
            return self._cm.set(key, value)

        if cmd == "config.reset":
            key = req.get("key")
            return self._cm.reset(key)

        return {"ok": False, "error": f"Unknown command: {cmd!r}"}
