# lldp/ipc.py
# Unix Domain Socket IPC server.
#
# Protocol: newline-delimited JSON over AF_UNIX SOCK_STREAM.
#
# Request  : {"id": <int>, "cmd": "<command>", "params": {...}}
# Response : {"id": <int>, "ok": true,  "result": ...}
#           : {"id": <int>, "ok": false, "error": "<message>"}
# Event    : {"event": "<type>", "data": {...}}   (subscribers only)

import json
import os
import socket
import threading
import time
import logging

from . import config
from . import config_manager
from ._config_groups import CONFIG_GROUPS
from .watcher import read_interfaces
from .security import check_peercred, validate_iface_name

log = logging.getLogger("lldp.ipc")

SOCKET_PATH    = "/tmp/lldpd.sock"
MAX_BUF_BYTES  = 65536   # reject connections that send lines longer than this


# ── Event broadcaster ─────────────────────────

class EventBroadcaster:
    """
    Thread-safe broadcaster.
    capture.py and reaper.py call emit() for each neighbor event.
    All subscribed IPC connections receive it.
    """
    def __init__(self):
        self._lock        = threading.Lock()
        self._subscribers = []   # list of (conn, lock)

    def subscribe(self, conn, conn_lock):
        with self._lock:
            self._subscribers.append((conn, conn_lock))
        log.debug("IPC subscriber added (%d total)", len(self._subscribers))

    def unsubscribe(self, conn):
        with self._lock:
            self._subscribers = [
                (c, l) for c, l in self._subscribers if c is not conn
            ]
        log.debug("IPC subscriber removed (%d remaining)", len(self._subscribers))

    def emit(self, event_type: str, data: dict):
        """Broadcast an event to all current subscribers."""
        msg     = json.dumps({"event": event_type, "data": data}) + "\n"
        encoded = msg.encode()
        dead    = []
        with self._lock:
            subs = list(self._subscribers)
        for conn, conn_lock in subs:
            try:
                with conn_lock:
                    conn.sendall(encoded)
            except OSError:
                dead.append(conn)
        for conn in dead:
            self.unsubscribe(conn)


# Singleton — imported by capture.py and reaper.py
broadcaster = EventBroadcaster()


# ── Command dispatcher ────────────────────────

def _dispatch(cmd: str, params: dict,
              neighbors: dict, neighbors_lock: threading.Lock,
              interfaces_file: str,
              conn, conn_lock) -> object:

    # ── Neighbor ──────────────────────────────
    if cmd == "neighbors.list":
        with neighbors_lock:
            return dict(neighbors)

    # ── Interfaces ────────────────────────────
    elif cmd == "interfaces.list":
        return read_interfaces(interfaces_file)

    elif cmd == "interfaces.add":
        name = validate_iface_name(params.get("name", "").strip())  # #9
        
        # Check if interface actually exists in the OS
        if not os.path.exists(f"/sys/class/net/{name}"):
            raise ValueError(f"Interface '{name}' does not exist on system")
            
        ifaces = read_interfaces(interfaces_file)
        if name not in ifaces:
            ifaces.append(name)
            _write_interfaces(interfaces_file, ifaces)
        return {"name": name}

    elif cmd == "interfaces.remove":
        name = validate_iface_name(params.get("name", "").strip())  # #9
        ifaces = read_interfaces(interfaces_file)
        if name in ifaces:
            ifaces.remove(name)
            _write_interfaces(interfaces_file, ifaces)
        return {"name": name}

    # ── Config ────────────────────────────────
    elif cmd == "config.get":
        key   = params.get("key", "").upper()
        value = config_manager.get(key)
        return {"key": key, "value": value}

    elif cmd == "config.set":
        key   = params.get("key", "").upper()
        value = params.get("value")
        if value is None:
            raise ValueError("'value' is required")
        config_manager.set(key, value)
        return {"key": key, "value": config_manager.get(key)}

    elif cmd == "config.show":
        rows = []
        for group, keys in CONFIG_GROUPS.items():
            for k in keys:
                try:
                    val  = config_manager.get(k)
                    desc = config_manager.SCHEMA[k][1]
                    rows.append({"group": group, "key": k,
                                 "value": val, "description": desc})
                except KeyError:
                    pass
        return rows

    # ── Custom TLVs ───────────────────────────
    elif cmd == "custom_tlv.add":
        idx = config_manager.custom_tlv_add(
            params.get("oui", ""),
            int(params.get("subtype", 0)),
            params.get("data", ""),
        )
        return {"index": idx}

    elif cmd == "custom_tlv.remove":
        config_manager.custom_tlv_remove(int(params.get("index", -1)))
        return {"index": params.get("index")}

    elif cmd == "custom_tlv.list":
        return list(config.CUSTOM_TLVS)

    # ── MED Policy ────────────────────────────
    elif cmd == "med_policy.add":
        idx = config_manager.med_policy_add(
            app_type = int(params["app_type"]),
            vlan_id  = int(params.get("vlan_id",  0)),
            priority = int(params.get("priority", 0)),
            dscp     = int(params.get("dscp",     0)),
            tagged   = bool(params.get("tagged",  False)),
            unknown  = bool(params.get("unknown", False)),
        )
        return {"index": idx}

    elif cmd == "med_policy.remove":
        config_manager.med_policy_remove(int(params.get("index", -1)))
        return {"index": params.get("index")}

    elif cmd == "med_policy.list":
        return list(config.MED_NETWORK_POLICIES)

    # ── MED Location ──────────────────────────
    elif cmd == "med_location.set":
        fmt = params.pop("format", params.pop("fmt", None))
        if not fmt:
            raise ValueError("'format' is required")
        config_manager.med_location_set(fmt, **params)
        return config.MED_LOCATION

    elif cmd == "med_location.clear":
        config_manager.med_location_clear()
        return {}

    # ── MED PoE ───────────────────────────────
    elif cmd == "med_poe.set":
        config_manager.med_poe_set(
            power_type   = int(params.get("power_type",   0)),
            power_source = int(params.get("power_source", 1)),
            priority     = int(params.get("priority",     2)),
            power_mw     = int(params.get("power_mw",  15400)),
        )
        return config.MED_POE

    # ── 802.3 PoE ─────────────────────────────
    elif cmd == "dot3_poe.set":
        config_manager.dot3_poe_set(
            port_class         = params.get("port_class",        "PSE"),
            poe_supported      = bool(params.get("poe_supported",  True)),
            poe_enabled        = bool(params.get("poe_enabled",    True)),
            pairs_controllable = bool(params.get("pairs_controllable", False)),
            power_pair         = int(params.get("power_pair",  1)),
            power_class        = int(params.get("power_class", 0)),
        )
        return config.DOT3_POE

    # ── Event subscription ────────────────────
    elif cmd == "events.subscribe":
        broadcaster.subscribe(conn, conn_lock)
        return {"subscribed": True}

    else:
        raise ValueError(f"Unknown command '{cmd}'")


# ── Interfaces file writer ────────────────────

def _write_interfaces(path: str, ifaces: list):
    header = ("# interfaces.txt — managed via IPC\n"
              "# One interface per line. Lines starting with # are ignored.\n")
    with open(path, "w") as f:
        f.write(header)
        for name in ifaces:
            f.write(name + "\n")


# ── Per-connection handler ────────────────────

def _handle_connection(conn: socket.socket,
                       neighbors: dict,
                       neighbors_lock: threading.Lock,
                       interfaces_file: str):
    conn_lock  = threading.Lock()
    buf        = b""
    subscribed = False
    req_id     = 0          # tracked here to avoid dir() hack

    # ── #6  Peer credential check ──────────────────────────
    try:
        pid, uid, gid = check_peercred(conn, config.IPC_ALLOWED_UIDS)
        log.debug("IPC connection accepted from PID=%d UID=%d", pid, uid)
    except PermissionError as e:
        log.warning("%s", e)
        try:
            err = json.dumps({"id": 0, "ok": False,
                              "error": "Permission denied"}) + "\n"
            conn.sendall(err.encode())
            conn.close()
        except OSError:
            pass
        return

    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk

            # Guard: reject oversized lines
            if len(buf) > MAX_BUF_BYTES:
                err = json.dumps({"id": 0, "ok": False,
                                  "error": "Request too large"}) + "\n"
                conn.sendall(err.encode())
                break

            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue

                try:
                    req    = json.loads(line)
                    req_id = req.get("id", 0)
                    cmd    = req.get("cmd", "")
                    prms   = req.get("params", {})
                    if not isinstance(prms, dict):
                        prms = {}

                    result = _dispatch(cmd, prms, neighbors, neighbors_lock,
                                       interfaces_file, conn, conn_lock)

                    if cmd == "events.subscribe":
                        subscribed = True

                    resp = json.dumps({"id": req_id, "ok": True,
                                       "result": result}) + "\n"

                except (ValueError, KeyError, IndexError, TypeError) as e:
                    resp = json.dumps({"id": req_id, "ok": False,
                                       "error": str(e)}) + "\n"
                except Exception as e:
                    log.exception("Unhandled error in IPC dispatch")
                    resp = json.dumps({"id": req_id, "ok": False,
                                       "error": f"Internal error: {e}"}) + "\n"

                with conn_lock:
                    conn.sendall(resp.encode())

    except OSError:
        pass
    finally:
        if subscribed:
            broadcaster.unsubscribe(conn)
        try:
            conn.close()
        except OSError:
            pass


# ── Server ────────────────────────────────────

def run(neighbors: dict, neighbors_lock: threading.Lock,
        socket_path: str = SOCKET_PATH):
    """Start the UDS server. Each client gets its own handler thread."""
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    os.chmod(socket_path, 0o660)
    srv.listen(16)

    print(f"[IPC] Server listening on {socket_path}")
    interfaces_file = config.INTERFACES_FILE

    while True:
        try:
            conn, _ = srv.accept()
            threading.Thread(
                target=_handle_connection,
                args=(conn, neighbors, neighbors_lock, interfaces_file),
                daemon=True,
                name="ipc-conn",
            ).start()
        except OSError as e:
            log.error("IPC accept error: %s", e)
            time.sleep(1)
