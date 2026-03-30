# lldp/security.py
# Security utilities shared across capture, config_manager, and ipc.
#
# Provides:
#   sanitize_str()         — strip non-printable / ANSI from TLV strings
#   validate_iface_name()  — IFNAMSIZ + charset check
#   RateLimiter            — per-source token-bucket rate limiter
#   check_peercred()       — SO_PEERCRED UID check for IPC connections

import re
import socket
import struct
import threading
import time


# ── #3  String sanitization ───────────────────────────────────

# Printable ASCII range only (0x20–0x7E), strip everything else.
# Also strip ANSI escape sequences (ESC [ ... m  and variants).
_ANSI_RE     = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_NONPRINT_RE = re.compile(r'[^\x20-\x7E]')

def sanitize_str(value: str, max_len: int = 256) -> str:
    """
    Remove ANSI escape codes and non-printable characters from a
    TLV string value, then truncate to max_len.
    """
    value = _ANSI_RE.sub('', value)
    value = _NONPRINT_RE.sub('', value)
    return value[:max_len]


# ── #9  Interface name validation ─────────────────────────────

# Linux IFNAMSIZ = 16 (15 chars + NUL).
# Allowed chars: alphanumeric, hyphen, dot, colon, underscore.
_IFACE_RE = re.compile(r'^[A-Za-z0-9.\-:_]{1,15}$')

def validate_iface_name(name: str) -> str:
    """
    Validate and return a sanitized interface name.
    Raises ValueError if invalid.
    """
    if not _IFACE_RE.match(name):
        raise ValueError(
            f"Invalid interface name '{name}': must be 1-15 chars, "
            f"alphanumeric / . - : _ only"
        )
    return name


# ── #2  Token-bucket rate limiter ─────────────────────────────

class RateLimiter:
    """
    Per-key token-bucket rate limiter.

    Each key (e.g. source MAC) gets its own bucket that refills at
    *rate* tokens/second up to *burst* tokens.  A call to allow()
    returns True and consumes one token if the bucket is non-empty,
    or False if the source is over-rate.

    Thread-safe.

    Default: 10 frames/sec burst, 1 frame/sec sustained.
    This is very generous — spec says one frame per tx-interval (30s).
    """

    def __init__(self, rate: float = 1.0, burst: int = 10):
        """
        rate  : sustained tokens per second (float)
        burst : maximum bucket depth (int)
        """
        self._rate  = rate
        self._burst = burst
        self._lock  = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}
        # bucket value: (tokens, last_refill_time)

    def allow(self, key: str) -> bool:
        """Return True if the key is within rate limit, False otherwise."""
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self._burst), now))
            # Refill
            tokens = min(self._burst,
                         tokens + (now - last) * self._rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return True
            else:
                self._buckets[key] = (tokens, now)
                return False

    def evict_stale(self, max_age_s: float = 300.0):
        """
        Remove buckets not seen for max_age_s seconds.
        Call periodically to prevent unbounded dict growth.
        """
        now = time.monotonic()
        with self._lock:
            stale = [k for k, (_, last) in self._buckets.items()
                     if now - last > max_age_s]
            for k in stale:
                del self._buckets[k]
        return len(stale)


# ── #6  IPC peer credential check ────────────────────────────

def check_peercred(conn: socket.socket,
                   allowed_uids: list = None) -> tuple:
    """
    Read SO_PEERCRED from a Unix socket connection.
    Returns (pid, uid, gid).

    If allowed_uids is provided (list of ints), raises PermissionError
    if the connecting process UID is not in the list.

    Passing allowed_uids=None (default) allows any local process
    (same behaviour as before, but now at least we log the UID).
    """
    # struct ucred: pid_t(4) + uid_t(4) + gid_t(4) = 12 bytes
    SO_PEERCRED = 17   # Linux constant
    try:
        cred = conn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, 12)
        pid, uid, gid = struct.unpack("III", cred)
    except OSError:
        # Not available on all platforms — fail open
        return (0, 0, 0)

    if allowed_uids is not None and uid not in allowed_uids:
        raise PermissionError(
            f"IPC connection rejected: UID {uid} not in allowed list "
            f"{allowed_uids} (PID {pid})"
        )
    return pid, uid, gid
