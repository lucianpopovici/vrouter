"""
BFD display helpers.
Mirrors lldp/display.py patterns.
"""

import time
from typing import List, Optional

from .session import BFDSessionInfo
from .packet import DIAG


# ANSI colours
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_CYAN   = "\033[36m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

_STATE_COLOR = {
    "Up":        _GREEN,
    "Init":      _YELLOW,
    "Down":      _RED,
    "AdminDown": _RED,
}


def _color_state(state: str) -> str:
    return f"{_STATE_COLOR.get(state, '')}{state}{_RESET}"


def _us_to_ms(us: int) -> str:
    return f"{us / 1000:.0f} ms"


def _elapsed(ts: Optional[float]) -> str:
    if ts is None:
        return "never"
    secs = int(time.monotonic() - ts)
    if secs < 60:
        return f"{secs}s ago"
    m, s = divmod(secs, 60)
    if m < 60:
        return f"{m}m{s:02d}s ago"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m ago"


def _uptime(ts: Optional[float]) -> str:
    if ts is None:
        return "-"
    secs = int(time.monotonic() - ts)
    m, s = divmod(secs, 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    if d:
        return f"{d}d{h:02d}h{m:02d}m"
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    return f"{m}m{s:02d}s"


# ── Public display functions ───────────────────────────────────────────────────

def display_sessions(sessions: List[BFDSessionInfo], verbose: bool = False) -> str:
    """Return a formatted session table as a string."""
    if not sessions:
        return "No BFD sessions configured.\n"

    lines = []

    if not verbose:
        # Compact summary table
        header = (
            f"{'Peer IP':<20} {'Local IP':<16} {'State':<12} "
            f"{'TX':<10} {'RX':<10} {'Mult':<6} {'Uptime':<14} {'Last RX'}"
        )
        lines.append(f"{_BOLD}{header}{_RESET}")
        lines.append("─" * len(header))
        for s in sessions:
            lines.append(
                f"{s.peer_ip:<20} {s.local_ip:<16} {_color_state(s.state):<21} "
                f"{_us_to_ms(s.negotiated_tx_us):<10} {_us_to_ms(s.required_min_rx_us):<10} "
                f"{s.detect_mult:<6} {_uptime(s.up_since):<14} {_elapsed(s.last_rx)}"
            )
    else:
        # Verbose per-session detail
        for s in sessions:
            lines.append(f"{_BOLD}{_CYAN}BFD Session: {s.peer_ip}{_RESET}")
            lines.append(f"  {'State':<28}: {_color_state(s.state)}")
            lines.append(f"  {'Local IP':<28}: {s.local_ip}")
            lines.append(f"  {'Local Discriminator':<28}: {s.local_disc:#010x}")
            lines.append(f"  {'Remote Discriminator':<28}: {s.remote_disc:#010x}")
            lines.append(f"  {'Desired Min TX':<28}: {_us_to_ms(s.desired_min_tx_us)}")
            lines.append(f"  {'Required Min RX':<28}: {_us_to_ms(s.required_min_rx_us)}")
            lines.append(f"  {'Negotiated TX':<28}: {_us_to_ms(s.negotiated_tx_us)}")
            lines.append(f"  {'Detect Multiplier':<28}: {s.detect_mult}")
            lines.append(f"  {'Remote Detect Mult':<28}: {s.remote_detect_mult}")
            lines.append(f"  {'Detection Time':<28}: {_us_to_ms(s.detect_time_us)}")
            lines.append(f"  {'Local Diagnostic':<28}: {DIAG.get(s.diag, s.diag)}")
            lines.append(f"  {'Remote Diagnostic':<28}: {DIAG.get(s.remote_diag, s.remote_diag)}")
            lines.append(f"  {'Last RX':<28}: {_elapsed(s.last_rx)}")
            lines.append(f"  {'Last State Change':<28}: {_elapsed(s.last_state_change)}")
            lines.append(f"  {'Uptime':<28}: {_uptime(s.up_since)}")
            lines.append("")

    lines.append(f"\nTotal sessions: {len(sessions)}")
    return "\n".join(lines) + "\n"


def display_config(cfg: dict) -> str:
    """Pretty-print config key/value pairs."""
    lines = [f"{_BOLD}BFD Configuration{_RESET}", "─" * 40]
    for k, v in sorted(cfg.items()):
        lines.append(f"  {k:<30}: {v}")
    return "\n".join(lines) + "\n"
