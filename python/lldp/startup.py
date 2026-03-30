# lldp/startup.py
# ─────────────────────────────────────────────────────────────
# Startup configuration loader.
#
# Loads LLDP config from one or more external sources at startup,
# in priority order (last source wins for overlapping keys).
#
# Supports:
#   - Config files  : JSON, YAML, TOML, INI
#   - Remote stores : Redis, etcd, Consul (via user callable)
#
# Usage:
#
#   from lldp.startup import load_from_file, load_from_remote, load_startup
#
#   # Single file
#   load_from_file("/etc/myapp/config.json", section="lldp")
#
#   # Single remote store
#   load_from_remote(lambda: redis.hgetall("lldp:config"))
#
#   # Multiple sources in priority order (last wins)
#   load_startup([
#       ("file",   "/etc/myapp/defaults.yaml"),          # base defaults
#       ("file",   "/etc/myapp/config.yaml"),             # site overrides
#       ("remote", lambda: consul_read("lldp/")),         # live overrides
#   ])
#
# ─────────────────────────────────────────────────────────────

from __future__ import annotations

import configparser
import json
import logging
import os
from typing import Any, Callable

log = logging.getLogger("lldp.startup")


# ══════════════════════════════════════════════════════════════
#  Internal helpers
# ══════════════════════════════════════════════════════════════

def _apply(raw: dict[str, Any], source_label: str) -> dict[str, str]:
    """
    Apply a flat {KEY: value} dict to config_manager.
    Returns {key: "applied" | "skipped: <reason>"} report.
    Keys are case-insensitive.
    """
    from . import config_manager

    report = {}
    for key, value in raw.items():
        key = str(key).upper()
        if key not in config_manager.SCHEMA:
            report[key] = "skipped: unknown key"
            continue
        try:
            config_manager.set(key, value)
            report[key] = "applied"
        except (ValueError, TypeError) as e:
            report[key] = f"skipped: {e}"
            log.warning("[startup] %s: could not apply %s=%r — %s",
                        source_label, key, value, e)

    applied = sum(1 for v in report.values() if v == "applied")
    skipped = len(report) - applied
    log.info("[startup] %s: %d key(s) applied, %d skipped",
             source_label, applied, skipped)
    return report


def _print_report(source: str, report: dict[str, str]):
    applied = [(k, v) for k, v in report.items() if v == "applied"]
    skipped = [(k, v) for k, v in report.items() if v != "applied"]
    print(f"[STARTUP] {source}: {len(applied)} applied"
          + (f", {len(skipped)} skipped" if skipped else ""))
    for k, v in applied:
        print(f"  ✓ {k}")
    for k, v in skipped:
        print(f"  ✗ {k} ({v})")


# ══════════════════════════════════════════════════════════════
#  File loader
# ══════════════════════════════════════════════════════════════

def load_from_file(
    path: str,
    fmt:     str        = "auto",
    section: str | None = "lldp",
    prefix:  str        = "",
    required: bool      = False,
    verbose: bool       = True,
) -> dict[str, str]:
    """
    Load LLDP config from a file at startup.

    Args:
        path     : path to the config file
        fmt      : "json" | "yaml" | "toml" | "ini" | "auto" (default)
        section  : key/section inside the file containing LLDP config.
                   - JSON/YAML/TOML: nested dict key  (e.g. "lldp")
                   - INI:            section name      (e.g. "[lldp]")
                   - None:           flat file, no nesting
        prefix   : strip this prefix from key names (e.g. "lldp_")
        required : if True, raise FileNotFoundError if file is missing
        verbose  : print a summary of what was applied

    Returns:
        dict of {key: "applied" | "skipped: <reason>"}

    File format examples
    ────────────────────
    JSON (nested):
        {
          "lldp": {
            "TTL": 60,
            "SEND_INTERVAL": 15,
            "TLV_DOT3_POE_ENABLED": false,
            "MAX_NEIGHBORS_PER_INTERFACE": 16
          }
        }

    JSON (flat):
        {
          "TTL": 60,
          "SEND_INTERVAL": 15
        }
        → section=None

    YAML:
        lldp:
          TTL: 60
          SEND_INTERVAL: 15
          TLV_MED_INVENTORY_ENABLED: true

    TOML:
        [lldp]
        TTL = 60
        SEND_INTERVAL = 15

    INI:
        [lldp]
        TTL = 60
        SEND_INTERVAL = 15
        TLV_DOT3_POE_ENABLED = false
    """
    if not os.path.exists(path):
        if required:
            raise FileNotFoundError(f"Required config file not found: {path}")
        log.info("[startup] file not found, skipping: %s", path)
        return {}

    detected = fmt if fmt != "auto" else _detect_fmt(path)

    try:
        raw_data = _read_file(path, detected, section, prefix)
    except Exception as e:
        log.error("[startup] failed to read %s: %s", path, e)
        if required:
            raise
        return {}

    report = _apply(raw_data, f"file:{path}")
    if verbose:
        _print_report(f"file:{os.path.basename(path)}", report)
    return report


def _detect_fmt(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    return {
        ".json": "json", ".yaml": "yaml", ".yml": "yaml",
        ".toml": "toml", ".ini": "ini", ".cfg": "ini",
    }.get(ext, "json")


def _read_file(path: str, fmt: str,
               section: str | None, prefix: str) -> dict[str, Any]:
    """Read file and return flat {LLDP_KEY: value} dict."""

    # ── JSON ──────────────────────────────────────────────────
    if fmt == "json":
        with open(path) as f:
            data = json.load(f)
        data = data.get(section, data) if section else data

    # ── YAML ──────────────────────────────────────────────────
    elif fmt == "yaml":
        try:
            import yaml
        except ImportError:
            raise ImportError("pyyaml required: pip install pyyaml")
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        data = data.get(section, data) if section else data

    # ── TOML ──────────────────────────────────────────────────
    elif fmt == "toml":
        try:
            try:
                import tomllib                    # Python 3.11+
            except ImportError:
                import tomli as tomllib           # type: ignore
        except ImportError:
            raise ImportError("tomli required for Python < 3.11: pip install tomli")
        with open(path, "rb") as f:
            data = tomllib.load(f)
        data = data.get(section, data) if section else data

    # ── INI ───────────────────────────────────────────────────
    elif fmt == "ini":
        cp = configparser.ConfigParser()
        cp.read(path)
        sec = section or "lldp"
        data = dict(cp[sec]) if cp.has_section(sec) else {}

    else:
        raise ValueError(f"Unknown format '{fmt}'")

    # Strip prefix and normalise keys to UPPER
    prefix_up = prefix.upper()
    result    = {}
    for k, v in data.items():
        uk = str(k).upper()
        if prefix_up and uk.startswith(prefix_up):
            uk = uk[len(prefix_up):]
        result[uk] = v
    return result


# ══════════════════════════════════════════════════════════════
#  Remote store loader
# ══════════════════════════════════════════════════════════════

def load_from_remote(
    reader:   Callable[[], dict[str, Any]],
    prefix:   str  = "",
    label:    str  = "remote",
    required: bool = False,
    verbose:  bool = True,
) -> dict[str, str]:
    """
    Load LLDP config from a remote store at startup.

    Args:
        reader   : callable returning {key: value} dict.
                   Called once at startup.
        prefix   : strip this prefix from returned keys (e.g. "lldp:")
        label    : display name for log messages
        required : if True, raise on error instead of returning {}
        verbose  : print a summary of what was applied

    Returns:
        dict of {key: "applied" | "skipped: <reason>"}

    Reader examples
    ───────────────
    Redis (hash):
        import redis
        r = redis.Redis(host="localhost", decode_responses=True)
        load_from_remote(
            reader = lambda: r.hgetall("lldp:config"),
            label  = "redis",
        )

        Redis hash format:
            HSET lldp:config TTL 60
            HSET lldp:config SEND_INTERVAL 15
            HSET lldp:config TLV_DOT3_POE_ENABLED false

    Redis (prefixed keys):
        load_from_remote(
            reader = lambda: {
                k.split(":", 1)[1]: r.get(k)
                for k in r.keys("lldp:*")
                if r.get(k) is not None
            },
            label = "redis-keys",
        )

    etcd (v3 — etcd3 library):
        import etcd3
        client = etcd3.client()
        def read_etcd():
            result = {}
            for value, meta in client.get_prefix("/lldp/"):
                key = meta.key.decode().split("/")[-1].upper()
                result[key] = value.decode()
            return result
        load_from_remote(reader=read_etcd, label="etcd")

    Consul:
        import consul
        c = consul.Consul()
        def read_consul():
            _, items = c.kv.get("lldp/", recurse=True)
            if not items:
                return {}
            return {
                item["Key"].split("/")[-1].upper(): item["Value"].decode()
                for item in items
                if item["Value"] is not None
            }
        load_from_remote(reader=read_consul, label="consul")

    HTTP / REST API:
        import urllib.request
        def read_api():
            url = "https://config.internal/api/lldp"
            with urllib.request.urlopen(url) as r:
                return json.loads(r.read())
        load_from_remote(reader=read_api, label="config-api")
    """
    try:
        raw = reader()
    except Exception as e:
        log.error("[startup] %s: read failed — %s", label, e)
        if required:
            raise
        return {}

    # Strip prefix and normalise
    prefix_up = prefix.upper()
    flat = {}
    for k, v in raw.items():
        uk = str(k).upper()
        if prefix_up and uk.startswith(prefix_up):
            uk = uk[len(prefix_up):]
        flat[uk] = v

    report = _apply(flat, label)
    if verbose:
        _print_report(label, report)
    return report


# ══════════════════════════════════════════════════════════════
#  Multi-source startup loader
# ══════════════════════════════════════════════════════════════

def load_startup(
    sources: list[tuple],
    verbose: bool = True,
    stop_on_error: bool = False,
) -> dict[str, list[str]]:
    """
    Load from multiple sources in order. Later sources override earlier ones
    for the same key (last wins).

    Args:
        sources : list of (type, ...) tuples:
                    ("file",   path, **kwargs)
                    ("remote", reader_callable, **kwargs)
        verbose : print per-source summary
        stop_on_error : if True, raise on first failure

    Returns:
        {key: [source1_result, source2_result, ...]} merged report

    Priority example — lowest to highest:
        load_startup([
            ("file",   "/etc/lldp/defaults.json"),       # shipped defaults
            ("file",   "/etc/lldp/site.yaml"),            # site overrides
            ("remote", lambda: redis.hgetall("lldp")),    # live overrides
        ])

    The last source that provides a key wins.
    Keys not provided by any source keep their config.py defaults.
    """
    merged: dict[str, list[str]] = {}

    for entry in sources:
        kind = entry[0]

        try:
            if kind == "file":
                path   = entry[1]
                kwargs = dict(entry[2]) if len(entry) > 2 else {}
                kwargs.setdefault("verbose", verbose)   # caller can override
                report = load_from_file(path, **kwargs)

            elif kind == "remote":
                reader = entry[1]
                kwargs = dict(entry[2]) if len(entry) > 2 else {}
                kwargs.setdefault("verbose", verbose)
                report = load_from_remote(reader, **kwargs)

            else:
                log.warning("[startup] unknown source type '%s' — skipped", kind)
                continue

        except Exception as e:
            log.error("[startup] source %r failed: %s", entry, e)
            if stop_on_error:
                raise
            continue

        for key, result in report.items():
            merged.setdefault(key, []).append(result)

    return merged


# ══════════════════════════════════════════════════════════════
#  Schema export
#  Writes a language-agnostic schema.json so non-Python tools
#  (project-cli file-based mode, external CLIs, monitoring
#  scripts) can discover all configurable keys without
#  importing the Python module.
# ══════════════════════════════════════════════════════════════

def export_schema(path: str = "lldp_schema.json") -> None:
    """
    Write a JSON file describing all configurable keys.

    Format:
    {
      "module":  "lldp",
      "version": "1.0.21",
      "keys": {
        "TTL": {
          "type":        "int",
          "description": "TTL advertised in frames (seconds)",
          "default":     120,
          "min":         10,
          "max":         65535,
          "mandatory":   true,
          "group":       "Timing"
        },
        ...
      }
    }

    Called automatically at daemon startup (see main.py).
    Non-Python tools read this file to learn the schema.
    """
    from . import config_manager
    from .__version__ import VERSION
    from ._config_groups import CONFIG_GROUPS

    keys = {}
    for group, group_keys in CONFIG_GROUPS.items():
        for k in group_keys:
            if k not in config_manager.SCHEMA:
                continue
            entry = config_manager.SCHEMA[k]
            typ   = entry[0].__name__
            desc  = entry[1]
            lo    = entry[2] if len(entry) > 2 else None
            hi    = entry[3] if len(entry) > 3 else None
            keys[k] = {
                "type":        typ,
                "description": desc,
                "default":     config_manager._read_defaults().get(k),
                "min":         lo,
                "max":         hi,
                "mandatory":   k in _MANDATORY_KEYS,
                "group":       group,
            }

    schema = {
        "module":  "lldp",
        "version": VERSION,
        "keys":    keys,
    }

    with open(path, "w") as f:
        json.dump(schema, f, indent=2)

    log.info("[startup] schema exported to %s (%d keys)", path, len(keys))


# Keys that must never be deleted/reset to None
_MANDATORY_KEYS = {
    "SEND_INTERVAL",
    "TTL",
    "WATCH_INTERVAL",
    "MAX_NEIGHBORS_PER_INTERFACE",
}
