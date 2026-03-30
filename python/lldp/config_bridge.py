# lldp/config_bridge.py
# ─────────────────────────────────────────────────────────────
# Bridges our config_manager to any external configuration system.
#
# Supports four provider types out of the box:
#   EnvProvider    — environment variables  (LLDP_TTL=60)
#   DictProvider   — Python dict / object   (app.settings["lldp"])
#   FileProvider   — JSON / YAML / TOML / INI file
#   RemoteProvider — etcd / Consul / Redis via a user callable
#
# Core class: ConfigBridge
#   bridge.load(provider)      — pull values from provider → config_manager
#   bridge.push(provider)      — push current config state → provider
#   bridge.watch(provider, N)  — poll provider every N seconds for changes
#   bridge.on_change(cb)       — register callback fired on any config change
#   bridge.bind(provider, N)   — load + watch + on_change in one call
#
# Quick-start:
#
#   from lldp.config_bridge import ConfigBridge, EnvProvider, DictProvider
#
#   bridge = ConfigBridge()
#
#   # 1. Load from environment variables
#   bridge.load(EnvProvider())
#
#   # 2. Load from your app's config dict
#   bridge.load(DictProvider(app.config, prefix="lldp"))
#
#   # 3. React when outer config changes
#   bridge.on_change(lambda key, old, new: print(f"LLDP {key}: {old}→{new}"))
#
#   # 4. Two-way live binding: pull changes from outer config every 10s
#   #    and push LLDP changes back to it
#   bridge.bind(DictProvider(app.config, prefix="lldp"), interval=10)
#
# ─────────────────────────────────────────────────────────────

from __future__ import annotations

import configparser
import json
import logging
import os
import threading
import time
from typing import Any, Callable, Iterator

log = logging.getLogger("lldp.bridge")


# ══════════════════════════════════════════════════════════════
#  Provider Protocol
#  Any object implementing read() / write() qualifies.
# ══════════════════════════════════════════════════════════════

class ConfigProvider:
    """
    Base class / informal protocol for config providers.

    Subclass and implement read() and optionally write().

    read()  → dict[str, Any]
        Return a flat dict of {LLDP_KEY: value} pairs.
        Keys must match config_manager.SCHEMA (case-insensitive).
        Only keys present in the returned dict are applied —
        missing keys are left at their current values.

    write(snapshot: dict[str, Any]) → None
        Receive the full current LLDP config snapshot and
        persist it back to the external system.
        Implement this only if you need two-way sync.
    """

    def read(self) -> dict[str, Any]:
        raise NotImplementedError

    def write(self, snapshot: dict[str, Any]) -> None:
        pass   # no-op by default — override for two-way sync


# ══════════════════════════════════════════════════════════════
#  Built-in providers
# ══════════════════════════════════════════════════════════════

class EnvProvider(ConfigProvider):
    """
    Reads LLDP config from environment variables.

    Mapping:   LLDP_<KEY>=<value>   →   config_manager.set(KEY, value)

    Examples:
        LLDP_TTL=60
        LLDP_SEND_INTERVAL=15
        LLDP_TLV_DOT3_POE_ENABLED=true
        LLDP_MAX_NEIGHBORS_PER_INTERFACE=16

    Args:
        prefix: env var prefix (default "LLDP_")

    Does NOT support write() — env vars are read-only at runtime.
    """

    def __init__(self, prefix: str = "LLDP_"):
        self._prefix = prefix.upper()

    def read(self) -> dict[str, Any]:
        result = {}
        for k, v in os.environ.items():
            if k.upper().startswith(self._prefix):
                key = k[len(self._prefix):].upper()
                result[key] = v
        return result

    def __repr__(self):
        return f"EnvProvider(prefix={self._prefix!r})"


class DictProvider(ConfigProvider):
    """
    Bridges a Python dict or any object with __getitem__/__setitem__.

    Suitable for:
      - Django settings dict
      - Flask app.config
      - Custom config objects
      - Pydantic / dataclass models (via adapter)

    Args:
        source  : dict or dict-like object
        prefix  : key prefix in the source dict (default "lldp_")
                  e.g. prefix="lldp_" → reads source["lldp_ttl"]
        strip_prefix: remove prefix when mapping to LLDP key (default True)

    Two-way: write() updates the source dict in-place.

    Examples:
        # Django settings
        bridge.load(DictProvider(settings.__dict__, prefix="LLDP_"))

        # Flask
        bridge.bind(DictProvider(app.config, prefix="LLDP_"))

        # Plain dict
        cfg = {"lldp_ttl": 60, "lldp_send_interval": 15}
        bridge.load(DictProvider(cfg, prefix="lldp_"))
    """

    def __init__(self, source: dict, prefix: str = "lldp_",
                 strip_prefix: bool = True):
        self._source       = source
        self._prefix       = prefix.lower()
        self._strip_prefix = strip_prefix

    def read(self) -> dict[str, Any]:
        result = {}
        for k, v in self._source.items():
            lk = str(k).lower()
            if lk.startswith(self._prefix):
                key = lk[len(self._prefix):].upper() if self._strip_prefix \
                      else lk.upper()
                result[key] = v
        return result

    def write(self, snapshot: dict[str, Any]) -> None:
        for key, value in snapshot.items():
            ext_key = self._prefix + key.lower()
            # Only write keys that already exist in source, or always write
            self._source[ext_key] = value

    def __repr__(self):
        return f"DictProvider(prefix={self._prefix!r})"


class FileProvider(ConfigProvider):
    """
    Reads and writes LLDP config from a file.

    Supports: JSON, YAML (requires pyyaml), TOML (requires tomllib/tomli),
              INI/ConfigParser (section = [lldp] or configurable).

    Args:
        path    : path to the config file
        fmt     : "json" | "yaml" | "toml" | "ini" | "auto" (default "auto")
        section : section name for INI files (default "lldp")
        prefix  : key prefix inside the file (default "", no prefix)

    Two-way: write() updates the file in place.

    Examples:
        bridge.load(FileProvider("/etc/myapp/config.json"))
        bridge.bind(FileProvider("/etc/myapp/config.yaml"), interval=30)

    JSON example (config.json):
        {
          "lldp": {
            "TTL": 60,
            "SEND_INTERVAL": 15,
            "TLV_DOT3_POE_ENABLED": false
          }
        }
        → FileProvider("config.json", section="lldp")

    Flat JSON (no nesting):
        {"TTL": 60, "SEND_INTERVAL": 15}
        → FileProvider("config.json", section=None)

    INI example (config.ini):
        [lldp]
        TTL = 60
        SEND_INTERVAL = 15
    """

    def __init__(self, path: str, fmt: str = "auto",
                 section: str | None = "lldp",
                 prefix: str = ""):
        self._path    = path
        self._fmt     = fmt if fmt != "auto" else self._detect_fmt(path)
        self._section = section
        self._prefix  = prefix.upper()

    @staticmethod
    def _detect_fmt(path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        return {".json": "json", ".yaml": "yaml", ".yml": "yaml",
                ".toml": "toml", ".ini": "ini", ".cfg": "ini",
                }.get(ext, "json")

    def _load_raw(self) -> dict:
        """Load file into a raw dict."""
        if not os.path.exists(self._path):
            return {}
        fmt = self._fmt

        if fmt == "json":
            with open(self._path) as f:
                data = json.load(f)
            return data.get(self._section, data) if self._section else data

        if fmt == "yaml":
            try:
                import yaml
                with open(self._path) as f:
                    data = yaml.safe_load(f) or {}
                return data.get(self._section, data) if self._section else data
            except ImportError:
                raise ImportError("pyyaml is required for YAML support: pip install pyyaml")

        if fmt == "toml":
            try:
                try:
                    import tomllib
                except ImportError:
                    import tomli as tomllib  # type: ignore
                with open(self._path, "rb") as f:
                    data = tomllib.load(f)
                return data.get(self._section, data) if self._section else data
            except ImportError:
                raise ImportError(
                    "tomllib (Python 3.11+) or tomli is required: pip install tomli")

        if fmt == "ini":
            cp = configparser.ConfigParser()
            cp.read(self._path)
            section = self._section or "lldp"
            if cp.has_section(section):
                return dict(cp[section])
            return {}

        raise ValueError(f"Unknown format '{fmt}'")

    def read(self) -> dict[str, Any]:
        raw = self._load_raw()
        result = {}
        for k, v in raw.items():
            uk = str(k).upper()
            if self._prefix:
                if uk.startswith(self._prefix):
                    uk = uk[len(self._prefix):]
                else:
                    continue
            result[uk] = v
        return result

    def write(self, snapshot: dict[str, Any]) -> None:
        fmt = self._fmt

        if fmt == "json":
            # Merge snapshot into existing file
            existing = {}
            if os.path.exists(self._path):
                with open(self._path) as f:
                    existing = json.load(f)
            payload = {(self._prefix + k).lower(): v
                       for k, v in snapshot.items()}
            if self._section:
                existing.setdefault(self._section, {}).update(payload)
            else:
                existing.update(payload)
            with open(self._path, "w") as f:
                json.dump(existing, f, indent=2)
            return

        if fmt == "ini":
            cp = configparser.ConfigParser()
            if os.path.exists(self._path):
                cp.read(self._path)
            section = self._section or "lldp"
            if not cp.has_section(section):
                cp.add_section(section)
            for k, v in snapshot.items():
                cp[section][(self._prefix + k).lower()] = str(v)
            with open(self._path, "w") as f:
                cp.write(f)
            return

        # YAML / TOML write — load, merge, write back
        if fmt in ("yaml", "toml"):
            log.warning("FileProvider: in-place write for %s is not yet "
                        "implemented — read-only mode", fmt.upper())

    def __repr__(self):
        return f"FileProvider({self._path!r}, fmt={self._fmt!r})"


class RemoteProvider(ConfigProvider):
    """
    Bridges a remote/dynamic config store via user-supplied callables.

    Suitable for: etcd, Consul, Redis, database, Vault, any HTTP API.

    Args:
        reader  : callable() → dict[str, Any]
                  Called by bridge.load() / bridge.watch().
        writer  : callable(snapshot: dict) → None   (optional)
                  Called by bridge.push().

    Examples:
        # Redis
        import redis
        r = redis.Redis()
        provider = RemoteProvider(
            reader  = lambda: {k.decode(): v.decode()
                               for k, v in r.hgetall("lldp:config").items()},
            writer  = lambda snap: r.hset("lldp:config", mapping=snap),
        )

        # etcd (etcd3 library)
        provider = RemoteProvider(
            reader = lambda: {k: v for v, meta in
                              [etcd.get(f"/lldp/{k}")
                               for k in config_manager.SCHEMA]
                              if v is not None},
        )

        # Consul
        provider = RemoteProvider(
            reader = lambda: {item["Key"].split("/")[-1].upper(): item["Value"].decode()
                              for item in consul.kv.get("lldp/", recurse=True)[1] or []},
        )
    """

    def __init__(self, reader: Callable[[], dict[str, Any]],
                 writer: Callable[[dict[str, Any]], None] | None = None):
        self._reader = reader
        self._writer = writer

    def read(self) -> dict[str, Any]:
        return self._reader()

    def write(self, snapshot: dict[str, Any]) -> None:
        if self._writer:
            self._writer(snapshot)

    def __repr__(self):
        return f"RemoteProvider(reader={self._reader!r})"


class CustomProvider(ConfigProvider):
    """
    Minimal provider for one-liners and tests.

    Examples:
        # Read from anywhere, write nowhere
        bridge.load(CustomProvider(lambda: {"TTL": 60}))

        # Read from Pydantic model
        bridge.load(CustomProvider(
            lambda: settings.lldp.dict()
        ))
    """

    def __init__(self, reader: Callable[[], dict[str, Any]],
                 writer: Callable[[dict[str, Any]], None] | None = None):
        self._reader = reader
        self._writer = writer

    def read(self) -> dict[str, Any]:
        return self._reader()

    def write(self, snapshot: dict[str, Any]) -> None:
        if self._writer:
            self._writer(snapshot)


# ══════════════════════════════════════════════════════════════
#  ConfigBridge
# ══════════════════════════════════════════════════════════════

class ConfigBridge:
    """
    Bidirectional bridge between config_manager and external providers.

    Lifecycle methods:
        load(provider)         — one-shot pull from provider
        push(provider)         — one-shot push to provider
        watch(provider, N)     — poll provider every N seconds (background thread)
        on_change(callback)    — register change listener
        bind(provider, N)      — load + watch + push (convenience)
        stop()                 — stop all watch threads
        snapshot()             — return current LLDP config as plain dict

    Change callbacks receive (key: str, old_value, new_value).
    """

    def __init__(self):
        self._lock        = threading.Lock()
        self._callbacks   : list[Callable[[str, Any, Any], None]] = []
        self._watch_threads: list[threading.Thread] = []
        self._stop_event  = threading.Event()

    # ── Read side ──────────────────────────────────────────────

    def load(self, provider: ConfigProvider) -> dict[str, str]:
        """
        Pull values from provider and apply to config_manager.
        Returns a dict of {key: "applied" | "skipped: <reason>"}.
        """
        from . import config_manager

        try:
            raw = provider.read()
        except Exception as e:
            log.error("ConfigBridge.load() provider error (%s): %s", provider, e)
            return {}

        results = {}
        for key, value in raw.items():
            key = key.upper()
            if key not in config_manager.SCHEMA:
                results[key] = f"skipped: unknown key"
                continue
            try:
                old = config_manager.get(key)
                config_manager.set(key, value)
                new = config_manager.get(key)
                if old != new:
                    self._fire(key, old, new)
                results[key] = "applied"
                log.debug("ConfigBridge: %s = %r (from %s)", key, new, provider)
            except Exception as e:
                results[key] = f"skipped: {e}"
                log.warning("ConfigBridge: could not apply %s=%r: %s", key, value, e)

        applied = sum(1 for v in results.values() if v == "applied")
        log.info("ConfigBridge.load(%s): %d applied, %d skipped",
                 provider, applied, len(results) - applied)
        return results

    # ── Write side ─────────────────────────────────────────────

    def push(self, provider: ConfigProvider) -> None:
        """
        Push current LLDP config snapshot to provider.
        Provider must implement write().
        """
        try:
            provider.write(self.snapshot())
            log.info("ConfigBridge.push(%s): snapshot written", provider)
        except Exception as e:
            log.error("ConfigBridge.push() error (%s): %s", provider, e)

    # ── Watch (polling) ────────────────────────────────────────

    def watch(self, provider: ConfigProvider, interval: float = 10.0) -> None:
        """
        Poll provider every *interval* seconds in a background thread.
        Applies any changed values to config_manager.
        Stops when stop() is called.
        """
        def _loop():
            log.info("ConfigBridge: watching %s every %ss", provider, interval)
            last_snapshot: dict = {}
            while not self._stop_event.is_set():
                try:
                    raw = provider.read()
                    # Only apply keys that actually changed
                    changed = {k: v for k, v in raw.items()
                               if last_snapshot.get(k) != v}
                    if changed:
                        self.load(
                            CustomProvider(lambda c=changed: c))
                    last_snapshot = raw
                except Exception as e:
                    log.warning("ConfigBridge.watch(%s) error: %s", provider, e)
                self._stop_event.wait(interval)

        t = threading.Thread(target=_loop, daemon=True,
                             name=f"bridge-watch-{provider}")
        t.start()
        with self._lock:
            self._watch_threads.append(t)

    # ── Change callbacks ───────────────────────────────────────

    def on_change(self,
                  callback: Callable[[str, Any, Any], None]) -> None:
        """
        Register a callback fired whenever a config value changes.

        Callback signature: (key: str, old_value, new_value) -> None

        Example:
            def my_handler(key, old, new):
                print(f"LLDP config changed: {key} {old!r} → {new!r}")

            bridge.on_change(my_handler)
        """
        with self._lock:
            self._callbacks.append(callback)

    def _fire(self, key: str, old: Any, new: Any) -> None:
        with self._lock:
            cbs = list(self._callbacks)
        for cb in cbs:
            try:
                cb(key, old, new)
            except Exception as e:
                log.warning("ConfigBridge callback error: %s", e)

    # ── Convenience ────────────────────────────────────────────

    def bind(self, provider: ConfigProvider,
             interval: float = 10.0,
             push_on_change: bool = False) -> "ConfigBridge":
        """
        All-in-one: load now + watch for external changes + optionally push back.

        Args:
            provider       : config source/sink
            interval       : polling interval in seconds (default 10)
            push_on_change : if True, push to provider whenever LLDP config
                             changes (two-way sync)

        Returns self for chaining.

        Example:
            bridge.bind(DictProvider(app.config), interval=5, push_on_change=True)
        """
        self.load(provider)
        self.watch(provider, interval)
        if push_on_change:
            self.on_change(lambda k, o, n: self.push(provider))
        return self

    def stop(self) -> None:
        """Stop all watch threads."""
        self._stop_event.set()
        log.info("ConfigBridge: stopped all watchers")

    def snapshot(self) -> dict[str, Any]:
        """
        Return the full current LLDP scalar config as a plain dict.
        Suitable for serialization or pushing to external systems.
        """
        from . import config_manager
        return {key: config_manager.get(key)
                for key in config_manager.SCHEMA}

    def diff(self, provider: ConfigProvider) -> dict[str, tuple]:
        """
        Compare provider values against current config.
        Returns {key: (current_value, provider_value)} for differing keys.

        Useful for dry-run / audit before applying.

        Example:
            for key, (current, external) in bridge.diff(provider).items():
                print(f"  {key}: current={current!r}  external={external!r}")
        """
        from . import config_manager
        raw  = provider.read()
        diffs = {}
        for key, ext_val in raw.items():
            key = key.upper()
            if key not in config_manager.SCHEMA:
                continue
            try:
                cur = config_manager.get(key)
                # Coerce ext_val to same type for fair comparison
                coerced = config_manager._coerce(key, ext_val)
                if cur != coerced:
                    diffs[key] = (cur, coerced)
            except Exception:
                pass
        return diffs


# ── Module-level singleton ─────────────────────────────────────
# Convenience: import and use directly without instantiation.
#
#   from lldp.config_bridge import bridge, EnvProvider
#   bridge.load(EnvProvider())

bridge = ConfigBridge()
