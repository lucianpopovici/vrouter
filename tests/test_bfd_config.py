"""Tests for bfd/config.py — validate(), coerce(), and BFDConfig."""

import pytest
from bfd.config import validate, coerce, BFDConfig, DEFAULTS


# ── validate() ────────────────────────────────────────────────────────────────

class TestValidateTimers:
    @pytest.mark.parametrize("key", ["DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US"])
    def test_valid_value(self, key):
        ok, err = validate(key, 300000)
        assert ok and err == ""

    @pytest.mark.parametrize("key", ["DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US"])
    def test_minimum_boundary(self, key):
        ok, _ = validate(key, 10000)
        assert ok

    @pytest.mark.parametrize("key", ["DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US"])
    def test_maximum_boundary(self, key):
        ok, _ = validate(key, 60000000)
        assert ok

    @pytest.mark.parametrize("key", ["DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US"])
    def test_below_minimum(self, key):
        ok, err = validate(key, 9999)
        assert not ok and "10000" in err

    @pytest.mark.parametrize("key", ["DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US"])
    def test_above_maximum(self, key):
        ok, err = validate(key, 60000001)
        assert not ok and "60000000" in err

    @pytest.mark.parametrize("key", ["DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US"])
    def test_non_integer(self, key):
        ok, err = validate(key, "fast")
        assert not ok and "integer" in err

    @pytest.mark.parametrize("key", ["DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US"])
    def test_string_integer_accepted(self, key):
        ok, _ = validate(key, "300000")
        assert ok


class TestValidateDetectMult:
    def test_valid(self):
        ok, _ = validate("DETECT_MULT", 3)
        assert ok

    def test_minimum(self):
        ok, _ = validate("DETECT_MULT", 1)
        assert ok

    def test_maximum(self):
        ok, _ = validate("DETECT_MULT", 255)
        assert ok

    def test_zero(self):
        ok, _ = validate("DETECT_MULT", 0)
        assert not ok

    def test_too_large(self):
        ok, _ = validate("DETECT_MULT", 256)
        assert not ok

    def test_non_integer(self):
        ok, _ = validate("DETECT_MULT", "abc")
        assert not ok


class TestValidateMaxSessions:
    def test_valid(self):
        ok, _ = validate("MAX_SESSIONS", 64)
        assert ok

    def test_minimum(self):
        ok, _ = validate("MAX_SESSIONS", 1)
        assert ok

    def test_maximum(self):
        ok, _ = validate("MAX_SESSIONS", 1024)
        assert ok

    def test_zero(self):
        ok, _ = validate("MAX_SESSIONS", 0)
        assert not ok

    def test_too_large(self):
        ok, _ = validate("MAX_SESSIONS", 1025)
        assert not ok


class TestValidateAuthType:
    @pytest.mark.parametrize("v", ["none", "md5", "sha1", "NONE", "MD5", "SHA1"])
    def test_valid(self, v):
        ok, _ = validate("DEFAULT_AUTH_TYPE", v)
        assert ok

    def test_invalid(self):
        ok, err = validate("DEFAULT_AUTH_TYPE", "hmac")
        assert not ok and "md5" in err


class TestValidateBoolKeys:
    @pytest.mark.parametrize("key", ["ECHO_ENABLED", "LOG_STATE_CHANGES"])
    @pytest.mark.parametrize("v", ["true", "false", "1", "0", "True", "False"])
    def test_valid(self, key, v):
        ok, _ = validate(key, v)
        assert ok

    @pytest.mark.parametrize("key", ["ECHO_ENABLED", "LOG_STATE_CHANGES"])
    def test_invalid(self, key):
        ok, _ = validate(key, "yes")
        assert not ok


class TestValidateLogLevel:
    @pytest.mark.parametrize("v", ["DEBUG", "INFO", "WARNING", "ERROR", "debug"])
    def test_valid(self, v):
        ok, _ = validate("LOG_LEVEL", v)
        assert ok

    def test_invalid(self):
        ok, _ = validate("LOG_LEVEL", "TRACE")
        assert not ok


class TestValidateUnknown:
    def test_unknown_key(self):
        ok, err = validate("NONEXISTENT_KEY", 42)
        assert not ok and "Unknown" in err

    def test_case_insensitive_key(self):
        # validate() uppercases the key, so lowercase works
        ok, _ = validate("desired_min_tx_us", 300000)
        assert ok


# ── coerce() ──────────────────────────────────────────────────────────────────

class TestCoerce:
    @pytest.mark.parametrize("key", ["DESIRED_MIN_TX_US", "REQUIRED_MIN_RX_US", "DETECT_MULT", "MAX_SESSIONS"])
    def test_int_keys(self, key):
        assert coerce(key, "42") == 42
        assert isinstance(coerce(key, "42"), int)

    @pytest.mark.parametrize("key", ["ECHO_ENABLED", "LOG_STATE_CHANGES"])
    def test_bool_from_string_true(self, key):
        assert coerce(key, "true") is True
        assert coerce(key, "1") is True

    @pytest.mark.parametrize("key", ["ECHO_ENABLED", "LOG_STATE_CHANGES"])
    def test_bool_from_string_false(self, key):
        assert coerce(key, "false") is False
        assert coerce(key, "0") is False

    @pytest.mark.parametrize("key", ["ECHO_ENABLED", "LOG_STATE_CHANGES"])
    def test_bool_passthrough(self, key):
        assert coerce(key, True) is True
        assert coerce(key, False) is False

    def test_auth_type_lowercased(self):
        assert coerce("DEFAULT_AUTH_TYPE", "MD5") == "md5"

    def test_log_level_uppercased(self):
        assert coerce("LOG_LEVEL", "debug") == "DEBUG"


# ── BFDConfig ─────────────────────────────────────────────────────────────────

class TestBFDConfig:
    def test_defaults(self):
        cfg = BFDConfig()
        assert cfg.desired_min_tx_us == DEFAULTS["DESIRED_MIN_TX_US"]
        assert cfg.required_min_rx_us == DEFAULTS["REQUIRED_MIN_RX_US"]
        assert cfg.detect_mult == DEFAULTS["DETECT_MULT"]
        assert cfg.max_sessions == DEFAULTS["MAX_SESSIONS"]

    def test_from_dict(self):
        d = {"DESIRED_MIN_TX_US": "100000", "DETECT_MULT": "5"}
        cfg = BFDConfig.from_dict(d)
        assert cfg.desired_min_tx_us == 100000
        assert cfg.detect_mult == 5
        # unspecified keys keep defaults
        assert cfg.required_min_rx_us == DEFAULTS["REQUIRED_MIN_RX_US"]

    def test_from_dict_ignores_unknown_keys(self):
        cfg = BFDConfig.from_dict({"UNKNOWN_KEY": 99})
        assert cfg.desired_min_tx_us == DEFAULTS["DESIRED_MIN_TX_US"]

    def test_to_dict_roundtrip(self):
        cfg = BFDConfig(desired_min_tx_us=200000, detect_mult=5)
        d = cfg.to_dict()
        cfg2 = BFDConfig.from_dict(d)
        assert cfg2.desired_min_tx_us == 200000
        assert cfg2.detect_mult == 5
