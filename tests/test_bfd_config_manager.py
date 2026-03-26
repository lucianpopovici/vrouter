"""Tests for bfd/config_manager.py — BFDConfigManager."""

import json
import pytest
from bfd.config_manager import BFDConfigManager
from bfd.config import DEFAULTS


@pytest.fixture
def manager(tmp_path):
    return BFDConfigManager(path=str(tmp_path / "bfd_runtime.json"))


class TestBFDConfigManagerDefaults:
    def test_all_defaults_present(self, manager):
        cfg = manager.get()
        for k in DEFAULTS:
            assert k in cfg

    def test_defaults_match(self, manager):
        for k, v in DEFAULTS.items():
            assert manager.get(k) == v


class TestBFDConfigManagerGet:
    def test_get_single_key(self, manager):
        assert manager.get("DETECT_MULT") == DEFAULTS["DETECT_MULT"]

    def test_get_case_insensitive(self, manager):
        assert manager.get("detect_mult") == DEFAULTS["DETECT_MULT"]

    def test_get_unknown_key_raises(self, manager):
        with pytest.raises(KeyError):
            manager.get("NONEXISTENT")


class TestBFDConfigManagerSet:
    def test_set_valid_key(self, manager):
        result = manager.set("DETECT_MULT", 5)
        assert result["ok"] is True
        assert result["value"] == 5
        assert manager.get("DETECT_MULT") == 5

    def test_set_coerces_type(self, manager):
        result = manager.set("DETECT_MULT", "7")
        assert result["ok"] is True
        assert isinstance(result["value"], int)

    def test_set_invalid_value(self, manager):
        result = manager.set("DETECT_MULT", 999)
        assert result["ok"] is False
        assert "error" in result

    def test_set_unknown_key(self, manager):
        result = manager.set("BOGUS_KEY", 42)
        assert result["ok"] is False

    def test_set_restart_required_flag(self, manager):
        result = manager.set("MAX_SESSIONS", 10)
        assert result["ok"] is True
        assert result["restart_required"] is True

    def test_set_no_restart_required(self, manager):
        result = manager.set("DETECT_MULT", 5)
        assert result["restart_required"] is False

    def test_set_bool_key(self, manager):
        result = manager.set("ECHO_ENABLED", "true")
        assert result["ok"] is True
        assert result["value"] is True


class TestBFDConfigManagerReset:
    def test_reset_single_key(self, manager):
        manager.set("DETECT_MULT", 10)
        result = manager.reset("DETECT_MULT")
        assert result["ok"] is True
        assert manager.get("DETECT_MULT") == DEFAULTS["DETECT_MULT"]

    def test_reset_all_keys(self, manager):
        manager.set("DETECT_MULT", 10)
        manager.set("MAX_SESSIONS", 10)
        result = manager.reset()
        assert result["ok"] is True
        assert set(result["reset"]) == set(DEFAULTS.keys())
        assert manager.get("DETECT_MULT") == DEFAULTS["DETECT_MULT"]

    def test_reset_unknown_key(self, manager):
        result = manager.reset("NONEXISTENT")
        assert result["ok"] is False

    def test_reset_case_insensitive(self, manager):
        manager.set("DETECT_MULT", 10)
        result = manager.reset("detect_mult")
        assert result["ok"] is True
        assert manager.get("DETECT_MULT") == DEFAULTS["DETECT_MULT"]


class TestBFDConfigManagerPersistence:
    def test_saves_to_file(self, tmp_path):
        path = str(tmp_path / "cfg.json")
        mgr = BFDConfigManager(path=path)
        mgr.set("DETECT_MULT", 7)
        with open(path) as f:
            saved = json.load(f)
        assert saved["DETECT_MULT"] == 7

    def test_loads_from_existing_file(self, tmp_path):
        path = str(tmp_path / "cfg.json")
        with open(path, "w") as f:
            json.dump({"DETECT_MULT": 9}, f)
        mgr = BFDConfigManager(path=path)
        assert mgr.get("DETECT_MULT") == 9

    def test_ignores_invalid_values_in_file(self, tmp_path):
        path = str(tmp_path / "cfg.json")
        with open(path, "w") as f:
            json.dump({"DETECT_MULT": 9999}, f)  # out of range
        mgr = BFDConfigManager(path=path)
        # Falls back to default when stored value is invalid
        assert mgr.get("DETECT_MULT") == DEFAULTS["DETECT_MULT"]

    def test_ignores_unknown_keys_in_file(self, tmp_path):
        path = str(tmp_path / "cfg.json")
        with open(path, "w") as f:
            json.dump({"UNKNOWN_KEY": 42, "DETECT_MULT": 4}, f)
        mgr = BFDConfigManager(path=path)
        assert mgr.get("DETECT_MULT") == 4

    def test_handles_corrupt_file(self, tmp_path):
        path = str(tmp_path / "cfg.json")
        with open(path, "w") as f:
            f.write("not valid json{{{")
        mgr = BFDConfigManager(path=path)  # should not raise
        assert mgr.get("DETECT_MULT") == DEFAULTS["DETECT_MULT"]


class TestBFDConfigManagerAsBFDConfig:
    def test_returns_bfd_config(self, manager):
        from bfd.config import BFDConfig
        manager.set("DETECT_MULT", 6)
        cfg = manager.as_bfd_config()
        assert isinstance(cfg, BFDConfig)
        assert cfg.detect_mult == 6
