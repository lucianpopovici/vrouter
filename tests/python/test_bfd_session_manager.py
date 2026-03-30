"""Tests for bfd/session_manager.py — BFDSessionManager."""

import json
import pytest
from unittest.mock import MagicMock, patch, call
from bfd.session_manager import BFDSessionManager
from bfd.config import BFDConfig


def make_manager(tmp_path, **kwargs) -> BFDSessionManager:
    cfg = BFDConfig()
    sessions_file = str(tmp_path / "sessions.json")
    return BFDSessionManager(cfg=cfg, sessions_file=sessions_file, **kwargs)


@pytest.fixture
def manager(tmp_path):
    return make_manager(tmp_path)


# We patch BFDSession to avoid real sockets / threads
@pytest.fixture(autouse=True)
def mock_session():
    with patch("bfd.session_manager.BFDSession") as MockSession:
        instance = MagicMock()
        instance.local_disc = 0xABCD1234
        instance.local_ip = "0.0.0.0"
        instance.desired_min_tx_us = 300000
        instance.required_min_rx_us = 300000
        instance.detect_mult = 3
        MockSession.return_value = instance
        yield MockSession


class TestAdd:
    def test_add_session(self, manager, mock_session):
        result = manager.add("10.0.0.1")
        assert result["ok"] is True
        assert result["peer_ip"] == "10.0.0.1"
        assert result["local_disc"] == mock_session.return_value.local_disc
        mock_session.return_value.start.assert_called_once()

    def test_add_duplicate(self, manager, mock_session):
        manager.add("10.0.0.1")
        result = manager.add("10.0.0.1")
        assert result["ok"] is False
        assert "already exists" in result["error"]

    def test_add_respects_max_sessions(self, tmp_path, mock_session):
        cfg = BFDConfig(max_sessions=2)
        mgr = BFDSessionManager(
            cfg=cfg, sessions_file=str(tmp_path / "s.json")
        )
        mgr.add("10.0.0.1")
        mgr.add("10.0.0.2")
        result = mgr.add("10.0.0.3")
        assert result["ok"] is False
        assert "Max sessions" in result["error"]

    def test_add_with_custom_timers(self, manager, mock_session):
        result = manager.add("10.0.0.1", desired_min_tx_us=100000, detect_mult=5)
        assert result["ok"] is True
        _, kwargs = mock_session.call_args
        assert kwargs["desired_min_tx_us"] == 100000
        assert kwargs["detect_mult"] == 5

    def test_add_uses_config_defaults_when_no_override(self, manager, mock_session):
        result = manager.add("10.0.0.1")
        assert result["ok"] is True
        _, kwargs = mock_session.call_args
        assert kwargs["desired_min_tx_us"] == 300000  # BFDConfig default


class TestRemove:
    def test_remove_existing(self, manager, mock_session):
        manager.add("10.0.0.1")
        result = manager.remove("10.0.0.1")
        assert result["ok"] is True
        mock_session.return_value.stop.assert_called_once_with(admin_down=True)

    def test_remove_nonexistent(self, manager):
        result = manager.remove("10.0.0.99")
        assert result["ok"] is False
        assert "No session" in result["error"]

    def test_remove_decrements_count(self, manager, mock_session):
        manager.add("10.0.0.1")
        assert manager.count() == 1
        manager.remove("10.0.0.1")
        assert manager.count() == 0


class TestGet:
    def test_get_existing(self, manager, mock_session):
        manager.add("10.0.0.1")
        sess = manager.get("10.0.0.1")
        assert sess is not None

    def test_get_nonexistent(self, manager):
        assert manager.get("10.0.0.99") is None


class TestCount:
    def test_count_empty(self, manager):
        assert manager.count() == 0

    def test_count_after_add(self, manager, mock_session):
        manager.add("10.0.0.1")
        manager.add("10.0.0.2")
        assert manager.count() == 2


class TestAllInfo:
    def test_all_info_empty(self, manager):
        assert manager.all_info() == []

    def test_all_info_calls_session_info(self, manager, mock_session):
        manager.add("10.0.0.1")
        manager.all_info()
        mock_session.return_value.info.assert_called()


class TestPersistence:
    def test_persist_creates_file(self, tmp_path, mock_session):
        path = str(tmp_path / "sessions.json")
        mgr = BFDSessionManager(cfg=BFDConfig(), sessions_file=path)
        mgr.add("10.0.0.1")
        with open(path) as f:
            saved = json.load(f)
        assert "10.0.0.1" in saved

    def test_restore_recreates_sessions(self, tmp_path, mock_session):
        path = str(tmp_path / "sessions.json")
        # Write a sessions file manually
        with open(path, "w") as f:
            json.dump({
                "10.0.0.5": {
                    "local_ip": "0.0.0.0",
                    "desired_min_tx_us": 300000,
                    "required_min_rx_us": 300000,
                    "detect_mult": 3,
                }
            }, f)
        mgr = BFDSessionManager(cfg=BFDConfig(), sessions_file=path)
        mgr.restore()
        assert mgr.count() == 1
        assert mgr.get("10.0.0.5") is not None


class TestStopAll:
    def test_stop_all(self, manager, mock_session):
        manager.add("10.0.0.1")
        manager.add("10.0.0.2")
        manager.stop_all()
        assert manager.count() == 0


class TestDiscriminatorIndex:
    def test_by_disc_populated_on_add(self, manager, mock_session):
        manager.add("10.0.0.1")
        disc = mock_session.return_value.local_disc
        assert manager.get_by_disc(disc) is not None

    def test_by_disc_removed_on_remove(self, manager, mock_session):
        manager.add("10.0.0.1")
        disc = mock_session.return_value.local_disc
        manager.remove("10.0.0.1")
        assert manager.get_by_disc(disc) is None

    def test_get_by_disc_returns_none_for_unknown(self, manager):
        assert manager.get_by_disc(0xDEAD1234) is None

    def test_disc_collision_resolved(self, tmp_path):
        """If two sessions share a discriminator, it should be regenerated."""
        import random as _random

        with patch("bfd.session_manager.BFDSession") as MockSession:
            # First session gets disc 0x1111
            first  = MagicMock()
            first.local_disc  = 0x1111
            first.local_ip    = "0.0.0.0"
            first.desired_min_tx_us  = 300000
            first.required_min_rx_us = 300000
            first.detect_mult = 3

            # Second session initially gets the same disc, then a unique one
            second = MagicMock()
            second.local_disc = 0x1111   # collision
            second.local_ip   = "0.0.0.0"
            second.desired_min_tx_us  = 300000
            second.required_min_rx_us = 300000
            second.detect_mult = 3

            MockSession.side_effect = [first, second]

            # Patch random.randint so the collision-resolution gives 0x2222
            with patch("bfd.session_manager.random.randint", return_value=0x2222):
                mgr = BFDSessionManager(
                    cfg=BFDConfig(),
                    sessions_file=str(tmp_path / "s.json"),
                )
                mgr.add("10.0.0.1")
                mgr.add("10.0.0.2")

            # second.local_disc was reassigned to 0x2222 by the manager
            assert second.local_disc == 0x2222
            assert mgr.get_by_disc(0x1111) is first
            assert mgr.get_by_disc(0x2222) is second


class TestStartCalledWithRxFalse:
    def test_start_called_with_rx_false_when_shared_rx_running(self, tmp_path, mock_session):
        """When the shared RX thread is active, sessions are started without per-session RX."""
        mgr = BFDSessionManager(
            cfg=BFDConfig(),
            sessions_file=str(tmp_path / "s.json"),
        )
        # Simulate shared RX already running
        fake_thread = MagicMock()
        fake_thread.is_alive.return_value = True
        mgr._rx_thread = fake_thread

        mgr.add("10.0.0.1")
        mock_session.return_value.start.assert_called_once_with(rx=False)

    def test_start_called_with_rx_true_when_no_shared_rx(self, manager, mock_session):
        """When no shared RX thread exists, sessions manage their own RX socket."""
        manager.add("10.0.0.1")
        mock_session.return_value.start.assert_called_once_with(rx=True)
