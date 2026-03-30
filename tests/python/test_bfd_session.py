"""Tests for bfd/session.py — BFDSession state machine.

We exercise the state machine by calling rx_packet() directly,
never starting threads or touching real sockets.
"""

import pytest
from unittest.mock import MagicMock, call
from bfd.session import BFDSession, BFDState
from bfd.packet import BFDPacket


def make_session(**kwargs) -> BFDSession:
    defaults = dict(peer_ip="10.0.0.2", local_ip="0.0.0.0")
    defaults.update(kwargs)
    return BFDSession(**defaults)


def pkt(state: int, your_disc: int = 0, my_disc: int = 1,
        detect_mult: int = 3, desired_tx: int = 300000,
        required_rx: int = 300000) -> BFDPacket:
    return BFDPacket(
        state=state,
        my_discriminator=my_disc,
        your_discriminator=your_disc,
        detect_mult=detect_mult,
        desired_min_tx_us=desired_tx,
        required_min_rx_us=required_rx,
    )


# ── Initial state ─────────────────────────────────────────────────────────────

class TestInitialState:
    def test_starts_in_down(self):
        sess = make_session()
        assert sess.state == BFDState.DOWN

    def test_local_disc_is_nonzero(self):
        sess = make_session()
        assert sess.local_disc != 0

    def test_remote_disc_is_zero(self):
        sess = make_session()
        assert sess.remote_disc == 0

    def test_default_timers(self):
        sess = make_session(desired_min_tx_us=200000, required_min_rx_us=100000)
        assert sess.desired_min_tx_us == 200000
        assert sess.required_min_rx_us == 100000


# ── Negotiated values ─────────────────────────────────────────────────────────

class TestNegotiatedValues:
    def test_negotiated_tx_uses_local_when_larger(self):
        sess = make_session(desired_min_tx_us=500000)
        sess.remote_required_min_rx_us = 100000
        assert sess.negotiated_tx_us == 500000

    def test_negotiated_tx_uses_remote_when_larger(self):
        sess = make_session(desired_min_tx_us=100000)
        sess.remote_required_min_rx_us = 500000
        assert sess.negotiated_tx_us == 500000

    def test_detect_time(self):
        # detect_time = remote_detect_mult × max(remote_desired_min_tx_us, required_min_rx_us)
        sess = make_session(required_min_rx_us=300000)
        sess.remote_desired_min_tx_us = 300000
        sess.remote_detect_mult = 3
        assert sess.detect_time_us == 900000

    def test_detect_time_uses_larger_of_remote_tx_and_local_rx(self):
        sess = make_session(required_min_rx_us=500000)
        sess.remote_desired_min_tx_us = 100000  # remote TX slower than our RX floor
        sess.remote_detect_mult = 3
        # max(100000, 500000) * 3 = 1500000
        assert sess.detect_time_us == 1500000


# ── State machine transitions ─────────────────────────────────────────────────

class TestStateMachineTransitions:
    def test_down_receives_remote_down_goes_to_init(self):
        sess = make_session()
        assert sess.state == BFDState.DOWN
        sess.rx_packet(pkt(state=BFDState.DOWN))
        assert sess.state == BFDState.INIT

    def test_down_receives_remote_init_goes_to_up(self):
        sess = make_session()
        # Remote knows our disc (they received our DOWN), so your_disc is set
        sess.rx_packet(pkt(state=BFDState.INIT, your_disc=sess.local_disc))
        assert sess.state == BFDState.UP

    def test_init_receives_remote_init_goes_to_up(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.DOWN))  # DOWN → INIT
        assert sess.state == BFDState.INIT
        sess.rx_packet(pkt(state=BFDState.INIT, your_disc=sess.local_disc))
        assert sess.state == BFDState.UP

    def test_init_receives_remote_up_goes_to_up(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.DOWN))  # DOWN → INIT
        sess.rx_packet(pkt(state=BFDState.UP, your_disc=sess.local_disc))
        assert sess.state == BFDState.UP

    def test_up_receives_remote_down_goes_to_down(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.INIT, your_disc=sess.local_disc))  # → UP
        assert sess.state == BFDState.UP
        sess.rx_packet(pkt(state=BFDState.DOWN, your_disc=sess.local_disc))
        assert sess.state == BFDState.DOWN

    def test_up_receives_remote_up_stays_up(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.INIT, your_disc=sess.local_disc))
        assert sess.state == BFDState.UP
        sess.rx_packet(pkt(state=BFDState.UP, your_disc=sess.local_disc))
        assert sess.state == BFDState.UP

    def test_remote_admin_down_forces_down(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.INIT, your_disc=sess.local_disc))  # → UP
        sess.rx_packet(pkt(state=BFDState.ADMIN_DOWN, your_disc=sess.local_disc))
        assert sess.state == BFDState.DOWN

    def test_admin_down_ignores_all_packets(self):
        sess = make_session()
        with sess._lock:
            from bfd.session import BFDState as S
            sess._state = S.ADMIN_DOWN
        sess.rx_packet(pkt(state=BFDState.DOWN))
        assert sess.state == BFDState.ADMIN_DOWN

    def test_wrong_discriminator_ignored(self):
        sess = make_session()
        # your_discriminator != 0 and != local_disc → ignored
        wrong_disc = sess.local_disc + 1
        sess.rx_packet(pkt(state=BFDState.DOWN, your_disc=wrong_disc))
        assert sess.state == BFDState.DOWN

    def test_zero_your_discriminator_accepted_when_remote_down(self):
        # RFC 5880 §6.8.6 rule 8: your_disc=0 is valid only when remote is Down/AdminDown
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.DOWN, your_disc=0))
        assert sess.state == BFDState.INIT

    def test_zero_your_discriminator_rejected_when_remote_init(self):
        # RFC 5880 §6.8.6 rule 8: must be discarded if remote state is not Down/AdminDown
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.INIT, your_disc=0))
        assert sess.state == BFDState.DOWN  # packet discarded, no transition

    def test_zero_your_discriminator_rejected_when_remote_up(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.UP, your_disc=0))
        assert sess.state == BFDState.DOWN


# ── Remote state is tracked ───────────────────────────────────────────────────

class TestRemoteStateTracking:
    def test_remote_disc_updated(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.DOWN, my_disc=0xABCD))
        assert sess.remote_disc == 0xABCD

    def test_remote_timers_updated(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.DOWN, desired_tx=500000, required_rx=400000))
        assert sess.remote_desired_min_tx_us == 500000
        assert sess.remote_required_min_rx_us == 400000

    def test_remote_detect_mult_updated(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.DOWN, detect_mult=5))
        assert sess.remote_detect_mult == 5


# ── Poll / Final flag ─────────────────────────────────────────────────────────

class TestPollFinalFlag:
    def test_poll_flag_sets_final(self):
        sess = make_session()
        p = pkt(state=BFDState.DOWN)
        p.poll = True
        sess.rx_packet(p)
        assert sess._final is True


# ── State change callback ─────────────────────────────────────────────────────

class TestStateChangeCallback:
    def test_callback_invoked_on_transition(self):
        cb = MagicMock()
        sess = make_session(on_state_change=cb)
        sess.rx_packet(pkt(state=BFDState.DOWN))
        cb.assert_called_once()
        args = cb.call_args[0]
        assert args[0] is sess
        assert args[1] == BFDState.DOWN   # old state
        assert args[2] == BFDState.INIT   # new state

    def test_callback_not_invoked_when_state_unchanged(self):
        cb = MagicMock()
        sess = make_session(on_state_change=cb)
        sess.rx_packet(pkt(state=BFDState.UP, your_disc=sess.local_disc))   # DOWN → UP
        cb.reset_mock()
        sess.rx_packet(pkt(state=BFDState.UP, your_disc=sess.local_disc))   # UP stays UP
        cb.assert_not_called()

    def test_callback_exception_does_not_propagate(self):
        def bad_cb(*_):
            raise RuntimeError("boom")
        sess = make_session(on_state_change=bad_cb)
        # Should not raise
        sess.rx_packet(pkt(state=BFDState.DOWN))


# ── Snapshot ──────────────────────────────────────────────────────────────────

class TestInfo:
    def test_info_returns_snapshot(self):
        sess = make_session(peer_ip="1.2.3.4", local_ip="5.6.7.8")
        info = sess.info()
        assert info.peer_ip == "1.2.3.4"
        assert info.local_ip == "5.6.7.8"
        assert info.state == "Down"
        assert info.local_disc == sess.local_disc

    def test_info_state_updates_after_transition(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.INIT, your_disc=sess.local_disc))
        info = sess.info()
        assert info.state == "Up"


# ── Mandatory discard rules (RFC 5880 §6.8.6) ────────────────────────────────

class TestMandatoryDiscardRules:
    def test_auth_present_discarded(self):
        # Rule 4: auth_present=True when no auth configured → discard
        sess = make_session()
        p = pkt(state=BFDState.DOWN)
        p.auth_present = True
        sess.rx_packet(p)
        assert sess.state == BFDState.DOWN  # no transition

    def test_multipoint_discarded(self):
        # Rule 6: multipoint bit → discard
        sess = make_session()
        p = pkt(state=BFDState.DOWN)
        p.multipoint = True
        sess.rx_packet(p)
        assert sess.state == BFDState.DOWN

    def test_zero_my_discriminator_discarded(self):
        # Rule 7: my_discriminator=0 → discard
        sess = make_session()
        p = pkt(state=BFDState.DOWN, my_disc=0)
        sess.rx_packet(p)
        assert sess.state == BFDState.DOWN
        assert sess.remote_disc == 0  # not updated

    def test_poll_and_final_both_set_discarded(self):
        # RFC 5880 §6.5: P+F simultaneously set → discard
        sess = make_session()
        p = pkt(state=BFDState.DOWN)
        p.poll  = True
        p.final = True
        sess.rx_packet(p)
        assert sess.state == BFDState.DOWN
        assert sess._final is False  # Final not set because packet was dropped

    def test_discarded_packet_does_not_update_remote_state(self):
        # Confirm that a discarded packet (multipoint) leaves remote state untouched
        sess = make_session()
        p = pkt(state=BFDState.DOWN, my_disc=0xDEAD)
        p.multipoint = True
        sess.rx_packet(p)
        assert sess.remote_disc == 0


# ── Poll Sequence (RFC 5880 §6.5, §6.8.3) ────────────────────────────────────

def _go_up(sess: BFDSession) -> None:
    """Helper: drive a session to UP state without threads."""
    sess.rx_packet(pkt(state=BFDState.INIT, your_disc=sess.local_disc))
    assert sess.state == BFDState.UP


class TestPollSequence:
    def test_update_timers_starts_poll_when_up(self):
        sess = make_session()
        _go_up(sess)
        sess.update_timers(desired_min_tx_us=500_000)
        assert sess._poll is True
        assert sess._poll_active is True

    def test_update_timers_freezes_tx_interval(self):
        sess = make_session(desired_min_tx_us=300_000)
        _go_up(sess)
        frozen = sess.negotiated_tx_us
        sess.update_timers(desired_min_tx_us=500_000)
        assert sess._scheduled_tx_us == frozen

    def test_final_received_completes_poll_sequence(self):
        sess = make_session()
        _go_up(sess)
        sess.update_timers(desired_min_tx_us=500_000)
        # Simulate remote sending a Final packet in response
        final_pkt = pkt(state=BFDState.UP, your_disc=sess.local_disc)
        final_pkt.final = True
        sess.rx_packet(final_pkt)
        assert sess._poll is False
        assert sess._poll_active is False
        assert sess._scheduled_tx_us is None

    def test_desired_min_tx_applies_after_poll_complete(self):
        sess = make_session(desired_min_tx_us=300_000)
        _go_up(sess)
        sess.update_timers(desired_min_tx_us=500_000)
        assert sess.desired_min_tx_us == 500_000  # advertised immediately
        final_pkt = pkt(state=BFDState.UP, your_disc=sess.local_disc)
        final_pkt.final = True
        sess.rx_packet(final_pkt)
        assert sess._scheduled_tx_us is None      # lock released

    def test_update_timers_no_poll_when_not_up(self):
        # Changes apply immediately when Down; no poll needed
        sess = make_session()
        assert sess.state == BFDState.DOWN
        sess.update_timers(desired_min_tx_us=500_000)
        assert sess._poll is False
        assert sess.desired_min_tx_us == 500_000

    def test_update_timers_required_min_rx_applies_immediately(self):
        sess = make_session()
        sess.update_timers(required_min_rx_us=200_000)
        assert sess.required_min_rx_us == 200_000

    def test_update_timers_required_min_rx_triggers_poll_when_up(self):
        sess = make_session()
        _go_up(sess)
        sess.update_timers(required_min_rx_us=200_000)
        assert sess._poll is True
        assert sess.required_min_rx_us == 200_000  # takes effect in packets immediately

    def test_poll_state_cleared_on_transition_to_down(self):
        sess = make_session()
        _go_up(sess)
        sess.update_timers(desired_min_tx_us=500_000)
        assert sess._poll_active is True
        # A DOWN packet from the remote drops us back to DOWN
        sess.rx_packet(pkt(state=BFDState.DOWN, your_disc=sess.local_disc))
        assert sess.state == BFDState.DOWN
        assert sess._poll is False
        assert sess._poll_active is False
        assert sess._scheduled_tx_us is None

    def test_final_without_active_poll_does_not_clear_state(self):
        # A stray Final when we didn't initiate a poll should be a no-op
        sess = make_session()
        _go_up(sess)
        assert sess._poll_active is False
        final_pkt = pkt(state=BFDState.UP, your_disc=sess.local_disc)
        final_pkt.final = True
        sess.rx_packet(final_pkt)
        assert sess._poll_active is False  # unchanged


# ── Demand mode (RFC 5880 §6.6) ───────────────────────────────────────────────

class TestDemandMode:
    def test_demand_bit_tracked(self):
        sess = make_session()
        p = pkt(state=BFDState.DOWN)
        p.demand = True
        sess.rx_packet(p)
        assert sess._remote_demand is True

    def test_demand_cleared_when_not_set(self):
        sess = make_session()
        p = pkt(state=BFDState.DOWN)
        p.demand = True
        sess.rx_packet(p)
        # Next packet without demand clears it
        sess.rx_packet(pkt(state=BFDState.DOWN))
        assert sess._remote_demand is False


# ── Resume (RFC 5880 §6.2) ────────────────────────────────────────────────────

class TestResume:
    def test_resume_from_admin_down(self):
        sess = make_session()
        with sess._lock:
            from bfd.session import BFDState as S
            sess._state = S.ADMIN_DOWN
        # resume() should transition to DOWN without starting real threads
        # We patch start to avoid actual socket creation
        sess._tx_thread = None
        sess._rx_thread = None
        # Just test the state transition part by calling resume() after setting stop_evt
        sess._stop_evt.set()  # will cause threads to stop immediately if they start
        result = sess.resume()
        assert result is True
        assert sess.state == BFDState.DOWN

    def test_resume_returns_false_when_not_admin_down(self):
        sess = make_session()
        assert sess.state == BFDState.DOWN
        result = sess.resume()
        assert result is False
        assert sess.state == BFDState.DOWN  # unchanged

    def test_resume_returns_false_when_up(self):
        sess = make_session()
        sess.rx_packet(pkt(state=BFDState.INIT, your_disc=sess.local_disc))
        assert sess.state == BFDState.UP
        assert sess.resume() is False
