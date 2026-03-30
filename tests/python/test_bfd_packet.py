"""Tests for bfd/packet.py — BFDPacket encode/decode."""

import struct
import pytest
from bfd.packet import BFDPacket, BFD_HDR_LEN, BFD_VERSION, DIAG, STATE


class TestBFDPacketDefaults:
    def test_default_fields(self):
        pkt = BFDPacket()
        assert pkt.version == BFD_VERSION
        assert pkt.state == 1  # Down
        assert pkt.diag == 0
        assert not pkt.poll
        assert not pkt.final
        assert not pkt.auth_present
        assert pkt.detect_mult == 3

    def test_str_contains_state(self):
        pkt = BFDPacket(state=3)  # Up
        assert "Up" in str(pkt)

    def test_str_contains_diag(self):
        pkt = BFDPacket(diag=1)
        assert "Control Detection Time Expired" in str(pkt)


class TestBFDPacketEncode:
    def test_encode_length(self):
        raw = BFDPacket().encode()
        assert len(raw) == BFD_HDR_LEN

    def test_encode_version_in_first_byte(self):
        raw = BFDPacket().encode()
        version = (raw[0] >> 5) & 0x07
        assert version == BFD_VERSION

    def test_encode_state_in_flags(self):
        for state_val in (0, 1, 2, 3):
            raw = BFDPacket(state=state_val).encode()
            flags = raw[1]
            assert (flags >> 6) & 0x03 == state_val

    def test_encode_poll_flag(self):
        raw = BFDPacket(poll=True).encode()
        assert raw[1] & 0x20

    def test_encode_final_flag(self):
        raw = BFDPacket(final=True).encode()
        assert raw[1] & 0x10

    def test_encode_auth_flag(self):
        raw = BFDPacket(auth_present=True).encode()
        assert raw[1] & 0x04

    def test_encode_discriminators(self):
        pkt = BFDPacket(my_discriminator=0xDEADBEEF, your_discriminator=0xCAFEBABE)
        raw = pkt.encode()
        _, _, _, _, my_disc, your_disc, _, _, _ = struct.unpack("!BBBBIIIII", raw)
        assert my_disc == 0xDEADBEEF
        assert your_disc == 0xCAFEBABE

    def test_encode_timers(self):
        pkt = BFDPacket(desired_min_tx_us=500000, required_min_rx_us=200000)
        raw = pkt.encode()
        _, _, _, _, _, _, desired_tx, required_rx, _ = struct.unpack("!BBBBIIIII", raw)
        assert desired_tx == 500000
        assert required_rx == 200000


class TestBFDPacketDecode:
    def _make_raw(self, **kwargs) -> bytes:
        return BFDPacket(**kwargs).encode()

    def test_roundtrip(self):
        pkt = BFDPacket(
            state=3,
            diag=1,
            poll=True,
            detect_mult=5,
            my_discriminator=0xABCD,
            your_discriminator=0x1234,
            desired_min_tx_us=100000,
            required_min_rx_us=200000,
        )
        decoded = BFDPacket.decode(pkt.encode())
        assert decoded is not None
        assert decoded.state == pkt.state
        assert decoded.diag == pkt.diag
        assert decoded.poll == pkt.poll
        assert decoded.detect_mult == pkt.detect_mult
        assert decoded.my_discriminator == pkt.my_discriminator
        assert decoded.your_discriminator == pkt.your_discriminator
        assert decoded.desired_min_tx_us == pkt.desired_min_tx_us
        assert decoded.required_min_rx_us == pkt.required_min_rx_us

    def test_decode_too_short(self):
        assert BFDPacket.decode(b"\x00" * (BFD_HDR_LEN - 1)) is None

    def test_decode_empty(self):
        assert BFDPacket.decode(b"") is None

    def test_decode_wrong_version(self):
        raw = bytearray(BFDPacket().encode())
        # Overwrite version bits in byte 0 to version 2
        raw[0] = (raw[0] & 0x1F) | (2 << 5)
        assert BFDPacket.decode(bytes(raw)) is None

    def test_decode_all_flags(self):
        pkt = BFDPacket(
            poll=True, final=True, ctrl_plane_indep=True,
            auth_present=True, demand=True, multipoint=True,
        )
        decoded = BFDPacket.decode(pkt.encode())
        assert decoded.poll
        assert decoded.final
        assert decoded.ctrl_plane_indep
        assert decoded.auth_present
        assert decoded.demand
        assert decoded.multipoint

    def test_decode_extra_bytes_ignored(self):
        raw = BFDPacket().encode() + b"\xFF" * 10
        decoded = BFDPacket.decode(raw)
        assert decoded is not None

    def test_decode_detect_mult_zero_returns_none(self):
        # RFC 5880 §6.8.6 rule 5
        raw = bytearray(BFDPacket().encode())
        raw[2] = 0  # detect_mult byte
        assert BFDPacket.decode(bytes(raw)) is None

    def test_decode_length_field_too_small_returns_none(self):
        # RFC 5880 §6.8.6 rule 2: length < BFD_HDR_LEN
        raw = bytearray(BFDPacket().encode())
        raw[3] = BFD_HDR_LEN - 1  # length byte
        assert BFDPacket.decode(bytes(raw)) is None

    def test_decode_length_field_exceeds_buffer_returns_none(self):
        # RFC 5880 §6.8.6 rule 3: length > payload size
        raw = bytearray(BFDPacket().encode())
        raw[3] = BFD_HDR_LEN + 1  # claims more bytes than the 24-byte buffer
        assert BFDPacket.decode(bytes(raw)) is None

    def test_decode_length_field_equals_buffer_size_accepted(self):
        # Boundary: length == len(data) is valid
        raw = BFDPacket().encode()
        assert BFDPacket.decode(raw) is not None


class TestDiagAndStateConstants:
    def test_diag_0_is_no_diagnostic(self):
        assert DIAG[0] == "No Diagnostic"

    def test_state_3_is_up(self):
        assert STATE[3] == "Up"

    def test_state_1_is_down(self):
        assert STATE[1] == "Down"
