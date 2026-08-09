"""Tests for seedlink_client.protocol."""

from __future__ import annotations

import struct

import pytest

from seedlink_client.protocol import (
    MAX_PAYLOAD_SIZE,
    MAX_STATIONID,
    Protocol,
    SeedLinkError,
    SeedLinkPacket,
    StreamEvent,
    classify_stream_prefix,
    is_packet_signature,
    parse_header_v3,
    parse_header_v4,
    parse_hello,
    parse_info_xml,
    parse_reply,
    select_protocol,
)


class TestParseHeaderV3:
    def test_data_header(self):
        header = parse_header_v3(b"SL0004D2xxxxxxx")
        assert header.seqnum == 0x4D2
        assert not header.is_info

    def test_info_header_continues(self):
        header = parse_header_v3(b"SLINFO *xxx")
        assert header.is_info
        assert header.info_continues

    def test_info_header_terminating(self):
        header = parse_header_v3(b"SLINFO  xxx")
        assert header.is_info
        assert not header.info_continues

    def test_too_short_raises(self):
        with pytest.raises(SeedLinkError):
            parse_header_v3(b"SL0001")

    def test_bad_signature_raises(self):
        with pytest.raises(SeedLinkError):
            parse_header_v3(b"XX0004D2")

    def test_bad_hex_sequence_raises(self):
        with pytest.raises(SeedLinkError):
            parse_header_v3(b"SL!!!!!!")


class TestParseHeaderV4:
    def _build(self, fmt=b"2", subfmt=b"D", length=512, seqnum=100, sidlen=7):
        return struct.pack("<2sccIQB", b"SE", fmt, subfmt, length, seqnum, sidlen)

    def test_basic_fields(self):
        header = parse_header_v4(self._build())
        assert header.payload_format == "2"
        assert header.payload_subformat == "D"
        assert header.payload_length == 512
        assert header.seqnum == 100
        assert header.station_id_length == 7

    def test_too_short_raises(self):
        with pytest.raises(SeedLinkError):
            parse_header_v4(b"SE" + b"\x00" * 5)

    def test_bad_signature_raises(self):
        with pytest.raises(SeedLinkError):
            parse_header_v4(self._build().replace(b"SE", b"XX", 1))

    def test_oversized_length_raises(self):
        with pytest.raises(SeedLinkError):
            parse_header_v4(self._build(length=MAX_PAYLOAD_SIZE + 1))

    def test_oversized_station_id_length_raises(self):
        with pytest.raises(SeedLinkError):
            parse_header_v4(self._build(sidlen=MAX_STATIONID + 1))


class TestClassifyStreamPrefix:
    def test_v3_signature(self):
        assert classify_stream_prefix(b"SL000001") is StreamEvent.PACKET

    def test_v4_signature(self):
        assert classify_stream_prefix(b"SE") is StreamEvent.PACKET

    def test_end(self):
        assert classify_stream_prefix(b"END") is StreamEvent.END

    def test_error(self):
        assert classify_stream_prefix(b"ERROR ARGUMENTS") is StreamEvent.ERROR

    def test_other(self):
        assert classify_stream_prefix(b"garbage") is StreamEvent.OTHER


class TestIsPacketSignature:
    def test_v3(self):
        assert is_packet_signature(ord("S"), ord("L"))

    def test_v4(self):
        assert is_packet_signature(ord("S"), ord("E"))

    def test_other(self):
        assert not is_packet_signature(ord("E"), ord("N"))


class TestSeedLinkPacketIsInfo:
    def test_v3_xml_info(self):
        pkt = SeedLinkPacket(station_id="", seqnum=None, payload_format="X",
                              payload_subformat="I", payload=b"")
        assert pkt.is_info

    def test_v4_json_info(self):
        pkt = SeedLinkPacket(station_id="IU_KONO", seqnum=1, payload_format="J",
                              payload_subformat="I", payload=b"{}")
        assert pkt.is_info

    def test_v4_json_error(self):
        pkt = SeedLinkPacket(station_id="", seqnum=1, payload_format="J",
                              payload_subformat="E", payload=b"{}")
        assert pkt.is_info

    def test_mseed_event_detection_is_not_info(self):
        # format '2' + subformat 'E' (miniSEED 2 event detection) collides
        # with SUBFORMAT_JSON_ERROR's 'E' on subformat alone -- is_info must
        # also check payload_format to tell them apart.
        pkt = SeedLinkPacket(station_id="IU_KONO", seqnum=1, payload_format="2",
                              payload_subformat="E", payload=b"")
        assert not pkt.is_info

    def test_ordinary_data_is_not_info(self):
        pkt = SeedLinkPacket(station_id="IU_KONO", seqnum=1, payload_format="2",
                              payload_subformat="D", payload=b"")
        assert not pkt.is_info


class TestParseReply:
    def test_ok(self):
        resp = parse_reply("OK")
        assert resp
        assert resp.status == "OK"
        assert resp.message is None

    def test_error_v4_code_and_message(self):
        resp = parse_reply("ERROR ARGUMENTS bad selector")
        assert not resp
        assert resp.code == "ARGUMENTS"
        assert resp.message == "bad selector"

    def test_error_v4_code_only(self):
        resp = parse_reply("ERROR UNSUPPORTED")
        assert resp.code == "UNSUPPORTED"
        assert resp.message is None

    def test_v3_extended_reply_ok(self):
        resp = parse_reply("OK\rselector accepted")
        assert resp
        assert resp.message == "selector accepted"

    def test_v3_extended_reply_error(self):
        resp = parse_reply("ERROR\rbad selector")
        assert not resp
        assert resp.message == "bad selector"

    def test_strips_crlf(self):
        resp = parse_reply("OK\r\n")
        assert resp.status == "OK"


class TestParseHello:
    def test_with_capabilities(self):
        server_id, org, caps, protocols = parse_hello(
            "SeedLink v4.0 (RingServer/4.5.4) :: SLPROTO:4.0 SLPROTO:3.1 CAP WS:13",
            "EarthScope Ring Server",
        )
        assert server_id == "SeedLink v4.0 (RingServer/4.5.4)"
        assert org == "EarthScope Ring Server"
        assert caps["SLPROTO"] in ("4.0", "3.1")  # last one wins in the dict
        assert caps["CAP"] is True
        assert caps["WS"] == "13"
        assert protocols == frozenset({"4", "3"})

    def test_no_capabilities(self):
        server_id, org, caps, protocols = parse_hello("SeedLink v3.1", "Site")
        assert server_id == "SeedLink v3.1"
        assert caps == {}
        assert protocols == frozenset()


class TestSelectProtocol:
    def test_v4_advertised_promotes(self):
        assert select_protocol(frozenset({"3", "4"}), None) is Protocol.V4

    def test_only_v3_advertised(self):
        assert select_protocol(frozenset({"3"}), None) is Protocol.V3

    def test_nothing_recognized_defaults_v3(self):
        assert select_protocol(frozenset(), None) is Protocol.V3

    def test_caller_pins_v3_despite_v4_support(self):
        assert select_protocol(frozenset({"3", "4"}), Protocol.V3) is Protocol.V3

    def test_caller_pins_v4_not_supported_raises(self):
        with pytest.raises(SeedLinkError):
            select_protocol(frozenset({"3"}), Protocol.V4)

    def test_caller_pins_v3_not_supported_raises(self):
        with pytest.raises(SeedLinkError):
            select_protocol(frozenset({"4"}), Protocol.V3)


class TestParseInfoXml:
    def test_basic_walk(self):
        result = parse_info_xml('<seedlink software="s" organization="o"><station name="A"/>'
                                 '<station name="B"/></seedlink>')
        assert result["seedlink"]["software"] == "s"
        stations = result["seedlink"]["station"]
        assert [s["name"] for s in stations] == ["A", "B"]

    def test_malformed_raises(self):
        with pytest.raises(SeedLinkError):
            parse_info_xml("<not><valid")
