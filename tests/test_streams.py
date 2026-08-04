"""Tests for seedlink_client.streams."""

from __future__ import annotations

import copy
import dataclasses
import pickle

from seedlink_client.protocol import SeedLinkError
from seedlink_client.streams import (
    Stream,
    parse_streamlist,
    read_streamlist_file,
    sort_streams,
    v3_to_v4_selector,
    v4_to_v3_selector,
)


class TestV3ToV4Selector:
    """Every conversion example from libslink's sl_v3to4selector() docs."""

    def test_three_char_no_location(self):
        assert v3_to_v4_selector("BHZ") == "*_B_H_Z"

    def test_five_char_with_location(self):
        assert v3_to_v4_selector("00BHZ") == "00_B_H_Z"

    def test_three_char_with_type_and_wildcard(self):
        assert v3_to_v4_selector("EH?.D") == "*_E_H_?.D"

    def test_explicit_empty_location(self):
        assert v3_to_v4_selector("--BHZ") == "_B_H_Z"

    def test_single_dash_empty_location(self):
        assert v3_to_v4_selector("-BHZ") == "_B_H_Z"

    def test_four_char_location(self):
        assert v3_to_v4_selector("1BHZ") == "1_B_H_Z"

    def test_already_v4_style_returns_none(self):
        assert v3_to_v4_selector("B_H_Z") is None

    def test_invalid_characters_return_none(self):
        assert v3_to_v4_selector("B#Z") is None

    def test_type_preserved(self):
        assert v3_to_v4_selector("00BHZ.D") == "00_B_H_Z.D"


class TestV4ToV3Selector:
    """The reverse conversion, for a v4-style selector against a v3 server."""

    def test_wildcard_location(self):
        assert v4_to_v3_selector("*_B_H_Z") == "BHZ"

    def test_specific_location(self):
        assert v4_to_v3_selector("00_B_H_Z") == "00BHZ"

    def test_empty_location(self):
        assert v4_to_v3_selector("_B_H_Z") == "--BHZ"

    def test_three_part_implies_wildcard_location(self):
        assert v4_to_v3_selector("B_H_Z") == "BHZ"

    def test_type_preserved(self):
        assert v4_to_v3_selector("*_B_H_Z.D") == "BHZ.D"

    def test_multi_char_subsource_has_no_v3_equivalent(self):
        assert v4_to_v3_selector("*_B_H_ZZ") is None

    def test_long_location_has_no_v3_equivalent(self):
        assert v4_to_v3_selector("XXX_B_H_Z") is None

    def test_round_trip(self):
        for v3 in ("BHZ", "00BHZ", "--BHZ", "1BHZ"):
            v4 = v3_to_v4_selector(v3)
            assert v4_to_v3_selector(v4) == v3


class TestParseStreamlist:
    def test_single_station_no_selectors(self):
        streams = parse_streamlist("GE_WLF")
        assert streams == [Stream(station_id="GE_WLF", selectors=[])]

    def test_selectors_split_at_first_colon(self):
        streams = parse_streamlist("IU_KONO:B_H_E B_H_N,GE_WLF,MN_AQU:H_H_?")
        assert streams == [
            Stream(station_id="IU_KONO", selectors=["B_H_E", "B_H_N"]),
            Stream(station_id="GE_WLF", selectors=[]),
            Stream(station_id="MN_AQU", selectors=["H_H_?"]),
        ]

    def test_selector_with_embedded_colon_filter_suffix(self):
        streams = parse_streamlist("IU_KONO:B_H_?:3")
        assert streams[0].selectors == ["B_H_?:3"]

    def test_default_selectors_applied(self):
        streams = parse_streamlist("GE_WLF,MN_AQU:H_H_?", default_selectors="B_H_?")
        assert streams[0].selectors == ["B_H_?"]
        assert streams[1].selectors == ["H_H_?"]

    def test_blank_entries_ignored(self):
        streams = parse_streamlist("GE_WLF,,MN_AQU")
        assert [s.station_id for s in streams] == ["GE_WLF", "MN_AQU"]


class TestReadStreamlistFile:
    def test_basic_file(self, tmp_path):
        path = tmp_path / "streams.conf"
        path.write_text("GE_ISP  BH?.D\n# a comment\n\nNL_HGN\nMN_AQU  BH? HH?\n")
        streams = read_streamlist_file(str(path))
        assert streams == [
            Stream(station_id="GE_ISP", selectors=["BH?.D"]),
            Stream(station_id="NL_HGN", selectors=[]),
            Stream(station_id="MN_AQU", selectors=["BH?", "HH?"]),
        ]

    def test_default_selectors(self, tmp_path):
        path = tmp_path / "streams.conf"
        path.write_text("NL_HGN\n")
        streams = read_streamlist_file(str(path), default_selectors="BH?")
        assert streams[0].selectors == ["BH?"]


class TestSortStreams:
    def test_exact_before_wildcard(self):
        streams = [
            Stream(station_id="IU_*"),
            Stream(station_id="IU_KONO"),
            Stream(station_id="IU_K?NO"),
        ]
        ordered = sort_streams(streams)
        assert [s.station_id for s in ordered] == ["IU_KONO", "IU_K?NO", "IU_*"]

    def test_alphanumeric_within_group(self):
        streams = [Stream(station_id="MN_AQU"), Stream(station_id="GE_WLF")]
        ordered = sort_streams(streams)
        assert [s.station_id for s in ordered] == ["GE_WLF", "MN_AQU"]


class TestStreamMatches:
    def test_wildcard_match(self):
        stream = Stream(station_id="IU_*")
        assert stream.matches("IU_COLA")
        assert not stream.matches("GE_WLF")

    def test_exact_match(self):
        stream = Stream(station_id="IU_COLA")
        assert stream.matches("IU_COLA")
        assert not stream.matches("IU_KONO")

    def test_question_mark_wildcard(self):
        stream = Stream(station_id="IU_K?NO")
        assert stream.matches("IU_KONO")
        assert not stream.matches("IU_KXXO")

    def test_compiled_pattern_cache_invalidated_on_change(self):
        stream = Stream(station_id="IU_*")
        assert stream.matches("IU_KONO")
        stream.station_id = "GE_*"
        assert not stream.matches("IU_KONO")
        assert stream.matches("GE_WLF")


class _FakePacket:
    """Stands in for a SeedLinkPacket: only .record() is ever called on it."""

    def __init__(self, starttime=None, error=None):
        self._starttime = starttime
        self._error = error
        self.parse_count = 0

    def record(self):
        self.parse_count += 1
        if self._error is not None:
            raise self._error
        return self

    def starttime_str(self):
        return self._starttime


class TestStreamTimestampDeferred:
    def test_resolved_lazily_and_cached(self):
        stream = Stream(station_id="IU_KONO")
        pkt = _FakePacket(starttime="2025-01-01T00:00:00.0000Z")
        stream._ts_pkt = pkt
        assert pkt.parse_count == 0  # not parsed until read
        assert stream.timestamp == "2025-01-01T00:00:00.0000Z"
        assert stream.timestamp == "2025-01-01T00:00:00.0000Z"
        assert pkt.parse_count == 1  # second read used the cached string

    def test_unparseable_payload_keeps_previous_timestamp(self):
        stream = Stream(station_id="IU_KONO", timestamp="2020-01-01T00:00:00.0000Z")
        stream._ts_pkt = _FakePacket(error=SeedLinkError("not miniSEED"))
        assert stream.timestamp == "2020-01-01T00:00:00.0000Z"

    def test_direct_assignment_overrides_pending_packet(self):
        pkt = _FakePacket(starttime="2025-01-01T00:00:00.0000Z")
        stream = Stream(station_id="IU_KONO")
        stream._ts_pkt = pkt
        stream.timestamp = "2030-01-01T00:00:00.0000Z"
        assert stream.timestamp == "2030-01-01T00:00:00.0000Z"
        assert pkt.parse_count == 0  # overwritten, never parsed


class TestStreamCopySemantics:
    """dataclass repr/eq/asdict and pickle/deepcopy must behave exactly as
    they would for a plain (non-deferred) timestamp field."""

    def test_repr_and_eq_unaffected(self):
        a = Stream(station_id="IU_KONO", timestamp="2020-01-01T00:00:00.0000Z")
        b = Stream(station_id="IU_KONO", timestamp="2020-01-01T00:00:00.0000Z")
        assert a == b
        assert "timestamp='2020-01-01T00:00:00.0000Z'" in repr(a)

    def test_asdict(self):
        stream = Stream(station_id="IU_KONO", timestamp="2020-01-01T00:00:00.0000Z")
        assert dataclasses.asdict(stream) == {
            "station_id": "IU_KONO", "selectors": [], "seqnum": None,
            "all_data": False, "timestamp": "2020-01-01T00:00:00.0000Z",
        }

    def test_deepcopy_resolves_and_drops_pending_packet(self):
        stream = Stream(station_id="IU_KONO")
        stream._ts_pkt = _FakePacket(starttime="2025-06-01T00:00:00.0000Z")
        clone = copy.deepcopy(stream)
        assert clone.timestamp == "2025-06-01T00:00:00.0000Z"
        assert "_ts_pkt" not in clone.__dict__

    def test_pickle_roundtrip(self):
        stream = Stream(station_id="IU_KONO", seqnum=5, timestamp="2020-01-01T00:00:00.0000Z")
        clone = pickle.loads(pickle.dumps(stream))
        assert clone == stream
