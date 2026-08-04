"""Tests for seedlink_client.state."""

from __future__ import annotations

from seedlink_client.state import load_state, save_state
from seedlink_client.streams import Stream


class TestSaveState:
    def test_header_and_format(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="II_BFO", seqnum=11646353,
                                       timestamp="2025-12-07T21:48:51.0445Z")])
        assert path.read_text() == (
            "#V2 StationID  Sequence  [Timestamp]\n"
            "II_BFO 11646353 2025-12-07T21:48:51.0445Z\n"
        )

    def test_unset_sequence(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="XX_NONE")])
        assert "XX_NONE UNSET\n" in path.read_text()

    def test_no_timestamp_omitted(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="IU_COLA", seqnum=5)])
        assert path.read_text().splitlines()[1] == "IU_COLA 5"


class TestLoadState:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "state.txt"
        streams = [
            Stream(station_id="II_BFO", seqnum=11646353, timestamp="2025-12-07T21:48:51.0445Z"),
            Stream(station_id="XX_NONE"),
        ]
        save_state(str(path), streams)
        loaded = load_state(str(path))
        assert loaded == {
            "II_BFO": (11646353, "2025-12-07T21:48:51.0445Z"),
            "XX_NONE": (None, None),
        }

    def test_legacy_headerless_format(self, tmp_path):
        path = tmp_path / "state.txt"
        path.write_text("IU COLA 12345 2024-01-01T00:00:00.0000Z\n")
        loaded = load_state(str(path))
        assert loaded == {"IU_COLA": (12345, "2024-01-01T00:00:00.0000Z")}

    def test_legacy_uni_station_maps_to_wildcard(self, tmp_path):
        path = tmp_path / "state.txt"
        path.write_text("XX UNI 42\n")
        loaded = load_state(str(path))
        assert loaded == {"*": (42, None)}

    def test_legacy_unset_sequence(self, tmp_path):
        path = tmp_path / "state.txt"
        path.write_text("IU COLA -1\n")
        loaded = load_state(str(path))
        assert loaded == {"IU_COLA": (None, None)}

    def test_comments_and_blank_lines_skipped(self, tmp_path):
        path = tmp_path / "state.txt"
        path.write_text("#V2 StationID  Sequence  [Timestamp]\n\n# comment\nIU_COLA 5\n")
        loaded = load_state(str(path))
        assert loaded == {"IU_COLA": (5, None)}

    def test_malformed_line_skipped(self, tmp_path):
        path = tmp_path / "state.txt"
        path.write_text("#V2 StationID  Sequence  [Timestamp]\nIU_COLA notanumber\nGE_WLF 5\n")
        loaded = load_state(str(path))
        assert loaded == {"GE_WLF": (5, None)}
