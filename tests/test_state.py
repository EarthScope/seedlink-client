"""Tests for seedlink_client.state."""

from __future__ import annotations

import os
import stat

import pytest

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

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions only")
    def test_permissions_follow_umask_not_mkstemp_default(self, tmp_path):
        """mkstemp() itself creates the temp file mode 0600; save_state()
        must widen that to ordinary umask-derived permissions before the
        rename, like a plain open(), so another process/user can read a
        state file meant to be shared (e.g. a monitoring tool)."""
        path = tmp_path / "state.txt"
        original_umask = os.umask(0o022)
        os.umask(original_umask)  # umask() sets while returning the old value
        try:
            save_state(str(path), [Stream(station_id="IU_COLA", seqnum=5)])
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == 0o666 & ~original_umask
        finally:
            os.umask(original_umask)

    def test_unset_sequence(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="XX_NONE")])
        assert "XX_NONE UNSET\n" in path.read_text()

    def test_no_timestamp_omitted(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="IU_COLA", seqnum=5)])
        assert path.read_text().splitlines()[1] == "IU_COLA 5"

    def test_deferred_timestamp_resolved_on_save(self, tmp_path):
        """A stream whose timestamp hasn't been resolved yet (set from a
        live packet during collect(), see Stream.resolve_timestamp) still
        resolves and saves correctly."""

        class _FakePacket:
            def record(self):
                return self

            def starttime_str(self):
                return "2025-12-07T21:48:51.0445Z"

        path = tmp_path / "state.txt"
        stream = Stream(station_id="IU_COLA", seqnum=5)
        stream.pending_packet = _FakePacket()
        save_state(str(path), [stream])
        assert path.read_text().splitlines()[1] == "IU_COLA 5 2025-12-07T21:48:51.0445Z"


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
