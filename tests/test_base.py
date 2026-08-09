"""Tests for seedlink_client._base: stream selection, state recovery, and
the config-only pieces shared by both transports (exercised via SeedLink,
since _SeedLinkBase itself can't be instantiated -- is_connected and
_init_transport are abstract)."""

from __future__ import annotations

from seedlink_client.client import SeedLink
from seedlink_client.state import save_state
from seedlink_client.streams import Stream


class TestRecoverState:
    """recover_state() may be called before or after stream setup; either
    way, matching streams end up with the saved sequence number/timestamp."""

    def test_applied_to_already_configured_streams(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="IU_COLA", seqnum=42,
                                       timestamp="2025-01-01T00:00:00.0000Z")])
        sl = SeedLink()
        sl.add_stream("IU_COLA")
        sl.recover_state(str(path))
        assert sl._streams[0].seqnum == 42
        assert sl._streams[0].timestamp == "2025-01-01T00:00:00.0000Z"

    def test_applied_to_streams_added_afterward(self, tmp_path):
        """The bug this guards: recover_state() called with no streams yet
        configured must still take effect once a stream is added."""
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="IU_COLA", seqnum=42)])
        sl = SeedLink()
        sl.recover_state(str(path))
        sl.add_stream("IU_COLA")
        assert sl._streams[0].seqnum == 42

    def test_applied_via_streamlist(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="GE_WLF", seqnum=7)])
        sl = SeedLink()
        sl.recover_state(str(path))
        sl.add_streamlist("GE_WLF,MN_AQU")
        assert sl._streams[0].seqnum == 7
        assert sl._streams[1].seqnum is None

    def test_applied_to_default_stream_when_none_configured(self, tmp_path):
        """negotiate() falls back to a '*' stream when none was configured;
        a state file saved under '*' (set_all_stations()/uni-station) must
        still resume it."""
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="*", seqnum=99)])
        sl = SeedLink()
        sl.recover_state(str(path))
        sl._ensure_default_stream()
        assert sl._streams[0].seqnum == 99

    def test_non_matching_station_untouched(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="IU_COLA", seqnum=42)])
        sl = SeedLink()
        sl.recover_state(str(path))
        sl.add_stream("GE_WLF")
        assert sl._streams[0].seqnum is None

    def test_second_call_merges_rather_than_replaces(self, tmp_path):
        path_a = tmp_path / "a.txt"
        path_b = tmp_path / "b.txt"
        save_state(str(path_a), [Stream(station_id="IU_COLA", seqnum=1)])
        save_state(str(path_b), [Stream(station_id="GE_WLF", seqnum=2)])
        sl = SeedLink()
        sl.recover_state(str(path_a))
        sl.recover_state(str(path_b))
        sl.add_stream("IU_COLA")
        sl.add_stream("GE_WLF")
        assert sl._streams[0].seqnum == 1
        assert sl._streams[1].seqnum == 2

    def test_missing_file_raises(self, tmp_path):
        import pytest

        sl = SeedLink()
        with pytest.raises(OSError):
            sl.recover_state(str(tmp_path / "does-not-exist.txt"))


class TestPublicProperties:
    def test_host_port_streams(self):
        sl = SeedLink("example.com", 18500)
        sl.add_stream("IU_COLA")
        assert sl.host == "example.com"
        assert sl.port == 18500
        assert [s.station_id for s in sl.streams] == ["IU_COLA"]

    def test_streams_is_a_copy(self):
        """Mutating the returned list must not affect the client's own."""
        sl = SeedLink()
        sl.add_stream("IU_COLA")
        sl.streams.append(Stream(station_id="GE_WLF"))
        assert [s.station_id for s in sl.streams] == ["IU_COLA"]
