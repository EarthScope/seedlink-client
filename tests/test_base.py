"""Tests for seedlink_client._base: stream selection, state recovery, and
the config-only pieces shared by both transports (exercised via SeedLink,
since _SeedLinkBase itself can't be instantiated -- is_connected and
_init_transport are abstract)."""

from __future__ import annotations

from seedlink_client import _commands
from seedlink_client.client import SeedLink
from seedlink_client.protocol import Protocol, SeedLinkPacket
from seedlink_client.state import save_state
from seedlink_client.streams import Stream, sort_streams


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


class TestWildcardExpansion:
    """Stations received via a wildcard station ID are tracked, saved, and
    resumed individually; the wildcard itself is not resumed or saved with
    a sequence where it matches them in multi-station mode."""

    @staticmethod
    def _packet(station_id: str, seqnum: int) -> SeedLinkPacket:
        return SeedLinkPacket(station_id=station_id, seqnum=seqnum,
                              payload_format="2", payload_subformat="D", payload=b"")

    def _client(self, protocol: Protocol = Protocol.V4) -> SeedLink:
        sl = SeedLink()
        sl.protocol = protocol
        return sl

    def test_recovered_stations_resumed_before_wildcards(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [
            Stream(station_id="II_AAK", seqnum=2),
            Stream(station_id="II_BFO", seqnum=4),
            Stream(station_id="II_*"),
            Stream(station_id="AK_*"),
        ])
        sl = self._client()
        sl.recover_state(str(path))
        sl.add_streamlist("II_*:B_H_Z,AK_*")
        sl._prepare_streams()
        sl._prepare_streams()  # idempotent across reconnects
        plan = _commands.plan_negotiation(
            Protocol.V4, sort_streams(sl._streams), dialup=False, multistation=True,
            resume=True, lastpkttime=False, batch_active=False,
        )
        assert [c.text for c in plan] == [
            "STATION II_AAK", "SELECT B_H_Z", "DATA 3",
            "STATION II_BFO", "SELECT B_H_Z", "DATA 5",
            "STATION AK_*", "DATA",
            "STATION II_*", "SELECT B_H_Z", "DATA",
            "END",
        ]

    def test_recovered_wildcard_sequence_not_resumed(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [
            Stream(station_id="IU_*", seqnum=5000, timestamp="2026-11-01T00:00:00.0Z"),
            Stream(station_id="IU_ANMO", seqnum=6000),
        ])
        sl = self._client()
        sl.recover_state(str(path))
        sl.add_stream("IU_*")
        sl._prepare_streams()
        plan = _commands.plan_negotiation(
            Protocol.V4, sort_streams(sl._streams), dialup=False, multistation=True,
            resume=True, lastpkttime=False, batch_active=False,
        )
        assert [c.text for c in plan] == [
            "STATION IU_ANMO", "DATA 6001",
            "STATION IU_*", "DATA",
            "END",
        ]

        sl.save_state(str(path))
        lines = path.read_text().splitlines()[1:]
        assert sorted(lines) == ["IU_* UNSET", "IU_ANMO 6000"]

    def test_wildcard_without_exact_match_resumed(self):
        sl = self._client()
        sl.add_stream("IU_*", seqnum=5000)
        sl.add_stream("GE_WLF", seqnum=10)
        sl._prepare_streams()
        plan = _commands.plan_negotiation(
            Protocol.V4, sort_streams(sl._streams), dialup=False, multistation=True,
            resume=True, lastpkttime=False, batch_active=False,
        )
        assert [c.text for c in plan] == [
            "STATION GE_WLF", "DATA 11",
            "STATION IU_*", "DATA 5001",
            "END",
        ]

    def test_derived_selectors_combine_matching_wildcards(self):
        sl = self._client()
        sl.add_stream("IU_*", "B_H_Z L_H_Z")
        sl.add_stream("*_ANMO", "L_H_Z H_H_Z")
        sl.add_stream("GE_*", "V_H_Z")
        sl._prepare_streams()
        sl._update_stream_state(self._packet("IU_ANMO", 6000))
        derived = next(s for s in sl.streams if s.station_id == "IU_ANMO")
        assert derived.selectors == ["B_H_Z", "L_H_Z", "H_H_Z"]

    def test_derived_selectors_all_streams_if_any_wildcard_has_none(self):
        sl = self._client()
        sl.add_stream("IU_*", "B_H_Z")
        sl.add_stream("*_ANMO")
        sl._prepare_streams()
        sl._update_stream_state(self._packet("IU_ANMO", 6000))
        derived = next(s for s in sl.streams if s.station_id == "IU_ANMO")
        assert derived.selectors == []

    def test_packets_tracked_per_station(self, tmp_path):
        sl = self._client()
        sl.add_stream("II_*")
        sl.add_stream("II_BFO")
        sl._prepare_streams()
        sl._update_stream_state(self._packet("II_AAK", 10))
        sl._update_stream_state(self._packet("II_AAK", 11))
        sl._update_stream_state(self._packet("II_BFO", 20))
        seqs = {s.station_id: s.seqnum for s in sl.streams}
        assert seqs == {"II_*": 20, "II_BFO": 20, "II_AAK": 11}

        path = tmp_path / "state.txt"
        sl.save_state(str(path))
        lines = path.read_text().splitlines()[1:]
        assert sorted(lines) == ["II_* UNSET", "II_AAK 11", "II_BFO 20"]

    def test_v3_uni_station_tracks_stations_but_negotiates_wildcard(self, tmp_path):
        path = tmp_path / "state.txt"
        save_state(str(path), [Stream(station_id="*", seqnum=5),
                               Stream(station_id="II_AAK", seqnum=2)])
        sl = self._client(Protocol.V3)
        sl.recover_state(str(path))
        sl.set_all_stations()
        sl._prepare_streams()
        plan = _commands.plan_negotiation(
            Protocol.V3, sort_streams(sl._streams), dialup=False, multistation=False,
            resume=True, lastpkttime=False, batch_active=False,
        )
        assert [c.text for c in plan] == ["DATA 6"]

        sl._update_stream_state(self._packet("II_AAK", 7))
        sl._update_stream_state(self._packet("GE_WLF", 8))
        assert [(s.station_id, s.seqnum) for s in sl.streams] == [
            ("*", 8), ("II_AAK", 7), ("GE_WLF", 8),
        ]
        sl.save_state(str(path))
        assert path.read_text().splitlines()[1:] == ["* 8", "II_AAK 7", "GE_WLF 8"]

    def test_v4_all_station_saves_wildcard_sequence(self, tmp_path):
        sl = self._client()
        sl.set_all_stations()
        sl._prepare_streams()
        sl._update_stream_state(self._packet("II_AAK", 7))
        sl._update_stream_state(self._packet("GE_WLF", 8))
        path = tmp_path / "state.txt"
        sl.save_state(str(path))
        assert path.read_text().splitlines()[1:] == ["* 8", "II_AAK 7", "GE_WLF 8"]

        plan = _commands.plan_negotiation(
            Protocol.V4, sort_streams(sl._streams), dialup=False, multistation=False,
            resume=True, lastpkttime=False, batch_active=False,
        )
        assert [c.text for c in plan] == [
            "STATION GE_WLF", "DATA 9",
            "STATION II_AAK", "DATA 8",
            "STATION *", "DATA",
            "END",
        ]
