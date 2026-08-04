"""Tests for seedlink_client.cli argument parsing and the interactive shell."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock

from pymseed import DataEncoding, MS3Record, timestr2nstime

from seedlink_client.cli import (
    SeedLinkShell,
    _build_parser,
    _configure_streams,
    _fmt_info,
    _normalize_stations,
    _parse_auth,
    _payload_format_str,
    _print_info,
    _print_packet,
    _verbose_timestamp_prefix,
)
from seedlink_client.protocol import Protocol, SeedLinkPacket


class TestArgumentParsing:
    def test_defaults(self):
        args = _build_parser().parse_args([])
        assert args.server == ""
        assert args.streams is None
        assert args.nettimeout == 600.0
        assert args.netdelay == 30.0

    def test_streams_and_selectors(self):
        args = _build_parser().parse_args(["-S", "IU_KONO:BHZ", "-s", "BHZ", "host"])
        assert args.streams == "IU_KONO:BHZ"
        assert args.selectors == "BHZ"
        assert args.server == "host"

    def test_protocol_choice(self):
        args = _build_parser().parse_args(["--protocol", "3"])
        assert args.protocol == "3"

    def test_dialup_and_batch_flags(self):
        args = _build_parser().parse_args(["-d", "-b"])
        assert args.dialup
        assert args.batch

    def test_debug_flag(self):
        assert not _build_parser().parse_args([]).debug
        assert _build_parser().parse_args(["--debug"]).debug

    def test_auth_mutually_exclusive(self):
        import pytest

        with pytest.raises(SystemExit):
            _build_parser().parse_args(["--auth", "u:p", "--jwt", "tok"])


class TestParseAuth:
    def test_userpass(self):
        args = _build_parser().parse_args(["--auth", "bob:secret"])
        assert _parse_auth(args) == ("bob", "secret")

    def test_jwt(self):
        args = _build_parser().parse_args(["--jwt", "sometoken"])
        assert _parse_auth(args) == "sometoken"

    def test_none(self):
        args = _build_parser().parse_args([])
        assert _parse_auth(args) is None


class TestConfigureStreams:
    def test_streams_arg(self):
        sl = MagicMock()
        args = _build_parser().parse_args(["-S", "IU_KONO:BHZ,GE_WLF"])
        _configure_streams(sl, args)
        sl.add_streamlist.assert_called_once_with("IU_KONO:BHZ,GE_WLF", default_selectors=None)

    def test_selectors_only_uses_all_stations(self):
        sl = MagicMock()
        args = _build_parser().parse_args(["-s", "BHZ"])
        _configure_streams(sl, args)
        sl.set_all_stations.assert_called_once_with(selectors="BHZ")

    def test_timewindow_begin_and_end(self):
        sl = MagicMock()
        args = _build_parser().parse_args(
            ["-tw", "2024-01-01T00:00:00/2024-01-02T00:00:00"]
        )
        _configure_streams(sl, args)
        sl.set_timewindow.assert_called_once_with("2024-01-01T00:00:00", "2024-01-02T00:00:00")

    def test_timewindow_no_end(self):
        sl = MagicMock()
        args = _build_parser().parse_args(["-tw", "2024-01-01T00:00:00"])
        _configure_streams(sl, args)
        sl.set_timewindow.assert_called_once_with("2024-01-01T00:00:00", None)

    def test_timewindow_does_not_swallow_server_positional(self):
        args = _build_parser().parse_args(
            ["-tw", "2024-01-01T00:00:00/2024-01-02T00:00:00", "myhost"]
        )
        assert args.server == "myhost"


def make_shell() -> tuple[SeedLinkShell, MagicMock]:
    sl = MagicMock()
    sl.protocol = Protocol.V4
    shell = SeedLinkShell(sl)
    return shell, sl


class TestSeedLinkShell:
    def test_case_insensitive_dispatch(self):
        shell, sl = make_shell()
        shell.onecmd(shell.precmd("STATION IU_KONO"))
        sl._send_command.assert_called_once()

    def test_unknown_command_sets_had_error(self):
        shell, sl = make_shell()
        shell.onecmd(shell.precmd("bogus"))
        assert shell.had_error

    def test_station_requires_argument(self):
        shell, sl = make_shell()
        shell.do_station("")
        assert shell.had_error

    def test_bye_disconnects_and_stops(self):
        shell, sl = make_shell()
        stop = shell.onecmd(shell.precmd("bye"))
        sl.bye.assert_called_once()
        assert stop

    def test_info_prints_dict(self, capsys):
        shell, sl = make_shell()
        sl.info_dict.return_value = {"software": "test"}
        shell.do_info("ID")
        sl.info_dict.assert_called_once_with("ID")
        assert "software: test" in capsys.readouterr().out

    def test_end_starts_streaming(self):
        shell, sl = make_shell()
        shell.do_end("")
        assert sl._streaming is True

    def test_quit_and_exit_are_aliases(self):
        shell, sl = make_shell()
        assert shell.do_quit("") is True
        assert shell.do_exit("") is True


def _make_mseed_packet(sourceid="FDSN:IU_COLA_00_B_H_Z", samplecnt=12) -> SeedLinkPacket:
    """Build a packet wrapping a real, pymseed-encoded miniSEED record."""
    msr = MS3Record(reclen=512)
    msr.sourceid = sourceid
    msr.starttime = timestr2nstime("2024-01-01T00:00:00Z")
    msr.samprate = 20.0
    msr.encoding = DataEncoding.STEIM2
    msr.pubversion = 1
    records = list(msr.generate(data_samples=list(range(samplecnt)), sample_type="i"))
    return SeedLinkPacket(
        station_id="IU_COLA", seqnum=42,
        payload_format="3", payload_subformat="D", payload=records[0],
    )


class TestPayloadFormatStr:
    def test_mseed2(self):
        assert _payload_format_str("2", "D") == "miniSEED 2"

    def test_mseed2_subformat(self):
        assert _payload_format_str("2", "L") == "miniSEED 2 log"

    def test_mseed3(self):
        assert _payload_format_str("3", "D") == "miniSEED 3"

    def test_unrecognized(self):
        assert _payload_format_str("?", "") == "Unrecognized payload type"


class TestVerboseTimestampPrefix:
    def test_cached_within_same_second(self):
        now = datetime.datetime(2025, 1, 1, 12, 0, 0, 123456)
        first = _verbose_timestamp_prefix(now)
        later_in_same_second = _verbose_timestamp_prefix(now.replace(microsecond=999000))
        assert first == later_in_same_second == "2025-01-01T12:00:00"

    def test_recomputed_on_new_second(self):
        _verbose_timestamp_prefix(datetime.datetime(2025, 1, 1, 12, 0, 0))
        next_second = _verbose_timestamp_prefix(datetime.datetime(2025, 1, 1, 12, 0, 1))
        assert next_second == "2025-01-01T12:00:01"


class TestPrintPacket:
    def test_silent_by_default(self, capsys):
        _print_packet(_make_mseed_packet())
        assert capsys.readouterr().out == ""

    def test_verbose_prints_header_only(self, capsys):
        _print_packet(_make_mseed_packet(), verbose=True)
        out = capsys.readouterr().out
        assert "(local), seq 42, Received" in out
        assert "payload format miniSEED 3" in out

    def test_details_one_prints_summary_line(self, capsys):
        _print_packet(_make_mseed_packet(), details=1)
        out = capsys.readouterr().out
        assert "FDSN:IU_COLA_00_B_H_Z, 1," in out
        assert "12 samples, 20 Hz" in out
        assert "latency ~" in out

    def test_details_two_uses_msr3_print_details_one(self, monkeypatch):
        # record.print(details) forwards straight to libmseed's msr3_print(),
        # which writes via the C runtime's own stdout -- not observable
        # through capsys, so verify the level mapping (details - 1) instead.
        calls = []
        monkeypatch.setattr(MS3Record, "print", lambda self, details=0: calls.append(details))
        _print_packet(_make_mseed_packet(), details=2)
        assert calls == [1]

    def test_details_three_uses_msr3_print_details_two(self, monkeypatch):
        calls = []
        monkeypatch.setattr(MS3Record, "print", lambda self, details=0: calls.append(details))
        _print_packet(_make_mseed_packet(), details=3)
        assert calls == [2]

    def test_unpack_implies_summary_and_prints_samples(self, capsys):
        _print_packet(_make_mseed_packet(samplecnt=3), unpack=True)
        out = capsys.readouterr().out
        assert "3 samples" in out  # the -p-equivalent summary line
        assert "0" in out and "1" in out and "2" in out  # sample values

    def test_non_mseed_payload_reports_parse_failure(self, capsys):
        pkt = SeedLinkPacket(
            station_id="", seqnum=None, payload_format="2", payload_subformat="D",
            payload=b"not miniSEED",
        )
        _print_packet(pkt, details=1)
        assert "cannot parse miniSEED record" in capsys.readouterr().out


class TestNormalizeStationsAndPrintInfo:
    def test_v4_stations_only(self):
        result = {"station": [{"id": "IU_COLA", "description": "College", "start_seq": 1, "end_seq": 99}]}
        stations = _normalize_stations(result, Protocol.V4)
        assert stations == [{
            "id": "IU_COLA", "description": "College",
            "start_seq": 1, "end_seq": 99, "streams": [],
        }]

    def test_v4_streams(self):
        result = {"station": [{
            "id": "IU_COLA", "description": "College",
            "stream": [{"id": "00_BHZ", "start_time": "t0", "end_time": "t1",
                        "format": "miniSEED", "subformat": "3"}],
        }]}
        stations = _normalize_stations(result, Protocol.V4)
        assert stations[0]["streams"] == [{
            "id": "00_BHZ", "start_time": "t0", "end_time": "t1",
            "format": "miniSEED", "subformat": "3", "gaps": [],
        }]

    def test_v3_stations_only(self):
        result = {"seedlink": {"station": [
            {"network": "IU", "name": "COLA", "description": "College",
             "begin_seq": "1", "end_seq": "99"},
        ]}}
        stations = _normalize_stations(result, Protocol.V3)
        assert stations == [{
            "id": "IU_COLA", "description": "College",
            "start_seq": "1", "end_seq": "99", "streams": [],
        }]

    def test_v3_streams_with_gaps(self):
        result = {"seedlink": {"station": [{
            "network": "IU", "name": "COLA",
            "stream": [{"location": "00", "seedname": "BHZ",
                        "begin_time": "t0", "end_time": "t1",
                        "gap": [{"begin_time": "g0", "end_time": "g1"}]}],
        }]}}
        stations = _normalize_stations(result, Protocol.V3)
        assert stations[0]["streams"] == [{
            "id": "00_BHZ", "start_time": "t0", "end_time": "t1",
            "format": None, "subformat": None, "gaps": [("g0", "g1")],
        }]

    def test_print_info_stations_terse(self, capsys):
        result = {"station": [{"id": "IU_COLA", "description": "College"}]}
        _print_info(result, "STATIONS", Protocol.V4)
        assert capsys.readouterr().out == "IU_COLA      College\n"

    def test_print_info_streams_terse(self, capsys):
        result = {"station": [{"id": "IU_COLA", "description": "College", "stream": [
            {"id": "00_BHZ", "start_time": "t0", "end_time": "t1"},
        ]}]}
        _print_info(result, "STREAMS", Protocol.V4)
        assert capsys.readouterr().out == "IU_COLA      00_BHZ        t0 - t1\n"

    def test_print_info_other_level_falls_back_to_generic(self, capsys):
        _print_info({"software": "test"}, "ID", Protocol.V4)
        assert "software: test" in capsys.readouterr().out


class TestFmtInfo:
    def test_scalar_list_has_no_separators(self, capsys):
        _fmt_info({"seedlink_protocol": ["SLPROTO:4.0", "SLPROTO:3.1"]})
        assert capsys.readouterr().out == (
            "seedlink_protocol:\n  SLPROTO:4.0\n  SLPROTO:3.1\n"
        )

    def test_single_item_scalar_list_has_no_trailing_dashes(self, capsys):
        _fmt_info({"datalink_protocol": ["DLPROTO:1.1"]})
        assert capsys.readouterr().out == "datalink_protocol:\n  DLPROTO:1.1\n"

    def test_dict_list_separates_entries_but_no_leading_or_trailing_dash(self, capsys):
        _fmt_info({"station": [{"id": "IU_COLA"}, {"id": "IU_ANMO"}]})
        assert capsys.readouterr().out == (
            "station:\n  id: IU_COLA\n  --\n  id: IU_ANMO\n"
        )
