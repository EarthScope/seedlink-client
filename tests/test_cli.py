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

    def test_dash3_and_dash4_shorthands(self):
        assert _build_parser().parse_args(["-3"]).protocol == "3"
        assert _build_parser().parse_args(["-4"]).protocol == "4"

    def test_protocol_shorthands_mutually_exclusive(self):
        import pytest

        with pytest.raises(SystemExit):
            _build_parser().parse_args(["-3", "-4"])
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["-3", "--protocol", "4"])

    def test_dash3_coexists_with_server_positional(self):
        args = _build_parser().parse_args(["-3", "myhost"])
        assert args.protocol == "3"
        assert args.server == "myhost"

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


def make_shell(details: int = 0, unpack: bool = False) -> tuple[SeedLinkShell, MagicMock]:
    sl = MagicMock()
    sl.protocol = Protocol.V4
    shell = SeedLinkShell(sl, details=details, unpack=unpack)
    return shell, sl


def _suppress_watcher_thread(monkeypatch) -> None:
    """_finish_handshake() spawns a daemon thread to watch stdin for Enter;
    under pytest that thread's select() call blows up on the captured stdin
    (no real fileno), so tests that don't care about it patch it away."""
    import seedlink_client.cli as cli_module

    class _NoThread:
        def __init__(self, target=None, daemon=None):
            pass

        def start(self):
            pass

    monkeypatch.setattr(cli_module.threading, "Thread", _NoThread)


class TestCmdloopLibeditFix:
    """cmd.Cmd's own readline setup binds Tab with GNU readline's "tab:
    complete" syntax; libedit (macOS's readline backend before Python 3.13)
    silently ignores it, so Tab just inserts a literal tab. cmdloop()
    rewrites that one call to libedit's own bind syntax for its duration.
    cli.py imports readline locally inside cmdloop(), so these patch the
    real readline module (the same object Python's import cache hands back)."""

    def test_translates_bind_for_libedit(self, monkeypatch):
        import cmd as cmd_module
        import readline

        monkeypatch.setattr(readline, "__doc__", "... libedit ...", raising=False)
        calls = []
        monkeypatch.setattr(readline, "parse_and_bind", calls.append, raising=False)

        def fake_super_cmdloop(self, intro=None):
            import readline as rl
            rl.parse_and_bind(f"{self.completekey}: complete")

        monkeypatch.setattr(cmd_module.Cmd, "cmdloop", fake_super_cmdloop)
        shell, sl = make_shell()
        shell.cmdloop()
        assert calls == ["bind ^I rl_complete"]

    def test_leaves_other_binds_untouched_under_libedit(self, monkeypatch):
        import cmd as cmd_module
        import readline

        monkeypatch.setattr(readline, "__doc__", "... libedit ...", raising=False)
        calls = []
        monkeypatch.setattr(readline, "parse_and_bind", calls.append, raising=False)

        def fake_super_cmdloop(self, intro=None):
            import readline as rl
            rl.parse_and_bind("set editing-mode emacs")

        monkeypatch.setattr(cmd_module.Cmd, "cmdloop", fake_super_cmdloop)
        shell, sl = make_shell()
        shell.cmdloop()
        assert calls == ["set editing-mode emacs"]

    def test_restores_parse_and_bind_after_loop(self, monkeypatch):
        import cmd as cmd_module
        import readline

        def original(arg):
            pass

        monkeypatch.setattr(readline, "__doc__", "... libedit ...", raising=False)
        monkeypatch.setattr(readline, "parse_and_bind", original, raising=False)
        monkeypatch.setattr(cmd_module.Cmd, "cmdloop", lambda self, intro=None: None)

        shell, sl = make_shell()
        shell.cmdloop()
        assert readline.parse_and_bind is original

    def test_gnu_readline_untouched(self, monkeypatch):
        """No libedit marker in readline.__doc__ -- delegate straight through,
        no monkeypatching at all."""
        import cmd as cmd_module
        import readline

        def original(arg):
            pass

        monkeypatch.setattr(readline, "__doc__", "GNU readline", raising=False)
        monkeypatch.setattr(readline, "parse_and_bind", original, raising=False)
        monkeypatch.setattr(cmd_module.Cmd, "cmdloop", lambda self, intro=None: None)

        shell, sl = make_shell()
        shell.cmdloop()
        assert readline.parse_and_bind is original


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

    def test_quit_and_exit_are_aliases(self):
        shell, sl = make_shell()
        assert shell.do_quit("") is True
        assert shell.do_exit("") is True

    def test_v3_data_after_station_expects_a_reply(self):
        shell, sl = make_shell()
        sl.protocol = Protocol.V3
        shell.do_station("IU_KONO")
        sl._streaming = False
        shell.do_data("")
        cmd = sl._send_command.call_args[0][0]
        assert cmd.parse is not None
        assert sl._streaming is False

    def test_hello_does_not_promote_protocol(self):
        shell, sl = make_shell()
        shell.do_hello("")
        sl._do_hello.assert_called_once_with(promote_protocol=False)

    def test_hello_reports_unnegotiated_protocol(self, capsys):
        shell, sl = make_shell()
        sl.protocol = None
        shell.do_hello("")
        assert "not yet negotiated" in capsys.readouterr().out

    def test_slproto_success_sets_protocol(self):
        shell, sl = make_shell()
        sl.protocol = None
        sl._send_command.return_value = MagicMock(__bool__=lambda self: True)
        shell.do_slproto("4.0")
        assert sl.protocol is Protocol.V4

    def test_slproto_v3_version_sets_protocol_v3(self):
        shell, sl = make_shell()
        sl.protocol = None
        sl._send_command.return_value = MagicMock(__bool__=lambda self: True)
        shell.do_slproto("3.1")
        assert sl.protocol is Protocol.V3

    def test_slproto_rejection_leaves_protocol_untouched(self):
        from seedlink_client.protocol import SeedLinkError

        shell, sl = make_shell()
        sl.protocol = None
        sl._send_command.side_effect = SeedLinkError("rejected")
        shell.do_slproto("4.0")
        assert sl.protocol is None
        assert shell.had_error

    def test_help_uppercases_protocol_commands(self, capsys):
        shell, sl = make_shell()
        shell.do_help("")
        out = capsys.readouterr().out
        assert "STATION" in out
        assert "SLPROTO" in out
        assert "quit" in out and "QUIT" not in out
        assert "Typical SeedLink v4 handshake" in out

    def test_help_topic_lookup_is_case_insensitive(self, capsys):
        shell, sl = make_shell()
        shell.do_help("STATION")
        upper_out = capsys.readouterr().out
        shell.do_help("station")
        lower_out = capsys.readouterr().out
        assert upper_out == lower_out
        assert "select a station" in upper_out

    def test_postcmd_ends_session_once_disconnected(self, capsys):
        shell, sl = make_shell()
        sl.is_connected = False
        assert shell.postcmd(False, "station foo") is True
        assert "Connection closed" in capsys.readouterr().out

    def test_postcmd_continues_while_connected(self, capsys):
        shell, sl = make_shell()
        sl.is_connected = True
        assert shell.postcmd(False, "station foo") is False
        assert capsys.readouterr().out == ""

    def test_postcmd_does_not_double_report_an_already_stopping_command(self, capsys):
        """BYE/QUIT/EXIT already return True on their own -- postcmd() must
        not print its own "Connection closed" on top of that."""
        shell, sl = make_shell()
        sl.is_connected = False
        assert shell.postcmd(True, "quit") is True
        assert capsys.readouterr().out == ""

    def test_details_reports_current_setting(self, capsys):
        shell, sl = make_shell(details=1)
        shell.do_details("")
        assert "Detail level 1, samples off." in capsys.readouterr().out

    def test_details_sets_level(self, capsys):
        shell, sl = make_shell()
        shell.do_details("2")
        assert shell.details == 2
        assert "Detail level 2" in capsys.readouterr().out

    def test_details_rejects_non_integer(self):
        shell, sl = make_shell()
        shell.do_details("many")
        assert shell.had_error
        assert shell.details == 0

    def test_details_rejects_out_of_range(self):
        shell, sl = make_shell()
        shell.do_details("4")
        assert shell.had_error
        assert shell.details == 0

    def test_samples_reports_current_setting(self, capsys):
        shell, sl = make_shell(unpack=True)
        shell.do_samples("")
        assert "Samples on." in capsys.readouterr().out

    def test_samples_toggles_on_and_off(self, capsys):
        shell, sl = make_shell()
        shell.do_samples("on")
        assert shell.unpack is True
        shell.do_samples("off")
        assert shell.unpack is False

    def test_samples_rejects_bad_argument(self):
        shell, sl = make_shell()
        shell.do_samples("maybe")
        assert shell.had_error
        assert shell.unpack is False


class TestFinishHandshake:
    """_finish_handshake() drives END and, in v3 uni-station mode, DATA/FETCH/TIME:
    it sends the command, then prints packets until Enter or Ctrl-C. The watcher
    thread is patched to a no-op here -- it only ever touches stdin/select,
    exercised manually, not the packet loop or error handling this covers."""

    def _run(self, monkeypatch, sl, packets_or_error, run=lambda shell: shell.do_end(""), **shell_kwargs):
        _suppress_watcher_thread(monkeypatch)

        def collect(reconnect):
            if isinstance(packets_or_error, Exception):
                raise packets_or_error
            yield from packets_or_error

        sl.collect.side_effect = collect
        shell = SeedLinkShell(sl, **shell_kwargs)
        run(shell)
        return shell

    def test_forwards_details_and_samples_settings(self, monkeypatch):
        import seedlink_client.cli as cli_module

        sl = MagicMock()
        sl.protocol = Protocol.V4
        pkt = SeedLinkPacket(station_id="IU_KONO", seqnum=1, payload_format="2",
                              payload_subformat="D", payload=b"x")
        calls = []
        monkeypatch.setattr(cli_module, "_print_packet", lambda pkt, **kw: calls.append(kw))
        self._run(monkeypatch, sl, [pkt], details=2, unpack=True)
        assert calls == [{"details": 2, "unpack": True, "verbose": True}]

    def test_prints_each_packet(self, monkeypatch, capsys):
        sl = MagicMock()
        sl.protocol = Protocol.V4
        pkt = SeedLinkPacket(station_id="IU_KONO", seqnum=1, payload_format="2",
                              payload_subformat="D", payload=b"x")
        self._run(monkeypatch, sl, [pkt, pkt])
        out = capsys.readouterr().out
        assert out.count("seq 1") == 2

    def test_streaming_flag_set_before_collect_is_called(self, monkeypatch):
        """Regression guard: collect() re-negotiates (and can inject a wildcard
        subscription) whenever _streaming is still False, so it must already be
        True by the time collect() is invoked."""
        sl = MagicMock()
        sl.protocol = Protocol.V4
        streaming_during_collect = []
        _suppress_watcher_thread(monkeypatch)

        def collect(reconnect):
            streaming_during_collect.append(sl._streaming)
            return iter(())

        sl.collect.side_effect = collect
        shell = SeedLinkShell(sl)
        shell.do_end("")
        assert streaming_during_collect == [True]
        sl.collect.assert_called_once_with(reconnect=False)

    def test_real_error_reported(self, monkeypatch):
        from seedlink_client.protocol import SeedLinkError

        sl = MagicMock()
        sl.protocol = Protocol.V4
        shell = self._run(monkeypatch, sl, SeedLinkError("connection reset"))
        assert shell.had_error

    def test_v3_data_with_no_prior_station_ends_handshake_and_streams(self, monkeypatch, capsys):
        sl = MagicMock()
        sl.protocol = Protocol.V3
        pkt = SeedLinkPacket(station_id="IU_KONO", seqnum=1, payload_format="2",
                              payload_subformat="D", payload=b"x")
        self._run(monkeypatch, sl, [pkt], run=lambda shell: shell.do_data(""))
        cmd = sl._send_command.call_args[0][0]
        assert cmd.parse is None
        assert sl._streaming is True
        assert "seq 1" in capsys.readouterr().out


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
