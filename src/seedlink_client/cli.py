"""SeedLink command-line client: a slinktool-style non-interactive runner,
plus an interactive shell for protocol exploration.
"""

from __future__ import annotations

import cmd
import datetime
import logging
import select
import socket
import sys
import threading
import time
from typing import Any

from . import _commands
from .client import SeedLink
from .protocol import Protocol, SeedLinkError, SeedLinkPacket

# How often the streaming loop writes the statefile, rather than after every
# packet; the run always saves once more on exit regardless of this interval.
_STATEFILE_SAVE_INTERVAL = 5.0

# -u prints a preview of a packet's sample values, not a full dump, unless
# -ppp (full header detail) was also given -- a real record can carry
# thousands of samples, and -u's job is a quick visual sanity check.
_DEFAULT_SAMPLE_LINES = 6

# ---------------------------------------------------------------------------
# Packet/INFO printing -- formats mirror slinktool.c / slinkinfo.c so output
# is directly comparable between the two clients.
# ---------------------------------------------------------------------------


_MSEED2_SUBFORMATS = {
    "E": "miniSEED 2 event detection",
    "C": "miniSEED 2 calibration",
    "T": "miniSEED 2 timing exception",
    "L": "miniSEED 2 log",
    "O": "miniSEED 2 opaque",
}

_JSON_SUBFORMATS = {"I": "INFO in JSON", "E": "ERROR in JSON"}

# Cache for _verbose_timestamp_prefix(): the "%Y-%m-%dT%H:%M:%S" formatting
# only needs to happen once per wall-clock second, not once per packet.
_verbose_ts_second: datetime.datetime | None = None
_verbose_ts_prefix = ""


def _verbose_timestamp_prefix(now: datetime.datetime) -> str:
    """Format now down to the second, cached across calls within the same
    second; callers append their own sub-second precision."""
    global _verbose_ts_second, _verbose_ts_prefix
    sec = now.replace(microsecond=0)
    if sec != _verbose_ts_second:
        _verbose_ts_prefix = f"{now:%Y-%m-%dT%H:%M:%S}"
        _verbose_ts_second = sec
    return _verbose_ts_prefix


def _payload_format_str(fmt: str, subfmt: str) -> str:
    """Human-readable payload format, matching slinktool's sl_formatstr()."""
    if fmt == "2":
        return _MSEED2_SUBFORMATS.get(subfmt, "miniSEED 2")
    if fmt == "3":
        return "miniSEED 3"
    if fmt == "J":
        return _JSON_SUBFORMATS.get(subfmt, "JSON")
    return "Unrecognized payload type"


def _print_samples(record, maxlines: int = 0) -> None:
    """Print sample values as slinktool's print_samples() does: 6 numeric
    values or 70 text characters per line; maxlines <= 0 prints every line.
    """
    if not record.numsamples:
        return
    sampletype = record.sampletype
    samples = record.datasamples

    if sampletype in ("i", "f", "d"):
        n = record.numsamples
        lines = (n + 5) // 6
        limit = lines if maxlines <= 0 else maxlines
        idx = 0
        line = 0
        while line < lines and line < limit:
            parts = []
            for _ in range(6):
                if idx < n:
                    v = samples[idx]
                    idx += 1
                    parts.append(f"{v:10d}  " if sampletype == "i" else f"{v:10g}  ")
            print("".join(parts))
            line += 1
        if line < lines:
            print("...")
    elif sampletype == "t":
        text = bytes(samples).decode("ascii", errors="replace")
        lines = (len(text) + 69) // 70
        limit = lines if maxlines <= 0 else maxlines
        line = 0
        while line < lines and line < limit:
            print(text[line * 70 : (line + 1) * 70])
            line += 1
        if line < lines:
            print("...")
    else:
        print(f"Unrecognized sample type: {sampletype}")


def _print_packet(pkt: SeedLinkPacket, details: int = 0, unpack: bool = False, verbose: bool = False) -> None:
    """Print a data packet as slinktool does: silent by default, a
    timestamped header line with -v, a miniSEED summary/dump with -p
    (repeatable), and sample values with -u (which implies -p if not
    already given).
    """
    if verbose:
        now = datetime.datetime.now()
        seq = pkt.seqnum if pkt.seqnum is not None else "-"
        print(
            f"{_verbose_timestamp_prefix(now)}.{now.microsecond // 1000:03d} (local), "
            f"seq {seq}, Received {len(pkt.payload)} bytes of payload format "
            f"{_payload_format_str(pkt.payload_format, pkt.payload_subformat)}"
        )

    if unpack and details == 0:
        details = 1
    if details == 0:
        return

    try:
        record = pkt.record()
    except SeedLinkError:
        print("cannot parse miniSEED record")
        return

    if details == 1:
        latency = (time.time_ns() - record.starttime) / 1e9
        print(
            f"{record.sourceid}, {record.pubversion}, {record.reclen}, "
            f"{record.samplecnt} samples, {record.samprate:g} Hz, "
            f"{record.starttime_str()} (latency ~{latency:.1f})"
        )
    else:
        record.print(details=details - 1)

    if unpack:
        try:
            record.unpack_data()
        except Exception as e:  # pymseed.MiniSEEDError, ValueError, etc.
            print(f"(could not unpack samples: {e})")
        else:
            maxlines = 0 if details >= 3 else _DEFAULT_SAMPLE_LINES
            _print_samples(record, maxlines=maxlines)


def _fmt_info(value: Any, indent: str = "") -> None:
    """Print an info_dict() result (JSON or generic-XML shape) readably."""
    if isinstance(value, dict):
        for key, val in value.items():
            if isinstance(val, (dict, list)):
                print(f"{indent}{key}:")
                _fmt_info(val, indent + "  ")
            else:
                print(f"{indent}{key}: {val}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if i > 0 and isinstance(item, dict):
                print(f"{indent}--")
            _fmt_info(item, indent)
    else:
        print(f"{indent}{value}")


def _normalize_stations(result: dict[str, Any], protocol: Protocol) -> list[dict[str, Any]]:
    """Flatten an info_dict() STATIONS/STREAMS reply into a common shape,
    regardless of whether it came from v4 JSON or a v3 XML attribute walk.
    """
    if protocol is Protocol.V4:
        stations = []
        for st in result.get("station") or []:
            streams = [
                {
                    "id": s.get("id"),
                    "start_time": s.get("start_time"),
                    "end_time": s.get("end_time"),
                    "format": s.get("format"),
                    "subformat": s.get("subformat"),
                    "gaps": [],
                }
                for s in st.get("stream") or []
            ]
            stations.append(
                {
                    "id": st.get("id"),
                    "description": st.get("description"),
                    "start_seq": st.get("start_seq"),
                    "end_seq": st.get("end_seq"),
                    "streams": streams,
                }
            )
        return stations

    # v3: parse_info_xml() wraps everything under the root element
    root = result.get("seedlink", {})
    stations = []
    for st in root.get("station") or []:
        streams = []
        for s in st.get("stream") or []:
            streams.append(
                {
                    "id": f"{s.get('location', '')}_{s.get('seedname', '')}",
                    "start_time": s.get("begin_time"),
                    "end_time": s.get("end_time"),
                    "format": None,
                    "subformat": None,
                    "gaps": [(g.get("begin_time"), g.get("end_time")) for g in s.get("gap") or []],
                }
            )
        stations.append(
            {
                "id": f"{st.get('network', '')}_{st.get('name', '')}",
                "description": st.get("description"),
                "start_seq": st.get("begin_seq"),
                "end_seq": st.get("end_seq"),
                "streams": streams,
            }
        )
    return stations


def _print_info_header(result: dict[str, Any], protocol: Protocol) -> None:
    if protocol is Protocol.V4:
        software = result.get("software", "")
        organization = result.get("organization", "")
        started = result.get("server_start")
    else:
        root = result.get("seedlink", {})
        software = root.get("software", "")
        organization = root.get("organization", "")
        started = root.get("started")
    print(f"SeedLink server: {software or ''}")
    print(f"Organization   : {organization or ''}")
    if started:
        print(f"Start time     : {started}")
    print()


def _print_stations(stations: list[dict[str, Any]], protocol: Protocol, verbose: bool = False) -> None:
    """Print STATIONS/STREAMS info the way slinktool's -F formatting does.

    v4 shows format/subformat on verbose stream lines; v3 has no such
    concept and shows gaps instead -- matching print_info_json/print_info_xml.
    """
    for st in stations:
        station_id = st["id"] or ""
        description = st["description"] or ""
        streams = st["streams"]
        if not streams:
            if verbose:
                print(f"{station_id:<12} {description}, start seq: {st['start_seq']}, end seq: {st['end_seq']}")
            else:
                print(f"{station_id:<12} {description}")
            continue
        for s in streams:
            stream_id = s["id"] or ""
            start, end = s["start_time"] or "", s["end_time"] or ""
            if verbose and protocol is Protocol.V4:
                print(
                    f"{station_id:<12} {stream_id:<12}  {start} - {end}, "
                    f"format: {s['format'] or ''}, subformat: {s['subformat'] or ''}"
                )
            else:
                print(f"{station_id:<12} {stream_id:<12}  {start} - {end}")
            if verbose:
                for begin, gend in s["gaps"]:
                    print(f"  Gap: {begin} - {gend}")


def _print_info(result: dict[str, Any], level: str, protocol: Protocol, verbose: bool = False) -> None:
    """Print an INFO reply, formatted like slinktool for STATIONS/STREAMS."""
    if level.upper() in ("STATIONS", "STREAMS"):
        if verbose:
            _print_info_header(result, protocol)
        _print_stations(_normalize_stations(result, protocol), protocol, verbose=verbose)
    else:
        _fmt_info(result)


# ---------------------------------------------------------------------------
# Stream configuration from CLI args
# ---------------------------------------------------------------------------


def _configure_streams(sl: SeedLink, args) -> None:
    if args.streams:
        sl.add_streamlist(args.streams, default_selectors=args.selectors)
    elif args.list_file:
        sl.add_streamlist_file(args.list_file, default_selectors=args.selectors)
    elif args.selectors:
        sl.set_all_stations(selectors=args.selectors)
    if args.timewindow:
        start, _, end = args.timewindow.partition("/")
        try:
            sl.set_timewindow(start, end or None)
        except ValueError as e:
            raise SeedLinkError(f"Invalid --timewindow {args.timewindow!r}: {e}") from e
    if args.statefile:
        try:
            sl.recover_state(args.statefile)
        except OSError:
            pass  # no state file yet


def _parse_auth(args) -> tuple[str, str] | str | None:
    if args.auth:
        user, _, password = args.auth.partition(":")
        return (user, password)
    if args.jwt:
        return args.jwt
    return None


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------


INFO_LEVELS = ["ID", "CAPABILITIES", "STATIONS", "STREAMS", "GAPS", "CONNECTIONS", "ALL"]

# Real SeedLink wire commands the shell implements, shown upper-case in HELP
# to set them apart from shell-only conveniences (help, quit, exit).
_PROTOCOL_COMMANDS = {
    "hello",
    "slproto",
    "station",
    "select",
    "data",
    "fetch",
    "time",
    "end",
    "info",
    "bye",
}

_HANDSHAKE_EXAMPLE = """\
Typical SeedLink v4 handshake to start streaming:
  HELLO
  SLPROTO 4.0
  STATION IU_COLA
  SELECT 00_B_H_Z
  DATA
  STATION II_KDAK
  SELECT *_B_H_Z
  DATA
  END

The same handshake using v3:
  HELLO
  STATION COLA IU
  SELECT 00BHZ
  DATA
  STATION KDAK II
  SELECT BHZ
  DATA
  END
"""


class SeedLinkShell(cmd.Cmd):
    """Interactive SeedLink protocol shell: one command per protocol command."""

    prompt = "SL> "
    intro = "Type HELLO to begin, HELP for commands, QUIT to exit. Tab completion is supported.\n"

    def __init__(self, sl: SeedLink, details: int = 0, unpack: bool = False):
        super().__init__()
        self.sl = sl
        self.had_error = False
        self._sent_station = False
        self.details = details
        self.unpack = unpack

    def onecmd(self, line: str) -> bool:
        """Run one command; had_error reflects only this one, not the
        whole session -- one earlier typo shouldn't poison the exit code
        of an otherwise successful interactive run."""
        self.had_error = False
        return super().onecmd(line)

    def postcmd(self, stop: bool, line: str) -> bool:
        """End the session once the connection drops -- every remaining
        command would just fail with "Not connected", so there's nothing
        left this shell can do. BYE/QUIT/EXIT already stop the loop
        themselves (stop is already true), so this only fires for a
        connection lost mid-command: a socket error, or _finish_handshake()'s
        own Enter-to-stop, which closes the connection to interrupt the read."""
        if not stop and not self.sl.is_connected:
            print("Connection closed.")
            return True
        return stop

    def cmdloop(self, intro: str | None = None) -> None:
        """Fix tab completion under libedit-backed readline (macOS's stock
        Python, at least before 3.13): cmd.Cmd's own setup binds Tab with
        GNU readline's "tab: complete" syntax, which libedit silently
        ignores -- Tab just inserts a literal tab instead of completing.
        Rewrite that one call to libedit's "bind ^I rl_complete" syntax for
        the duration of the loop, the same fix cmd.py itself gained in 3.13.
        """
        try:
            import readline
        except ImportError:
            super().cmdloop(intro)
            return
        if "libedit" not in (readline.__doc__ or ""):
            super().cmdloop(intro)
            return
        gnu_bind = f"{self.completekey}: complete"
        libedit_bind = "bind ^I rl_complete" if self.completekey == "tab" else f"bind {self.completekey} rl_complete"
        original_parse_and_bind = readline.parse_and_bind
        readline.parse_and_bind = lambda arg: original_parse_and_bind(libedit_bind if arg == gnu_bind else arg)
        try:
            super().cmdloop(intro)
        finally:
            readline.parse_and_bind = original_parse_and_bind

    def _fail(self, message: str) -> None:
        print(f"Error: {message}", file=sys.stderr)
        self.had_error = True

    def parseline(self, line: str):
        cmd_name, arg, full = super().parseline(line)
        if cmd_name and cmd_name != "EOF":
            cmd_name = cmd_name.lower()
        return cmd_name, arg, full

    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> None:
        self._fail(f"Unknown command: {line.split()[0] if line.split() else line!r}")

    def _send(self, command) -> Any:
        try:
            resp = self.sl._send_command(command)
        except SeedLinkError as e:
            self._fail(str(e))
            return None
        if resp is None:
            print("(no reply)")
        else:
            print("OK" if resp else f"ERROR {resp.code or ''} {resp.message or ''}".strip())
        return resp

    def _finish_handshake(self, command) -> None:
        """Send an unacknowledged command that ends the handshake -- v4
        END/ENDFETCH, or v3 DATA/FETCH/TIME in uni-station mode -- then print
        packets as they arrive until Enter or Ctrl-C.

        _streaming is set before collect() runs so it never re-negotiates a
        subscription of its own; the command just sent is what the server is
        now honoring.

        collect() only checks for a pending packet at its own pace, so a
        watcher thread waits for stdin to become readable and shuts down the
        socket to interrupt it -- shutdown() rather than close(), since
        closing the fd out from under the main thread's own blocked
        select()/recv() is a race (it can see a bad-file-descriptor error
        instead of a clean disconnect); collect() notices the shutdown itself
        and closes the connection from its own thread. The watcher never
        actually reads the line, so the keypress that stopped streaming is
        just left in stdin's buffer -- postcmd() ends the session right after
        anyway, once it notices the connection this just closed.
        """
        try:
            self.sl._send_command(command)
        except SeedLinkError as e:
            self._fail(str(e))
            return
        self.sl._streaming = True
        print("Streaming; press Enter to stop.")
        stopped = threading.Event()

        def watch_for_enter() -> None:
            select.select([sys.stdin], [], [], None)
            if not stopped.is_set():
                stopped.set()
                sock = self.sl._sock
                if sock is not None:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        threading.Thread(target=watch_for_enter, daemon=True).start()
        try:
            for pkt in self.sl.collect(reconnect=False):
                _print_packet(pkt, details=self.details, unpack=self.unpack, verbose=True)
        except KeyboardInterrupt:
            print()
        except SeedLinkError as e:
            if not stopped.is_set():  # a real error, not our own shutdown() above
                self._fail(str(e))
        finally:
            stopped.set()

    def do_hello(self, arg: str) -> None:
        "HELLO: exchange identification with the server."
        try:
            self.sl._do_hello(promote_protocol=False)
        except SeedLinkError as e:
            self._fail(str(e))
            return
        print(f"Server: {self.sl.server_id}")
        print(f"Organization: {self.sl.organization}")
        if self.sl.protocol:
            print(f"Protocol: v{self.sl.protocol.value}")
        else:
            print("Protocol: not yet negotiated (SLPROTO to upgrade)")

    def do_slproto(self, arg: str) -> None:
        "SLPROTO <version>: upgrade the wire protocol (e.g. 4.0); v3 until this succeeds."
        version = arg.strip() or "4.0"
        resp = self._send(_commands.slproto(version))
        if resp:
            self.sl.protocol = Protocol.V4 if version.split(".", 1)[0] == "4" else Protocol.V3

    def do_station(self, arg: str) -> None:
        "STATION <NET_STA>: select a station (v4) or 'STA NET' (v3)."
        if not arg:
            self._fail("STATION requires a station ID")
            return
        if self.sl.protocol is Protocol.V4:
            self._send(_commands.station_v4(arg))
        else:
            self._send(_commands.station_v3(arg, expect_reply=True))
        self._sent_station = True

    def complete_station(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return [s.station_id for s in self.sl.streams if s.station_id.startswith(text)]

    def do_select(self, arg: str) -> None:
        "SELECT <selector>: choose streams for the current station."
        if self.sl.protocol is Protocol.V4:
            self._send(_commands.select_v4("", arg))
        else:
            self._send(_commands.select_v3("", arg, expect_reply=True))

    def do_data(self, arg: str) -> None:
        """DATA [seq]: request real-time data, optionally resuming from seq.

        In v3 without a prior STATION, this is uni-station mode: DATA itself
        ends the handshake and starts streaming, with no reply to read.
        """
        try:
            seq = int(arg) if arg.strip() else None
        except ValueError:
            self._fail(f"Invalid sequence number: {arg!r}")
            return
        if self.sl.protocol is Protocol.V4:
            self._send(_commands.data_v4("", seq, False, None, None))
        elif self._sent_station:
            self._send(_commands.data_v3("", "DATA", seq, None, expect_reply=True))
        else:
            self._finish_handshake(_commands.data_v3("", "DATA", seq, None, expect_reply=False))

    def do_fetch(self, arg: str) -> None:
        """FETCH [seq]: like DATA, in dial-up mode (v3 only).

        Without a prior STATION (uni-station mode), FETCH ends the handshake
        and starts streaming, same as DATA.
        """
        try:
            seq = int(arg) if arg.strip() else None
        except ValueError:
            self._fail(f"Invalid sequence number: {arg!r}")
            return
        if self._sent_station:
            self._send(_commands.data_v3("", "FETCH", seq, None, expect_reply=True))
        else:
            self._finish_handshake(_commands.data_v3("", "FETCH", seq, None, expect_reply=False))

    def do_time(self, arg: str) -> None:
        """TIME <start> [end]: request a time window (v3 only).

        Without a prior STATION (uni-station mode), TIME ends the handshake
        and starts streaming, same as DATA.
        """
        parts = arg.split(None, 1)
        if not parts:
            self._fail("TIME requires a start time")
            return
        start, end = parts[0], parts[1] if len(parts) > 1 else None
        if self._sent_station:
            self._send(_commands.time_v3("", start, end, expect_reply=True))
        else:
            self._finish_handshake(_commands.time_v3("", start, end, expect_reply=False))

    def do_end(self, arg: str) -> None:
        "END: finish handshaking and print packets as they arrive."
        cmd_obj = _commands.end_v4(self.sl._dialup) if self.sl.protocol is Protocol.V4 else _commands.end_v3()
        self._finish_handshake(cmd_obj)

    def do_details(self, arg: str) -> None:
        """details [N]: set the packet-detail level for streaming output
        (0-3, matching -p/-pp/-ppp); with no argument, report the current
        setting. Takes effect on the next END."""
        arg = arg.strip()
        if arg:
            try:
                level = int(arg)
            except ValueError:
                self._fail(f"Invalid detail level: {arg!r}")
                return
            if not 0 <= level <= 3:
                self._fail(f"Detail level must be 0-3, got {level}")
                return
            self.details = level
        print(f"Detail level {self.details}, samples {'on' if self.unpack else 'off'}.")

    def do_samples(self, arg: str) -> None:
        """samples [on|off]: toggle sample-value printing for streaming
        output (like -u); with no argument, report the current setting."""
        arg = arg.strip().lower()
        if arg:
            if arg not in ("on", "off"):
                self._fail(f"Expected 'on' or 'off', got {arg!r}")
                return
            self.unpack = arg == "on"
        print(f"Samples {'on' if self.unpack else 'off'}.")

    def do_info(self, arg: str) -> None:
        "INFO <level>: request server metadata (ID, STATIONS, STREAMS, ...)."
        level = arg.strip() or "ID"
        try:
            result = self.sl.info_dict(level)
        except SeedLinkError as e:
            self._fail(str(e))
            return
        _print_info(result, level, self.sl.protocol)

    def complete_info(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return [lvl for lvl in INFO_LEVELS if lvl.startswith(text.upper())]

    def do_bye(self, arg: str) -> bool:
        "BYE: notify the server and disconnect."
        try:
            self.sl.bye()
        except SeedLinkError as e:
            self._fail(str(e))
        return True

    def do_quit(self, arg: str) -> bool:
        "QUIT: disconnect and exit."
        return True

    do_exit = do_quit

    def do_EOF(self, arg: str) -> bool:
        print()
        return True

    def get_names(self) -> list[str]:
        """Hide EOF from HELP -- it's cmd.Cmd's Ctrl-D hook, not something to type."""
        return [name for name in super().get_names() if name != "do_EOF"]

    def do_help(self, arg: str) -> None:
        """List commands, or "help <cmd>" for one -- lookup is case-insensitive."""
        if arg:
            super().do_help(arg.lower())
            return
        cmds_doc, cmds_undoc = [], []
        prevname = ""
        for name in sorted(set(self.get_names())):
            if not name.startswith("do_") or name == prevname:
                continue
            prevname = name
            cmd_name = name[3:]
            label = cmd_name.upper() if cmd_name in _PROTOCOL_COMMANDS else cmd_name
            (cmds_doc if getattr(self, name).__doc__ else cmds_undoc).append(label)
        self.stdout.write(f"{self.doc_leader}\n")
        self.print_topics(self.doc_header, cmds_doc, 15, 80)
        self.print_topics(self.undoc_header, cmds_undoc, 15, 80)
        self.stdout.write(f"\n{_HANDSHAKE_EXAMPLE}")


# ---------------------------------------------------------------------------
# Non-interactive entry point
# ---------------------------------------------------------------------------


def _build_parser():
    import argparse

    from . import __version__

    parser = argparse.ArgumentParser(
        prog="seedlink-client",
        description="SeedLink protocol 3.x/4.0 client for streaming geophysical data.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "server", nargs="?", default="", help="Server address as host:port or host (default: localhost:18000)"
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Be more verbose")
    parser.add_argument("--debug", action="store_true", help="Print each network command and response")
    parser.add_argument("-P", "--ping", action="store_true", help="Report the server ID and exit")
    parser.add_argument(
        "-p",
        "--packet-details",
        action="count",
        default=0,
        help="Print details of data packets (repeatable: -p summary, -pp full header, -ppp + extra headers)",
    )
    parser.add_argument(
        "-u",
        "--unpack",
        action="store_true",
        help="Print unpacked sample values (implies -p if not already given); "
        f"a preview of the first {_DEFAULT_SAMPLE_LINES} lines unless -ppp is also given",
    )
    parser.add_argument("-S", "--streams", metavar="STREAMS", help='Stream list, e.g. "IU_KONO:BHE BHN,GE_WLF"')
    parser.add_argument(
        "-s",
        "--selectors",
        metavar="SELECTORS",
        help="Default selectors for uni-station or unqualified multi-station entries",
    )
    parser.add_argument("-l", "--list-file", metavar="FILE", help="Read a stream list from FILE")
    parser.add_argument(
        "-tw",
        "--timewindow",
        metavar="BEGIN[/END]",
        help="Request a time window instead of resuming from a sequence number; "
        "times may be ISO 8601 or comma-delimited, separated by '/' if both given",
    )
    parser.add_argument("-x", "--statefile", metavar="FILE", help="Save/restore stream sequence numbers to this file")
    parser.add_argument("-k", "--keepalive", type=float, metavar="SECS", help="Send an INFO ID heartbeat this often")
    parser.add_argument(
        "-nd", "--netdelay", type=float, default=30.0, metavar="SECS", help="Reconnection delay (default: 30)"
    )
    parser.add_argument(
        "-nt",
        "--nettimeout",
        type=float,
        default=600.0,
        metavar="SECS",
        help="Idle timeout before reconnecting (default: 600)",
    )
    parser.add_argument("-d", "--dialup", action="store_true", help="Dial-up mode: fetch queued data, then exit")
    parser.add_argument("-b", "--batch", action="store_true", help="Request v3 BATCH mode")
    protocol_group = parser.add_mutually_exclusive_group()
    protocol_group.add_argument(
        "--protocol", choices=["3", "4"], help="Pin the protocol version instead of negotiating"
    )
    protocol_group.add_argument(
        "-3", dest="protocol", action="store_const", const="3", help="Shorthand for --protocol 3"
    )
    protocol_group.add_argument(
        "-4", dest="protocol", action="store_const", const="4", help="Shorthand for --protocol 4"
    )
    parser.add_argument("--timeout", type=float, help="Socket timeout in seconds")
    parser.add_argument("--tls", action="store_true", help="Force TLS (auto-enabled for port 18500)")
    parser.add_argument("--tls-noverify", action="store_true", help="Disable TLS certificate verification (insecure)")
    parser.add_argument("-o", "--dumpfile", metavar="FILE", help="Write all received payloads to FILE")
    parser.add_argument("-i", "--info", metavar="LEVEL", help="Send INFO <LEVEL> and print the result, then exit")
    parser.add_argument("-I", "--id", action="store_true", help="Shorthand for --info ID")
    parser.add_argument("-L", "--station-list", action="store_true", help="Shorthand for --info STATIONS")
    parser.add_argument("-Q", "--stream-list", action="store_true", help="Shorthand for --info STREAMS")
    parser.add_argument("-C", "--connection-list", action="store_true", help="Shorthand for --info CONNECTIONS")
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument("--auth", metavar="USER:PASS", help="Authenticate with username:password (v4)")
    auth_group.add_argument("--jwt", metavar="TOKEN", help="Authenticate with a JWT (v4)")
    parser.add_argument("-c", "--interactive", action="store_true", help="Drop into the interactive shell")
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.debug:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        pkg_logger = logging.getLogger("seedlink_client")
        pkg_logger.setLevel(logging.DEBUG)
        pkg_logger.addHandler(handler)

    protocol = Protocol(args.protocol) if args.protocol else None
    tls = True if args.tls else None
    try:
        sl = SeedLink.from_server_string(
            args.server,
            timeout=args.timeout,
            tls=tls,
            tls_noverify=args.tls_noverify,
            protocol=protocol,
            keepalive=args.keepalive,
            idle_timeout=args.nettimeout,
            reconnect_delay=args.netdelay,
            dialup=args.dialup,
            batch=args.batch,
            auth=_parse_auth(args),
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.ping:
        try:
            server_id, organization = sl.ping()
            print(server_id)
            print(organization)
            return 0
        except SeedLinkError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    info_level = args.info
    if args.id:
        info_level = "ID"
    elif args.station_list:
        info_level = "STATIONS"
    elif args.stream_list:
        info_level = "STREAMS"
    elif args.connection_list:
        info_level = "CONNECTIONS"

    try:
        # -c drives the handshake by hand -- HELLO/SLPROTO are the operator's
        # to send -- unless -c is combined with a one-shot --info query.
        skip_handshake = args.interactive and not info_level
        sl.connect(handshake=not skip_handshake)
        if args.verbose:
            proto_suffix = f" (protocol v{sl.protocol.value})" if sl.protocol else ""
            print(f"Connected to {sl.host}:{sl.port}{proto_suffix}", file=sys.stderr)

        if info_level:
            result = sl.info_dict(info_level)
            _print_info(result, info_level, sl.protocol, verbose=bool(args.verbose))
            return 0

        _configure_streams(sl, args)

        if args.interactive:
            shell = SeedLinkShell(sl, details=args.packet_details, unpack=args.unpack)
            try:
                shell.cmdloop()
            except KeyboardInterrupt:
                print()
            return 1 if shell.had_error else 0

        dumpfile = open(args.dumpfile, "ab") if args.dumpfile else None
        last_statefile_save = time.monotonic()
        try:
            for pkt in sl.collect():
                _print_packet(pkt, details=args.packet_details, unpack=args.unpack, verbose=bool(args.verbose))
                if dumpfile:
                    dumpfile.write(pkt.payload)
                # Saved periodically rather than after every packet -- the
                # final `finally` below always saves once more on exit, so
                # this only bounds how much resume progress a crash could lose.
                if args.statefile and time.monotonic() - last_statefile_save >= _STATEFILE_SAVE_INTERVAL:
                    sl.save_state(args.statefile)
                    last_statefile_save = time.monotonic()
        finally:
            if dumpfile:
                dumpfile.close()
        return 0
    except SeedLinkError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 0
    finally:
        if args.statefile and sl.streams:
            try:
                sl.save_state(args.statefile)
            except OSError:
                pass
        sl.close()


if __name__ == "__main__":
    sys.exit(main())
