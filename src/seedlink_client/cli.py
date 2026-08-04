"""SeedLink command-line client: a slinktool-style non-interactive runner,
plus an interactive shell for protocol exploration.
"""

from __future__ import annotations

import cmd
import datetime
import logging
import select
import sys
import time
from typing import Any

from . import _commands
from .client import SeedLink
from .protocol import Protocol, SeedLinkError, SeedLinkPacket

# How often the streaming loop writes the statefile, rather than after every
# packet; the run always saves once more on exit regardless of this interval.
_STATEFILE_SAVE_INTERVAL = 5.0

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
            print(text[line * 70:(line + 1) * 70])
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
        print(f"{now:%Y-%m-%dT%H:%M:%S}.{now.microsecond // 1000:03d} (local), "
              f"seq {seq}, Received {len(pkt.payload)} bytes of payload format "
              f"{_payload_format_str(pkt.payload_format, pkt.payload_subformat)}")

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
        print(f"{record.sourceid}, {record.pubversion}, {record.reclen}, "
              f"{record.samplecnt} samples, {record.samprate:g} Hz, "
              f"{record.starttime_str()} (latency ~{latency:.1f})")
    else:
        record.print(details=details - 1)

    if unpack:
        try:
            record.unpack_data()
        except Exception as e:  # pymseed.MiniSEEDError, ValueError, etc.
            print(f"(could not unpack samples: {e})")
        else:
            _print_samples(record)


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
            stations.append({
                "id": st.get("id"), "description": st.get("description"),
                "start_seq": st.get("start_seq"), "end_seq": st.get("end_seq"),
                "streams": streams,
            })
        return stations

    # v3: parse_info_xml() wraps everything under the root element
    root = result.get("seedlink", {})
    stations = []
    for st in root.get("station") or []:
        streams = []
        for s in st.get("stream") or []:
            streams.append({
                "id": f"{s.get('location', '')}_{s.get('seedname', '')}",
                "start_time": s.get("begin_time"), "end_time": s.get("end_time"),
                "format": None, "subformat": None,
                "gaps": [(g.get("begin_time"), g.get("end_time")) for g in s.get("gap") or []],
            })
        stations.append({
            "id": f"{st.get('network', '')}_{st.get('name', '')}",
            "description": st.get("description"),
            "start_seq": st.get("begin_seq"), "end_seq": st.get("end_seq"),
            "streams": streams,
        })
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
                print(f"{station_id:<12} {description}, "
                      f"start seq: {st['start_seq']}, end seq: {st['end_seq']}")
            else:
                print(f"{station_id:<12} {description}")
            continue
        for s in streams:
            stream_id = s["id"] or ""
            start, end = s["start_time"] or "", s["end_time"] or ""
            if verbose and protocol is Protocol.V4:
                print(f"{station_id:<12} {stream_id:<12}  {start} - {end}, "
                      f"format: {s['format'] or ''}, subformat: {s['subformat'] or ''}")
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


class SeedLinkShell(cmd.Cmd):
    """Interactive SeedLink protocol shell: one command per protocol command."""

    prompt = "SL> "
    intro = "Type HELP for commands, QUIT to exit. Tab completion is supported.\n"

    def __init__(self, sl: SeedLink):
        super().__init__()
        self.sl = sl
        self.had_error = False

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

    def _send(self, command) -> None:
        try:
            resp = self.sl._send_command(command)
        except SeedLinkError as e:
            self._fail(str(e))
            return
        if resp is None:
            print("(no reply)")
        else:
            print("OK" if resp else f"ERROR {resp.code or ''} {resp.message or ''}".strip())

    def do_hello(self, arg: str) -> None:
        "HELLO: exchange identification with the server."
        try:
            self.sl._do_hello()
        except SeedLinkError as e:
            self._fail(str(e))
            return
        print(f"Server: {self.sl.server_id}")
        print(f"Organization: {self.sl.organization}")
        print(f"Protocol: v{self.sl.protocol.value if self.sl.protocol else '?'}")

    def do_station(self, arg: str) -> None:
        "STATION <NET_STA>: select a station (v4) or 'STA NET' (v3)."
        if not arg:
            self._fail("STATION requires a station ID")
            return
        if self.sl.protocol is Protocol.V4:
            self._send(_commands.station_v4(arg))
        else:
            self._send(_commands.station_v3(arg, expect_reply=True))

    def complete_station(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return [s.station_id for s in self.sl._streams if s.station_id.startswith(text)]

    def do_select(self, arg: str) -> None:
        "SELECT <selector>: choose streams for the current station."
        if self.sl.protocol is Protocol.V4:
            self._send(_commands.select_v4("", arg))
        else:
            self._send(_commands.select_v3("", arg, expect_reply=True))

    def do_data(self, arg: str) -> None:
        "DATA [seq]: request real-time data, optionally resuming from seq."
        try:
            seq = int(arg) if arg.strip() else None
        except ValueError:
            self._fail(f"Invalid sequence number: {arg!r}")
            return
        if self.sl.protocol is Protocol.V4:
            self._send(_commands.data_v4("", seq, False, None, None))
        else:
            self._send(_commands.data_v3("", "DATA", seq, None, expect_reply=True))

    def do_fetch(self, arg: str) -> None:
        "FETCH [seq]: like DATA, in dial-up mode (v3 only)."
        try:
            seq = int(arg) if arg.strip() else None
        except ValueError:
            self._fail(f"Invalid sequence number: {arg!r}")
            return
        self._send(_commands.data_v3("", "FETCH", seq, None, expect_reply=True))

    def do_time(self, arg: str) -> None:
        "TIME <start> [end]: request a time window (v3 only)."
        parts = arg.split(None, 1)
        if not parts:
            self._fail("TIME requires a start time")
            return
        self._send(_commands.time_v3("", parts[0], parts[1] if len(parts) > 1 else None, expect_reply=True))

    def do_end(self, arg: str) -> None:
        "END: finish handshaking and start streaming."
        cmd_obj = _commands.end_v4(self.sl._dialup) if self.sl.protocol is Protocol.V4 else _commands.end_v3()
        try:
            self.sl._send_command(cmd_obj)
        except SeedLinkError as e:
            self._fail(str(e))
            return
        self.sl._streaming = True
        print("Streaming.")

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

    def do_stream(self, arg: str) -> None:
        "STREAM: print packets as they arrive until Enter or Ctrl-C."
        print("Streaming; press Enter to stop.")
        try:
            for pkt in self.sl.collect(reconnect=False):
                _print_packet(pkt, verbose=True)
                if select.select([sys.stdin], [], [], 0)[0]:
                    sys.stdin.readline()
                    break
        except KeyboardInterrupt:
            print()
        except SeedLinkError as e:
            self._fail(str(e))

    def do_quit(self, arg: str) -> bool:
        "QUIT: disconnect and exit."
        return True

    do_exit = do_quit

    def do_EOF(self, arg: str) -> bool:
        print()
        return True


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
    parser.add_argument("server", nargs="?", default="",
                         help="Server address as host:port or host (default: localhost:18000)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Be more verbose")
    parser.add_argument("--debug", action="store_true", help="Print each network command and response")
    parser.add_argument("-P", "--ping", action="store_true", help="Report the server ID and exit")
    parser.add_argument("-p", "--packet-details", action="count", default=0,
                         help="Print details of data packets (repeatable: -p summary, "
                              "-pp full header, -ppp + extra headers)")
    parser.add_argument("-u", "--unpack", action="store_true",
                         help="Print unpacked sample values (implies -p if not already given)")
    parser.add_argument("-S", "--streams", metavar="STREAMS",
                         help='Stream list, e.g. "IU_KONO:BHE BHN,GE_WLF"')
    parser.add_argument("-s", "--selectors", metavar="SELECTORS",
                         help="Default selectors for uni-station or unqualified multi-station entries")
    parser.add_argument("-l", "--list-file", metavar="FILE", help="Read a stream list from FILE")
    parser.add_argument("-tw", "--timewindow", metavar="BEGIN[/END]",
                         help="Request a time window instead of resuming from a sequence number; "
                              "times may be ISO 8601 or comma-delimited, separated by '/' if both given")
    parser.add_argument("-x", "--statefile", metavar="FILE",
                         help="Save/restore stream sequence numbers to this file")
    parser.add_argument("-k", "--keepalive", type=float, metavar="SECS",
                         help="Send an INFO ID heartbeat this often")
    parser.add_argument("-nd", "--netdelay", type=float, default=30.0, metavar="SECS",
                         help="Reconnection delay (default: 30)")
    parser.add_argument("-nt", "--nettimeout", type=float, default=600.0, metavar="SECS",
                         help="Idle timeout before reconnecting (default: 600)")
    parser.add_argument("-d", "--dialup", action="store_true", help="Dial-up mode: fetch queued data, then exit")
    parser.add_argument("-b", "--batch", action="store_true", help="Request v3 BATCH mode")
    parser.add_argument("--protocol", choices=["3", "4"], help="Pin the protocol version instead of negotiating")
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
            args.server, timeout=args.timeout, tls=tls, tls_noverify=args.tls_noverify,
            protocol=protocol, keepalive=args.keepalive, idle_timeout=args.nettimeout,
            reconnect_delay=args.netdelay, dialup=args.dialup, batch=args.batch,
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
        sl.connect()
        if args.verbose:
            print(f"Connected to {sl._host}:{sl._port} (protocol v{sl.protocol.value})", file=sys.stderr)

        if info_level:
            result = sl.info_dict(info_level)
            _print_info(result, info_level, sl.protocol, verbose=bool(args.verbose))
            return 0

        _configure_streams(sl, args)

        if args.interactive:
            shell = SeedLinkShell(sl)
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
        if args.statefile and sl._streams:
            try:
                sl.save_state(args.statefile)
            except OSError:
                pass
        sl.close()


if __name__ == "__main__":
    sys.exit(main())
