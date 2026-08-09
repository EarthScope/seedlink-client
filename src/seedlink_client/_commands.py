"""The SeedLink command vocabulary: pure request/reply builders, no I/O.

Every SeedLink command has the same shape: send a text line, and -- for
all but a few fire-and-forget commands -- read back exactly one reply line
and parse it. A :class:`Command` captures that shape as data, the same
pattern used by ``datalink_client._commands``. Both transports execute a
``Command`` with the same dispatch: send ``cmd.text`` + ``cmd.terminator``,
then, if ``cmd.parse`` is not None, read one reply line and call it.

:func:`plan_handshake` and :func:`plan_negotiation` are the heart of
transparent v3/v4 support: each takes configuration and returns an ordered
``list[Command]``, so the sync and async transports share every protocol
decision, and the planners are directly unit-testable without a socket.

SeedLink's negotiation is more stateful than DataLink's simple 1:1
command/reply model -- a rejected v3 STATION means skip that station's
SELECT/DATA, and a rejected selector is logged but not fatal -- so
``Command`` carries a little routing metadata (``role``, ``stream_id``) that
the transport's negotiation loop uses to apply that behavior generically
across all three negotiation shapes (v4, v3 multi-station, v3 uni-station).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from .protocol import (
    Protocol,
    SeedLinkAuthError,
    SeedLinkError,
    SeedLinkResponse,
    generate_client_id,
    parse_reply,
)
from .streams import Stream, v3_to_v4_selector, v4_to_v3_selector
from .time_utils import parse_timestring, to_comma_timestring, to_iso_timestring

logger = logging.getLogger(__name__)

Role = Literal["generic", "station", "select", "data", "end"]


@dataclass(frozen=True)
class Command:
    """A SeedLink request plus how to interpret its reply.

    Attributes:
        text:       The ASCII command line to send, without CR/LF.
        parse:      Callable to turn the reply line into a result, or None
                    if no reply is expected at all (e.g. END, BYE, or a v3
                    command sent while BATCH is active).
        terminator: Line terminator to send after ``text``. v4's
                    STATION/SELECT/DATA use a bare ``\\r``; everything else
                    uses ``\\r\\n``.
        role:       Routing hint for :meth:`negotiate` loops; ``"generic"``
                    for anything sent outside a negotiation plan.
        stream_id:  The station ID this command belongs to, for negotiation
                    commands; None otherwise.
    """

    text: str
    parse: Callable[[str], Any] | None = None
    terminator: bytes = b"\r\n"
    role: Role = "generic"
    stream_id: str | None = None


def _expect_ok(line: str) -> SeedLinkResponse:
    resp = parse_reply(line)
    if not resp:
        raise SeedLinkError(resp.message or "Server returned ERROR", resp.code)
    return resp


def _expect_auth_ok(line: str) -> SeedLinkResponse:
    resp = parse_reply(line)
    if not resp:
        raise SeedLinkAuthError(resp.message or "Authentication failed", resp.code)
    return resp


# ---------------------------------------------------------------------------
# Handshake commands (HELLO, SLPROTO, CAPABILITIES, USERAGENT, AUTH, BATCH)
# ---------------------------------------------------------------------------


def hello() -> Command:
    """HELLO. The two-line reply is special-cased by the transport."""
    return Command("HELLO", parse=None)


def slproto(version: str = "4.0") -> Command:
    return Command(f"SLPROTO {version}", parse=_expect_ok)


def capabilities(flags: str = "EXTREPLY") -> Command:
    return Command(f"CAPABILITIES {flags}", parse=_expect_ok)


def useragent(client_name: str | None, client_version: str | None) -> Command:
    """USERAGENT <name>/<version> [seedlink-client/<version>].

    Falls back to :func:`~seedlink_client.protocol.generate_client_id` (the
    running program's basename) when ``client_name`` is not given, so the
    reported identity is never just the library on its own.
    """
    from . import __version__

    if client_name:
        tokens = [f"{client_name}/{client_version}" if client_version else client_name]
    else:
        name, version = generate_client_id()
        tokens = [f"{name}/{version}"]
    tokens.append(f"seedlink-client/{__version__}")
    return Command(f"USERAGENT {' '.join(tokens)}", parse=_expect_ok)


def auth_userpass(username: str, password: str) -> Command:
    if " " in username or " " in password:
        raise SeedLinkError("AUTH USERPASS username/password must not contain spaces")
    return Command(f"AUTH USERPASS {username} {password}", parse=_expect_auth_ok)


def auth_jwt(token: str) -> Command:
    return Command(f"AUTH JWT {token}", parse=_expect_auth_ok)


def batch() -> Command:
    """BATCH (v3). Non-fatal if rejected -- the caller just stays unbatched."""
    return Command("BATCH", parse=parse_reply)


def bye() -> Command:
    return Command("BYE", parse=None)


def info(level: str) -> Command:
    """INFO <level>. The reply arrives as a data-stream packet, not a
    single reply line, so this is sent with no expected line reply."""
    return Command(f"INFO {level}", parse=None)


# ---------------------------------------------------------------------------
# Negotiation-command builders
# ---------------------------------------------------------------------------


def _split_net_sta(station_id: str) -> tuple[str, str]:
    """Split 'NET_STA' at the first underscore; v3 STATION wants STA then NET."""
    net, _, sta = station_id.partition("_")
    return net, sta


def station_v4(station_id: str) -> Command:
    return Command(
        f"STATION {station_id}", parse=_expect_ok, terminator=b"\r",
        role="station", stream_id=station_id,
    )


def station_v3(station_id: str, expect_reply: bool) -> Command:
    net, sta = _split_net_sta(station_id)
    return Command(
        f"STATION {sta} {net}", parse=parse_reply if expect_reply else None,
        role="station", stream_id=station_id,
    )


def select_v4(station_id: str, selector: str) -> Command:
    return Command(
        f"SELECT {selector}", parse=_expect_ok, terminator=b"\r",
        role="select", stream_id=station_id,
    )


def select_v3(station_id: str, selector: str, expect_reply: bool) -> Command:
    return Command(
        f"SELECT {selector}", parse=parse_reply if expect_reply else None,
        role="select", stream_id=station_id,
    )


def data_v4(
    station_id: str,
    seqnum: int | None,
    all_data: bool,
    start: datetime | None,
    end: datetime | None,
) -> Command:
    """DATA [<seq>|ALL] [<start> [<end>]] (v4).

    A stream requesting a time window with no prior sequence number gets
    ``DATA ALL <start>...`` -- "give me everything in this window".
    """
    parts = ["DATA"]
    if seqnum is not None:
        parts.append(str(seqnum))
    elif all_data or start is not None:
        parts.append("ALL")
    if start is not None:
        parts.append(to_iso_timestring(start))
        if end is not None:
            parts.append(to_iso_timestring(end))
    return Command(
        " ".join(parts), parse=_expect_ok, terminator=b"\r",
        role="data", stream_id=station_id,
    )


def data_v3(
    station_id: str,
    cmd_name: str,
    seqnum: int | None,
    timestamp: str | None,
    expect_reply: bool,
) -> Command:
    """DATA or FETCH [<seq> [<timestamp>]] (v3). ``cmd_name`` is 'DATA' or 'FETCH'."""
    if seqnum is not None:
        text = f"{cmd_name} {seqnum:X}"
        if timestamp:
            text += f" {timestamp}"
    else:
        text = cmd_name
    return Command(
        text, parse=parse_reply if expect_reply else None,
        role="data", stream_id=station_id,
    )


def time_v3(station_id: str, start: str, end: str | None, expect_reply: bool) -> Command:
    """TIME <start> [<end>] (v3); requesting a time window overrides resume."""
    text = f"TIME {start}" + (f" {end}" if end else "")
    return Command(
        text, parse=parse_reply if expect_reply else None,
        role="data", stream_id=station_id,
    )


def end_v3() -> Command:
    return Command("END", parse=None, role="end")


def end_v4(dialup: bool) -> Command:
    return Command("ENDFETCH" if dialup else "END", parse=None, role="end")


# ---------------------------------------------------------------------------
# Negotiation walk -- shared by both transports' negotiate()
# ---------------------------------------------------------------------------


@dataclass
class NegotiationWalk:
    """Tracks accept/skip state while a transport sends a plan_negotiation()
    plan and reads each command's reply.

    Both transports send commands themselves (blocking vs. ``await``ed I/O)
    and call back into this one command at a time: :meth:`should_send` first
    (a rejected v3 STATION means its stream's SELECT/DATA are skipped, not
    sent), then :meth:`record` with the reply once sent. :meth:`finish`
    raises if no station was ever accepted (v3 multi-station).
    """

    seen_station_role: bool = field(default=False, init=False)
    accepted_any_station: bool = field(default=False, init=False)
    _skip_stream: bool = field(default=False, init=False)

    def should_send(self, cmd: Command) -> bool:
        if cmd.role == "station":
            self.seen_station_role = True
            self._skip_stream = False
            return True
        return not (self._skip_stream and cmd.role in ("select", "data"))

    def record(self, cmd: Command, resp: SeedLinkResponse | None) -> None:
        if cmd.role == "station":
            if resp is not None and not resp:
                logger.warning("Station %s rejected: %s", cmd.stream_id, resp.message)
                self._skip_stream = True
                return
            self.accepted_any_station = True
        elif cmd.role == "select" and resp is not None and not resp:
            logger.warning(
                "SELECT rejected for %s: %s -- station stays subscribed without this filter",
                cmd.stream_id, resp.message,
            )
        elif cmd.role == "data" and resp is not None and not resp:
            logger.warning("%s rejected for %s: %s", cmd.text.split()[0], cmd.stream_id, resp.message)

    def finish(self) -> None:
        if self.seen_station_role and not self.accepted_any_station:
            raise SeedLinkError("No stations accepted")


# ---------------------------------------------------------------------------
# Planners
# ---------------------------------------------------------------------------


def plan_handshake(
    protocol: Protocol,
    server_capabilities: dict[str, str | bool],
    client_name: str | None,
    client_version: str | None,
    auth: tuple[str, str] | str | None,
    want_batch: bool,
) -> list[Command]:
    """Build the post-HELLO handshake commands, in send order.

    ``auth`` is ``(username, password)`` for USERPASS, a bare token string
    for JWT, or None to send no AUTH command (v4 only; v3 has no AUTH).
    Unlike :func:`plan_negotiation`'s v4 commands, these are meant to be
    sent one at a time with its reply read immediately -- each of
    SLPROTO/CAPABILITIES/USERAGENT/AUTH depends on the outcome of the one
    before it.
    """
    commands: list[Command] = []
    if protocol is Protocol.V4:
        commands.append(slproto("4.0"))
        commands.append(useragent(client_name, client_version))
        if auth is not None:
            if isinstance(auth, str):
                commands.append(auth_jwt(auth))
            else:
                commands.append(auth_userpass(*auth))
    elif server_capabilities.get("CAP"):
        commands.append(capabilities("EXTREPLY"))
    if protocol is Protocol.V3 and want_batch:
        commands.append(batch())
    return commands


def plan_negotiation(
    protocol: Protocol,
    streams: list[Stream],
    dialup: bool,
    multistation: bool,
    resume: bool,
    lastpkttime: bool,
    batch_active: bool,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[Command]:
    """Build the stream-selection commands that start streaming, in order.

    Three shapes, chosen by ``protocol`` and ``multistation``:

    - v4: per stream, STATION then one SELECT per selector then DATA;
      finally END or ENDFETCH. STATION/SELECT/DATA errors are fatal
      (raised immediately by the transport as it reads each reply).
    - v3 multi-station: per stream, STATION then SELECT(s) then
      DATA/FETCH/TIME; finally END. A rejected STATION means that
      stream's SELECT/DATA commands are skipped (the transport's
      negotiation loop does this via ``role``/``stream_id``); a rejected
      SELECT or DATA/FETCH/TIME is logged but not fatal.
    - v3 uni-station (exactly one stream): no STATION, no END -- just
      SELECT(s) then DATA/FETCH/TIME.

    A stream's ``all_data``/time window takes precedence over resuming
    from ``seqnum`` (v4 only -- v3 has no "all data" request). A set time
    window always overrides sequence resumption, matching libslink.
    """
    start_str = to_comma_timestring(start_time) if start_time else None
    end_str = to_comma_timestring(end_time) if end_time else None
    cmd_name = "FETCH" if dialup else "DATA"

    def _resume_seqnum(stream: Stream) -> int | None:
        return (stream.seqnum + 1) if (resume and stream.seqnum is not None) else None

    def _resume_timestamp(stream: Stream, seqnum: int | None) -> str | None:
        if not (lastpkttime and seqnum is not None):
            return None
        timestamp = stream.resolve_timestamp()
        if not timestamp:
            return None
        try:
            return to_comma_timestring(parse_timestring(timestamp))
        except ValueError:
            logger.warning(
                "Ignoring unparsable saved timestamp %r for %s", timestamp, stream.station_id
            )
            return None

    def _wire_selector(selector: str) -> str:
        """Convert a selector to the negotiated protocol's syntax if it
        looks like it's written in the other one; already-native selectors
        (and ones with no v3/v4 equivalent -- e.g. a v4 selector using a
        multi-character subsource code, which v3 has no syntax for at all)
        pass through unchanged, on the chance the server recognizes it
        anyway. If it doesn't, the server rejects the SELECT and
        NegotiationWalk logs that the station stays subscribed without it,
        rather than silently dropping the filter."""
        if protocol is Protocol.V4:
            return v3_to_v4_selector(selector) or selector
        return v4_to_v3_selector(selector) or selector

    if protocol is Protocol.V4:
        commands: list[Command] = []
        for stream in streams:
            commands.append(station_v4(stream.station_id))
            for selector in stream.selectors:
                commands.append(select_v4(stream.station_id, _wire_selector(selector)))
            # A set time window always overrides sequence resumption, matching
            # v3's TIME-vs-DATA/FETCH choice above.
            seqnum = None if start_time is not None else _resume_seqnum(stream)
            commands.append(data_v4(stream.station_id, seqnum, stream.all_data, start_time, end_time))
        commands.append(end_v4(dialup))
        return commands

    if not multistation:
        if len(streams) != 1:
            raise SeedLinkError("v3 uni-station mode requires exactly one stream")
        stream = streams[0]
        expect_reply = not batch_active
        commands = [
            select_v3(stream.station_id, _wire_selector(selector), expect_reply)
            for selector in stream.selectors
        ]
        if start_str:
            commands.append(time_v3(stream.station_id, start_str, end_str, expect_reply=False))
        else:
            seqnum = _resume_seqnum(stream)
            timestamp = _resume_timestamp(stream, seqnum)
            commands.append(
                data_v3(stream.station_id, cmd_name, seqnum, timestamp, expect_reply=False)
            )
        return commands

    commands = []
    for stream in streams:
        expect_reply = not batch_active
        commands.append(station_v3(stream.station_id, expect_reply))
        for selector in stream.selectors:
            commands.append(select_v3(stream.station_id, _wire_selector(selector), expect_reply))
        if start_str:
            commands.append(time_v3(stream.station_id, start_str, end_str, expect_reply))
        else:
            seqnum = _resume_seqnum(stream)
            timestamp = _resume_timestamp(stream, seqnum)
            commands.append(
                data_v3(stream.station_id, cmd_name, seqnum, timestamp, expect_reply)
            )
    commands.append(end_v3())
    return commands
