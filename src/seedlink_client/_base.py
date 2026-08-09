"""Shared, transport-independent state and config for SeedLink clients.

Both :class:`~seedlink_client.client.SeedLink` (sockets) and
:class:`~seedlink_client.aio.AsyncSeedLink` (asyncio) subclass
:class:`_SeedLinkBase` for everything that doesn't touch a connection:
construction, host/port/TLS configuration, ``from_server_string``,
``__repr__``, stream selection (:meth:`add_stream` and friends), state file
save/restore, the persistent receive buffer, and turning a decoded frame
into the packet/stream-state updates :meth:`collect` needs. Each subclass
implements :meth:`_init_transport` (its connection handle) and
:attr:`is_connected`; everything else here is shared verbatim.
"""

from __future__ import annotations

import json
from datetime import datetime

from . import state, streams
from .protocol import (
    DEFAULT_PORT,
    FORMAT_JSON,
    FORMAT_XML,
    SUBFORMAT_JSON_ERROR,
    SUBFORMAT_JSON_INFO,
    Protocol,
    SeedLinkError,
    SeedLinkPacket,
    _RawFrame,
    parse_hello,
)
from .protocol import TLS_PORT as _TLS_PORT
from .streams import Stream
from .time_utils import parse_timestring

# Default/minimum size of the persistent receive buffer. It grows to fit an
# oversized payload but is released back to this size once drained, so one
# large packet doesn't pin that memory for the life of the connection.
_RECV_BUF_SIZE = 65536


class _SeedLinkBase:
    """Transport-independent config and state shared by both SeedLink clients.

    Args:
        host:       Server hostname or IP address.
        port:       Server TCP port (typically 18000, or 18500 for TLS).
        timeout:    Optional socket timeout in seconds for connect and
                    command I/O. None means block indefinitely. Applied
                    per socket operation on the sync client; on
                    :class:`~seedlink_client.aio.AsyncSeedLink` it is a
                    single deadline covering an entire ``connect()``/
                    ``negotiate()``/``info()`` call instead.
        tls:        Enable TLS encryption. If None (default), TLS is
                    auto-enabled when port is 18500.
        tls_noverify: If True, disable TLS certificate verification
                      (insecure; useful for self-signed certificates).
        protocol:   Pin the protocol version (``Protocol.V3``/``V4``)
                    instead of negotiating automatically.
        keepalive:  Send an INFO ID heartbeat this often (seconds) while
                    streaming. None disables keepalives.
        idle_timeout: Reconnect if no data arrives for this long (seconds).
        reconnect_delay: Seconds to wait between reconnection attempts.
        dialup:     Dial-up mode: fetch queued data then stop, instead of
                    streaming in real time.
        batch:      Request v3 BATCH mode (suppresses per-command replies
                    during negotiation). Ignored for v4.
        clientname, clientversion: Reported to the server via USERAGENT (v4).
        auth:       ``(username, password)`` for AUTH USERPASS, or a bare
                    token string for AUTH JWT (v4 only).

    Attributes:
        server_id, organization: Parsed from the HELLO reply, once connected.
        server_capabilities: Dict of capability tokens from the HELLO reply.
        protocol:   The negotiated :class:`Protocol`, once connected.
    """

    TLS_PORT = _TLS_PORT

    def __init__(
        self,
        host: str = "localhost",
        port: int = DEFAULT_PORT,
        timeout: float | None = None,
        tls: bool | None = None,
        tls_noverify: bool = False,
        protocol: Protocol | None = None,
        keepalive: float | None = None,
        idle_timeout: float = 600.0,
        reconnect_delay: float = 30.0,
        dialup: bool = False,
        batch: bool = False,
        clientname: str | None = None,
        clientversion: str | None = None,
        auth: tuple[str, str] | str | None = None,
    ):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._tls = tls if tls is not None else (port == self.TLS_PORT)
        self._tls_noverify = tls_noverify
        self._requested_protocol = protocol
        self._keepalive = keepalive
        self._idle_timeout = idle_timeout
        self._reconnect_delay = reconnect_delay
        self._dialup = dialup
        self._want_batch = batch
        self._batch_active = False
        self._clientname = clientname
        self._clientversion = clientversion
        self._auth = auth
        self._streams: list[Stream] = []
        self._match_cache: dict[str, list[Stream]] = {}
        self._recovered_state: dict[str, tuple[int | None, str | None]] = {}
        self._multistation = False
        self._all_stations = False
        self._start_time: datetime | None = None
        self._end_time: datetime | None = None
        self._streaming = False

        self.protocol: Protocol | None = None  # negotiated, set by connect()
        self.server_id: str | None = None
        self.organization: str | None = None
        self.server_capabilities: dict[str, str | bool] = {}
        self._server_protocol_majors: frozenset[str] = frozenset()

        self._recv_buf = bytearray(_RECV_BUF_SIZE)
        self._recv_view = memoryview(self._recv_buf)
        self._recv_start = 0
        self._recv_end = 0
        self._init_transport()

    def _init_transport(self) -> None:
        """Initialize the transport's connection handle (unconnected).

        Each subclass sets whatever it checks in :attr:`is_connected`: the
        sync client its ``_sock``/``_is_ssl``, the async client its
        ``_reader``/``_writer``.
        """
        raise NotImplementedError

    @classmethod
    def from_server_string(
        cls,
        server: str,
        timeout: float | None = None,
        tls: bool | None = None,
        tls_noverify: bool = False,
        **kwargs,
    ):
        """Create a client from a server string (host:port, host@port, host, or '').

        ``host@port`` is an unambiguous alternative to ``host:port`` for use
        with a bare IPv6 host, which cannot otherwise be told apart from the
        ``:port`` suffix; ``[host]:port`` bracket notation works too.
        """

        def _parse_port(text: str) -> int:
            try:
                port = int(text)
            except ValueError:
                raise ValueError(f"Invalid port in server string: {server!r}") from None
            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of range in server string: {server!r}")
            return port

        host = "localhost"
        port = DEFAULT_PORT
        server = server.strip()
        if server:
            if server.startswith("["):
                bracket_end = server.find("]")
                if bracket_end < 0:
                    raise ValueError(
                        f"Missing closing bracket in server string: {server!r}"
                    )
                host = server[1:bracket_end] or "localhost"
                remainder = server[bracket_end + 1 :]
                if remainder.startswith(":") and remainder[1:]:
                    port = _parse_port(remainder[1:])
            elif "@" in server:
                # host@port: split on the last '@' only, so a host containing
                # '@' before this point is preserved rather than mangled.
                head, _, tail = server.rpartition("@")
                host = head or "localhost"
                if tail:
                    port = _parse_port(tail)
            elif server.count(":") > 1:
                # A bare IPv6 literal (2+ colons) can't be split from a port
                # suffix unambiguously; require bracket or '@' notation.
                raise ValueError(
                    f"Ambiguous server string {server!r}; use '[host]:port' or "
                    "'host@port' for a bare IPv6 address"
                )
            else:
                parts = server.rsplit(":", 1)
                host = parts[0] or "localhost"
                if len(parts) == 2 and parts[1]:
                    port = _parse_port(parts[1])
        return cls(host, port, timeout=timeout, tls=tls, tls_noverify=tls_noverify, **kwargs)

    @property
    def is_connected(self) -> bool:
        """Whether the transport currently holds an open connection.

        Each transport overrides this: the sync client checks ``_sock``, the
        async client checks its ``_writer``.
        """
        raise NotImplementedError

    @property
    def is_streaming(self) -> bool:
        return self._streaming

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def streams(self) -> list[Stream]:
        """The configured streams (read-only view; use :meth:`add_stream` and
        friends to change selection)."""
        return list(self._streams)

    def __repr__(self) -> str:
        state_str = "connected" if self.is_connected else "disconnected"
        tls = ", tls" if self._tls else ""
        proto = f", v{self.protocol.value}" if self.protocol else ""
        return f"{type(self).__name__}({self._host!r}, {self._port}, {state_str}{tls}{proto})"

    def _store_identity(self, line1: str, line2: str) -> None:
        """Record a HELLO reply's server ID, organization, and capabilities."""
        server_id, organization, capabilities, protocol_majors = parse_hello(line1, line2)
        self.server_id = server_id
        self.organization = organization
        self.server_capabilities = capabilities
        self._server_protocol_majors = protocol_majors

    def _streams_matching(self, station_id: str) -> list[Stream]:
        """Streams whose pattern matches ``station_id``, cached per station ID.

        Invalidated whenever the stream list changes; see the ``_streams``
        mutators below and each transport's ``negotiate()``.
        """
        cached = self._match_cache.get(station_id)
        if cached is None:
            cached = [s for s in self._streams if s.matches(station_id)]
            self._match_cache[station_id] = cached
        return cached

    # -- Frame/packet handling, shared by both transports' collect() --------

    def _to_packet(self, frame: _RawFrame) -> SeedLinkPacket:
        pkt = SeedLinkPacket(
            station_id=frame.station_id, seqnum=frame.seqnum,
            payload_format=frame.payload_format, payload_subformat=frame.payload_subformat,
            payload=frame.payload,
        )
        if frame.record is not None:
            pkt._record = frame.record
        return pkt

    def _update_stream_state(self, pkt: SeedLinkPacket) -> None:
        if pkt.seqnum is None:
            return
        for stream in self._streams_matching(pkt.station_id):
            stream.seqnum = pkt.seqnum
            # Deferred: the packet is only parsed for its start time if
            # something calls stream.resolve_timestamp() (e.g. save_state()).
            stream.pending_packet = pkt

    @staticmethod
    def _is_info_frame(frame: _RawFrame) -> bool:
        """Whether frame carries our own (or an interleaved) INFO reply, to
        be consumed internally by collect() rather than yielded as data."""
        return frame.payload_format == FORMAT_XML or (
            frame.payload_format == FORMAT_JSON and frame.payload_subformat == SUBFORMAT_JSON_INFO
        )

    @staticmethod
    def _is_json_error_frame(frame: _RawFrame) -> bool:
        """Whether frame carries a v4 JSON ERROR packet arriving mid-stream
        -- as opposed to a synchronous ERROR reply line (handled by the
        transport's StreamEvent.ERROR case) or an ordinary INFO reply
        (_is_info_frame)."""
        return frame.payload_format == FORMAT_JSON and frame.payload_subformat == SUBFORMAT_JSON_ERROR

    @staticmethod
    def _json_error_message(payload: bytes) -> str:
        """Best-effort human-readable message from a JSON ERROR packet's
        payload, for logging/raising the same way an ERROR reply line's
        message is used."""
        text = payload.decode("utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return text
        if isinstance(data, dict):
            return str(data.get("message") or data.get("error") or text)
        return text

    # -- Receive buffer, shared by both transports' _ensure() ----------------

    def _reset_recv_buf(self) -> None:
        """Release an oversized receive buffer back to its default capacity."""
        if len(self._recv_buf) > _RECV_BUF_SIZE:
            self._recv_buf = bytearray(_RECV_BUF_SIZE)
            self._recv_view = memoryview(self._recv_buf)
        self._recv_start = 0
        self._recv_end = 0

    def _prepare_room(self, n: int) -> bool:
        """Ensure the buffer can hold >= n bytes total, growing or
        compacting it as needed, without reading anything.

        Returns True if n bytes are already buffered (nothing left for the
        caller to fill); the transport's ``_ensure()`` then only has to run
        its fill loop when this returns False.
        """
        available = self._recv_end - self._recv_start
        if available >= n:
            return True
        if available == 0 and n <= _RECV_BUF_SIZE:
            self._reset_recv_buf()
        if n > len(self._recv_buf):
            new_size = max(n, len(self._recv_buf) * 2)
            new_buf = bytearray(new_size)
            if available > 0:
                new_buf[:available] = self._recv_buf[self._recv_start:self._recv_end]
            self._recv_buf = new_buf
            self._recv_view = memoryview(self._recv_buf)
            self._recv_start = 0
            self._recv_end = available
        elif len(self._recv_buf) - self._recv_start < n:
            if available > 0:
                self._recv_buf[:available] = self._recv_buf[self._recv_start:self._recv_end]
            self._recv_start = 0
            self._recv_end = available
        return False

    # -- Stream selection -----------------------------------------------------

    def _apply_recovered_state(self, new_streams: list[Stream]) -> None:
        """Apply any sequence number/timestamp loaded by :meth:`recover_state`
        to ``new_streams``, matched by exact station ID."""
        if not self._recovered_state:
            return
        for stream in new_streams:
            saved = self._recovered_state.get(stream.station_id)
            if saved is not None:
                stream.seqnum, stream.timestamp = saved

    def _ensure_default_stream(self) -> None:
        """Fall back to the default '*' stream if none was configured
        (equivalent to ``set_all_stations()`` with no selectors), applying
        any recovered state to it same as an explicitly added stream."""
        if not self._streams:
            self._streams = [Stream(station_id="*")]
            self._apply_recovered_state(self._streams)

    def add_stream(
        self,
        station_id: str,
        selectors: str | list[str] | None = None,
        seqnum: int | None = None,
        all_data: bool = False,
        timestamp: str | None = None,
    ) -> None:
        """Add one station to request, enabling multi-station mode.

        Args:
            station_id: 'NET_STA', wildcards allowed (guaranteed in v4 only).
            selectors:  A selector string ('B_H_? B_L_?') or list of
                        selectors; None or empty means all streams.
            seqnum:     Resume after this sequence number.
            all_data:   Request the earliest available data (v4 ``DATA ALL``).
            timestamp:  ISO time of the last packet received, if resuming.
        """
        if self._all_stations:
            raise SeedLinkError("Cannot mix add_stream() with set_all_stations()")
        sels = selectors.split() if isinstance(selectors, str) else list(selectors or [])
        stream = Stream(station_id=station_id, selectors=sels, seqnum=seqnum,
                         all_data=all_data, timestamp=timestamp)
        self._streams.append(stream)
        self._apply_recovered_state([stream])
        self._multistation = True
        self._match_cache.clear()

    def set_all_stations(
        self,
        selectors: str | list[str] | None = None,
        seqnum: int | None = None,
        all_data: bool = False,
        timestamp: str | None = None,
    ) -> None:
        """Request all stations (v3 uni-station mode; v4 ``STATION *``)."""
        if self._all_stations:
            raise SeedLinkError("set_all_stations() may only be called once")
        if self._streams:
            raise SeedLinkError("Cannot mix set_all_stations() with add_stream()")
        sels = selectors.split() if isinstance(selectors, str) else list(selectors or [])
        self._streams = [
            Stream(station_id="*", selectors=sels, seqnum=seqnum,
                   all_data=all_data, timestamp=timestamp)
        ]
        self._apply_recovered_state(self._streams)
        self._multistation = False
        self._all_stations = True
        self._match_cache.clear()

    def add_streamlist(self, text: str, default_selectors: str | None = None) -> None:
        """Add streams from a stream-list string; see :func:`streams.parse_streamlist`."""
        if self._all_stations:
            raise SeedLinkError("Cannot mix add_streamlist() with set_all_stations()")
        new_streams = streams.parse_streamlist(text, default_selectors)
        self._streams.extend(new_streams)
        self._apply_recovered_state(new_streams)
        self._multistation = True
        self._match_cache.clear()

    def add_streamlist_file(self, path: str, default_selectors: str | None = None) -> None:
        """Add streams from a stream-list file; see :func:`streams.read_streamlist_file`."""
        if self._all_stations:
            raise SeedLinkError("Cannot mix add_streamlist_file() with set_all_stations()")
        new_streams = streams.read_streamlist_file(path, default_selectors)
        self._streams.extend(new_streams)
        self._apply_recovered_state(new_streams)
        self._multistation = True
        self._match_cache.clear()

    def set_timewindow(self, start: str | datetime, end: str | datetime | None = None) -> None:
        """Request a fixed time window instead of resuming from a sequence number."""
        self._start_time = parse_timestring(start) if isinstance(start, str) else start
        self._end_time = parse_timestring(end) if isinstance(end, str) else end

    def save_state(self, path: str) -> None:
        """Write each stream's current sequence number and timestamp to a state file."""
        state.save_state(path, self._streams)

    def recover_state(self, path: str) -> None:
        """Load a state file and apply its sequence numbers/timestamps to
        matching streams, by exact station ID.

        May be called before or after stream setup, in either order: state
        loaded here is also applied to any station added afterward, by
        :meth:`add_stream` and friends, or negotiated by default if none is
        configured at all. A later state file's entries take precedence
        over an earlier one's for the same station ID; both are otherwise
        kept.
        """
        self._recovered_state.update(state.load_state(path))
        self._apply_recovered_state(self._streams)
