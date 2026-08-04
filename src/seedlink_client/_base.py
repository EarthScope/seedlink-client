"""Shared, transport-independent state and config for SeedLink clients.

Both :class:`~seedlink_client.client.SeedLink` (sockets) and
:class:`~seedlink_client.aio.AsyncSeedLink` (asyncio) subclass
:class:`_SeedLinkBase` for everything that doesn't touch a connection:
host/port/TLS configuration, ``from_server_string``, ``__repr__``, stream
selection (:meth:`add_stream` and friends), and state file save/restore.
"""

from __future__ import annotations

from datetime import datetime

from . import state, streams
from .protocol import Protocol, SeedLinkError, parse_hello
from .streams import Stream
from .time_utils import parse_timestring


class _SeedLinkBase:
    """Transport-independent config and state shared by both SeedLink clients."""

    TLS_PORT = 18500

    def __init__(
        self,
        host: str = "localhost",
        port: int = 18000,
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
        port = 18000
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

    # -- Stream selection -----------------------------------------------------

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
        self._streams.append(
            Stream(station_id=station_id, selectors=sels, seqnum=seqnum,
                   all_data=all_data, timestamp=timestamp)
        )
        self._multistation = True

    def set_all_stations(
        self,
        selectors: str | list[str] | None = None,
        seqnum: int | None = None,
        all_data: bool = False,
        timestamp: str | None = None,
    ) -> None:
        """Request all stations (v3 uni-station mode; v4 ``STATION *``)."""
        if self._streams:
            raise SeedLinkError("Cannot mix set_all_stations() with add_stream()")
        sels = selectors.split() if isinstance(selectors, str) else list(selectors or [])
        self._streams = [
            Stream(station_id="*", selectors=sels, seqnum=seqnum,
                   all_data=all_data, timestamp=timestamp)
        ]
        self._multistation = False
        self._all_stations = True

    def add_streamlist(self, text: str, default_selectors: str | None = None) -> None:
        """Add streams from a stream-list string; see :func:`streams.parse_streamlist`."""
        if self._all_stations:
            raise SeedLinkError("Cannot mix add_streamlist() with set_all_stations()")
        self._streams.extend(streams.parse_streamlist(text, default_selectors))
        self._multistation = True

    def add_streamlist_file(self, path: str, default_selectors: str | None = None) -> None:
        """Add streams from a stream-list file; see :func:`streams.read_streamlist_file`."""
        if self._all_stations:
            raise SeedLinkError("Cannot mix add_streamlist_file() with set_all_stations()")
        self._streams.extend(streams.read_streamlist_file(path, default_selectors))
        self._multistation = True

    def set_timewindow(self, start: str | datetime, end: str | datetime | None = None) -> None:
        """Request a fixed time window instead of resuming from a sequence number."""
        self._start_time = parse_timestring(start) if isinstance(start, str) else start
        self._end_time = parse_timestring(end) if isinstance(end, str) else end

    def save_state(self, path: str) -> None:
        """Write each stream's current sequence number and timestamp to a state file."""
        state.save_state(path, self._streams)

    def recover_state(self, path: str) -> None:
        """Load a state file and apply saved sequence numbers to matching streams."""
        saved = state.load_state(path)
        for stream in self._streams:
            if stream.station_id in saved:
                stream.seqnum, stream.timestamp = saved[stream.station_id]
