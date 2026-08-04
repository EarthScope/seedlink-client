"""SeedLink protocol client (query and streaming modes), socket transport."""

from __future__ import annotations

import json
import logging
import select
import socket
import ssl
import time
from collections.abc import Generator
from dataclasses import dataclass
from typing import Any

from . import _commands, mseed
from ._base import _SeedLinkBase
from ._commands import Command
from .protocol import (
    FORMAT_JSON,
    FORMAT_XML,
    HEADSIZE_V3,
    HEADSIZE_V4,
    MAX_COMMAND_LEN,
    MAX_LINE_LEN,
    MAX_RECORD_LEN,
    MIN_PAYLOAD_DETECT,
    SUBFORMAT_JSON_INFO,
    Protocol,
    SeedLinkAuthError,
    SeedLinkError,
    SeedLinkPacket,
    SeedLinkResponse,
    SeedLinkTimeout,
    StreamEvent,
    classify_stream_prefix,
    parse_header_v3,
    parse_header_v4,
    parse_info_xml,
    parse_reply,
    select_protocol,
)
from .streams import Stream, sort_streams

logger = logging.getLogger(__name__)

# Default/minimum size of the persistent receive buffer. It grows to fit an
# oversized payload but is released back to this size once drained, so one
# large packet doesn't pin that memory for the life of the connection.
_RECV_BUF_SIZE = 65536

# How often the streaming loop wakes up to check the keepalive/idle-timeout
# clocks when no data is arriving.
_POLL_INTERVAL = 1.0

# First-byte values of a v3/v4 packet signature ('S' + 'L' or 'E'), checked
# directly against the receive buffer in _classify_next() so the steady
# state of packet-after-packet streaming never allocates a bytes object.
_ORD_S = ord("S")
_ORD_L = ord("L")
_ORD_E = ord("E")


@dataclass(slots=True)
class _RawFrame:
    """One decoded packet frame, before being wrapped as a public SeedLinkPacket.

    ``info_continues`` is only meaningful for a v3 SLINFO packet -- whether
    more INFO packets follow this one.
    """

    station_id: str
    seqnum: int | None
    payload_format: str
    payload_subformat: str
    payload: bytes
    info_continues: bool
    record: Any = None  # pre-parsed pymseed record, if already known


class SeedLink(_SeedLinkBase):
    """SeedLink protocol client, transparently supporting both v3.x and v4.0.

    Supports both uni-station and multi-station selection, time-window and
    sequence-number resumption, dial-up mode, v3 BATCH mode, v4 AUTH, and
    INFO queries -- whichever the negotiated protocol version provides.

    The connection starts unconfigured. Call :meth:`add_stream` (or
    :meth:`set_all_stations`) to select what to receive, then
    :meth:`collect` to start streaming (it negotiates automatically on
    first use).

    For asyncio-based use, see :class:`~seedlink_client.aio.AsyncSeedLink`,
    which offers the same API as coroutines.

    Args:
        host:       Server hostname or IP address.
        port:       Server TCP port (typically 18000, or 18500 for TLS).
        timeout:    Optional socket timeout in seconds for connect and
                    command I/O. None means block indefinitely.
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
        super().__init__(
            host, port, timeout=timeout, tls=tls, tls_noverify=tls_noverify,
            protocol=protocol, keepalive=keepalive, idle_timeout=idle_timeout,
            reconnect_delay=reconnect_delay, dialup=dialup, batch=batch,
            clientname=clientname, clientversion=clientversion, auth=auth,
        )
        self._sock: socket.socket | None = None
        self._is_ssl = False
        self._recv_buf = bytearray(_RECV_BUF_SIZE)
        self._recv_view = memoryview(self._recv_buf)
        self._recv_start = 0
        self._recv_end = 0

    @property
    def is_connected(self) -> bool:
        return self._sock is not None

    def __enter__(self) -> SeedLink:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # -- Connection lifecycle ---------------------------------------------

    def _connect_socket(self) -> None:
        """Open the TCP/TLS connection only, no protocol handshake."""
        if self._sock is not None:
            raise SeedLinkError("Already connected")
        try:
            infos = socket.getaddrinfo(self._host, self._port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as e:
            raise SeedLinkError(f"Could not resolve address: {self._host}:{self._port}: {e}") from e
        if not infos:
            raise SeedLinkError(f"Could not resolve address: {self._host}:{self._port}")
        last_err: OSError | None = None
        for af, socktype, proto, _canonname, sockaddr in infos:
            sock: socket.socket | None = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if self._timeout is not None:
                    sock.settimeout(self._timeout)
                sock.connect(sockaddr)
                if self._tls:
                    context = ssl.create_default_context()
                    if self._tls_noverify:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=self._host)
                self._sock = sock
                self._is_ssl = isinstance(sock, ssl.SSLSocket)
                self._reset_recv_buf()
                sock = None  # ownership transferred to self._sock
                break
            except ssl.SSLCertVerificationError as e:
                raise SeedLinkError(
                    f"TLS certificate verification failed for "
                    f"{self._host}:{self._port}: {e.verify_message}. "
                    f"Use tls_noverify=True to skip verification "
                    f"(insecure, e.g. for self-signed certificates)"
                ) from e
            except OSError as e:
                last_err = e
            finally:
                if sock is not None:
                    sock.close()
        else:
            raise SeedLinkError(f"Could not connect to {self._host}:{self._port}") from last_err
        logger.debug("Connected to %s:%d%s", self._host, self._port, " (TLS)" if self._tls else "")

    def _do_hello(self) -> None:
        self._send_command(_commands.hello())
        line1 = self._read_line()
        line2 = self._read_line()
        logger.debug("<-- %s", line1)
        logger.debug("<-- %s", line2)
        self._store_identity(line1, line2)
        self.protocol = select_protocol(self._server_protocol_majors, self._requested_protocol)

    def connect(self) -> None:
        """Open the connection: TCP/TLS, HELLO, and protocol handshake.

        Raises:
            SeedLinkAuthError: if AUTH is configured and rejected.
            SeedLinkError: on any other connection or handshake failure.
        """
        self._connect_socket()
        try:
            self._do_hello()
            handshake = _commands.plan_handshake(
                self.protocol, self.server_capabilities, self._clientname,
                self._clientversion, self._auth, self._want_batch,
            )
            for cmd in handshake:
                resp = self._send_command(cmd)
                if cmd.text == "BATCH":
                    self._batch_active = bool(resp)
        except SeedLinkError:
            self.close()
            raise

    def close(self) -> None:
        """Gracefully close the connection."""
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                try:
                    self._sock.close()
                finally:
                    self._sock = None
        self._is_ssl = False
        self._streaming = False
        self._batch_active = False
        self._reset_recv_buf()

    def reconnect(self) -> None:
        """Close the current connection (if any), reconnect, and re-negotiate."""
        self.close()
        self.connect()
        if self._streams:
            self.negotiate()

    def ping(self) -> tuple[str, str]:
        """Connect, HELLO, report identity, and disconnect. No stream setup."""
        self._connect_socket()
        try:
            self._do_hello()
        finally:
            self.close()
        return self.server_id, self.organization

    def bye(self) -> None:
        """Send BYE to gracefully notify the server before disconnecting."""
        if self._sock is not None:
            self._send_command(_commands.bye())

    # -- Byte-level transport ----------------------------------------------

    def _reset_recv_buf(self) -> None:
        """Release an oversized receive buffer back to its default capacity."""
        if len(self._recv_buf) > _RECV_BUF_SIZE:
            self._recv_buf = bytearray(_RECV_BUF_SIZE)
            self._recv_view = memoryview(self._recv_buf)
        self._recv_start = 0
        self._recv_end = 0

    def _has_buffered(self) -> bool:
        if self._recv_end > self._recv_start:
            return True
        return self._is_ssl and self._sock.pending() > 0

    def _poll_readable(self, timeout: float) -> bool:
        if self._has_buffered():
            return True
        readable, _, _ = select.select([self._sock], [], [], timeout)
        return bool(readable)

    def _ensure(self, n: int) -> None:
        """Ensure at least n bytes are buffered, filling from the socket as needed."""
        if self._sock is None:
            raise SeedLinkError("Not connected")
        available = self._recv_end - self._recv_start
        if available >= n:
            return
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
        while self._recv_end - self._recv_start < n:
            try:
                chunk = self._sock.recv_into(self._recv_view[self._recv_end:])
            except socket.timeout as e:
                partial = self._recv_end - self._recv_start
                if partial > 0:
                    self.close()
                    raise SeedLinkTimeout(
                        f"Timeout after partial read ({partial}/{n} bytes); connection closed"
                    ) from e
                raise SeedLinkTimeout(f"Timed out waiting for {n} bytes") from e
            except OSError as e:
                self.close()
                raise SeedLinkError(f"recv failed: {e}") from e
            if not chunk:
                self.close()
                raise SeedLinkError("Connection closed")
            self._recv_end += chunk

    def _peek(self, n: int) -> bytes:
        self._ensure(n)
        return bytes(self._recv_view[self._recv_start:self._recv_start + n])

    def _take(self, n: int) -> bytes:
        self._ensure(n)
        data = bytes(self._recv_view[self._recv_start:self._recv_start + n])
        self._recv_start += n
        return data

    def _read_line(self) -> str:
        """Read up through the next b'\\r\\n', returning the text before it.

        Searches the buffer in place (no copy) each pass, resuming from
        where the previous pass left off, and gives up once the pending
        line exceeds ``MAX_LINE_LEN`` -- otherwise a peer that never sends
        a terminator would grow the receive buffer without bound.
        """
        search_from = 0
        while True:
            available = self._recv_end - self._recv_start
            idx = self._recv_buf.find(b"\r\n", self._recv_start + search_from, self._recv_end)
            if idx >= 0:
                line = bytes(self._recv_buf[self._recv_start:idx])
                self._recv_start = idx + 2
                try:
                    return line.decode("ascii")
                except UnicodeDecodeError as e:
                    self.close()
                    raise SeedLinkError(f"Reply is not ASCII: {line!r}") from e
            if available >= MAX_LINE_LEN:
                self.close()
                raise SeedLinkError(f"Reply line exceeds {MAX_LINE_LEN} bytes with no terminator")
            search_from = max(0, available - 1)
            self._ensure(available + 1)

    def _send_command(self, cmd: Command) -> Any:
        if self._sock is None:
            raise SeedLinkError("Not connected")
        wire = cmd.text.encode("ascii") + cmd.terminator
        if len(wire) > MAX_COMMAND_LEN:
            raise SeedLinkError(
                f"Command exceeds the {MAX_COMMAND_LEN}-byte command-line limit: {cmd.text!r}"
            )
        logger.debug("--> %s", cmd.text)
        try:
            self._sock.sendall(wire)
        except OSError as e:
            self.close()
            raise SeedLinkError(f"send failed: {e}") from e
        if cmd.parse is None:
            return None
        line = self._read_line()
        logger.debug("<-- %s", line)
        return cmd.parse(line)

    # -- Packet framing -----------------------------------------------------

    def _classify_next(self) -> StreamEvent:
        """Classify the next bytes, peeking incrementally so a bare 3-byte
        dial-up END with nothing behind it doesn't block waiting for a
        5-byte peek."""
        self._ensure(2)
        first, second = self._recv_buf[self._recv_start], self._recv_buf[self._recv_start + 1]
        if first == _ORD_S and second in (_ORD_L, _ORD_E):
            return StreamEvent.PACKET  # steady state: 'SL'/'SE' packet signature
        if first == _ORD_E:
            event = classify_stream_prefix(self._peek(3))
            if event is StreamEvent.OTHER:
                event = classify_stream_prefix(self._peek(5))
            if event in (StreamEvent.END, StreamEvent.ERROR):
                return event
        prefix = bytes(self._recv_view[self._recv_start:self._recv_start + 1])
        raise SeedLinkError(f"Unexpected data in stream: {prefix!r}")

    def _read_mseed_payload(self) -> bytes:
        """Read one miniSEED record for a v3 packet, whose header carries no length."""
        size = MIN_PAYLOAD_DETECT
        while True:
            result = mseed.detect_record_length(self._peek(size))
            if result is not None:
                reclen, _formatversion = result
                return self._take(reclen)
            if size >= MAX_RECORD_LEN:
                raise SeedLinkError("Could not determine miniSEED record length")
            size = min(size * 2, MAX_RECORD_LEN)

    def _recv_frame_v3(self) -> _RawFrame:
        header = parse_header_v3(self._take(HEADSIZE_V3))
        payload = self._read_mseed_payload()
        if header.is_info:
            text = mseed.extract_info_text(payload)
            return _RawFrame(
                station_id="", seqnum=None, payload_format=FORMAT_XML,
                payload_subformat=SUBFORMAT_JSON_INFO, payload=text.encode("utf-8"),
                info_continues=header.info_continues,
            )
        record = mseed.parse_record(payload)
        return _RawFrame(
            station_id=mseed.station_id(record), seqnum=header.seqnum,
            payload_format="2", payload_subformat="D", payload=payload,
            info_continues=False, record=record,
        )

    def _recv_frame_v4(self) -> _RawFrame:
        # A single _ensure() for the whole frame, rather than one per field,
        # avoids repeatedly re-walking _ensure()'s compaction/grow logic and
        # copying each field out separately.
        self._ensure(HEADSIZE_V4)
        header = parse_header_v4(self._recv_view[self._recv_start:self._recv_start + HEADSIZE_V4])
        total = HEADSIZE_V4 + header.station_id_length + header.payload_length
        self._ensure(total)
        pos = self._recv_start + HEADSIZE_V4
        if header.station_id_length:
            station_id = bytes(self._recv_view[pos:pos + header.station_id_length]).decode("ascii")
            pos += header.station_id_length
        else:
            station_id = ""
        payload = bytes(self._recv_view[pos:pos + header.payload_length])
        self._recv_start += total
        return _RawFrame(
            station_id=station_id, seqnum=header.seqnum,
            payload_format=header.payload_format, payload_subformat=header.payload_subformat,
            payload=payload, info_continues=False,
        )

    def _recv_frame(self) -> _RawFrame | SeedLinkResponse | None:
        """Read one frame: a data/INFO packet, an ERROR reply, or None (dial-up END)."""
        event = self._classify_next()
        if event is StreamEvent.END:
            self._take(3)
            logger.debug("<-- END")
            result = None
        elif event is StreamEvent.ERROR:
            line = self._read_line()
            logger.debug("<-- %s", line)
            result = parse_reply(line)
        else:
            result = self._recv_frame_v4() if self.protocol is Protocol.V4 else self._recv_frame_v3()
            logger.debug("<-- packet station=%s seq=%s format=%s%s (%d bytes)",
                         result.station_id or "-", result.seqnum, result.payload_format,
                         result.payload_subformat, len(result.payload))
        # A large payload's buffer would otherwise be pinned for the life of
        # the connection: _ensure() only shrinks it on entry with nothing
        # buffered, which a continuously busy connection may never reach.
        if self._recv_start == self._recv_end:
            self._reset_recv_buf()
        return result

    def _to_packet(self, frame: _RawFrame) -> SeedLinkPacket:
        pkt = SeedLinkPacket(
            station_id=frame.station_id, seqnum=frame.seqnum,
            payload_format=frame.payload_format, payload_subformat=frame.payload_subformat,
            payload=frame.payload,
        )
        if frame.record is not None:
            pkt._record = frame.record
        return pkt

    # -- Negotiation ----------------------------------------------------------

    def negotiate(self) -> None:
        """Select streams and start streaming: STATION/SELECT/DATA, then END.

        Raises:
            SeedLinkError: if no station was accepted (v3 multi-station), or
                (v4) if any STATION/SELECT/DATA command was rejected.
        """
        self._match_cache.clear()
        if not self._streams:
            self._streams = [Stream(station_id="*")]
        plan = _commands.plan_negotiation(
            self.protocol, sort_streams(self._streams), self._dialup, self._multistation,
            resume=True, lastpkttime=True, batch_active=self._batch_active,
            start_time=self._start_time, end_time=self._end_time,
        )
        accepted_any_station = False
        seen_station_role = False
        skip_stream = False
        for cmd in plan:
            if cmd.role == "station":
                seen_station_role = True
                skip_stream = False
            elif skip_stream and cmd.role in ("select", "data"):
                continue
            resp = self._send_command(cmd)
            if cmd.role == "station":
                if resp is not None and not resp:
                    logger.warning("Station %s rejected: %s", cmd.stream_id, resp.message)
                    skip_stream = True
                    continue
                accepted_any_station = True
            elif cmd.role in ("select", "data") and resp is not None and not resp:
                logger.warning("%s rejected for %s: %s", cmd.role, cmd.stream_id, resp.message)
        if seen_station_role and not accepted_any_station:
            raise SeedLinkError("No stations accepted")
        self._streaming = True

    def _update_stream_state(self, pkt: SeedLinkPacket) -> None:
        if pkt.seqnum is None:
            return
        for stream in self._streams_matching(pkt.station_id):
            stream.seqnum = pkt.seqnum
            # Deferred: the packet is only parsed for its start time if
            # stream.timestamp is actually read (see Stream._get_timestamp).
            stream._ts_pkt = pkt

    def _reconnect_after_delay(self) -> None:
        time.sleep(self._reconnect_delay)
        while True:
            try:
                self.connect()
                self.negotiate()
                return
            except SeedLinkAuthError:
                raise
            except SeedLinkError as e:
                logger.warning("Reconnect to %s:%d failed: %s; retrying in %.0fs",
                                self._host, self._port, e, self._reconnect_delay)
                self.close()
                time.sleep(self._reconnect_delay)

    def collect(self, reconnect: bool = True) -> Generator[SeedLinkPacket, None, None]:
        """Streaming generator: yields a SeedLinkPacket for each data packet received.

        Negotiates automatically on first use if not already streaming.
        Updates each matching stream's sequence number and timestamp as
        packets arrive, so :meth:`~seedlink_client._base._SeedLinkBase.save_state`
        is always current and a reconnect resumes where it left off.

        An INFO ID heartbeat is sent every ``keepalive`` seconds (its reply
        is consumed internally, never yielded); the connection is dropped
        and retried after ``reconnect_delay`` seconds if no data arrives for
        ``idle_timeout`` seconds, unless ``reconnect`` is False.

        Args:
            reconnect: If True (default), transparently reconnect and
                resume on any error or idle timeout. If False, raise
                instead -- and dial-up end-of-stream simply ends iteration
                either way.
        """
        if not self._streaming:
            self.negotiate()
        last_data_time = time.monotonic()
        next_keepalive = (time.monotonic() + self._keepalive) if self._keepalive else None
        while True:
            if self._sock is None:
                if not reconnect:
                    return
                self._reconnect_after_delay()
                last_data_time = time.monotonic()
                next_keepalive = (time.monotonic() + self._keepalive) if self._keepalive else None
                continue

            if not self._poll_readable(_POLL_INTERVAL):
                now = time.monotonic()
                if now - last_data_time > self._idle_timeout:
                    logger.warning("No data for over %.0fs, reconnecting", self._idle_timeout)
                    self.close()
                    if not reconnect:
                        raise SeedLinkTimeout(f"No data for over {self._idle_timeout:.0f}s")
                    continue
                if next_keepalive is not None and now >= next_keepalive:
                    next_keepalive = now + self._keepalive
                    try:
                        self._send_command(_commands.info("ID"))
                    except SeedLinkError:
                        self.close()
                continue

            try:
                frame = self._recv_frame()
            except SeedLinkError:
                self.close()
                if not reconnect:
                    raise
                continue

            if frame is None:  # dial-up end of stream
                self._streaming = False
                return
            if isinstance(frame, SeedLinkResponse):  # mid-stream ERROR line
                logger.warning("Server error during streaming: %s", frame.message)
                self.close()
                if not reconnect:
                    raise SeedLinkError(frame.message or "Stream error", frame.code)
                continue

            if frame.payload_format == FORMAT_XML or (
                frame.payload_format == FORMAT_JSON and frame.payload_subformat == SUBFORMAT_JSON_INFO
            ):
                continue  # our own (or an interleaved) INFO reply; never yielded -- and
                # doesn't reset the idle-timeout clock, which tracks data, not keepalives
            last_data_time = time.monotonic()
            pkt = self._to_packet(frame)
            self._update_stream_state(pkt)
            yield pkt

    # -- INFO -----------------------------------------------------------------

    def info(self, level: str) -> str:
        """Send INFO <level> and return the raw reply text (JSON for v4, XML for v3).

        Raises:
            SeedLinkError: if called while streaming -- the keepalive
                mechanism handles periodic INFO requests automatically;
                call this only in query mode, before :meth:`collect`.
        """
        if self._streaming:
            raise SeedLinkError("Cannot call info() while streaming")
        self._send_command(_commands.info(level))
        chunks = []
        while True:
            frame = self._recv_frame()
            if not isinstance(frame, _RawFrame) or frame.payload_format not in (FORMAT_JSON, FORMAT_XML):
                raise SeedLinkError("Expected an INFO reply")
            chunks.append(frame.payload.decode("utf-8", errors="replace"))
            if not frame.info_continues:
                break
        return "".join(chunks)

    def info_dict(self, level: str) -> dict[str, Any]:
        """Like :meth:`info`, decoded to a dict.

        The shape reflects the negotiated protocol's native reply: parsed
        JSON for v4, a generic attribute/element walk of the XML for v3
        (see :func:`~seedlink_client.protocol.parse_info_xml`).
        """
        text = self.info(level)
        if self.protocol is Protocol.V4:
            return json.loads(text)
        return parse_info_xml(text)
