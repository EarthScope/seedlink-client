"""SeedLink protocol client (query and streaming modes), socket transport."""

from __future__ import annotations

import json
import logging
import select
import socket
import ssl
import time
from collections.abc import Generator
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
    MAX_RECORD_LEN,
    MIN_PAYLOAD_DETECT,
    Protocol,
    SeedLinkAuthError,
    SeedLinkError,
    SeedLinkPacket,
    SeedLinkResponse,
    SeedLinkTimeout,
    StreamEvent,
    _RawFrame,
    classify_stream_prefix,
    decode_frame_v3,
    decode_frame_v4_body,
    is_packet_signature,
    parse_header_v3,
    parse_header_v4,
    parse_info_xml,
    parse_reply,
    scan_line,
    select_protocol,
)
from .streams import sort_streams

logger = logging.getLogger(__name__)

# How often the streaming loop wakes up to check the keepalive/idle-timeout
# clocks when no data is arriving.
_POLL_INTERVAL = 1.0


class SeedLink(_SeedLinkBase):
    """SeedLink protocol client, transparently supporting both v3.x and v4.0.

    Supports both uni-station and multi-station selection, time-window and
    sequence-number resumption, dial-up mode, v3 BATCH mode, v4 AUTH, and
    INFO queries -- whichever the negotiated protocol version provides.

    The connection starts unconfigured. Call :meth:`add_stream` (or
    :meth:`set_all_stations`) to select what to receive, then
    :meth:`collect` to start streaming (it negotiates automatically on
    first use).

    See :meth:`_SeedLinkBase.__init__` for the full argument and attribute
    documentation, shared with :class:`~seedlink_client.aio.AsyncSeedLink`.
    """

    def _init_transport(self) -> None:
        self._sock: socket.socket | None = None
        self._is_ssl = False

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

    def _do_hello(self, promote_protocol: bool = True) -> None:
        """Send HELLO and store the server's identity.

        promote_protocol decides the negotiated version locally, but that's
        only real once SLPROTO has actually been sent and acknowledged (see
        plan_handshake()); callers driving the handshake by hand (the
        interactive shell) pass False and upgrade explicitly instead.
        """
        self._send_command(_commands.hello())
        line1 = self._read_line()
        line2 = self._read_line()
        logger.debug("<-- %s", line1)
        logger.debug("<-- %s", line2)
        self._store_identity(line1, line2)
        if promote_protocol:
            self.protocol = select_protocol(self._server_protocol_majors, self._requested_protocol)

    def connect(self, handshake: bool = True) -> None:
        """Open the connection: TCP/TLS, and by default HELLO plus the
        protocol handshake.

        Args:
            handshake: If False, only open the TCP/TLS socket -- skip HELLO
                and the post-HELLO handshake (SLPROTO/USERAGENT/AUTH/
                CAPABILITIES/BATCH), for driving the raw protocol by hand.

        Raises:
            SeedLinkAuthError: if AUTH is configured and rejected.
            SeedLinkError: on any other connection or handshake failure.
        """
        self._connect_socket()
        if not handshake:
            return
        try:
            self._do_hello()
            handshake_cmds = _commands.plan_handshake(
                self.protocol, self.server_capabilities, self._clientname,
                self._clientversion, self._auth, self._want_batch,
            )
            for cmd in handshake_cmds:
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

    def ping(self) -> tuple[str | None, str | None]:
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
        if self._prepare_room(n):
            return
        while self._recv_end - self._recv_start < n:
            try:
                chunk = self._sock.recv_into(self._recv_view[self._recv_end:])
            except TimeoutError as e:
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
        """Read up through the next b'\\r\\n', returning the text before it."""
        search_from = 0
        while True:
            try:
                result = scan_line(self._recv_buf, self._recv_start, self._recv_end, search_from)
            except SeedLinkError:
                self.close()
                raise
            if result is not None:
                line, new_start = result
                self._recv_start = new_start
                return line
            available = self._recv_end - self._recv_start
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
        if is_packet_signature(first, second):
            return StreamEvent.PACKET  # steady state: 'SL'/'SE' packet signature
        if first == ord("E"):
            event = classify_stream_prefix(self._peek(3))
            if event is StreamEvent.OTHER:
                event = classify_stream_prefix(self._peek(5))
            if event in (StreamEvent.END, StreamEvent.ERROR):
                return event
        prefix = bytes(self._recv_view[self._recv_start:self._recv_start + 2])
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
        return decode_frame_v3(header, payload)

    def _recv_frame_v4(self) -> _RawFrame:
        # A single _ensure() for the whole frame, rather than one per field,
        # avoids repeatedly re-walking _ensure()'s compaction/grow logic and
        # copying each field out separately.
        self._ensure(HEADSIZE_V4)
        header = parse_header_v4(self._recv_view[self._recv_start:self._recv_start + HEADSIZE_V4])
        total = HEADSIZE_V4 + header.station_id_length + header.payload_length
        self._ensure(total)
        frame = decode_frame_v4_body(self._recv_view, self._recv_start, header)
        self._recv_start += total
        return frame

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

    # -- Negotiation ----------------------------------------------------------

    def negotiate(self) -> None:
        """Select streams and start streaming: STATION/SELECT/DATA, then END.

        Raises:
            SeedLinkError: if no station was accepted (v3 multi-station), or
                (v4) if any STATION/SELECT/DATA command was rejected.
        """
        self._match_cache.clear()
        self._ensure_default_stream()
        plan = _commands.plan_negotiation(
            self.protocol, sort_streams(self._streams), self._dialup, self._multistation,
            resume=True, lastpkttime=True, batch_active=self._batch_active,
            start_time=self._start_time, end_time=self._end_time,
        )
        walk = _commands.NegotiationWalk()
        for cmd in plan:
            if not walk.should_send(cmd):
                continue
            resp = self._send_command(cmd)
            walk.record(cmd, resp)
        walk.finish()
        self._streaming = True

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

        Breaking out of the ``for`` loop early (or otherwise letting this
        generator get garbage-collected mid-stream) closes the connection,
        same as calling :meth:`close` directly.
        """
        try:
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

                # Checked every pass, not just when nothing is readable -- a
                # server sending only INFO/keepalive replies (no real data)
                # would otherwise keep the socket readable forever and this
                # timeout would never get a chance to fire.
                now = time.monotonic()
                if now - last_data_time > self._idle_timeout:
                    logger.warning("No data for over %.0fs, reconnecting", self._idle_timeout)
                    self.close()
                    if not reconnect:
                        raise SeedLinkTimeout(f"No data for over {self._idle_timeout:.0f}s")
                    continue

                if not self._poll_readable(_POLL_INTERVAL):
                    now = time.monotonic()
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
                if self._is_json_error_frame(frame):  # v4 JSON ERROR packet
                    message = self._json_error_message(frame.payload)
                    logger.warning("Server error during streaming: %s", message)
                    self.close()
                    if not reconnect:
                        raise SeedLinkError(message)
                    continue

                if self._is_info_frame(frame):
                    continue  # our own (or an interleaved) INFO reply; never yielded -- and
                    # doesn't reset the idle-timeout clock, which tracks data, not keepalives
                last_data_time = time.monotonic()
                pkt = self._to_packet(frame)
                self._update_stream_state(pkt)
                yield pkt
        except GeneratorExit:
            self.close()
            raise

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
