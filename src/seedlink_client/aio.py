"""SeedLink protocol client (query and streaming modes), asyncio transport.

A deliberate mirror of :mod:`seedlink_client.client`: same structure, same
method names, coroutines and an async generator in place of blocking
calls, and the same persistent-buffer approach (rather than relying on
:class:`asyncio.StreamReader` internals, which have no public peek).

Cancellation is handled at exactly two levels: :meth:`collect` polls for
the next frame's first byte with a short :func:`asyncio.wait_for` timeout
to check the keepalive/idle-timeout clocks -- an expected, non-fatal
``TimeoutError`` that never touches the connection, since it only ever
fires between frames, never mid-frame -- and every public method's body is
wrapped so that a genuine external ``CancelledError`` (the caller cancelling
the whole call) closes the connection before propagating, since a
cancelled read cannot be resumed mid-frame.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from collections.abc import AsyncGenerator
from typing import Any

from . import _commands, mseed
from ._base import _SeedLinkBase
from ._commands import Command
from .client import _RawFrame
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

_RECV_BUF_SIZE = 65536
_POLL_INTERVAL = 1.0

# First-byte values of a v3/v4 packet signature ('S' + 'L' or 'E'), checked
# directly against the receive buffer in _classify_next() so the steady
# state of packet-after-packet streaming never allocates a bytes object.
_ORD_S = ord("S")
_ORD_L = ord("L")
_ORD_E = ord("E")


class AsyncSeedLink(_SeedLinkBase):
    """Asyncio SeedLink client, offering the same API as :class:`~seedlink_client.client.SeedLink`.

    See :class:`~seedlink_client.client.SeedLink` for the full argument and
    attribute documentation, identical here.
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
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._recv_buf = bytearray(_RECV_BUF_SIZE)
        self._recv_view = memoryview(self._recv_buf)
        self._recv_start = 0
        self._recv_end = 0

    @property
    def is_connected(self) -> bool:
        return self._writer is not None

    async def __aenter__(self) -> AsyncSeedLink:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # -- Connection lifecycle ---------------------------------------------

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if self._tls_noverify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    async def _connect_socket(self) -> None:
        if self._writer is not None:
            raise SeedLinkError("Already connected")
        try:
            reader, writer = await asyncio.open_connection(
                self._host, self._port,
                ssl=self._ssl_context() if self._tls else None,
                server_hostname=self._host if self._tls else None,
            )
        except ssl.SSLCertVerificationError as e:
            raise SeedLinkError(
                f"TLS certificate verification failed for {self._host}:{self._port}: "
                f"{e.verify_message}. Use tls_noverify=True to skip verification "
                f"(insecure, e.g. for self-signed certificates)"
            ) from e
        except (ssl.SSLError, OSError) as e:
            raise SeedLinkError(f"Could not connect to {self._host}:{self._port}: {e}") from e
        sock = writer.get_extra_info("socket")
        if sock is not None:
            import socket as socket_module

            sock.setsockopt(socket_module.IPPROTO_TCP, socket_module.TCP_NODELAY, 1)
        self._reader = reader
        self._writer = writer
        self._reset_recv_buf()
        logger.debug("Connected to %s:%d%s", self._host, self._port, " (TLS)" if self._tls else "")

    async def _do_hello(self) -> None:
        await self._send_command(_commands.hello())
        line1 = await self._read_line()
        line2 = await self._read_line()
        self._store_identity(line1, line2)
        self.protocol = select_protocol(self._server_protocol_majors, self._requested_protocol)

    async def connect(self) -> None:
        """Open the connection: TCP/TLS, HELLO, and protocol handshake."""
        try:
            async with self._timeout_scope():
                await self._connect_socket()
                await self._do_hello()
                handshake = _commands.plan_handshake(
                    self.protocol, self.server_capabilities, self._clientname,
                    self._clientversion, self._auth, self._want_batch,
                )
                for cmd in handshake:
                    resp = await self._send_command(cmd)
                    if cmd.text == "BATCH":
                        self._batch_active = bool(resp)
        except asyncio.CancelledError:
            await self.close()
            raise
        except TimeoutError as e:
            await self.close()
            raise SeedLinkTimeout(f"Timed out connecting to {self._host}:{self._port}") from e
        except SeedLinkError:
            await self.close()
            raise

    async def close(self) -> None:
        """Gracefully close the connection.

        State is cleared before the awaited ``wait_closed()`` so a
        cancellation landing on that await still leaves the client in a
        consistent, reconnectable disconnected state.
        """
        writer = self._writer
        self._reader = None
        self._writer = None
        self._streaming = False
        self._batch_active = False
        self._reset_recv_buf()
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def reconnect(self) -> None:
        """Close the current connection (if any), reconnect, and re-negotiate."""
        await self.close()
        await self.connect()
        if self._streams:
            await self.negotiate()

    async def ping(self) -> tuple[str, str]:
        """Connect, HELLO, report identity, and disconnect. No stream setup."""
        try:
            async with self._timeout_scope():
                await self._connect_socket()
                await self._do_hello()
        except TimeoutError as e:
            raise SeedLinkTimeout(f"Timed out pinging {self._host}:{self._port}") from e
        finally:
            await self.close()
        return self.server_id, self.organization

    async def bye(self) -> None:
        """Send BYE to gracefully notify the server before disconnecting."""
        if self._writer is not None:
            await self._send_command(_commands.bye())

    def _timeout_scope(self):
        """Context manager applying ``self._timeout`` if set, else a no-op."""
        return asyncio.timeout(self._timeout) if self._timeout is not None else _NoTimeout()

    # -- Byte-level transport ----------------------------------------------

    def _reset_recv_buf(self) -> None:
        if len(self._recv_buf) > _RECV_BUF_SIZE:
            self._recv_buf = bytearray(_RECV_BUF_SIZE)
            self._recv_view = memoryview(self._recv_buf)
        self._recv_start = 0
        self._recv_end = 0

    async def _ensure(self, n: int) -> None:
        """Ensure at least n bytes are buffered, filling from the socket as needed.

        No timeout/cancellation handling here -- callers wrap the operation
        that needs one (:meth:`_timeout_scope` for handshake-phase calls,
        :func:`asyncio.wait_for` with ``_POLL_INTERVAL`` for the streaming
        poll in :meth:`collect`), so a poll's expected, harmless
        cancellation never has to be told apart from a real failure here.
        """
        if self._reader is None:
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
                chunk = await self._reader.read(len(self._recv_buf) - self._recv_end)
            except OSError as e:
                await self.close()
                raise SeedLinkError(f"recv failed: {e}") from e
            if not chunk:
                await self.close()
                raise SeedLinkError("Connection closed")
            self._recv_view[self._recv_end:self._recv_end + len(chunk)] = chunk
            self._recv_end += len(chunk)

    async def _peek(self, n: int) -> bytes:
        await self._ensure(n)
        return bytes(self._recv_view[self._recv_start:self._recv_start + n])

    async def _read_exact(self, n: int) -> bytes:
        await self._ensure(n)
        data = bytes(self._recv_view[self._recv_start:self._recv_start + n])
        self._recv_start += n
        return data

    async def _read_line(self) -> str:
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
                    await self.close()
                    raise SeedLinkError(f"Reply is not ASCII: {line!r}") from e
            if available >= MAX_LINE_LEN:
                await self.close()
                raise SeedLinkError(f"Reply line exceeds {MAX_LINE_LEN} bytes with no terminator")
            search_from = max(0, available - 1)
            await self._ensure(available + 1)

    async def _send_command(self, cmd: Command) -> Any:
        if self._writer is None:
            raise SeedLinkError("Not connected")
        wire = cmd.text.encode("ascii") + cmd.terminator
        if len(wire) > MAX_COMMAND_LEN:
            raise SeedLinkError(
                f"Command exceeds the {MAX_COMMAND_LEN}-byte command-line limit: {cmd.text!r}"
            )
        try:
            self._writer.write(wire)
            await self._writer.drain()
        except OSError as e:
            await self.close()
            raise SeedLinkError(f"send failed: {e}") from e
        if cmd.parse is None:
            return None
        return cmd.parse(await self._read_line())

    # -- Packet framing -----------------------------------------------------

    async def _classify_next(self) -> StreamEvent:
        """Classify the next bytes, peeking incrementally so a bare 3-byte
        dial-up END with nothing behind it doesn't block waiting for a
        5-byte peek."""
        await self._ensure(2)
        first, second = self._recv_buf[self._recv_start], self._recv_buf[self._recv_start + 1]
        if first == _ORD_S and second in (_ORD_L, _ORD_E):
            return StreamEvent.PACKET  # steady state: 'SL'/'SE' packet signature
        if first == _ORD_E:
            event = classify_stream_prefix(await self._peek(3))
            if event is StreamEvent.OTHER:
                event = classify_stream_prefix(await self._peek(5))
            if event in (StreamEvent.END, StreamEvent.ERROR):
                return event
        prefix = bytes(self._recv_view[self._recv_start:self._recv_start + 1])
        raise SeedLinkError(f"Unexpected data in stream: {prefix!r}")

    async def _read_mseed_payload(self) -> bytes:
        size = MIN_PAYLOAD_DETECT
        while True:
            result = mseed.detect_record_length(await self._peek(size))
            if result is not None:
                reclen, _formatversion = result
                return await self._read_exact(reclen)
            if size >= MAX_RECORD_LEN:
                raise SeedLinkError("Could not determine miniSEED record length")
            size = min(size * 2, MAX_RECORD_LEN)

    async def _recv_frame_v3(self) -> _RawFrame:
        header = parse_header_v3(await self._read_exact(HEADSIZE_V3))
        payload = await self._read_mseed_payload()
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

    async def _recv_frame_v4(self) -> _RawFrame:
        # A single _ensure() for the whole frame, rather than one per field,
        # avoids repeatedly re-walking _ensure()'s compaction/grow logic and
        # copying each field out separately.
        await self._ensure(HEADSIZE_V4)
        header = parse_header_v4(self._recv_view[self._recv_start:self._recv_start + HEADSIZE_V4])
        total = HEADSIZE_V4 + header.station_id_length + header.payload_length
        await self._ensure(total)
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

    async def _recv_frame(self) -> _RawFrame | SeedLinkResponse | None:
        """Read one frame: a data/INFO packet, an ERROR reply, or None (dial-up END)."""
        event = await self._classify_next()
        if event is StreamEvent.END:
            await self._read_exact(3)
            result = None
        elif event is StreamEvent.ERROR:
            result = parse_reply(await self._read_line())
        else:
            result = await self._recv_frame_v4() if self.protocol is Protocol.V4 else await self._recv_frame_v3()
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

    async def negotiate(self) -> None:
        """Select streams and start streaming: STATION/SELECT/DATA, then END."""
        try:
            async with self._timeout_scope():
                await self._negotiate()
        except asyncio.CancelledError:
            await self.close()
            raise
        except TimeoutError as e:
            await self.close()
            raise SeedLinkTimeout("Timed out negotiating stream selection") from e

    async def _negotiate(self) -> None:
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
            resp = await self._send_command(cmd)
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

    async def _reconnect_after_delay(self) -> None:
        await asyncio.sleep(self._reconnect_delay)
        while True:
            try:
                await self.connect()
                await self.negotiate()
                return
            except SeedLinkAuthError:
                raise
            except SeedLinkError as e:
                logger.warning("Reconnect to %s:%d failed: %s; retrying in %.0fs",
                                self._host, self._port, e, self._reconnect_delay)
                await self.close()
                await asyncio.sleep(self._reconnect_delay)

    async def collect(self, reconnect: bool = True) -> AsyncGenerator[SeedLinkPacket, None]:
        """Streaming async generator: yields a SeedLinkPacket per data packet.

        See :meth:`~seedlink_client.client.SeedLink.collect` for full
        behavior -- identical here, as a coroutine/async generator. The
        wait for the next frame is polled with a short internal timeout to
        check the keepalive/idle-timeout clocks; that expected timeout
        never closes the connection, unlike a genuine external cancellation
        of this generator itself, which does.
        """
        try:
            if not self._streaming:
                await self.negotiate()
            last_data_time = time.monotonic()
            next_keepalive = (time.monotonic() + self._keepalive) if self._keepalive else None
            while True:
                if self._writer is None:
                    if not reconnect:
                        return
                    await self._reconnect_after_delay()
                    last_data_time = time.monotonic()
                    next_keepalive = (time.monotonic() + self._keepalive) if self._keepalive else None
                    continue

                try:
                    # Wait for the next frame to start, not for it to finish --
                    # once a byte has arrived, _recv_frame() below reads the
                    # rest of that frame with no timeout, exactly like the
                    # sync client's _poll_readable()-then-_recv_frame() split.
                    # Timing out (or cancelling) a read already in progress
                    # would leave _recv_start advanced mid-frame.
                    await asyncio.wait_for(self._ensure(1), timeout=_POLL_INTERVAL)
                except TimeoutError:
                    now = time.monotonic()
                    if now - last_data_time > self._idle_timeout:
                        logger.warning("No data for over %.0fs, reconnecting", self._idle_timeout)
                        await self.close()
                        if not reconnect:
                            raise SeedLinkTimeout(f"No data for over {self._idle_timeout:.0f}s") from None
                        continue
                    if next_keepalive is not None and now >= next_keepalive:
                        next_keepalive = now + self._keepalive
                        try:
                            await self._send_command(_commands.info("ID"))
                        except SeedLinkError:
                            await self.close()
                    continue
                except SeedLinkError:
                    await self.close()
                    if not reconnect:
                        raise
                    continue

                try:
                    frame = await self._recv_frame()
                except SeedLinkError:
                    await self.close()
                    if not reconnect:
                        raise
                    continue

                if frame is None:  # dial-up end of stream
                    self._streaming = False
                    return
                if isinstance(frame, SeedLinkResponse):  # mid-stream ERROR line
                    logger.warning("Server error during streaming: %s", frame.message)
                    await self.close()
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
        except asyncio.CancelledError:
            await self.close()
            raise

    # -- INFO -----------------------------------------------------------------

    async def info(self, level: str) -> str:
        """Send INFO <level> and return the raw reply text (JSON for v4, XML for v3).

        Raises:
            SeedLinkError: if called while streaming -- the keepalive
                mechanism handles periodic INFO requests automatically;
                call this only in query mode, before :meth:`collect`.
        """
        if self._streaming:
            raise SeedLinkError("Cannot call info() while streaming")
        try:
            async with self._timeout_scope():
                await self._send_command(_commands.info(level))
                chunks = []
                while True:
                    frame = await self._recv_frame()
                    if not isinstance(frame, _RawFrame) or frame.payload_format not in (FORMAT_JSON, FORMAT_XML):
                        raise SeedLinkError("Expected an INFO reply")
                    chunks.append(frame.payload.decode("utf-8", errors="replace"))
                    if not frame.info_continues:
                        break
                return "".join(chunks)
        except asyncio.CancelledError:
            await self.close()
            raise
        except TimeoutError as e:
            await self.close()
            raise SeedLinkTimeout(f"Timed out waiting for INFO {level} reply") from e

    async def info_dict(self, level: str) -> dict[str, Any]:
        """Like :meth:`info`, decoded to a dict; see the sync client for the shape note."""
        text = await self.info(level)
        if self.protocol is Protocol.V4:
            return json.loads(text)
        return parse_info_xml(text)


class _NoTimeout:
    """No-op async context manager, used when ``self._timeout`` is None."""

    async def __aenter__(self):
        return None

    async def __aexit__(self, *exc_info):
        return False
