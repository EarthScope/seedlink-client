"""Tests for seedlink_client.aio.AsyncSeedLink.

These drive a real loopback asyncio.start_server speaking minimal SeedLink
v4, rather than mocking asyncio internals -- the transport is thin enough
that a real socket round-trip is both simpler and more trustworthy than a
mock. Uses asyncio.run() inside ordinary test functions so no
pytest-asyncio dependency is needed.
"""

from __future__ import annotations

import asyncio
import inspect
import struct
from unittest.mock import AsyncMock, MagicMock

import pytest

from seedlink_client.aio import AsyncSeedLink
from seedlink_client.client import SeedLink
from seedlink_client.protocol import (
    FORMAT_JSON,
    FORMAT_XML,
    SUBFORMAT_JSON_ERROR,
    SUBFORMAT_JSON_INFO,
    Protocol,
    SeedLinkError,
    SeedLinkTimeout,
    _RawFrame,
    _UndecodablePacket,
)


def run(coro):
    """Run a coroutine to completion; thin wrapper for readability."""
    return asyncio.run(coro)


def _v4_frame(payload: bytes, station_id: str = "IU_KONO", seqnum: int = 1,
              fmt: str = "J", subfmt: str = "I") -> bytes:
    sid = station_id.encode("ascii")
    header = struct.pack("<2sccIQB", b"SE", fmt.encode(), subfmt.encode(),
                          len(payload), seqnum, len(sid))
    return header + sid + payload


class _LineReader:
    """Reads command lines from the client, tolerating either a '\\r\\n' or
    a bare '\\r' terminator -- v4's STATION/SELECT/DATA use a bare '\\r'
    on the wire (see _commands.station_v4 et al.), everything else '\\r\\n'.
    """

    def __init__(self, reader: asyncio.StreamReader):
        self._reader = reader
        self._buf = b""

    async def read_line(self) -> str:
        while b"\r" not in self._buf:
            chunk = await self._reader.read(4096)
            if not chunk:
                raise asyncio.IncompleteReadError(self._buf, None)
            self._buf += chunk
        line, _, rest = self._buf.partition(b"\r")
        if rest.startswith(b"\n"):
            rest = rest[1:]
        self._buf = rest
        return line.decode("ascii")


async def _serve_once(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


class TestConnectAndInfo:
    def test_v4_hello_and_info_id(self):
        async def scenario():
            async def handle(reader, writer):
                lines = _LineReader(reader)
                line = await lines.read_line()
                assert line == "HELLO"
                writer.write(b"SeedLink v4.0 (test) :: SLPROTO:4.0\r\n")
                writer.write(b"Test Server\r\n")
                await writer.drain()

                line = await lines.read_line()
                assert line == "SLPROTO 4.0"
                writer.write(b"OK\r\n")
                await writer.drain()

                line = await lines.read_line()
                assert line.startswith("USERAGENT")
                writer.write(b"OK\r\n")
                await writer.drain()

                line = await lines.read_line()
                assert line == "INFO ID"
                writer.write(_v4_frame(b'{"software":"test"}'))
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            async with AsyncSeedLink("127.0.0.1", port) as sl:
                assert sl.server_id == "SeedLink v4.0 (test)"
                assert sl.organization == "Test Server"
                info = await sl.info_dict("ID")
                assert info["software"] == "test"
            server.close()

        run(scenario())


class TestInfoErrors:
    def test_v4_json_error_raises(self):
        async def scenario():
            async def handle(reader, writer):
                lines = _LineReader(reader)
                assert await lines.read_line() == "INFO BOGUS"
                writer.write(_v4_frame(b'{"message": "unknown level"}', station_id="",
                                       fmt="J", subfmt="E"))
                await writer.drain()

            server, port = await _serve_once(handle)
            sl = AsyncSeedLink("127.0.0.1", port)
            await sl.connect(handshake=False)
            sl.protocol = Protocol.V4
            try:
                with pytest.raises(SeedLinkError, match="unknown level"):
                    await sl.info("BOGUS")
            finally:
                await sl.close()
                server.close()

        run(scenario())


class TestConnectHandshakeFlag:
    def test_handshake_false_sends_nothing(self):
        async def scenario():
            sent_something = asyncio.Event()

            async def handle(reader, writer):
                try:
                    data = await asyncio.wait_for(reader.read(100), timeout=0.3)
                    if data:
                        sent_something.set()
                except TimeoutError:
                    pass
                writer.close()

            server, port = await _serve_once(handle)
            sl = AsyncSeedLink("127.0.0.1", port, timeout=5)
            await sl.connect(handshake=False)
            assert sl.is_connected
            assert sl.protocol is None
            await asyncio.sleep(0.35)
            await sl.close()
            server.close()
            assert not sent_something.is_set()

        run(scenario())


class TestConnectWhileConnected:
    """B4 regression: connect()/ping() must not tear down an existing
    connection when called again while already connected."""

    async def _connect_to_idle_server(self):
        async def handle(reader, writer):
            writer.write(b"SeedLink v3.1\r\nTest Server\r\n")
            await writer.drain()
            await reader.read(1)  # keep the connection open until the client disconnects

        server, port = await _serve_once(handle)
        sl = AsyncSeedLink("127.0.0.1", port, timeout=5)
        await sl.connect()
        return sl, server

    def test_second_connect_raises_without_closing(self):
        async def scenario():
            sl, server = await self._connect_to_idle_server()
            assert sl.is_connected
            with pytest.raises(SeedLinkError, match="Already connected"):
                await sl.connect()
            assert sl.is_connected
            await sl.close()
            server.close()

        run(scenario())

    def test_ping_while_connected_raises_without_closing(self):
        async def scenario():
            sl, server = await self._connect_to_idle_server()
            assert sl.is_connected
            with pytest.raises(SeedLinkError, match="Already connected"):
                await sl.ping()
            assert sl.is_connected
            await sl.close()
            server.close()

        run(scenario())


class TestStreaming:
    def test_negotiate_and_collect_one_packet(self):
        async def scenario():
            async def handle(reader, writer):
                lines = _LineReader(reader)
                assert await lines.read_line() == "HELLO"
                writer.write(b"SeedLink v4.0 (test) :: SLPROTO:4.0\r\n")
                writer.write(b"Test Server\r\n")
                await writer.drain()
                assert await lines.read_line() == "SLPROTO 4.0"
                writer.write(b"OK\r\n")
                await writer.drain()
                assert (await lines.read_line()).startswith("USERAGENT")
                writer.write(b"OK\r\n")
                await writer.drain()

                assert await lines.read_line() == "STATION IU_KONO"
                writer.write(b"OK\r\n")
                await writer.drain()
                assert await lines.read_line() == "SELECT B_H_Z"
                writer.write(b"OK\r\n")
                await writer.drain()
                assert await lines.read_line() == "DATA"
                writer.write(b"OK\r\n")
                await writer.drain()
                assert await lines.read_line() == "END"

                writer.write(_v4_frame(b"waveformbytes", station_id="IU_KONO",
                                        seqnum=7, fmt="2", subfmt="D"))
                await writer.drain()
                writer.write(b"END")  # dial-up-style end for this test
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            async with AsyncSeedLink("127.0.0.1", port) as sl:
                sl.add_stream("IU_KONO", "B_H_Z")
                packets = []
                async for pkt in sl.collect(reconnect=False):
                    packets.append(pkt)
                assert len(packets) == 1
                assert packets[0].station_id == "IU_KONO"
                assert packets[0].seqnum == 7
                assert packets[0].payload == b"waveformbytes"
                # _update_stream_state() applied the seqnum via the memoized
                # station-match cache (see _SeedLinkBase._streams_matching).
                assert sl._streams[0].seqnum == 7
                assert sl._match_cache["IU_KONO"] == [sl._streams[0]]
            server.close()

        run(scenario())


class TestNegotiatePipelined:
    async def _handshake(self, reader, writer):
        lines = _LineReader(reader)
        assert await lines.read_line() == "HELLO"
        writer.write(b"SeedLink v4.0 (test) :: SLPROTO:4.0\r\nTest Server\r\n")
        await writer.drain()
        assert await lines.read_line() == "SLPROTO 4.0"
        writer.write(b"OK\r\n")
        await writer.drain()
        assert (await lines.read_line()).startswith("USERAGENT")
        writer.write(b"OK\r\n")
        await writer.drain()
        return lines

    def test_commands_arrive_before_any_reply(self):
        async def scenario():
            received = []
            done = asyncio.Event()

            async def handle(reader, writer):
                lines = await self._handshake(reader, writer)
                # No reply is sent until all three commands have arrived.
                for _ in range(3):
                    received.append(await lines.read_line())
                writer.write(b"OK\r\n" * 3)
                await writer.drain()
                received.append(await lines.read_line())
                done.set()
                writer.close()

            server, port = await _serve_once(handle)
            async with AsyncSeedLink("127.0.0.1", port, timeout=5) as sl:
                sl.add_stream("IU_KONO", "B_H_Z")
                await sl.negotiate()
                assert sl.is_streaming
                await asyncio.wait_for(done.wait(), timeout=5)
            server.close()
            assert received == ["STATION IU_KONO", "SELECT B_H_Z", "DATA", "END"]

        run(scenario())

    def test_rejection_raises_without_end(self):
        async def scenario():
            received = []

            async def handle(reader, writer):
                lines = await self._handshake(reader, writer)
                for _ in range(2):
                    received.append(await lines.read_line())
                writer.write(b"ERROR ARGUMENTS bad station\r\nOK\r\n")
                await writer.drain()
                try:
                    received.append(await asyncio.wait_for(lines.read_line(), timeout=0.3))
                except (TimeoutError, asyncio.IncompleteReadError):
                    pass
                writer.close()

            server, port = await _serve_once(handle)
            async with AsyncSeedLink("127.0.0.1", port, timeout=5) as sl:
                sl.add_stream("IU_KONO")
                with pytest.raises(SeedLinkError, match="bad station"):
                    await sl.negotiate()
                assert not sl.is_streaming
                assert not sl.is_connected  # server may hold a partial selection
                await asyncio.sleep(0.35)
            server.close()
            assert received == ["STATION IU_KONO", "DATA"]

        run(scenario())

    def test_rejection_of_station_covered_by_wildcard_tolerated(self):
        async def scenario():
            received = []

            async def handle(reader, writer):
                lines = await self._handshake(reader, writer)
                for _ in range(4):
                    received.append(await lines.read_line())
                writer.write(b"ERROR ARGUMENTS unknown station\r\nERROR ARGUMENTS no station\r\n"
                             b"OK\r\nOK\r\n")
                await writer.drain()
                received.append(await lines.read_line())
                writer.close()

            server, port = await _serve_once(handle)
            async with AsyncSeedLink("127.0.0.1", port, timeout=5) as sl:
                sl.add_stream("IU_*")
                sl.add_stream("IU_KONO")
                await sl.negotiate()
                assert sl.is_streaming
                await asyncio.sleep(0.05)
            server.close()
            assert received == ["STATION IU_KONO", "DATA", "STATION IU_*", "DATA", "END"]

        run(scenario())


class TestCollectIdleTimeout:
    def test_info_traffic_resets_timer(self):
        async def scenario():
            sl = AsyncSeedLink("127.0.0.1", 0)
            sl._writer = MagicMock()  # is_connected -> True; no real socket needed
            sl._writer.wait_closed = AsyncMock()
            sl._streaming = True
            sl._idle_timeout = 0.05

            async def always_ready(n):
                return None

            info_frame = _RawFrame(station_id="", seqnum=None, payload_format=FORMAT_XML,
                                    payload_subformat=SUBFORMAT_JSON_INFO, payload=b"<x/>",
                                    info_continues=False)

            count = 0

            async def recv_frame():
                nonlocal count
                count += 1
                if count > 6:
                    raise SeedLinkError("stop")
                await asyncio.sleep(0.02)  # 0.12s in all, past the idle timeout
                return info_frame

            sl._ensure = always_ready
            sl._recv_frame = recv_frame
            gen = sl.collect(reconnect=False)
            try:
                with pytest.raises(SeedLinkError, match="stop"):
                    await gen.__anext__()
            finally:
                await gen.aclose()

        run(scenario())


class TestCollectJsonError:
    """A mid-stream v4 JSON ERROR packet is logged and skipped, keeping the
    connection -- see the sync client's TestCollectJsonError."""

    def test_logged_and_skipped(self, caplog):
        async def scenario():
            sl = AsyncSeedLink("127.0.0.1", 0)
            sl._writer = MagicMock()  # is_connected -> True; no real socket needed
            sl._writer.wait_closed = AsyncMock()
            sl._streaming = True

            error_frame = _RawFrame(station_id="", seqnum=None, payload_format=FORMAT_JSON,
                                     payload_subformat=SUBFORMAT_JSON_ERROR,
                                     payload=b'{"message": "no such station"}',
                                     info_continues=False)
            data_frame = _RawFrame(station_id="IU_KONO", seqnum=8, payload_format="2",
                                    payload_subformat="D", payload=b"x", info_continues=False)
            frames = iter([error_frame, data_frame])

            async def always_ready(n):
                return None

            async def recv_frame():
                return next(frames)

            sl._ensure = always_ready
            sl._recv_frame = recv_frame
            gen = sl.collect(reconnect=False)
            try:
                with caplog.at_level("WARNING"):
                    pkt = await gen.__anext__()
                assert pkt.seqnum == 8
                assert sl.is_connected
                assert "no such station" in caplog.text
            finally:
                await gen.aclose()

        run(scenario())


class TestCollectStalledFrame:
    def test_idle_timeout_bounds_partial_frame(self):
        async def scenario():
            async def handle(reader, writer):
                writer.write(b"SE2D")  # header started, never finished
                await writer.drain()
                await asyncio.sleep(5)

            server, port = await _serve_once(handle)
            sl = AsyncSeedLink("127.0.0.1", port, idle_timeout=0.2)
            await sl.connect(handshake=False)
            sl.protocol = Protocol.V4
            sl._streaming = True
            gen = sl.collect(reconnect=False)
            try:
                with pytest.raises(SeedLinkTimeout, match="Timed out reading"):
                    await asyncio.wait_for(gen.__anext__(), timeout=2)
                assert not sl.is_connected
            finally:
                await gen.aclose()
                server.close()

        run(scenario())


class TestCollectUndecodablePacket:
    def test_skipped_without_dropping_connection(self, caplog):
        async def scenario():
            sl = AsyncSeedLink("127.0.0.1", 0)
            sl._writer = MagicMock()  # is_connected -> True; no real socket needed
            sl._writer.wait_closed = AsyncMock()
            sl._streaming = True
            data_frame = _RawFrame(station_id="IU_KONO", seqnum=8, payload_format="2",
                                    payload_subformat="D", payload=b"x", info_continues=False)
            frames = iter([_UndecodablePacket("bad record", 7), data_frame])

            async def always_ready(n):
                return None

            async def recv_frame():
                item = next(frames)
                if isinstance(item, Exception):
                    raise item
                return item

            sl._ensure = always_ready
            sl._recv_frame = recv_frame
            gen = sl.collect(reconnect=False)
            try:
                with caplog.at_level("WARNING"):
                    pkt = await gen.__anext__()
                assert pkt.seqnum == 8
                assert sl.is_connected
                assert "Skipping undecodable packet seq=7" in caplog.text
            finally:
                await gen.aclose()

        run(scenario())


class TestErrorHandling:
    def test_station_rejected_raises(self):
        async def scenario():
            async def handle(reader, writer):
                lines = _LineReader(reader)
                assert await lines.read_line() == "HELLO"
                writer.write(b"SeedLink v4.0 (test) :: SLPROTO:4.0\r\n")
                writer.write(b"Test Server\r\n")
                await writer.drain()
                assert await lines.read_line() == "SLPROTO 4.0"
                writer.write(b"OK\r\n")
                await writer.drain()
                assert (await lines.read_line()).startswith("USERAGENT")
                writer.write(b"OK\r\n")
                await writer.drain()
                assert await lines.read_line() == "STATION IU_KONO"
                writer.write(b"ERROR ARGUMENTS bad station\r\n")
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            async with AsyncSeedLink("127.0.0.1", port) as sl:
                sl.add_stream("IU_KONO")
                raised = False
                try:
                    await sl.negotiate()
                except Exception:
                    raised = True
                assert raised
            server.close()

        run(scenario())


class TestCommandParity:
    """Guard against sync/async drift: every public SeedLink method should
    have a same-named AsyncSeedLink counterpart that is a coroutine or
    async generator."""

    SYNC_ONLY = {"is_connected", "is_streaming"}  # properties, not methods

    def test_every_public_method_has_async_counterpart(self):
        for name in vars(SeedLink):
            if name.startswith("_") or name in self.SYNC_ONLY:
                continue
            sync_attr = getattr(SeedLink, name)
            if not callable(sync_attr):
                continue
            assert hasattr(AsyncSeedLink, name), f"AsyncSeedLink is missing {name}"
            async_attr = getattr(AsyncSeedLink, name)
            is_coro_or_gen = (
                inspect.iscoroutinefunction(async_attr)
                or inspect.isasyncgenfunction(async_attr)
            )
            assert is_coro_or_gen, f"AsyncSeedLink.{name} is not async"
