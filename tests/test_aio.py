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

from seedlink_client.aio import AsyncSeedLink
from seedlink_client.client import SeedLink


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
