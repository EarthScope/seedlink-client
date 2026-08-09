"""
SeedLink protocol client for streaming geophysical (seismic) data, with
transparent support for both SeedLink 3.x and 4.0.

SeedLink is a real-time streaming protocol used by seismological data
systems (e.g. SeisComP, ringserver) to deliver miniSEED data as it is
recorded. This client negotiates whichever protocol version a server
speaks and presents the same API either way.

Quick start::

    from seedlink_client import SeedLink

    with SeedLink("rtserve.earthscope.org") as sl:
        sl.add_stream("IU_COLA", "BH?")
        for packet in sl.collect():
            print(packet.station_id, packet.seqnum, len(packet.payload))

Async quick start (requires Python 3.11+; only the methods that do network
I/O, e.g. connect/collect/info, are coroutines -- stream selection like
add_stream() is plain configuration and stays synchronous)::

    import asyncio
    from seedlink_client import AsyncSeedLink

    async def main():
        async with AsyncSeedLink("rtserve.earthscope.org") as sl:
            sl.add_stream("IU_COLA", "BH?")
            async for packet in sl.collect():
                print(packet.station_id, packet.seqnum, len(packet.payload))

    asyncio.run(main())

Command-line client (non-interactive by default; ``-c`` drops into an
interactive protocol shell)::

    seedlink-client [host:port]
"""

from typing import TYPE_CHECKING

from .client import SeedLink
from .protocol import (
    Protocol,
    SeedLinkAuthError,
    SeedLinkError,
    SeedLinkPacket,
    SeedLinkResponse,
    SeedLinkTimeout,
)
from .streams import Stream

if TYPE_CHECKING:
    # Only for type checkers/IDEs; the real (lazy) imports are in
    # __getattr__ below, so importing seedlink_client doesn't pull in
    # asyncio (AsyncSeedLink) or cmd/threading/select (main) unless one of
    # them is actually used.
    from .aio import AsyncSeedLink
    from .cli import main

__version__ = "0.2.0"
__all__ = [
    "AsyncSeedLink",
    "Protocol",
    "SeedLink",
    "SeedLinkAuthError",
    "SeedLinkError",
    "SeedLinkPacket",
    "SeedLinkResponse",
    "SeedLinkTimeout",
    "Stream",
    "main",
]


def __getattr__(name: str):
    if name == "AsyncSeedLink":
        from .aio import AsyncSeedLink

        return AsyncSeedLink
    if name == "main":
        from .cli import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
