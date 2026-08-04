# seedlink-client

SeedLink protocol client for streaming geophysical (seismic) data, with transparent support for
both [SeedLink 3.x](https://www.seiscomp.de/doc/apps/seedlink.html) and
[4.0](https://docs.fdsn.org/projects/seedlink/en/latest/protocol.html). SeedLink is a real-time
streaming protocol used by seismological data systems (e.g. SeisComP, EarthScope's
[ringserver](https://github.com/earthscope/ringserver)) to deliver miniSEED data as it is recorded.

Requires Python 3.11+.

## Installation

```bash
pip install seedlink-client
```

## Usage

### Sync API

```python
from seedlink_client import SeedLink

with SeedLink("rtserve.earthscope.org") as sl:
    sl.add_stream("IU_COLA", "BH?")
    for packet in sl.collect():
        print(packet.station_id, packet.seqnum, len(packet.payload))
```

### Async API

`AsyncSeedLink` offers the same API as `SeedLink`, built on `asyncio`. Only the methods that
do network I/O (`connect`, `collect`, `info`, ...) are coroutines; stream selection (`add_stream`
and friends) is plain configuration and stays synchronous on both clients:

```python
import asyncio
from seedlink_client import AsyncSeedLink

async def main():
    async with AsyncSeedLink("rtserve.earthscope.org") as sl:
        sl.add_stream("IU_COLA", "BH?")
        async for packet in sl.collect():
            print(packet.station_id, packet.seqnum, len(packet.payload))

asyncio.run(main())
```

### Protocol versions

`SeedLink`/`AsyncSeedLink` negotiate SeedLink 3.x or 4.0 automatically from the server's `HELLO`
reply and speak whichever is offered -- selectors, sequence numbers, time windows, and INFO
queries all work the same way from the caller's side regardless of which protocol is in use. Pass
`protocol=Protocol.V3` or `Protocol.V4` to pin a version instead of negotiating.

Packets carry their payload as raw `bytes`; call `packet.record()` to decode it as a
[pymseed](https://pypi.org/project/pymseed/) `MS3Record`.

### Command-line client

A non-interactive client is available after install:

```bash
seedlink-client [host:port]
```

Default is `localhost:18000`. Use `seedlink-client --help` for options (stream selection, time
windows, state files, INFO queries, TLS, auth). Pass `-c`/`--interactive` for a low-level
interactive shell that sends individual protocol commands (`HELLO`, `STATION`, `SELECT`, `DATA`,
`INFO`, ...).
