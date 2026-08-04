"""Stream selection model: station/selector configuration and stream lists.

A :class:`Stream` describes what to request from one station: its
station-ID pattern, selectors, and (for resumable streaming) where to pick
up from. This module also carries the v3/v4 selector syntax conversion, so
a client written against one selector syntax still gets a working
connection when the negotiated protocol turns out to be the other.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from .protocol import SeedLinkError


@dataclass
class Stream:
    """One station's stream selection and resume position.

    Attributes:
        station_id: 'NET_STA', or a pattern with '?'/'*' wildcards.
        selectors:  Stream ID / selector patterns (v3 'BH?.D' or v4
                    'B_H_?.D' style, or a mix -- see :func:`v3_to_v4_selector`
                    and :func:`v4_to_v3_selector`). Empty means "all streams".
        seqnum:     Resume after this sequence number, or None to start
                    from the next available packet (real-time).
        all_data:   Request the earliest available data (v4 ``DATA ALL``),
                    overriding ``seqnum``.
        timestamp:  ISO time of the last packet received for this stream,
                    if resuming from saved state. Set from a live data
                    packet, the underlying miniSEED record isn't parsed
                    until this is actually read -- so tracking it while
                    streaming costs nothing unless something (e.g.
                    save_state()) asks for it.
    """

    station_id: str
    selectors: list[str] = field(default_factory=list)
    seqnum: int | None = None
    all_data: bool = False
    timestamp: str | None = None

    def matches(self, station_id: str) -> bool:
        """Whether this (possibly wildcarded) station ID pattern matches."""
        pattern = self.station_id
        if not any(c in pattern for c in "*?["):
            return station_id == pattern
        compiled = self.__dict__.get("_match_re")
        if compiled is None or self.__dict__.get("_match_re_pattern") != pattern:
            compiled = re.compile(fnmatch.translate(pattern))
            self.__dict__["_match_re"] = compiled
            self.__dict__["_match_re_pattern"] = pattern
        return compiled.match(station_id) is not None

    def _get_timestamp(self) -> str | None:
        """Format and cache the pending packet's start time, if any.

        Deferred so that tracking a stream's resume position while
        streaming never forces a miniSEED parse unless the timestamp is
        actually read.
        """
        pkt = self.__dict__.pop("_ts_pkt", None)
        if pkt is not None:
            try:
                self.__dict__["_timestamp_str"] = pkt.record().starttime_str()
            except SeedLinkError:
                pass  # leave the previously stored timestamp, if any
        return self.__dict__.get("_timestamp_str")

    def _set_timestamp(self, value: str | None) -> None:
        self.__dict__.pop("_ts_pkt", None)
        self.__dict__["_timestamp_str"] = value

    def __getstate__(self) -> dict:
        self._get_timestamp()  # resolve any pending packet before copying
        state = dict(self.__dict__)
        state.pop("_ts_pkt", None)
        state.pop("_match_re", None)  # matches()'s compiled-pattern cache
        state.pop("_match_re_pattern", None)
        return state

    def __setstate__(self, state: dict) -> None:
        self.__dict__.update(state)


# Attached after @dataclass runs so the generated __init__(timestamp=None),
# __repr__, and __eq__ are unaffected -- they all just read/write
# self.timestamp, which this property intercepts to defer the actual
# miniSEED parse (see _get_timestamp) until the timestamp is read.
Stream.timestamp = property(Stream._get_timestamp, Stream._set_timestamp)


def v3_to_v4_selector(selector: str) -> str | None:
    """Convert a v3 stream selector to v4 form.

    v3 selectors are ``[LL]CCC[.T]`` (optional 2-char location, 3-char
    channel, optional '.'-separated type); v4 selectors are
    ``LOC_BAND_SOURCE_SUBSOURCE[.T]``. Leading ``-`` characters mean an
    explicit empty (blank) location code, as opposed to no location at all.

    Returns:
        The converted v4 selector, or None if ``selector`` isn't a
        recognizable v3 selector (e.g. it is already in v4 form, or
        otherwise not a plain 3/4/5-character code) -- the caller should
        send such a selector unconverted.
    """
    s = selector
    emptylocation = False
    while s.startswith("-"):
        s = s[1:]
        emptylocation = True

    streamid, sep, rest = s.partition(".")
    type_suffix = f".{rest}" if sep else ""

    if not streamid or not all(c.isalnum() or c in "?*" for c in streamid):
        return None

    if len(streamid) == 3:
        location = "" if emptylocation else "*"
        return f"{location}_{streamid[0]}_{streamid[1]}_{streamid[2]}{type_suffix}"
    if len(streamid) == 4:
        return f"{streamid[0]}_{streamid[1]}_{streamid[2]}_{streamid[3]}{type_suffix}"
    if len(streamid) == 5:
        return f"{streamid[0]}{streamid[1]}_{streamid[2]}_{streamid[3]}_{streamid[4]}{type_suffix}"
    return None


def v4_to_v3_selector(selector: str) -> str | None:
    """Convert a v4 stream selector back to v3 form.

    Only selectors built from classic single-character band/source/
    subsource codes (as v3 itself requires) have a v3 equivalent; anything
    else -- a wildcarded location other than ``*``, or a subsource code
    longer than one character -- returns None, meaning "no v3 equivalent,
    drop it when talking v3".
    """
    streamid, sep, rest = selector.partition(".")
    type_suffix = f".{rest}" if sep else ""
    parts = streamid.split("_")

    if len(parts) == 4:
        location, band, source, subsource = parts
    elif len(parts) == 3:
        location = "*"
        band, source, subsource = parts
    else:
        return None

    if len(band) != 1 or len(source) != 1 or len(subsource) != 1 or len(location) > 2:
        return None

    channel = band + source + subsource
    if location == "*":
        return f"{channel}{type_suffix}"
    if location == "":
        return f"--{channel}{type_suffix}"
    return f"{location}{channel}{type_suffix}"


def parse_streamlist(text: str, default_selectors: str | None = None) -> list[Stream]:
    """Parse a stream-list string: ``'STA[:selectors],STA2,...'``.

    Selectors are split at the *first* colon in each entry (so a per-format
    filter suffix like ``:3`` in the selector itself is preserved), and are
    themselves space-separated. Entries without an explicit selector use
    ``default_selectors``.

    Example:
        ``"IU_KONO:B_H_E B_H_N,GE_WLF,MN_AQU:H_H_?"``
    """
    streams = []
    for entry in text.split(","):
        entry = entry.strip()
        if not entry:
            continue
        station_id, sep, selector_str = entry.partition(":")
        if sep:
            selectors = selector_str.split()
        elif default_selectors:
            selectors = default_selectors.split()
        else:
            selectors = []
        streams.append(Stream(station_id=station_id.strip(), selectors=selectors))
    return streams


def read_streamlist_file(path: str, default_selectors: str | None = None) -> list[Stream]:
    """Read a stream-list file: one ``StationID [selectors]`` entry per line.

    Blank lines and ``#`` comments are ignored. A line without selectors
    uses ``default_selectors``.
    """
    streams = []
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            station_id = parts[0]
            selector_str = parts[1] if len(parts) > 1 else default_selectors
            selectors = selector_str.split() if selector_str else []
            streams.append(Stream(station_id=station_id, selectors=selectors))
    return streams


def sort_streams(streams: list[Stream]) -> list[Stream]:
    """Order streams so specific station IDs are sent before wildcarded ones.

    Matches libslink's ordering: exact IDs first, then '?'-containing, then
    '*'-containing, alphanumeric within each group.
    """

    def sort_key(stream: Stream) -> tuple[int, str]:
        if "*" in stream.station_id:
            rank = 2
        elif "?" in stream.station_id:
            rank = 1
        else:
            rank = 0
        return (rank, stream.station_id)

    return sorted(streams, key=sort_key)
