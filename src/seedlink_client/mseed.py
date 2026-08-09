"""Thin adapter over :mod:`pymseed` for the miniSEED-specific pieces the
SeedLink v3 wire format depends on: detecting a v3 packet's record length
(not carried on the wire, unlike v4), deriving a v3 packet's station ID
(also not carried on the wire) from the record's own SEED codes, and
unwrapping the miniSEED2 "envelope" v3 servers use to carry an INFO
reply's XML text.
"""

from __future__ import annotations

from pymseed import MiniSEEDError, MS3Record, sourceid2nslc
from pymseed.clib import buffer_pointer, clibmseed, ffi

from .protocol import SeedLinkError


def detect_record_length(buf: bytes) -> tuple[int, int] | None:
    """Detect a miniSEED record's length and format version from its start.

    Wraps libmseed's ``ms3_detect()`` -- the same routine libslink's own
    ``detect()`` reimplements in C -- to determine how many bytes of a v3
    SeedLink packet's payload to read, since v3 headers carry no length.

    ``buf`` must be at least ``protocol.MIN_PAYLOAD_DETECT`` bytes (the
    libmseed fixed-header minimum); a shorter buffer cannot be told apart
    from genuinely invalid data and is reported as not miniSEED.

    Returns:
        (record_length, format_version), or None if not enough of the
        record is present yet to determine its length (the caller should
        read more bytes and retry).

    Raises:
        SeedLinkError: if the buffer does not look like a miniSEED record.
    """
    buf_ptr = buffer_pointer(buf)
    formatversion = ffi.new("uint8_t *")
    reclen = clibmseed.ms3_detect(buf_ptr, len(buf_ptr), formatversion)
    if reclen < 0:
        raise SeedLinkError("Payload does not look like a miniSEED record")
    if reclen == 0:
        return None
    return reclen, formatversion[0]


def parse_record(payload: bytes) -> MS3Record:
    """Parse a complete miniSEED record from a packet payload.

    Raises:
        SeedLinkError: if the payload is not a complete, valid miniSEED
            record (e.g. an INFO packet's JSON/XML payload).
    """
    try:
        return MS3Record.parse(payload)
    except (MiniSEEDError, ValueError, BufferError) as e:
        raise SeedLinkError(f"Payload is not a valid miniSEED record: {e}") from e


def station_id(record: MS3Record) -> str:
    """Derive 'NET_STA' from a parsed record's source ID.

    v3 SeedLink packets carry no station ID on the wire; it comes from the
    record's own SEED network/station codes instead.
    """
    net, sta, _loc, _chan = sourceid2nslc(record.sourceid)
    return f"{net}_{sta}"


def extract_info_text(payload: bytes) -> str:
    """Extract INFO reply text from a v3 SLINFO packet's miniSEED payload.

    v3 servers carry an INFO reply's XML as the "data" section of an
    otherwise ordinary miniSEED2 record (text-encoded, one or more chained
    records for a reply too long for one record).

    Raises:
        SeedLinkError: if the payload doesn't decode to a text-encoded
            miniSEED record.
    """
    try:
        record = MS3Record.parse(payload, unpack_data=True)
    except (MiniSEEDError, ValueError, BufferError) as e:
        raise SeedLinkError(f"INFO payload is not a valid miniSEED record: {e}") from e
    if record.sampletype != "t":
        raise SeedLinkError(f"INFO payload is not text-encoded (sampletype={record.sampletype!r})")
    return bytes(record.datasamples).decode("utf-8", errors="replace")
