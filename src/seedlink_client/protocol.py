"""SeedLink protocol wire codec: framing, header/reply parsing, and types.

Everything in this module is pure (no sockets, no I/O), so it is shared
verbatim by both the synchronous :class:`~seedlink_client.client.SeedLink`
and the asyncio-based :class:`~seedlink_client.aio.AsyncSeedLink`. Each
transport is responsible only for getting bytes on and off the wire; every
decision about what those bytes *mean* — v3 vs v4 framing, reply shape,
protocol negotiation — is made here.

SeedLink v3 and v4 use unrelated packet framings, so this module speaks
both: v3's 8-byte ``"SL"`` + 6-hex-digit sequence header (record length is
not on the wire and must be detected from the miniSEED payload itself, see
:mod:`seedlink_client.mseed`), and v4's 17-byte ``"SE"`` header carrying an
explicit payload length, 64-bit sequence number, and station ID.
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Default/TLS ports
DEFAULT_PORT = 18000
TLS_PORT = 18500

# v3 framing
SIGNATURE_V3 = b"SL"
INFO_SIGNATURE_V3 = b"SLINFO"
HEADSIZE_V3 = 8

# v4 framing
SIGNATURE_V4 = b"SE"
HEADSIZE_V4 = 17
_V4_HEADER_STRUCT = struct.Struct("<2sccIQB")

# miniSEED detection needs at least this many payload bytes to recognize a
# record and, for miniSEED 2 without a Blockette 1000, to search for the
# start of the next record.
MIN_PAYLOAD_DETECT = 64

MAX_STATIONID = 21   # usable station ID length (libslink reserves 1 for NUL)
MAX_COMMAND_LEN = 255  # max command line length per the v4 spec, incl. CRLF

# Sanity cap on a buffered reply/HELLO line with no terminator in sight yet.
# Generous relative to MAX_COMMAND_LEN (which bounds what we send, not what a
# server may reply with, e.g. a v3 EXTREPLY message) but still bounded, so a
# corrupt or malicious peer can't grow the receive buffer without limit.
MAX_LINE_LEN = 8192

# Sanity cap on a v4 header's declared payload length. A corrupt or
# malicious header could otherwise claim an enormous size and force the
# reader to allocate/wait for a buffer far beyond any real SeedLink payload.
MAX_PAYLOAD_SIZE = 256 * 1024 * 1024

# Sanity cap on how far to search for a v3 packet's miniSEED record length
# (protocol.py's MIN_PAYLOAD_DETECT is the minimum; this is the maximum). No
# real SeedLink record exceeds a few hundred KiB; capping the detection
# window keeps a corrupt v3 stream from growing the receive buffer toward
# MAX_PAYLOAD_SIZE just to conclude it isn't miniSEED.
MAX_RECORD_LEN = 1024 * 1024

# miniSEED/JSON/XML payload format codes (the literal v4 wire byte)
FORMAT_MSEED2 = "2"
FORMAT_MSEED3 = "3"
FORMAT_JSON = "J"
FORMAT_XML = "X"
SUBFORMAT_JSON_INFO = "I"
SUBFORMAT_JSON_ERROR = "E"

# Known v4 ERROR codes, for reference; servers are not restricted to these.
V4_ERROR_CODES = frozenset(
    {"UNSUPPORTED", "UNEXPECTED", "UNAUTHORIZED", "LIMIT", "ARGUMENTS", "AUTH", "INTERNAL"}
)


class Protocol(Enum):
    """Negotiated SeedLink protocol version."""

    V3 = "3"
    V4 = "4"


class StreamEvent(Enum):
    """Classification of the next bytes while in streaming mode."""

    PACKET = "PACKET"
    END = "END"
    ERROR = "ERROR"
    OTHER = "OTHER"


class SeedLinkError(Exception):
    """Raised when the server returns ERROR or on protocol/socket errors.

    Attributes:
        code: The v4 ERROR code token (e.g. ``"UNAUTHORIZED"``), or None.
    """

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


class SeedLinkTimeout(SeedLinkError, TimeoutError):
    """Raised when a socket operation exceeds its timeout.

    Inherits from both :class:`SeedLinkError` and the built-in
    :class:`TimeoutError`, so it can be caught as either.
    """


class SeedLinkAuthError(SeedLinkError):
    """Raised when AUTH is rejected by the server.

    This is fatal and not retried: an authentication failure will not
    resolve itself by reconnecting with the same credentials.
    """


@dataclass
class SeedLinkResponse:
    """OK or ERROR status response from the server.

    Attributes:
        status:  'OK' or 'ERROR'.
        code:    v4 ERROR code token (e.g. 'ARGUMENTS'), or None.
        message: Extended/error message text, or None.
    """

    status: str
    code: str | None
    message: str | None

    def __bool__(self) -> bool:
        """True if status is 'OK', False if 'ERROR'."""
        return self.status == "OK"


@dataclass
class SeedLinkPacket:
    """A decoded SeedLink data or INFO packet.

    Attributes:
        station_id: 'NET_STA'. Read from the v4 header, or derived from the
            miniSEED payload's SEED codes for v3 (which carries none).
        seqnum:     Sequence number, or None if unset (v3 INFO packets).
        payload_format:    Payload format code ('2', '3', 'J', 'X', ...).
        payload_subformat: Payload subformat code.
        payload:    Raw payload bytes.
    """

    station_id: str
    seqnum: int | None
    payload_format: str
    payload_subformat: str
    payload: bytes
    _record: Any = field(default=None, init=False, repr=False, compare=False)

    @property
    def is_info(self) -> bool:
        """Whether this packet carries an INFO reply rather than data."""
        return self.payload_subformat in (SUBFORMAT_JSON_INFO, SUBFORMAT_JSON_ERROR)

    def record(self):
        """Parse the payload as a miniSEED record, via :mod:`pymseed`.

        The parsed :class:`pymseed.MS3Record` is cached on first call.

        Raises:
            SeedLinkError: if the payload is not miniSEED (e.g. an INFO
                packet, whose payload is JSON or XML).
        """
        if self._record is None:
            from . import mseed

            self._record = mseed.parse_record(self.payload)
        return self._record


@dataclass
class HeaderV3:
    """Parsed v3 packet header (8 bytes: 'SL' + 6 hex digits, or 'SLINFO')."""

    seqnum: int | None
    is_info: bool
    info_continues: bool  # only meaningful when is_info is True


@dataclass
class HeaderV4:
    """Parsed v4 packet header (17 bytes, station ID follows separately)."""

    payload_format: str
    payload_subformat: str
    payload_length: int
    seqnum: int
    station_id_length: int


def parse_header_v3(buf: bytes) -> HeaderV3:
    """Parse an 8-byte v3 header: 'SL' + 6 hex-digit sequence, or 'SLINFO'.

    An INFO header's 8th byte is '*' if more INFO packets follow, anything
    else on the final packet of the reply.
    """
    if len(buf) < HEADSIZE_V3:
        raise SeedLinkError(f"v3 header too short: {len(buf)} bytes")
    if buf[:6] == INFO_SIGNATURE_V3:
        return HeaderV3(seqnum=None, is_info=True, info_continues=buf[7:8] == b"*")
    if buf[:2] == SIGNATURE_V3:
        try:
            seqnum = int(buf[2:8], 16)
        except ValueError as e:
            raise SeedLinkError(f"Invalid v3 sequence number: {buf[2:8]!r}") from e
        return HeaderV3(seqnum=seqnum, is_info=False, info_continues=False)
    raise SeedLinkError(f"Unrecognized v3 header signature: {buf[:2]!r}")


def parse_header_v4(buf: bytes) -> HeaderV4:
    """Parse the fixed 17-byte portion of a v4 header (before the station ID).

    Layout: 'SE' + format + subformat + payload length (u32le) +
    sequence number (u64le) + station ID length (u8).
    """
    if len(buf) < HEADSIZE_V4:
        raise SeedLinkError(f"v4 header too short: {len(buf)} bytes")
    signature, fmt, subfmt, length, seqnum, sidlen = _V4_HEADER_STRUCT.unpack_from(buf, 0)
    if signature != SIGNATURE_V4:
        raise SeedLinkError(f"Unrecognized v4 header signature: {signature!r}")
    if length > MAX_PAYLOAD_SIZE:
        raise SeedLinkError(
            f"Declared payload length {length} exceeds sanity limit {MAX_PAYLOAD_SIZE}"
        )
    return HeaderV4(
        payload_format=fmt.decode("ascii"),
        payload_subformat=subfmt.decode("ascii"),
        payload_length=length,
        seqnum=seqnum,
        station_id_length=sidlen,
    )


def classify_stream_prefix(buf: bytes) -> StreamEvent:
    """Classify the next bytes of a streaming connection.

    Before a packet header, the server may send a bare ``END`` (dial-up end
    of stream) or ``ERROR ...`` (rejected command) ASCII line instead of a
    binary packet; both are distinguishable from the 'SL'/'SE' signatures
    by their first bytes.
    """
    if buf.startswith(b"END"):
        return StreamEvent.END
    if buf.startswith(b"ERROR"):
        return StreamEvent.ERROR
    if buf.startswith(SIGNATURE_V3) or buf.startswith(SIGNATURE_V4):
        return StreamEvent.PACKET
    return StreamEvent.OTHER


def parse_reply(text: str) -> SeedLinkResponse:
    """Parse an OK/ERROR reply line into a :class:`SeedLinkResponse`.

    Handles the v4 shape (``OK`` / ``ERROR <CODE> [message]``) and the v3
    CAPABILITIES EXTREPLY shape, where an extended message follows the
    status on the same line separated by an embedded CR
    (``OK\\rmessage`` / ``ERROR\\rmessage``).
    """
    text = text.rstrip("\r\n")
    head, _, extra = text.partition("\r")
    parts = head.split(None, 1)
    status = parts[0] if parts else ""
    if status == "OK":
        return SeedLinkResponse(status="OK", code=None, message=extra or None)
    if status == "ERROR":
        code = None
        message = extra or None
        if len(parts) > 1:
            rest_parts = parts[1].split(None, 1)
            code = rest_parts[0]
            if len(rest_parts) > 1:
                message = rest_parts[1]
        return SeedLinkResponse(status="ERROR", code=code, message=message)
    return SeedLinkResponse(status=status, code=None, message=text or None)


def parse_hello(line1: str, line2: str) -> tuple[str, str, dict[str, str | bool], frozenset[str]]:
    """Parse the two-line HELLO reply.

    Line 1 is ``"<server id> :: <capability tokens>"``; line 2 is the
    organization/site description. A capability token with a ``:value``
    suffix is stored as a string, a bare token as True. Every
    ``SLPROTO:<major>.<minor>`` token's major version is collected
    separately (a server may advertise more than one), for
    :func:`select_protocol`.

    Returns:
        (server_id, organization, capabilities, protocol_majors)
    """
    line1 = line1.rstrip("\r\n")
    line2 = line2.rstrip("\r\n")
    server_id = line1.strip()
    capabilities: dict[str, str | bool] = {}
    protocols: set[str] = set()
    if "::" in line1:
        server_id, _, caps_str = line1.partition("::")
        server_id = server_id.strip()
        for token in caps_str.split():
            if ":" in token:
                key, value = token.split(":", 1)
                capabilities[key] = value
                if key == "SLPROTO":
                    protocols.add(value.split(".", 1)[0])
            else:
                capabilities[token] = True
    return server_id, line2.strip(), capabilities, frozenset(protocols)


def select_protocol(protocol_majors: frozenset[str], requested: Protocol | None) -> Protocol:
    """Pick the protocol version to use for this connection.

    Mirrors libslink's negotiation rule: promote to v4 whenever the server
    advertises it, unless the caller pinned v3; otherwise use v3 if
    advertised. A server that advertises nothing recognized is assumed to
    speak v3 (the protocol predating the ``SLPROTO`` capability token).

    Raises:
        SeedLinkError: if ``requested`` pins a version the server does not
            support, or if the server supports neither.
    """
    supports_v3 = "3" in protocol_majors or not protocol_majors
    supports_v4 = "4" in protocol_majors

    if requested is Protocol.V3:
        if supports_v3:
            return Protocol.V3
        raise SeedLinkError("Server does not support SeedLink v3")
    if requested is Protocol.V4:
        if supports_v4:
            return Protocol.V4
        raise SeedLinkError("Server does not support SeedLink v4")
    if supports_v4:
        return Protocol.V4
    if supports_v3:
        return Protocol.V3
    raise SeedLinkError("No supported protocol version found")


def parse_info_xml(text: str) -> dict[str, Any]:
    """Parse a v3 INFO reply's XML body into a dict.

    A generic, schema-free walk: each element becomes a dict of its
    attributes, with child elements collected under their own tag as a
    list (since a v3 INFO document may repeat e.g. multiple ``<station>``
    elements). All attribute values stay strings, unlike v4's typed JSON
    reply -- ``info_dict()`` returns whichever shape the negotiated
    protocol actually produces, rather than forcing both into one schema.
    """

    def walk(element: ET.Element) -> dict[str, Any]:
        result: dict[str, Any] = dict(element.attrib)
        for child in element:
            result.setdefault(child.tag, []).append(walk(child))
        return result

    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise SeedLinkError(f"Malformed INFO XML from server: {e}") from e
    return {root.tag: walk(root)}


def generate_client_id(program_name: str | None = None) -> tuple[str, str]:
    """Build a (name, version) pair for the USERAGENT command.

    Falls back to the running program's basename and this package's
    version when not supplied.
    """
    if program_name is None:
        import os
        import sys

        main_module = sys.modules.get("__main__")
        if main_module is not None and hasattr(main_module, "__file__"):
            program_name = os.path.basename(main_module.__file__)
        else:
            program_name = "seedlink-client"
    from . import __version__

    return program_name, __version__
