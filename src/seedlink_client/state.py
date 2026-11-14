"""State file save/restore for resumable sequence numbers.

Writes and reads the same format libslink uses (``sl_savestate()`` /
``sl_recoverstate()`` in libslink's statefile.c), so a state file is
interchangeable with slinktool, slarchive, and other libslink-based tools.
"""

from __future__ import annotations

import os
import secrets

from .protocol import MAX_STATIONID
from .streams import Stream, is_wildcard
from .time_utils import parse_timestring, to_iso_timestring

_HEADER_V2 = "#V2 StationID  Sequence  [Timestamp]"

# Longest state file line accepted, excluding the line terminator
_MAX_LINE_LEN = 199


def save_state(path: str, streams: list[Stream], multistation: bool = False) -> None:
    """Write each stream's sequence number and last-packet timestamp.

    Format (one line per stream, matching libslink's #V2 state file)::

        StationID Sequence [Timestamp]

    Sequence is decimal, or 'UNSET' if the stream has none yet. A
    timestamp that does not parse is omitted. With
    ``multistation``, wildcard station IDs are always written as 'UNSET'
    with no timestamp: stations received via them have their own entries.

    Written via a temporary file in the same directory, flushed to disk,
    then renamed into place, so a crash or interrupt mid-write can't leave
    a truncated state file behind. The temp file is created mode 0666 less
    the umask, matching a plain ``open()``, since a state file is often
    meant to be read by another process or user (e.g. a monitoring tool,
    or a different service account resuming the same stream).
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = _create_temp(directory)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(_HEADER_V2 + "\n")
            for stream in streams:
                if multistation and is_wildcard(stream.station_id):
                    f.write(f"{stream.station_id} UNSET\n")
                    continue
                seq = "UNSET" if stream.seqnum is None else str(stream.seqnum)
                fields = [stream.station_id, seq]
                timestamp = stream.resolve_timestamp()
                if timestamp and _valid_timestamp(timestamp):
                    fields.append(timestamp)
                f.write(" ".join(fields) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def _valid_timestamp(timestamp: str) -> bool:
    """Whether ``timestamp`` parses, excluding sentinels such as 'UNSET'
    or 'ERROR' that would make the line unreadable."""
    try:
        parse_timestring(timestamp)
    except ValueError:
        return False
    return True


def _create_temp(directory: str) -> tuple[int, str]:
    """Exclusively create a uniquely named temp file in ``directory``,
    letting the umask set its permissions."""
    for _ in range(100):
        tmp_path = os.path.join(directory, f".tmp-{secrets.token_hex(8)}.state")
        try:
            return os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666), tmp_path
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a temporary state file in {directory}")


def load_state(path: str) -> dict[str, tuple[int | None, str | None]]:
    """Read a state file into ``{station_id: (seqnum, timestamp)}``.

    Accepts both the ``#V2`` format written by :func:`save_state` and
    libslink's legacy headerless format, ``NET STA seq [timestamp]``
    (station ID becomes ``NET_STA``); the legacy uni-station entry
    ``XX UNI`` maps to station ID ``'*'``. A missing sequence number is
    represented as ``UNSET`` or ``-1`` in either format. A legacy
    comma-delimited timestamp is converted to ISO format.

    Unlike libslink's ``sl_recoverstate()``, this does not require streams
    to already be configured -- state may be loaded before or after
    stream setup.

    Raises ValueError if the file is not text, or has a line that is too
    long, has too few fields, or has an invalid station ID, sequence
    number or timestamp.
    """
    state: dict[str, tuple[int | None, str | None]] = {}
    try:
        with open(path, encoding="utf-8") as f:
            lines = [line.rstrip("\n") for line in f]
    except UnicodeDecodeError as e:
        raise ValueError(
            f"Not a valid state file: {path!r} (undecodable byte at offset {e.start})"
        ) from e

    def invalid(reason: str, lineno: int) -> ValueError:
        return ValueError(f"Not a valid state file: {path!r} ({reason} on line {lineno})")

    is_v2 = bool(lines) and lines[0].startswith("#V2")
    for lineno, line in enumerate(lines, start=1):
        if lineno == 1 and is_v2:
            continue
        line = line.rstrip("\r")
        if len(line) > _MAX_LINE_LEN:
            raise invalid("line too long", lineno)
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if is_v2:
            if len(fields) < 2:
                raise invalid("too few fields", lineno)
            station_id, seq_str = fields[0], fields[1]
            timestamp = fields[2] if len(fields) > 2 else None
        else:
            # Legacy: "NET STA seq [timestamp]"; "XX UNI" is the uni-station entry.
            if len(fields) < 3:
                raise invalid("too few fields", lineno)
            net, sta, seq_str = fields[0], fields[1], fields[2]
            station_id = "*" if (net, sta) == ("XX", "UNI") else f"{net}_{sta}"
            timestamp = fields[3] if len(fields) > 3 else None
        if len(station_id) > MAX_STATIONID:
            raise invalid("station ID too long", lineno)
        if seq_str in ("UNSET", "-1"):
            seqnum = None
        elif seq_str.isascii() and seq_str.isdigit() and int(seq_str) < 2**64:
            seqnum = int(seq_str)
        else:
            raise invalid(f"invalid sequence number {seq_str!r}", lineno)
        if timestamp is not None:
            try:
                parsed = parse_timestring(timestamp)
            except ValueError:
                raise invalid(f"invalid timestamp {timestamp!r}", lineno) from None
            if "," in timestamp:
                timestamp = to_iso_timestring(parsed)
        state[station_id] = (seqnum, timestamp)
    return state
