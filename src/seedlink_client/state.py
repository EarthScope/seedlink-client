"""State file save/restore for resumable sequence numbers.

Writes and reads the same format libslink uses (``sl_savestate()`` /
``sl_recoverstate()`` in libslink's statefile.c), so a state file is
interchangeable with slinktool, slarchive, and other libslink-based tools.
"""

from __future__ import annotations

import os
import tempfile

from .streams import Stream

_HEADER_V2 = "#V2 StationID  Sequence  [Timestamp]"


def save_state(path: str, streams: list[Stream]) -> None:
    """Write each stream's sequence number and last-packet timestamp.

    Format (one line per stream, matching libslink's #V2 state file)::

        StationID Sequence [Timestamp]

    Sequence is decimal, or 'UNSET' if the stream has none yet.

    Written via a temporary file in the same directory, then renamed into
    place, so a crash or interrupt mid-write can't leave a truncated state
    file behind.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".state")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(_HEADER_V2 + "\n")
            for stream in streams:
                seq = "UNSET" if stream.seqnum is None else str(stream.seqnum)
                fields = [stream.station_id, seq]
                if stream.timestamp:
                    fields.append(stream.timestamp)
                f.write(" ".join(fields) + "\n")
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def load_state(path: str) -> dict[str, tuple[int | None, str | None]]:
    """Read a state file into ``{station_id: (seqnum, timestamp)}``.

    Accepts both the ``#V2`` format written by :func:`save_state` and
    libslink's legacy headerless format, ``NET STA seq [timestamp]``
    (station ID becomes ``NET_STA``); the legacy uni-station entry
    ``XX UNI`` maps to station ID ``'*'``. A missing sequence number is
    represented as ``UNSET`` or ``-1`` in either format. Unparsable lines
    are skipped.

    Unlike libslink's ``sl_recoverstate()``, this does not require streams
    to already be configured -- state may be loaded before or after
    stream setup.
    """
    state: dict[str, tuple[int | None, str | None]] = {}
    with open(path) as f:
        lines = [line.rstrip("\n") for line in f]

    is_v2 = bool(lines) and lines[0].startswith("#V2")
    for line in lines[1:] if is_v2 else lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if is_v2:
            if len(fields) < 2:
                continue
            station_id, seq_str = fields[0], fields[1]
            timestamp = fields[2] if len(fields) > 2 else None
        else:
            # Legacy: "NET STA seq [timestamp]"; "XX UNI" is the uni-station entry.
            if len(fields) < 3:
                continue
            net, sta, seq_str = fields[0], fields[1], fields[2]
            station_id = "*" if (net, sta) == ("XX", "UNI") else f"{net}_{sta}"
            timestamp = fields[3] if len(fields) > 3 else None
        try:
            seqnum = None if seq_str in ("UNSET", "-1") else int(seq_str)
        except ValueError:
            continue
        state[station_id] = (seqnum, timestamp)
    return state
