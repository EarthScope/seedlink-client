"""Time string conversions between SeedLink v3 and v4 (and ISO 8601) formats."""

import re
from datetime import datetime, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _normalize_timestring(timestring: str) -> str:
    """Zero-pad single-digit date/time fields for datetime.fromisoformat().

    fromisoformat() natively accepts a ``Z`` suffix, a space in place of
    ``T``, 1-6 digit fractional seconds, bare dates, and the "basic" (no
    separator) format; this only needs to handle what it still rejects: a
    single-digit month, day, hour, minute, or second.
    """
    s = timestring.strip()

    # Zero-pad month and day: 2026-2-9 -> 2026-02-09
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})(.*)", s)
    if m:
        s = f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}{m.group(4)}"

    # Zero-pad hour, minute, second: 0:1:1 -> 00:01:01 (T or space separator)
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ])(\d{1,2}):(\d{1,2}):(\d{1,2})(.*)", s)
    if m:
        s = f"{m.group(1)}{int(m.group(2)):02d}:{int(m.group(3)):02d}:{int(m.group(4)):02d}{m.group(5)}"

    return s


def parse_timestring(timestring: str) -> datetime:
    """Parse an ISO 8601 (v4) or comma-delimited (v3) SeedLink time string.

    Accepts:
      - ``2025-02-06T10:30:00.123456Z`` (ISO 8601, v4 ``DATA``/``TIME``)
      - ``2025-2-6T10:30:00`` (single-digit month/day)
      - ``2025-02-06 10:30:00`` (space instead of T)
      - ``2025-02-06`` (date only, midnight UTC)
      - ``2002,08,05,14,00,00`` (comma-delimited, v3 ``TIME``)

    A timezone of ``Z``, ``+00:00``, or omitted is treated as UTC.

    Returns:
        An aware ``datetime`` in UTC.
    """
    if "," in timestring:
        parts = [int(p) for p in timestring.strip().split(",")]
        parts += [1, 1, 0, 0, 0][len(parts) - 1 :] if len(parts) < 3 else []
        while len(parts) < 6:
            parts.append(0)
        year, month, day, hour, minute, second = parts[:6]
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    normalized = _normalize_timestring(timestring)
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso_timestring(dt: datetime) -> str:
    """Format a datetime as a v4 ISO 8601 SeedLink time string.

    Format: ``YYYY-MM-DDThh:mm:ss[.ffffff]Z``. Fractional seconds are
    omitted when zero, matching the examples in the v4 protocol spec.
    """
    dt = dt.astimezone(timezone.utc)
    if dt.microsecond:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def to_comma_timestring(dt: datetime) -> str:
    """Format a datetime as a v3 comma-delimited SeedLink time string.

    Format: ``year,month,day,hour,minute,second``. Fractional seconds are
    not representable in v3 and are truncated.
    """
    dt = dt.astimezone(timezone.utc)
    return f"{dt.year},{dt.month},{dt.day},{dt.hour},{dt.minute},{dt.second}"
