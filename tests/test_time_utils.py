"""Tests for seedlink_client.time_utils."""

from __future__ import annotations

from datetime import datetime, timezone

from seedlink_client.time_utils import (
    parse_timestring,
    to_comma_timestring,
    to_iso_timestring,
)


class TestParseTimestring:
    """parse_timestring() accepts both v4 ISO 8601 and v3 comma-delimited strings."""

    def test_iso_with_fraction_and_z(self):
        dt = parse_timestring("2025-02-06T10:30:00.123456Z")
        assert dt == datetime(2025, 2, 6, 10, 30, 0, 123456, tzinfo=timezone.utc)

    def test_iso_single_digit_month_day(self):
        dt = parse_timestring("2025-2-6T10:30:00")
        assert dt == datetime(2025, 2, 6, 10, 30, 0, tzinfo=timezone.utc)

    def test_iso_space_separator(self):
        dt = parse_timestring("2025-02-06 10:30:00")
        assert dt == datetime(2025, 2, 6, 10, 30, 0, tzinfo=timezone.utc)

    def test_iso_date_only(self):
        dt = parse_timestring("2025-02-06")
        assert dt == datetime(2025, 2, 6, tzinfo=timezone.utc)

    def test_comma_delimited(self):
        dt = parse_timestring("2002,08,05,14,00,00")
        assert dt == datetime(2002, 8, 5, 14, 0, 0, tzinfo=timezone.utc)

    def test_comma_delimited_partial(self):
        dt = parse_timestring("2002,08,05")
        assert dt == datetime(2002, 8, 5, 0, 0, 0, tzinfo=timezone.utc)

    def test_comma_delimited_year_month_only(self):
        dt = parse_timestring("2002,08")
        assert dt == datetime(2002, 8, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_comma_delimited_missing_seconds(self):
        dt = parse_timestring("2002,08,05,14,30")
        assert dt == datetime(2002, 8, 5, 14, 30, 0, tzinfo=timezone.utc)


class TestToIsoTimestring:
    def test_with_fraction(self):
        dt = datetime(2024, 1, 1, 0, 0, 0, 500000, tzinfo=timezone.utc)
        assert to_iso_timestring(dt) == "2024-01-01T00:00:00.500000Z"

    def test_without_fraction(self):
        dt = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert to_iso_timestring(dt) == "2024-01-01T00:00:00Z"


class TestToCommaTimestring:
    def test_basic(self):
        dt = datetime(2002, 8, 5, 14, 0, 0, tzinfo=timezone.utc)
        assert to_comma_timestring(dt) == "2002,8,5,14,0,0"
