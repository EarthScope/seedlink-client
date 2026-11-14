"""Tests for seedlink_client.mseed, the pymseed adapter.

Fixture records are generated with pymseed itself rather than hand-built
byte literals, so these tests exercise the real libmseed encode/decode
round-trip the same way a live server's records would.
"""

from __future__ import annotations

import struct

import pytest
from pymseed import MS3Record, timestr2nstime

from seedlink_client.mseed import detect_record_length, extract_info_text, parse_record, station_id
from seedlink_client.protocol import SeedLinkError


def _make_mseed_record(sourceid="FDSN:IU_COLA_00_B_H_Z", reclen=512) -> bytes:
    msr = MS3Record(reclen=reclen)
    msr.sourceid = sourceid
    msr.starttime = timestr2nstime("2024-01-01T00:00:00Z")
    msr.samprate = 20.0
    from pymseed import DataEncoding

    msr.encoding = DataEncoding.STEIM2
    msr.pubversion = 1
    records = list(msr.generate(data_samples=list(range(100)), sample_type="i"))
    assert len(records) == 1
    return records[0]


def _make_info_record(xml_text: str, seqnum: int = 1, terminating: bool = True) -> bytes:
    """Build a v3 SLINFO-style miniSEED2 record exactly as ringserver does."""
    record = bytearray(512)
    record[0:6] = f"{seqnum:06d}".encode("ascii")
    record[6:7] = b"D"
    record[7:8] = b" "
    record[8:13] = b"INFO "
    record[13:15] = b"  "
    record[15:18] = b"INF"
    record[18:20] = b"XX"
    struct.pack_into(">H", record, 20, 2024)  # year
    struct.pack_into(">H", record, 22, 1)  # day
    record[24] = record[25] = record[26] = 0
    struct.pack_into(">H", record, 28, 0)  # fsec
    nsamps = min(len(xml_text), 456)
    struct.pack_into(">H", record, 30, nsamps)
    struct.pack_into(">h", record, 32, 0)
    struct.pack_into(">h", record, 34, 0)
    record[39] = 1  # numblockettes
    struct.pack_into(">H", record, 44, 56)  # dataoffset
    struct.pack_into(">H", record, 46, 48)  # blockette offset
    struct.pack_into(">H", record, 48, 1000)
    struct.pack_into(">H", record, 50, 0)
    record[52] = 0  # DE_TEXT
    record[53] = 1  # big endian
    record[54] = 9  # 2^9 = 512
    data = xml_text.encode("ascii")[:nsamps]
    record[56:56 + len(data)] = data
    return bytes(record)


class TestDetectRecordLength:
    def test_complete_record(self):
        record = _make_mseed_record()
        length, formatversion = detect_record_length(record)
        assert length == len(record)
        assert formatversion == 3

    def test_truncated_record_returns_none_or_raises(self):
        record = _make_mseed_record()
        # Fewer than libmseed's fixed-header minimum: can't be told apart
        # from invalid data.
        with pytest.raises(SeedLinkError):
            detect_record_length(record[:30])

    def test_non_mseed_raises(self):
        with pytest.raises(SeedLinkError):
            detect_record_length(b"not miniSEED data at all, just junk padding out to 64 bytes!!")

    def test_oversized_record_length_raises(self):
        record = bytearray(_make_info_record("<seedlink/>"))
        record[54] = 21  # 2^21 bytes, over MAX_RECORD_LEN
        with pytest.raises(SeedLinkError, match="exceeds limit"):
            detect_record_length(bytes(record))

    def test_record_without_b1000_found_by_next_v3_packet(self):
        def without_b1000(seqnum):
            record = bytearray(_make_info_record("<x/>", seqnum=seqnum))
            record[39] = 0  # numblockettes
            struct.pack_into(">H", record, 46, 0)
            record[48:56] = bytes(8)
            return bytes(record)

        stream = without_b1000(1) + b"SL000002" + without_b1000(2)
        assert detect_record_length(stream[:512]) is None
        assert detect_record_length(stream) == (512, 2)

    def test_info_record_detected(self):
        record = _make_info_record("<seedlink/>")
        length, formatversion = detect_record_length(record)
        assert length == 512
        assert formatversion == 2


class TestParseRecord:
    def test_parses_sourceid_and_time(self):
        record = _make_mseed_record()
        parsed = parse_record(record)
        assert parsed.sourceid == "FDSN:IU_COLA_00_B_H_Z"
        assert parsed.starttime_str() == "2024-01-01T00:00:00Z"

    def test_non_mseed_raises(self):
        with pytest.raises(SeedLinkError):
            parse_record(b"not a record")


class TestStationId:
    def test_derives_net_sta(self):
        record = parse_record(_make_mseed_record())
        assert station_id(record) == "IU_COLA"


class TestExtractInfoText:
    def test_round_trips_text(self):
        xml = '<?xml version="1.0"?><seedlink><id>Test</id></seedlink>'
        record = _make_info_record(xml)
        assert extract_info_text(record) == xml

    def test_non_text_record_raises(self):
        record = _make_mseed_record()  # STEIM2-encoded, not text
        with pytest.raises(SeedLinkError):
            extract_info_text(record)

    def test_non_mseed_raises(self):
        with pytest.raises(SeedLinkError):
            extract_info_text(b"not a record")
