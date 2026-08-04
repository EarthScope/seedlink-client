"""Tests for seedlink_client._commands: the command builders and negotiation planners."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from seedlink_client._commands import plan_handshake, plan_negotiation
from seedlink_client.protocol import Protocol, SeedLinkError
from seedlink_client.streams import Stream


class TestPlanHandshake:
    def test_v4_full_handshake(self):
        cmds = plan_handshake(Protocol.V4, {}, "myclient", "1.0", ("bob", "secret"), want_batch=False)
        texts = [c.text for c in cmds]
        assert texts[0] == "SLPROTO 4.0"
        assert texts[1].startswith("USERAGENT myclient/1.0")
        assert texts[2] == "AUTH USERPASS bob secret"

    def test_v4_jwt_auth(self):
        cmds = plan_handshake(Protocol.V4, {}, None, None, "sometoken", want_batch=False)
        assert any(c.text == "AUTH JWT sometoken" for c in cmds)

    def test_v4_no_auth(self):
        cmds = plan_handshake(Protocol.V4, {}, None, None, None, want_batch=False)
        assert not any(c.text.startswith("AUTH") for c in cmds)

    def test_v3_capabilities_only_if_advertised(self):
        cmds = plan_handshake(Protocol.V3, {"CAP": True}, None, None, None, want_batch=False)
        assert cmds[0].text == "CAPABILITIES EXTREPLY"

    def test_v3_no_capabilities_if_not_advertised(self):
        cmds = plan_handshake(Protocol.V3, {}, None, None, None, want_batch=False)
        assert cmds == []

    def test_v3_batch_appended_last(self):
        cmds = plan_handshake(Protocol.V3, {"CAP": True}, None, None, None, want_batch=True)
        assert cmds[-1].text == "BATCH"

    def test_v4_batch_ignored(self):
        cmds = plan_handshake(Protocol.V4, {}, None, None, None, want_batch=True)
        assert not any(c.text == "BATCH" for c in cmds)

    def test_username_with_space_rejected(self):
        with pytest.raises(SeedLinkError):
            plan_handshake(Protocol.V4, {}, None, None, ("bad user", "pw"), want_batch=False)


class TestSelectorAutoUpgrade:
    """A v3-style selector sent over a v4 connection (or vice versa) is
    converted to the wire protocol's own syntax, so 'BHZ' works whichever
    protocol was negotiated -- this is what makes selectors transparently
    dual-protocol, not just the framing."""

    def test_v3_selector_upgraded_for_v4(self):
        streams = [Stream(station_id="IU_KONO", selectors=["BHZ"])]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        select_cmd = next(c for c in cmds if c.role == "select")
        assert select_cmd.text == "SELECT *_B_H_Z"

    def test_already_v4_selector_passed_through(self):
        streams = [Stream(station_id="IU_KONO", selectors=["00_B_H_Z"])]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        select_cmd = next(c for c in cmds if c.role == "select")
        assert select_cmd.text == "SELECT 00_B_H_Z"

    def test_v4_selector_downgraded_for_v3(self):
        streams = [Stream(station_id="IU_KONO", selectors=["00_B_H_Z"])]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        select_cmd = next(c for c in cmds if c.role == "select")
        assert select_cmd.text == "SELECT 00BHZ"

    def test_already_v3_selector_passed_through(self):
        streams = [Stream(station_id="IU_KONO", selectors=["BHZ"])]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        select_cmd = next(c for c in cmds if c.role == "select")
        assert select_cmd.text == "SELECT BHZ"


class TestPlanNegotiationV4:
    def test_station_select_data_end(self):
        streams = [Stream(station_id="IU_KONO", selectors=["B_H_?"], seqnum=100)]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        assert [(c.text, c.terminator) for c in cmds] == [
            ("STATION IU_KONO", b"\r"),
            ("SELECT B_H_?", b"\r"),
            ("DATA 101", b"\r"),
            ("END", b"\r\n"),
        ]

    def test_multiple_selectors(self):
        streams = [Stream(station_id="IU_KONO", selectors=["B_H_Z", "B_H_N"])]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        selects = [c.text for c in cmds if c.role == "select"]
        assert selects == ["SELECT B_H_Z", "SELECT B_H_N"]

    def test_no_prior_seqnum_gives_bare_data(self):
        streams = [Stream(station_id="IU_KONO")]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA"

    def test_all_data(self):
        streams = [Stream(station_id="IU_KONO", all_data=True)]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA ALL"

    def test_dialup_uses_endfetch(self):
        streams = [Stream(station_id="IU_KONO")]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=True, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        assert cmds[-1].text == "ENDFETCH"

    def test_time_window_with_seqnum(self):
        streams = [Stream(station_id="IU_KONO", seqnum=100)]
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False,
                                 start_time=start, end_time=end)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA 101 2024-01-01T00:00:00Z 2024-01-02T00:00:00Z"

    def test_time_window_without_seqnum_requests_all(self):
        streams = [Stream(station_id="IU_KONO")]
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False,
                                 start_time=start)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA ALL 2024-01-01T00:00:00Z"

    def test_resume_false_ignores_seqnum(self):
        streams = [Stream(station_id="IU_KONO", seqnum=100)]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=False, lastpkttime=True, batch_active=False)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA"

    def test_multiple_streams(self):
        streams = [Stream(station_id="IU_KONO"), Stream(station_id="GE_WLF")]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        stations = [c.text for c in cmds if c.role == "station"]
        assert stations == ["STATION IU_KONO", "STATION GE_WLF"]
        assert cmds[-1].text == "END"  # single END at the very end


class TestPlanNegotiationV3Multi:
    def test_station_split_net_sta(self):
        streams = [Stream(station_id="IU_KONO")]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        station_cmd = next(c for c in cmds if c.role == "station")
        assert station_cmd.text == "STATION KONO IU"
        assert station_cmd.terminator == b"\r\n"

    def test_data_sequence_is_unpadded_hex(self):
        streams = [Stream(station_id="IU_KONO", seqnum=0x64)]  # 100 decimal
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA 65"  # 101 decimal -> unpadded hex

    def test_dialup_uses_fetch(self):
        streams = [Stream(station_id="IU_KONO")]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=True, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "FETCH"

    def test_time_window_uses_time_command(self):
        streams = [Stream(station_id="IU_KONO", seqnum=100)]
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False,
                                 start_time=start, end_time=end)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "TIME 2024,1,1,0,0,0 2024,1,2,0,0,0"

    def test_single_end_at_close(self):
        streams = [Stream(station_id="IU_KONO"), Stream(station_id="GE_WLF")]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        assert cmds[-1].text == "END"
        assert sum(1 for c in cmds if c.role == "end") == 1

    def test_batch_active_no_reply_expected(self):
        streams = [Stream(station_id="IU_KONO", selectors=["BHZ"])]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=True)
        for cmd in cmds:
            if cmd.role in ("station", "select", "data"):
                assert cmd.parse is None

    def test_not_batch_active_reply_expected(self):
        streams = [Stream(station_id="IU_KONO", selectors=["BHZ"])]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        for cmd in cmds:
            if cmd.role in ("station", "select", "data"):
                assert cmd.parse is not None


class TestPlanNegotiationV3Uni:
    def test_no_station_or_end(self):
        streams = [Stream(station_id="*", selectors=["BHZ"])]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=False,
                                 resume=True, lastpkttime=True, batch_active=False)
        assert not any(c.role in ("station", "end") for c in cmds)
        assert [c.text for c in cmds] == ["SELECT BHZ", "DATA"]

    def test_final_command_never_expects_reply(self):
        streams = [Stream(station_id="*", seqnum=5)]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=False,
                                 resume=True, lastpkttime=True, batch_active=False)
        data_cmd = cmds[-1]
        assert data_cmd.parse is None

    def test_select_always_expects_reply_regardless_of_batch(self):
        streams = [Stream(station_id="*", selectors=["BHZ"])]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=False,
                                 resume=True, lastpkttime=True, batch_active=True)
        select_cmd = next(c for c in cmds if c.role == "select")
        assert select_cmd.parse is not None

    def test_requires_exactly_one_stream(self):
        streams = [Stream(station_id="*"), Stream(station_id="IU_KONO")]
        with pytest.raises(SeedLinkError):
            plan_negotiation(Protocol.V3, streams, dialup=False, multistation=False,
                              resume=True, lastpkttime=True, batch_active=False)
