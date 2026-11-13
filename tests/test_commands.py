"""Tests for seedlink_client._commands: the command builders and negotiation planners."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from seedlink_client._commands import (
    NegotiationWalk,
    auth_jwt,
    auth_userpass,
    encode,
    plan_handshake,
    plan_negotiation,
    station_v3,
    station_v4,
)
from seedlink_client.protocol import MAX_COMMAND_LEN, Protocol, SeedLinkError
from seedlink_client.streams import Stream


class TestEncode:
    def test_terminators(self):
        assert encode(station_v4("IU_KONO")) == b"STATION IU_KONO\r"
        assert encode(plan_handshake(Protocol.V4, {}, None, None, None, False)[0]) == b"SLPROTO 4.0\r\n"

    def test_over_length_rejected(self):
        with pytest.raises(SeedLinkError, match="command-line limit"):
            encode(station_v4("X" * MAX_COMMAND_LEN))

    def test_non_ascii_rejected(self):
        with pytest.raises(SeedLinkError, match="non-ASCII"):
            encode(station_v4("IU_KÖNO"))

    def test_embedded_line_break_rejected(self):
        with pytest.raises(SeedLinkError, match="control characters"):
            encode(station_v4("IU_KONO\r\nBYE"))


class TestAuthMasking:
    def test_userpass_password_masked(self):
        cmd = auth_userpass("alice", "s3cret")
        assert cmd.text == "AUTH USERPASS alice s3cret"
        assert cmd.display_text == "AUTH USERPASS alice ****"

    def test_jwt_token_masked(self):
        cmd = auth_jwt("eyJhbGciOi.payload.sig")
        assert "eyJ" not in cmd.display_text

    def test_error_message_masked(self):
        with pytest.raises(SeedLinkError) as excinfo:
            encode(auth_jwt("x" * MAX_COMMAND_LEN))
        assert "xxxx" not in str(excinfo.value)


class TestStationV3:
    @pytest.mark.parametrize("station_id", ["KONO", "IU_", "_KONO"])
    def test_missing_net_or_sta_rejected(self, station_id):
        with pytest.raises(SeedLinkError, match="NET_STA"):
            station_v3(station_id, expect_reply=True)


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

    def test_v4_only_selector_passed_through_unconverted_for_v3(self):
        """A v4 selector with no v3 equivalent (multi-character subsource)
        is sent as-is rather than dropped -- see v4_to_v3_selector's
        docstring and _wire_selector."""
        streams = [Stream(station_id="IU_KONO", selectors=["B_H_ZZ"])]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        select_cmd = next(c for c in cmds if c.role == "select")
        assert select_cmd.text == "SELECT B_H_ZZ"


class TestNegotiationWalk:
    """The shared per-command bookkeeping both transports' negotiate() loops
    drive; see client.SeedLink.negotiate() for how it's used."""

    @staticmethod
    def _walk_plan(streams, replies, multistation=True, invalid=None):
        """Drive a v3 plan through a walk, replying OK except as given in
        ``replies`` (command text -> ERROR message) or ``invalid`` (command
        text -> reply status); returns the commands sent."""
        from seedlink_client.protocol import SeedLinkResponse

        walk = NegotiationWalk()
        sent = []
        for cmd in plan_negotiation(Protocol.V3, streams, dialup=False, multistation=multistation,
                                    resume=True, lastpkttime=True, batch_active=False):
            if not walk.should_send(cmd):
                continue
            sent.append(cmd.text)
            msg = replies.get(cmd.text)
            status = (invalid or {}).get(cmd.text) or ("ERROR" if msg else "OK")
            resp = None if cmd.parse is None else SeedLinkResponse(
                status=status, code=None, message=msg or "")
            walk.record(cmd, resp)
        walk.finish()
        return sent

    def test_rejected_select_logged(self, caplog):
        streams = [Stream(station_id="IU_KONO", selectors=["BHZ", "BHN"])]
        with caplog.at_level("WARNING"):
            sent = self._walk_plan(streams, {"SELECT BHN": "bad selector"})
        assert "SELECT rejected for IU_KONO: bad selector" in caplog.text
        assert sent[-2:] == ["DATA", "END"]

    def test_invalid_reply_fatal(self):
        streams = [Stream(station_id="IU_KONO", selectors=["BHZ"])]
        with pytest.raises(SeedLinkError, match="Invalid response to SELECT BHZ"):
            self._walk_plan(streams, {}, invalid={"SELECT BHZ": "SLINFO"})

    def test_all_selects_rejected_fatal(self):
        streams = [Stream(station_id="GE_WLF"),
                   Stream(station_id="IU_KONO", selectors=["BHZ", "BHN"])]
        with pytest.raises(SeedLinkError, match="No selectors accepted for IU_KONO"):
            self._walk_plan(streams, {"SELECT BHZ": "bad", "SELECT BHN": "bad"})

    def test_all_selects_rejected_fatal_uni_station(self):
        streams = [Stream(station_id="*", selectors=["BHZ"])]
        with pytest.raises(SeedLinkError, match=r"No selectors accepted for \*"):
            self._walk_plan(streams, {"SELECT BHZ": "bad"}, multistation=False)

    def test_batched_selects_count_as_accepted(self):
        from seedlink_client._commands import data_v3, select_v3

        walk = NegotiationWalk()
        select_cmd = select_v3("*", "BHZ", expect_reply=False)
        walk.should_send(select_cmd)
        walk.record(select_cmd, None)
        assert walk.should_send(data_v3("*", "DATA", None, None, expect_reply=False))

    def test_rejected_station_skips_dependents(self):
        walk = NegotiationWalk()
        from seedlink_client._commands import data_v3, select_v3, station_v3
        from seedlink_client.protocol import SeedLinkResponse

        station_cmd = station_v3("IU_KONO", expect_reply=True)
        assert walk.should_send(station_cmd)
        walk.record(station_cmd, SeedLinkResponse(status="ERROR", code=None, message="no such station"))

        select_cmd = select_v3("IU_KONO", "BHZ", expect_reply=True)
        assert not walk.should_send(select_cmd)
        data_cmd = data_v3("IU_KONO", "DATA", None, None, expect_reply=True)
        assert not walk.should_send(data_cmd)

    def test_rejected_data_logged_with_command_name(self, caplog):
        """The log message names the actual command sent (DATA/FETCH/TIME),
        not the generic "data" role used for routing."""
        from seedlink_client._commands import data_v3
        from seedlink_client.protocol import SeedLinkResponse

        walk = NegotiationWalk()
        cmd = data_v3("IU_KONO", "FETCH", None, None, expect_reply=True)
        with caplog.at_level("WARNING"):
            walk.record(cmd, SeedLinkResponse(status="ERROR", code=None, message="denied"))
        assert "FETCH rejected for IU_KONO" in caplog.text

    def test_finish_raises_if_no_station_accepted(self):
        walk = NegotiationWalk()
        from seedlink_client._commands import station_v3
        from seedlink_client.protocol import SeedLinkResponse

        cmd = station_v3("IU_KONO", expect_reply=True)
        walk.should_send(cmd)
        walk.record(cmd, SeedLinkResponse(status="ERROR", code=None, message="rejected"))
        with pytest.raises(SeedLinkError, match="No stations accepted"):
            walk.finish()

    def test_finish_ok_if_no_station_role_seen(self):
        """v3 uni-station negotiation has no STATION command at all."""
        NegotiationWalk().finish()  # must not raise


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

    def test_time_window_resumes_from_seqnum(self):
        streams = [Stream(station_id="IU_KONO", seqnum=100)]
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False,
                                 start_time=start, end_time=end)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA 101 2024-01-01T00:00:00Z 2024-01-02T00:00:00Z"

    def test_time_window_overlapping_wildcard_requests_all(self):
        streams = [Stream(station_id="IU_KONO", seqnum=100),
                   Stream(station_id="IU_*", seqnum=500)]
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False,
                                 start_time=start)
        assert [c.text for c in cmds if c.role == "data"] == [
            "DATA 101 2024-01-01T00:00:00Z",
            "DATA ALL 2024-01-01T00:00:00Z",
        ]

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

    def test_data_sequence_wraps_at_24_bits(self):
        streams = [Stream(station_id="IU_KONO", seqnum=0xFFFFFF)]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=False, batch_active=False)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA 0"

    def test_dialup_uses_fetch(self):
        streams = [Stream(station_id="IU_KONO")]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=True, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "FETCH"

    def test_resume_includes_last_packet_timestamp(self):
        streams = [Stream(station_id="IU_KONO", seqnum=100, timestamp="2024-01-01T00:00:00Z")]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                 resume=True, lastpkttime=True, batch_active=False)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA 65 2024,1,1,0,0,0"

    def test_malformed_saved_timestamp_is_dropped_not_fatal(self, caplog):
        # A hand-edited or truncated state file's timestamp field must not
        # abort negotiation with a bare ValueError -- resume by sequence
        # number alone instead.
        streams = [Stream(station_id="IU_KONO", seqnum=100, timestamp="not-a-timestamp")]
        with caplog.at_level("WARNING"):
            cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=True,
                                     resume=True, lastpkttime=True, batch_active=False)
        data_cmd = next(c for c in cmds if c.role == "data")
        assert data_cmd.text == "DATA 65"
        assert "IU_KONO" in caplog.text

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

    def test_select_expects_no_reply_while_batched(self):
        # A batched v3 server suppresses OK/ERROR for SELECT same as it does
        # in multi-station mode; expecting one here would hang forever
        # waiting for a reply line the server never sends.
        streams = [Stream(station_id="*", selectors=["BHZ"])]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=False,
                                 resume=True, lastpkttime=True, batch_active=True)
        select_cmd = next(c for c in cmds if c.role == "select")
        assert select_cmd.parse is None

    def test_select_expects_reply_when_not_batched(self):
        streams = [Stream(station_id="*", selectors=["BHZ"])]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=False,
                                 resume=True, lastpkttime=True, batch_active=False)
        select_cmd = next(c for c in cmds if c.role == "select")
        assert select_cmd.parse is not None

    def test_requires_exactly_one_stream(self):
        streams = [Stream(station_id="*"), Stream(station_id="IU_*")]
        with pytest.raises(SeedLinkError):
            plan_negotiation(Protocol.V3, streams, dialup=False, multistation=False,
                              resume=True, lastpkttime=True, batch_active=False)

    def test_received_stations_not_negotiated(self):
        streams = [Stream(station_id="IU_KONO", seqnum=9), Stream(station_id="*", seqnum=4)]
        cmds = plan_negotiation(Protocol.V3, streams, dialup=False, multistation=False,
                                 resume=True, lastpkttime=False, batch_active=False)
        assert [c.text for c in cmds] == ["DATA 5"]


class TestPlanNegotiationTolerated:
    def test_v4_station_covered_by_wildcard_tolerated(self):
        streams = [Stream(station_id="IU_KONO", selectors=["B_H_Z"]),
                   Stream(station_id="GE_WLF"), Stream(station_id="IU_*")]
        cmds = plan_negotiation(Protocol.V4, streams, dialup=False, multistation=True,
                                resume=True, lastpkttime=False, batch_active=False)
        assert [(c.text, c.tolerated) for c in cmds] == [
            ("STATION IU_KONO", True), ("SELECT B_H_Z", True), ("DATA", True),
            ("STATION GE_WLF", False), ("DATA", False),
            ("STATION IU_*", False), ("DATA", False),
            ("END", False),
        ]
