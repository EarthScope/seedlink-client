"""Tests for seedlink_client.client: framing, handshake, and negotiation."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock

import pytest

from seedlink_client.client import SeedLink
from seedlink_client.protocol import (
    FORMAT_JSON,
    FORMAT_XML,
    SUBFORMAT_JSON_ERROR,
    SUBFORMAT_JSON_INFO,
    Protocol,
    SeedLinkAuthError,
    SeedLinkError,
    SeedLinkPacket,
    SeedLinkTimeout,
    _RawFrame,
)
from seedlink_client.streams import Stream


def make_client(protocol: Protocol | None = None) -> SeedLink:
    """Construct a SeedLink with a mocked socket for framing tests."""
    client = SeedLink(host="localhost", port=18000, tls=False, protocol=protocol)
    client._sock = MagicMock()
    client.protocol = protocol
    return client


def _mock_recv_stream(stream: bytes):
    """Build a recv_into side effect that serves raw `stream` bytes verbatim,
    one real socket read at a time (whatever fits the caller's buffer)."""
    remaining = bytearray(stream)

    def _recv_into(buf):
        if not remaining:
            return 0
        n = min(len(buf), len(remaining))
        buf[:n] = remaining[:n]
        del remaining[:n]
        return n

    return _recv_into


def _v4_frame(payload: bytes, station_id: str = "IU_KONO", seqnum: int = 42,
              fmt: str = "2", subfmt: str = "D") -> bytes:
    sid = station_id.encode("ascii")
    header = struct.pack("<2sccIQB", b"SE", fmt.encode(), subfmt.encode(),
                          len(payload), seqnum, len(sid))
    return header + sid + payload


class TestClassifyNext:
    def test_v4_signature(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"SE" + b"x" * 20))
        from seedlink_client.protocol import StreamEvent
        assert client._classify_next() is StreamEvent.PACKET

    def test_end(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"END"))
        from seedlink_client.protocol import StreamEvent
        assert client._classify_next() is StreamEvent.END

    def test_error(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"ERROR ARGUMENTS\r\n"))
        from seedlink_client.protocol import StreamEvent
        assert client._classify_next() is StreamEvent.ERROR

    def test_garbage_raises(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"garbage!"))
        with pytest.raises(SeedLinkError):
            client._classify_next()


class TestRecvFrameV4:
    def test_data_packet(self):
        client = make_client(Protocol.V4)
        frame_bytes = _v4_frame(b"payloadbytes", station_id="IU_KONO", seqnum=99)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(frame_bytes))
        frame = client._recv_frame()
        assert frame.station_id == "IU_KONO"
        assert frame.seqnum == 99
        assert frame.payload == b"payloadbytes"
        assert frame.payload_format == "2"

    def test_dialup_end(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"END"))
        assert client._recv_frame() is None

    def test_error_reply(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"ERROR INTERNAL oops\r\n"))
        resp = client._recv_frame()
        assert not resp
        assert resp.code == "INTERNAL"
        assert resp.message == "oops"

    def test_info_packet_no_station_id(self):
        client = make_client(Protocol.V4)
        frame_bytes = _v4_frame(b'{"software":"x"}', station_id="", seqnum=0, fmt="J", subfmt="I")
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(frame_bytes))
        frame = client._recv_frame()
        assert frame.payload_format == "J"
        assert frame.payload_subformat == "I"

    def test_frame_split_across_many_small_reads(self):
        """_recv_frame_v4() ensures the header, then the whole remainder, in
        just two _ensure() calls -- exercise that against a socket that
        delivers one byte per recv_into(), which forces multiple buffer
        compactions in between."""
        client = make_client(Protocol.V4)
        frame_bytes = _v4_frame(b"payloadbytes", station_id="IU_KONO", seqnum=99)
        chunks = iter([frame_bytes[i:i + 1] for i in range(len(frame_bytes))])

        def _recv_into(buf):
            chunk = next(chunks, b"")
            buf[:len(chunk)] = chunk
            return len(chunk)

        client._sock.recv_into = MagicMock(side_effect=_recv_into)
        frame = client._recv_frame()
        assert frame.station_id == "IU_KONO"
        assert frame.seqnum == 99
        assert frame.payload == b"payloadbytes"


class TestHasBuffered:
    def test_buffered_bytes_short_circuits(self):
        client = make_client(Protocol.V4)
        client._recv_start, client._recv_end = 0, 5
        assert client._has_buffered()
        client._sock.pending.assert_not_called()

    def test_empty_buffer_non_ssl_socket_skips_pending(self):
        client = make_client(Protocol.V4)
        client._recv_start = client._recv_end = 0
        client._is_ssl = False
        assert not client._has_buffered()
        client._sock.pending.assert_not_called()

    def test_empty_buffer_ssl_socket_checks_pending(self):
        client = make_client(Protocol.V4)
        client._recv_start = client._recv_end = 0
        client._is_ssl = True
        client._sock.pending.return_value = 3
        assert client._has_buffered()


class TestUpdateStreamState:
    def test_matching_stream_gets_seqnum_deferred_timestamp(self):
        client = make_client(Protocol.V4)
        stream = Stream(station_id="IU_KONO")
        client._streams = [stream]
        pkt = SeedLinkPacket(station_id="IU_KONO", seqnum=7, payload_format="2",
                              payload_subformat="D", payload=b"not really miniSEED")
        client._update_stream_state(pkt)
        assert stream.seqnum == 7
        # The payload above isn't parseable miniSEED, so if the timestamp
        # were resolved eagerly this packet would raise; storing it
        # unresolved instead proves the parse is deferred.
        assert stream.pending_packet is pkt

    def test_no_seqnum_is_a_noop(self):
        client = make_client(Protocol.V4)
        stream = Stream(station_id="IU_KONO", seqnum=3)
        client._streams = [stream]
        pkt = SeedLinkPacket(station_id="IU_KONO", seqnum=None, payload_format="2",
                              payload_subformat="D", payload=b"x")
        client._update_stream_state(pkt)
        assert stream.seqnum == 3
        assert stream.pending_packet is None

    def test_match_cache_reused_then_invalidated_by_add_stream(self):
        client = make_client(Protocol.V4)
        stream = Stream(station_id="IU_*")
        client._streams = [stream]
        pkt = SeedLinkPacket(station_id="IU_KONO", seqnum=1, payload_format="2",
                              payload_subformat="D", payload=b"x")
        client._update_stream_state(pkt)
        cached = client._match_cache["IU_KONO"]
        assert cached == [stream]
        client._update_stream_state(pkt)
        assert client._match_cache["IU_KONO"] is cached  # reused, not rebuilt
        client.add_stream("GE_WLF")
        assert client._match_cache == {}


class TestSendCommand:
    def test_sends_text_and_terminator(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"OK\r\n"))
        from seedlink_client._commands import slproto
        resp = client._send_command(slproto("4.0"))
        client._sock.sendall.assert_called_once_with(b"SLPROTO 4.0\r\n")
        assert resp

    def test_debug_logs_command_and_reply(self, caplog):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"OK\r\n"))
        from seedlink_client._commands import slproto
        with caplog.at_level("DEBUG", logger="seedlink_client.client"):
            client._send_command(slproto("4.0"))
        assert "--> SLPROTO 4.0" in caplog.text
        assert "<-- OK" in caplog.text

    def test_no_reply_when_parse_none(self):
        client = make_client(Protocol.V4)
        from seedlink_client._commands import bye
        result = client._send_command(bye())
        assert result is None
        client._sock.sendall.assert_called_once_with(b"BYE\r\n")

    def test_not_connected_raises(self):
        client = SeedLink()
        from seedlink_client._commands import bye
        with pytest.raises(SeedLinkError):
            client._send_command(bye())

    def test_realistic_jwt_length_command_is_sent(self):
        """A real AUTH JWT token routinely runs several hundred bytes --
        well past the v4 spec's 255-byte command line limit, which is
        enforced at MAX_COMMAND_LEN's much larger, deliberate ceiling
        instead (see protocol.MAX_COMMAND_LEN)."""
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"OK\r\n"))
        from seedlink_client._commands import auth_jwt

        token = "x" * 800
        client._send_command(auth_jwt(token))
        client._sock.sendall.assert_called_once_with(f"AUTH JWT {token}\r\n".encode("ascii"))

    def test_command_past_max_length_rejected(self):
        client = make_client(Protocol.V4)
        from seedlink_client._commands import auth_jwt
        from seedlink_client.protocol import MAX_COMMAND_LEN

        token = "x" * MAX_COMMAND_LEN
        with pytest.raises(SeedLinkError):
            client._send_command(auth_jwt(token))


class TestNegotiateV3MultiStationSkip:
    """A rejected v3 STATION should skip that stream's SELECT/DATA but not abort."""

    def test_rejected_station_skips_its_selectors(self):
        client = make_client(Protocol.V3)
        client._streams = [
            Stream(station_id="IU_KONO", selectors=["BHZ"]),
            Stream(station_id="GE_WLF", selectors=["BHZ"]),
        ]
        client._multistation = True
        # negotiate() sorts exact station IDs alphabetically (libslink order),
        # so GE_WLF is sent first here, then IU_KONO.
        replies = iter([
            b"OK\r\n",     # STATION GE_WLF accepted
            b"OK\r\n",     # SELECT for GE_WLF
            b"OK\r\n",     # DATA for GE_WLF
            b"ERROR\r\n",  # STATION IU_KONO rejected
        ])
        client._sock.recv_into = MagicMock(side_effect=lambda buf: _consume(buf, next(replies)))
        client.negotiate()
        # STATION/SELECT/DATA(WLF) sent and read; STATION(KONO) rejected, its
        # SELECT/DATA skipped; END sent last with no reply expected.
        assert client._sock.sendall.call_count == 5
        sent_texts = [call.args[0] for call in client._sock.sendall.call_args_list]
        assert sent_texts == [
            b"STATION WLF GE\r\n",
            b"SELECT BHZ\r\n",
            b"DATA\r\n",
            b"STATION KONO IU\r\n",
            b"END\r\n",
        ]

    def test_all_stations_rejected_raises(self):
        client = make_client(Protocol.V3)
        client._streams = [Stream(station_id="IU_KONO", selectors=["BHZ"])]
        client._multistation = True
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"ERROR\r\n"))
        with pytest.raises(SeedLinkError, match="No stations accepted"):
            client.negotiate()


def _consume(buf, chunk: bytes) -> int:
    n = min(len(buf), len(chunk))
    buf[:n] = chunk[:n]
    return n


class TestNegotiateV4HardFail:
    def test_rejected_station_raises_immediately(self):
        client = make_client(Protocol.V4)
        client._streams = [Stream(station_id="IU_KONO", selectors=["B_H_?"])]
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"ERROR ARGUMENTS bad station\r\n"))
        with pytest.raises(SeedLinkError):
            client.negotiate()


class TestConnectHandshakeFlag:
    def test_handshake_false_skips_hello(self, monkeypatch):
        client = SeedLink(host="localhost", port=18000, tls=False)
        monkeypatch.setattr(client, "_connect_socket", MagicMock())
        monkeypatch.setattr(client, "_do_hello", MagicMock())
        client.connect(handshake=False)
        client._connect_socket.assert_called_once()
        client._do_hello.assert_not_called()
        assert client.protocol is None

    def test_handshake_true_runs_hello(self, monkeypatch):
        client = SeedLink(host="localhost", port=18000, tls=False)
        monkeypatch.setattr(client, "_connect_socket", MagicMock())
        monkeypatch.setattr(client, "_do_hello", MagicMock())
        client.connect()
        client._connect_socket.assert_called_once()
        client._do_hello.assert_called_once_with()


class TestAuthFailure:
    def test_auth_userpass_rejected_raises_autherror(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"ERROR AUTH bad credentials\r\n"))
        from seedlink_client._commands import auth_userpass
        with pytest.raises(SeedLinkAuthError):
            client._send_command(auth_userpass("bob", "wrong"))


class TestReadLine:
    def test_reads_up_to_crlf(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"OK\r\nEXTRA"))
        assert client._read_line() == "OK"

    def test_non_ascii_closes_connection(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(b"\xff\xfe\r\n"))
        with pytest.raises(SeedLinkError):
            client._read_line()
        assert not client.is_connected


class TestRecvAllTimeout:
    def test_clean_timeout_raises_without_closing(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=TimeoutError("timed out"))
        with pytest.raises(SeedLinkTimeout):
            client._ensure(5)
        assert client.is_connected

    def test_partial_read_timeout_closes_connection(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(side_effect=[2, TimeoutError("timed out")])
        with pytest.raises(SeedLinkTimeout, match="partial"):
            client._ensure(5)
        assert not client.is_connected

    def test_connection_closed_on_empty_recv(self):
        client = make_client(Protocol.V4)
        client._sock.recv_into = MagicMock(return_value=0)
        with pytest.raises(SeedLinkError, match="Connection closed"):
            client._ensure(5)
        assert not client.is_connected


class TestCollectIdleTimeout:
    """B7 regression: the idle timeout must fire even when the socket
    keeps reporting data available, as long as none of it is real
    (non-INFO) data -- see collect()'s idle-timeout comment."""

    def _info_frame(self) -> _RawFrame:
        return _RawFrame(station_id="", seqnum=None, payload_format=FORMAT_XML,
                          payload_subformat=SUBFORMAT_JSON_INFO, payload=b"<x/>",
                          info_continues=False)

    def test_fires_despite_constant_info_traffic(self):
        client = make_client(Protocol.V4)
        client._streaming = True
        client._idle_timeout = 0.05
        client._poll_readable = lambda timeout: True
        client._recv_frame = self._info_frame
        with pytest.raises(SeedLinkTimeout, match="No data"):
            next(client.collect(reconnect=False))

    def test_keepalive_still_sent_while_quiet(self):
        """A quiet channel (nothing readable) still gets its periodic INFO
        ID heartbeat -- eventually hits the idle timeout too, here just used
        as a bound so the test doesn't hang."""
        client = make_client(Protocol.V4)
        client._streaming = True
        client._idle_timeout = 0.2
        client._keepalive = 0.05
        client._poll_readable = lambda timeout: False
        client._send_command = MagicMock(return_value=None)
        with pytest.raises(SeedLinkTimeout):
            next(client.collect(reconnect=False))
        client._send_command.assert_called()
        assert client._send_command.call_args_list[0].args[0].text == "INFO ID"


class TestCollectJsonError:
    """A mid-stream v4 JSON ERROR packet must be handled the same way a
    synchronous ERROR reply line is -- logged and reconnected/raised --
    not yielded to the caller as an ordinary data packet."""

    def _error_frame(self) -> _RawFrame:
        return _RawFrame(station_id="", seqnum=None, payload_format=FORMAT_JSON,
                          payload_subformat=SUBFORMAT_JSON_ERROR,
                          payload=b'{"message": "no such station"}', info_continues=False)

    def test_raised_when_reconnect_false(self, caplog):
        client = make_client(Protocol.V4)
        client._streaming = True
        client._poll_readable = lambda timeout: True
        client._recv_frame = self._error_frame
        with caplog.at_level("WARNING"):
            with pytest.raises(SeedLinkError, match="no such station"):
                next(client.collect(reconnect=False))
        assert "no such station" in caplog.text


class TestFromServerString:
    def test_default(self):
        client = SeedLink.from_server_string("")
        assert client._host == "localhost"
        assert client._port == 18000

    def test_host_and_port(self):
        client = SeedLink.from_server_string("example.com:18500")
        assert client._host == "example.com"
        assert client._port == 18500
        assert client._tls  # auto-enabled on the TLS port

    def test_bare_ipv6_ambiguous_rejected(self):
        with pytest.raises(ValueError):
            SeedLink.from_server_string("::1:18000")

    def test_bracketed_ipv6(self):
        client = SeedLink.from_server_string("[::1]:18000")
        assert client._host == "::1"
        assert client._port == 18000
