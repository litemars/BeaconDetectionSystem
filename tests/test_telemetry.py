"""Tests for data_plane/telemetry.py — pure-Python data structures.

Covers: ConnectionEvent, TelemetryBatch, TelemetryBuffer, DataPlaneStats.
No eBPF, no network; everything is in-memory.

Run with: pytest tests/test_telemetry.py -v
"""

import json
import struct
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from data_plane.telemetry import (
    ConnectionEvent,
    ConnectionEventCType,
    DataPlaneStats,
    Direction,
    Protocol,
    TCPFlags,
    TelemetryBatch,
    TelemetryBuffer,
)


# ---------------------------------------------------------------------------
# ConnectionEvent
# ---------------------------------------------------------------------------

class TestConnectionEvent:

    def _make_event(self, **kwargs):
        defaults = dict(
            timestamp_ns=1_000_000_000,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            packet_size=1024,
            protocol=6,
            tcp_flags=0x10,
            direction=1,
            timestamp_utc="2024-01-01T00:00:01Z",
            node_id="test-node",
        )
        defaults.update(kwargs)
        return ConnectionEvent(**defaults)

    def test_protocol_name_tcp(self):
        evt = self._make_event(protocol=6)
        assert evt.protocol_name == "TCP"

    def test_protocol_name_udp(self):
        evt = self._make_event(protocol=17)
        assert evt.protocol_name == "UDP"

    def test_protocol_name_unknown(self):
        evt = self._make_event(protocol=255)
        assert "255" in evt.protocol_name

    def test_direction_name_egress(self):
        evt = self._make_event(direction=1)
        assert evt.direction_name == "EGRESS"

    def test_direction_name_ingress(self):
        evt = self._make_event(direction=0)
        assert evt.direction_name == "INGRESS"

    def test_connection_key_format(self):
        evt = self._make_event()
        assert evt.connection_key == "192.168.1.10:54321->10.0.0.1:443/TCP"

    def test_bidirectional_key_sorted(self):
        """bidirectional_key is the same regardless of who initiates."""
        evt_fwd = self._make_event(
            src_ip="10.0.0.1", src_port=1234,
            dst_ip="10.0.0.2", dst_port=5678,
        )
        evt_rev = self._make_event(
            src_ip="10.0.0.2", src_port=5678,
            dst_ip="10.0.0.1", dst_port=1234,
        )
        assert evt_fwd.bidirectional_key == evt_rev.bidirectional_key

    def test_tcp_flags_list_ack(self):
        evt = self._make_event(protocol=6, tcp_flags=TCPFlags.ACK)
        assert evt.tcp_flags_list == ["ACK"]

    def test_tcp_flags_list_syn_ack(self):
        evt = self._make_event(protocol=6, tcp_flags=TCPFlags.SYN | TCPFlags.ACK)
        assert set(evt.tcp_flags_list) == {"SYN", "ACK"}

    def test_tcp_flags_list_empty_for_udp(self):
        evt = self._make_event(protocol=17, tcp_flags=0xFF)
        assert evt.tcp_flags_list == []

    def test_to_dict_roundtrip(self):
        evt = self._make_event()
        d = evt.to_dict()
        assert d["src_ip"] == "192.168.1.10"
        assert d["protocol"] == 6
        assert d["protocol_name"] == "TCP"
        assert "connection_key" in d

    def test_to_json_valid_json(self):
        evt = self._make_event()
        raw = evt.to_json()
        parsed = json.loads(raw)
        assert parsed["dst_port"] == 443

    def test_from_dict_roundtrip(self):
        evt = self._make_event()
        d = evt.to_dict()
        restored = ConnectionEvent.from_dict(d)
        assert restored.src_ip == evt.src_ip
        assert restored.dst_port == evt.dst_port
        assert restored.protocol == evt.protocol

    def test_timestamp_utc_fallback_when_none(self):
        """If timestamp_utc is omitted, __post_init__ sets it to a wall-clock value."""
        evt = ConnectionEvent(
            timestamp_ns=0,
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2,
            packet_size=64,
            protocol=6,
        )
        assert evt.timestamp_utc is not None
        assert "T" in evt.timestamp_utc  # ISO 8601 check

    def test_from_ctype_no_ktime(self):
        """from_ctype with no ktime offset preserves the raw timestamp_ns."""
        import ctypes
        ctype_evt = ConnectionEventCType()
        ctype_evt.timestamp_ns = 999_000_000_000
        # IPs in network byte order: 192.168.1.10 → pack as little-endian
        import socket
        ctype_evt.src_ip = struct.unpack("I", socket.inet_aton("192.168.1.10"))[0]
        ctype_evt.dst_ip = struct.unpack("I", socket.inet_aton("10.0.0.1"))[0]
        ctype_evt.src_port = 1234
        ctype_evt.dst_port = 443
        ctype_evt.packet_size = 512
        ctype_evt.protocol = 6
        ctype_evt.tcp_flags = 0x10
        ctype_evt.direction = 1

        evt = ConnectionEvent.from_ctype(ctype_evt, node_id="n1")
        assert evt.timestamp_ns == 999_000_000_000
        assert evt.node_id == "n1"

    def test_from_ctype_with_ktime_offset(self):
        """from_ctype with ktime_offset_ns shifts the timestamp to wall time."""
        import ctypes
        import socket
        ctype_evt = ConnectionEventCType()
        ctype_evt.timestamp_ns = 1_000_000_000  # 1 second after boot
        ctype_evt.src_ip = struct.unpack("I", socket.inet_aton("1.2.3.4"))[0]
        ctype_evt.dst_ip = struct.unpack("I", socket.inet_aton("5.6.7.8"))[0]
        ctype_evt.src_port = 11111
        ctype_evt.dst_port = 80
        ctype_evt.packet_size = 100
        ctype_evt.protocol = 6

        offset = 1_000_000_000_000  # 1000 seconds in ns
        evt = ConnectionEvent.from_ctype(ctype_evt, ktime_offset_ns=offset)
        assert evt.timestamp_ns == 1_000_000_000 + offset
        assert "T" in evt.timestamp_utc  # Should have been converted to ISO string

    def test_repr_contains_connection_key(self):
        evt = self._make_event()
        r = repr(evt)
        assert "192.168.1.10" in r


# ---------------------------------------------------------------------------
# TelemetryBatch
# ---------------------------------------------------------------------------

class TestTelemetryBatch:

    def _make_events(self, n, protocol=6):
        return [
            ConnectionEvent(
                timestamp_ns=i * 1_000_000_000,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=1000 + i,
                dst_port=443,
                packet_size=512,
                protocol=protocol,
                timestamp_utc="2024-01-01T00:00:00Z",
                node_id="node1",
            )
            for i in range(n)
        ]

    def test_event_count(self):
        events = self._make_events(5)
        batch = TelemetryBatch(batch_id="b1", node_id="n1", events=events)
        assert batch.event_count == 5

    def test_tcp_count(self):
        tcp = self._make_events(3, protocol=6)
        udp = self._make_events(2, protocol=17)
        batch = TelemetryBatch(batch_id="b2", node_id="n1", events=tcp + udp)
        assert batch.tcp_count == 3
        assert batch.udp_count == 2

    def test_unique_connections(self):
        """Each event has a unique src_port → unique connection keys."""
        events = self._make_events(4)
        batch = TelemetryBatch(batch_id="b3", node_id="n1", events=events)
        assert batch.unique_connections == 4

    def test_to_json_from_json_roundtrip(self):
        events = self._make_events(3)
        batch = TelemetryBatch(batch_id="round-1", node_id="n1", events=events)
        raw = batch.to_json()
        restored = TelemetryBatch.from_json(raw)
        assert restored.batch_id == "round-1"
        assert restored.event_count == 3
        assert restored.events[0].dst_port == 443

    def test_to_dict_structure(self):
        batch = TelemetryBatch(
            batch_id="d1", node_id="node-x", events=self._make_events(2)
        )
        d = batch.to_dict()
        assert d["batch_id"] == "d1"
        assert d["node_id"] == "node-x"
        assert "events" in d
        assert len(d["events"]) == 2

    def test_from_dict(self):
        events = self._make_events(2)
        batch = TelemetryBatch(batch_id="fd1", node_id="n1", events=events)
        d = batch.to_dict()
        restored = TelemetryBatch.from_dict(d)
        assert restored.node_id == "n1"
        assert len(restored.events) == 2

    def test_repr_contains_ids(self):
        events = self._make_events(1)
        batch = TelemetryBatch(batch_id="repr-test", node_id="mynode", events=events)
        r = repr(batch)
        assert "repr-test" in r
        assert "mynode" in r


# ---------------------------------------------------------------------------
# TelemetryBuffer
# ---------------------------------------------------------------------------

class TestTelemetryBuffer:

    def _make_event(self, i=0):
        return ConnectionEvent(
            timestamp_ns=i * 1_000_000_000,
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1000, dst_port=443,
            packet_size=64, protocol=6,
            timestamp_utc="2024-01-01T00:00:00Z",
        )

    def test_add_and_drain(self):
        buf = TelemetryBuffer(max_size=100)
        for i in range(5):
            buf.add(self._make_event(i))
        assert buf.size == 5
        drained = buf.drain()
        assert len(drained) == 5
        assert buf.size == 0

    def test_overflow_rejected(self):
        buf = TelemetryBuffer(max_size=3)
        for i in range(3):
            result = buf.add(self._make_event(i))
            assert result is True
        result = buf.add(self._make_event(99))
        assert result is False
        assert buf.overflow_count == 1

    def test_add_batch_partial_overflow(self):
        buf = TelemetryBuffer(max_size=5)
        events = [self._make_event(i) for i in range(8)]
        added = buf.add_batch(events)
        assert added == 5
        assert buf.overflow_count == 3

    def test_drain_empties_buffer(self):
        buf = TelemetryBuffer(max_size=10)
        for i in range(4):
            buf.add(self._make_event(i))
        buf.drain()
        assert buf.size == 0

    def test_reset_overflow_count(self):
        buf = TelemetryBuffer(max_size=1)
        buf.add(self._make_event(0))
        buf.add(self._make_event(1))  # overflow
        assert buf.overflow_count == 1
        buf.reset_overflow_count()
        assert buf.overflow_count == 0


# ---------------------------------------------------------------------------
# DataPlaneStats
# ---------------------------------------------------------------------------

class TestDataPlaneStats:

    def test_to_dict_has_all_fields(self):
        stats = DataPlaneStats(
            packets_total=100,
            packets_tcp=70,
            packets_udp=30,
            events_submitted=90,
            events_dropped=10,
        )
        d = stats.to_dict()
        assert d["packets_total"] == 100
        assert d["events_dropped"] == 10

    def test_repr_contains_counts(self):
        stats = DataPlaneStats(packets_total=42, packets_tcp=20, packets_udp=22,
                               events_submitted=40, events_dropped=2)
        r = repr(stats)
        assert "42" in r


# ---------------------------------------------------------------------------
# Protocol / Direction / TCPFlags enums
# ---------------------------------------------------------------------------

class TestEnums:

    def test_protocol_values(self):
        assert Protocol.TCP == 6
        assert Protocol.UDP == 17

    def test_direction_values(self):
        assert Direction.INGRESS == 0
        assert Direction.EGRESS == 1

    def test_tcpflags_bit_positions(self):
        assert TCPFlags.SYN == 0x02
        assert TCPFlags.ACK == 0x10
        assert TCPFlags.FIN == 0x01


if __name__ == "__main__":
    import pytest as _pytest
    _pytest.main([__file__, "-v"])
