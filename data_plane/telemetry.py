import ctypes
import json
import socket
import struct
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import List


class Protocol(IntEnum):

    TCP = 6
    UDP = 17


class Direction(IntEnum):

    INGRESS = 0
    EGRESS = 1


class TCPFlags(IntEnum):

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


class ConnectionEventCType(ctypes.Structure):

    # C-compatible structure matching the eBPF connection_event struct.
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("packet_size", ctypes.c_uint32),
        ("protocol", ctypes.c_uint8),
        ("tcp_flags", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("padding", ctypes.c_uint8),
    ]


@dataclass
class ConnectionEvent:

    timestamp_ns: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packet_size: int
    protocol: int
    tcp_flags: int = 0
    direction: int = 0

    # Derived fields (computed, not transmitted from kernel)
    timestamp_utc: str = None
    node_id: str = None

    def __post_init__(self):

        if self.timestamp_utc is None:
            # Convert kernel timestamp to UTC datetime string
            # Note: bpf_ktime_get_ns() returns time since boot, not epoch
            # We'll use current time for UTC representation
            self.timestamp_utc = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )

    @classmethod
    def from_ctype(cls, event: ConnectionEventCType, node_id: str = None):
        """
        Create a ConnectionEvent from the C-type structure.
        """
        return cls(
            timestamp_ns=event.timestamp_ns,
            src_ip=cls._int_to_ip(event.src_ip),
            dst_ip=cls._int_to_ip(event.dst_ip),
            src_port=event.src_port,
            dst_port=event.dst_port,
            packet_size=event.packet_size,
            protocol=event.protocol,
            tcp_flags=event.tcp_flags,
            direction=event.direction,
            node_id=node_id,
        )

    @staticmethod
    def _int_to_ip(ip_int: int):

        # The IP is in network byte order from the kernel
        # struct.pack('!I', ...) expects host order, so we use ntohl to convert
        return socket.inet_ntoa(struct.pack("I", socket.ntohl(ip_int)))

    @property
    def protocol_name(self):

        return (
            Protocol(self.protocol).name
            if self.protocol in [6, 17]
            else f"UNKNOWN({self.protocol})"
        )

    @property
    def direction_name(self):

        return Direction(self.direction).name

    @property
    def tcp_flags_list(self):

        if self.protocol != Protocol.TCP:
            return []
        flags = []
        if self.tcp_flags & TCPFlags.FIN:
            flags.append("FIN")
        if self.tcp_flags & TCPFlags.SYN:
            flags.append("SYN")
        if self.tcp_flags & TCPFlags.RST:
            flags.append("RST")
        if self.tcp_flags & TCPFlags.PSH:
            flags.append("PSH")
        if self.tcp_flags & TCPFlags.ACK:
            flags.append("ACK")
        if self.tcp_flags & TCPFlags.URG:
            flags.append("URG")
        return flags

    @property
    def connection_key(self):

        # Generate a unique key for this connection pair.
        # Used for grouping events by connection.

        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol_name}"

    @property
    def bidirectional_key(self):

        # Generate a key that is the same regardless of direction.
        # Used for matching request/response pairs.

        # Sort the endpoints to get consistent key
        ep1 = (self.src_ip, self.src_port)
        ep2 = (self.dst_ip, self.dst_port)

        if ep1 < ep2:
            return f"{self.src_ip}:{self.src_port}<->{self.dst_ip}:{self.dst_port}/{self.protocol_name}"
        else:
            return f"{self.dst_ip}:{self.dst_port}<->{self.src_ip}:{self.src_port}/{self.protocol_name}"

    def to_dict(self):

        return {
            "timestamp_ns": self.timestamp_ns,
            "timestamp_utc": self.timestamp_utc,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_size": self.packet_size,
            "protocol": self.protocol,
            "protocol_name": self.protocol_name,
            "tcp_flags": self.tcp_flags,
            "tcp_flags_list": self.tcp_flags_list,
            "direction": self.direction,
            "direction_name": self.direction_name,
            "node_id": self.node_id,
            "connection_key": self.connection_key,
        }

    def to_json(self):

        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data):

        return cls(
            timestamp_ns=data["timestamp_ns"],
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            src_port=data["src_port"],
            dst_port=data["dst_port"],
            packet_size=data["packet_size"],
            protocol=data["protocol"],
            tcp_flags=data.get("tcp_flags", 0),
            direction=data.get("direction", 0),
            timestamp_utc=data.get("timestamp_utc"),
            node_id=data.get("node_id"),
        )

    def __repr__(self):
        flags_str = f" [{','.join(self.tcp_flags_list)}]" if self.tcp_flags_list else ""
        return (
            f"ConnectionEvent({self.connection_key}{flags_str} "
            f"size={self.packet_size} dir={self.direction_name})"
        )


@dataclass
class TelemetryBatch:

    batch_id: str
    node_id: str
    events: List[ConnectionEvent]
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    # Statistics
    event_count: int = field(init=False)
    tcp_count: int = field(init=False)
    udp_count: int = field(init=False)
    unique_connections: int = field(init=False)

    def __post_init__(self):

        self.event_count = len(self.events)
        self.tcp_count = sum(1 for e in self.events if e.protocol == Protocol.TCP)
        self.udp_count = sum(1 for e in self.events if e.protocol == Protocol.UDP)
        self.unique_connections = len(set(e.connection_key for e in self.events))

    def to_dict(self):

        return {
            "batch_id": self.batch_id,
            "node_id": self.node_id,
            "created_at": self.created_at,
            "event_count": self.event_count,
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
            "unique_connections": self.unique_connections,
            "events": [e.to_dict() for e in self.events],
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data):

        events = [ConnectionEvent.from_dict(e) for e in data["events"]]
        batch = cls(
            batch_id=data["batch_id"],
            node_id=data["node_id"],
            events=events,
            created_at=data.get(
                "created_at",
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            ),
        )
        return batch

    @classmethod
    def from_json(cls, json_str: str):
        return cls.from_dict(json.loads(json_str))

    def __repr__(self):
        return (
            f"TelemetryBatch(id={self.batch_id}, node={self.node_id}, "
            f"events={self.event_count}, unique_conns={self.unique_connections})"
        )


@dataclass
class DataPlaneStats:

    packets_total: int = 0
    packets_ipv4: int = 0
    packets_tcp: int = 0
    packets_udp: int = 0
    events_submitted: int = 0
    events_dropped: int = 0
    dedup_hits: int = 0
    parse_errors: int = 0

    # User-space statistics
    batches_sent: int = 0
    batches_failed: int = 0
    events_buffered: int = 0

    def to_dict(self):

        return asdict(self)

    def __repr__(self):
        return (
            f"DataPlaneStats(total={self.packets_total}, tcp={self.packets_tcp}, "
            f"udp={self.packets_udp}, submitted={self.events_submitted}, "
            f"dropped={self.events_dropped})"
        )


class TelemetryBuffer:

    def __init__(self, max_size: int = 100000):

        import threading

        self.max_size = max_size
        self._buffer: List[ConnectionEvent] = []
        self._lock = threading.Lock()
        self._overflow_count = 0

    def add(self, event):

        with self._lock:
            if len(self._buffer) >= self.max_size:
                self._overflow_count += 1
                return False
            self._buffer.append(event)
            return True

    def add_batch(self, events):

        with self._lock:
            available = self.max_size - len(self._buffer)
            to_add = events[:available]
            self._buffer.extend(to_add)
            overflow = len(events) - len(to_add)
            self._overflow_count += overflow
            return len(to_add)

    def drain(self):

        # Remove and return all events from the buffer.

        with self._lock:
            events = self._buffer
            self._buffer = []
            return events

    @property
    def size(self):

        with self._lock:
            return len(self._buffer)

    @property
    def overflow_count(self):

        with self._lock:
            return self._overflow_count

    def reset_overflow_count(self):

        with self._lock:
            self._overflow_count = 0
