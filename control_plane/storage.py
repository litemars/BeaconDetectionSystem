import bisect
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Set

logger = logging.getLogger("beacon_detect.control_plane.storage")


@dataclass
class ConnectionRecord:

    timestamp_ns: int
    timestamp_utc: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packet_size: int
    protocol: int
    protocol_name: str
    tcp_flags: int
    direction: int
    node_id: str
    connection_key: str

    # Computed fields
    timestamp_epoch: float = field(init=False)

    def __post_init__(self):

        try:
            dt = datetime.fromisoformat(self.timestamp_utc.replace("Z", "+00:00"))
            self.timestamp_epoch = dt.timestamp()
        except (ValueError, AttributeError):
            self.timestamp_epoch = time.time()

    @classmethod
    def from_dict(cls, data):

        return cls(
            timestamp_ns=data["timestamp_ns"],
            timestamp_utc=data["timestamp_utc"],
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            src_port=data["src_port"],
            dst_port=data["dst_port"],
            packet_size=data["packet_size"],
            protocol=data["protocol"],
            protocol_name=data["protocol_name"],
            tcp_flags=data.get("tcp_flags", 0),
            direction=data.get("direction", 0),
            node_id=data.get("node_id", "unknown"),
            connection_key=data["connection_key"],
        )


@dataclass
class ConnectionPair:

    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str

    # Timestamps of all observed connections (epoch seconds)
    timestamps: List[float] = field(default_factory=list)

    # Packet sizes
    packet_sizes: List[int] = field(default_factory=list)

    # Source ports (may vary for same destination)
    src_ports: Set[int] = field(default_factory=set)

    # Nodes that reported this connection
    nodes: Set[str] = field(default_factory=set)

    # First and last seen
    first_seen = None
    last_seen = None

    @property
    def pair_key(self):

        return f"{self.src_ip}->{self.dst_ip}:{self.dst_port}/{self.protocol}"

    @property
    def connection_count(self):

        return len(self.timestamps)

    @property
    def duration_seconds(self):

        if self.first_seen and self.last_seen:
            return self.last_seen - self.first_seen
        return 0.0

    def add_connection(self, record):

        ts = record.timestamp_epoch

        # Find insertion index to maintain sorted order
        idx = bisect.bisect_right(self.timestamps, ts)
        self.timestamps.insert(idx, ts)
        self.packet_sizes.insert(idx, record.packet_size)

        self.src_ports.add(record.src_port)
        self.nodes.add(record.node_id)

        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

    def get_intervals(self):

        if len(self.timestamps) < 2:
            return []

        intervals = []
        for i in range(1, len(self.timestamps)):
            interval = self.timestamps[i] - self.timestamps[i - 1]
            intervals.append(interval)

        return intervals

    def prune_old(self, cutoff_time):

        # Find index of first timestamp >= cutoff_time
        idx = bisect.bisect_left(self.timestamps, cutoff_time)

        if idx > 0:
            self.timestamps = self.timestamps[idx:]
            # Can't easily prune packet_sizes without matching indices
            # Keep recent ones proportionally
            if self.packet_sizes:
                keep_ratio = len(self.timestamps) / (len(self.timestamps) + idx)
                keep_count = max(1, int(len(self.packet_sizes) * keep_ratio))
                self.packet_sizes = self.packet_sizes[-keep_count:]

            # Update first_seen
            if self.timestamps:
                self.first_seen = self.timestamps[0]
            else:
                self.first_seen = None
                self.last_seen = None


class ConnectionStorage:

    def __init__(self, retention_seconds: int = 7200, cleanup_interval: int = 300):
        self.retention_seconds = retention_seconds
        self.cleanup_interval = cleanup_interval

        # Primary storage: connection pairs indexed by pair key
        self._pairs: Dict[str, ConnectionPair] = {}

        # Index by source IP for efficient lookup
        self._by_src_ip: Dict[str, Set[str]] = defaultdict(set)

        # Index by destination IP
        self._by_dst_ip: Dict[str, Set[str]] = defaultdict(set)

        # Index by destination port
        self._by_dst_port: Dict[int, Set[str]] = defaultdict(set)

        # Thread safety
        self._lock = threading.RLock()

        # Statistics
        self._records_added = 0
        self._records_expired = 0
        self._batches_received = 0

        # Cleanup thread
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()

        logger.info(
            f"ConnectionStorage initialized: retention={retention_seconds}s, "
            f"cleanup_interval={cleanup_interval}s"
        )

    def start_cleanup(self):

        self._stop_cleanup.clear()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        logger.info("Storage cleanup thread started")

    def stop_cleanup(self):

        self._stop_cleanup.set()
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
        logger.info("Storage cleanup thread stopped")

    def _cleanup_loop(self):

        while not self._stop_cleanup.wait(timeout=self.cleanup_interval):
            self.cleanup_expired()

    def add_record(self, record):

        with self._lock:
            # Create pair key (src -> dst:port/proto)
            pair_key = f"{record.src_ip}->{record.dst_ip}:{record.dst_port}/{record.protocol_name}"

            # Get or create connection pair
            if pair_key not in self._pairs:
                self._pairs[pair_key] = ConnectionPair(
                    src_ip=record.src_ip,
                    dst_ip=record.dst_ip,
                    dst_port=record.dst_port,
                    protocol=record.protocol_name,
                )

                # Update indices
                self._by_src_ip[record.src_ip].add(pair_key)
                self._by_dst_ip[record.dst_ip].add(pair_key)
                self._by_dst_port[record.dst_port].add(pair_key)

            # Add connection to pair
            self._pairs[pair_key].add_connection(record)
            self._records_added += 1

    def add_batch(self, records):

        with self._lock:
            self._batches_received += 1
            for record_data in records:
                try:
                    record = ConnectionRecord.from_dict(record_data)
                    self.add_record(record)
                except Exception as e:
                    logger.warning(f"Failed to add record: {e}")

    def get_pair(self, pair_key):
        with self._lock:
            return self._pairs.get(pair_key)

    def get_pairs_by_src(self, src_ip):

        with self._lock:
            pair_keys = self._by_src_ip.get(src_ip, set())
            return [self._pairs[k] for k in pair_keys if k in self._pairs]

    def get_pairs_by_dst(self, dst_ip):

        with self._lock:
            pair_keys = self._by_dst_ip.get(dst_ip, set())
            return [self._pairs[k] for k in pair_keys if k in self._pairs]

    def get_pairs_by_port(self, dst_port):

        with self._lock:
            pair_keys = self._by_dst_port.get(dst_port, set())
            return [self._pairs[k] for k in pair_keys if k in self._pairs]

    def get_all_pairs(self):

        with self._lock:
            return list(self._pairs.values())

    def get_analyzable_pairs(self, min_connections=10, min_duration=300):
        with self._lock:
            result = []
            for pair in self._pairs.values():
                if (
                    pair.connection_count >= min_connections
                    and pair.duration_seconds >= min_duration
                ):
                    result.append(pair)
            return result

    def cleanup_expired(self):
        cutoff_time = time.time() - self.retention_seconds
        removed_count = 0

        with self._lock:
            # Prune old timestamps from pairs
            pairs_to_remove = []

            for pair_key, pair in self._pairs.items():
                original_count = pair.connection_count
                pair.prune_old(cutoff_time)
                removed_count += original_count - pair.connection_count

                # Mark empty pairs for removal
                if pair.connection_count == 0:
                    pairs_to_remove.append(pair_key)

            # Remove empty pairs
            for pair_key in pairs_to_remove:
                pair = self._pairs.pop(pair_key)

                # Update indices
                self._by_src_ip[pair.src_ip].discard(pair_key)
                self._by_dst_ip[pair.dst_ip].discard(pair_key)
                self._by_dst_port[pair.dst_port].discard(pair_key)

                # Clean up empty index entries
                if not self._by_src_ip[pair.src_ip]:
                    del self._by_src_ip[pair.src_ip]
                if not self._by_dst_ip[pair.dst_ip]:
                    del self._by_dst_ip[pair.dst_ip]
                if not self._by_dst_port[pair.dst_port]:
                    del self._by_dst_port[pair.dst_port]

        if removed_count > 0 or pairs_to_remove:
            self._records_expired += removed_count
            logger.info(
                f"Cleanup complete: removed {removed_count} records, "
                f"{len(pairs_to_remove)} empty pairs"
            )

    @property
    def statistics(self):
        with self._lock:
            total_connections = sum(p.connection_count for p in self._pairs.values())
            return {
                "pair_count": len(self._pairs),
                "total_connections": total_connections,
                "unique_src_ips": len(self._by_src_ip),
                "unique_dst_ips": len(self._by_dst_ip),
                "unique_dst_ports": len(self._by_dst_port),
                "records_added": self._records_added,
                "records_expired": self._records_expired,
                "batches_received": self._batches_received,
                "retention_seconds": self.retention_seconds,
            }

    def __len__(self):

        with self._lock:
            return len(self._pairs)

    def __repr__(self):
        stats = self.statistics
        return (
            f"ConnectionStorage(pairs={stats['pair_count']}, "
            f"connections={stats['total_connections']})"
        )
