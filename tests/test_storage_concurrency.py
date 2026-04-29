"""Tests for ConnectionStorage thread-safety and cleanup logic.

Covers:
- cleanup_expired(): removes stale timestamps, deletes empty pairs,
  updates all three indices
- Concurrent add_record() + cleanup_expired() under many threads
- start_cleanup() / stop_cleanup() lifecycle
- prune_old() on ConnectionPair

Run with: pytest tests/test_storage_concurrency.py -v
"""

import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.storage import ConnectionPair, ConnectionRecord, ConnectionStorage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(src_ip, dst_ip, dst_port, protocol_name, epoch_s, packet_size=128):
    """Return a ConnectionRecord whose timestamp_epoch is set to *epoch_s*."""
    rec = ConnectionRecord(
        timestamp_ns=int(epoch_s * 1e9),
        timestamp_utc="2024-01-01T00:00:00Z",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=dst_port,
        packet_size=packet_size,
        protocol=6 if protocol_name == "TCP" else 17,
        protocol_name=protocol_name,
        tcp_flags=0,
        direction=1,
        node_id="test",
        connection_key=f"{src_ip}:12345->{dst_ip}:{dst_port}/{protocol_name}",
    )
    # Override the UTC-parsed value with a precise wall-clock epoch.
    rec.timestamp_epoch = epoch_s
    return rec


def _fill_storage(storage, src_ip, dst_ip, dst_port, n, base_epoch, interval=60.0):
    """Add *n* records spaced *interval* seconds apart starting at *base_epoch*."""
    for i in range(n):
        rec = _make_record(src_ip, dst_ip, dst_port, "TCP", base_epoch + i * interval)
        storage.add_record(rec)


# ---------------------------------------------------------------------------
# cleanup_expired
# ---------------------------------------------------------------------------

class TestCleanupExpired:

    def test_old_records_removed(self):
        """Records older than retention_seconds are pruned from the pair."""
        storage = ConnectionStorage(retention_seconds=100)
        now = time.time()

        # Two old records (200 s ago) and two fresh records (10 s ago)
        for delta in [200, 190, 10, 5]:
            storage.add_record(_make_record("1.1.1.1", "2.2.2.2", 443, "TCP", now - delta))

        assert storage.get_pair("1.1.1.1->2.2.2.2:443/TCP").connection_count == 4
        storage.cleanup_expired()

        pair = storage.get_pair("1.1.1.1->2.2.2.2:443/TCP")
        assert pair is not None, "Pair with fresh records must not be removed"
        assert pair.connection_count == 2

    def test_fully_expired_pair_removed(self):
        """A pair whose every record is expired is deleted and absent from indices."""
        storage = ConnectionStorage(retention_seconds=60)
        now = time.time()

        _fill_storage(storage, "10.0.0.1", "10.0.0.2", 80, n=5,
                      base_epoch=now - 3600, interval=60.0)

        assert len(storage) == 1
        storage.cleanup_expired()

        assert len(storage) == 0
        assert storage.get_pair("10.0.0.1->10.0.0.2:80/TCP") is None

    def test_indices_cleared_after_pair_removal(self):
        """src/dst/port indices must not reference the removed pair key."""
        storage = ConnectionStorage(retention_seconds=60)
        now = time.time()

        _fill_storage(storage, "10.1.0.1", "10.1.0.2", 9090, n=5,
                      base_epoch=now - 3600, interval=60.0)
        storage.cleanup_expired()

        assert storage.get_pairs_by_src("10.1.0.1") == []
        assert storage.get_pairs_by_dst("10.1.0.2") == []
        assert storage.get_pairs_by_port(9090) == []

    def test_fresh_pair_survives_cleanup(self):
        """A pair with all fresh records is untouched by cleanup."""
        storage = ConnectionStorage(retention_seconds=3600)
        now = time.time()

        _fill_storage(storage, "10.2.0.1", "10.2.0.2", 443, n=20,
                      base_epoch=now - 60, interval=5.0)

        storage.cleanup_expired()

        pair = storage.get_pair("10.2.0.1->10.2.0.2:443/TCP")
        assert pair is not None
        assert pair.connection_count == 20

    def test_mixed_pairs_cleanup_removes_only_stale(self):
        """Only the expired pair is deleted; the fresh pair remains."""
        storage = ConnectionStorage(retention_seconds=120)
        now = time.time()

        # Stale pair: all records from 1 hour ago
        _fill_storage(storage, "5.5.5.5", "6.6.6.6", 80, n=10,
                      base_epoch=now - 3600, interval=60.0)
        # Fresh pair: records from the last 60 seconds
        _fill_storage(storage, "7.7.7.7", "8.8.8.8", 443, n=10,
                      base_epoch=now - 60, interval=5.0)

        assert len(storage) == 2
        storage.cleanup_expired()
        assert len(storage) == 1
        assert storage.get_pair("7.7.7.7->8.8.8.8:443/TCP") is not None

    def test_statistics_updated_after_cleanup(self):
        """records_expired stat increases after old records are pruned."""
        storage = ConnectionStorage(retention_seconds=60)
        now = time.time()

        _fill_storage(storage, "9.9.9.9", "1.2.3.4", 8080, n=10,
                      base_epoch=now - 3600, interval=60.0)

        before = storage.statistics["records_expired"]
        storage.cleanup_expired()
        after = storage.statistics["records_expired"]
        assert after > before


# ---------------------------------------------------------------------------
# ConnectionPair.prune_old
# ---------------------------------------------------------------------------

class TestPruneOld:

    def test_prune_old_removes_early_timestamps(self):
        pair = ConnectionPair(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                              dst_port=443, protocol="TCP")
        for t in [100.0, 200.0, 300.0, 400.0, 500.0]:
            pair.timestamps.append(t)
            pair.packet_sizes.append(128)
        pair.first_seen = 100.0
        pair.last_seen = 500.0

        pair.prune_old(350.0)  # remove t=100, 200, 300
        assert pair.timestamps == [400.0, 500.0]
        assert pair.first_seen == 400.0

    def test_prune_all_clears_pair(self):
        pair = ConnectionPair(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                              dst_port=443, protocol="TCP")
        for t in [100.0, 200.0]:
            pair.timestamps.append(t)
            pair.packet_sizes.append(64)
        pair.first_seen = 100.0
        pair.last_seen = 200.0

        pair.prune_old(9999.0)
        assert pair.timestamps == []
        assert pair.first_seen is None

    def test_prune_none_when_all_fresh(self):
        pair = ConnectionPair(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                              dst_port=443, protocol="TCP")
        for t in [900.0, 950.0, 1000.0]:
            pair.timestamps.append(t)
            pair.packet_sizes.append(64)
        pair.first_seen = 900.0
        pair.last_seen = 1000.0

        pair.prune_old(500.0)  # cutoff before all records
        assert len(pair.timestamps) == 3


# ---------------------------------------------------------------------------
# Concurrent add_record + cleanup_expired
# ---------------------------------------------------------------------------

class TestConcurrentAccess:

    def test_concurrent_add_record_count(self):
        """100 threads each adding 10 records to the same pair → 1000 total."""
        storage = ConnectionStorage(retention_seconds=86400)
        now = time.time()

        def add_records(thread_idx):
            for j in range(10):
                rec = _make_record(
                    "192.168.0.1", "10.0.0.1", 443, "TCP",
                    now + thread_idx * 0.1 + j * 0.01
                )
                storage.add_record(rec)

        threads = [threading.Thread(target=add_records, args=(i,))
                   for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        pair = storage.get_pair("192.168.0.1->10.0.0.1:443/TCP")
        assert pair is not None
        assert pair.connection_count == 1000

    def test_concurrent_add_and_cleanup_no_exception(self):
        """Interleaved add_record and cleanup_expired must not raise."""
        storage = ConnectionStorage(retention_seconds=5)
        now = time.time()
        errors = []

        def add_worker():
            try:
                for i in range(200):
                    rec = _make_record("172.16.0.1", "172.16.0.2", 8080, "TCP",
                                       now + i * 0.01)
                    storage.add_record(rec)
            except Exception as exc:
                errors.append(exc)

        def cleanup_worker():
            try:
                for _ in range(50):
                    storage.cleanup_expired()
                    time.sleep(0.001)
            except Exception as exc:
                errors.append(exc)

        threads = (
            [threading.Thread(target=add_worker) for _ in range(5)]
            + [threading.Thread(target=cleanup_worker) for _ in range(3)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Exceptions during concurrent access: {errors}"

    def test_concurrent_distinct_pairs(self):
        """50 threads writing to 50 different pairs → 50 pairs in storage."""
        storage = ConnectionStorage(retention_seconds=86400)
        now = time.time()

        def add_pair(port):
            for i in range(20):
                rec = _make_record("10.0.0.1", "10.0.0.2", port, "TCP",
                                   now + i * 1.0)
                storage.add_record(rec)

        threads = [threading.Thread(target=add_pair, args=(5000 + p,))
                   for p in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(storage) == 50


# ---------------------------------------------------------------------------
# Cleanup thread lifecycle
# ---------------------------------------------------------------------------

class TestCleanupThreadLifecycle:

    def test_start_stop_cleanup_thread(self):
        """start_cleanup() and stop_cleanup() complete without error."""
        storage = ConnectionStorage(retention_seconds=3600, cleanup_interval=60)
        storage.start_cleanup()
        assert storage._cleanup_thread is not None
        assert storage._cleanup_thread.is_alive()
        storage.stop_cleanup()
        # Thread should have exited within the join timeout
        assert not storage._cleanup_thread.is_alive()

    def test_cleanup_thread_actually_runs(self):
        """Cleanup thread prunes expired records within a short interval."""
        storage = ConnectionStorage(retention_seconds=1, cleanup_interval=1)
        now = time.time()

        # Add records that will expire within 1 second
        _fill_storage(storage, "1.2.3.4", "5.6.7.8", 9999, n=10,
                      base_epoch=now - 3, interval=0.1)
        assert len(storage) == 1

        storage.start_cleanup()
        # Wait for at least one cleanup cycle (interval=1s + a small buffer)
        time.sleep(2.5)
        storage.stop_cleanup()

        assert len(storage) == 0, "Cleanup thread should have removed the expired pair"
