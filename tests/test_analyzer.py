import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.alerter import Alert, AlertManager, AlertSeverity
from control_plane.analyzer import (
    AnalysisRun,
    AnalyzerConfig,
    BenignPattern,
    ConnectionAnalyzer,
)
from control_plane.detector import (
    BeaconConfidence,
    BeaconDetector,
    DetectionResult,
    DetectorConfig,
)
from control_plane.storage import ConnectionPair, ConnectionRecord, ConnectionStorage


# ---------------------------------------------------------------------------
# ConnectionStorage
# ---------------------------------------------------------------------------


class TestConnectionStorage:

    def test_add_record(self):
        storage = ConnectionStorage(retention_seconds=3600)
        record = ConnectionRecord(
            timestamp_ns=1000000000,
            timestamp_utc="2024-01-01T00:00:00Z",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            packet_size=1500,
            protocol=6,
            protocol_name="TCP",
            tcp_flags=0x10,
            direction=1,
            node_id="test-node",
            connection_key="192.168.1.100:54321->10.0.0.1:443/TCP",
        )
        storage.add_record(record)
        stats = storage.statistics
        assert stats["records_added"] == 1
        assert stats["pair_count"] == 1

    def test_add_batch(self):
        storage = ConnectionStorage(retention_seconds=3600)
        records = [
            {
                "timestamp_ns": 1000000000 + i * 1000000,
                "timestamp_utc": f"2024-01-01T00:00:0{i}Z",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "src_port": 54321 + i,
                "dst_port": 443,
                "packet_size": 1500,
                "protocol": 6,
                "protocol_name": "TCP",
                "tcp_flags": 0x10,
                "direction": 1,
                "node_id": "test-node",
                "connection_key": f"192.168.1.100:{54321+i}->10.0.0.1:443/TCP",
            }
            for i in range(10)
        ]
        storage.add_batch(records)
        assert storage.statistics["records_added"] == 10

    def test_get_pairs_by_src(self):
        storage = ConnectionStorage()
        for i in range(5):
            record = ConnectionRecord(
                timestamp_ns=1000000000 + i,
                timestamp_utc="2024-01-01T00:00:00Z",
                src_ip="192.168.1.100",
                dst_ip=f"10.0.0.{i}",
                src_port=54321,
                dst_port=443,
                packet_size=1500,
                protocol=6,
                protocol_name="TCP",
                tcp_flags=0x10,
                direction=1,
                node_id="test-node",
                connection_key=f"192.168.1.100:54321->10.0.0.{i}:443/TCP",
            )
            storage.add_record(record)
        assert len(storage.get_pairs_by_src("192.168.1.100")) == 5
        assert len(storage.get_pairs_by_src("192.168.1.200")) == 0

    def test_get_analyzable_pairs(self):
        storage = ConnectionStorage()
        for i in range(15):
            record = ConnectionRecord(
                timestamp_ns=1000000000 + i * 60000000000,
                timestamp_utc=f"2024-01-01T00:{i:02d}:00Z",
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=443,
                packet_size=1500,
                protocol=6,
                protocol_name="TCP",
                tcp_flags=0x10,
                direction=1,
                node_id="test-node",
                connection_key="192.168.1.100:54321->10.0.0.1:443/TCP",
            )
            storage.add_record(record)
        for i in range(3):
            record = ConnectionRecord(
                timestamp_ns=1000000000 + i,
                timestamp_utc=f"2024-01-01T00:{i:02d}:00Z",
                src_ip="192.168.1.101",
                dst_ip="10.0.0.2",
                src_port=54322,
                dst_port=80,
                packet_size=1500,
                protocol=6,
                protocol_name="TCP",
                tcp_flags=0x10,
                direction=1,
                node_id="test-node",
                connection_key="192.168.1.101:54322->10.0.0.2:80/TCP",
            )
            storage.add_record(record)
        pairs = storage.get_analyzable_pairs(min_connections=10, min_duration=60)
        assert len(pairs) == 1
        assert pairs[0].src_ip == "192.168.1.100"


# ---------------------------------------------------------------------------
# ConnectionPair
# ---------------------------------------------------------------------------


class TestConnectionPair:

    def test_get_intervals(self):
        pair = ConnectionPair(
            src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=443, protocol="TCP"
        )
        for i in range(5):
            pair.timestamps.append(1000.0 + i * 60.0)
            pair.packet_sizes.append(128)
        intervals = pair.get_intervals()
        assert len(intervals) == 4
        assert all(i == 60.0 for i in intervals)

    def test_duration(self):
        pair = ConnectionPair(
            src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=443, protocol="TCP"
        )
        pair.first_seen = 1000.0
        pair.last_seen = 2000.0
        assert pair.duration_seconds == 1000.0

    def test_prune_old_index_aligned(self):
        """After pruning, timestamps and packet_sizes must have the same length."""
        pair = ConnectionPair(
            src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=443, protocol="TCP"
        )
        base = time.time() - 7200
        for i in range(10):
            pair.timestamps.append(base + i * 600)
            pair.packet_sizes.append(100 + i)
        pair.first_seen = pair.timestamps[0]
        pair.last_seen = pair.timestamps[-1]

        cutoff = time.time() - 3600
        pair.prune_old(cutoff)

        assert len(pair.timestamps) == len(pair.packet_sizes)
        assert pair.connection_count < 10


# ---------------------------------------------------------------------------
# BenignPattern
# ---------------------------------------------------------------------------


class TestBenignPattern:

    def test_matches_by_port_and_protocol(self):
        pattern = BenignPattern(dst_port=123, protocol="UDP", label="NTP")
        ntp_pair = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="1.2.3.4", dst_port=123, protocol="UDP"
        )
        tcp_pair = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="1.2.3.4", dst_port=123, protocol="TCP"
        )
        other_pair = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="1.2.3.4", dst_port=443, protocol="UDP"
        )
        assert pattern.matches(ntp_pair) is True
        assert pattern.matches(tcp_pair) is False
        assert pattern.matches(other_pair) is False

    def test_matches_any_protocol_when_unset(self):
        pattern = BenignPattern(dst_port=53, label="DNS")
        tcp_dns = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=53, protocol="TCP"
        )
        udp_dns = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=53, protocol="UDP"
        )
        assert pattern.matches(tcp_dns) is True
        assert pattern.matches(udp_dns) is True


# ---------------------------------------------------------------------------
# AnalyzerConfig
# ---------------------------------------------------------------------------


class TestAnalyzerConfig:

    def test_default_config(self):
        config = AnalyzerConfig()
        assert config.analysis_interval == 60
        assert config.min_connections == 10
        assert config.min_duration == 300.0
        assert config.alert_cooldown == 300
        assert config.benign_baseline_enabled is True

    def test_effective_patterns_use_defaults_when_empty(self):
        config = AnalyzerConfig(benign_baseline_enabled=True, benign_patterns=[])
        patterns = config.get_effective_benign_patterns()
        assert len(patterns) > 0  # default NTP pattern

    def test_effective_patterns_empty_when_disabled(self):
        config = AnalyzerConfig(benign_baseline_enabled=False)
        assert config.get_effective_benign_patterns() == []

    def test_custom_patterns_override_defaults(self):
        custom = [BenignPattern(dst_port=8125, label="StatsD")]
        config = AnalyzerConfig(benign_baseline_enabled=True, benign_patterns=custom)
        patterns = config.get_effective_benign_patterns()
        assert len(patterns) == 1
        assert patterns[0].label == "StatsD"


# ---------------------------------------------------------------------------
# AnalysisRun
# ---------------------------------------------------------------------------


class TestAnalysisRun:

    def test_creation(self):
        run = AnalysisRun("test-run-1")
        assert run.run_id == "test-run-1"
        assert run.pairs_analyzed == 0
        assert run.pairs_suppressed == 0
        assert run.end_time is None

    def test_completion(self):
        run = AnalysisRun("test-run-1")
        run.pairs_analyzed = 100
        run.pairs_suppressed = 5
        run.beacons_detected = 2
        run.complete()
        assert run.end_time is not None
        assert run.duration_seconds >= 0

    def test_to_dict_includes_suppressed(self):
        run = AnalysisRun("test-run-1")
        run.pairs_suppressed = 3
        run.complete()
        d = run.to_dict()
        assert "pairs_suppressed" in d
        assert d["pairs_suppressed"] == 3


# ---------------------------------------------------------------------------
# ConnectionAnalyzer
# ---------------------------------------------------------------------------


class TestConnectionAnalyzer:

    def setup_method(self):
        self.storage = ConnectionStorage()
        self.detector = BeaconDetector(DetectorConfig(min_connections=5))
        self.alert_manager = Mock(spec=AlertManager)
        self.alert_manager.send_alert = Mock()
        self.alert_manager.config = Mock()
        self.alert_manager.config.enabled = False

        self.analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            config=AnalyzerConfig(
                analysis_interval=60,
                min_connections=5,
                min_duration=60,
                alert_cooldown=60,
                benign_baseline_enabled=False,  # disabled for unit tests
            ),
        )

    def test_run_analysis_empty_storage(self):
        run = self.analyzer.run_analysis()
        assert run.pairs_analyzed == 0
        assert run.beacons_detected == 0

    def test_run_analysis_with_data(self):
        base_time = time.time()
        for i in range(20):
            record = ConnectionRecord(
                timestamp_ns=int((base_time + i * 60) * 1e9),
                timestamp_utc=f"2024-01-01T00:{i:02d}:00Z",
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=443,
                packet_size=1500,
                protocol=6,
                protocol_name="TCP",
                tcp_flags=0x10,
                direction=1,
                node_id="test-node",
                connection_key="192.168.1.100:54321->10.0.0.1:443/TCP",
            )
            record.timestamp_epoch = base_time + i * 60
            self.storage.add_record(record)
        run = self.analyzer.run_analysis()
        assert run.pairs_analyzed >= 1

    def test_benign_suppression_skips_ntp(self):
        """NTP pairs (UDP/123) must be suppressed and not reach the detector."""
        storage = ConnectionStorage()
        analyzer = ConnectionAnalyzer(
            storage=storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            config=AnalyzerConfig(
                min_connections=5,
                min_duration=60,
                benign_baseline_enabled=True,
                benign_patterns=[
                    BenignPattern(dst_port=123, protocol="UDP", label="NTP")
                ],
            ),
        )
        base = time.time()
        for i in range(20):
            record = ConnectionRecord(
                timestamp_ns=int((base + i * 64) * 1e9),
                timestamp_utc=f"2024-01-01T00:{i:02d}:00Z",
                src_ip="10.0.0.5",
                dst_ip="192.0.2.1",
                src_port=12345,
                dst_port=123,
                packet_size=48,
                protocol=17,
                protocol_name="UDP",
                tcp_flags=0,
                direction=1,
                node_id="test-node",
                connection_key="10.0.0.5:12345->192.0.2.1:123/UDP",
            )
            record.timestamp_epoch = base + i * 64
            storage.add_record(record)
        run = analyzer.run_analysis()
        assert run.pairs_suppressed == 1
        assert run.pairs_analyzed == 0

    def test_alert_cooldown(self):
        pair_key = "192.168.1.100->10.0.0.1:443/TCP"
        self.analyzer._alert_cooldowns[pair_key] = time.time()
        mock_result = Mock(spec=DetectionResult)
        mock_result.pair_key = pair_key
        mock_result.combined_score = 0.9
        mock_result.confidence = BeaconConfidence.HIGH
        self.analyzer._known_beacons[pair_key] = mock_result
        assert not self.analyzer._should_alert(mock_result)

    def test_get_known_beacons(self):
        mock_result = Mock(spec=DetectionResult)
        mock_result.pair_key = "test-pair"
        self.analyzer._known_beacons["test-pair"] = mock_result
        assert len(self.analyzer.get_known_beacons()) == 1

    def test_statistics_includes_suppression_fields(self):
        stats = self.analyzer.statistics
        assert "total_suppressed" in stats
        assert "benign_baseline_enabled" in stats
        assert "benign_pattern_count" in stats


# ---------------------------------------------------------------------------
# Alert infrastructure
# ---------------------------------------------------------------------------


class TestAlertManager:

    def test_alert_creation(self):
        alert = Alert(
            alert_id="test-1",
            title="Test Alert",
            description="desc",
            severity=AlertSeverity.HIGH,
            source="test",
        )
        assert alert.alert_id == "test-1"
        assert alert.severity == AlertSeverity.HIGH

    def test_alert_to_dict(self):
        alert = Alert(
            alert_id="test-1",
            title="Test",
            description="desc",
            severity=AlertSeverity.CRITICAL,
            source="test",
            details={"key": "value"},
        )
        d = alert.to_dict()
        assert d["severity"] == "critical"
        assert d["details"] == {"key": "value"}

    def test_alert_to_syslog(self):
        alert = Alert(
            alert_id="test-1",
            title="Beacon Detected",
            description="Beaconing from 192.168.1.100",
            severity=AlertSeverity.HIGH,
            source="beacon_detector",
        )
        msg = alert.to_syslog_message()
        assert "[HIGH]" in msg
        assert "Beacon Detected" in msg


class TestAlertSeverity:

    def test_syslog_priority_mapping(self):
        import logging

        assert AlertSeverity.INFO.syslog_priority == logging.INFO
        assert AlertSeverity.LOW.syslog_priority == logging.WARNING
        assert AlertSeverity.HIGH.syslog_priority == logging.ERROR
        assert AlertSeverity.CRITICAL.syslog_priority == logging.CRITICAL


class TestWhitelist:

    def setup_method(self):

        self.storage = ConnectionStorage()
        self.detector = BeaconDetector(DetectorConfig(min_connections=5))
        self.alert_manager = Mock(spec=AlertManager)
        self.alert_manager.send_alert = Mock()

    def test_whitelist_source_ip(self):

        whitelist = {"source_ips": ["192.168.1.100"]}
        analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            whitelist=whitelist,
        )
        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=443, protocol="TCP"
        )
        assert analyzer._is_whitelisted(pair) is True

    def test_whitelist_destination_ip(self):

        whitelist = {"destination_ips": ["10.0.0.1"]}
        analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            whitelist=whitelist,
        )
        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=443, protocol="TCP"
        )
        assert analyzer._is_whitelisted(pair) is True

    def test_whitelist_port(self):

        whitelist = {"ports": [53, 123]}
        analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            whitelist=whitelist,
        )
        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=53, protocol="UDP"
        )
        assert analyzer._is_whitelisted(pair) is True

    def test_whitelist_pair(self):

        whitelist = {"pairs": ["192.168.1.100:10.0.0.1:443"]}
        analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            whitelist=whitelist,
        )
        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=443, protocol="TCP"
        )
        assert analyzer._is_whitelisted(pair) is True

    def test_no_whitelist_match(self):

        whitelist = {"source_ips": ["10.10.10.10"]}
        analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            whitelist=whitelist,
        )
        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=443, protocol="TCP"
        )
        assert analyzer._is_whitelisted(pair) is False

    def test_empty_whitelist(self):

        analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            whitelist={},
        )
        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=443, protocol="TCP"
        )
        assert analyzer._is_whitelisted(pair) is False

    def test_analysis_run_skips_whitelisted(self):

        whitelist = {"destination_ips": ["10.0.0.1"]}
        analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            config=AnalyzerConfig(min_connections=5, min_duration=60),
            whitelist=whitelist,
        )

        base_time = time.time()
        # Add whitelisted pair
        for i in range(20):
            record = ConnectionRecord(
                timestamp_ns=int((base_time + i * 60) * 1e9),
                timestamp_utc=f"2024-01-01T00:{i:02d}:00Z",
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=443,
                packet_size=1500,
                protocol=6,
                protocol_name="TCP",
                tcp_flags=0x10,
                direction=1,
                node_id="test-node",
                connection_key="192.168.1.100:54321->10.0.0.1:443/TCP",
            )
            record.timestamp_epoch = base_time + i * 60
            self.storage.add_record(record)

        # Add non-whitelisted pair
        for i in range(20):
            record = ConnectionRecord(
                timestamp_ns=int((base_time + i * 60) * 1e9),
                timestamp_utc=f"2024-01-01T00:{i:02d}:00Z",
                src_ip="192.168.1.200",
                dst_ip="10.0.0.2",
                src_port=54322,
                dst_port=80,
                packet_size=1500,
                protocol=6,
                protocol_name="TCP",
                tcp_flags=0x10,
                direction=1,
                node_id="test-node",
                connection_key="192.168.1.200:54322->10.0.0.2:80/TCP",
            )
            record.timestamp_epoch = base_time + i * 60
            self.storage.add_record(record)

        run = analyzer.run_analysis()

        assert run.pairs_skipped == 1
        assert run.pairs_analyzed == 1

    def test_update_whitelist(self):

        analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            whitelist={},
        )

        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=443, protocol="TCP"
        )
        assert analyzer._is_whitelisted(pair) is False

        analyzer.update_whitelist({"source_ips": ["192.168.1.100"]})
        assert analyzer._is_whitelisted(pair) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
