import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.alerter import Alert, AlertManager, AlertSeverity
from control_plane.analyzer import (AnalysisRun, AnalyzerConfig,
                                    ConnectionAnalyzer)
from control_plane.detector import (BeaconConfidence, BeaconDetector,
                                    DetectionResult, DetectorConfig)
from control_plane.storage import (ConnectionPair, ConnectionRecord,
                                   ConnectionStorage)


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

        stats = storage.statistics
        assert stats["records_added"] == 10

    def test_get_pairs_by_src(self):

        storage = ConnectionStorage()

        for i in range(5):
            record = ConnectionRecord(
                timestamp_ns=1000000000 + i * 1000000,
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

        pairs = storage.get_pairs_by_src("192.168.1.100")
        assert len(pairs) == 5

        pairs = storage.get_pairs_by_src("192.168.1.200")
        assert len(pairs) == 0

    def test_get_analyzable_pairs(self):

        storage = ConnectionStorage()

        for i in range(15):
            record = ConnectionRecord(
                timestamp_ns=1000000000 + i * 60000000000,  # 60s apart
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
                timestamp_ns=1000000000 + i * 60000000000,
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


class TestConnectionPair:

    def test_get_intervals(self):

        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=443, protocol="TCP"
        )

        for i in range(5):
            pair.timestamps.append(1000.0 + i * 60.0)

        intervals = pair.get_intervals()

        assert len(intervals) == 4
        assert all(i == 60.0 for i in intervals)

    def test_duration(self):

        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=443, protocol="TCP"
        )

        pair.first_seen = 1000.0
        pair.last_seen = 2000.0

        assert pair.duration_seconds == 1000.0

    def test_prune_old(self):

        pair = ConnectionPair(
            src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=443, protocol="TCP"
        )

        base_time = time.time() - 7200
        for i in range(10):
            pair.timestamps.append(base_time + i * 600)
        pair.first_seen = pair.timestamps[0]
        pair.last_seen = pair.timestamps[-1]

        cutoff = time.time() - 3600
        pair.prune_old(cutoff)

        assert pair.connection_count < 10


class TestAnalyzerConfig:

    def test_default_config(self):

        config = AnalyzerConfig()

        assert config.analysis_interval == 60
        assert config.min_connections == 10
        assert config.min_duration == 300.0
        assert config.alert_cooldown == 300

    def test_custom_config(self):

        config = AnalyzerConfig(
            analysis_interval=120, min_connections=20, alert_cooldown=600
        )

        assert config.analysis_interval == 120
        assert config.min_connections == 20
        assert config.alert_cooldown == 600


class TestAnalysisRun:

    def test_analysis_run_creation(self):

        run = AnalysisRun("test-run-1")

        assert run.run_id == "test-run-1"
        assert run.pairs_analyzed == 0
        assert run.beacons_detected == 0
        assert run.end_time is None

    def test_analysis_run_completion(self):

        run = AnalysisRun("test-run-1")
        run.pairs_analyzed = 100
        run.beacons_detected = 2
        run.alerts_generated = 2

        run.complete()

        assert run.end_time is not None
        assert run.duration_seconds >= 0

    def test_to_dict(self):

        run = AnalysisRun("test-run-1")
        run.pairs_analyzed = 50
        run.complete()

        d = run.to_dict()

        assert d["run_id"] == "test-run-1"
        assert d["pairs_analyzed"] == 50
        assert "start_time" in d
        assert "end_time" in d


class TestConnectionAnalyzer:

    def setup_method(self):

        self.storage = ConnectionStorage()
        self.detector = BeaconDetector(DetectorConfig(min_connections=5))
        self.alert_manager = Mock(spec=AlertManager)
        self.alert_manager.send_alert = Mock()

        self.analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            config=AnalyzerConfig(
                analysis_interval=60,
                min_connections=5,
                min_duration=60,
                alert_cooldown=60,
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

    def test_alert_cooldown(self):

        pair_key = "192.168.1.100->10.0.0.1:443/TCP"
        self.analyzer._alert_cooldowns[pair_key] = time.time()

        mock_result = Mock(spec=DetectionResult)
        mock_result.pair_key = pair_key
        mock_result.combined_score = 0.9
        mock_result.confidence = BeaconConfidence.HIGH

        self.analyzer._known_beacons[pair_key] = mock_result

        should_alert = self.analyzer._should_alert(mock_result)
        assert not should_alert

    def test_get_known_beacons(self):

        mock_result = Mock(spec=DetectionResult)
        mock_result.pair_key = "test-pair"

        self.analyzer._known_beacons["test-pair"] = mock_result

        beacons = self.analyzer.get_known_beacons()

        assert len(beacons) == 1

    def test_statistics(self):

        stats = self.analyzer.statistics

        assert "running" in stats
        assert "analysis_interval" in stats
        assert "total_runs" in stats
        assert "current_known_beacons" in stats


class TestAlertManager:

    def test_alert_creation(self):

        alert = Alert(
            alert_id="test-alert-1",
            title="Test Alert",
            description="This is a test alert",
            severity=AlertSeverity.HIGH,
            source="test",
        )

        assert alert.alert_id == "test-alert-1"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.timestamp is not None

    def test_alert_to_dict(self):

        alert = Alert(
            alert_id="test-alert-1",
            title="Test Alert",
            description="This is a test alert",
            severity=AlertSeverity.CRITICAL,
            source="test",
            details={"key": "value"},
        )

        d = alert.to_dict()

        assert d["alert_id"] == "test-alert-1"
        assert d["severity"] == "critical"
        assert d["details"] == {"key": "value"}

    def test_alert_to_syslog(self):
        alert = Alert(
            alert_id="test-alert-1",
            title="Beacon Detected",
            description="Beaconing detected from 192.168.1.100",
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
        assert AlertSeverity.MEDIUM.syslog_priority == logging.WARNING
        assert AlertSeverity.HIGH.syslog_priority == logging.ERROR
        assert AlertSeverity.CRITICAL.syslog_priority == logging.CRITICAL


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
