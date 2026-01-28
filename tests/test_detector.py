"""
Tests for Beacon Detection Algorithms
Run with: pytest tests/test_detector.py -v
"""

import random
import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.detector import (BeaconConfidence, BeaconDetector,
                                    DetectionResult, DetectorConfig,
                                    IntervalStats, PeriodicityResult)
from control_plane.storage import ConnectionPair


class TestIntervalStats:

    def test_regular_intervals(self):

        detector = BeaconDetector()
        intervals = [60.0] * 20  # 20 intervals of 60 seconds each

        stats = detector._calculate_interval_stats(intervals)

        assert stats.count == 20
        assert stats.mean == 60.0
        assert stats.std_dev == 0.0
        assert stats.cv == 0.0
        assert stats.median == 60.0
        assert stats.jitter == 0.0

    def test_irregular_intervals(self):

        detector = BeaconDetector()
        intervals = [10.0, 50.0, 30.0, 70.0, 40.0]  # Highly variable

        stats = detector._calculate_interval_stats(intervals)

        assert stats.count == 5
        assert stats.mean == 40.0
        assert stats.cv >= 0.5  # High coefficient of variation
        assert stats.min_interval == 10.0
        assert stats.max_interval == 70.0

    def test_small_jitter(self):

        detector = BeaconDetector()
        base = 60.0
        jitter_range = 2.0
        intervals = [
            base + random.uniform(-jitter_range, jitter_range) for _ in range(50)
        ]

        stats = detector._calculate_interval_stats(intervals)

        assert stats.count == 50
        assert 58.0 < stats.mean < 62.0
        assert stats.cv < 0.1  # Low CV due to small jitter
        assert stats.jitter < 5.0


class TestCVScore:

    def test_zero_cv_max_score(self):

        detector = BeaconDetector()
        score = detector._calculate_cv_score(0.0)
        assert score == 1.0

    def test_high_cv_low_score(self):

        detector = BeaconDetector()
        score = detector._calculate_cv_score(1.0)
        assert score < 0.1

    def test_threshold_cv_medium_score(self):

        config = DetectorConfig(cv_threshold=0.15)
        detector = BeaconDetector(config)
        score = detector._calculate_cv_score(0.15)
        assert 0.4 < score < 0.6


class TestPeriodicityAnalysis:

    def test_perfectly_periodic(self):

        detector = BeaconDetector()
        # Create perfectly periodic intervals
        intervals = [60.0] * 30

        result = detector._analyze_periodicity(intervals)

        # Perfect periodicity should have low score (no variation to detect)
        # But our implementation should handle this edge case
        assert isinstance(result, PeriodicityResult)

    def test_periodic_with_noise(self):

        detector = BeaconDetector()
        # Create periodic intervals with small noise
        base = 60.0
        noise = 3.0
        intervals = [base + random.gauss(0, noise) for _ in range(50)]

        result = detector._analyze_periodicity(intervals)

        assert isinstance(result, PeriodicityResult)
        # Should have some periodicity detected

    def test_random_no_periodicity(self):

        detector = BeaconDetector()
        # Create random intervals
        intervals = [random.uniform(10, 300) for _ in range(50)]

        result = detector._analyze_periodicity(intervals)

        assert isinstance(result, PeriodicityResult)
        # Random data should have low periodicity score
        assert result.periodicity_score < 0.5


class TestJitterScore:

    def test_zero_jitter_max_score(self):

        detector = BeaconDetector()
        score = detector._calculate_jitter_score(0.0)
        assert score == 1.0

    def test_threshold_jitter(self):

        config = DetectorConfig(jitter_threshold=5.0)
        detector = BeaconDetector(config)
        score = detector._calculate_jitter_score(5.0)
        assert 0.4 < score < 0.6

    def test_high_jitter_low_score(self):

        config = DetectorConfig(jitter_threshold=5.0)
        detector = BeaconDetector(config)
        score = detector._calculate_jitter_score(50.0)
        assert score < 0.2


class TestBeaconDetection:

    def create_connection_pair(
        self,
        intervals: list,
        src_ip: str = "192.168.1.100",
        dst_ip: str = "10.0.0.1",
        dst_port: int = 443,
    ):
        pair = ConnectionPair(
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, protocol="TCP"
        )

        # Generate timestamps from intervals
        timestamp = 1000000.0
        pair.timestamps.append(timestamp)
        for interval in intervals:
            timestamp += interval
            pair.timestamps.append(timestamp)

        pair.first_seen = pair.timestamps[0]
        pair.last_seen = pair.timestamps[-1]

        return pair

    def test_detect_regular_beacon(self):

        config = DetectorConfig(
            min_connections=10,
            cv_threshold=0.15,
            periodicity_threshold=0.5,
            jitter_threshold=5.0,
            alert_threshold=0.6,
        )
        detector = BeaconDetector(config)

        # Create regular beacon pattern (60s intervals with small jitter)
        intervals = [60.0 + random.uniform(-1, 1) for _ in range(30)]
        pair = self.create_connection_pair(intervals)

        result = detector.analyze(pair)

        assert result is not None
        assert result.cv_score > 0.7  # High score for regular intervals
        assert result.combined_score > 0.5
        # Note: May or may not trigger is_beacon depending on exact jitter

    def test_detect_random_traffic(self):
        config = DetectorConfig(
            min_connections=10, cv_threshold=0.15, alert_threshold=0.7
        )
        detector = BeaconDetector(config)

        # Create random traffic pattern
        intervals = [random.uniform(5, 300) for _ in range(30)]
        pair = self.create_connection_pair(intervals)

        result = detector.analyze(pair)

        assert result is not None
        assert result.cv_score < 0.5  # Low score for irregular intervals
        assert not result.is_beacon

    def test_insufficient_data(self):

        config = DetectorConfig(min_connections=20)
        detector = BeaconDetector(config)

        # Only 10 connections (need 20)
        intervals = [60.0] * 9
        pair = self.create_connection_pair(intervals)

        result = detector.analyze(pair)

        assert result is None

    def test_confidence_levels(self):

        detector = BeaconDetector()

        # Test various score combinations
        assert (
            detector._determine_confidence(0.1, 0.1, 0.1, 0.1) == BeaconConfidence.NONE
        )
        assert (
            detector._determine_confidence(0.4, 0.4, 0.4, 0.4) == BeaconConfidence.LOW
        )
        assert (
            detector._determine_confidence(0.6, 0.6, 0.6, 0.6)
            == BeaconConfidence.MEDIUM
        )
        assert (
            detector._determine_confidence(0.8, 0.8, 0.8, 0.8) == BeaconConfidence.HIGH
        )

    def test_batch_analyze(self):

        detector = BeaconDetector(DetectorConfig(min_connections=5))

        # Create multiple pairs
        pairs = []

        # Regular beacon
        pairs.append(
            self.create_connection_pair(
                [60.0 + random.uniform(-1, 1) for _ in range(20)],
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
            )
        )

        # Random traffic
        pairs.append(
            self.create_connection_pair(
                [random.uniform(5, 300) for _ in range(20)],
                src_ip="192.168.1.101",
                dst_ip="10.0.0.2",
            )
        )

        # Another beacon with different interval
        pairs.append(
            self.create_connection_pair(
                [120.0 + random.uniform(-2, 2) for _ in range(20)],
                src_ip="192.168.1.102",
                dst_ip="10.0.0.3",
            )
        )

        results = detector.batch_analyze(pairs)

        assert len(results) == 3
        # Results should be sorted by score descending
        assert results[0].combined_score >= results[-1].combined_score


class TestDetectorConfig:

    def test_default_config(self):

        config = DetectorConfig()

        assert config.min_connections == 10
        assert config.cv_threshold == 0.15
        assert config.periodicity_threshold == 0.7
        assert config.jitter_threshold == 5.0
        assert config.alert_threshold == 0.7

    def test_custom_config(self):

        config = DetectorConfig(
            min_connections=20, cv_threshold=0.1, alert_threshold=0.8
        )

        assert config.min_connections == 20
        assert config.cv_threshold == 0.1
        assert config.alert_threshold == 0.8

    def test_weight_validation(self):

        # Weights should sum to 1.0
        config = DetectorConfig(
            cv_weight=0.5, periodicity_weight=0.3, jitter_weight=0.2
        )
        detector = BeaconDetector(config)

        # Should not raise any warnings
        total = config.cv_weight + config.periodicity_weight + config.jitter_weight
        assert abs(total - 1.0) < 0.01


class TestDetectionResult:

    def test_to_dict(self):

        # Create a mock result
        interval_stats = IntervalStats(
            count=20,
            mean=60.0,
            std_dev=2.0,
            cv=0.033,
            median=60.0,
            min_interval=58.0,
            max_interval=62.0,
            jitter=2.0,
        )

        periodicity_result = PeriodicityResult(
            is_periodic=True,
            dominant_period=60.0,
            periodicity_score=0.8,
            frequency_peaks=[(0.0167, 0.8)],
        )

        result = DetectionResult(
            pair_key="192.168.1.100->10.0.0.1:443/TCP",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol="TCP",
            cv_score=0.9,
            periodicity_score=0.8,
            jitter_score=0.85,
            combined_score=0.85,
            is_beacon=True,
            confidence=BeaconConfidence.HIGH,
            interval_stats=interval_stats,
            periodicity_result=periodicity_result,
            connection_count=21,
            duration_seconds=1200.0,
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-01T00:20:00Z",
        )

        d = result.to_dict()

        assert d["pair_key"] == "192.168.1.100->10.0.0.1:443/TCP"
        assert d["is_beacon"] == True
        assert d["confidence"] == "high"
        assert "interval_stats" in d
        assert "periodicity_result" in d


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
