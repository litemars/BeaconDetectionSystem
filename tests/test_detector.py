"""Tests for Beacon Detection Algorithms.

Run with: pytest tests/test_detector.py -v
"""

import random
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.detector import (
    BeaconConfidence,
    BeaconDetector,
    DetectionResult,
    DetectorConfig,
    IntervalStats,
    PeriodicityResult,
)
from control_plane.storage import ConnectionPair


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_pair(
    intervals,
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    dst_port=443,
    protocol="TCP",
    packet_sizes=None,
):
    pair = ConnectionPair(
        src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, protocol=protocol
    )
    ts = 1_000_000.0
    pair.timestamps.append(ts)
    default_size = 128
    pair.packet_sizes.append(packet_sizes[0] if packet_sizes else default_size)
    for i, interval in enumerate(intervals):
        ts += interval
        pair.timestamps.append(ts)
        size = (
            packet_sizes[i + 1]
            if packet_sizes and i + 1 < len(packet_sizes)
            else default_size
        )
        pair.packet_sizes.append(size)
    pair.first_seen = pair.timestamps[0]
    pair.last_seen = pair.timestamps[-1]
    return pair


# ---------------------------------------------------------------------------
# Interval statistics
# ---------------------------------------------------------------------------


class TestIntervalStats:

    def test_regular_intervals(self):
        detector = BeaconDetector()
        stats = detector._calculate_interval_stats([60.0] * 20)
        assert stats.count == 20
        assert stats.mean == 60.0
        assert stats.std_dev == 0.0
        assert stats.cv == 0.0
        assert stats.jitter == 0.0

    def test_irregular_intervals(self):
        detector = BeaconDetector()
        stats = detector._calculate_interval_stats([10.0, 50.0, 30.0, 70.0, 40.0])
        assert stats.count == 5
        assert stats.mean == 40.0
        assert stats.cv >= 0.5
        assert stats.min_interval == 10.0
        assert stats.max_interval == 70.0

    def test_small_jitter(self):
        random.seed(0)
        detector = BeaconDetector()
        intervals = [60.0 + random.uniform(-2, 2) for _ in range(50)]
        stats = detector._calculate_interval_stats(intervals)
        assert stats.cv < 0.1
        assert stats.jitter < 5.0


# ---------------------------------------------------------------------------
# CV score
# ---------------------------------------------------------------------------


class TestCVScore:

    def test_zero_cv_max_score(self):
        assert BeaconDetector()._calculate_cv_score(0.0) == 1.0

    def test_high_cv_low_score(self):
        assert BeaconDetector()._calculate_cv_score(1.0) < 0.1

    def test_threshold_cv_medium_score(self):
        detector = BeaconDetector(DetectorConfig(cv_threshold=0.15))
        score = detector._calculate_cv_score(0.15)
        assert 0.4 < score < 0.6


# ---------------------------------------------------------------------------
# Periodicity analysis
# ---------------------------------------------------------------------------


class TestPeriodicityAnalysis:

    def test_perfectly_periodic(self):
        result = BeaconDetector()._analyze_periodicity([60.0] * 30)
        assert isinstance(result, PeriodicityResult)

    def test_periodic_with_noise(self):
        random.seed(1)
        intervals = [60.0 + random.gauss(0, 3) for _ in range(50)]
        result = BeaconDetector()._analyze_periodicity(intervals)
        assert isinstance(result, PeriodicityResult)

    def test_random_no_periodicity(self):
        random.seed(2)
        intervals = [random.uniform(10, 300) for _ in range(50)]
        result = BeaconDetector()._analyze_periodicity(intervals)
        assert result.periodicity_score < 0.5

    def test_sample_penalty_small_n(self):
        """With n<20 the score should be lower than with n>=20 for identical signal."""
        random.seed(3)
        intervals_large = [60.0 + random.gauss(0, 1) for _ in range(40)]
        intervals_small = intervals_large[:10]
        detector = BeaconDetector()
        score_large = detector._analyze_periodicity(intervals_large).periodicity_score
        score_small = detector._analyze_periodicity(intervals_small).periodicity_score
        assert score_large >= score_small


# ---------------------------------------------------------------------------
# Jitter score
# ---------------------------------------------------------------------------


class TestJitterScore:

    def test_zero_jitter(self):
        assert BeaconDetector()._calculate_jitter_score(0.0) == 1.0

    def test_at_threshold(self):
        detector = BeaconDetector(DetectorConfig(jitter_threshold=5.0))
        score = detector._calculate_jitter_score(5.0)
        assert 0.4 < score < 0.6

    def test_high_jitter(self):
        detector = BeaconDetector(DetectorConfig(jitter_threshold=5.0))
        assert detector._calculate_jitter_score(50.0) < 0.2


# ---------------------------------------------------------------------------
# Packet-size consistency score
# ---------------------------------------------------------------------------


class TestSizeScore:

    def test_uniform_sizes_high_score(self):
        detector = BeaconDetector()
        sizes = [128] * 30
        assert detector._calculate_size_score(sizes) > 0.9

    def test_variable_sizes_low_score(self):
        random.seed(4)
        detector = BeaconDetector()
        sizes = [random.randint(64, 1400) for _ in range(30)]
        assert detector._calculate_size_score(sizes) < 0.5

    def test_insufficient_samples_neutral(self):
        detector = BeaconDetector()
        assert detector._calculate_size_score([128, 130]) == 0.5


# ---------------------------------------------------------------------------
# Full beacon detection
# ---------------------------------------------------------------------------


class TestBeaconDetection:

    def test_detect_regular_beacon(self):
        random.seed(5)
        config = DetectorConfig(
            min_connections=10,
            cv_threshold=0.15,
            periodicity_threshold=0.5,
            jitter_threshold=5.0,
            alert_threshold=0.6,
        )
        detector = BeaconDetector(config)
        intervals = [60.0 + random.uniform(-1, 1) for _ in range(30)]
        pair = make_pair(intervals)
        result = detector.analyze(pair)
        assert result is not None
        assert result.cv_score > 0.7
        assert result.combined_score > 0.5

    def test_detect_random_traffic(self):
        random.seed(6)
        detector = BeaconDetector(
            DetectorConfig(min_connections=10, alert_threshold=0.7)
        )
        pair = make_pair([random.uniform(5, 300) for _ in range(30)])
        result = detector.analyze(pair)
        assert result is not None
        assert result.cv_score < 0.5
        assert not result.is_beacon

    def test_insufficient_data_returns_none(self):
        detector = BeaconDetector(DetectorConfig(min_connections=20))
        pair = make_pair([60.0] * 9)
        assert detector.analyze(pair) is None

    def test_result_has_size_score(self):
        random.seed(7)
        config = DetectorConfig(min_connections=10, alert_threshold=0.5)
        detector = BeaconDetector(config)
        sizes = [128 + random.randint(-2, 2) for _ in range(31)]
        pair = make_pair(
            [60.0 + random.uniform(-1, 1) for _ in range(30)], packet_sizes=sizes
        )
        result = detector.analyze(pair)
        assert result is not None
        assert 0.0 <= result.size_score <= 1.0

    def test_result_has_explanation(self):
        random.seed(8)
        config = DetectorConfig(min_connections=10, alert_threshold=0.5)
        detector = BeaconDetector(config)
        pair = make_pair([60.0 + random.uniform(-1, 1) for _ in range(30)])
        result = detector.analyze(pair)
        assert result is not None
        exp = result.explanation
        assert "detected_interval_seconds" in exp
        assert "contributing_signals" in exp
        assert len(exp["contributing_signals"]) == 4
        signal_names = {s["name"] for s in exp["contributing_signals"]}
        assert "cv" in signal_names
        assert "periodicity" in signal_names
        assert "jitter" in signal_names
        assert "packet_size_consistency" in signal_names

    def test_time_window_slicing(self):
        """Only intervals within time_window seconds of last_seen are scored.

        Setup: 61 events at exactly 60s apart spanning 3600s total.
        time_window=600 → cutoff = last_seen - 600 = T + 3000.
        Events T+3000 … T+3600 fall inside the window: 11 timestamps → 10 intervals.
        sample_count must equal 10 exactly.
        """
        T = 1_000_000.0  # fixed epoch base — no wall-clock dependency
        config = DetectorConfig(
            min_connections=10, time_window=600, alert_threshold=0.5
        )
        detector = BeaconDetector(config)

        pair = ConnectionPair(
            src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=443, protocol="TCP"
        )
        # 61 events: T, T+60, T+120, ..., T+3600
        for i in range(61):
            pair.timestamps.append(T + i * 60.0)
            pair.packet_sizes.append(128)
        pair.first_seen = pair.timestamps[0]
        pair.last_seen = pair.timestamps[-1]  # T + 3600

        result = detector.analyze(pair)
        assert result is not None, "Expected a result for a perfectly periodic pair"
        # Cutoff = T+3600 - 600 = T+3000; bisect finds index 50 → 11 timestamps → 10 intervals
        assert result.explanation["sample_count"] == 10

    def test_confidence_levels(self):
        detector = BeaconDetector()
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
        assert (
            detector._determine_confidence(0.9, 0.9, 0.9, 0.9, 0.9)
            == BeaconConfidence.CRITICAL
        )

    def test_batch_analyze_sorted_by_score(self):
        random.seed(9)
        detector = BeaconDetector(DetectorConfig(min_connections=5))
        pairs = [
            make_pair(
                [60.0 + random.uniform(-1, 1) for _ in range(20)],
                src_ip="1.1.1.1",
                dst_ip="2.2.2.1",
            ),
            make_pair(
                [random.uniform(5, 300) for _ in range(20)],
                src_ip="1.1.1.2",
                dst_ip="2.2.2.2",
            ),
            make_pair(
                [120.0 + random.uniform(-2, 2) for _ in range(20)],
                src_ip="1.1.1.3",
                dst_ip="2.2.2.3",
            ),
        ]
        results = detector.batch_analyze(pairs)
        assert len(results) == 3
        assert results[0].combined_score >= results[-1].combined_score


# ---------------------------------------------------------------------------
# DetectorConfig
# ---------------------------------------------------------------------------


class TestDetectorConfig:

    def test_default_config(self):
        config = DetectorConfig()
        assert config.min_connections == 10
        assert config.cv_threshold == 0.15
        assert config.alert_threshold == 0.7
        # New defaults for 4-signal weights
        assert (
            abs(
                config.cv_weight
                + config.periodicity_weight
                + config.jitter_weight
                + config.size_weight
                - 1.0
            )
            < 0.01
        )

    def test_weights_sum_to_one(self):
        config = DetectorConfig(
            cv_weight=0.3, periodicity_weight=0.3, jitter_weight=0.2, size_weight=0.2
        )
        total = (
            config.cv_weight
            + config.periodicity_weight
            + config.jitter_weight
            + config.size_weight
        )
        assert abs(total - 1.0) < 0.01


# ---------------------------------------------------------------------------
# DetectionResult serialisation
# ---------------------------------------------------------------------------


class TestDetectionResult:

    def test_to_dict_includes_new_fields(self):
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
            size_score=0.75,
            combined_score=0.83,
            is_beacon=True,
            confidence=BeaconConfidence.HIGH,
            interval_stats=interval_stats,
            periodicity_result=periodicity_result,
            connection_count=21,
            duration_seconds=1200.0,
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-01T00:20:00Z",
            explanation={"detected_interval_seconds": 60.0},
        )
        d = result.to_dict()
        assert d["is_beacon"] is True
        assert d["confidence"] == "high"
        assert "size_score" in d
        assert "explanation" in d
        assert d["explanation"]["detected_interval_seconds"] == 60.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
