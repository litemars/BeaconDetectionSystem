"""Tests for detection scoring signals and candidate pre-filter.

Definition of Done checks covered here:
  [DoD-1] A synthetic 60s beacon with 5% packet-size CV scores >= 0.75 combined.
  [DoD-2] A synthetic 60s beacon with max jitter 30s but consistent packet size
          scores >= 0.6 combined.
  [DoD-3] (covered in test_suppression.py) NTP suppressed at stage 1.

Run with: pytest tests/test_scoring_signals.py -v
"""

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.detector import BeaconDetector, DetectorConfig
from control_plane.storage import ConnectionPair


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_pair(
    intervals,
    dst_port=443,
    protocol="TCP",
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    packet_sizes=None,
    base_size=512,
):
    pair = ConnectionPair(
        src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, protocol=protocol
    )
    ts = 1_000_000.0
    pair.timestamps.append(ts)
    pair.packet_sizes.append(packet_sizes[0] if packet_sizes else base_size)
    for i, iv in enumerate(intervals):
        ts += iv
        pair.timestamps.append(ts)
        sz = (
            packet_sizes[i + 1]
            if packet_sizes and i + 1 < len(packet_sizes)
            else base_size
        )
        pair.packet_sizes.append(sz)
    pair.first_seen = pair.timestamps[0]
    pair.last_seen = pair.timestamps[-1]
    return pair


# ---------------------------------------------------------------------------
# [DoD-1] 60s beacon with 5% packet-size CV must score >= 0.75 combined
# ---------------------------------------------------------------------------


class TestSizeConsistencySignal:

    def test_dod1_60s_beacon_5pct_size_cv_above_075(self):
        """[DoD-1] 60s beacon, 5% size CV, combined score >= 0.75."""
        random.seed(10)
        n = 40
        intervals = [60.0 + random.gauss(0, 1.0) for _ in range(n)]
        # ~5% CV: std_dev ≈ 0.05 × 1000 = 50
        sizes = [int(1000 + random.gauss(0, 50)) for _ in range(n + 1)]
        pair = make_pair(intervals, packet_sizes=sizes)
        det = BeaconDetector(DetectorConfig(min_connections=10, alert_threshold=0.6))
        result = det.analyze(pair)
        assert result is not None
        assert result.combined_score >= 0.75, (
            f"[DoD-1] Expected combined >= 0.75, got {result.combined_score:.4f} "
            f"(cv={result.cv_score:.3f} per={result.periodicity_score:.3f} "
            f"jit={result.jitter_score:.3f} sz={result.size_score:.3f})"
        )

    def test_uniform_sizes_raise_size_score(self):
        """Highly uniform packet sizes (CV ≈ 0) produce size_score > 0.9."""
        sizes = [512] * 41
        pair = make_pair([60.0] * 40, packet_sizes=sizes)
        det = BeaconDetector()
        result = det.analyze(pair)
        assert result is not None
        assert result.size_score > 0.9

    def test_variable_sizes_lower_size_score(self):
        """Highly variable packet sizes (64–1400 B) produce size_score < 0.5."""
        random.seed(42)
        sizes = [random.randint(64, 1400) for _ in range(41)]
        pair = make_pair([60.0] * 40, packet_sizes=sizes)
        det = BeaconDetector()
        result = det.analyze(pair)
        assert result is not None
        assert result.size_score < 0.5

    def test_size_signal_in_explanation(self):
        """Explanation dict exposes packet_size_cv and the packet_size_consistency signal."""
        pair = make_pair([60.0] * 40, packet_sizes=[512] * 41)
        det = BeaconDetector(DetectorConfig(min_connections=10))
        result = det.analyze(pair)
        assert result is not None
        exp = result.explanation
        assert "packet_size_cv" in exp
        signal_names = {s["name"] for s in exp["contributing_signals"]}
        assert "packet_size_consistency" in signal_names

    def test_replacing_uniform_sizes_with_variable_lowers_combined(self):
        """Same timing, different size variance: combined score must drop."""
        random.seed(44)
        intervals = [60.0 + random.gauss(0, 1.0) for _ in range(40)]
        det = BeaconDetector(DetectorConfig(min_connections=10, alert_threshold=0.3))
        r_uniform = det.analyze(make_pair(intervals, packet_sizes=[512] * 41))
        r_variable = det.analyze(
            make_pair(
                intervals, packet_sizes=[random.randint(64, 1400) for _ in range(41)]
            )
        )
        assert r_uniform is not None
        assert r_variable is not None
        assert r_uniform.size_score > r_variable.size_score
        assert r_uniform.combined_score > r_variable.combined_score


# ---------------------------------------------------------------------------
# [DoD-2] 60s beacon with high jitter (30s max) but consistent size >= 0.6
# ---------------------------------------------------------------------------


class TestHighJitterConsistentSize:

    def test_dod2_high_jitter_consistent_size_above_06(self):
        """[DoD-2] 60s beacon, max jitter 30s (two outlier intervals), consistent
        packet size.  combined score must be >= 0.6.

        Setup: 38 tight 60s ± 1s intervals + 2 outliers at ~90s (30s over median).
        This makes interval_stats.jitter ≈ 30s (the max deviation metric), while
        the majority of the signal is still regular.  The consistent sizes keep
        size_score high and, together with the strong CV and periodicity from the
        38 tight intervals, push the combined above 0.6 despite the jitter penalty.
        """
        random.seed(20)
        tight = [60.0 + random.gauss(0, 1.0) for _ in range(38)]
        outliers = [90.0, 91.5]  # max deviation ≈ 30s
        intervals = tight + outliers
        random.shuffle(intervals)
        n = len(intervals)
        sizes = [int(512 + random.gauss(0, 4)) for _ in range(n + 1)]  # ~0.8% CV
        pair = make_pair(intervals, packet_sizes=sizes)
        det = BeaconDetector(DetectorConfig(min_connections=10, alert_threshold=0.5))
        result = det.analyze(pair)
        assert result is not None
        assert result.combined_score >= 0.6, (
            f"[DoD-2] Expected combined >= 0.6, got {result.combined_score:.4f} "
            f"(cv={result.cv_score:.3f} per={result.periodicity_score:.3f} "
            f"jit={result.jitter_score:.3f} sz={result.size_score:.3f})"
        )

    def test_high_jitter_uniform_sizes_better_than_variable(self):
        """Same high-jitter timing: consistent sizes must outscore variable sizes."""
        random.seed(21)
        tight = [60.0 + random.gauss(0, 1.0) for _ in range(38)]
        outliers = [90.0, 91.5]
        intervals = tight + outliers
        random.shuffle(intervals)
        n = len(intervals)
        uniform_sizes = [512] * (n + 1)
        variable_sizes = [random.randint(64, 1400) for _ in range(n + 1)]
        det = BeaconDetector(DetectorConfig(min_connections=10, alert_threshold=0.3))
        r_u = det.analyze(make_pair(list(intervals), packet_sizes=uniform_sizes))
        r_v = det.analyze(make_pair(list(intervals), packet_sizes=variable_sizes))
        assert r_u is not None and r_v is not None
        assert r_u.combined_score > r_v.combined_score


# ---------------------------------------------------------------------------
# FFT stability (cap + sample penalty)
# ---------------------------------------------------------------------------


class TestFFTStability:

    def test_ratio_cap_score_bounded_by_one(self):
        """With n=5, the raw ratio can be very large; cap must keep score <= 1.0."""
        det = BeaconDetector()
        result = det._analyze_periodicity([60.0] * 5)
        assert result.periodicity_score <= 1.0

    def test_sample_penalty_small_n_below_large_n(self):
        """n=8 must score strictly lower than n=40 for an identical periodic signal."""
        random.seed(30)
        large = [60.0 + random.gauss(0, 1) for _ in range(40)]
        small = large[:8]
        det = BeaconDetector()
        assert (
            det._analyze_periodicity(large).periodicity_score
            > det._analyze_periodicity(small).periodicity_score
        )

    def test_random_intervals_low_periodicity(self):
        """Purely random intervals must produce periodicity_score < 0.5."""
        random.seed(31)
        intervals = [random.uniform(10, 300) for _ in range(40)]
        result = BeaconDetector()._analyze_periodicity(intervals)
        assert result.periodicity_score < 0.5

    def test_regular_intervals_high_periodicity(self):
        """Perfectly regular 60s intervals with n=40 must produce score > 0.5."""
        result = BeaconDetector()._analyze_periodicity([60.0] * 40)
        assert result.periodicity_score > 0.5


# ---------------------------------------------------------------------------
# Candidate pre-filter (batch_analyze fast path)
# ---------------------------------------------------------------------------


class TestCandidatePrefilter:

    def test_pair_below_min_connections_not_in_results(self):
        """batch_analyze skips pairs with fewer connections than min_connections."""
        det = BeaconDetector(DetectorConfig(min_connections=20))
        pair = make_pair([60.0] * 5)  # 6 connections total
        assert det.batch_analyze([pair]) == []

    def test_pair_span_shorter_than_beacon_interval_filtered(self):
        """A pair whose entire span < min_beacon_interval is pre-filtered."""
        det = BeaconDetector(
            DetectorConfig(min_connections=5, min_beacon_interval=60.0)
        )
        # 10 events 2 s apart → total span 20 s < 60 s
        pair = make_pair([2.0] * 10)
        assert det.batch_analyze([pair]) == []

    def test_pair_with_wildly_long_rough_interval_filtered(self):
        """A pair whose rough mean interval >> max_beacon_interval is pre-filtered."""
        det = BeaconDetector(
            DetectorConfig(min_connections=5, max_beacon_interval=3600.0)
        )
        # 5 events spanning 3 years  → rough interval ≈ 9 months >> 7200 s
        YEAR = 365.25 * 24 * 3600
        pair = make_pair([YEAR] * 10)
        assert det.batch_analyze([pair]) == []

    def test_valid_pair_passes_prefilter_and_scores(self):
        """A well-formed 60s beacon must pass the pre-filter and return a result."""
        random.seed(40)
        det = BeaconDetector(DetectorConfig(min_connections=10, alert_threshold=0.3))
        intervals = [60.0 + random.gauss(0, 1) for _ in range(20)]
        pair = make_pair(intervals)
        results = det.batch_analyze([pair])
        assert len(results) == 1

    def test_mixed_batch_only_valid_pairs_scored(self):
        """batch_analyze with one valid and one too-sparse pair returns one result."""
        random.seed(41)
        det = BeaconDetector(DetectorConfig(min_connections=10, alert_threshold=0.3))
        good = make_pair(
            [60.0 + random.gauss(0, 1) for _ in range(20)], src_ip="1.1.1.1"
        )
        bad = make_pair([60.0] * 3, src_ip="2.2.2.2")  # only 4 connections
        results = det.batch_analyze([good, bad])
        pair_keys = {r.pair_key for r in results}
        assert good.pair_key in pair_keys
        assert bad.pair_key not in pair_keys


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
