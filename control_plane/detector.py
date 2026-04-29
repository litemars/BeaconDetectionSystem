import bisect
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy import fft

from .storage import ConnectionPair

logger = logging.getLogger("beacon_detect.control_plane.detector")


class BeaconConfidence(Enum):

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IntervalStats:

    count: int
    mean: float
    std_dev: float
    cv: float
    median: float
    min_interval: float
    max_interval: float
    jitter: float  # max deviation from median

    def to_dict(self):
        return {
            "count": int(self.count),
            "mean": float(round(self.mean, 3)),
            "std_dev": float(round(self.std_dev, 3)),
            "cv": float(round(self.cv, 4)),
            "median": float(round(self.median, 3)),
            "min_interval": float(round(self.min_interval, 3)),
            "max_interval": float(round(self.max_interval, 3)),
            "jitter": float(round(self.jitter, 3)),
        }


@dataclass
class PeriodicityResult:

    is_periodic: bool
    dominant_period: Optional[float]  # seconds
    periodicity_score: float  # 0.0 to 1.0
    frequency_peaks: List[Tuple[float, float]]  # (frequency, magnitude)

    def to_dict(self):
        return {
            "is_periodic": bool(self.is_periodic),
            "dominant_period": (
                float(round(self.dominant_period, 3)) if self.dominant_period else None
            ),
            "periodicity_score": float(round(self.periodicity_score, 4)),
            "frequency_peaks": [
                (float(round(f, 6)), float(round(m, 4)))
                for f, m in self.frequency_peaks
            ],
        }


@dataclass
class DetectionResult:

    pair_key: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str

    # Detection scores (0.0–1.0, higher = more beacon-like)
    cv_score: float
    periodicity_score: float
    jitter_score: float
    size_score: float
    combined_score: float

    # Detection outcome
    is_beacon: bool
    confidence: BeaconConfidence

    # Supporting data
    interval_stats: IntervalStats
    periodicity_result: PeriodicityResult

    # Metadata
    connection_count: int
    duration_seconds: float
    first_seen: str
    last_seen: str
    analysis_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    # Analyst-facing explanation (structured per-signal breakdown)
    explanation: Dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "pair_key": str(self.pair_key),
            "src_ip": str(self.src_ip),
            "dst_ip": str(self.dst_ip),
            "dst_port": int(self.dst_port),
            "protocol": str(self.protocol),
            "cv_score": float(round(self.cv_score, 4)),
            "periodicity_score": float(round(self.periodicity_score, 4)),
            "jitter_score": float(round(self.jitter_score, 4)),
            "size_score": float(round(self.size_score, 4)),
            "combined_score": float(round(self.combined_score, 4)),
            "is_beacon": bool(self.is_beacon),
            "confidence": str(self.confidence.value),
            "interval_stats": self.interval_stats.to_dict(),
            "periodicity_result": self.periodicity_result.to_dict(),
            "connection_count": int(self.connection_count),
            "duration_seconds": float(round(self.duration_seconds, 2)),
            "first_seen": str(self.first_seen),
            "last_seen": str(self.last_seen),
            "analysis_time": str(self.analysis_time),
            "explanation": self.explanation,
        }


@dataclass
class DetectorConfig:

    # Minimum data requirements
    min_connections: int = 10
    time_window: int = 3600  # seconds — analysis window enforced at analysis time

    # CV threshold (lower = more regular, beacon-like)
    cv_threshold: float = 0.15

    # Periodicity threshold (higher = more periodic)
    periodicity_threshold: float = 0.7

    # Jitter threshold in seconds (lower = more consistent)
    jitter_threshold: float = 5.0

    # Interval bounds
    min_beacon_interval: float = 10.0  # seconds
    max_beacon_interval: float = 3600.0  # seconds

    # Score weights (must sum to 1.0)
    cv_weight: float = 0.35
    periodicity_weight: float = 0.35
    jitter_weight: float = 0.15
    size_weight: float = 0.15

    # Final threshold for beacon classification
    alert_threshold: float = 0.7


class BeaconDetector:

    def __init__(self, config=None):

        self.config = config or DetectorConfig()

        total_weight = (
            self.config.cv_weight
            + self.config.periodicity_weight
            + self.config.jitter_weight
            + self.config.size_weight
        )
        if not 0.99 <= total_weight <= 1.01:
            logger.warning(f"Score weights sum to {total_weight:.4f}, should be 1.0")

        logger.info(f"BeaconDetector initialized with config: {self.config}")

    def analyze(self, pair: ConnectionPair):

        if pair.connection_count < self.config.min_connections:
            logger.debug(
                f"Insufficient connections for {pair.pair_key}: "
                f"{pair.connection_count} < {self.config.min_connections}"
            )
            return None

        # Enforce time_window: slice timestamps to the last N seconds.
        # pair.timestamps is bisect-maintained sorted, so we can binary-search.
        if pair.last_seen is not None:
            cutoff = pair.last_seen - self.config.time_window
            start_idx = bisect.bisect_left(pair.timestamps, cutoff)
        else:
            start_idx = 0

        windowed_ts = pair.timestamps[start_idx:]
        # packet_sizes is kept index-aligned with timestamps (see storage.prune_old)
        if len(pair.packet_sizes) == len(pair.timestamps):
            windowed_sizes = pair.packet_sizes[start_idx:]
        else:
            windowed_sizes = pair.packet_sizes  # safety fallback

        if len(windowed_ts) < self.config.min_connections:
            logger.debug(f"Insufficient windowed connections for {pair.pair_key}")
            return None

        # Compute intervals from the windowed timestamp slice
        intervals = [
            windowed_ts[i] - windowed_ts[i - 1] for i in range(1, len(windowed_ts))
        ]

        # Filter intervals to the valid beacon range
        intervals = [
            i
            for i in intervals
            if self.config.min_beacon_interval <= i <= self.config.max_beacon_interval
        ]

        if len(intervals) < self.config.min_connections - 1:
            logger.debug(f"Insufficient valid intervals for {pair.pair_key}")
            return None

        interval_stats = self._calculate_interval_stats(intervals)
        cv_score = self._calculate_cv_score(interval_stats.cv)
        periodicity_result = self._analyze_periodicity(intervals)
        jitter_score = self._calculate_jitter_score(
            interval_stats.jitter, interval_stats.median
        )
        size_score = self._calculate_size_score(windowed_sizes)

        combined_score = (
            self.config.cv_weight * cv_score
            + self.config.periodicity_weight * periodicity_result.periodicity_score
            + self.config.jitter_weight * jitter_score
            + self.config.size_weight * size_score
        )

        is_beacon = combined_score >= self.config.alert_threshold

        confidence = self._determine_confidence(
            combined_score,
            cv_score,
            periodicity_result.periodicity_score,
            jitter_score,
            size_score,
        )

        explanation = self._build_explanation(
            interval_stats=interval_stats,
            periodicity_result=periodicity_result,
            cv_score=cv_score,
            jitter_score=jitter_score,
            size_score=size_score,
            windowed_sizes=windowed_sizes,
            sample_count=len(intervals),
        )

        result = DetectionResult(
            pair_key=pair.pair_key,
            src_ip=pair.src_ip,
            dst_ip=pair.dst_ip,
            dst_port=pair.dst_port,
            protocol=pair.protocol,
            cv_score=cv_score,
            periodicity_score=periodicity_result.periodicity_score,
            jitter_score=jitter_score,
            size_score=size_score,
            combined_score=combined_score,
            is_beacon=is_beacon,
            confidence=confidence,
            interval_stats=interval_stats,
            periodicity_result=periodicity_result,
            connection_count=pair.connection_count,
            duration_seconds=pair.duration_seconds,
            first_seen=(
                datetime.fromtimestamp(pair.first_seen).isoformat() + "Z"
                if pair.first_seen
                else ""
            ),
            last_seen=(
                datetime.fromtimestamp(pair.last_seen).isoformat() + "Z"
                if pair.last_seen
                else ""
            ),
            explanation=explanation,
        )

        if is_beacon:
            logger.warning(
                f"Beacon detected: {pair.pair_key} "
                f"(score={combined_score:.3f}, confidence={confidence.value})"
            )

        return result

    # ------------------------------------------------------------------
    # Scoring functions
    # ------------------------------------------------------------------

    def _calculate_interval_stats(self, intervals: List[float]) -> IntervalStats:

        arr = np.array(intervals)
        mean = float(np.mean(arr))
        std_dev = float(np.std(arr))
        median = float(np.median(arr))
        cv = std_dev / mean if mean > 0 else float("inf")
        jitter = float(np.max(np.abs(arr - median)))

        return IntervalStats(
            count=len(intervals),
            mean=mean,
            std_dev=std_dev,
            cv=cv,
            median=median,
            min_interval=float(np.min(arr)),
            max_interval=float(np.max(arr)),
            jitter=jitter,
        )

    def _calculate_cv_score(self, cv: float) -> float:
        """Sigmoid: score→1 when cv≪threshold, score→0 when cv≫threshold."""
        if cv <= 0:
            return 1.0
        threshold = self.config.cv_threshold
        k = 10.0 / threshold
        return 1.0 / (1.0 + math.exp(k * (cv - threshold)))

    def _analyze_periodicity(self, intervals: List[float]) -> PeriodicityResult:
        """Hybrid periodicity scorer: consistency + FFT.

        Two complementary components are computed and the higher score wins:

        Consistency (fraction-within-tolerance)
            Measures what fraction of intervals falls within a tolerance band
            centred on the median.  Tolerance = max(cv_threshold × median,
            jitter_threshold).  This is reliable for tight, uniform beacons
            where the FFT fails (after DC-removal the centred series is near-
            zero noise, leaving no dominant peak).

        FFT (spectral dominance)
            Detects structured periodicity in the *interval deviation* sequence
            (e.g. sinusoidal / alternating jitter patterns added by evasive C2
            implants).  Weak for purely uniform intervals; the ratio is capped
            at 3.0 to prevent super-linear amplification on small samples.

        Both components share the same linear sample-count ramp-up penalty:
        score → 0 at n=4, unchanged at n≥20.
        """
        if len(intervals) < 4:
            return PeriodicityResult(
                is_periodic=False,
                dominant_period=None,
                periodicity_score=0.0,
                frequency_peaks=[],
            )

        arr = np.array(intervals)
        n = len(arr)
        median = float(np.median(arr))

        # ---- Consistency-based score ------------------------------------
        # Effective tolerance: relative floor prevents over-penalising
        # long-period beacons with proportionally larger jitter.
        if median > 0:
            tolerance = max(
                self.config.cv_threshold * median,
                self.config.jitter_threshold,
            )
            consistency_score = float(np.sum(np.abs(arr - median) <= tolerance)) / n
        else:
            consistency_score = 0.0

        # ---- FFT-based score --------------------------------------------
        mean_interval = float(np.mean(arr))
        arr_centered = arr - mean_interval
        fft_result = fft.fft(arr_centered)
        frequencies = fft.fftfreq(n, d=max(mean_interval, 1e-10))

        magnitude = np.abs(fft_result[: n // 2])
        freq_positive = frequencies[: n // 2]
        magnitude_norm = magnitude / (np.sum(magnitude) + 1e-10)

        peaks = []
        for i in range(1, len(magnitude) - 1):
            if magnitude[i] > magnitude[i - 1] and magnitude[i] > magnitude[i + 1]:
                if freq_positive[i] > 0:
                    peaks.append((freq_positive[i], magnitude_norm[i]))

        peaks.sort(key=lambda x: x[1], reverse=True)
        top_peaks = peaks[:5]

        if top_peaks:
            dominant_magnitude = top_peaks[0][1]
            dominant_freq = top_peaks[0][0]
            fft_period = 1.0 / dominant_freq if dominant_freq > 0 else None

            if len(top_peaks) > 1:
                ratio = min(3.0, dominant_magnitude / (top_peaks[1][1] + 1e-10))
                fft_score = min(1.0, dominant_magnitude * ratio)
            else:
                fft_score = dominant_magnitude
        else:
            fft_period = None
            fft_score = 0.0

        # dominant_period: prefer FFT-derived value; fall back to median
        dominant_period = (
            fft_period if fft_period is not None else (median if median > 0 else None)
        )

        # ---- Sample-count penalty (applied to both components) ----------
        # Linear ramp-up: score → 0 at n=4, unchanged at n≥20.
        sample_factor = min(1.0, max(0.0, (n - 4) / (20 - 4))) if n < 20 else 1.0

        # Final: take the stronger of the two components, then penalise.
        periodicity_score = max(fft_score, consistency_score) * sample_factor

        is_periodic = periodicity_score >= self.config.periodicity_threshold

        return PeriodicityResult(
            is_periodic=is_periodic,
            dominant_period=dominant_period,
            periodicity_score=periodicity_score,
            frequency_peaks=top_peaks,
        )

    def _calculate_jitter_score(
        self, jitter: float, interval_median: float = 0.0
    ) -> float:
        """Piecewise: 1.0 at zero jitter, ~0.5 at threshold, exponential decay beyond.

        The effective threshold is the larger of the configured absolute threshold and
        5% of the median interval.  This prevents long-period beacons (e.g. 300s with
        ±15s jitter) from being penalised by a threshold calibrated for 60s beacons.
        """
        if jitter <= 0:
            return 1.0
        relative_floor = interval_median * 0.05 if interval_median > 0 else 0.0
        threshold = max(self.config.jitter_threshold, relative_floor)
        if jitter <= threshold:
            return 1.0 - (jitter / threshold) * 0.5
        return max(0.0, 0.5 * math.exp(-(jitter - threshold) / threshold))

    def _calculate_size_score(self, packet_sizes: List[int]) -> float:
        """Coefficient-of-variation of packet sizes.

        Beacons typically use uniform packet sizes (low CV → high score).
        Returns 0.5 as a neutral score when fewer than 5 samples are available.
        """
        if len(packet_sizes) < 5:
            return 0.5

        arr = np.array(packet_sizes, dtype=float)
        mean = float(np.mean(arr))
        if mean <= 0:
            return 0.5

        cv = float(np.std(arr)) / mean
        # Reuse the same sigmoid as the interval CV scorer, with a slightly
        # looser threshold since packet sizes vary more than intervals.
        threshold = 0.25
        k = 10.0 / threshold
        return 1.0 / (1.0 + math.exp(k * (cv - threshold)))

    # ------------------------------------------------------------------
    # Confidence determination
    # ------------------------------------------------------------------

    def _determine_confidence(
        self,
        combined_score: float,
        cv_score: float,
        periodicity_score: float,
        jitter_score: float,
        size_score: float = 0.5,
    ) -> BeaconConfidence:
        # Thresholds match the user-facing severity ladder shown in the README
        # and used by control_plane.cli.format_severity.
        if combined_score < 0.3:
            return BeaconConfidence.NONE
        elif combined_score < 0.7:
            return BeaconConfidence.LOW
        elif combined_score < 0.8:
            return BeaconConfidence.MEDIUM
        elif combined_score < 0.9:
            return BeaconConfidence.HIGH
        else:
            return BeaconConfidence.CRITICAL

    # ------------------------------------------------------------------
    # Analyst-facing explanation
    # ------------------------------------------------------------------

    def _build_explanation(
        self,
        interval_stats: IntervalStats,
        periodicity_result: PeriodicityResult,
        cv_score: float,
        jitter_score: float,
        size_score: float,
        windowed_sizes: List[int],
        sample_count: int,
    ) -> Dict:

        size_cv = None
        if len(windowed_sizes) >= 5:
            arr = np.array(windowed_sizes, dtype=float)
            mean = float(np.mean(arr))
            size_cv = round(float(np.std(arr)) / mean, 4) if mean > 0 else None

        signals = [
            {
                "name": "cv",
                "score": round(cv_score, 4),
                "weight": self.config.cv_weight,
                "contribution": round(self.config.cv_weight * cv_score, 4),
                "raw_value": round(interval_stats.cv, 4),
                "threshold": self.config.cv_threshold,
            },
            {
                "name": "periodicity",
                "score": round(periodicity_result.periodicity_score, 4),
                "weight": self.config.periodicity_weight,
                "contribution": round(
                    self.config.periodicity_weight
                    * periodicity_result.periodicity_score,
                    4,
                ),
                "raw_value": round(periodicity_result.periodicity_score, 4),
                "threshold": self.config.periodicity_threshold,
            },
            {
                "name": "jitter",
                "score": round(jitter_score, 4),
                "weight": self.config.jitter_weight,
                "contribution": round(self.config.jitter_weight * jitter_score, 4),
                "raw_value": round(interval_stats.jitter, 3),
                "threshold": round(
                    max(self.config.jitter_threshold, interval_stats.median * 0.05), 3
                ),
            },
            {
                "name": "packet_size_consistency",
                "score": round(size_score, 4),
                "weight": self.config.size_weight,
                "contribution": round(self.config.size_weight * size_score, 4),
                "raw_value": size_cv,
                "threshold": 0.25,
            },
        ]

        return {
            "detected_interval_seconds": round(interval_stats.median, 2),
            "interval_mean_seconds": round(interval_stats.mean, 2),
            "interval_std_seconds": round(interval_stats.std_dev, 2),
            "dominant_fft_period_seconds": (
                round(periodicity_result.dominant_period, 2)
                if periodicity_result.dominant_period
                else None
            ),
            "jitter_seconds": round(interval_stats.jitter, 2),
            "packet_size_cv": size_cv,
            "sample_count": sample_count,
            "observation_window_seconds": self.config.time_window,
            "contributing_signals": signals,
            "signals_above_threshold": [
                s["name"] for s in signals if s["score"] >= 0.7
            ],
        }

    # ------------------------------------------------------------------
    # Batch helpers
    # ------------------------------------------------------------------

    def _prefilter(self, pair: ConnectionPair) -> bool:
        """Fast pre-checks applied before full FFT scoring.

        Returns False when the pair can be discarded without any heavy
        computation — skipping numpy allocation, bisect, and FFT entirely.

        Checks (in order of cheapness):
        1. Raw connection count below minimum.
        2. Total observation span shorter than one beacon interval (no valid
           intervals can exist in the beacon range).
        3. Rough mean interval far above max_beacon_interval (too slow to be
           a beacon within the configured window).
        """
        if pair.connection_count < self.config.min_connections:
            return False

        if pair.first_seen is not None and pair.last_seen is not None:
            span = pair.last_seen - pair.first_seen
            # No interval can be >= min_beacon_interval if the whole span is shorter
            if span < self.config.min_beacon_interval:
                logger.debug(
                    f"Pre-filter: {pair.pair_key} span={span:.1f}s < "
                    f"min_beacon_interval={self.config.min_beacon_interval}s"
                )
                return False
            # Rough mean interval: if clearly above max, skip
            if pair.connection_count > 1:
                rough_interval = span / (pair.connection_count - 1)
                if rough_interval > self.config.max_beacon_interval * 2:
                    logger.debug(
                        f"Pre-filter: {pair.pair_key} rough_interval={rough_interval:.1f}s "
                        f"> 2×max_beacon_interval={self.config.max_beacon_interval}s"
                    )
                    return False

        return True

    def batch_analyze(self, pairs: List[ConnectionPair]) -> List[DetectionResult]:

        results = []
        for pair in pairs:
            try:
                if not self._prefilter(pair):
                    continue
                result = self.analyze(pair)
                if result is not None:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing {pair.pair_key}: {e}")

        results.sort(key=lambda r: r.combined_score, reverse=True)
        return results

    def get_beacons(self, pairs: List[ConnectionPair]) -> List[DetectionResult]:

        return [r for r in self.batch_analyze(pairs) if r.is_beacon]
