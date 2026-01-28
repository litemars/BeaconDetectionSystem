import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Tuple

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
    cv: float  # Coefficient of variation
    median: float
    min_interval: float
    max_interval: float
    jitter: float  # Max deviation from median

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
    dominant_period: float  # In seconds
    periodicity_score: float  # 0.0 to 1.0
    frequency_peaks: List[Tuple[float, float]]  # (frequency, magnitude) pairs

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

    # Detection scores (0.0 to 1.0, higher = more beacon-like)
    cv_score: float
    periodicity_score: float
    jitter_score: float
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
        }


@dataclass
class DetectorConfig:

    # Minimum data requirements
    min_connections: int = 10
    time_window: int = 3600  # seconds

    # CV threshold (lower = more regular, beacon-like)
    cv_threshold: float = 0.15

    # Periodicity threshold (higher = more periodic)
    periodicity_threshold: float = 0.7

    # Jitter threshold in seconds (lower = more consistent)
    jitter_threshold: float = 5.0

    # Interval bounds
    min_beacon_interval: float = 10.0  # seconds
    max_beacon_interval: float = 3600.0  # seconds

    # Score weights (should sum to 1.0)
    cv_weight: float = 0.4
    periodicity_weight: float = 0.4
    jitter_weight: float = 0.2

    # Final threshold for beacon classification
    alert_threshold: float = 0.7


class BeaconDetector:

    def __init__(self, config=None):

        self.config = config or DetectorConfig()

        # Validate weights
        total_weight = (
            self.config.cv_weight
            + self.config.periodicity_weight
            + self.config.jitter_weight
        )
        if not 0.99 <= total_weight <= 1.01:
            logger.warning(f"Score weights sum to {total_weight}, should be 1.0")

        logger.info(f"BeaconDetector initialized with config: {self.config}")

    def analyze(self, pair: ConnectionPair):
        # Check minimum data requirements
        if pair.connection_count < self.config.min_connections:
            logger.debug(
                f"Insufficient connections for {pair.pair_key}: "
                f"{pair.connection_count} < {self.config.min_connections}"
            )
            return None

        # Get intervals
        intervals = pair.get_intervals()
        if len(intervals) < self.config.min_connections - 1:
            return None

        # Filter intervals within bounds
        intervals = [
            i
            for i in intervals
            if self.config.min_beacon_interval <= i <= self.config.max_beacon_interval
        ]

        if len(intervals) < self.config.min_connections - 1:
            logger.debug(f"Insufficient valid intervals for {pair.pair_key}")
            return None

        # Calculate interval statistics
        interval_stats = self._calculate_interval_stats(intervals)

        # Calculate CV score (lower CV = higher score)
        cv_score = self._calculate_cv_score(interval_stats.cv)

        # Perform periodicity analysis
        periodicity_result = self._analyze_periodicity(intervals)

        # Calculate jitter score (lower jitter = higher score)
        jitter_score = self._calculate_jitter_score(interval_stats.jitter)
        # logger.info(f"interval {interval_stats}, cv_score {cv_score}, periodicity {periodicity_result}")
        # Calculate combined score
        combined_score = (
            self.config.cv_weight * cv_score
            + self.config.periodicity_weight * periodicity_result.periodicity_score
            + self.config.jitter_weight * jitter_score
        )

        # Determine if beacon
        is_beacon = combined_score >= self.config.alert_threshold

        # Determine confidence level
        confidence = self._determine_confidence(
            combined_score, cv_score, periodicity_result.periodicity_score, jitter_score
        )

        # Create result
        result = DetectionResult(
            pair_key=pair.pair_key,
            src_ip=pair.src_ip,
            dst_ip=pair.dst_ip,
            dst_port=pair.dst_port,
            protocol=pair.protocol,
            cv_score=cv_score,
            periodicity_score=periodicity_result.periodicity_score,
            jitter_score=jitter_score,
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
        )

        if is_beacon:
            logger.warning(
                f"Beacon detected: {pair.pair_key} "
                f"(score={combined_score:.3f}, confidence={confidence.value})"
            )

        return result

    def _calculate_interval_stats(self, intervals):
        arr = np.array(intervals)

        mean = float(np.mean(arr))
        std_dev = float(np.std(arr))
        median = float(np.median(arr))

        # Coefficient of variation
        cv = std_dev / mean if mean > 0 else float("inf")

        # Jitter = maximum deviation from median
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

    def _calculate_cv_score(self, cv: float):

        if cv <= 0:
            return 1.0

        # Sigmoid transformation
        # At cv = threshold, score ≈ 0.5
        # cv << threshold: score → 1.0
        # cv >> threshold: score → 0.0
        threshold = self.config.cv_threshold
        k = 10.0 / threshold  # Steepness factor

        score = 1.0 / (1.0 + math.exp(k * (cv - threshold)))
        return score

    def _analyze_periodicity(self, intervals: List[float]):

        if len(intervals) < 4:
            return PeriodicityResult(
                is_periodic=False,
                dominant_period=None,
                periodicity_score=0.0,
                frequency_peaks=[],
            )

        arr = np.array(intervals)
        n = len(arr)

        # Remove mean (DC component)
        arr_centered = arr - np.mean(arr)

        # Perform FFT
        fft_result = fft.fft(arr_centered)
        frequencies = fft.fftfreq(n, d=np.mean(arr))

        # Get magnitude spectrum (positive frequencies only)
        magnitude = np.abs(fft_result[: n // 2])
        freq_positive = frequencies[: n // 2]

        # Normalize magnitude
        magnitude_norm = magnitude / (np.sum(magnitude) + 1e-10)

        # Find peaks
        peaks = []
        for i in range(1, len(magnitude) - 1):
            if magnitude[i] > magnitude[i - 1] and magnitude[i] > magnitude[i + 1]:
                if freq_positive[i] > 0:  # Skip DC
                    peaks.append((freq_positive[i], magnitude_norm[i]))

        # Sort peaks by magnitude
        peaks.sort(key=lambda x: x[1], reverse=True)
        top_peaks = peaks[:5]

        # Calculate periodicity score
        # Based on how dominant the main frequency is
        if len(top_peaks) > 0:
            dominant_magnitude = top_peaks[0][1]
            dominant_freq = top_peaks[0][0]
            dominant_period = 1.0 / dominant_freq if dominant_freq > 0 else None

            # Score is based on dominance of primary frequency
            # A strong single frequency indicates regular periodicity
            if len(top_peaks) > 1:
                # Ratio of dominant to second peak
                ratio = dominant_magnitude / (top_peaks[1][1] + 1e-10)
                periodicity_score = min(1.0, dominant_magnitude * ratio)
            else:
                periodicity_score = dominant_magnitude
        else:
            dominant_period = None
            periodicity_score = 0.0

        # Determine if periodic based on threshold
        is_periodic = periodicity_score >= self.config.periodicity_threshold

        return PeriodicityResult(
            is_periodic=is_periodic,
            dominant_period=dominant_period,
            periodicity_score=periodicity_score,
            frequency_peaks=top_peaks,
        )

    def _calculate_jitter_score(self, jitter: float):

        if jitter <= 0:
            return 1.0

        threshold = self.config.jitter_threshold

        # Linear scaling with cutoff
        if jitter <= threshold:
            score = 1.0 - (jitter / threshold) * 0.5  # Score 0.5-1.0
        else:
            # Exponential decay beyond threshold
            score = 0.5 * math.exp(-(jitter - threshold) / threshold)

        return max(0.0, min(1.0, score))

    def _determine_confidence(
        self,
        combined_score: float,
        cv_score: float,
        periodicity_score: float,
        jitter_score: float,
    ):

        if combined_score < 0.3:
            return BeaconConfidence.NONE
        elif combined_score < 0.5:
            return BeaconConfidence.LOW
        elif combined_score < 0.7:
            return BeaconConfidence.MEDIUM
        elif combined_score < 0.85:
            return BeaconConfidence.HIGH
        else:
            # Critical requires all three indicators to be strong
            if cv_score > 0.7 and periodicity_score > 0.7 and jitter_score > 0.7:
                return BeaconConfidence.CRITICAL
            return BeaconConfidence.HIGH

    def batch_analyze(self, pairs: List[ConnectionPair]):
        results = []

        for pair in pairs:
            try:
                result = self.analyze(pair)
                if result is not None:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing {pair.pair_key}: {e}")

        # Sort by combined score descending
        results.sort(key=lambda r: r.combined_score, reverse=True)

        return results

    def get_beacons(self, pairs: List[ConnectionPair]):

        all_results = self.batch_analyze(pairs)
        return [r for r in all_results if r.is_beacon]
