import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .alerter import Alert, AlertManager, AlertSeverity
from .detector import BeaconDetector, DetectionResult
from .storage import ConnectionPair, ConnectionStorage

logger = logging.getLogger("beacon_detect.control_plane.analyzer")


@dataclass
class BenignPattern:
    """A known-benign periodic traffic pattern.

    A pair is suppressed when dst_port matches (and protocol matches if set).
    The suppression is logged with the label so analysts can audit the decision.
    """

    dst_port: int
    protocol: Optional[str] = None  # "TCP", "UDP", or None (matches both)
    label: str = "benign"

    def matches(self, pair: ConnectionPair) -> bool:
        if pair.dst_port != self.dst_port:
            return False
        if self.protocol is not None and pair.protocol.upper() != self.protocol.upper():
            return False
        return True


# Default benign baseline applied when benign_baseline.enabled is true
# and no custom patterns are configured.
DEFAULT_BENIGN_PATTERNS: List[BenignPattern] = [
    BenignPattern(dst_port=123, protocol="UDP", label="NTP"),
]


@dataclass
class AnalyzerConfig:

    analysis_interval: int = 60
    min_connections: int = 10
    min_duration: float = 300.0
    alert_cooldown: int = 300
    max_pairs_per_run: int = 10000

    # Benign traffic suppression
    benign_baseline_enabled: bool = True
    benign_patterns: List[BenignPattern] = field(default_factory=list)

    def get_effective_benign_patterns(self) -> List[BenignPattern]:
        """Return user-configured patterns, falling back to defaults."""
        if not self.benign_baseline_enabled:
            return []
        return self.benign_patterns if self.benign_patterns else DEFAULT_BENIGN_PATTERNS


class AnalysisRun:

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.start_time = datetime.now(timezone.utc)
        self.end_time = None
        self.pairs_analyzed = 0
        self.pairs_suppressed = 0
        self.beacons_detected = 0
        self.alerts_generated = 0
        self.errors = 0
        self.results: List[DetectionResult] = []

    def complete(self):
        self.end_time = datetime.now(timezone.utc)

    @property
    def duration_seconds(self):
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()

    def to_dict(self):
        return {
            "run_id": str(self.run_id),
            "start_time": self.start_time.isoformat() + "Z",
            "end_time": self.end_time.isoformat() + "Z" if self.end_time else None,
            "duration_seconds": float(round(self.duration_seconds, 2)),
            "pairs_analyzed": int(self.pairs_analyzed),
            "pairs_suppressed": int(self.pairs_suppressed),
            "beacons_detected": int(self.beacons_detected),
            "alerts_generated": int(self.alerts_generated),
            "errors": int(self.errors),
        }


class ConnectionAnalyzer:

    def __init__(
        self,
        storage: ConnectionStorage,
        detector: BeaconDetector,
        alert_manager: AlertManager,
        config=None,
    ):
        self.storage = storage
        self.detector = detector
        self.alert_manager = alert_manager
        self.config = config or AnalyzerConfig()

        self._lock = threading.RLock()
        self._alert_cooldowns: Dict[str, float] = {}
        self._known_beacons: Dict[str, DetectionResult] = {}
        self._run_history: List[AnalysisRun] = []
        self._max_run_history = 100

        self._running = False
        self._analysis_thread = None
        self._stop_event = threading.Event()

        self._total_runs = 0
        self._total_beacons_detected = 0
        self._total_alerts_generated = 0
        self._total_suppressed = 0

        self._run_counter = 0

        logger.info(
            f"ConnectionAnalyzer initialized: interval={self.config.analysis_interval}s"
        )

    def start(self):

        if self._running:
            logger.warning("Analyzer already running")
            return

        self._running = True
        self._stop_event.clear()

        self._analysis_thread = threading.Thread(
            target=self._analysis_loop, daemon=True
        )
        self._analysis_thread.start()
        logger.info("ConnectionAnalyzer started")

    def stop(self):

        self._running = False
        self._stop_event.set()

        if self._analysis_thread:
            self._analysis_thread.join(timeout=10)

        logger.info("ConnectionAnalyzer stopped")

    def _analysis_loop(self):

        logger.info("Analysis loop started")

        while not self._stop_event.wait(timeout=self.config.analysis_interval):
            try:
                self.run_analysis()
            except Exception as e:
                logger.error(f"Analysis run failed: {e}", exc_info=True)

        logger.info("Analysis loop stopped")

    # ------------------------------------------------------------------
    # Benign traffic suppression
    # ------------------------------------------------------------------

    def _get_suppression_reason(self, pair: ConnectionPair) -> Optional[str]:
        """Return a human-readable suppression label if this pair matches a
        benign baseline pattern, or None if it should be analyzed normally."""
        for pattern in self.config.get_effective_benign_patterns():
            if pattern.matches(pair):
                return pattern.label
        return None

    # ------------------------------------------------------------------
    # Main analysis run
    # ------------------------------------------------------------------

    def run_analysis(self) -> AnalysisRun:

        self._run_counter += 1
        run_id = f"run-{self._run_counter}-{int(time.time())}"
        run = AnalysisRun(run_id)

        logger.info(f"Starting analysis run: {run_id}")

        try:
            pairs = self.storage.get_analyzable_pairs(
                min_connections=self.config.min_connections,
                min_duration=self.config.min_duration,
            )

            if len(pairs) > self.config.max_pairs_per_run:
                logger.warning(
                    f"Limiting analysis to {self.config.max_pairs_per_run} "
                    f"pairs (total: {len(pairs)})"
                )
                pairs.sort(key=lambda p: p.connection_count, reverse=True)
                pairs = pairs[: self.config.max_pairs_per_run]

            # Stage 1: candidate filter — suppress known-benign patterns
            candidates = []
            for pair in pairs:
                reason = self._get_suppression_reason(pair)
                if reason:
                    run.pairs_suppressed += 1
                    logger.debug(
                        f"Suppressed {pair.pair_key}: matched benign pattern '{reason}'"
                    )
                else:
                    candidates.append(pair)

            run.pairs_analyzed = len(candidates)
            logger.info(
                f"Analyzing {len(candidates)} pairs "
                f"({run.pairs_suppressed} suppressed by benign baseline)"
            )

            # Stage 2: full scoring
            results = self.detector.batch_analyze(candidates)
            run.results = results

            beacons = [r for r in results if r.is_beacon]
            run.beacons_detected = len(beacons)

            logger.info(f"Detection complete: {len(beacons)} beacons found")

            for result in beacons:
                try:
                    if self._should_alert(result):
                        self._generate_alert(result)
                        run.alerts_generated += 1
                        with self._lock:
                            self._alert_cooldowns[result.pair_key] = time.time()

                    with self._lock:
                        self._known_beacons[result.pair_key] = result

                except Exception as e:
                    logger.error(f"Error generating alert for {result.pair_key}: {e}")
                    run.errors += 1

            # Evict pairs that are no longer scored as beacons
            with self._lock:
                current_beacon_keys = {r.pair_key for r in beacons}
                stale_keys = [
                    k for k in self._known_beacons if k not in current_beacon_keys
                ]
                for key in stale_keys:
                    del self._known_beacons[key]

        except Exception as e:
            logger.error(f"Analysis run error: {e}", exc_info=True)
            run.errors += 1

        run.complete()

        self._total_runs += 1
        self._total_beacons_detected += run.beacons_detected
        self._total_alerts_generated += run.alerts_generated
        self._total_suppressed += run.pairs_suppressed

        self._run_history.append(run)
        if len(self._run_history) > self._max_run_history:
            self._run_history = self._run_history[-self._max_run_history :]

        logger.info(
            f"Analysis run complete: {run_id} — "
            f"{run.pairs_analyzed} analyzed, {run.pairs_suppressed} suppressed, "
            f"{run.beacons_detected} beacons, {run.alerts_generated} alerts, "
            f"{run.duration_seconds:.2f}s"
        )

        return run

    # ------------------------------------------------------------------
    # Alert gating
    # ------------------------------------------------------------------

    def _should_alert(self, result: DetectionResult) -> bool:

        pair_key = result.pair_key

        with self._lock:
            last_alert = self._alert_cooldowns.get(pair_key, 0)
            if time.time() - last_alert < self.config.alert_cooldown:
                logger.debug(f"Skipping alert for {pair_key}: cooldown active")
                return False

            previous = self._known_beacons.get(pair_key)
            if previous is None:
                return True

            if result.combined_score - previous.combined_score > 0.1:
                return True

            conf_order = ["none", "low", "medium", "high", "critical"]
            if conf_order.index(result.confidence.value) > conf_order.index(
                previous.confidence.value
            ):
                return True

            return False

    def _generate_alert(self, result: DetectionResult):

        severity_map = {
            "none": AlertSeverity.INFO,
            "low": AlertSeverity.LOW,
            "medium": AlertSeverity.MEDIUM,
            "high": AlertSeverity.HIGH,
            "critical": AlertSeverity.CRITICAL,
        }
        severity = severity_map.get(result.confidence.value, AlertSeverity.MEDIUM)

        explanation = result.explanation
        interval_s = explanation.get("detected_interval_seconds", "?")
        fft_period = explanation.get("dominant_fft_period_seconds")
        fft_str = f", FFT period {fft_period}s" if fft_period else ""

        alert = Alert(
            alert_id=f"beacon-{result.pair_key}-{int(time.time())}",
            title=f"Beaconing Detected: {result.src_ip} -> {result.dst_ip}:{result.dst_port}",
            description=(
                f"Potential beaconing between {result.src_ip} and "
                f"{result.dst_ip}:{result.dst_port}/{result.protocol}. "
                f"Confidence: {result.confidence.value.upper()}. "
                f"Score: {result.combined_score:.3f}. "
                f"Interval: ~{interval_s}s{fft_str}. "
                f"{result.connection_count} connections over "
                f"{result.duration_seconds / 60:.1f} min."
            ),
            severity=severity,
            source="beacon_detector",
            details=result.to_dict(),
        )

        self.alert_manager.send_alert(alert)

        logger.warning(
            f"Alert generated: {alert.alert_id} — "
            f"{result.pair_key} (score={result.combined_score:.3f})"
        )

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    def get_known_beacons(self) -> List[DetectionResult]:
        with self._lock:
            return list(self._known_beacons.values())

    def get_run_history(self, limit: int = 10) -> List[dict]:
        runs = self._run_history[-limit:]
        return [r.to_dict() for r in reversed(runs)]

    @property
    def statistics(self) -> dict:
        return {
            "running": self._running,
            "analysis_interval": self.config.analysis_interval,
            "total_runs": self._total_runs,
            "total_beacons_detected": self._total_beacons_detected,
            "total_alerts_generated": self._total_alerts_generated,
            "total_suppressed": self._total_suppressed,
            "current_known_beacons": len(self._known_beacons),
            "active_cooldowns": len(self._alert_cooldowns),
            "benign_baseline_enabled": self.config.benign_baseline_enabled,
            "benign_pattern_count": len(self.config.get_effective_benign_patterns()),
        }
