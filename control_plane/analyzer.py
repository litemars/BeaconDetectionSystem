import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List

from .storage import ConnectionStorage
from .detector import BeaconDetector, DetectionResult
from .alerter import AlertManager, Alert, AlertSeverity

logger = logging.getLogger('beacon_detect.control_plane.analyzer')


@dataclass
class AnalyzerConfig:
    # How often to run analysis (seconds)
    analysis_interval: int = 60
    
    # Minimum connections required for analysis
    min_connections: int = 10
    
    # Minimum duration for a pair to be analyzed
    min_duration: float = 300.0  # 5 minutes
    
    # Alert cooldown - don't re-alert same pair within this time
    alert_cooldown: int = 300  # 5 minutes
    
    # Maximum pairs to analyze per run (for performance)
    max_pairs_per_run: int = 10000


class AnalysisRun:


    def __init__(self, run_id: str):
        self.run_id = run_id
        self.start_time = datetime.now(timezone.utc)
        self.end_time = None
        self.pairs_analyzed = 0
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
            'run_id': str(self.run_id),
            'start_time': self.start_time.isoformat() + 'Z',
            'end_time': self.end_time.isoformat() + 'Z' if self.end_time else None,
            'duration_seconds': float(round(self.duration_seconds, 2)),
            'pairs_analyzed': int(self.pairs_analyzed),
            'beacons_detected': int(self.beacons_detected),
            'alerts_generated': int(self.alerts_generated),
            'errors': int(self.errors)
        }


class ConnectionAnalyzer:

    
    def __init__(
        self,
        storage: ConnectionStorage,
        detector: BeaconDetector,
        alert_manager: AlertManager,
        config = None
    ):
        """
        Initialize the analyzer.
        
        Args:
            storage: ConnectionStorage instance
            detector: BeaconDetector instance
            alert_manager: AlertManager instance
            config: Analyzer configuration
        """
        self.storage = storage
        self.detector = detector
        self.alert_manager = alert_manager
        self.config = config or AnalyzerConfig()
        
        # Thread safety lock for shared state
        self._lock = threading.RLock()
        
        # Track alert cooldowns: pair_key -> last_alert_time
        self._alert_cooldowns: Dict[str, float] = {}
        
        # Track known beacons for monitoring
        self._known_beacons: Dict[str, DetectionResult] = {}
        
        # Analysis run history
        self._run_history: List[AnalysisRun] = []
        self._max_run_history = 100
        
        # Running state
        self._running = False
        self._analysis_thread = None
        self._stop_event = threading.Event()
        
        # Statistics
        self._total_runs = 0
        self._total_beacons_detected = 0
        self._total_alerts_generated = 0
        
        # Run counter for IDs
        self._run_counter = 0
        
        logger.info(f"ConnectionAnalyzer initialized: interval={self.config.analysis_interval}s")
    
    def start(self):

        if self._running:
            logger.warning("Analyzer already running")
            return
        
        self._running = True
        self._stop_event.clear()
        
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True
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
    
    def run_analysis(self):

        self._run_counter += 1
        run_id = f"run-{self._run_counter}-{int(time.time())}"
        run = AnalysisRun(run_id)
        
        logger.info(f"Starting analysis run: {run_id}")
        
        try:
            # logger.info(f"self.config.min_connections {self.config.min_connections} and self.config.min_duration {self.config.min_duration}")
            # Get analyzable pairs from storage
            pairs = self.storage.get_analyzable_pairs(
                min_connections=self.config.min_connections,
                min_duration=self.config.min_duration
            )
            # logger.info(f"pairs{pairs}")
            # Limit pairs for performance
            if len(pairs) > self.config.max_pairs_per_run:
                logger.warning(
                    f"Limiting analysis to {self.config.max_pairs_per_run} "
                    f"pairs (total: {len(pairs)})"
                )
                # Prioritize pairs with more connections
                pairs.sort(key=lambda p: p.connection_count, reverse=True)
                pairs = pairs[:self.config.max_pairs_per_run]
            
            run.pairs_analyzed = len(pairs)
            logger.info(f"Analyzing {len(pairs)} connection pairs")
            
            # Run detection
            results = self.detector.batch_analyze(pairs)
            run.results = results
            
            # Process results
            beacons = [r for r in results if r.is_beacon]
            run.beacons_detected = len(beacons)
            
            logger.info(f"Detection complete: {len(beacons)} beacons found")
            
            # Generate alerts for new/updated beacons
            for result in beacons:
                try:
                    if self._should_alert(result):
                        self._generate_alert(result)
                        run.alerts_generated += 1
                        with self._lock:
                            self._alert_cooldowns[result.pair_key] = time.time()
                    
                    # Update known beacons
                    with self._lock:
                        self._known_beacons[result.pair_key] = result
                    
                except Exception as e:
                    logger.error(f"Error generating alert for {result.pair_key}: {e}")
                    run.errors += 1
            
            # Clean up cooldowns for pairs no longer seen as beacons
            with self._lock:
                current_beacon_keys = {r.pair_key for r in beacons}
                stale_keys = [k for k in self._known_beacons if k not in current_beacon_keys]
                for key in stale_keys:
                    del self._known_beacons[key]
            
        except Exception as e:
            logger.error(f"Analysis run error: {e}", exc_info=True)
            run.errors += 1
        
        run.complete()
        
        # Update statistics
        self._total_runs += 1
        self._total_beacons_detected += run.beacons_detected
        self._total_alerts_generated += run.alerts_generated
        
        # Store run history
        self._run_history.append(run)
        if len(self._run_history) > self._max_run_history:
            self._run_history = self._run_history[-self._max_run_history:]
        
        logger.info(
            f"Analysis run complete: {run_id} - "
            f"{run.pairs_analyzed} pairs, {run.beacons_detected} beacons, "
            f"{run.alerts_generated} alerts, {run.duration_seconds:.2f}s"
        )
        
        return run
    
    def _should_alert(self, result):
        pair_key = result.pair_key
        
        with self._lock:
            # Check cooldown
            last_alert = self._alert_cooldowns.get(pair_key, 0)
            if time.time() - last_alert < self.config.alert_cooldown:
                logger.debug(f"Skipping alert for {pair_key}: cooldown active")
                return False
            
            # Check if this is a new detection or significant change
            previous = self._known_beacons.get(pair_key)
            if previous is None:
                # New beacon
                return True
            
            # Check for significant score increase
            if result.combined_score - previous.combined_score > 0.1:
                return True
            
            # Check for confidence upgrade
            conf_order = ['none', 'low', 'medium', 'high', 'critical']
            if (conf_order.index(result.confidence.value) > 
                conf_order.index(previous.confidence.value)):
                return True
            
            return False
    
    def _generate_alert(self, result):

        # Map confidence to severity
        severity_map = {
            'none': AlertSeverity.INFO,
            'low': AlertSeverity.LOW,
            'medium': AlertSeverity.MEDIUM,
            'high': AlertSeverity.HIGH,
            'critical': AlertSeverity.CRITICAL
        }
        severity = severity_map.get(result.confidence.value, AlertSeverity.MEDIUM)
        
        # Create alert
        alert = Alert(
            alert_id=f"beacon-{result.pair_key}-{int(time.time())}",
            title=f"Beaconing Detected: {result.src_ip} -> {result.dst_ip}:{result.dst_port}",
            description=(
                f"Potential beaconing behavior detected between {result.src_ip} "
                f"and {result.dst_ip}:{result.dst_port}/{result.protocol}. "
                f"Detection confidence: {result.confidence.value.upper()}. "
                f"Combined score: {result.combined_score:.3f}. "
                f"Observed {result.connection_count} connections over "
                f"{result.duration_seconds/60:.1f} minutes."
            ),
            severity=severity,
            source="beacon_detector",
            details=result.to_dict()
        )
        
        # Send alert through alert manager
        self.alert_manager.send_alert(alert)
        
        logger.warning(
            f"Alert generated: {alert.alert_id} - "
            f"{result.pair_key} (score={result.combined_score:.3f})"
        )
    
    def get_known_beacons(self):
        """Get list of known beacons (thread-safe)."""
        with self._lock:
            return list(self._known_beacons.values())
    
    def get_run_history(self, limit: int = 10):
        runs = self._run_history[-limit:]
        return [r.to_dict() for r in reversed(runs)]
    
    @property
    def statistics(self):
        """Get analyzer statistics"""
        return {
            'running': self._running,
            'analysis_interval': self.config.analysis_interval,
            'total_runs': self._total_runs,
            'total_beacons_detected': self._total_beacons_detected,
            'total_alerts_generated': self._total_alerts_generated,
            'current_known_beacons': len(self._known_beacons),
            'active_cooldowns': len(self._alert_cooldowns)
        }
