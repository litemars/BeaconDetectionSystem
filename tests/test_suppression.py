"""Tests for benign traffic suppression (stage-1 candidate filtering).

Verifies that:
- Known-benign pairs (NTP, DNS, OCSP-like) are suppressed at stage 1 and never
  reach the FFT scorer (pairs_analyzed == 0).
- Beacon pairs on non-suppressed ports reach the scorer (pairs_analyzed >= 1).
- Suppression is a no-op when benign_baseline_enabled is False.

Run with: pytest tests/test_suppression.py -v
"""

import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.analyzer import (
    AnalyzerConfig,
    BenignPattern,
    ConnectionAnalyzer,
    DEFAULT_BENIGN_PATTERNS,
)
from control_plane.detector import BeaconDetector, DetectorConfig
from control_plane.storage import ConnectionPair, ConnectionRecord, ConnectionStorage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_storage(src_ip, dst_ip, dst_port, protocol, n=20, interval_s=60.0):
    """Return a ConnectionStorage pre-loaded with a single periodic pair."""
    storage = ConnectionStorage(retention_seconds=86400)
    proto_name = "TCP" if protocol == 6 else "UDP"
    base = time.time()
    for i in range(n):
        rec = ConnectionRecord(
            timestamp_ns=int((base + i * interval_s) * 1e9),
            timestamp_utc=f"2024-01-01T{i // 60:02d}:{i % 60:02d}:00Z",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=12345,
            dst_port=dst_port,
            packet_size=128,
            protocol=protocol,
            protocol_name=proto_name,
            tcp_flags=0,
            direction=1,
            node_id="test",
            connection_key=f"{src_ip}:12345->{dst_ip}:{dst_port}/{proto_name}",
        )
        # timestamp_epoch is computed from timestamp_utc by __post_init__;
        # override with the wall-clock-relative value so duration filters pass.
        rec.timestamp_epoch = base + i * interval_s
        storage.add_record(rec)
    return storage


def _make_analyzer(storage, patterns, enabled=True):
    detector = BeaconDetector(DetectorConfig(min_connections=5, alert_threshold=0.5))
    alert_stub = Mock()
    alert_stub.config.enabled = False
    return ConnectionAnalyzer(
        storage=storage,
        detector=detector,
        alert_manager=alert_stub,
        config=AnalyzerConfig(
            min_connections=5,
            min_duration=0,
            benign_baseline_enabled=enabled,
            benign_patterns=patterns,
        ),
    )


# ---------------------------------------------------------------------------
# BenignPattern unit tests
# ---------------------------------------------------------------------------


class TestBenignPatternMatching:

    def test_ntp_matches_udp_123(self):
        pat = BenignPattern(dst_port=123, protocol="UDP", label="NTP")
        pair = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="192.0.2.1", dst_port=123, protocol="UDP"
        )
        assert pat.matches(pair)

    def test_ntp_does_not_match_tcp_123(self):
        pat = BenignPattern(dst_port=123, protocol="UDP", label="NTP")
        pair = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="192.0.2.1", dst_port=123, protocol="TCP"
        )
        assert not pat.matches(pair)

    def test_port_only_matches_both_protocols(self):
        """A pattern without a protocol constraint matches TCP and UDP alike."""
        pat = BenignPattern(dst_port=53, label="DNS")
        udp = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=53, protocol="UDP"
        )
        tcp = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=53, protocol="TCP"
        )
        assert pat.matches(udp)
        assert pat.matches(tcp)

    def test_different_port_no_match(self):
        pat = BenignPattern(dst_port=123, protocol="UDP", label="NTP")
        pair = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, protocol="UDP"
        )
        assert not pat.matches(pair)

    def test_protocol_comparison_is_case_insensitive(self):
        pat = BenignPattern(dst_port=123, protocol="udp", label="NTP")
        pair = ConnectionPair(
            src_ip="10.0.0.1", dst_ip="192.0.2.1", dst_port=123, protocol="UDP"
        )
        assert pat.matches(pair)

    def test_default_patterns_include_ntp(self):
        ntp_patterns = [p for p in DEFAULT_BENIGN_PATTERNS if p.dst_port == 123]
        assert len(ntp_patterns) >= 1


# ---------------------------------------------------------------------------
# Stage-1 suppression integration
# ---------------------------------------------------------------------------


class TestStage1Suppression:

    def test_ntp_suppressed_before_fft_scorer(self):
        """NTP (UDP/123) at ~64s intervals: pairs_suppressed=1, pairs_analyzed=0.

        This is the primary DoD check: port-123/UDP pairs must never reach FFT.
        """
        storage = _make_storage("10.0.0.5", "192.0.2.1", 123, 17, n=20, interval_s=64.0)
        analyzer = _make_analyzer(
            storage,
            [BenignPattern(dst_port=123, protocol="UDP", label="NTP")],
        )
        run = analyzer.run_analysis()
        assert (
            run.pairs_suppressed == 1
        ), f"Expected 1 suppressed pair, got {run.pairs_suppressed}"
        assert run.pairs_analyzed == 0, (
            f"NTP pair must not reach the FFT scorer (got pairs_analyzed="
            f"{run.pairs_analyzed})"
        )

    def test_dns_udp_suppressed_when_configured(self):
        """DNS (UDP/53) is suppressed when that pattern is explicitly configured."""
        storage = _make_storage("10.0.0.5", "8.8.8.8", 53, 17, n=20)
        analyzer = _make_analyzer(
            storage,
            [BenignPattern(dst_port=53, protocol="UDP", label="DNS-UDP")],
        )
        run = analyzer.run_analysis()
        assert run.pairs_suppressed == 1
        assert run.pairs_analyzed == 0

    def test_dns_tcp_suppressed_when_configured(self):
        """DNS over TCP (TCP/53) is suppressed by a protocol-specific pattern."""
        storage = _make_storage("10.0.0.5", "8.8.8.8", 53, 6, n=20)
        analyzer = _make_analyzer(
            storage,
            [BenignPattern(dst_port=53, protocol="TCP", label="DNS-TCP")],
        )
        run = analyzer.run_analysis()
        assert run.pairs_suppressed == 1
        assert run.pairs_analyzed == 0

    def test_ocsp_http_suppressed_when_configured(self):
        """OCSP/CRL over TCP/80 is suppressed when that pattern is configured."""
        storage = _make_storage("10.0.0.5", "192.0.2.100", 80, 6, n=20)
        analyzer = _make_analyzer(
            storage,
            [BenignPattern(dst_port=80, protocol="TCP", label="OCSP-HTTP")],
        )
        run = analyzer.run_analysis()
        assert run.pairs_suppressed == 1
        assert run.pairs_analyzed == 0

    def test_beacon_tcp_443_not_suppressed(self):
        """A beacon on TCP/443 is NOT suppressed when only NTP is in the list."""
        storage = _make_storage("10.10.1.50", "203.0.113.99", 443, 6, n=20)
        analyzer = _make_analyzer(
            storage,
            [BenignPattern(dst_port=123, protocol="UDP", label="NTP")],
        )
        run = analyzer.run_analysis()
        assert run.pairs_suppressed == 0
        assert run.pairs_analyzed >= 1

    def test_beacon_on_custom_port_not_suppressed(self):
        """A beacon on TCP/8443 is not suppressed when no matching pattern exists."""
        storage = _make_storage("10.10.1.50", "198.51.100.10", 8443, 6, n=20)
        analyzer = _make_analyzer(
            storage,
            [BenignPattern(dst_port=123, protocol="UDP", label="NTP")],
        )
        run = analyzer.run_analysis()
        assert run.pairs_suppressed == 0

    def test_suppression_disabled_ntp_reaches_scorer(self):
        """When benign_baseline_enabled=False, NTP pairs are not suppressed."""
        storage = _make_storage("10.0.0.5", "192.0.2.1", 123, 17, n=20)
        analyzer = _make_analyzer(storage, [], enabled=False)
        run = analyzer.run_analysis()
        assert run.pairs_suppressed == 0
        # Pair must have reached the scorer (even if it's not flagged as a beacon)
        assert run.pairs_analyzed >= 1

    def test_multiple_patterns_suppress_multiple_pairs(self):
        """Two pairs matching two distinct patterns are both suppressed in one run."""
        storage = ConnectionStorage(retention_seconds=86400)
        base = time.time()

        # NTP-like: UDP/123
        for i in range(20):
            rec = ConnectionRecord(
                timestamp_ns=int((base + i * 64) * 1e9),
                timestamp_utc=f"2024-01-01T{i // 60:02d}:{i % 60:02d}:00Z",
                src_ip="10.0.0.5",
                dst_ip="192.0.2.1",
                src_port=12345,
                dst_port=123,
                packet_size=48,
                protocol=17,
                protocol_name="UDP",
                tcp_flags=0,
                direction=1,
                node_id="test",
                connection_key="10.0.0.5:12345->192.0.2.1:123/UDP",
            )
            rec.timestamp_epoch = base + i * 64
            storage.add_record(rec)

        # DNS-like: UDP/53
        for i in range(20):
            rec = ConnectionRecord(
                timestamp_ns=int((base + i * 30 + 1) * 1e9),
                timestamp_utc=f"2024-01-01T{i // 60:02d}:{i % 60:02d}:30Z",
                src_ip="10.0.0.5",
                dst_ip="8.8.8.8",
                src_port=54321,
                dst_port=53,
                packet_size=64,
                protocol=17,
                protocol_name="UDP",
                tcp_flags=0,
                direction=1,
                node_id="test",
                connection_key="10.0.0.5:54321->8.8.8.8:53/UDP",
            )
            rec.timestamp_epoch = base + i * 30 + 1
            storage.add_record(rec)

        patterns = [
            BenignPattern(dst_port=123, protocol="UDP", label="NTP"),
            BenignPattern(dst_port=53, protocol="UDP", label="DNS-UDP"),
        ]
        detector = BeaconDetector(
            DetectorConfig(min_connections=5, alert_threshold=0.5)
        )
        alert_stub = Mock()
        alert_stub.config.enabled = False
        analyzer = ConnectionAnalyzer(
            storage=storage,
            detector=detector,
            alert_manager=alert_stub,
            config=AnalyzerConfig(
                min_connections=5,
                min_duration=0,
                benign_baseline_enabled=True,
                benign_patterns=patterns,
            ),
        )
        run = analyzer.run_analysis()
        assert run.pairs_suppressed == 2
        assert run.pairs_analyzed == 0


# ---------------------------------------------------------------------------
# Syslog message format
# ---------------------------------------------------------------------------


class TestSyslogSignalFormat:

    def test_syslog_includes_signal_scores_from_details(self):
        """to_syslog_message embeds contributing_signals when present in details."""
        from control_plane.alerter import Alert, AlertSeverity

        signals = [
            {
                "name": "cv",
                "score": 0.92,
                "weight": 0.35,
                "contribution": 0.322,
                "raw_value": 0.04,
                "threshold": 0.15,
            },
            {
                "name": "periodicity",
                "score": 0.81,
                "weight": 0.35,
                "contribution": 0.284,
                "raw_value": 0.81,
                "threshold": 0.7,
            },
            {
                "name": "jitter",
                "score": 0.74,
                "weight": 0.15,
                "contribution": 0.111,
                "raw_value": 3.2,
                "threshold": 5.0,
            },
            {
                "name": "packet_size_consistency",
                "score": 0.98,
                "weight": 0.15,
                "contribution": 0.147,
                "raw_value": 0.02,
                "threshold": 0.25,
            },
        ]
        details = {"explanation": {"contributing_signals": signals}}
        alert = Alert(
            alert_id="test-sig-1",
            title="Beacon Detected",
            description="Test",
            severity=AlertSeverity.HIGH,
            source="beacon_detector",
            details=details,
        )
        msg = alert.to_syslog_message()
        assert "Signals:" in msg
        assert "cv=0.92" in msg
        assert "periodicity=0.81" in msg
        assert "jitter=0.74" in msg
        assert "packet_size_consistency=0.98" in msg

    def test_syslog_graceful_without_signals(self):
        """to_syslog_message works correctly when no contributing_signals are present."""
        from control_plane.alerter import Alert, AlertSeverity

        alert = Alert(
            alert_id="test-nosig",
            title="Beacon Detected",
            description="No signals",
            severity=AlertSeverity.MEDIUM,
            source="beacon_detector",
        )
        msg = alert.to_syslog_message()
        assert "[MEDIUM]" in msg
        assert "Beacon Detected" in msg
        assert "Signals:" not in msg


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
