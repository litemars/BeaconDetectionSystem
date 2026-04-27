import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.alerter import Alert, AlertManager, AlertSeverity
from control_plane.detector import (
    BeaconConfidence,
    DetectionResult,
    IntervalStats,
    PeriodicityResult,
)
from control_plane.persistence import PersistenceConfig, SQLiteStore


@pytest.fixture
def db_store(tmp_path):
    """Create a temporary SQLiteStore for testing."""
    db_path = str(tmp_path / "test.db")
    store = SQLiteStore(PersistenceConfig(db_path=db_path))
    store.open()
    yield store
    store.close()


def _make_alert_dict(alert_id="test-alert-1", severity="high"):
    return {
        "alert_id": alert_id,
        "title": "Beacon Detected",
        "description": "Beaconing from 192.168.1.100 to 10.0.0.1:443",
        "severity": severity,
        "source": "beacon_detector",
        "details": {"score": 0.85, "pair_key": "192.168.1.100->10.0.0.1:443/TCP"},
        "timestamp": "2024-01-01T00:00:00Z",
        "tags": ["beacon", "tcp"],
    }


def _make_detection_result():
    return DetectionResult(
        pair_key="192.168.1.100->10.0.0.1:443/TCP",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        dst_port=443,
        protocol="TCP",
        cv_score=0.9,
        periodicity_score=0.85,
        jitter_score=0.8,
        combined_score=0.87,
        is_beacon=True,
        confidence=BeaconConfidence.HIGH,
        interval_stats=IntervalStats(
            count=20,
            mean=60.0,
            std_dev=2.0,
            cv=0.033,
            median=60.0,
            min_interval=58.0,
            max_interval=62.0,
            jitter=2.0,
        ),
        periodicity_result=PeriodicityResult(
            is_periodic=True,
            dominant_period=60.0,
            periodicity_score=0.85,
            frequency_peaks=[(0.0167, 0.95)],
        ),
        connection_count=20,
        duration_seconds=1140.0,
        first_seen="2024-01-01T00:00:00Z",
        last_seen="2024-01-01T00:19:00Z",
    )


class TestAlertPersistence:

    def test_save_and_load_alert(self, db_store):

        alert_dict = _make_alert_dict()
        db_store.save_alert(alert_dict)

        alerts = db_store.load_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "test-alert-1"
        assert alerts[0]["severity"] == "high"
        assert alerts[0]["details"]["score"] == 0.85
        assert alerts[0]["tags"] == ["beacon", "tcp"]

    def test_alert_deduplication(self, db_store):

        alert_dict = _make_alert_dict()
        db_store.save_alert(alert_dict)
        db_store.save_alert(alert_dict)

        assert db_store.get_alert_count() == 1

    def test_multiple_alerts(self, db_store):

        for i in range(5):
            db_store.save_alert(_make_alert_dict(alert_id=f"alert-{i}"))

        alerts = db_store.load_alerts()
        assert len(alerts) == 5

    def test_load_alerts_limit(self, db_store):

        for i in range(10):
            db_store.save_alert(
                _make_alert_dict(
                    alert_id=f"alert-{i}",
                )
            )

        alerts = db_store.load_alerts(limit=3)
        assert len(alerts) == 3

    def test_load_empty_alerts(self, db_store):

        alerts = db_store.load_alerts()
        assert len(alerts) == 0
        assert db_store.get_alert_count() == 0


class TestBeaconPersistence:

    def test_save_and_load_beacon(self, db_store):

        result = _make_detection_result()
        db_store.save_beacon(result.pair_key, result.to_dict())

        beacons = db_store.load_beacons()
        assert len(beacons) == 1
        assert result.pair_key in beacons

        loaded = beacons[result.pair_key]
        assert loaded["combined_score"] == 0.87
        assert loaded["is_beacon"] is True

    def test_beacon_first_detected_preserved(self, db_store):

        result = _make_detection_result()
        db_store.save_beacon(result.pair_key, result.to_dict())

        # Load to check first_detected
        cursor = db_store._conn.execute(
            "SELECT first_detected FROM beacons WHERE pair_key = ?",
            (result.pair_key,),
        )
        first_detected_original = cursor.fetchone()["first_detected"]

        # Save again (update)
        time.sleep(0.01)
        db_store.save_beacon(result.pair_key, result.to_dict())

        cursor = db_store._conn.execute(
            "SELECT first_detected, last_updated FROM beacons WHERE pair_key = ?",
            (result.pair_key,),
        )
        row = cursor.fetchone()
        assert row["first_detected"] == first_detected_original

    def test_remove_beacon(self, db_store):

        result = _make_detection_result()
        db_store.save_beacon(result.pair_key, result.to_dict())
        assert db_store.get_beacon_count() == 1

        db_store.remove_beacon(result.pair_key)
        assert db_store.get_beacon_count() == 0

    def test_load_empty_beacons(self, db_store):

        beacons = db_store.load_beacons()
        assert len(beacons) == 0


class TestDetectionResultRoundtrip:

    def test_to_dict_from_dict(self):

        original = _make_detection_result()
        d = original.to_dict()
        restored = DetectionResult.from_dict(d)

        assert restored.pair_key == original.pair_key
        assert restored.src_ip == original.src_ip
        assert restored.dst_ip == original.dst_ip
        assert restored.dst_port == original.dst_port
        assert restored.combined_score == pytest.approx(original.combined_score, abs=0.001)
        assert restored.is_beacon == original.is_beacon
        assert restored.confidence == original.confidence
        assert restored.interval_stats.mean == pytest.approx(original.interval_stats.mean)
        assert restored.periodicity_result.is_periodic == original.periodicity_result.is_periodic

    def test_roundtrip_via_persistence(self, db_store):

        original = _make_detection_result()
        db_store.save_beacon(original.pair_key, original.to_dict())

        beacons = db_store.load_beacons()
        restored = DetectionResult.from_dict(beacons[original.pair_key])

        assert restored.pair_key == original.pair_key
        assert restored.combined_score == pytest.approx(original.combined_score, abs=0.001)
        assert restored.confidence == original.confidence


class TestAlertRoundtrip:

    def test_to_dict_from_dict(self):

        original = Alert(
            alert_id="test-1",
            title="Test Alert",
            description="Testing roundtrip",
            severity=AlertSeverity.HIGH,
            source="test",
            details={"key": "value"},
            tags=["tag1", "tag2"],
        )

        d = original.to_dict()
        restored = Alert.from_dict(d)

        assert restored.alert_id == original.alert_id
        assert restored.title == original.title
        assert restored.severity == original.severity
        assert restored.details == original.details
        assert restored.tags == original.tags

    def test_roundtrip_via_persistence(self, db_store):

        original = Alert(
            alert_id="test-persist",
            title="Persisted Alert",
            description="Testing persistence roundtrip",
            severity=AlertSeverity.CRITICAL,
            source="beacon_detector",
            details={"score": 0.95},
            tags=["critical"],
        )

        db_store.save_alert(original.to_dict())
        loaded = db_store.load_alerts()
        restored = Alert.from_dict(loaded[0])

        assert restored.alert_id == original.alert_id
        assert restored.severity == original.severity
        assert restored.details == {"score": 0.95}


class TestAlertManagerWithPersistence:

    def test_deliver_persists_alert(self, db_store):

        manager = AlertManager(persistence=db_store)
        alert = Alert(
            alert_id="persist-test",
            title="Test",
            description="Test alert",
            severity=AlertSeverity.MEDIUM,
            source="test",
        )

        manager._deliver_alert(alert)

        assert db_store.get_alert_count() == 1
        loaded = db_store.load_alerts()
        assert loaded[0]["alert_id"] == "persist-test"

    def test_load_historical_alerts(self, db_store):

        # Pre-populate DB
        for i in range(3):
            db_store.save_alert(_make_alert_dict(alert_id=f"historical-{i}"))

        manager = AlertManager(persistence=db_store)
        manager.load_historical_alerts()

        assert len(manager._recent_alerts) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
