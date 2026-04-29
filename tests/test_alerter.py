"""Tests for control_plane/alerter.py.

Covers:
- Alert.to_dict(): all convert_value branches (None, numpy, bool, list, dict, str, int)
- Alert.to_json()
- AlertSeverity.syslog_priority for every severity level
- AlertingConfig dataclass
- AlertManager: constructor, send_alert, send_alert_sync, create_and_send,
  start/stop lifecycle, _deliver_alert, get_recent_alerts with/without filter,
  statistics
- SyslogHandler with syslog disabled (avoids needing /dev/log)
- FileHandler with file disabled
- WebhookHandler with webhook disabled

Run with: pytest tests/test_alerter.py -v
"""

import logging
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.alerter import (
    Alert,
    AlertingConfig,
    AlertManager,
    AlertSeverity,
    FileHandler,
    SyslogHandler,
    WebhookHandler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(severity=AlertSeverity.HIGH, details=None):
    return Alert(
        alert_id="test-001",
        title="Test Alert",
        description="Unit test alert",
        severity=severity,
        source="test",
        details=details or {},
    )


def _disabled_config(**kwargs):
    """AlertingConfig with all channels off (safe for unit tests)."""
    defaults = dict(
        enabled=True,
        syslog_enabled=False,
        file_enabled=False,
        webhook_enabled=False,
    )
    defaults.update(kwargs)
    return AlertingConfig(**defaults)


# ---------------------------------------------------------------------------
# AlertSeverity
# ---------------------------------------------------------------------------

class TestAlertSeverity:

    def test_syslog_priority_info(self):
        assert AlertSeverity.INFO.syslog_priority == logging.INFO

    def test_syslog_priority_low(self):
        assert AlertSeverity.LOW.syslog_priority == logging.WARNING

    def test_syslog_priority_medium(self):
        assert AlertSeverity.MEDIUM.syslog_priority == logging.WARNING

    def test_syslog_priority_high(self):
        assert AlertSeverity.HIGH.syslog_priority == logging.ERROR

    def test_syslog_priority_critical(self):
        assert AlertSeverity.CRITICAL.syslog_priority == logging.CRITICAL

    def test_value_strings(self):
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.INFO.value == "info"


# ---------------------------------------------------------------------------
# Alert.to_dict — convert_value branches
# ---------------------------------------------------------------------------

class TestAlertToDict:

    def test_basic_fields_present(self):
        alert = _make_alert()
        d = alert.to_dict()
        assert d["alert_id"] == "test-001"
        assert d["severity"] == "high"
        assert d["source"] == "test"

    def test_none_value_in_details(self):
        """convert_value(None) must return None without raising."""
        alert = _make_alert(details={"key": None})
        d = alert.to_dict()
        assert d["details"]["key"] is None

    def test_numpy_scalar_in_details(self):
        """Numpy scalars (have .item()) must be converted to Python natives."""
        import numpy as np
        alert = _make_alert(details={"score": np.float64(0.95)})
        d = alert.to_dict()
        # Must be a plain Python float, not a numpy scalar
        assert isinstance(d["details"]["score"], float)
        assert abs(d["details"]["score"] - 0.95) < 1e-9

    def test_bool_value_in_details(self):
        alert = _make_alert(details={"flag": True})
        d = alert.to_dict()
        assert d["details"]["flag"] is True

    def test_list_value_in_details(self):
        alert = _make_alert(details={"items": [1, 2, 3]})
        d = alert.to_dict()
        assert d["details"]["items"] == [1, 2, 3]

    def test_nested_dict_in_details(self):
        alert = _make_alert(details={"outer": {"inner": 42}})
        d = alert.to_dict()
        assert d["details"]["outer"]["inner"] == 42

    def test_string_value_in_details(self):
        alert = _make_alert(details={"msg": "hello"})
        d = alert.to_dict()
        assert d["details"]["msg"] == "hello"

    def test_int_float_values(self):
        alert = _make_alert(details={"count": 10, "rate": 1.5})
        d = alert.to_dict()
        assert d["details"]["count"] == 10
        assert d["details"]["rate"] == 1.5

    def test_tags_serialized(self):
        alert = Alert(
            alert_id="t1", title="T", description="D",
            severity=AlertSeverity.LOW, source="s",
            tags=["c2", "periodic"],
        )
        d = alert.to_dict()
        assert d["tags"] == ["c2", "periodic"]

    def test_to_json_valid(self):
        import json
        alert = _make_alert()
        raw = alert.to_json()
        parsed = json.loads(raw)
        assert parsed["severity"] == "high"

    def test_unknown_type_converted_to_str_or_number(self):
        """convert_value fallback: object whose str() doesn't parse as a number."""

        class _Weird:
            def __str__(self):
                return "weird-value"

        alert = _make_alert(details={"obj": _Weird()})
        d = alert.to_dict()
        # Must not raise; value becomes a string
        assert isinstance(d["details"]["obj"], str)

    def test_unknown_type_without_int_falls_back_to_str(self):
        """convert_value fallback: object with no __int__ is stringified."""

        class _StrOnly:
            def __str__(self):
                return "no-dot-no-int"

        alert = _make_alert(details={"n": _StrOnly()})
        d = alert.to_dict()
        # int(_StrOnly()) raises TypeError → str() fallback is used
        assert d["details"]["n"] == "no-dot-no-int"


# ---------------------------------------------------------------------------
# AlertingConfig
# ---------------------------------------------------------------------------

class TestAlertingConfig:

    def test_default_values(self):
        cfg = AlertingConfig()
        assert cfg.enabled is True
        assert cfg.syslog_enabled is True
        assert cfg.file_enabled is True
        assert cfg.webhook_enabled is False

    def test_custom_values(self):
        cfg = AlertingConfig(enabled=False, webhook_enabled=True, webhook_url="http://x")
        assert cfg.enabled is False
        assert cfg.webhook_url == "http://x"


# ---------------------------------------------------------------------------
# SyslogHandler (disabled mode — no /dev/log needed)
# ---------------------------------------------------------------------------

class TestSyslogHandler:

    def test_disabled_handler_no_logger(self):
        cfg = AlertingConfig(syslog_enabled=False)
        h = SyslogHandler(cfg)
        assert h._logger is None

    def test_disabled_send_noop(self):
        """send() with no logger must not raise."""
        cfg = AlertingConfig(syslog_enabled=False)
        h = SyslogHandler(cfg)
        h.send(_make_alert())  # must not raise


# ---------------------------------------------------------------------------
# FileHandler (disabled mode — no filesystem needed)
# ---------------------------------------------------------------------------

class TestFileHandler:

    def test_disabled_handler_no_logger(self):
        cfg = AlertingConfig(file_enabled=False)
        h = FileHandler(cfg)
        assert h._logger is None

    def test_disabled_send_noop(self):
        cfg = AlertingConfig(file_enabled=False)
        h = FileHandler(cfg)
        h.send(_make_alert())  # must not raise

    def test_file_handler_setup_in_tmp(self, tmp_path):
        """FileHandler can write to a temp directory."""
        cfg = AlertingConfig(
            file_enabled=True,
            syslog_enabled=False,
            webhook_enabled=False,
            file_path=str(tmp_path / "alerts.json"),
        )
        h = FileHandler(cfg)
        assert h._logger is not None
        h.send(_make_alert())
        # File should exist after send
        assert (tmp_path / "alerts.json").exists()


# ---------------------------------------------------------------------------
# WebhookHandler (disabled mode)
# ---------------------------------------------------------------------------

class TestWebhookHandler:

    def test_disabled_no_session(self):
        cfg = AlertingConfig(webhook_enabled=False, webhook_url="")
        h = WebhookHandler(cfg)
        assert h._session is None

    def test_enabled_but_no_url_no_session(self):
        cfg = AlertingConfig(webhook_enabled=True, webhook_url="")
        h = WebhookHandler(cfg)
        assert h._session is None

    def test_send_noop_when_no_session(self):
        cfg = AlertingConfig(webhook_enabled=False)
        h = WebhookHandler(cfg)
        h.send(_make_alert())  # must not raise


# ---------------------------------------------------------------------------
# AlertManager lifecycle and dispatch
# ---------------------------------------------------------------------------

class TestAlertManager:

    def test_constructor_disabled_channels(self):
        """AlertManager initialises without errors when all channels are off."""
        mgr = AlertManager(_disabled_config())
        assert mgr._alerts_sent == 0

    def test_send_alert_queues_when_enabled(self):
        mgr = AlertManager(_disabled_config())
        mgr.start()
        try:
            mgr.send_alert(_make_alert())
            time.sleep(0.05)  # give processor thread time to drain
        finally:
            mgr.stop()
        # Either sent or failed (file/syslog disabled → success path)
        assert mgr._alerts_sent + mgr._alerts_failed >= 1

    def test_send_alert_discarded_when_disabled(self):
        cfg = _disabled_config(enabled=False)
        mgr = AlertManager(cfg)
        mgr.send_alert(_make_alert())
        assert mgr._alert_queue.qsize() == 0

    def test_send_alert_sync_delivers_directly(self):
        mgr = AlertManager(_disabled_config())
        mgr.send_alert_sync(_make_alert())
        assert mgr._alerts_sent == 1

    def test_send_alert_sync_disabled_noop(self):
        cfg = _disabled_config(enabled=False)
        mgr = AlertManager(cfg)
        mgr.send_alert_sync(_make_alert())
        assert mgr._alerts_sent == 0

    def test_create_and_send_returns_alert(self):
        mgr = AlertManager(_disabled_config())
        alert = mgr.create_and_send(
            title="Test",
            description="Desc",
            severity=AlertSeverity.MEDIUM,
        )
        assert alert.title == "Test"

    def test_deliver_alert_increments_severity_counter(self):
        mgr = AlertManager(_disabled_config())
        alert = _make_alert(AlertSeverity.CRITICAL)
        mgr._deliver_alert(alert)
        assert mgr._alerts_by_severity.get("critical", 0) >= 1

    def test_deliver_multiple_alerts_accumulate_recent(self):
        mgr = AlertManager(_disabled_config())
        for i in range(5):
            a = Alert(
                alert_id=f"a-{i}", title="T", description="D",
                severity=AlertSeverity.LOW, source="s",
            )
            mgr._deliver_alert(a)
        assert len(mgr._recent_alerts) == 5

    def test_get_recent_alerts_no_filter(self):
        mgr = AlertManager(_disabled_config())
        mgr._deliver_alert(_make_alert(AlertSeverity.HIGH))
        mgr._deliver_alert(_make_alert(AlertSeverity.MEDIUM))
        results = mgr.get_recent_alerts(limit=10)
        assert len(results) == 2

    def test_get_recent_alerts_severity_filter(self):
        mgr = AlertManager(_disabled_config())
        mgr._deliver_alert(_make_alert(AlertSeverity.HIGH))
        mgr._deliver_alert(_make_alert(AlertSeverity.MEDIUM))
        results = mgr.get_recent_alerts(limit=10, severity=AlertSeverity.HIGH)
        assert len(results) == 1
        assert results[0]["severity"] == "high"

    def test_start_stop_lifecycle(self):
        mgr = AlertManager(_disabled_config())
        mgr.start()
        assert mgr._running is True
        assert mgr._processor_thread.is_alive()
        mgr.stop()
        assert mgr._running is False

    def test_statistics_keys(self):
        mgr = AlertManager(_disabled_config())
        stats = mgr.statistics
        assert "enabled" in stats
        assert "alerts_sent" in stats
        assert "alerts_failed" in stats

    def test_queue_full_increments_failed(self):
        """Filling the alert queue must increment _alerts_failed."""
        import queue as _queue
        mgr = AlertManager(_disabled_config())
        mgr._alert_queue = _queue.Queue(maxsize=1)
        mgr._alert_queue.put(_make_alert())  # fills it
        mgr.send_alert(_make_alert())  # this one should be dropped
        assert mgr._alerts_failed == 1

    def test_recent_alerts_capped_at_max(self):
        """_deliver_alert trims _recent_alerts to _max_recent_alerts."""
        mgr = AlertManager(_disabled_config())
        mgr._max_recent_alerts = 3
        for i in range(5):
            a = Alert(
                alert_id=f"cap-{i}", title="T", description="D",
                severity=AlertSeverity.INFO, source="s",
            )
            mgr._deliver_alert(a)
        assert len(mgr._recent_alerts) == 3

    def test_deliver_alert_with_syslog_enabled_mocked(self):
        """_deliver_alert calls _syslog.send when syslog_enabled=True."""
        cfg = _disabled_config(syslog_enabled=True)
        mgr = AlertManager(cfg)
        mgr._syslog = MagicMock()   # avoid real syslog
        mgr._deliver_alert(_make_alert())
        mgr._syslog.send.assert_called_once()

    def test_deliver_alert_with_file_enabled_mocked(self):
        """_deliver_alert calls _file.send when file_enabled=True."""
        cfg = _disabled_config(file_enabled=True)
        mgr = AlertManager(cfg)
        mgr._file = MagicMock()
        mgr._deliver_alert(_make_alert())
        mgr._file.send.assert_called_once()

    def test_deliver_alert_with_webhook_enabled_mocked(self):
        """_deliver_alert calls _webhook.send when webhook_enabled=True."""
        cfg = _disabled_config(webhook_enabled=True)
        mgr = AlertManager(cfg)
        mgr._webhook = MagicMock()
        mgr._deliver_alert(_make_alert())
        mgr._webhook.send.assert_called_once()

    def test_deliver_alert_syslog_exception_increments_failed(self):
        """An exception in syslog delivery marks the send as failed."""
        cfg = _disabled_config(syslog_enabled=True)
        mgr = AlertManager(cfg)
        mgr._syslog = MagicMock()
        mgr._syslog.send.side_effect = RuntimeError("syslog broke")
        mgr._deliver_alert(_make_alert())
        assert mgr._alerts_failed == 1

    def test_stop_drains_queued_alerts(self):
        """stop() processes alerts still in the queue before joining the thread."""
        mgr = AlertManager(_disabled_config())
        mgr.start()
        for i in range(3):
            a = Alert(
                alert_id=f"drain-{i}", title="T", description="D",
                severity=AlertSeverity.LOW, source="s",
            )
            mgr._alert_queue.put(a)
        mgr.stop()
        # All queued alerts should have been processed
        assert mgr._alert_queue.empty()


if __name__ == "__main__":
    import pytest as _pytest
    _pytest.main([__file__, "-v"])
