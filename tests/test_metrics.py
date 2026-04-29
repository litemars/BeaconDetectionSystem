"""Tests for GET /api/v1/metrics (Prometheus text endpoint) and
alert-queue backpressure in GET /api/v1/health.

Definition-of-Done checks:
  [DoD-M1] GET /api/v1/metrics returns valid Prometheus text with all six
           required counter/gauge names.
  [DoD-M2] Injecting 200 events and triggering analysis increments
           beacon_detector_events_total to 200.
  [DoD-M3] GET /api/v1/health exposes alert_queue_fill_percent and
           alert_queue_backpressure.

Run with: pytest tests/test_metrics.py -v
"""

import json
import sys
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.server import ControlPlaneServer

_MINIMAL_CONFIG = {
    "control_plane": {
        "listen_address": "127.0.0.1",
        "listen_port": 9090,
        "data_retention": 7200,
        "cleanup_interval": 300,
    },
    "detection": {
        "min_connections": 10,
        "alert_threshold": 0.7,
    },
    "alerting": {
        "enabled": False,
        "syslog": {"enabled": False},
        "file": {"enabled": False},
        "webhook": {"enabled": False},
    },
    "benign_baseline": {"enabled": False},
}

# Six metric names the DoD requires
_REQUIRED_METRICS = [
    "beacon_detector_events_total",
    "beacon_detector_pairs_active",
    "beacon_detector_analysis_duration_seconds",
    "beacon_detector_alerts_total",
    "beacon_detector_buffer_overflow_total",
    "beacon_detector_ebpf_drops_total",
]


def _make_app() -> web.Application:
    server = ControlPlaneServer(_MINIMAL_CONFIG)
    app = web.Application(middlewares=[server._cors_middleware])
    server._setup_routes(app)
    return app


def _make_event(i: int) -> dict:
    """Build one minimal connection event dict."""
    return {
        "timestamp_ns": 1_700_000_000_000_000_000 + i * 60_000_000_000,
        "timestamp_utc": f"2024-01-01T{i // 60:02d}:{i % 60:02d}:00Z",
        "src_ip": "10.100.0.1",
        "dst_ip": "203.0.113.50",
        "src_port": 54321,
        "dst_port": 443,
        "packet_size": 128,
        "protocol": 6,
        "protocol_name": "TCP",
        "tcp_flags": 16,
        "direction": 1,
        "node_id": "test-node",
        "connection_key": "10.100.0.1:54321->203.0.113.50:443/TCP",
    }


# ─────────────────────────────────────────────────────────────────────────────
# [DoD-M1]  All six metric names present and valid Prometheus text
# ─────────────────────────────────────────────────────────────────────────────

class TestMetricsFormat:

    @pytest.mark.asyncio
    async def test_metrics_returns_200(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/metrics")
            assert resp.status == 200

    @pytest.mark.asyncio
    async def test_metrics_content_type_is_prometheus(self):
        """Content-Type header must contain 'text/plain' and version tag."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/metrics")
            ct = resp.headers.get("Content-Type", "")
        assert "text/plain" in ct
        assert "version=0.0.4" in ct

    @pytest.mark.asyncio
    async def test_all_six_metric_names_present(self):
        """[DoD-M1] Every required metric must appear in the response body."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/metrics")
            body = await resp.text()
        for name in _REQUIRED_METRICS:
            assert name in body, f"Missing metric: {name}\n\nBody:\n{body}"

    @pytest.mark.asyncio
    async def test_help_and_type_lines_present(self):
        """Each metric must be preceded by # HELP and # TYPE comment lines."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/metrics")
            body = await resp.text()
        for name in _REQUIRED_METRICS:
            assert f"# HELP {name}" in body, f"Missing # HELP for {name}"
            assert f"# TYPE {name}" in body, f"Missing # TYPE for {name}"

    @pytest.mark.asyncio
    async def test_counter_type_declared(self):
        """events_total, alerts_total, buffer_overflow_total, ebpf_drops_total
        must be declared as 'counter'."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/metrics")
            body = await resp.text()
        for counter_name in [
            "beacon_detector_events_total",
            "beacon_detector_alerts_total",
            "beacon_detector_buffer_overflow_total",
            "beacon_detector_ebpf_drops_total",
        ]:
            assert f"# TYPE {counter_name} counter" in body, (
                f"{counter_name} must be declared as counter"
            )

    @pytest.mark.asyncio
    async def test_gauge_type_declared(self):
        """pairs_active and analysis_duration_seconds must be gauges."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/metrics")
            body = await resp.text()
        for gauge_name in [
            "beacon_detector_pairs_active",
            "beacon_detector_analysis_duration_seconds",
        ]:
            assert f"# TYPE {gauge_name} gauge" in body, (
                f"{gauge_name} must be declared as gauge"
            )

    @pytest.mark.asyncio
    async def test_metric_values_are_numeric(self):
        """Each metric line must end with a parseable float/int value."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/metrics")
            body = await resp.text()
        for name in _REQUIRED_METRICS:
            # Find the data line (no leading #)
            for line in body.splitlines():
                if line.startswith(name):
                    parts = line.split()
                    assert len(parts) == 2, (
                        f"Metric line has unexpected format: {line!r}"
                    )
                    float(parts[1])  # must not raise
                    break
            else:
                pytest.fail(f"No data line found for metric {name}")


# ─────────────────────────────────────────────────────────────────────────────
# [DoD-M2]  beacon_detector_events_total increments correctly
# ─────────────────────────────────────────────────────────────────────────────

class TestEventsCounter:

    @pytest.mark.asyncio
    async def test_events_total_zero_on_fresh_server(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/metrics")
            body = await resp.text()
        value = _parse_metric(body, "beacon_detector_events_total")
        assert value == 0

    @pytest.mark.asyncio
    async def test_events_total_after_200_events_injected(self):
        """[DoD-M2] Injecting 200 events must set events_total to 200."""
        events = [_make_event(i) for i in range(200)]
        payload = {
            "node_id": "test-node",
            "batch_id": "batch-200",
            "events": events,
        }
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            post_resp = await client.post("/api/v1/telemetry", json=payload)
            assert post_resp.status == 200

            metrics_resp = await client.get("/api/v1/metrics")
            body = await metrics_resp.text()

        value = _parse_metric(body, "beacon_detector_events_total")
        assert value == 200, (
            f"[DoD-M2] Expected events_total=200, got {value}"
        )

    @pytest.mark.asyncio
    async def test_events_total_accumulates_across_batches(self):
        """Two batches of 50 events each must produce events_total == 100."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            for batch_num in range(2):
                events = [_make_event(batch_num * 50 + i) for i in range(50)]
                resp = await client.post(
                    "/api/v1/telemetry",
                    json={
                        "node_id": "n1",
                        "batch_id": f"b-{batch_num}",
                        "events": events,
                    },
                )
                assert resp.status == 200

            body = await (await client.get("/api/v1/metrics")).text()

        assert _parse_metric(body, "beacon_detector_events_total") == 100

    @pytest.mark.asyncio
    async def test_pairs_active_nonzero_after_injection(self):
        """pairs_active gauge must be ≥ 1 after events are injected."""
        events = [_make_event(i) for i in range(5)]
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            await client.post(
                "/api/v1/telemetry",
                json={"node_id": "n", "batch_id": "b", "events": events},
            )
            body = await (await client.get("/api/v1/metrics")).text()

        assert _parse_metric(body, "beacon_detector_pairs_active") >= 1

    @pytest.mark.asyncio
    async def test_analysis_duration_updates_after_analyze(self):
        """Triggering /api/v1/analyze must produce a non-negative duration."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            await client.post("/api/v1/analyze")
            body = await (await client.get("/api/v1/metrics")).text()

        duration = _parse_metric(body, "beacon_detector_analysis_duration_seconds")
        assert duration >= 0.0

    @pytest.mark.asyncio
    async def test_data_plane_stats_increments_overflow_counter(self):
        """A batch that includes data_plane_stats.events_dropped_overflow must
        increment beacon_detector_buffer_overflow_total."""
        payload = {
            "node_id": "n1",
            "batch_id": "b-overflow",
            "events": [_make_event(0)],
            "data_plane_stats": {
                "events_dropped_overflow": 7,
                "events_dropped_ebpf": 3,
            },
        }
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            await client.post("/api/v1/telemetry", json=payload)
            body = await (await client.get("/api/v1/metrics")).text()

        assert _parse_metric(body, "beacon_detector_buffer_overflow_total") == 7
        assert _parse_metric(body, "beacon_detector_ebpf_drops_total") == 3


# ─────────────────────────────────────────────────────────────────────────────
# [DoD-M3]  Health endpoint includes queue fill / backpressure
# ─────────────────────────────────────────────────────────────────────────────

class TestHealthBackpressure:

    @pytest.mark.asyncio
    async def test_health_has_queue_fill_percent(self):
        """[DoD-M3] GET /api/v1/health must include alert_queue_fill_percent."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/health")
            body = await resp.json()
        assert "alert_queue_fill_percent" in body, (
            f"alert_queue_fill_percent missing from health: {body}"
        )

    @pytest.mark.asyncio
    async def test_health_has_backpressure_flag(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/health")
            body = await resp.json()
        assert "alert_queue_backpressure" in body

    @pytest.mark.asyncio
    async def test_health_has_alert_queue_drops(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/health")
            body = await resp.json()
        assert "alert_queue_drops" in body
        assert isinstance(body["alert_queue_drops"], int)

    @pytest.mark.asyncio
    async def test_health_backpressure_false_on_empty_queue(self):
        """An empty queue must report backpressure=False and fill_percent=0."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/health")
            body = await resp.json()
        assert body["alert_queue_backpressure"] is False
        assert body["alert_queue_fill_percent"] == 0.0

    @pytest.mark.asyncio
    async def test_health_backpressure_true_when_queue_over_80pct(self):
        """Pre-filling the queue to >80 % must flip alert_queue_backpressure."""
        import queue as _queue
        from control_plane.alerter import Alert, AlertSeverity

        server = ControlPlaneServer(_MINIMAL_CONFIG)
        app = web.Application(middlewares=[server._cors_middleware])
        server._setup_routes(app)

        # Replace the alert queue with a tiny one and fill it past 80 %
        tiny_q = _queue.Queue(maxsize=10)
        for i in range(9):  # 90 % full
            tiny_q.put(Alert(
                alert_id=f"fill-{i}", title="T", description="D",
                severity=AlertSeverity.LOW, source="test",
            ))
        server.alert_manager._alert_queue = tiny_q

        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/health")
            body = await resp.json()

        assert body["alert_queue_backpressure"] is True, (
            f"Expected backpressure=True at 90% fill; got: {body}"
        )
        assert body["alert_queue_fill_percent"] >= 80.0

    @pytest.mark.asyncio
    async def test_status_includes_alert_queue_drops(self):
        """GET /api/v1/status must expose alert_queue_drops at the top level."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/status")
            body = await resp.json()
        assert "alert_queue_drops" in body

    @pytest.mark.asyncio
    async def test_status_includes_ebpf_and_overflow_totals(self):
        """GET /api/v1/status must expose ebpf_drops_total and
        buffer_overflow_total at the top level."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/status")
            body = await resp.json()
        assert "ebpf_drops_total" in body
        assert "buffer_overflow_total" in body


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def _parse_metric(prometheus_text: str, name: str) -> float:
    """Extract the scalar value from a Prometheus metric line."""
    for line in prometheus_text.splitlines():
        if line.startswith(name) and not line.startswith("#"):
            parts = line.split()
            if len(parts) == 2:
                return float(parts[1])
    raise AssertionError(
        f"Metric '{name}' not found in Prometheus output:\n{prometheus_text}"
    )


if __name__ == "__main__":
    import pytest as _pytest
    _pytest.main([__file__, "-v"])
