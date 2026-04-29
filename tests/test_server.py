"""HTTP integration tests for ControlPlaneServer.

Run with: pytest tests/test_server.py -v
"""

import gzip
import json
import sys
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).parent.parent))

from control_plane.server import ControlPlaneServer

# Minimal config: all background services disabled so __init__ is safe to call
# in a test without threads or file handles being opened.
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


def _make_app() -> web.Application:
    """Build the aiohttp Application without starting background services."""
    server = ControlPlaneServer(_MINIMAL_CONFIG)
    app = web.Application(middlewares=[server._cors_middleware])
    server._setup_routes(app)
    return app


# ---------------------------------------------------------------------------
# Gzip telemetry
# ---------------------------------------------------------------------------


class TestGzipTelemetry:

    @pytest.mark.asyncio
    async def test_large_gzip_batch_accepted(self):
        """A >1 KB gzip-compressed batch must be decompressed and fully accepted."""
        events = [
            {
                "timestamp_ns": 1_700_000_000_000_000_000 + i * 60_000_000_000,
                "timestamp_utc": f"2024-01-01T00:{i:02d}:00Z",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "src_port": 54321 + i,
                "dst_port": 443,
                "packet_size": 1500,
                "protocol": 6,
                "protocol_name": "TCP",
                "tcp_flags": 16,
                "direction": 1,
                "node_id": "test-gzip",
                "connection_key": f"192.168.1.100:{54321 + i}->10.0.0.1:443/TCP",
            }
            for i in range(20)
        ]
        payload = json.dumps(
            {"node_id": "test-gzip", "batch_id": "batch-001", "events": events}
        ).encode("utf-8")
        assert len(payload) > 1024, f"Fixture too small for test: {len(payload)} bytes"

        compressed = gzip.compress(payload)

        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(
                "/api/v1/telemetry",
                data=compressed,
                headers={
                    "Content-Encoding": "gzip",
                    "Content-Type": "application/json",
                },
            )
            assert resp.status == 200
            body = await resp.json()
            assert body["status"] == "accepted"
            assert body["events_received"] == 20

    @pytest.mark.asyncio
    async def test_uncompressed_telemetry_still_works(self):
        """Plain JSON telemetry (no Content-Encoding) must continue to work."""
        events = [
            {
                "timestamp_ns": 1_700_000_000_000_000_000,
                "timestamp_utc": "2024-01-01T00:00:00Z",
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.3",
                "src_port": 12345,
                "dst_port": 80,
                "packet_size": 512,
                "protocol": 6,
                "protocol_name": "TCP",
                "tcp_flags": 16,
                "direction": 1,
                "node_id": "test-plain",
                "connection_key": "10.0.0.2:12345->10.0.0.3:80/TCP",
            }
        ]
        payload = {"node_id": "test-plain", "batch_id": "batch-002", "events": events}

        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post("/api/v1/telemetry", json=payload)
            assert resp.status == 200
            body = await resp.json()
            assert body["events_received"] == 1

    @pytest.mark.asyncio
    async def test_missing_events_field_returns_400(self):
        """Telemetry body without an 'events' key must be rejected with 400."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(
                "/api/v1/telemetry", json={"node_id": "x", "batch_id": "y"}
            )
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_invalid_json_returns_400(self):
        """Raw non-JSON bytes must be rejected with 400 (JSONDecodeError path)."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(
                "/api/v1/telemetry",
                data=b"this is not json",
                headers={"Content-Type": "application/json"},
            )
            assert resp.status == 400


# ---------------------------------------------------------------------------
# /api/v1/status
# ---------------------------------------------------------------------------


class TestStatusEndpoint:

    @pytest.mark.asyncio
    async def test_status_includes_system_metrics(self):
        """GET /api/v1/status must include system.cpu_percent and system.memory_mb.

        Keys must be present even when psutil is not installed (values will be
        None in that case — the contract is key presence, not non-null values).
        """
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/status")
            assert resp.status == 200
            body = await resp.json()
            assert "system" in body, "top-level 'system' key missing"
            system = body["system"]
            assert "cpu_percent" in system, "system.cpu_percent key missing"
            assert "memory_mb" in system, "system.memory_mb key missing"

    @pytest.mark.asyncio
    async def test_status_top_level_structure(self):
        """GET /api/v1/status must return status=running with storage and analyzer keys."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/status")
            assert resp.status == 200
            body = await resp.json()
            assert body["status"] == "running"
            assert "storage" in body
            assert "analyzer" in body


# ---------------------------------------------------------------------------
# /api/v1/health
# ---------------------------------------------------------------------------


class TestHealthEndpoint:

    @pytest.mark.asyncio
    async def test_health_returns_200(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/health")
            assert resp.status == 200
            body = await resp.json()
            assert body["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_has_timestamp(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/health")
            body = await resp.json()
            assert "timestamp" in body


# ---------------------------------------------------------------------------
# GET /  (info)
# ---------------------------------------------------------------------------


class TestInfoEndpoint:

    @pytest.mark.asyncio
    async def test_root_returns_name(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/")
            assert resp.status == 200
            body = await resp.json()
            assert "Beacon Detection" in body.get("name", "")

    @pytest.mark.asyncio
    async def test_root_lists_endpoints(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/")
            body = await resp.json()
            assert "endpoints" in body


# ---------------------------------------------------------------------------
# /api/v1/beacons  (GET + DELETE)
# ---------------------------------------------------------------------------


class TestBeaconsEndpoint:

    @pytest.mark.asyncio
    async def test_get_beacons_empty(self):
        """GET /api/v1/beacons on a fresh server returns an empty list."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/beacons")
            assert resp.status == 200
            body = await resp.json()
            assert "beacons" in body
            assert body["count"] == 0

    @pytest.mark.asyncio
    async def test_delete_beacons_clears(self):
        """DELETE /api/v1/beacons (no API key required when auth disabled) → 200."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.delete("/api/v1/beacons")
            assert resp.status == 200
            body = await resp.json()
            assert body["status"] == "cleared"


# ---------------------------------------------------------------------------
# /api/v1/connections
# ---------------------------------------------------------------------------


class TestConnectionsEndpoint:

    @pytest.mark.asyncio
    async def test_connections_empty(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/connections")
            assert resp.status == 200
            body = await resp.json()
            assert "pairs" in body

    @pytest.mark.asyncio
    async def test_connections_after_telemetry(self):
        """Injecting telemetry and then querying /connections returns that pair."""
        events = [
            {
                "timestamp_ns": 1_700_000_000_000_000_000 + i * 60_000_000_000,
                "timestamp_utc": f"2024-01-01T00:{i:02d}:00Z",
                "src_ip": "10.1.2.3",
                "dst_ip": "10.9.9.9",
                "src_port": 55000,
                "dst_port": 8080,
                "packet_size": 200,
                "protocol": 6,
                "protocol_name": "TCP",
                "tcp_flags": 16,
                "direction": 1,
                "node_id": "conn-test",
                "connection_key": "10.1.2.3:55000->10.9.9.9:8080/TCP",
            }
            for i in range(3)
        ]
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            await client.post(
                "/api/v1/telemetry",
                json={"node_id": "conn-test", "batch_id": "b1", "events": events},
            )
            resp = await client.get("/api/v1/connections")
            body = await resp.json()
            assert body["count"] >= 1
            pair_keys = [p["pair_key"] for p in body["pairs"]]
            assert "10.1.2.3->10.9.9.9:8080/TCP" in pair_keys

    @pytest.mark.asyncio
    async def test_connections_filter_by_src_ip(self):
        """?src_ip= query filters results to pairs from that source."""
        events = [
            {
                "timestamp_ns": 1_700_000_000_000_000_000 + i * 1_000_000_000,
                "timestamp_utc": f"2024-01-01T00:00:{i:02d}Z",
                "src_ip": "172.0.1.1",
                "dst_ip": "8.8.8.8",
                "src_port": 40000,
                "dst_port": 53,
                "packet_size": 64,
                "protocol": 17,
                "protocol_name": "UDP",
                "tcp_flags": 0,
                "direction": 1,
                "node_id": "src-filter",
                "connection_key": "172.0.1.1:40000->8.8.8.8:53/UDP",
            }
            for i in range(3)
        ]
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            await client.post(
                "/api/v1/telemetry",
                json={"node_id": "src-filter", "batch_id": "b2", "events": events},
            )
            resp = await client.get("/api/v1/connections?src_ip=172.0.1.1")
            body = await resp.json()
            for pair in body["pairs"]:
                assert pair["src_ip"] == "172.0.1.1"

    @pytest.mark.asyncio
    async def test_connections_filter_by_dst_ip(self):
        events = [
            {
                "timestamp_ns": 1_700_000_000_000_000_000 + i * 1_000_000_000,
                "timestamp_utc": f"2024-01-01T00:00:{i:02d}Z",
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.50.50",
                "src_port": 33333,
                "dst_port": 9000,
                "packet_size": 128,
                "protocol": 6,
                "protocol_name": "TCP",
                "tcp_flags": 0,
                "direction": 1,
                "node_id": "dst-filter",
                "connection_key": "10.0.0.1:33333->192.168.50.50:9000/TCP",
            }
            for i in range(3)
        ]
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            await client.post(
                "/api/v1/telemetry",
                json={"node_id": "dst-filter", "batch_id": "b3", "events": events},
            )
            resp = await client.get("/api/v1/connections?dst_ip=192.168.50.50")
            body = await resp.json()
            for pair in body["pairs"]:
                assert pair["dst_ip"] == "192.168.50.50"


# ---------------------------------------------------------------------------
# /api/v1/alerts
# ---------------------------------------------------------------------------


class TestAlertsEndpoint:

    @pytest.mark.asyncio
    async def test_get_alerts_empty(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/alerts")
            assert resp.status == 200
            body = await resp.json()
            assert "alerts" in body

    @pytest.mark.asyncio
    async def test_get_alerts_with_severity_filter(self):
        """?severity=high must not cause a 500 error."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/alerts?severity=high")
            assert resp.status == 200

    @pytest.mark.asyncio
    async def test_get_alerts_unknown_severity_still_200(self):
        """Unknown severity value is silently ignored (not a 400)."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/alerts?severity=bogus")
            assert resp.status == 200


# ---------------------------------------------------------------------------
# /api/v1/config  (GET and POST)
# ---------------------------------------------------------------------------


class TestConfigEndpoint:

    @pytest.mark.asyncio
    async def test_get_config_returns_detection_section(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/config")
            assert resp.status == 200
            body = await resp.json()
            assert "detection" in body

    @pytest.mark.asyncio
    async def test_post_config_updates_alert_threshold(self):
        """POST /api/v1/config with a detection update must return updated config."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(
                "/api/v1/config",
                json={"detection": {"alert_threshold": 0.65}},
            )
            assert resp.status == 200
            body = await resp.json()
            assert body["status"] == "updated"
            assert body["config"]["detection"]["alert_threshold"] == 0.65

    @pytest.mark.asyncio
    async def test_post_config_updates_weights(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(
                "/api/v1/config",
                json={"weights": {"cv": 0.40, "periodicity": 0.30,
                                   "jitter": 0.15, "size": 0.15}},
            )
            assert resp.status == 200
            body = await resp.json()
            assert body["config"]["weights"]["cv"] == 0.40

    @pytest.mark.asyncio
    async def test_post_config_updates_alerting_section(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(
                "/api/v1/config",
                json={"alerting": {"webhook_enabled": False}},
            )
            assert resp.status == 200


# ---------------------------------------------------------------------------
# /api/v1/analyze  (manual trigger)
# ---------------------------------------------------------------------------


class TestManualAnalyze:

    @pytest.mark.asyncio
    async def test_post_analyze_returns_run_info(self):
        """POST /api/v1/analyze must return status=completed with run metadata."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post("/api/v1/analyze")
            assert resp.status == 200
            body = await resp.json()
            assert body["status"] == "completed"
            assert "run" in body
            assert "beacons_found" in body


# ---------------------------------------------------------------------------
# /api/v1/statistics
# ---------------------------------------------------------------------------


class TestStatisticsEndpoint:

    @pytest.mark.asyncio
    async def test_statistics_has_server_section(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/statistics")
            assert resp.status == 200
            body = await resp.json()
            assert "server" in body
            assert "storage" in body


# ---------------------------------------------------------------------------
# CORS preflight
# ---------------------------------------------------------------------------


class TestCORS:

    @pytest.mark.asyncio
    async def test_options_preflight_returns_200(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.options("/api/v1/telemetry")
            assert resp.status == 200
            assert "Access-Control-Allow-Origin" in resp.headers

    @pytest.mark.asyncio
    async def test_get_includes_cors_header(self):
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/v1/health")
            assert resp.headers.get("Access-Control-Allow-Origin") == "*"


# ---------------------------------------------------------------------------
# API key auth
# ---------------------------------------------------------------------------


class TestApiKeyAuth:

    @pytest.mark.asyncio
    async def test_no_key_required_when_unset(self):
        """Without api_key in config, all write endpoints are open."""
        app = _make_app()
        async with TestClient(TestServer(app)) as client:
            resp = await client.post("/api/v1/analyze")
            assert resp.status == 200  # not 401

    @pytest.mark.asyncio
    async def test_wrong_key_returns_401(self):
        """With api_key configured, a wrong key must return 401."""
        config = dict(_MINIMAL_CONFIG)
        config["control_plane"] = dict(config["control_plane"])
        config["control_plane"]["api_key"] = "secret123"
        server = ControlPlaneServer(config)
        app = web.Application(middlewares=[server._cors_middleware])
        server._setup_routes(app)
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(
                "/api/v1/telemetry",
                json={"node_id": "x", "batch_id": "y",
                      "events": [{"timestamp_ns": 0, "timestamp_utc": "2024-01-01T00:00:00Z",
                                   "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                                   "src_port": 1, "dst_port": 443,
                                   "packet_size": 100, "protocol": 6,
                                   "protocol_name": "TCP", "tcp_flags": 0,
                                   "direction": 1, "node_id": "x",
                                   "connection_key": "1.1.1.1:1->2.2.2.2:443/TCP"}]},
                headers={"X-API-Key": "wrong"},
            )
            assert resp.status == 401

    @pytest.mark.asyncio
    async def test_correct_key_accepted(self):
        """With api_key configured, the correct key must be accepted."""
        config = dict(_MINIMAL_CONFIG)
        config["control_plane"] = dict(config["control_plane"])
        config["control_plane"]["api_key"] = "secret123"
        server = ControlPlaneServer(config)
        app = web.Application(middlewares=[server._cors_middleware])
        server._setup_routes(app)
        async with TestClient(TestServer(app)) as client:
            resp = await client.post(
                "/api/v1/analyze",
                headers={"X-API-Key": "secret123"},
            )
            assert resp.status == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
