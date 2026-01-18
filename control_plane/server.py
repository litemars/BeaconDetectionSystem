#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import logging.handlers
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from aiohttp import web

from .storage import ConnectionStorage
from .detector import BeaconDetector, DetectorConfig
from .analyzer import ConnectionAnalyzer, AnalyzerConfig
from .alerter import AlertManager, AlertingConfig, AlertSeverity


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('beacon_detect.control_plane.server')


class ControlPlaneServer:

    def __init__(self, config):

        self.config = config
        self._runtime_config = self._build_runtime_config(config)
        cp_config = config.get('control_plane', {})
        
        self.host = cp_config.get('listen_address', '0.0.0.0')
        self.port = cp_config.get('listen_port', 9090)
        
        # Shutdown event for clean termination
        self._shutdown_event = asyncio.Event()
        
        # Initialize components
        self._init_storage(config)
        self._init_detector(config)
        self._init_alerter(config)
        self._init_analyzer(config)
        
        # HTTP app
        self._app = None
        self._runner = None
        self._site = None
        
        # Statistics
        self._start_time = None
        self._requests_received = 0
        self._batches_processed = 0
        self._events_received = 0
        
        logger.info(f"ControlPlaneServer initialized: {self.host}:{self.port}")
    
    def _build_runtime_config(self, config):

        det = config.get('detection', {})
        alert = config.get('alerting', {})
        whitelist = config.get('whitelist', {})
        
        return {
            'detection': {
                'min_connections': det.get('min_connections', 10),
                'cv_threshold': det.get('cv_threshold', 0.15),
                'alert_threshold': det.get('alert_threshold', 0.7),
                'jitter_threshold': det.get('jitter_threshold', 5.0),
                'analysis_interval': det.get('analysis_interval', 60),
                'alert_cooldown': det.get('alert_cooldown', 300),
            },
            'weights': {
                'cv': det.get('cv_weight', 0.4),
                'periodicity': det.get('periodicity_weight', 0.4),
                'jitter': det.get('jitter_weight', 0.2),
            },
            'alerting': {
                'syslog_enabled': alert.get('syslog', {}).get('enabled', True),
                'file_enabled': alert.get('file', {}).get('enabled', True),
                'file_path': alert.get('file', {}).get('path', '/var/log/beacon-detect/alerts.json'),
                'webhook_enabled': alert.get('webhook', {}).get('enabled', False),
                'webhook_url': alert.get('webhook', {}).get('url', ''),
            },
            'whitelist': {
                'source_ips': whitelist.get('source_ips', []),
                'destination_ips': whitelist.get('destination_ips', []),
                'destination_ports': whitelist.get('ports', []),
            }
        }
    
    def _init_storage(self, config):

        cp_config = config.get('control_plane', {})
        self.storage = ConnectionStorage(
            retention_seconds=cp_config.get('data_retention', 7200),
            cleanup_interval=cp_config.get('cleanup_interval', 300)
        )
    
    def _init_detector(self, config):

        det_config = config.get('detection', {})
        detector_config = DetectorConfig(
            min_connections=det_config.get('min_connections', 10),
            time_window=det_config.get('time_window', 3600),
            cv_threshold=det_config.get('cv_threshold', 0.15),
            periodicity_threshold=det_config.get('periodicity_threshold', 0.7),
            jitter_threshold=det_config.get('jitter_threshold', 5.0),
            min_beacon_interval=det_config.get('min_beacon_interval', 10.0),
            max_beacon_interval=det_config.get('max_beacon_interval', 3600.0),
            cv_weight=det_config.get('cv_weight', 0.4),
            periodicity_weight=det_config.get('periodicity_weight', 0.4),
            jitter_weight=det_config.get('jitter_weight', 0.2),
            alert_threshold=det_config.get('alert_threshold', 0.7)
        )
        self.detector = BeaconDetector(detector_config)
    
    def _init_alerter(self, config):

        alert_config = config.get('alerting', {})
        
        # Build alerting config
        alerting_config = AlertingConfig(
            enabled=alert_config.get('enabled', True),
            syslog_enabled=alert_config.get('syslog', {}).get('enabled', True),
            syslog_facility=alert_config.get('syslog', {}).get('facility', 'local0'),
            file_enabled=alert_config.get('file', {}).get('enabled', True),
            file_path=alert_config.get('file', {}).get('path', '/var/log/beacon-detect/alerts.json'),
            file_max_size_mb=alert_config.get('file', {}).get('max_size_mb', 100),
            file_backup_count=alert_config.get('file', {}).get('backup_count', 5),
            webhook_enabled=alert_config.get('webhook', {}).get('enabled', False),
            webhook_url=alert_config.get('webhook', {}).get('url', ''),
            webhook_headers=alert_config.get('webhook', {}).get('headers', {}),
            webhook_timeout=alert_config.get('webhook', {}).get('timeout', 10),
            webhook_retries=alert_config.get('webhook', {}).get('retries', 3)
        )
        self.alert_manager = AlertManager(alerting_config)
    
    def _init_analyzer(self, config):

        det_config = config.get('detection', {})
        analyzer_config = AnalyzerConfig(
            analysis_interval=60,  # Run every minute
            min_connections=det_config.get('min_connections', 10),
            min_duration=30.0,
            alert_cooldown=det_config.get('alert_cooldown', 300)
        )
        self.analyzer = ConnectionAnalyzer(
            storage=self.storage,
            detector=self.detector,
            alert_manager=self.alert_manager,
            config=analyzer_config
        )
    
    def _setup_routes(self, app: web.Application):

        # API routes
        app.router.add_get('/', self._handle_info)
        app.router.add_post('/api/v1/telemetry', self._handle_telemetry)
        app.router.add_get('/api/v1/health', self._handle_health)
        app.router.add_get('/api/v1/status', self._handle_status)
        app.router.add_get('/api/v1/statistics', self._handle_statistics)
        app.router.add_get('/api/v1/beacons', self._handle_beacons)
        app.router.add_get('/api/v1/alerts', self._handle_alerts)
        app.router.add_delete('/api/v1/alerts', self._handle_clear_alerts)
        app.router.add_get('/api/v1/connections', self._handle_connections)
        app.router.add_post('/api/v1/analyze', self._handle_manual_analyze)
        app.router.add_get('/api/v1/config', self._handle_get_config)
        app.router.add_post('/api/v1/config', self._handle_set_config)
        app.router.add_delete('/api/v1/beacons', self._handle_clear_beacons)
        
        # CORS preflight handler for all API routes
        app.router.add_route('OPTIONS', '/api/v1/{path:.*}', self._handle_options)
    
    async def _handle_info(self, request: web.Request) -> web.Response:
        return web.json_response({
            'name': 'Beacon Detection Control Plane',
            'version': '1.0.0',
            'description': 'Use the CLI for monitoring: python3 -m control_plane.cli',
            'endpoints': {
                'GET /api/v1/health': 'Health check',
                'GET /api/v1/status': 'Server status',
                'GET /api/v1/beacons': 'List detected beacons',
                'GET /api/v1/alerts': 'List alerts',
                'GET /api/v1/connections': 'List connection pairs',
                'GET /api/v1/config': 'Get configuration',
                'POST /api/v1/config': 'Update configuration',
                'POST /api/v1/telemetry': 'Receive telemetry data',
                'POST /api/v1/analyze': 'Trigger analysis',
            }
        })
    
    async def _handle_options(self, request: web.Request) -> web.Response:

        return web.Response(status=200)
    
    async def _handle_health(self, request: web.Request) -> web.Response:

        return web.json_response({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat() + 'Z'
        })
    
    async def _handle_status(self, request: web.Request) -> web.Response:

        uptime = None
        if self._start_time:
            uptime = (datetime.now(timezone.utc) - self._start_time).total_seconds()
        
        return web.json_response({
            'status': 'running',
            'uptime_seconds': uptime,
            'start_time': self._start_time.isoformat() + 'Z' if self._start_time else None,
            'requests_received': self._requests_received,
            'batches_processed': self._batches_processed,
            'events_received': self._events_received,
            'storage': self.storage.statistics,
            'analyzer': self.analyzer.statistics,
            'alerter': self.alert_manager.statistics
        })
    
    async def _handle_statistics(self, request: web.Request) -> web.Response:

        return web.json_response({
            'server': {
                'requests_received': self._requests_received,
                'batches_processed': self._batches_processed,
                'events_received': self._events_received
            },
            'storage': self.storage.statistics,
            'analyzer': self.analyzer.statistics,
            'alerter': self.alert_manager.statistics
        })
    
    async def _handle_telemetry(self, request: web.Request) -> web.Response:

        self._requests_received += 1
        
        try:
            # Get request body
            body = await request.read()
            
            data = json.loads(body.decode('utf-8'))
            
            # Validate batch structure
            if 'events' not in data:
                return web.json_response(
                    {'error': 'Missing events field'},
                    status=400
                )
            
            events = data['events']
            node_id = data.get('node_id', 'unknown')
            batch_id = data.get('batch_id', 'unknown')
            
            # Add events to storage
            self.storage.add_batch(events)
            
            self._batches_processed += 1
            self._events_received += len(events)
            
            logger.info(
                f"Received batch {batch_id} from {node_id}: "
                f"{len(events)} events"
            )
            
            return web.json_response({
                'status': 'accepted',
                'batch_id': batch_id,
                'events_received': len(events)
            })
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in telemetry: {e}")
            return web.json_response(
                {'error': 'Invalid JSON'},
                status=400
            )
        except Exception as e:
            logger.error(f"Error processing telemetry: {e}")
            return web.json_response(
                {'error': str(e)},
                status=500
            )
    
    async def _handle_beacons(self, request: web.Request) -> web.Response:

        beacons = self.analyzer.get_known_beacons()
        return web.json_response({
            'count': len(beacons),
            'beacons': [b.to_dict() for b in beacons]
        })
    
    async def _handle_alerts(self, request: web.Request) -> web.Response:

        limit = int(request.query.get('limit', 50))
        severity = request.query.get('severity')
        
        sev_filter = None
        if severity:
            try:
                sev_filter = AlertSeverity(severity.lower())
            except ValueError:
                pass
        
        alerts = self.alert_manager.get_recent_alerts(limit=limit, severity=sev_filter)
        
        return web.json_response({
            'count': len(alerts),
            'alerts': alerts
        })
    
    async def _handle_connections(self, request: web.Request) -> web.Response:

        src_ip = request.query.get('src_ip')
        dst_ip = request.query.get('dst_ip')
        limit = int(request.query.get('limit', 100))
        
        if src_ip:
            pairs = self.storage.get_pairs_by_src(src_ip)
        elif dst_ip:
            pairs = self.storage.get_pairs_by_dst(dst_ip)
        else:
            pairs = self.storage.get_all_pairs()
        
        # Sort by connection count and limit
        pairs.sort(key=lambda p: p.connection_count, reverse=True)
        pairs = pairs[:limit]
        
        return web.json_response({
            'count': len(pairs),
            'pairs': [
                {
                    'pair_key': p.pair_key,
                    'src_ip': p.src_ip,
                    'dst_ip': p.dst_ip,
                    'dst_port': p.dst_port,
                    'protocol': p.protocol,
                    'connection_count': p.connection_count,
                    'duration_seconds': p.duration_seconds,
                    'first_seen': datetime.fromtimestamp(p.first_seen).isoformat() + 'Z' if p.first_seen else None,
                    'last_seen': datetime.fromtimestamp(p.last_seen).isoformat() + 'Z' if p.last_seen else None
                }
                for p in pairs
            ]
        })
    
    async def _handle_manual_analyze(self, request: web.Request) -> web.Response:

        try:
            run = self.analyzer.run_analysis()
            return web.json_response({
                'status': 'completed',
                'run': run.to_dict(),
                'beacons_found': [r.to_dict() for r in run.results if r.is_beacon]
            })
        except Exception as e:
            logger.error(f"Manual analysis failed: {e}")
            return web.json_response(
                {'error': str(e)},
                status=500
            )
    
    async def _handle_get_config(self, request: web.Request) -> web.Response:

        return web.json_response(self._runtime_config)
    
    async def _handle_set_config(self, request: web.Request) -> web.Response:

        try:
            data = await request.json()
            
            # Update runtime config
            if 'detection' in data:
                self._runtime_config['detection'].update(data['detection'])
                # Update detector config
                if hasattr(self.detector, 'config'):
                    det = data['detection']
                    if 'min_connections' in det:
                        self.detector.config.min_connections = det['min_connections']
                    if 'cv_threshold' in det:
                        self.detector.config.cv_threshold = det['cv_threshold']
                    if 'alert_threshold' in det:
                        self.detector.config.alert_threshold = det['alert_threshold']
                    if 'jitter_threshold' in det:
                        self.detector.config.jitter_threshold = det['jitter_threshold']
                # Update analyzer config
                if hasattr(self.analyzer, 'config'):
                    if 'analysis_interval' in det:
                        self.analyzer.config.analysis_interval = det.get('analysis_interval', 60)
                    if 'alert_cooldown' in det:
                        self.analyzer.config.alert_cooldown = det.get('alert_cooldown', 300)
            
            if 'weights' in data:
                self._runtime_config['weights'].update(data['weights'])
                # Update detector weights
                if hasattr(self.detector, 'config'):
                    w = data['weights']
                    if 'cv' in w:
                        self.detector.config.cv_weight = w['cv']
                    if 'periodicity' in w:
                        self.detector.config.periodicity_weight = w['periodicity']
                    if 'jitter' in w:
                        self.detector.config.jitter_weight = w['jitter']
            
            if 'alerting' in data:
                self._runtime_config['alerting'].update(data['alerting'])
                # Update alert manager config
                if hasattr(self.alert_manager, 'config'):
                    a = data['alerting']
                    if 'syslog_enabled' in a:
                        self.alert_manager.config.syslog_enabled = a['syslog_enabled']
                    if 'file_enabled' in a:
                        self.alert_manager.config.file_enabled = a['file_enabled']
                    if 'webhook_enabled' in a:
                        self.alert_manager.config.webhook_enabled = a['webhook_enabled']
                    if 'webhook_url' in a:
                        self.alert_manager.config.webhook_url = a['webhook_url']
            
            if 'whitelist' in data:
                self._runtime_config['whitelist'].update(data['whitelist'])
                # Update whitelist in main config for filtering
                if 'source_ips' in data['whitelist']:
                    self.config.setdefault('whitelist', {})['source_ips'] = data['whitelist']['source_ips']
                if 'destination_ips' in data['whitelist']:
                    self.config.setdefault('whitelist', {})['destination_ips'] = data['whitelist']['destination_ips']
                if 'destination_ports' in data['whitelist']:
                    self.config.setdefault('whitelist', {})['ports'] = data['whitelist']['destination_ports']
            
            logger.info("Configuration updated via API")
            return web.json_response({'status': 'updated', 'config': self._runtime_config})
            
        except Exception as e:
            logger.error(f"Config update failed: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_clear_alerts(self, request: web.Request) -> web.Response:

        try:
            if hasattr(self.alert_manager, '_recent_alerts'):
                self.alert_manager._recent_alerts = []
            return web.json_response({'status': 'cleared'})
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_clear_beacons(self, request: web.Request) -> web.Response:

        try:
            if hasattr(self.analyzer, '_known_beacons'):
                self.analyzer._known_beacons = {}
            return web.json_response({'status': 'cleared'})
        except Exception as e:
            return web.json_response({'error': str(e)}, status=500)
    
    async def start(self):

        logger.info(f"Starting control plane server on {self.host}:{self.port}")
        
        # Start components
        self.storage.start_cleanup()
        self.alert_manager.start()
        self.analyzer.start()
        
        # Create and configure app with CORS support
        self._app = web.Application(middlewares=[self._cors_middleware])
        self._setup_routes(self._app)
        
        # Create runner
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        
        # Create site
        self._site = web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()
        
        self._start_time = datetime.now(timezone.utc)
        
        logger.info(f"Control plane server started on {self.host}:{self.port}")
        
        # Send startup alert
        self.alert_manager.create_and_send(
            title="Beacon Detection Control Plane Started",
            description=f"Control plane server started on {self.host}:{self.port}",
            severity=AlertSeverity.INFO,
            source="control_plane"
        )
    
    @web.middleware
    async def _cors_middleware(self, request: web.Request, handler):

        # Handle preflight OPTIONS requests
        if request.method == 'OPTIONS':
            response = web.Response()
        else:
            try:
                response = await handler(request)
            except web.HTTPException as ex:
                response = ex
        
        # Add CORS headers
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Max-Age'] = '3600'
        
        return response
    
    async def stop(self):
        logger.info("Stopping control plane server...")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Stop components
        try:
            self.analyzer.stop()
        except Exception as e:
            logger.warning(f"Error stopping analyzer: {e}")
        
        try:
            self.alert_manager.stop()
        except Exception as e:
            logger.warning(f"Error stopping alert manager: {e}")
        
        try:
            self.storage.stop_cleanup()
        except Exception as e:
            logger.warning(f"Error stopping storage cleanup: {e}")
        
        # Stop HTTP server
        if self._site:
            try:
                await self._site.stop()
            except Exception as e:
                logger.warning(f"Error stopping site: {e}")
        
        if self._runner:
            try:
                await self._runner.cleanup()
            except Exception as e:
                logger.warning(f"Error cleaning up runner: {e}")
        
        logger.info("Control plane server stopped")
    
    def request_shutdown(self):

        logger.info("Shutdown requested")
        self._shutdown_event.set()
    
    async def run_forever(self):

        await self.start()
        
        # Wait for shutdown signal
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()


def load_config(config_path: str):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def setup_logging(config):
    log_config = config.get('logging', {})
    
    level_str = log_config.get('level', 'INFO')
    level = getattr(logging, level_str.upper(), logging.INFO)
    
    logging.getLogger().setLevel(level)
    logging.getLogger('beacon_detect').setLevel(level)
    
    # Add file handler if configured
    log_file = log_config.get('file')
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            handler = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=log_config.get('max_size_mb', 50) * 1024 * 1024,
                backupCount=log_config.get('backup_count', 5)
            )
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            logging.getLogger().addHandler(handler)
        except Exception as e:
            logger.warning(f"Could not set up file logging: {e}")


async def main_async(config):

    server = ControlPlaneServer(config)
    
    # Set up signal handlers using the shutdown event
    loop = asyncio.get_running_loop()
    
    def handle_signal():
        logger.info("Signal received, initiating shutdown...")
        server.request_shutdown()
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_signal)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
    
    await server.run_forever()


def main():

    parser = argparse.ArgumentParser(
        description='eBPF Beaconing Detection - Control Plane Server'
    )
    parser.add_argument(
        '-c', '--config',
        required=True,
        help='Path to configuration file'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Set up logging
    setup_logging(config)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run server
    try:
        asyncio.run(main_async(config))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()