import asyncio
import logging
import socket
import time
import uuid
from dataclasses import dataclass

import aiohttp
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)

from .telemetry import TelemetryBatch


logger = logging.getLogger('beacon_detect.data_plane.exporter')


@dataclass
class ExporterConfig:
    control_plane_host: str = "127.0.0.1"
    control_plane_port: int = 9090
    connection_timeout: float = 10.0
    request_timeout: float = 30.0
    max_retries: int = 3
    batch_size: int = 1000
    compression_enabled: bool = True
    node_id: str = None
    
    @property
    def control_plane_url(self):
        return f"http://{self.control_plane_host}:{self.control_plane_port}/api/v1/telemetry"
    
    @property
    def health_check_url(self):
        return f"http://{self.control_plane_host}:{self.control_plane_port}/api/v1/health"


class ExportError(Exception):
    pass


class TelemetryExporter:
    
    def __init__(self, config: ExporterConfig):
        self.config = config
        self.node_id = config.node_id or self._generate_node_id()
        
        self._session: aiohttp.ClientSession = None
        
        # Statistics
        self._batches_sent = 0
        self._batches_failed = 0
        self._events_sent = 0
        self._bytes_sent = 0
        self._last_export_time: float = None
        self._last_error: str = None
        
        # Connection state
        self._control_plane_healthy = False
        self._last_health_check: float = None
        
        logger.info(f"TelemetryExporter initialized with node_id={self.node_id}")
    
    def _generate_node_id(self):
        hostname = socket.gethostname()
        unique_suffix = uuid.uuid4().hex[:8]
        return f"{hostname}-{unique_suffix}"
    
    async def start(self):
        timeout = aiohttp.ClientTimeout(
            total=self.config.request_timeout,
            connect=self.config.connection_timeout
        )
        
        connector = aiohttp.TCPConnector(
            limit=10,
            limit_per_host=5,
            keepalive_timeout=60
        )
        
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'Content-Type': 'application/json',
                'X-Node-ID': self.node_id
            }
        )
        
        # Initial health check
        await self._check_health()
        
        logger.info("TelemetryExporter started")
    
    async def stop(self):

        if self._session:
            await self._session.close()
            self._session = None
        
        logger.info("TelemetryExporter stopped")
    
    async def _check_health(self):
        if not self._session:
            return False
        
        try:
            async with self._session.get(self.config.health_check_url) as response:
                if response.status == 200:
                    self._control_plane_healthy = True
                    self._last_health_check = time.time()
                    logger.debug("Control plane health check passed")
                    return True
                else:
                    self._control_plane_healthy = False
                    logger.warning(f"Control plane health check failed: {response.status}")
                    return False
        except Exception as e:
            self._control_plane_healthy = False
            self._last_error = str(e)
            logger.warning(f"Control plane health check error: {e}")
            return False
    
    async def export_events(self, events: list):
        if not events:
            logger.debug("No events to export")
            return True
        
        # Create batch
        batch = TelemetryBatch(
            batch_id=str(uuid.uuid4()),
            node_id=self.node_id,
            events=events
        )
        
        return await self.export_batch(batch)
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(ExportError),
        reraise=True
    )
    async def export_batch(self, batch):

        if not self._session:
            raise ExportError("Exporter not started")
        
        # Serialize batch
        try:
            payload = batch.to_json()
            payload_bytes = payload.encode('utf-8')
        except Exception as e:
            logger.error(f"Failed to serialize batch: {e}")
            self._batches_failed += 1
            raise ExportError(f"Serialization failed: {e}")
        
        # Compress if enabled and beneficial
        headers = {}
        if self.config.compression_enabled and len(payload_bytes) > 1024:
            import gzip
            payload_bytes = gzip.compress(payload_bytes)
            headers['Content-Encoding'] = 'gzip'
        
        # Send to control plane
        try:
            async with self._session.post(
                self.config.control_plane_url,
                data=payload_bytes,
                headers=headers
            ) as response:
                if response.status == 200:
                    self._batches_sent += 1
                    self._events_sent += batch.event_count
                    self._bytes_sent += len(payload_bytes)
                    self._last_export_time = time.time()
                    self._control_plane_healthy = True
                    
                    logger.info(
                        f"Exported batch {batch.batch_id}: "
                        f"{batch.event_count} events, {len(payload_bytes)} bytes"
                    )
                    return True
                elif response.status == 429:
                    # Rate limited - wait and retry
                    retry_after = int(response.headers.get('Retry-After', 5))
                    logger.warning(f"Rate limited, waiting {retry_after}s")
                    await asyncio.sleep(retry_after)
                    raise ExportError(f"Rate limited: {response.status}")
                else:
                    body = await response.text()
                    logger.error(f"Export failed: {response.status} - {body}")
                    self._batches_failed += 1
                    raise ExportError(f"HTTP {response.status}: {body}")
                    
        except aiohttp.ClientError as e:
            self._batches_failed += 1
            self._control_plane_healthy = False
            self._last_error = str(e)
            logger.error(f"Connection error during export: {e}")
            raise ExportError(f"Connection error: {e}")
    
    async def export_events_chunked(
        self, 
        events: list,
        chunk_size: int = None
    ):
 
        chunk_size = chunk_size or self.config.batch_size
        successful = 0
        failed = 0
        
        for i in range(0, len(events), chunk_size):
            chunk = events[i:i + chunk_size]
            try:
                if await self.export_events(chunk):
                    successful += len(chunk)
                else:
                    failed += len(chunk)
            except ExportError:
                failed += len(chunk)
        
        return successful, failed
    
    @property
    def is_healthy(self):
        return self._control_plane_healthy
    
    @property
    def statistics(self):
        return {
            'node_id': self.node_id,
            'batches_sent': self._batches_sent,
            'batches_failed': self._batches_failed,
            'events_sent': self._events_sent,
            'bytes_sent': self._bytes_sent,
            'last_export_time': self._last_export_time,
            'last_error': self._last_error,
            'control_plane_healthy': self._control_plane_healthy,
            'last_health_check': self._last_health_check
        }


class SyncTelemetryExporter:
    
    def __init__(self, config: ExporterConfig):
        self.config = config
        self._async_exporter: TelemetryExporter = None
        self._loop: asyncio.AbstractEventLoop = None
        self._thread = None
        
    def start(self):
        import threading
        
        def run_event_loop():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            
            self._async_exporter = TelemetryExporter(self.config)
            self._loop.run_until_complete(self._async_exporter.start())
            
            # Keep the loop running
            self._loop.run_forever()
        
        self._thread = threading.Thread(target=run_event_loop, daemon=True)
        self._thread.start()
        
        # Wait for initialization
        time.sleep(0.5)
        logger.info("SyncTelemetryExporter started")
    
    def stop(self):

        if self._loop and self._async_exporter:
            # Schedule stop coroutine and wait for it to complete
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self._async_exporter.stop(),
                    self._loop
                )
                # Wait for the stop coroutine to complete with timeout
                future.result(timeout=5)
            except Exception as e:
                logger.warning(f"Error stopping async exporter: {e}")
            
            # Stop the event loop
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception as e:
                logger.warning(f"Error stopping event loop: {e}")
            
        if self._thread:
            try:
                self._thread.join(timeout=5)
            except Exception as e:
                logger.warning(f"Error joining thread: {e}")
            
        logger.info("SyncTelemetryExporter stopped")
    
    def export_events(self, events: list):

        if not self._loop or not self._async_exporter:
            logger.error("Exporter not started")
            return False
        
        future = asyncio.run_coroutine_threadsafe(
            self._async_exporter.export_events(events),
            self._loop
        )
        
        try:
            return future.result(timeout=self.config.request_timeout + 5)
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False
    
    @property
    def statistics(self):
        if self._async_exporter:
            return self._async_exporter.statistics
        return {}
    
    @property
    def is_healthy(self):
        if self._async_exporter:
            return self._async_exporter.is_healthy
        return False
