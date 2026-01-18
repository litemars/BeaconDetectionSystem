import json
import logging
import logging.handlers
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger('beacon_detect.control_plane.alerter')


class AlertSeverity(Enum):

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @property
    def syslog_priority(self):

        mapping = {
            'info': logging.INFO,
            'low': logging.WARNING,
            'medium': logging.WARNING,
            'high': logging.ERROR,
            'critical': logging.CRITICAL
        }
        return mapping.get(self.value, logging.WARNING)


@dataclass
class Alert:

    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    source: str
    details: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
    tags: List = field(default_factory=list)
    
    def to_dict(self):

        def convert_value(v):

            if v is None:
                return None
            if hasattr(v, 'item'):  # numpy scalar
                return v.item()
            if isinstance(v, dict):
                return {k: convert_value(val) for k, val in v.items()}
            if isinstance(v, (list, tuple)):
                return [convert_value(item) for item in v]
            if isinstance(v, bool):
                return bool(v)
            if isinstance(v, (int, float, str)):
                return v
            # Try to convert unknown types
            try:
                return float(v) if '.' in str(v) else int(v)
            except (ValueError, TypeError):
                return str(v)
        
        return {
            'alert_id': str(self.alert_id),
            'title': str(self.title),
            'description': str(self.description),
            'severity': str(self.severity.value),
            'source': str(self.source),
            'details': convert_value(self.details),
            'timestamp': str(self.timestamp),
            'tags': [str(t) for t in self.tags]
        }
    
    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)
    
    def to_syslog_message(self):
        return (
            f"[{self.severity.value.upper()}] {self.title} | "
            f"Source: {self.source} | "
            f"ID: {self.alert_id} | "
            f"Description: {self.description}"
        )


@dataclass
class AlertingConfig:

    enabled: bool = True
    
    # Syslog settings
    syslog_enabled: bool = True
    syslog_facility: str = "local0"
    syslog_address: str = "/dev/log"
    
    # File settings
    file_enabled: bool = True
    file_path: str = "/var/log/beacon-detect/alerts.json"
    file_max_size_mb: int = 100
    file_backup_count: int = 5
    
    # Webhook settings
    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_headers: Dict[str, str] = field(default_factory=dict)
    webhook_timeout: int = 10
    webhook_retries: int = 3


class SyslogHandler:
    
    def __init__(self, config):

        self.config = config
        self._logger = None
        
        if config.syslog_enabled:
            self._setup_syslog()
    
    def _setup_syslog(self):

        self._logger = logging.getLogger('beacon_detect.alerts.syslog')
        self._logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        self._logger.handlers = []
        
        # Get facility
        facility_map = {
            'local0': logging.handlers.SysLogHandler.LOG_LOCAL0,
            'local1': logging.handlers.SysLogHandler.LOG_LOCAL1,
            'local2': logging.handlers.SysLogHandler.LOG_LOCAL2,
            'local3': logging.handlers.SysLogHandler.LOG_LOCAL3,
            'local4': logging.handlers.SysLogHandler.LOG_LOCAL4,
            'local5': logging.handlers.SysLogHandler.LOG_LOCAL5,
            'local6': logging.handlers.SysLogHandler.LOG_LOCAL6,
            'local7': logging.handlers.SysLogHandler.LOG_LOCAL7,
        }
        facility = facility_map.get(self.config.syslog_facility, 
                                    logging.handlers.SysLogHandler.LOG_LOCAL0)
        
        try:
            # Try Unix socket first
            if os.path.exists(self.config.syslog_address):
                handler = logging.handlers.SysLogHandler(
                    address=self.config.syslog_address,
                    facility=facility
                )
            else:
                # Fall back to localhost:514
                handler = logging.handlers.SysLogHandler(
                    address=('localhost', 514),
                    facility=facility
                )
            
            formatter = logging.Formatter(
                'beacon-detect[%(process)d]: %(message)s'
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            
            logger.info("Syslog handler initialized")
        except Exception as e:
            logger.error(f"Failed to initialize syslog: {e}")
            self._logger = None
    
    def send(self, alert):

        if not self._logger:
            return
        
        try:
            message = alert.to_syslog_message()
            self._logger.log(alert.severity.syslog_priority, message)
        except Exception as e:
            logger.error(f"Failed to send syslog alert: {e}")


class FileHandler:


    def __init__(self, config ):

        self.config = config
        self._file_path: Path = None
        self._file_handler = None
        self._logger = None
        
        if config.file_enabled:
            self._setup_file()
    
    def _setup_file(self):

        try:
            self._file_path = Path(self.config.file_path)
            
            # Create directory if needed
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Set up rotating file handler
            self._logger = logging.getLogger('beacon_detect.alerts.file')
            self._logger.setLevel(logging.DEBUG)
            self._logger.handlers = []
            
            max_bytes = self.config.file_max_size_mb * 1024 * 1024
            
            self._file_handler = logging.handlers.RotatingFileHandler(
                self._file_path,
                maxBytes=max_bytes,
                backupCount=self.config.file_backup_count
            )
            
            # Use a simple formatter that just writes the message
            self._file_handler.setFormatter(logging.Formatter('%(message)s'))
            self._logger.addHandler(self._file_handler)
            
            logger.info(f"File alert handler initialized: {self._file_path}")
        except Exception as e:
            logger.error(f"Failed to initialize file handler: {e}")
            self._logger = None
    
    def send(self, alert: Alert):

        if not self._logger:
            return
        
        try:
            # Write JSON on single line
            json_str = json.dumps(alert.to_dict())
            self._logger.info(json_str)
        except Exception as e:
            logger.error(f"Failed to write alert to file: {e}")


class WebhookHandler:

    
    def __init__(self, config: AlertingConfig):

        self.config = config
        self._session = None
        
        if config.webhook_enabled and config.webhook_url:
            self._setup_session()
    
    def _setup_session(self):

        self._session = requests.Session()
        
        # Set default headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'BeaconDetect/1.0'
        }
        headers.update(self.config.webhook_headers)
        self._session.headers.update(headers)
        
        logger.info(f"Webhook handler initialized: {self.config.webhook_url}")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    def _send_request(self, payload: str):

        if not self._session:
            return
        
        response = self._session.post(
            self.config.webhook_url,
            data=payload,
            timeout=self.config.webhook_timeout
        )
        response.raise_for_status()
    
    def send(self, alert: Alert):

        if not self._session or not self.config.webhook_url:
            return
        
        try:
            payload = alert.to_json()
            self._send_request(payload)
            logger.debug(f"Webhook alert sent: {alert.alert_id}")
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")


class AlertManager:
    
    def __init__(self, config = None):

        self.config = config or AlertingConfig()
        
        # Initialize handlers
        self._syslog = SyslogHandler(self.config)
        self._file = FileHandler(self.config)
        self._webhook = WebhookHandler(self.config)
        
        # Alert queue for async processing
        self._alert_queue: queue.Queue = queue.Queue(maxsize=1000)
        
        # Processing thread
        self._running = False
        self._processor_thread = None
        
        # Statistics
        self._alerts_sent = 0
        self._alerts_failed = 0
        self._alerts_by_severity: Dict[str, int] = {}
        
        # Alert history (for deduplication and review)
        self._recent_alerts: List[Alert] = []
        self._max_recent_alerts = 1000
        
        logger.info("AlertManager initialized")
    
    def start(self):

        if self._running:
            return
        
        self._running = True
        self._processor_thread = threading.Thread(
            target=self._process_alerts,
            daemon=True
        )
        self._processor_thread.start()
        logger.info("Alert processing started")
    
    def stop(self):

        self._running = False
        
        # Process remaining alerts
        while not self._alert_queue.empty():
            try:
                alert = self._alert_queue.get_nowait()
                self._deliver_alert(alert)
            except queue.Empty:
                break
        
        if self._processor_thread:
            self._processor_thread.join(timeout=5)
        
        logger.info("Alert processing stopped")
    
    def _process_alerts(self):

        while self._running:
            try:
                # Wait for alert with timeout
                alert = self._alert_queue.get(timeout=1.0)
                self._deliver_alert(alert)
                self._alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Alert processing error: {e}")
    
    def _deliver_alert(self, alert: Alert):

        success = True
        
        # Syslog
        if self.config.syslog_enabled:
            try:
                self._syslog.send(alert)
            except Exception as e:
                logger.error(f"Syslog delivery failed: {e}")
                success = False
        
        # File
        if self.config.file_enabled:
            try:
                self._file.send(alert)
            except Exception as e:
                logger.error(f"File delivery failed: {e}")
                success = False
        
        # Webhook
        if self.config.webhook_enabled:
            try:
                self._webhook.send(alert)
            except Exception as e:
                logger.error(f"Webhook delivery failed: {e}")
                success = False
        
        # Update statistics
        if success:
            self._alerts_sent += 1
        else:
            self._alerts_failed += 1
        
        severity_key = alert.severity.value
        self._alerts_by_severity[severity_key] = (
            self._alerts_by_severity.get(severity_key, 0) + 1
        )
        
        # Store in recent alerts
        self._recent_alerts.append(alert)
        if len(self._recent_alerts) > self._max_recent_alerts:
            self._recent_alerts = self._recent_alerts[-self._max_recent_alerts:]
    
    def send_alert(self, alert: Alert):

        if not self.config.enabled:
            logger.debug("Alerting disabled, discarding alert")
            return
        
        try:
            self._alert_queue.put_nowait(alert)
            logger.debug(f"Alert queued: {alert.alert_id}")
        except queue.Full:
            logger.error("Alert queue full, discarding alert")
            self._alerts_failed += 1
    
    def send_alert_sync(self, alert):

        if not self.config.enabled:
            return
        
        self._deliver_alert(alert)
    
    def create_and_send(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        source = "beacon_detector",
        details = None,
        tags = None
    ):
        alert = Alert(
            alert_id=f"alert-{int(time.time())}-{self._alerts_sent}",
            title=title,
            description=description,
            severity=severity,
            source=source,
            details=details or {},
            tags=tags or []
        )
        
        self.send_alert(alert)
        return alert
    
    def get_recent_alerts(
        self, 
        limit: int = 50,
        severity = None
    ):
        alerts = self._recent_alerts[-limit:]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        return [a.to_dict() for a in reversed(alerts)]
    
    @property
    def statistics(self):

        return {
            'enabled': self.config.enabled,
            'alerts_sent': self._alerts_sent,
            'alerts_failed': self._alerts_failed,
            'alerts_by_severity': self._alerts_by_severity.copy(),
            'queue_size': self._alert_queue.qsize(),
            'recent_alerts_count': len(self._recent_alerts),
            'channels': {
                'syslog': self.config.syslog_enabled,
                'file': self.config.file_enabled,
                'webhook': self.config.webhook_enabled
            }
        }
