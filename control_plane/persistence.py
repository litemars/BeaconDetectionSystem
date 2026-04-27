"""
SQLite persistence layer for beacon detection system.

Persists alerts and detected beacons across restarts.
Raw connection data is NOT persisted (ephemeral, high-volume).
"""

import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("beacon_detect.control_plane.persistence")


@dataclass
class PersistenceConfig:
    db_path: str = "./beacon_detect.db"
    journal_mode: str = "WAL"
    busy_timeout_ms: int = 5000


class SQLiteStore:
    """Thread-safe SQLite persistence for alerts and beacons."""

    def __init__(self, config: PersistenceConfig = None):
        self.config = config or PersistenceConfig()
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None

    def open(self):
        """Open database connection and create tables."""
        db_path = Path(self.config.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(db_path),
            check_same_thread=False,
        )
        self._conn.execute(f"PRAGMA journal_mode={self.config.journal_mode}")
        self._conn.execute(f"PRAGMA busy_timeout={self.config.busy_timeout_ms}")
        self._conn.row_factory = sqlite3.Row

        self._create_tables()
        logger.info(f"SQLiteStore opened: {db_path}")

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.info("SQLiteStore closed")

    def _create_tables(self):
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    details_json TEXT DEFAULT '{}',
                    timestamp TEXT NOT NULL,
                    tags_json TEXT DEFAULT '[]',
                    created_at TEXT DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                    ON alerts(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity
                    ON alerts(severity);

                CREATE TABLE IF NOT EXISTS beacons (
                    pair_key TEXT PRIMARY KEY,
                    detection_json TEXT NOT NULL,
                    first_detected TEXT NOT NULL,
                    last_updated TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_beacons_last_updated
                    ON beacons(last_updated DESC);
            """
            )
            self._conn.commit()

    # -- Alert persistence --

    def save_alert(self, alert_dict: dict):
        """Persist a single alert."""
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO alerts
                   (alert_id, title, description, severity, source,
                    details_json, timestamp, tags_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert_dict["alert_id"],
                    alert_dict["title"],
                    alert_dict["description"],
                    alert_dict["severity"],
                    alert_dict["source"],
                    json.dumps(alert_dict.get("details", {})),
                    alert_dict["timestamp"],
                    json.dumps(alert_dict.get("tags", [])),
                ),
            )
            self._conn.commit()

    def load_alerts(self, limit: int = 1000) -> List[dict]:
        """Load recent alerts from database."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()

            alerts = []
            for row in rows:
                alerts.append(
                    {
                        "alert_id": row["alert_id"],
                        "title": row["title"],
                        "description": row["description"],
                        "severity": row["severity"],
                        "source": row["source"],
                        "details": json.loads(row["details_json"]),
                        "timestamp": row["timestamp"],
                        "tags": json.loads(row["tags_json"]),
                    }
                )
            return alerts

    def get_alert_count(self) -> int:
        with self._lock:
            cursor = self._conn.execute("SELECT COUNT(*) FROM alerts")
            return cursor.fetchone()[0]

    # -- Beacon persistence --

    def save_beacon(self, pair_key: str, detection_dict: dict):
        """Persist a detected beacon."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with self._lock:
            # Preserve first_detected if beacon already exists
            cursor = self._conn.execute(
                "SELECT first_detected FROM beacons WHERE pair_key = ?",
                (pair_key,),
            )
            row = cursor.fetchone()
            first_detected = row["first_detected"] if row else now

            self._conn.execute(
                """INSERT OR REPLACE INTO beacons
                   (pair_key, detection_json, first_detected, last_updated)
                   VALUES (?, ?, ?, ?)""",
                (
                    pair_key,
                    json.dumps(detection_dict),
                    first_detected,
                    now,
                ),
            )
            self._conn.commit()

    def remove_beacon(self, pair_key: str):
        """Remove a beacon that is no longer detected."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM beacons WHERE pair_key = ?", (pair_key,)
            )
            self._conn.commit()

    def load_beacons(self) -> Dict[str, dict]:
        """Load all known beacons. Returns {pair_key: detection_dict}."""
        with self._lock:
            cursor = self._conn.execute("SELECT * FROM beacons")
            rows = cursor.fetchall()

            beacons = {}
            for row in rows:
                beacons[row["pair_key"]] = json.loads(row["detection_json"])
            return beacons

    def get_beacon_count(self) -> int:
        with self._lock:
            cursor = self._conn.execute("SELECT COUNT(*) FROM beacons")
            return cursor.fetchone()[0]
