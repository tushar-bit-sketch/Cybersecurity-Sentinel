"""SQLite persistence for accepted telemetry and generated alerts."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS events (
    record_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    event_type TEXT NOT NULL,
    risk INTEGER NOT NULL CHECK (risk BETWEEN 0 AND 100),
    predicted_class TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL REFERENCES events(record_id),
    risk INTEGER NOT NULL CHECK (risk BETWEEN 0 AND 100),
    band TEXT NOT NULL CHECK (band IN ('Normal', 'Suspicious', 'Malicious')),
    predicted_class TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    anomaly_score REAL NOT NULL CHECK (anomaly_score BETWEEN 0 AND 1),
    evidence_json TEXT NOT NULL,
    model_version TEXT NOT NULL DEFAULT '1',
    detector_version TEXT NOT NULL DEFAULT 'robust-mad',
    risk_components_json TEXT NOT NULL DEFAULT '{}',
    feature_json TEXT NOT NULL DEFAULT '{}',
    probabilities_json TEXT NOT NULL DEFAULT '{}',
    raw_event_ids_json TEXT NOT NULL DEFAULT '[]',
    risk_weights_json TEXT NOT NULL DEFAULT '{}',
    noise_discount REAL NOT NULL DEFAULT 1.0,
    status TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'REVIEWED', 'RESOLVED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(record_id)
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts(risk);
CREATE TABLE IF NOT EXISTS telemetry_runs (
    run_id TEXT PRIMARY KEY,
    input_source TEXT NOT NULL,
    input_format TEXT NOT NULL,
    total_lines INTEGER NOT NULL,
    valid_records INTEGER NOT NULL,
    malformed_records INTEGER NOT NULL,
    noise_records INTEGER NOT NULL,
    dropped_noise_records INTEGER NOT NULL,
    alerts_generated INTEGER NOT NULL,
    max_risk_score INTEGER NOT NULL CHECK (max_risk_score BETWEEN 0 AND 100),
    policy_threshold INTEGER,
    policy_breach INTEGER NOT NULL CHECK (policy_breach IN (0, 1)),
    exit_code INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_runs_created_at ON telemetry_runs(created_at);
CREATE TABLE IF NOT EXISTS alert_status_history (
    change_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(alert_id),
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_status_history_alert ON alert_status_history(alert_id, changed_at);
"""


class EventStore:
    def __init__(self, location: str | Path) -> None:
        if str(location) != ":memory:":
            Path(location).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(location))
        self.connection.execute("PRAGMA busy_timeout = 3000")
        self.connection.executescript(SCHEMA)
        columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(alerts)")
        }
        for name, definition in (
            ("model_version", "TEXT NOT NULL DEFAULT '1'"),
            ("detector_version", "TEXT NOT NULL DEFAULT 'robust-mad'"),
            ("risk_components_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("feature_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("probabilities_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("raw_event_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("risk_weights_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("noise_discount", "REAL NOT NULL DEFAULT 1.0"),
            ("status", "TEXT NOT NULL DEFAULT 'NEW'"),
        ):
            if name not in columns:
                self.connection.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)"
        )
        self.connection.commit()

    def save(self, result: dict[str, Any]) -> None:
        event = result["event"]
        with self.connection:
            self.connection.execute(
                """INSERT INTO events
                (record_id, timestamp, source_ip, destination_ip, event_type, risk, predicted_class, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(record_id) DO UPDATE SET
                    timestamp=excluded.timestamp,
                    source_ip=excluded.source_ip,
                    destination_ip=excluded.destination_ip,
                    event_type=excluded.event_type,
                    risk=excluded.risk,
                    predicted_class=excluded.predicted_class,
                    raw_json=excluded.raw_json""",
                (
                    event["record_id"],
                    event["timestamp"],
                    event["source_ip"],
                    event["destination_ip"],
                    event["event_type"],
                    result["risk"],
                    result["predicted_class"],
                    json.dumps(event["raw"], sort_keys=True),
                ),
            )
            self.connection.execute(
                """INSERT INTO alerts
                (record_id, risk, band, predicted_class, confidence, anomaly_score,
                 evidence_json, model_version, detector_version, risk_components_json,
                 feature_json, probabilities_json, raw_event_ids_json,
                 risk_weights_json, noise_discount)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(record_id) DO UPDATE SET
                    risk=excluded.risk,
                    band=excluded.band,
                    predicted_class=excluded.predicted_class,
                    confidence=excluded.confidence,
                    anomaly_score=excluded.anomaly_score,
                    evidence_json=excluded.evidence_json,
                    model_version=excluded.model_version,
                    detector_version=excluded.detector_version,
                    risk_components_json=excluded.risk_components_json,
                    feature_json=excluded.feature_json,
                    probabilities_json=excluded.probabilities_json,
                    raw_event_ids_json=excluded.raw_event_ids_json,
                    risk_weights_json=excluded.risk_weights_json,
                    noise_discount=excluded.noise_discount""",
                (
                    event["record_id"],
                    result["risk"],
                    result["band"],
                    result["predicted_class"],
                    result["confidence"],
                    result["anomaly_score"],
                    json.dumps(result["evidence"], sort_keys=True),
                    result["model_version"],
                    result.get("detector", "robust-mad"),
                    json.dumps(result.get("risk_components", {}), sort_keys=True),
                    json.dumps(result["features"], sort_keys=True),
                    json.dumps(result["model_probabilities"], sort_keys=True),
                    json.dumps(result.get("raw_event_ids", [event["record_id"]]), sort_keys=True),
                    json.dumps(result.get("risk_weights", {}), sort_keys=True),
                    result.get("noise_discount", 1.0),
                ),
            )

    def update_status(self, alert_id: int, status: str) -> None:
        if status not in {"NEW", "REVIEWED", "RESOLVED"}:
            raise ValueError("status must be NEW, REVIEWED, or RESOLVED.")
        with self.connection:
            row = self.connection.execute(
                "SELECT status FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"Alert {alert_id} does not exist.")
            previous_status = row[0]
            cursor = self.connection.execute(
                "UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id)
            )
            if cursor.rowcount:
                self.connection.execute(
                    """INSERT INTO alert_status_history
                    (alert_id, previous_status, new_status) VALUES (?, ?, ?)""",
                    (alert_id, previous_status, status),
                )

    def save_run(self, run: dict[str, Any]) -> None:
        with self.connection:
            self.connection.execute(
                """INSERT INTO telemetry_runs
                (run_id, input_source, input_format, total_lines, valid_records,
                 malformed_records, noise_records, dropped_noise_records,
                 alerts_generated, max_risk_score, policy_threshold, policy_breach, exit_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run["run_id"], run["input_source"], run["input_format"],
                    run["total_lines"], run["valid_records"], run["malformed_records"],
                    run["noise_records"], run["dropped_noise_records"],
                    run["alerts_generated"], run["max_risk_score"],
                    run["policy_threshold"], int(run["policy_breach"]), run["exit_code"],
                ),
            )

    def close(self) -> None:
        self.connection.close()