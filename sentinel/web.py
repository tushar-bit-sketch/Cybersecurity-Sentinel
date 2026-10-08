"""Loopback-only web dashboard that runs the real sentinel scanner."""

from __future__ import annotations

import ipaddress
import contextlib
import json
import sqlite3
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .cli import DEFAULT_SCENARIOS, PROJECT_ROOT
from .storage import EventStore


MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 5_000
MAX_JOB_EVENTS = 5_000
SCAN_TIMEOUT_SECONDS = 120
PAGE = Path(__file__).with_name("dashboard.html")
SCENARIOS = {
    "normal": "normal.jsonl",
    "portscan": "portscan.jsonl",
    "bruteforce": "bruteforce.jsonl",
    "lateralmovement": "lateralmovement.jsonl",
    "dataexfiltration": "dataexfiltration.jsonl",
    "beaconing": "beaconing.jsonl",
    "noise": "noise.jsonl",
    "hostile": "hostile.jsonl",
}


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        database: Path,
        model: Path,
        demo: Path,
    ) -> None:
        self.database = database
        self.model = model
        self.demo = demo
        self.job_lock = threading.Lock()
        self.job: dict[str, Any] | None = None
        super().__init__(address, DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"[dashboard] {self.address_string()} {format % args}\n")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _valid_local_origin(self, value: str | None) -> bool:
        allowed_hosts = {"localhost", "127.0.0.1", "::1"}
        try:
            host_header = urlsplit(f"//{self.headers.get('Host', '')}")
            origin = urlsplit(value) if value else None
            expected_port = self.server.server_port
            if host_header.hostname not in allowed_hosts or host_header.port != expected_port:
                return False
            if origin is None:
                return True
            if (
                origin.scheme != "http"
                or origin.hostname not in allowed_hosts
                or origin.hostname != host_header.hostname
                or origin.username is not None
                or origin.password is not None
            ):
                return False
            origin_port = origin.port or 80
            return origin_port == expected_port
        except ValueError:
            return False

    def do_GET(self) -> None:
        if not self._valid_local_origin(None):
            self._json(403, {"error": "Requests must use the local dashboard host and port."})
            return
        parsed = urlsplit(self.path)
        if parsed.path in ("/", "/dashboard.html"):
            try:
                self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            except OSError as error:
                self._json(500, {"error": f"Cannot read dashboard page: {error}"})
            return
        if parsed.path == "/api/history":
            self._history()
            return
        if parsed.path == "/api/summary":
            self._summary()
            return
        if parsed.path.startswith("/api/alerts/") and parsed.path.count("/") == 3:
            self._alert_detail(parsed.path.removeprefix("/api/alerts/"))
            return
        if parsed.path.startswith("/api/scan/"):
            self._job(parsed.path.removeprefix("/api/scan/"), parse_qs(parsed.query))
            return
        self._json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if not self._valid_local_origin(self.headers.get("Origin")):
            self._json(403, {"error": "Cross-origin or non-local requests are not allowed."})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "Content-Type must be application/json."})
            return
        parsed = urlsplit(self.path)
        if parsed.path.startswith("/api/alerts/") and parsed.path.endswith("/status"):
            self._update_alert_status(parsed.path)
            return
        if parsed.path != "/api/scan":
            self._json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_REQUEST_BYTES:
                self._json(413, {"error": f"Request must be between 1 byte and {MAX_REQUEST_BYTES} bytes."})
                return
            request = json.loads(
                self.rfile.read(length),
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Invalid JSON number: {value}")),
            )
            if not isinstance(request, dict):
                raise ValueError("Request body must be a JSON object.")
            source = request.get("source", "demo")
            if source == "demo":
                input_data = self.server.demo.read_text(encoding="utf-8")
            elif source == "scenario":
                scenario = request.get("scenario")
                if not isinstance(scenario, str) or scenario not in SCENARIOS:
                    raise ValueError("Scenario must be one of the bundled replay choices.")
                input_data = (
                    DEFAULT_SCENARIOS / SCENARIOS[scenario]
                ).read_text(encoding="utf-8")
            elif source == "upload":
                input_data = request.get("data")
                if not isinstance(input_data, str) or not input_data.strip():
                    raise ValueError("Upload source requires non-empty JSONL data.")
            else:
                raise ValueError("Source must be 'demo' or 'upload'; arbitrary paths are not accepted.")
            record_count = sum(1 for line in input_data.splitlines() if line.strip())
            if record_count > MAX_RECORDS:
                self._json(413, {"error": f"Scans are limited to {MAX_RECORDS} non-empty records."})
                return
            max_risk = request.get("max_risk")
            if max_risk is not None and (
                isinstance(max_risk, bool)
                or not isinstance(max_risk, int)
                or not 0 <= max_risk <= 100
            ):
                raise ValueError("max_risk must be an integer between 0 and 100.")
            drop_noise = request.get("drop_noise", False)
            if not isinstance(drop_noise, bool):
                raise ValueError("drop_noise must be a boolean.")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            self._json(400, {"error": str(error)})
            return

        with self.server.job_lock:
            if self.server.job and self.server.job["status"] == "running":
                self._json(409, {"error": "A scan is already running."})
                return
            job_id = uuid.uuid4().hex
            self.server.job = {
                "id": job_id,
                "status": "running",
                "phase": "Initializing scanner",
                "source": source,
                "scenario": request.get("scenario") if source == "scenario" else None,
                "max_risk": max_risk,
                "drop_noise": drop_noise,
                "total_records": record_count,
                "processed": 0,
                "events": [],
                "stderr": [],
                "summary": None,
                "exit_code": None,
                "error": None,
            }
        threading.Thread(
            target=self._run_scan,
            args=(job_id, input_data, max_risk, drop_noise),
            name=f"sentinel-scan-{job_id[:8]}",
            daemon=True,
        ).start()
        self._json(202, {"job_id": job_id, "status": "running"})

    def _run_scan(
        self, job_id: str, input_data: str, max_risk: int | None, drop_noise: bool
    ) -> None:
        with self.server.job_lock:
            if not self.server.job or self.server.job["id"] != job_id:
                return
            self.server.job["phase"] = "Analyzing telemetry"
        try:
            command = [
                    sys.executable, "-m", "sentinel", "scan",
                    "--input", "-", "--model", str(self.server.model),
                    "--database", str(self.server.database), "--format", "json",
                ]
            if max_risk is not None:
                command.extend(["--max-risk", str(max_risk)])
            if drop_noise:
                command.append("--drop-noise")
            process = subprocess.Popen(
                command,
                cwd=PROJECT_ROOT,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None

            def read_output() -> None:
                with process.stdout as stdout_stream:
                    for line in stdout_stream:
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            self._append_stderr(job_id, line.rstrip())
                            continue
                        with self.server.job_lock:
                            job = self.server.job
                            if job and job["id"] == job_id:
                                job["processed"] += 1
                                if len(job["events"]) < MAX_JOB_EVENTS:
                                    job["events"].append(event)

            def read_errors() -> None:
                with process.stderr as stderr_stream:
                    for line in stderr_stream:
                        self._append_stderr(job_id, line.rstrip())

            stdout_thread = threading.Thread(target=read_output, daemon=True)
            stderr_thread = threading.Thread(target=read_errors, daemon=True)
            stdout_thread.start()
            stderr_thread.start()
            try:
                process.stdin.write(input_data)
                process.stdin.close()
                exit_code = process.wait(timeout=SCAN_TIMEOUT_SECONDS)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                process.kill()
                process.wait()
                raise TimeoutError(f"Scanner did not finish within {SCAN_TIMEOUT_SECONDS} seconds.")
            finally:
                if not process.stdin.closed:
                    try:
                        process.stdin.close()
                    except BrokenPipeError:
                        pass
                stdout_thread.join(timeout=5)
                stderr_thread.join(timeout=5)
            with self.server.job_lock:
                job = self.server.job
                if job and job["id"] == job_id:
                    job["exit_code"] = exit_code
                    job["status"] = "complete" if exit_code in (0, 2) else "failed"
                    job["phase"] = "Scan complete" if exit_code in (0, 2) else "Scanner returned an error"
                    if exit_code not in (0, 2):
                        job["error"] = "The scanner exited with an error; see diagnostics."
        except (OSError, TimeoutError, ValueError) as error:
            with self.server.job_lock:
                job = self.server.job
                if job and job["id"] == job_id:
                    job["status"] = "failed"
                    job["phase"] = "Scan failed"
                    job["error"] = str(error)

    def _append_stderr(self, job_id: str, line: str) -> None:
        if not line:
            return
        with self.server.job_lock:
            job = self.server.job
            if not job or job["id"] != job_id:
                return
            if line.startswith("summary: "):
                job["summary"] = line[:1_000]
                if len(job["stderr"]) >= 200:
                    job["stderr"].pop()
                job["stderr"].append(job["summary"])
            elif len(job["stderr"]) < 199:
                job["stderr"].append(line[:1_000])

    def _job(self, job_id: str, query: dict[str, list[str]]) -> None:
        try:
            offset = max(0, int(query.get("offset", ["0"])[0]))
        except ValueError:
            self._json(400, {"error": "offset must be a non-negative integer."})
            return
        with self.server.job_lock:
            job = self.server.job
            if not job or job["id"] != job_id:
                self._json(404, {"error": "Scan job not found."})
                return
            response = dict(job)
            response["events"] = job["events"][offset:]
            response["event_offset"] = offset
        self._json(200, response)

    def _history(self) -> None:
        if not self.server.database.exists():
            self._json(200, {"alerts": []})
            return
        try:
            with contextlib.closing(sqlite3.connect(self.server.database, timeout=2)) as connection:
                with connection:
                    connection.row_factory = sqlite3.Row
                    rows = connection.execute(
                        """SELECT a.alert_id, a.record_id, a.risk, a.band, a.predicted_class,
                                  a.confidence, a.anomaly_score, a.evidence_json, a.created_at,
                                  a.status, a.detector_version, a.risk_components_json,
                                  a.noise_discount,
                                  e.timestamp, e.source_ip, e.destination_ip, e.event_type
                           FROM alerts a JOIN events e USING (record_id)
                           ORDER BY a.alert_id DESC LIMIT 100"""
                    ).fetchall()
            alerts = []
            for row in rows:
                item = dict(row)
                item["evidence"] = json.loads(item.pop("evidence_json"))
                item["risk_components"] = json.loads(item.pop("risk_components_json"))
                alerts.append(item)
            self._json(200, {"alerts": alerts})
        except (sqlite3.Error, json.JSONDecodeError) as error:
            self._json(500, {"error": f"Cannot load alert history: {error}"})

    def _summary(self) -> None:
        try:
            with contextlib.closing(sqlite3.connect(self.server.database, timeout=2)) as connection:
                connection.row_factory = sqlite3.Row
                total_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                total_alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                bands = {
                    row["band"]: row["count"]
                    for row in connection.execute(
                        "SELECT band, COUNT(*) AS count FROM alerts GROUP BY band"
                    )
                }
                classes = {
                    row["predicted_class"]: row["count"]
                    for row in connection.execute(
                        "SELECT predicted_class, COUNT(*) AS count FROM alerts GROUP BY predicted_class"
                    )
                }
                pending = connection.execute(
                    "SELECT COUNT(*) FROM alerts WHERE status='NEW'"
                ).fetchone()[0]
                latest = connection.execute(
                    """SELECT run_id, input_source, total_lines, valid_records, malformed_records,
                              noise_records, dropped_noise_records, alerts_generated,
                              max_risk_score, policy_threshold, policy_breach, exit_code, created_at
                       FROM telemetry_runs ORDER BY created_at DESC LIMIT 1"""
                ).fetchone()
            latest_run = dict(latest) if latest else None
            self._json(200, {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "pending_triage": pending,
                "risk_bands": bands,
                "threat_classes": classes,
                "latest_run": latest_run,
                "policy_status": (
                    "BREACH" if latest_run and latest_run["policy_breach"]
                    else "COMPLIANT" if latest_run and latest_run["policy_threshold"] is not None
                    else "NOT CONFIGURED" if latest_run else "NO SCANS"
                ),
            })
        except sqlite3.Error as error:
            self._json(500, {"error": f"Cannot load run summary: {error}"})

    def _update_alert_status(self, path: str) -> None:
        parts = path.strip("/").split("/")
        if len(parts) != 4 or parts[0:2] != ["api", "alerts"]:
            self._json(404, {"error": "Not found"})
            return
        try:
            alert_id = int(parts[2])
            length = int(self.headers.get("Content-Length", "0"))
            if alert_id < 1 or length <= 0 or length > 8_192:
                raise ValueError("Invalid alert ID or status request size.")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("Status body must be a JSON object.")
            status = body.get("status")
            if status not in {"NEW", "REVIEWED", "RESOLVED"}:
                raise ValueError("status must be NEW, REVIEWED, or RESOLVED.")
            with contextlib.closing(sqlite3.connect(self.server.database, timeout=2)) as connection:
                with connection:
                    previous = connection.execute(
                        "SELECT status FROM alerts WHERE alert_id=?", (alert_id,)
                    ).fetchone()
                    if previous is None:
                        raise ValueError(f"Alert {alert_id} does not exist.")
                    cursor = connection.execute(
                        "UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id)
                    )
                    if cursor.rowcount == 1 and previous[0] != status:
                        connection.execute(
                            """INSERT INTO alert_status_history
                            (alert_id, previous_status, new_status) VALUES (?, ?, ?)""",
                            (alert_id, previous[0], status),
                        )
            self._json(200, {"alert_id": alert_id, "status": status})
        except (ValueError, sqlite3.Error, json.JSONDecodeError) as error:
            self._json(400, {"error": str(error)})

    def _alert_detail(self, alert_id: str) -> None:
        try:
            numeric_id = int(alert_id)
            with contextlib.closing(sqlite3.connect(self.server.database, timeout=2)) as connection:
                cursor = connection.execute(
                    """SELECT a.alert_id, a.record_id, a.risk, a.band, a.predicted_class,
                              a.confidence, a.anomaly_score, a.evidence_json, a.model_version,
                              a.detector_version, a.risk_components_json, a.feature_json,
                              a.probabilities_json, a.raw_event_ids_json, a.risk_weights_json,
                              a.noise_discount, a.status, e.timestamp, e.source_ip,
                              e.destination_ip, e.event_type, e.raw_json
                       FROM alerts a JOIN events e USING(record_id) WHERE a.alert_id=?""",
                    (numeric_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    self._json(404, {"error": "Alert not found."})
                    return
                detail = dict(zip([description[0] for description in cursor.description], row))
                related = connection.execute(
                    """SELECT a.alert_id, a.record_id, a.risk, a.predicted_class, e.timestamp,
                              e.destination_ip
                       FROM alerts a JOIN events e USING(record_id)
                       WHERE e.source_ip=? AND a.alert_id<>? ORDER BY a.alert_id DESC LIMIT 20""",
                    (detail["source_ip"], numeric_id),
                ).fetchall()
            for key in (
                "evidence_json", "risk_components_json", "feature_json",
                "probabilities_json", "raw_event_ids_json", "risk_weights_json", "raw_json",
            ):
                detail[key.removesuffix("_json")] = json.loads(detail.pop(key))
            with contextlib.closing(sqlite3.connect(self.server.database, timeout=2)) as connection:
                history = connection.execute(
                    """SELECT previous_status, new_status, changed_at
                       FROM alert_status_history WHERE alert_id=? ORDER BY change_id""",
                    (numeric_id,),
                ).fetchall()
            detail["status_history"] = [
                {"previous_status": item[0], "new_status": item[1], "changed_at": item[2]}
                for item in history
            ]
            detail["related_records"] = [
                {
                    "alert_id": item[0], "record_id": item[1], "risk": item[2],
                    "predicted_class": item[3], "timestamp": item[4], "destination_ip": item[5],
                }
                for item in related
            ]
            self._json(200, detail)
        except (ValueError, sqlite3.Error, json.JSONDecodeError) as error:
            self._json(400, {"error": str(error)})


def create_server(
    host: str,
    port: int,
    database: Path,
    model: Path,
    demo: Path,
) -> DashboardServer:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        if host.lower() != "localhost":
            raise ValueError("Dashboard host must be localhost or a loopback IP address.") from error
        host = "127.0.0.1"
    else:
        if not address.is_loopback:
            raise ValueError("Dashboard binds to loopback only; remote exposure is disabled.")
    if not 0 <= port <= 65535:
        raise ValueError("Dashboard port must be between 0 and 65535.")
    store = EventStore(database)
    store.close()
    return DashboardServer((host, port), database, model, demo)


def serve(host: str, port: int, database: Path, model: Path, demo: Path) -> None:
    server = create_server(host, port, database, model, demo)
    display_host = f"[{host}]" if ":" in host else host
    print(f"Cyber Sentinel dashboard: http://{display_host}:{server.server_port}", flush=True)
    print("Local access only. Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.", flush=True)
    finally:
        server.server_close()
