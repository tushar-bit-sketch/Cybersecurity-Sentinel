"""HTTP and real-subprocess tests for the local dashboard."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sentinel.cli import DEFAULT_DEMO, DEFAULT_MODEL, main
from sentinel.web import create_server


class DashboardTests(unittest.TestCase):
    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.temp_dir = temporary_directory.name
        self.database = Path(self.temp_dir) / "web-audit.sqlite3"
        self.server = create_server("127.0.0.1", 0, self.database, DEFAULT_MODEL, DEFAULT_DEMO)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request_json(self, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"} if data is not None else {},
        )
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())

    def test_dashboard_serves_ui_and_real_scan_populates_audit_history(self):
        with urlopen(self.base_url + "/", timeout=5) as response:
            page = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn("Threat observability", page)
            self.assertIn("Risk trace", page)
            self.assertIn("/api/scan", page)

        status, started = self.request_json("/api/scan", {"source": "demo"})
        self.assertEqual(status, 202)
        self.assertEqual(started["status"], "running")
        job_id = started["job_id"]
        offset = 0
        scored = []
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            _, current = self.request_json(f"/api/scan/{job_id}?offset={offset}")
            scored.extend(current["events"])
            offset += len(current["events"])
            if current["status"] != "running":
                break
            time.sleep(0.05)
        else:
            self.fail("Dashboard scan did not finish within 20 seconds.")

        self.assertEqual(current["status"], "complete", current)
        self.assertEqual(current["exit_code"], 0)
        self.assertEqual(current["processed"], 34)
        self.assertIn("summary: accepted=34 rejected=2", current["summary"])
        self.assertEqual(len(scored), 34)
        self.assertTrue(all(0 <= item["risk"] <= 100 for item in scored))
        self.assertTrue(all(item["features"] and item["evidence"] for item in scored))
        self.assertTrue(any("warning: line " in line for line in current["stderr"]))

        _, history = self.request_json("/api/history")
        self.assertEqual(len(history["alerts"]), 34)
        self.assertTrue(history["alerts"][0]["evidence"])
        alert_id = history["alerts"][0]["alert_id"]
        _, detail = self.request_json(f"/api/alerts/{alert_id}")
        self.assertIn("raw", detail)
        self.assertIn("feature", detail)
        self.assertIn("probabilities", detail)
        self.assertIn("related_records", detail)
        _, updated = self.request_json(
            f"/api/alerts/{alert_id}/status", {"status": "REVIEWED"}
        )
        self.assertEqual(updated["status"], "REVIEWED")
        _, history = self.request_json("/api/history")
        self.assertEqual(history["alerts"][0]["status"], "REVIEWED")
        _, detail_after_triage = self.request_json(f"/api/alerts/{alert_id}")
        self.assertEqual(detail_after_triage["status_history"][0]["new_status"], "REVIEWED")
        _, summary = self.request_json("/api/summary")
        self.assertEqual(summary["total_events"], 34)
        self.assertEqual(summary["total_alerts"], 34)
        self.assertEqual(summary["pending_triage"], 33)
        self.assertEqual(summary["policy_status"], "NOT CONFIGURED")
        self.assertTrue(self.database.exists())

    def test_upload_validation_and_loopback_binding(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            create_server("0.0.0.0", 8765, self.database, DEFAULT_MODEL, DEFAULT_DEMO)

        for payload in (
            {"source": "upload", "data": ""},
            {"source": "path", "path": str(DEFAULT_DEMO)},
            {"source": "scenario", "scenario": ["..", "outside"]},
        ):
            with self.assertRaises(HTTPError) as raised:
                self.request_json("/api/scan", payload)
            self.assertEqual(raised.exception.code, 400)
            error = json.loads(raised.exception.read())
            self.assertIn("error", error)

    def test_bundled_scenario_replay_uses_real_scanner_and_policy_gate(self):
        status, started = self.request_json(
            "/api/scan", {"source": "scenario", "scenario": "dataexfiltration", "max_risk": 0}
        )
        self.assertEqual(status, 202)
        job_id = started["job_id"]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            _, current = self.request_json(f"/api/scan/{job_id}?offset=0")
            if current["status"] != "running":
                break
            time.sleep(0.05)
        else:
            self.fail("Scenario replay did not finish.")
        self.assertEqual(current["status"], "complete")
        self.assertEqual(current["exit_code"], 2)
        _, summary = self.request_json("/api/summary")
        self.assertEqual(summary["policy_status"], "BREACH")
        self.assertTrue(summary["latest_run"]["policy_breach"])

    def test_dashboard_noise_drop_is_counted_in_run_summary(self):
        _, started = self.request_json(
            "/api/scan", {"source": "scenario", "scenario": "noise", "drop_noise": True}
        )
        job_id = started["job_id"]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            _, current = self.request_json(f"/api/scan/{job_id}?offset=0")
            if current["status"] != "running":
                break
            time.sleep(0.05)
        else:
            self.fail("Noise scenario replay did not finish.")
        self.assertEqual(current["status"], "complete")
        self.assertEqual(current["processed"], 0)
        self.assertIn("dropped_noise=7", current["summary"])
        _, summary = self.request_json("/api/summary")
        self.assertEqual(summary["latest_run"]["noise_records"], 7)
        self.assertEqual(summary["latest_run"]["dropped_noise_records"], 7)

    def test_cross_origin_scan_is_rejected(self):
        request = Request(
            self.base_url + "/api/scan",
            data=json.dumps({"source": "demo"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Origin": "https://attacker.example",
            },
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 403)

    def test_cli_web_rejects_non_loopback_without_starting_server(self):
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            result = main(["web", "--host", "0.0.0.0"])
        self.assertEqual(result, 1)
        self.assertIn("loopback", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
