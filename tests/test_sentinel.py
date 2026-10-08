"""Contract tests for the telemetry sentinel (standard library only)."""
from __future__ import annotations
import contextlib
import io
import json
import tempfile
import unittest
import contextlib
from pathlib import Path
from sentinel.cli import main
from sentinel.models import train_model
from sentinel.scoring import assess
from sentinel.storage import EventStore
from sentinel.telemetry import FeatureEngine, read_jsonl

ROOT = Path(__file__).resolve().parents[1]

class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.training = ROOT / "data" / "training.jsonl"
        self.rows = []
        engine = FeatureEngine()
        with self.training.open(encoding="utf-8") as stream:
            for _, event, error in read_jsonl(stream):
                if not error:
                    self.rows.append((engine.features_for(event), event["label"]))
        self.model = train_model(self.rows)

    def test_training_has_multiclass_and_probabilities(self):
        self.assertGreaterEqual(len(self.model["classes"]), 5)
        self.assertIn("Normal", self.model["classes"])
        self.assertIn("LateralMovement", self.model["classes"])
        self.assertIn("DataExfiltration", self.model["classes"])
        from sentinel.models import classify
        probabilities = classify(self.model, self.rows[-1][0])
        self.assertAlmostEqual(sum(probabilities.values()), 1.0, places=8)
        self.assertTrue(all(0 <= p <= 1 for p in probabilities.values()))

    def test_bad_record_does_not_prevent_following_valid_record(self):
        sample = json.dumps({"timestamp":"2026-10-08T10:00:00Z","event_type":"network","source_ip":"192.0.2.1"})
        parsed = list(read_jsonl(["not json\n", sample + "\n"]))
        self.assertIsNotNone(parsed[0][2])
        self.assertIsNone(parsed[1][2])
        self.assertEqual(parsed[1][1]["source_ip"], "192.0.2.1")
        repeated = list(read_jsonl([sample + "\n", sample + "\n"]))
        self.assertNotEqual(repeated[0][1]["record_id"], repeated[1][1]["record_id"])
    def test_missing_source_and_nonfinite_counters_are_rejected(self):
        rows = [
            {"timestamp": "2026-10-08T10:00:00Z", "event_type": "network"},
            {"timestamp": "2026-10-08T10:00:00Z", "event_type": "network", "source_ip": "192.0.2.1", "bytes": float("inf")},
        ]
        for row in rows:
            _, event, error = next(read_jsonl([json.dumps(row)]))
            self.assertIsNone(event)
            self.assertIsNotNone(error)
    def test_unlabeled_record_is_not_silently_trained_as_normal(self):
        from sentinel.cli import _training_rows
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unlabeled.jsonl"
            path.write_text(
                '{"timestamp":"2026-10-08T10:00:00Z","event_type":"network","source_ip":"192.0.2.2"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "missing a label"):
                _training_rows(path)

    def test_risk_is_deterministic_bounded_and_evidence_linked(self):
        engine = FeatureEngine()
        event = None
        features = None
        for _, candidate, error in read_jsonl((ROOT/"data"/"training.jsonl").read_text(encoding="utf-8").splitlines()):
            if not error and candidate["label"] == "DataExfiltration":
                event = candidate
                features = engine.features_for(candidate)
                break
        first = assess(event, features, self.model)
        second = assess(event, features, self.model)
        self.assertEqual(first["risk"], second["risk"])
        self.assertGreaterEqual(first["risk"], 0)
        self.assertLessEqual(first["risk"], 100)
        self.assertTrue(first["evidence"])
        self.assertTrue(all(item["record_id"] == event["record_id"] for item in first["evidence"]))

    def test_sqlite_audit_persistence(self):
        engine=FeatureEngine()
        _,event,error=next(read_jsonl((ROOT/"data"/"training.jsonl").read_text(encoding="utf-8").splitlines()))
        self.assertIsNone(error)
        result=assess(event,engine.features_for(event),self.model)
        with tempfile.TemporaryDirectory() as tmp:
            store=EventStore(Path(tmp)/"audit.sqlite3")
            store.save(result)
            count=store.connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            stored=store.connection.execute("SELECT risk, model_version, feature_json, probabilities_json FROM alerts").fetchone()
            store.close()
        self.assertEqual(count,1)
        self.assertEqual(stored[0],result["risk"])
        self.assertEqual(stored[1], result["model_version"])
        self.assertTrue(json.loads(stored[2]))
        self.assertAlmostEqual(sum(json.loads(stored[3]).values()), 1.0, places=8)

    def test_sqlite_telemetry_run_summary_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "audit.sqlite3")
            run = {
                "run_id": "run-contract",
                "input_source": "fixture.csv",
                "input_format": "csv",
                "total_lines": 4,
                "valid_records": 2,
                "malformed_records": 1,
                "noise_records": 1,
                "dropped_noise_records": 1,
                "alerts_generated": 1,
                "max_risk_score": 77,
                "policy_threshold": 70,
                "policy_breach": True,
                "exit_code": 2,
            }
            store.save_run(run)
            saved = store.connection.execute(
                "SELECT input_format, valid_records, noise_records, policy_breach, exit_code "
                "FROM telemetry_runs WHERE run_id='run-contract'"
            ).fetchone()
            store.close()
        self.assertEqual(tuple(saved), ("csv", 2, 1, 1, 2))

    def test_cli_csv_scan_autodetection_and_audit_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "events.csv"
            input_path.write_text(
                "timestamp,event_type,source_ip,destination_ip,destination_port,protocol,bytes,packets\n"
                "1700000000,FLOW,192.0.2.4,198.51.100.9,443,tcp,300,2\n",
                encoding="utf-8",
            )
            database = Path(tmp) / "audit.sqlite3"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = main([
                    "scan", "--input", str(input_path), "--model", str(ROOT / "models" / "sentinel-model.json"),
                    "--database", str(database),
                ])
            self.assertEqual(status, 0)
            import sqlite3
            with contextlib.closing(sqlite3.connect(database)) as connection:
                run = connection.execute(
                    "SELECT input_format, total_lines, valid_records FROM telemetry_runs"
                ).fetchone()
            self.assertEqual(run, ("csv", 2, 1))

    def test_cli_can_drop_tagged_noise_without_stopping_later_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "noise.jsonl"
            noise = {
                "timestamp": "2026-10-08T10:00:00Z", "event_type": "network",
                "source_ip": "192.0.2.4", "destination_ip": "224.0.0.251",
                "destination_port": 5353, "protocol": "udp",
            }
            normal = {
                "timestamp": "2026-10-08T10:00:01Z", "event_type": "network",
                "source_ip": "192.0.2.4", "destination_ip": "198.51.100.9",
                "destination_port": 443, "protocol": "tcp",
            }
            input_path.write_text(
                json.dumps(noise) + "\n{broken\n" + json.dumps(normal) + "\n",
                encoding="utf-8",
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = main([
                    "scan", "--input", str(input_path), "--model", str(ROOT / "models" / "sentinel-model.json"),
                    "--no-database", "--drop-noise", "--format", "json",
                ])
            rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual(status, 0)
            self.assertEqual(len(rows), 1)
            self.assertIn("dropped_noise=1", stderr.getvalue())
            self.assertIn("rejected=1", stderr.getvalue())

    def test_cli_train_scan_recovery_and_risk_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            model=Path(tmp)/"model.json"
            database=Path(tmp)/"audit.sqlite3"
            stdout,stderr=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                train_rc=main(["train","--input",str(self.training),"--output",str(model)])
            self.assertEqual(train_rc,0)
            self.assertTrue(model.exists())
            stdout,stderr=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                scan_rc=main(["scan","--input",str(ROOT/"data"/"demo.jsonl"),"--model",str(model),"--database",str(database),"--format","json","--max-risk","0"])
            self.assertEqual(scan_rc,2,stderr.getvalue())
            self.assertIn("continuing",stderr.getvalue())
            expected = sum(1 for _, event, error in read_jsonl((ROOT/"data"/"demo.jsonl").read_text(encoding="utf-8").splitlines()) if not error)
            self.assertIn(f"accepted={expected} rejected=2", stderr.getvalue())
            outputs=[json.loads(line) for line in stdout.getvalue().splitlines() if line.startswith("{")]
            self.assertEqual(len(outputs),expected)
            self.assertTrue(any(item["risk"]>0 for item in outputs))
            self.assertTrue(database.exists())

if __name__ == "__main__":
    unittest.main()
