"""Expanded taxonomy, adversarial-input, feature, model, and evaluation contracts."""
from __future__ import annotations

import json
import copy
import tempfile
import unittest
from pathlib import Path

from sentinel.evaluation import evaluate_model
from sentinel.models import anomaly_score, classify, load_model, save_model, train_model
from sentinel.scoring import assess
from sentinel.synthetic import generate_fixtures, generate_records
from sentinel.telemetry import FeatureEngine, normalize, read_csv, read_jsonl

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "sentinel-model.json"


def make_event(
    seconds: int,
    *,
    source: str = "10.0.0.7",
    destination: str = "10.0.0.8",
    kind: str = "network",
    port: int = 443,
    **extra,
):
    payload = {
        "timestamp": f"2026-10-08T10:00:{seconds:02d}Z",
        "event_type": kind,
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": port,
        **extra,
    }
    _, event, error = next(read_jsonl([json.dumps(payload)]))
    if error:
        raise AssertionError(error)
    return event


class HostileInputTests(unittest.TestCase):
    def invalid(self, payload, expected=None):
        _, event, error = next(read_jsonl([json.dumps(payload)]))
        self.assertIsNone(event)
        self.assertTrue(error)
        if expected:
            self.assertIn(expected, error)

    def base(self):
        return {"timestamp": "2026-10-08T10:00:00Z", "event_type": "network", "source_ip": "192.0.2.8"}

    def test_missing_timestamp_is_rejected(self):
        item = self.base(); item.pop("timestamp")
        self.invalid(item, "timestamp")

    def test_invalid_ip_address_is_rejected(self):
        item = self.base(); item["source_ip"] = "999.1.1.1"
        self.invalid(item, "valid IPv4")

    def test_invalid_destination_address_is_rejected(self):
        item = self.base(); item["destination_ip"] = "host.example"
        self.invalid(item, "destination_ip")

    def test_invalid_port_is_rejected(self):
        item = self.base(); item["destination_port"] = 65536
        self.invalid(item, "destination_port")

    def test_negative_bytes_are_rejected(self):
        item = self.base(); item["bytes"] = -1
        self.invalid(item, "bytes")

    def test_non_numeric_counter_is_rejected(self):
        item = self.base(); item["packets"] = "many"
        self.invalid(item, "packets")

    def test_nan_constant_is_rejected_as_invalid_json(self):
        line = '{"timestamp":"2026-10-08T10:00:00Z","event_type":"network","source_ip":"192.0.2.8","bytes":NaN}'
        _, event, error = next(read_jsonl([line]))
        self.assertIsNone(event)
        self.assertIn("non-standard numeric", error)

    def test_infinity_constant_is_rejected_as_invalid_json(self):
        line = '{"timestamp":"2026-10-08T10:00:00Z","event_type":"network","source_ip":"192.0.2.8","bytes":Infinity}'
        _, event, error = next(read_jsonl([line]))
        self.assertIsNone(event)
        self.assertIn("non-standard numeric", error)

    def test_extremely_large_counter_is_rejected(self):
        item = self.base(); item["bytes"] = 2**128
        self.invalid(item, "bytes")

    def test_unexpected_fields_are_preserved_and_accepted(self):
        item = self.base(); item["vendor_extension"] = {"trace": [1, 2, 3]}
        event = normalize(item, 4)
        self.assertEqual(event["raw"]["vendor_extension"]["trace"], [1, 2, 3])

    def test_duplicate_rows_get_distinct_provenance_ids(self):
        item = json.dumps(self.base())
        parsed = list(read_jsonl([item, item]))
        self.assertNotEqual(parsed[0][1]["record_id"], parsed[1][1]["record_id"])

    def test_unknown_event_type_is_skipped_and_following_valid_row_survives(self):
        unknown = self.base(); unknown["event_type"] = "made_up"
        valid = self.base()
        parsed = list(read_jsonl([json.dumps(unknown), json.dumps(valid)]))
        self.assertIsNotNone(parsed[0][2])
        self.assertIsNone(parsed[1][2])

    def test_timestamp_without_zone_is_normalized_as_utc(self):
        event = normalize({"timestamp": "2026-10-08T10:00:00", "event_type": "network", "source_ip": "192.0.2.1"}, 1)
        self.assertTrue(event["timestamp"].endswith("Z"))

    def test_event_aliases_are_normalized(self):
        event = normalize({"time": "2026-10-08T10:00:00Z", "type": "network", "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2"}, 1)
        self.assertEqual((event["source_ip"], event["destination_ip"]), ("192.0.2.1", "192.0.2.2"))

    def test_epoch_seconds_and_milliseconds_are_normalized(self):
        seconds = normalize({"timestamp": 1_700_000_000, "event_type": "network", "source_ip": "192.0.2.1"}, 1)
        millis = normalize({"timestamp": 1_700_000_000_000, "event_type": "network", "source_ip": "192.0.2.1"}, 1)
        self.assertEqual(seconds["timestamp"], millis["timestamp"])

    def test_reference_label_aliases_become_canonical_classes(self):
        for label, expected in (
            ("Port Scan", "PortScan"), ("Brute Force", "BruteForce"),
            ("Lateral Movement", "LateralMovement"),
            ("Data Exfiltration", "DataExfiltration"),
        ):
            event = normalize({
                "timestamp": "2026-10-08T10:00:00Z",
                "event_type": "FLOW", "source_ip": "192.0.2.1", "label": label,
            }, 1)
            self.assertEqual(event["label"], expected)

    def test_csv_parser_uses_aliases_and_recovers_after_invalid_row(self):
        rows = list(read_csv([
            "time,type,src,dst,dport,protocol,auth_status,label\n",
            "1700000000,FLOW,192.0.2.1,192.0.2.2,22,tcp,FAILURE,Brute Force\n",
            "bad,network,invalid,192.0.2.2,22,tcp,NONE,Normal\n",
            "1700000002,FLOW,192.0.2.1,192.0.2.3,443,tcp,NONE,Normal\n",
        ]))
        self.assertEqual(rows[0][1]["label"], "BruteForce")
        self.assertIsNotNone(rows[1][2])
        self.assertIsNone(rows[2][2])
        self.assertEqual(rows[2][1]["source_ip"], "192.0.2.1")

    def test_known_background_noise_is_tagged_with_reasons(self):
        event = normalize({
            "timestamp": "2026-10-08T10:00:00Z",
            "event_type": "network", "source_ip": "192.0.2.1",
            "destination_ip": "224.0.0.251", "destination_port": 5353,
            "protocol": "udp",
        }, 1)
        self.assertTrue(event["is_noise"])
        self.assertTrue(any("5353" in reason for reason in event["noise_reasons"]))


class BehavioralFeatureTests(unittest.TestCase):
    def test_event_counts_are_source_scoped(self):
        engine = FeatureEngine()
        engine.features_for(make_event(0))
        features = engine.features_for(make_event(1, source="10.0.0.9"))
        self.assertEqual(features["window_event_count"], 1)

    def test_short_and_medium_window_rates(self):
        engine = FeatureEngine()
        engine.features_for(make_event(0))
        features = engine.features_for(make_event(20))
        self.assertEqual(features["window_short_event_count"], 2)
        self.assertEqual(features["window_medium_event_count"], 2)

    def test_older_records_expire_from_short_window(self):
        engine = FeatureEngine()
        engine.features_for(make_event(0))
        features = engine.features_for(make_event(45))
        self.assertEqual(features["window_short_event_count"], 1)

    def test_destination_and_service_diversity_are_counted(self):
        engine = FeatureEngine()
        engine.features_for(make_event(0, destination="10.0.0.9", port=22))
        features = engine.features_for(make_event(1, destination="10.0.0.10", port=443))
        self.assertEqual(features["window_unique_destinations"], 2)
        self.assertEqual(features["window_unique_services"], 2)

    def test_authentication_failure_and_success_counters(self):
        engine = FeatureEngine()
        engine.features_for(make_event(0, kind="auth", success=False, user="alice"))
        features = engine.features_for(make_event(1, kind="auth", success=True, user="alice"))
        self.assertEqual(features["window_failed_auth"], 1)
        self.assertEqual(features["window_successful_auth"], 1)
        self.assertEqual(features["window_failure_ratio"], 0.5)

    def test_directional_byte_counters_and_transfer_ratio(self):
        engine = FeatureEngine()
        features = engine.features_for(make_event(0, bytes_sent=8000, bytes_received=1000, direction="outbound"))
        self.assertEqual(features["window_bytes_sent"], 8000)
        self.assertEqual(features["window_bytes_received"], 1000)
        self.assertEqual(features["window_outbound_inbound_ratio"], 8)

    def test_relationship_novelty_changes_on_repeat(self):
        engine = FeatureEngine()
        first = engine.features_for(make_event(0, destination="10.0.0.20"))
        repeated = engine.features_for(make_event(1, destination="10.0.0.20"))
        self.assertEqual(first["source_destination_pair_novelty"], 1)
        self.assertEqual(repeated["source_destination_pair_novelty"], 0)

    def test_new_internal_admin_peers_are_counted(self):
        engine = FeatureEngine()
        for second, target in enumerate(("10.1.0.2", "10.1.0.3", "10.1.0.4")):
            features = engine.features_for(make_event(second, destination=target, port=445))
        self.assertEqual(features["window_new_internal_peers_60s"], 3)
        self.assertGreaterEqual(features["window_admin_service_access_60s"], 3)

    def test_internal_networks_are_configurable(self):
        engine = FeatureEngine(internal_networks=("172.20.0.0/16",))
        features = engine.features_for(make_event(0, destination="172.20.1.4", port=22))
        self.assertEqual(features["window_internal_peers"], 1)

    def test_noise_event_types_parse(self):
        for kind in ("dns", "dhcp", "arp", "multicast", "monitoring", "scheduled_job"):
            event = make_event(1, kind=kind, destination="224.0.0.251" if kind == "multicast" else "192.0.2.53")
            self.assertEqual(event["event_type"], kind)

    def test_history_cap_bounds_per_source_memory(self):
        engine = FeatureEngine(max_history=2)
        for second in range(5):
            engine.features_for(make_event(second))
        self.assertLessEqual(len(engine.events["10.0.0.7"]), 2)

    def test_service_access_counts_admin_port_attempts(self):
        engine = FeatureEngine()
        engine.features_for(make_event(0, destination="10.0.0.10", port=3389))
        features = engine.features_for(make_event(1, destination="10.0.0.11", port=22))
        self.assertEqual(features["window_admin_port_coverage"], 2)

    def test_reference_behavioral_features_are_available_in_stable_values(self):
        engine = FeatureEngine(window_seconds=60)
        engine.features_for(make_event(0, destination="10.0.0.9", port=22, kind="auth",
                                       success=False, bytes_sent=80, bytes_received=20,
                                       packets=3, protocol="tcp"))
        event = make_event(1, destination="10.0.0.10", port=53, kind="auth",
                           success=False, bytes_sent=160, bytes_received=40,
                           packets=5, protocol="udp")
        event["record_id"] = "record-2"
        features = engine.features_for(event)
        self.assertEqual(features["event_count"], 2)
        self.assertEqual(features["unique_dest_ips"], 2)
        self.assertEqual(features["unique_dest_ports"], 2)
        self.assertEqual(features["auth_attempts"], 2)
        self.assertEqual(features["auth_failures"], 2)
        self.assertEqual(features["total_bytes_sent"], 240)
        self.assertEqual(features["total_bytes_received"], 60)
        self.assertEqual(features["total_packets"], 8)
        self.assertEqual(features["protocol_diversity"], 2)
        self.assertEqual(len(features["window_record_ids"]), 2)
        self.assertEqual(features["window_record_ids"][-1], "record-2")


class DetectorAndPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = load_model(MODEL_PATH)
        cls.training_records = []
        with (ROOT / "data" / "training.jsonl").open(encoding="utf-8") as stream:
            for _, event, error in read_jsonl(stream):
                if not error:
                    cls.training_records.append(event)

    def test_canonical_taxonomy_contains_required_classes(self):
        self.assertTrue({"Normal", "PortScan", "BruteForce", "LateralMovement", "DataExfiltration"} <= set(self.model["classes"]))

    def test_isolation_forest_is_primary_detector_metadata(self):
        self.assertEqual(self.model["anomaly_detector"]["name"], "stdlib-isolation-forest")
        self.assertEqual(len(self.model["anomaly_detector"]["forest"]), 64)
        self.assertEqual(self.model["anomaly_detector"]["seed"], 1729)

    def test_random_forest_is_primary_classifier_with_feature_schema(self):
        self.assertEqual(self.model["classifier"]["name"], "stdlib-random-forest")
        self.assertEqual(self.model["classifier"]["tree_count"], 24)
        self.assertEqual(self.model["feature_count"], len(self.model["feature_names"]))

    def test_model_loader_rejects_inconsistent_feature_dimension(self):
        malformed = copy.deepcopy(self.model)
        malformed["feature_count"] += 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken-model.json"
            save_model(malformed, path)
            with self.assertRaisesRegex(ValueError, "schema or dimensions"):
                load_model(path)

    def test_training_requires_each_primary_threat_class(self):
        event = self.training_records[0]
        features = FeatureEngine().features_for(event)
        with self.assertRaisesRegex(ValueError, "missing required classes"):
            train_model([(features, "Normal")])

    def test_forest_probabilities_cover_all_classes_and_are_repeatable(self):
        event = self.training_records[-1]
        features = FeatureEngine().features_for(event)
        first = classify(self.model, features)
        self.assertEqual(first, classify(self.model, features))
        self.assertEqual(set(first), set(self.model["classes"]))
        self.assertAlmostEqual(sum(first.values()), 1.0, places=8)


    def test_classifier_probabilities_sum_to_one(self):
        event = self.training_records[0]
        features = FeatureEngine().features_for(event)
        self.assertAlmostEqual(sum(classify(self.model, features).values()), 1.0, places=8)

    def test_isolation_forest_score_is_bounded_and_deterministic(self):
        event = self.training_records[-1]
        features = FeatureEngine().features_for(event)
        first = anomaly_score(self.model, features)
        self.assertEqual(first, anomaly_score(self.model, features))
        self.assertTrue(0 <= first <= 1)

    def test_robust_mad_fallback_is_honestly_identified(self):
        fallback = dict(self.model)
        fallback.pop("anomaly_detector")
        event = self.training_records[0]
        features = FeatureEngine().features_for(event)
        result = assess(event, features, fallback)
        self.assertEqual(result["detector"], "robust-mad")

    def test_risk_components_sum_to_risk(self):
        event = self.training_records[-1]
        features = FeatureEngine().features_for(event)
        result = assess(event, features, self.model)
        self.assertEqual(result["risk"], round(sum(result["risk_components"].values())))

    def test_risk_weights_are_configurable_and_normalized(self):
        event = self.training_records[0]
        features = FeatureEngine().features_for(event)
        result = assess(event, features, self.model, weights={"anomaly": 1, "classifier": 1, "behavior": 2})
        self.assertAlmostEqual(sum(result["risk_weights"].values()), 1.0)

    def test_invalid_risk_weights_are_rejected(self):
        event = self.training_records[0]
        with self.assertRaises(ValueError):
            assess(event, {}, self.model, weights={"anomaly": -1, "classifier": 1, "behavior": 1})

    def test_heuristic_threshold_overrides_are_validated(self):
        event = self.training_records[-1]
        features = FeatureEngine().features_for(event)
        with self.assertRaisesRegex(ValueError, "Unknown heuristic"):
            assess(event, features, self.model, thresholds={"made_up": 1})
        with self.assertRaisesRegex(ValueError, "finite non-negative"):
            assess(event, features, self.model, thresholds={"unique_ports": float("inf")})

    def test_noise_discount_is_explicit_and_risk_components_still_reconcile(self):
        event = self.training_records[0].copy()
        event["is_noise"] = True
        event["noise_reasons"] = ["test background"]
        features = FeatureEngine().features_for(event)
        result = assess(event, features, self.model)
        self.assertEqual(result["noise_discount"], 0.65)
        self.assertEqual(result["risk"], round(sum(result["risk_components"].values())))
        self.assertTrue(any(item["feature"] == "is_noise" for item in result["evidence"]))
        self.assertTrue(all(item["raw_record_ids"] for item in result["evidence"]))

    def test_evidence_has_provenance_and_is_ranked(self):
        event = self.training_records[-1]
        features = FeatureEngine().features_for(event)
        evidence = assess(event, features, self.model)["evidence"]
        contributions = [item["contribution"] for item in evidence]
        self.assertEqual(contributions, sorted(contributions, reverse=True))
        self.assertTrue(all(item["record_id"] == event["record_id"] and item["timestamp"] and item["source_ip"] for item in evidence))

    def test_each_required_threat_fixture_is_present(self):
        labels = {event["label"] for event in self.training_records}
        self.assertTrue({"PortScan", "BruteForce", "LateralMovement", "DataExfiltration"} <= labels)

    def test_evaluation_metrics_are_reproducible_and_count_confusion(self):
        evaluation = []
        with (ROOT / "data" / "evaluation.jsonl").open(encoding="utf-8") as stream:
            for _, event, error in read_jsonl(stream):
                if not error:
                    evaluation.append(event)
        first = evaluate_model(self.model, evaluation, dataset_name="synthetic fixture")
        second = evaluate_model(self.model, evaluation, dataset_name="synthetic fixture")
        self.assertEqual(first, second)
        self.assertEqual(sum(sum(row.values()) for row in first["confusion_matrix"].values()), first["evaluated_records"])
        self.assertEqual(first["dataset"], "synthetic fixture")
        self.assertIn("accuracy", first["anomaly"])

    def test_evaluation_rejects_empty_labeled_input(self):
        with self.assertRaisesRegex(ValueError, "no labeled"):
            evaluate_model(self.model, [])

    def test_fixed_seed_synthetic_generation_is_reproducible(self):
        first = generate_records(55, 3)
        second = generate_records(55, 3)
        self.assertEqual(first, second)

    def test_fixture_generator_emits_trainable_csv(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            generate_fixtures(directory, seed=55, cases=3)
            with (directory / "training.csv").open(encoding="utf-8", newline="") as stream:
                parsed = [event for _, event, error in read_csv(stream) if not error]
            self.assertEqual(len(parsed), len(generate_records(55, 3)))
            self.assertTrue(all(event["source_ip"] for event in parsed))
            self.assertTrue(any(event["success"] is False for event in parsed))

    def test_normal_noise_categories_are_in_synthetic_dataset(self):
        labels = {event["event_type"] for event in generate_records(77, 7) if event["label"] == "Normal"}
        self.assertTrue({"dns", "dhcp", "arp", "multicast", "monitoring", "scheduled_job"} <= labels)


class ThreatEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = load_model(MODEL_PATH)

    def run_sequence(self, events):
        engine = FeatureEngine()
        result = None
        for event in events:
            features = engine.features_for(event)
            result = assess(event, features, self.model)
        return result

    def test_port_scan_evidence_reports_observed_port_fanout(self):
        rows = [
            make_event(index, destination="10.0.1.10", port=1000 + index, bytes=80)
            for index in range(7)
        ]
        result = self.run_sequence(rows)
        evidence = [item for item in result["evidence"] if item["feature"] == "window_unique_ports"]
        self.assertTrue(evidence)
        self.assertGreaterEqual(evidence[0]["value"], evidence[0]["threshold"])
        self.assertIn("unique destination ports", evidence[0]["explanation"])

    def test_brute_force_evidence_reports_real_failed_login_count(self):
        rows = [
            make_event(index, kind="auth", port=22, success=False, user=f"user{index % 3}", action="deny")
            for index in range(7)
        ]
        evidence = self.run_sequence(rows)["evidence"]
        failed = [item for item in evidence if item["feature"] == "window_failed_auth"]
        self.assertTrue(failed)
        self.assertEqual(failed[0]["value"], 7)

    def test_lateral_movement_evidence_reports_new_internal_peers(self):
        targets = [f"10.8.0.{index}" for index in range(10, 15)]
        rows = [
            make_event(index, kind="connection", destination=target, port=445, direction="internal")
            for index, target in enumerate(targets)
        ]
        evidence = self.run_sequence(rows)["evidence"]
        lateral = [item for item in evidence if item["feature"] == "window_new_internal_peers_60s"]
        self.assertTrue(lateral)
        self.assertEqual(lateral[0]["value"], 5)
        self.assertIn("previously unseen internal peers", lateral[0]["explanation"])

    def test_data_exfiltration_evidence_reports_outbound_volume(self):
        rows = [
            make_event(index, destination="198.51.10.20", bytes=600_000,
                       bytes_sent=600_000, bytes_received=10_000, direction="outbound")
            for index in range(5)
        ]
        evidence = self.run_sequence(rows)["evidence"]
        outbound = [item for item in evidence if item["feature"] == "window_bytes_sent"]
        self.assertTrue(outbound)
        self.assertGreaterEqual(outbound[0]["value"], outbound[0]["threshold"])
        self.assertIn("MB outbound", outbound[0]["explanation"])

    def test_normal_noise_does_not_dominate_suspicious_risk(self):
        records = []
        with (ROOT / "data" / "evaluation.jsonl").open(encoding="utf-8") as stream:
            for _, event, error in read_jsonl(stream):
                if not error and event["label"] == "Normal":
                    records.append(event)
        engine = FeatureEngine()
        elevated = 0
        for event in records:
            result = assess(event, engine.features_for(event), self.model)
            elevated += result["band"] != "Normal"
        self.assertLess(elevated, len(records) / 2)


if __name__ == "__main__":
    unittest.main()
