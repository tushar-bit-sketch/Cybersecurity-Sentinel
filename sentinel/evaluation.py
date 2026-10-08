"""Deterministic metrics for labeled, synthetic telemetry replay datasets."""

from __future__ import annotations

from typing import Any

from .models import THREAT_CLASSES, anomaly_score, classify
from .telemetry import FeatureEngine


def _prf(true_positive: int, false_positive: int, false_negative: int) -> dict[str, float]:
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def evaluate_model(
    model: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    anomaly_threshold: float | None = None,
    dataset_name: str = "labeled evaluation input",
) -> dict[str, Any]:
    labels = list(THREAT_CLASSES)
    confusion = {actual: {predicted: 0 for predicted in labels} for actual in labels}
    anomaly_confusion = {"Normal": {"Normal": 0, "Anomaly": 0}, "Threat": {"Normal": 0, "Anomaly": 0}}
    engine = FeatureEngine()
    correct = false_positive = false_negative = anomaly_correct = 0
    per_class_counts = {label: {"tp": 0, "fp": 0, "fn": 0, "support": 0} for label in labels}
    detector_threshold = anomaly_threshold
    if detector_threshold is None:
        detector_threshold = float(model.get("anomaly_detector", {}).get("threshold", 0.6))

    for event in records:
        actual = event["label"]
        if actual not in labels:
            continue
        features = engine.features_for(event)
        probabilities = classify(model, features)
        predicted = max(probabilities, key=probabilities.get)
        confusion[actual][predicted] += 1
        per_class_counts[actual]["support"] += 1
        if predicted == actual:
            correct += 1
            per_class_counts[actual]["tp"] += 1
        else:
            per_class_counts[predicted]["fp"] += 1
            per_class_counts[actual]["fn"] += 1

        actual_anomaly = "Normal" if actual == "Normal" else "Threat"
        predicted_anomaly = "Anomaly" if anomaly_score(model, features) >= detector_threshold else "Normal"
        anomaly_confusion[actual_anomaly][predicted_anomaly] += 1
        anomaly_correct += (
            (actual_anomaly == "Normal" and predicted_anomaly == "Normal")
            or (actual_anomaly == "Threat" and predicted_anomaly == "Anomaly")
        )
        false_positive += actual == "Normal" and predicted != "Normal"
        false_negative += actual != "Normal" and predicted == "Normal"

    count = sum(per_class_counts[label]["support"] for label in labels)
    if not count:
        raise ValueError("Evaluation data contains no labeled supported records.")
    per_class = {
        label: {
            **_prf(per_class_counts[label]["tp"], per_class_counts[label]["fp"], per_class_counts[label]["fn"]),
            "support": per_class_counts[label]["support"],
        }
        for label in labels
    }
    macro_f1 = sum(metrics["f1"] for metrics in per_class.values()) / len(labels)
    anomaly_tp = anomaly_confusion["Threat"]["Anomaly"]
    anomaly_fp = anomaly_confusion["Normal"]["Anomaly"]
    anomaly_fn = anomaly_confusion["Threat"]["Normal"]
    anomaly_metrics = _prf(anomaly_tp, anomaly_fp, anomaly_fn)
    return {
        "dataset": dataset_name,
        "evaluated_records": count,
        "accuracy": correct / count,
        "macro_f1": macro_f1,
        "per_class": per_class,
        "confusion_matrix": confusion,
        "false_positive_count": false_positive,
        "false_negative_count": false_negative,
        "anomaly": {
            **anomaly_metrics,
            "accuracy": anomaly_correct / count,
            "threshold": detector_threshold,
            "confusion_matrix": anomaly_confusion,
            "detector": model.get("anomaly_detector", {}).get("name", "robust-mad"),
        },
    }
