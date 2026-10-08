"""Small, deterministic supervised and unsupervised models using only the stdlib."""

from __future__ import annotations

import json
import math
import random
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FEATURE_NAMES = (
    "bytes",
    "packets",
    "dst_port",
    "src_port",
    "window_event_count",
    "window_bytes",
    "window_unique_destinations",
    "window_unique_ports",
    "window_failed_auth",
    "window_denied",
    "window_failure_ratio",
    "bytes_sent",
    "bytes_received",
    "duration_ms",
    "window_bytes_sent",
    "window_bytes_received",
    "window_unique_services",
    "window_successful_auth",
    "window_failure_success_ratio",
    "window_connection_rate_30s",
    "window_connection_rate_60s",
    "window_connection_rate_300s",
    "window_short_event_count",
    "window_medium_event_count",
    "window_internal_peers",
    "window_new_internal_peers_60s",
    "window_admin_service_access_60s",
    "window_bytes_per_connection",
    "window_packets_per_connection",
    "window_outbound_inbound_ratio",
    "window_bytes_vs_prior_average",
    "destination_novelty",
    "source_destination_pair_novelty",
    "window_unique_accounts",
    "window_unique_protocols",
    "window_admin_port_coverage",
    "window_short_lived_connections",
    "interarrival_seconds",
    "window_mean_interarrival_60s",
    "window_interarrival_cv_60s",
    "event_count",
    "unique_dest_ips",
    "unique_dest_ports",
    "auth_attempts",
    "auth_failures",
    "auth_fail_ratio",
    "total_bytes_sent",
    "total_bytes_received",
    "bytes_out_ratio",
    "total_packets",
    "protocol_diversity",
    "peer_rarity_score",
    "high_port_ratio",
    "event_rate_per_sec",
    "is_noise",
)
NUMERIC_FIELDS = FEATURE_NAMES
ANOMALY_FIELDS = (
    "bytes",
    "packets",
    "window_event_count",
    "window_bytes",
    "window_unique_destinations",
    "window_unique_ports",
    "window_failed_auth",
    "window_denied",
    "window_unique_services",
    "window_new_internal_peers_60s",
    "window_admin_service_access_60s",
    "window_bytes_sent",
    "window_outbound_inbound_ratio",
    "window_bytes_vs_prior_average",
    "window_connection_rate_30s",
    "unique_dest_ips",
    "auth_fail_ratio",
    "bytes_out_ratio",
    "peer_rarity_score",
    "high_port_ratio",
    "event_rate_per_sec",
)
CATEGORICAL_FIELDS = ("event_type", "protocol", "action")
THREAT_CLASSES = ("Normal", "PortScan", "BruteForce", "LateralMovement", "DataExfiltration", "Beaconing")
REQUIRED_CLASSES = frozenset({
    "Normal", "PortScan", "BruteForce", "LateralMovement", "DataExfiltration",
})
CLASS_ALIASES = {
    "Exfiltration": "DataExfiltration",
    "Port Scan": "PortScan",
    "Brute Force": "BruteForce",
    "Lateral Movement": "LateralMovement",
    "Data Exfiltration": "DataExfiltration",
}
CLASS_SEVERITY = {
    "Normal": 0.0,
    "PortScan": 0.72,
    "BruteForce": 0.82,
    "LateralMovement": 0.88,
    "DataExfiltration": 0.92,
    "Beaconing": 0.62,
}
LEGACY_NUMERIC_FIELDS = NUMERIC_FIELDS[:11]
ISOLATION_FOREST_TREES = 64
ISOLATION_FOREST_SEED = 1729
RANDOM_FOREST_TREES = 24
RANDOM_FOREST_MAX_DEPTH = 7
RANDOM_FOREST_SEED = 1729


def _number(value: Any) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else 0.0
    except (TypeError, ValueError):
        return 0.0


def _vectorize(
    features: dict[str, Any],
    categories: dict[str, list[str]],
    numeric_fields: tuple[str, ...] | list[str] = NUMERIC_FIELDS,
) -> list[float]:
    vector = [
        math.log1p(max(0.0, _number(features.get(field, 0))))
        for field in numeric_fields
    ]
    for field in CATEGORICAL_FIELDS:
        value = str(features.get(field, "unknown"))
        vector.extend(1.0 if value == category else 0.0 for category in categories[field])
    return vector


def _mean(values: list[float]) -> float:
    return sum(values) / len(values)


def _variance(values: list[float], mean: float) -> float:
    return max(sum((value - mean) ** 2 for value in values) / len(values), 1e-6)


def _gini(counts: list[int], size: int) -> float:
    if not size:
        return 0.0
    return 1.0 - sum((count / size) ** 2 for count in counts)


def _tree_probabilities(tree: dict[str, Any], vector: list[float]) -> list[float]:
    if "probabilities" in tree:
        return tree["probabilities"]
    branch = "left" if vector[tree["feature"]] < tree["threshold"] else "right"
    return _tree_probabilities(tree[branch], vector)


def _validate_classifier_tree(
    tree: Any, feature_count: int, class_count: int, depth: int = 0
) -> None:
    if not isinstance(tree, dict) or depth > RANDOM_FOREST_MAX_DEPTH + 1:
        raise ValueError("Random Forest tree has an invalid structure or depth.")
    if "probabilities" in tree:
        values = tree["probabilities"]
        if (
            not isinstance(values, list)
            or len(values) != class_count
            or any(not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in values)
            or not math.isclose(sum(values), 1.0, rel_tol=1e-6, abs_tol=1e-6)
        ):
            raise ValueError("Random Forest leaf probabilities have an invalid class dimension.")
        return
    feature = tree.get("feature")
    threshold = tree.get("threshold")
    if (
        not isinstance(feature, int) or isinstance(feature, bool)
        or not 0 <= feature < feature_count
        or not isinstance(threshold, (int, float)) or not math.isfinite(threshold)
        or "left" not in tree or "right" not in tree
    ):
        raise ValueError("Random Forest split is inconsistent with its feature schema.")
    _validate_classifier_tree(tree["left"], feature_count, class_count, depth + 1)
    _validate_classifier_tree(tree["right"], feature_count, class_count, depth + 1)


def _best_forest_split(
    indices: list[int],
    vectors: list[list[float]],
    target_ids: list[int],
    class_count: int,
    rng: random.Random,
) -> tuple[int, float, float] | None:
    feature_count = len(vectors[0])
    candidate_features = rng.sample(
        range(feature_count), min(feature_count, max(1, int(math.sqrt(feature_count))))
    )
    parent_counts = [0] * class_count
    for index in indices:
        parent_counts[target_ids[index]] += 1
    parent_gini = _gini(parent_counts, len(indices))
    best: tuple[int, float, float] | None = None

    for feature in candidate_features:
        ordered = sorted(indices, key=lambda index: vectors[index][feature])
        split_positions = [
            position for position in range(1, len(ordered))
            if vectors[ordered[position - 1]][feature] < vectors[ordered[position]][feature]
        ]
        if not split_positions:
            continue
        if len(split_positions) > 8:
            selected = sorted({
                split_positions[round(i * (len(split_positions) - 1) / 7)]
                for i in range(8)
            })
        else:
            selected = split_positions
        left_counts = [0] * class_count
        selected_set = set(selected)
        for position, index in enumerate(ordered, start=1):
            left_counts[target_ids[index]] += 1
            if position not in selected_set:
                continue
            right_counts = [
                parent_counts[label] - left_counts[label] for label in range(class_count)
            ]
            gain = parent_gini - (
                position / len(ordered) * _gini(left_counts, position)
                + (len(ordered) - position) / len(ordered)
                * _gini(right_counts, len(ordered) - position)
            )
            lower = vectors[ordered[position - 1]][feature]
            upper = vectors[ordered[position]][feature]
            threshold = lower + (upper - lower) / 2
            if best is None or gain > best[2]:
                best = (feature, threshold, gain)
    return best


def _build_classifier_tree(
    indices: list[int],
    vectors: list[list[float]],
    target_ids: list[int],
    class_count: int,
    rng: random.Random,
    depth: int = 0,
) -> dict[str, Any]:
    counts = [0] * class_count
    for index in indices:
        counts[target_ids[index]] += 1
    probabilities = [count / max(len(indices), 1) for count in counts]
    if depth >= RANDOM_FOREST_MAX_DEPTH or len(indices) < 6 or sum(count > 0 for count in counts) <= 1:
        return {"probabilities": probabilities}
    split = _best_forest_split(indices, vectors, target_ids, class_count, rng)
    if split is None or split[2] <= 1e-12:
        return {"probabilities": probabilities}
    feature, threshold, _ = split
    left = [index for index in indices if vectors[index][feature] < threshold]
    right = [index for index in indices if vectors[index][feature] >= threshold]
    if not left or not right:
        return {"probabilities": probabilities}
    return {
        "feature": feature,
        "threshold": threshold,
        "left": _build_classifier_tree(left, vectors, target_ids, class_count, rng, depth + 1),
        "right": _build_classifier_tree(right, vectors, target_ids, class_count, rng, depth + 1),
    }


def _average_path_length(size: int) -> float:
    if size <= 1:
        return 0.0
    if size == 2:
        return 1.0
    harmonic = math.log(size - 1) + 0.5772156649 + 0.5 / (size - 1)
    return 2 * harmonic - 2 * (size - 1) / size


def _build_isolation_tree(
    rows: list[list[float]],
    rng: random.Random,
    depth: int,
    max_depth: int,
) -> dict[str, Any]:
    if len(rows) <= 1 or depth >= max_depth:
        return {"size": len(rows)}
    varying = [
        column for column in range(len(rows[0]))
        if min(row[column] for row in rows) < max(row[column] for row in rows)
    ]
    if not varying:
        return {"size": len(rows)}
    feature = rng.choice(varying)
    values = [row[feature] for row in rows]
    threshold = rng.uniform(min(values), max(values))
    left = [row for row in rows if row[feature] < threshold]
    right = [row for row in rows if row[feature] >= threshold]
    if not left or not right:
        return {"size": len(rows)}
    return {
        "feature": feature,
        "threshold": threshold,
        "left": _build_isolation_tree(left, rng, depth + 1, max_depth),
        "right": _build_isolation_tree(right, rng, depth + 1, max_depth),
    }


def train_model(rows: list[tuple[dict[str, Any], str]]) -> dict[str, Any]:
    if not rows:
        raise ValueError("Training data contains no labeled events.")
    rows = [(features, CLASS_ALIASES.get(label, label)) for features, label in rows]
    labels = sorted({label for _, label in rows})
    if "Normal" not in labels:
        raise ValueError("Training data must include at least one Normal event.")
    missing_required = REQUIRED_CLASSES - set(labels)
    if missing_required:
        raise ValueError(
            "Training data is missing required classes: "
            + ", ".join(sorted(missing_required))
        )
    if any(label not in THREAT_CLASSES for label in labels):
        invalid = sorted({label for _, label in rows if label not in THREAT_CLASSES})
        raise ValueError(f"Unsupported training labels: {', '.join(invalid)}")

    categories = {
        field: sorted({str(features.get(field, "unknown")) for features, _ in rows})
        for field in CATEGORICAL_FIELDS
    }
    vectors = [(_vectorize(features, categories), label) for features, label in rows]
    class_rows: dict[str, list[list[float]]] = defaultdict(list)
    for vector, label in vectors:
        class_rows[label].append(vector)

    numeric_model: dict[str, Any] = {}
    for label in labels:
        samples = class_rows[label]
        columns = list(zip(*samples))
        means = [_mean(list(column)) for column in columns]
        numeric_model[label] = {
            "count": len(samples),
            "means": means,
            "variances": [_variance(list(column), mean) for column, mean in zip(columns, means)],
        }

    normal_rows = [features for features, label in rows if label == "Normal"]
    anomaly_model: dict[str, list[float]] = {}
    for field in ANOMALY_FIELDS:
        values = [_number(features.get(field, 0)) for features in normal_rows]
        median = sorted(values)[len(values) // 2]
        deviations = sorted(abs(value - median) for value in values)
        mad = deviations[len(deviations) // 2]
        anomaly_model[field] = [median, max(1.4826 * mad, 1.0)]

    normal_vectors = [
        [math.log1p(max(0.0, _number(features.get(field, 0)))) for field in ANOMALY_FIELDS]
        for features, label in rows if label == "Normal"
    ]
    sample_size = min(256, len(normal_vectors))
    max_depth = math.ceil(math.log2(max(sample_size, 2)))
    forest: list[dict[str, Any]] = []
    forest_rng = random.Random(ISOLATION_FOREST_SEED)
    for _ in range(ISOLATION_FOREST_TREES):
        if len(normal_vectors) > sample_size:
            indices = forest_rng.sample(range(len(normal_vectors)), sample_size)
            sample = [normal_vectors[index] for index in indices]
        else:
            sample = list(normal_vectors)
        forest.append(_build_isolation_tree(sample, forest_rng, 0, max_depth))

    vector_feature_names = list(NUMERIC_FIELDS) + [
        f"{field}={category}"
        for field in CATEGORICAL_FIELDS
        for category in categories[field]
    ]
    forest_rng = random.Random(RANDOM_FOREST_SEED)
    target_ids = [labels.index(label) for _, label in rows]
    classifier_vectors = [_vectorize(features, categories) for features, _ in rows]
    classifier_trees = []
    for _ in range(RANDOM_FOREST_TREES):
        bootstrap = [forest_rng.randrange(len(rows)) for _ in rows]
        classifier_trees.append(_build_classifier_tree(
            bootstrap, classifier_vectors, target_ids, len(labels), forest_rng
        ))

    model = {
        "format_version": 3,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_rows": len(rows),
        "categories": categories,
        "numeric_fields": list(NUMERIC_FIELDS),
        "feature_names": vector_feature_names,
        "feature_count": len(vector_feature_names),
        "transform": {
            "name": "log1p-nonnegative-numerics-plus-categorical-one-hot",
            "scaler": "not-required-for-tree-ensembles",
        },
        "classes": labels,
        "training_seed": RANDOM_FOREST_SEED,
        "gaussian_nb": numeric_model,
        "classifier": {
            "name": "stdlib-random-forest",
            "version": "1",
            "trees": classifier_trees,
            "tree_count": RANDOM_FOREST_TREES,
            "max_depth": RANDOM_FOREST_MAX_DEPTH,
            "seed": RANDOM_FOREST_SEED,
            "feature_count": len(vector_feature_names),
        },
        "robust_baseline": anomaly_model,
        "anomaly_detector": {
            "name": "stdlib-isolation-forest",
            "version": "1",
            "trees": ISOLATION_FOREST_TREES,
            "seed": ISOLATION_FOREST_SEED,
            "sample_size": sample_size,
            "features": list(ANOMALY_FIELDS),
            "forest": forest,
            "threshold": 0.6,
            "threshold_quantile": 0.95,
        },
    }
    normal_scores = sorted(
        anomaly_score(model, features)
        for features, label in rows if label == "Normal"
    )
    quantile_index = max(0, math.ceil(0.95 * len(normal_scores)) - 1)
    model["anomaly_detector"]["threshold"] = normal_scores[quantile_index]
    return model


def classify(model: dict[str, Any], features: dict[str, Any]) -> dict[str, float]:
    numeric_fields = model.get(
        "numeric_fields",
        LEGACY_NUMERIC_FIELDS if model.get("format_version") == 1 else NUMERIC_FIELDS,
    )
    vector = _vectorize(features, model["categories"], numeric_fields)
    classifier = model.get("classifier")
    if classifier and classifier.get("name") == "stdlib-random-forest":
        if len(vector) != classifier.get("feature_count"):
            raise ValueError(
                f"Feature vector has {len(vector)} values; model expects "
                f"{classifier.get('feature_count')}."
            )
        class_count = len(model["classes"])
        probabilities = [0.0] * class_count
        trees = classifier["trees"]
        if not trees:
            raise ValueError("Random Forest model contains no trees.")
        for tree in trees:
            tree_probabilities = _tree_probabilities(tree, vector)
            if len(tree_probabilities) != class_count:
                raise ValueError("Random Forest leaf has an invalid class dimension.")
            for index, probability in enumerate(tree_probabilities):
                probabilities[index] += probability / len(trees)
        return {
            CLASS_ALIASES.get(label, label): probabilities[index]
            for index, label in enumerate(model["classes"])
        }
    scores: dict[str, float] = {}
    total = sum(model["gaussian_nb"][label]["count"] for label in model["classes"])
    for label in model["classes"]:
        data = model["gaussian_nb"][label]
        score = math.log(data["count"] / total)
        for value, mean, variance in zip(vector, data["means"], data["variances"]):
            score -= 0.5 * (math.log(2 * math.pi * variance) + ((value - mean) ** 2 / variance))
        scores[label] = score
    peak = max(scores.values())
    exp_scores = {label: math.exp(max(score - peak, -700)) for label, score in scores.items()}
    denominator = sum(exp_scores.values())
    return {
        CLASS_ALIASES.get(label, label): exp_scores[label] / denominator
        for label in model["classes"]
    }


def _path_length(tree: dict[str, Any], vector: list[float], depth: int = 0) -> float:
    if "size" in tree:
        return depth + _average_path_length(tree["size"])
    branch = "left" if vector[tree["feature"]] < tree["threshold"] else "right"
    return _path_length(tree[branch], vector, depth + 1)


def anomaly_score(model: dict[str, Any], features: dict[str, Any]) -> float:
    detector = model.get("anomaly_detector")
    if detector and detector.get("forest"):
        vector = [
            math.log1p(max(0.0, _number(features.get(field, 0))))
            for field in detector["features"]
        ]
        path_lengths = [_path_length(tree, vector) for tree in detector["forest"]]
        average_path = sum(path_lengths) / len(path_lengths)
        normalization = _average_path_length(detector["sample_size"])
        raw_score = 2 ** (-average_path / normalization) if normalization else 0.0
        return min(1.0, max(0.0, (raw_score - 0.45) / 0.4))
    excess = 0.0
    for field, (median, scale) in model["robust_baseline"].items():
        z_score = abs(_number(features.get(field, 0)) - median) / scale
        excess += max(0.0, z_score - 3.0)
    return min(1.0, excess / (3.0 * max(len(model["robust_baseline"]), 1)))


def save_model(model: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(model, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_model(path: Path) -> dict[str, Any]:
    try:
        model = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Cannot load model at {path}: {error}") from error
    if model.get("format_version") not in {1, 2, 3} or "robust_baseline" not in model:
        raise ValueError(f"Unsupported or invalid model file: {path}")
    if "gaussian_nb" not in model and "classifier" not in model:
        raise ValueError(f"Model has no supported classifier: {path}")
    if model.get("format_version") == 3:
        categories = model.get("categories", {})
        if model.get("numeric_fields") != list(NUMERIC_FIELDS):
            raise ValueError(f"Model numeric feature order does not match this application: {path}")
        expected_names = list(model.get("numeric_fields", ())) + [
            f"{field}={category}"
            for field in CATEGORICAL_FIELDS
            for category in categories.get(field, [])
        ]
        if (
            model.get("feature_names") != expected_names
            or model.get("feature_count") != len(expected_names)
            or model.get("classifier", {}).get("feature_count") != len(expected_names)
            or not model.get("classifier", {}).get("trees")
            or model.get("classifier", {}).get("tree_count")
            != len(model.get("classifier", {}).get("trees", []))
        ):
            raise ValueError(f"Model feature schema or dimensions are inconsistent: {path}")
        if set(model.get("classes", [])) - set(THREAT_CLASSES):
            raise ValueError(f"Model contains unsupported threat classes: {path}")
        for tree in model["classifier"]["trees"]:
            _validate_classifier_tree(
                tree, len(expected_names), len(model["classes"])
            )
    return model
