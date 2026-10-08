"""Command-line interface for training and scanning defensive telemetry."""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .evaluation import evaluate_model
from .models import REQUIRED_CLASSES, THREAT_CLASSES, load_model, save_model, train_model
from .scoring import DEFAULT_HEURISTIC_THRESHOLDS, assess, render_text
from .storage import EventStore
from .telemetry import FeatureEngine, follow_lines, read_jsonl, read_telemetry
from .synthetic import generate_fixtures


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_RESOURCES = Path(__file__).with_name("resources")
SOURCE_DATA = PROJECT_ROOT / "data"
SOURCE_MODELS = PROJECT_ROOT / "models"
INSTALLED_DATA = Path.cwd() / "data"
INSTALLED_MODELS = Path.cwd() / "models"


def _default_asset(filename: str) -> Path:
    source_asset = SOURCE_DATA / filename
    local_asset = INSTALLED_DATA / filename
    if source_asset.is_file():
        return source_asset
    if local_asset.is_file():
        return local_asset
    return PACKAGE_RESOURCES / filename


DEFAULT_TRAINING = _default_asset("training.jsonl")
DEFAULT_EVALUATION = _default_asset("evaluation.jsonl")
DEFAULT_DEMO = _default_asset("demo.jsonl")
DEFAULT_SCENARIOS = (
    SOURCE_DATA / "scenarios"
    if (SOURCE_DATA / "scenarios").is_dir()
    else INSTALLED_DATA / "scenarios"
    if (INSTALLED_DATA / "scenarios").is_dir()
    else PACKAGE_RESOURCES / "scenarios"
)
DEFAULT_MODEL = (
    SOURCE_MODELS / "sentinel-model.json"
    if (SOURCE_DATA / "training.jsonl").is_file()
    else INSTALLED_MODELS / "sentinel-model.json"
    if (INSTALLED_MODELS / "sentinel-model.json").is_file()
    else PACKAGE_RESOURCES / "sentinel-model.json"
)
DEFAULT_MODEL_OUTPUT = (
    SOURCE_MODELS / "sentinel-model.json"
    if (SOURCE_DATA / "training.jsonl").is_file()
    else INSTALLED_MODELS / "sentinel-model.json"
)
DEFAULT_DATABASE = (
    SOURCE_DATA / "sentinel.sqlite3"
    if (SOURCE_DATA / "training.jsonl").is_file()
    else INSTALLED_DATA / "sentinel.sqlite3"
)
DEFAULT_DATA_OUTPUT = (
    SOURCE_DATA if (SOURCE_DATA / "training.jsonl").is_file() else INSTALLED_DATA
)


def _training_rows(path: Path) -> list[tuple[dict[str, Any], str]]:
    engine = FeatureEngine()
    rows: list[tuple[dict[str, Any], str]] = []
    invalid = 0
    with path.open("r", encoding="utf-8-sig") as stream:
        for _, event, error in read_telemetry(stream, _file_format(path, "auto")):
            if error:
                invalid += 1
                continue
            if not event["label"]:
                raise ValueError(
                    f"Training record on line {event['line_number']} is missing a label."
                )
            features = engine.features_for(event)
            label = event["label"]
            rows.append((features, label))
    if invalid:
        print(f"warning: skipped {invalid} malformed/invalid training rows", file=sys.stderr)
    return rows


def _train(args: argparse.Namespace) -> int:
    try:
        rows = _training_rows(args.input)
        model = train_model(rows)
        save_model(model, args.output)
        if args.output.resolve() == (SOURCE_MODELS / "sentinel-model.json").resolve():
            save_model(model, PACKAGE_RESOURCES / "sentinel-model.json")
        if args.evaluation_input.resolve() == args.input.resolve():
            print("warning: evaluation skipped because the evaluation input is the training input", file=sys.stderr)
        else:
            evaluation_records = []
            rejected = 0
            with args.evaluation_input.open("r", encoding="utf-8-sig") as stream:
                for line_number, event, error in read_telemetry(
                    stream, _file_format(args.evaluation_input, "auto")
                ):
                    if error or not event["label"] or event["label"] not in THREAT_CLASSES:
                        rejected += 1
                        message = error or (
                            "missing evaluation label" if not event["label"]
                            else f"unsupported evaluation label '{event['label']}'"
                        )
                        print(
                            f"warning: evaluation line {line_number}: {message}; continuing",
                            file=sys.stderr,
                        )
                        continue
                    evaluation_records.append(event)
            evaluation_report = evaluate_model(
                model,
                evaluation_records,
                dataset_name=(
                    "synthetic fixture"
                    if args.evaluation_input.resolve()
                    == DEFAULT_EVALUATION.resolve()
                    else "provided labeled evaluation input"
                ),
            )
            evaluation_report["rejected_records"] = rejected
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"trained model from {model['training_rows']} labeled records -> {args.output}")
    if args.evaluation_input.resolve() != args.input.resolve():
        print("held-out evaluation:")
        print(json.dumps(evaluation_report, indent=2, sort_keys=True))
    return 0


def _source(path: str) -> tuple[TextIO, bool]:
    if path == "-":
        return sys.stdin, False
    return Path(path).open("r", encoding="utf-8-sig"), True


def _file_format(path: Path | str, requested: str) -> str:
    if requested in {"jsonl", "csv"}:
        return requested
    return "csv" if str(path).lower().endswith(".csv") else "jsonl"


def _threshold_overrides(values: list[str]) -> dict[str, float]:
    thresholds: dict[str, float] = {}
    for item in values:
        name, separator, raw_value = item.partition("=")
        if not separator or name not in DEFAULT_HEURISTIC_THRESHOLDS:
            raise ValueError(
                f"Invalid --threshold '{item}'; use NAME=VALUE with one of: "
                + ", ".join(sorted(DEFAULT_HEURISTIC_THRESHOLDS))
            )
        try:
            value = float(raw_value)
        except ValueError as error:
            raise ValueError(f"Invalid threshold value in '{item}'.") from error
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"Threshold '{name}' must be a finite non-negative number.")
        thresholds[name] = value
    return thresholds


def _scan(args: argparse.Namespace) -> int:
    try:
        model = load_model(args.model)
        engine = FeatureEngine(
            window_seconds=args.window_seconds,
            internal_networks=tuple(args.internal_network or ()),
        )
        stream, should_close = _source(args.input)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    store: EventStore | None = None
    accepted = malformed = 0
    valid_records = noise_records = dropped_noise_records = total_lines = 0
    highest_risk = 0
    interrupted = False
    run_id = uuid.uuid4().hex
    try:
        if not args.no_database:
            store = EventStore(args.database)
        source = follow_lines(stream) if args.follow else stream
        input_format = _file_format(args.input, args.input_format)
        thresholds = _threshold_overrides(args.threshold)
        for line_number, event, error in read_telemetry(source, input_format):
            total_lines = max(total_lines, line_number)
            if error:
                malformed += 1
                print(f"warning: line {line_number}: {error}; continuing", file=sys.stderr)
                continue
            valid_records += 1
            if event["is_noise"]:
                noise_records += 1
                if args.drop_noise:
                    dropped_noise_records += 1
                    print(
                        f"info: line {line_number}: dropped tagged background traffic "
                        f"({'; '.join(event['noise_reasons'])})",
                        file=sys.stderr,
                    )
                    continue
            features = engine.features_for(event)
            result = assess(event, features, model, weights={
                "anomaly": args.anomaly_weight,
                "classifier": args.classifier_weight,
                "behavior": args.behavior_weight,
            }, thresholds=thresholds)
            accepted += 1
            highest_risk = max(highest_risk, result["risk"])
            if store:
                store.save(result)
            if args.format == "json":
                print(json.dumps({
                    "record_id": event["record_id"],
                    "line_number": event["line_number"],
                    "timestamp": event["timestamp"],
                    "source_ip": event["source_ip"],
                    "destination_ip": event["destination_ip"],
                    "event_type": event["event_type"],
                    "risk": result["risk"],
                    "band": result["band"],
                    "predicted_class": result["predicted_class"],
                    "confidence": result["confidence"],
                    "anomaly_score": result["anomaly_score"],
                    "anomaly_decision": result["anomaly_decision"],
                    "detector": result["detector"],
                    "risk_components": result["risk_components"],
                    "features": result["features"],
                    "raw_event_ids": result["raw_event_ids"],
                    "model_probabilities": result["model_probabilities"],
                    "raw_event": event["raw"],
                    "risk_weights": result["risk_weights"],
                    "noise_discount": result["noise_discount"],
                    "is_noise": event["is_noise"],
                    "noise_reasons": event["noise_reasons"],
                    "evidence": result["evidence"],
                }, sort_keys=True), flush=True)
            else:
                print(render_text(result))
    except KeyboardInterrupt:
        interrupted = True
        print("scan interrupted by operator", file=sys.stderr)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        exit_code = (
            130 if interrupted else
            2 if args.max_risk is not None and highest_risk > args.max_risk else 0
        )
        if args.max_risk is not None and highest_risk > args.max_risk:
            print(
                f"risk gate exceeded: highest risk {highest_risk} > --max-risk {args.max_risk}",
                file=sys.stderr,
            )
        print(
            f"summary: accepted={accepted} rejected={malformed} valid={valid_records} "
            f"noise={noise_records} dropped_noise={dropped_noise_records} "
            f"highest_risk={highest_risk}",
            file=sys.stderr,
        )
        if store:
            store.save_run({
                "run_id": run_id,
                "input_source": args.input,
                "input_format": _file_format(args.input, args.input_format),
                "total_lines": total_lines,
                "valid_records": valid_records,
                "malformed_records": malformed,
                "noise_records": noise_records,
                "dropped_noise_records": dropped_noise_records,
                "alerts_generated": accepted,
                "max_risk_score": highest_risk,
                "policy_threshold": args.max_risk,
                "policy_breach": bool(args.max_risk is not None and highest_risk > args.max_risk),
                "exit_code": exit_code,
            })
            store.close()
        if should_close:
            stream.close()
    if interrupted:
        return 130
    if args.max_risk is not None and highest_risk > args.max_risk:
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyber-sentinel",
        description="Defensive, evidence-first cybersecurity telemetry anomaly sentinel.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    train = commands.add_parser("train", help="train a reproducible model from labeled JSONL or CSV")
    train.add_argument("--input", type=Path, default=DEFAULT_TRAINING)
    train.add_argument("--output", type=Path, default=DEFAULT_MODEL_OUTPUT)
    train.add_argument(
        "--evaluation-input", type=Path,
        default=DEFAULT_EVALUATION,
        help="separate labeled holdout for metrics; never used to fit the model",
    )
    train.set_defaults(handler=_train)

    scan = commands.add_parser("scan", help="score JSONL or CSV telemetry from a file or stdin")
    scan.add_argument("--input", default=str(DEFAULT_DEMO), help="JSONL/CSV file path or - for stdin")
    scan.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    scan.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    scan.add_argument("--input-format", choices=("auto", "jsonl", "csv"), default="auto")
    scan.add_argument("--window-seconds", type=int, default=60)
    scan.add_argument(
        "--internal-network", action="append", default=[],
        help="additional internal CIDR (repeatable); RFC-private addresses are internal by default",
    )
    scan.add_argument("--max-risk", type=int, help="exit with status 2 if any risk exceeds this value")
    scan.add_argument("--anomaly-weight", type=float, default=0.30)
    scan.add_argument("--classifier-weight", type=float, default=0.45)
    scan.add_argument("--behavior-weight", type=float, default=0.25)
    scan.add_argument(
        "--threshold", action="append", default=[], metavar="NAME=VALUE",
        help="override a heuristic threshold (repeatable; see --help for accepted names)",
    )
    scan.add_argument("--drop-noise", action="store_true", help="skip tagged background/noise rows after counting them")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--no-database", action="store_true", help="disable SQLite audit persistence")
    scan.add_argument("--follow", action="store_true", help="continue reading complete JSONL lines appended to a file")
    scan.set_defaults(handler=_scan)

    web = commands.add_parser("web", help="launch the local interactive operations dashboard")
    web.add_argument("--host", default="127.0.0.1", help="bind address (default: loopback only)")
    web.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    web.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    web.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    web.set_defaults(handler=_web)

    evaluate = commands.add_parser("evaluate", help="calculate deterministic metrics from labeled JSONL or CSV")
    evaluate.add_argument("--input", type=Path, default=DEFAULT_EVALUATION)
    evaluate.add_argument("--input-format", choices=("auto", "jsonl", "csv"), default="auto")
    evaluate.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    evaluate.set_defaults(handler=_evaluate)

    generate = commands.add_parser("generate-data", help="regenerate deterministic synthetic JSONL/CSV fixtures")
    generate.add_argument("--output-dir", type=Path, default=DEFAULT_DATA_OUTPUT)
    generate.add_argument("--seed", type=int, default=1729)
    generate.add_argument("--cases", type=int, default=12)
    generate.set_defaults(handler=_generate_data)
    return parser


def _web(args: argparse.Namespace) -> int:
    from .web import serve

    try:
        serve(args.host, args.port, args.database, args.model, DEFAULT_DEMO)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    try:
        model = load_model(args.model)
        records = []
        rejected = 0
        with args.input.open("r", encoding="utf-8-sig") as stream:
            for line_number, event, error in read_telemetry(
                stream, _file_format(args.input, args.input_format)
            ):
                if error:
                    rejected += 1
                    print(f"warning: line {line_number}: {error}; continuing", file=sys.stderr)
                    continue
                if not event["label"]:
                    rejected += 1
                    print(f"warning: line {line_number}: missing evaluation label; continuing", file=sys.stderr)
                    continue
                if event["label"] not in THREAT_CLASSES:
                    rejected += 1
                    print(
                        f"warning: line {line_number}: unsupported evaluation label '{event['label']}'; continuing",
                        file=sys.stderr,
                    )
                    continue
                records.append(event)
        report = evaluate_model(
            model, records,
            dataset_name=(
                "synthetic fixture"
                if args.input.resolve() == DEFAULT_EVALUATION.resolve()
                else "provided labeled evaluation input"
            ),
        )
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    report["rejected_records"] = rejected
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _generate_data(args: argparse.Namespace) -> int:
    try:
        generate_fixtures(args.output_dir, args.seed, args.cases)
        if args.output_dir.resolve() == SOURCE_DATA.resolve():
            generate_fixtures(PACKAGE_RESOURCES, args.seed, args.cases)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"generated fixed-seed synthetic training/evaluation/demo fixtures in {args.output_dir} "
        f"(seed={args.seed}, cases={args.cases})"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "window_seconds", 1) < 1:
        parser.error("--window-seconds must be at least 1")
    if getattr(args, "follow", False) and args.input == "-":
        parser.error("--follow requires a file path; it cannot follow stdin")
    if getattr(args, "follow", False) and _file_format(args.input, args.input_format) == "csv":
        parser.error("--follow supports JSONL only")
    if getattr(args, "max_risk", None) is not None and not 0 <= args.max_risk <= 100:
        parser.error("--max-risk must be between 0 and 100")
    weights = [
        getattr(args, "anomaly_weight", 0.30),
        getattr(args, "classifier_weight", 0.45),
        getattr(args, "behavior_weight", 0.25),
    ]
    if any(weight < 0 for weight in weights) or sum(weights) <= 0:
        parser.error("risk weights must be non-negative and have a positive sum")
    if any(not math.isfinite(weight) for weight in weights):
        parser.error("risk weights must be finite numbers")
    return args.handler(args)
