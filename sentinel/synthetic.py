"""Deterministic synthetic telemetry fixtures for demonstrations and evaluation."""

from __future__ import annotations

import json
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CANONICAL_CLASSES = (
    "Normal", "PortScan", "BruteForce", "LateralMovement",
    "DataExfiltration", "Beaconing",
)


def _event(
    when: datetime,
    source: str,
    destination: str,
    *,
    kind: str = "network",
    port: int = 443,
    label: str,
    rng: random.Random,
    **values: Any,
) -> dict[str, Any]:
    return {
        "timestamp": when.isoformat().replace("+00:00", "Z"),
        "event_type": kind,
        "source_ip": source,
        "destination_ip": destination,
        "source_port": rng.randint(30_000, 60_000),
        "destination_port": port,
        "protocol": "tcp",
        "bytes": 500,
        "packets": 4,
        "action": "allow",
        "label": label,
        **values,
    }


def generate_records(seed: int, per_class: int, *, evaluation: bool = False) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    records: list[dict[str, Any]] = []
    anchor = datetime(2026, 10, 1 if evaluation else 2, tzinfo=timezone.utc)
    for case in range(per_class):
        case_base = anchor + timedelta(hours=case * 3)
        source_suffix = case + (90 if evaluation else 10)
        source = f"10.20.{source_suffix // 250}.{source_suffix % 250 + 1}"
        for label in CANONICAL_CLASSES:
            base = case_base + timedelta(minutes=CANONICAL_CLASSES.index(label) * 10)
            if label == "Normal":
                routine_type = ("network", "dns", "dhcp", "arp", "multicast", "monitoring", "scheduled_job")[case % 7]
                destination = (
                    f"10.30.{case % 8}.{(case * 7) % 200 + 2}"
                    if routine_type in {"network", "monitoring", "scheduled_job"}
                    else ("224.0.0.251" if routine_type == "multicast" else "10.30.0.53")
                )
                for index in range(5):
                    records.append(_event(
                        base + timedelta(seconds=index * rng.randint(14, 22)),
                        source, destination, kind=routine_type,
                        port=(53 if routine_type == "dns" else 443 if routine_type == "network" else 0),
                        label=label, rng=rng, bytes=rng.randint(250, 2_200),
                        packets=rng.randint(1, 12), action="allow",
                        direction="internal" if routine_type in {"arp", "dhcp", "multicast"} else "outbound",
                        bytes_received=rng.randint(100, 3_000) if routine_type == "network" else 0,
                        bytes_sent=rng.randint(100, 2_500) if routine_type == "network" else 0,
                    ))
            elif label == "PortScan":
                count = rng.randint(7, 13)
                for index in range(count):
                    destination = f"10.40.{case % 6}.{(index % 230) + 10}"
                    port = (3000 + index * rng.randint(1, 3)) if case % 2 else (20 + index)
                    records.append(_event(
                        base + timedelta(seconds=index * rng.randint(1, 3)),
                        source, destination, port=port, label=label, rng=rng,
                        bytes=rng.randint(50, 250), packets=1,
                        duration_ms=rng.randint(30, 700),
                        action="deny" if index % 4 == 0 else "allow",
                        direction="internal",
                    ))
            elif label == "BruteForce":
                count = rng.randint(5, 10)
                target = f"10.50.{case % 5}.{case + 10}"
                for index in range(count):
                    success = index == count - 1 and case % 3 == 0
                    records.append(_event(
                        base + timedelta(seconds=index * rng.randint(3, 9)),
                        source, target, kind="auth", port=22 if case % 2 else 3389,
                        label=label, rng=rng, bytes=rng.randint(100, 450),
                        packets=1, success=success, user=f"acct-{(index + case) % 5}",
                        action="allow" if success else "deny", direction="internal",
                    ))
            elif label == "LateralMovement":
                count = rng.randint(4, 8)
                for index in range(count):
                    destination = f"10.60.{case % 8}.{index + 30}"
                    records.append(_event(
                        base + timedelta(seconds=index * rng.randint(5, 12)),
                        source, destination, kind="connection",
                        port=rng.choice((22, 445, 3389, 5985, 5986)),
                        label=label, rng=rng, bytes=rng.randint(200, 1_500),
                        packets=rng.randint(1, 8), direction="internal",
                        duration_ms=rng.randint(200, 3_000),
                    ))
            elif label == "DataExfiltration":
                count = rng.randint(4, 7)
                destination = f"198.51.{case % 20}.{case + 20}"
                for index in range(count):
                    records.append(_event(
                        base + timedelta(seconds=index * rng.randint(7, 18)),
                        source, destination, port=443, label=label, rng=rng,
                        bytes=rng.randint(120_000, 650_000),
                        bytes_sent=rng.randint(120_000, 650_000),
                        bytes_received=rng.randint(2_000, 30_000),
                        packets=rng.randint(30, 240), direction="outbound",
                    ))
            else:
                destination = f"203.0.113.{case + 1}"
                for index in range(5):
                    records.append(_event(
                        base + timedelta(seconds=index * rng.randint(45, 80)),
                        source, destination, port=443, label=label, rng=rng,
                        bytes=rng.randint(350, 1_600), bytes_sent=rng.randint(250, 1_000),
                        bytes_received=rng.randint(200, 1_400), packets=rng.randint(2, 12),
                        direction="outbound",
                    ))
    return sorted(records, key=lambda item: item["timestamp"])


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def generate_fixtures(directory: Path, seed: int = 1729, cases: int = 12) -> None:
    if cases < 3:
        raise ValueError("Fixture generation requires at least 3 independent cases.")
    training = generate_records(seed, cases)
    evaluation = generate_records(seed + 1, max(4, cases // 2), evaluation=True)
    demo_records = generate_records(seed + 2, 1)
    write_jsonl(directory / "training.jsonl", training)
    write_csv(directory / "training.csv", training)
    write_jsonl(directory / "evaluation.jsonl", evaluation)
    midpoint = len(demo_records) // 2
    demo_rows = [
        *demo_records[:midpoint],
        None,
        {
            "timestamp": "2026-10-08T18:00:00Z",
            "event_type": "unsupported_test_event",
            "source_ip": "192.0.2.9",
        },
        *demo_records[midpoint:],
    ]
    demo_path = directory / "demo.jsonl"
    demo_path.parent.mkdir(parents=True, exist_ok=True)
    with demo_path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in demo_rows:
            if row is None:
                stream.write("{malformed demo record\n")
            else:
                stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    for label in CANONICAL_CLASSES:
        write_jsonl(
            directory / "scenarios" / f"{label.lower()}.jsonl",
            [record for record in demo_records if record["label"] == label],
        )
    noise_time = datetime(2026, 10, 9, tzinfo=timezone.utc)
    noise_rows = []
    for index, (kind, destination, port, protocol) in enumerate((
        ("dhcp", "255.255.255.255", 67, "udp"),
        ("network", "129.6.15.28", 123, "udp"),
        ("network", "239.255.255.250", 1900, "udp"),
        ("dns", "224.0.0.251", 5353, "udp"),
        ("multicast", "ff02::fb", 5353, "udp"),
        ("arp", "10.0.0.1", 0, "arp"),
        ("network", "192.0.2.53", 5355, "llmnr"),
    )):
        noise_rows.append(_event(
            noise_time + timedelta(seconds=index * 8),
            "10.99.0.10", destination, kind=kind, port=port,
            label="Normal", rng=random.Random(seed + index),
            protocol=protocol, direction="internal", bytes=160, packets=1,
        ))
    write_jsonl(directory / "scenarios" / "noise.jsonl", noise_rows)
    hostile_path = directory / "scenarios" / "hostile.jsonl"
    hostile_path.parent.mkdir(parents=True, exist_ok=True)
    with hostile_path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write("{malformed replay row\n")
        stream.write(json.dumps({
            "timestamp": "2026-10-09T00:00:01Z",
            "event_type": "unsupported_fixture_type",
            "source_ip": "192.0.2.7",
        }, sort_keys=True, separators=(",", ":")) + "\n")
        stream.write(json.dumps({
            "timestamp": "2026-10-09T00:00:02Z",
            "event_type": "network",
            "source_ip": "999.999.0.1",
        }, sort_keys=True, separators=(",", ":")) + "\n")
        stream.write(json.dumps(noise_rows[-1], sort_keys=True, separators=(",", ":")) + "\n")
