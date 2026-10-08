"""Telemetry parsing, normalization, validation, and rolling-window features."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import csv
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator


EVENT_TYPES = {
    "network",
    "connection",
    "flow",
    "auth",
    "login",
    "dns",
    "dns_query",
    "process",
    "firewall",
    "audit",
    "dhcp",
    "arp",
    "multicast",
    "ntp",
    "ssdp",
    "mdns",
    "igmp",
    "llmnr",
    "discovery",
    "monitoring",
    "scheduled_job",
}
NOISE_EVENT_TYPES = {"dhcp", "arp", "multicast", "ntp", "ssdp", "mdns", "igmp", "llmnr", "discovery"}
NOISE_PORTS = {67, 68, 123, 1900, 5353, 5355}
ALIASES = {
    "timestamp": ("timestamp", "time", "@timestamp", "ts"),
    "source_ip": ("source_ip", "src_ip", "source", "src"),
    "destination_ip": ("destination_ip", "dest_ip", "dst_ip", "destination", "dst"),
    "source_port": ("source_port", "src_port", "sport"),
    "destination_port": ("destination_port", "dst_port", "port"),
    "event_type": ("event_type", "type", "kind"),
    "bytes": ("bytes", "byte_count"),
    "bytes_sent": ("bytes_sent", "outbound_bytes", "bytes_out"),
    "bytes_received": ("bytes_received", "inbound_bytes", "bytes_in"),
    "packets": ("packets", "packet_count"),
    "protocol": ("protocol", "proto"),
    "action": ("action", "status", "decision"),
    "auth_status": ("auth_status", "auth"),
    "success": ("success", "authenticated"),
    "user": ("user", "username", "account"),
    "label": ("label", "class", "threat_class"),
    "direction": ("direction", "traffic_direction"),
    "duration_ms": ("duration_ms", "duration"),
    "service": ("service", "destination_service"),
}


class TelemetryError(ValueError):
    """A single record could not be accepted."""


def _first(record: dict[str, Any], names: tuple[str, ...], default: Any = None) -> Any:
    for name in names:
        if name in record:
            return record[name]
    return default


def _integer(value: Any, field: str, minimum: int = 0, maximum: int | None = 2**63 - 1) -> int:
    if value == "":
        value = 0
    if isinstance(value, bool):
        raise TelemetryError(f"{field} must be an integer.")
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise TelemetryError(f"{field} must be an integer.") from error
    if isinstance(value, float) and not value.is_integer():
        raise TelemetryError(f"{field} must be an integer.")
    if number < minimum or (maximum is not None and number > maximum):
        bound = f"{minimum}..{maximum}" if maximum is not None else f">= {minimum}"
        raise TelemetryError(f"{field} must be {bound}.")
    return number


def _boolean(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "success", "accepted"}:
            return True
        if lowered in {"false", "no", "0", "failed", "failure", "denied"}:
            return False
    raise TelemetryError("success must be a boolean or a recognized true/false value.")


def normalize(record: dict[str, Any], line_number: int) -> dict[str, Any]:
    raw_time = _first(record, ALIASES["timestamp"])
    if isinstance(raw_time, bool) or raw_time is None:
        raise TelemetryError("timestamp is required as an ISO-8601 string or epoch number.")
    try:
        if isinstance(raw_time, (int, float)):
            epoch = float(raw_time)
            if abs(epoch) > 100_000_000_000:
                epoch /= 1000
            timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
        elif isinstance(raw_time, str) and raw_time.strip():
            value = raw_time.strip()
            try:
                epoch = float(value)
            except ValueError:
                timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            else:
                if abs(epoch) > 100_000_000_000:
                    epoch /= 1000
                timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
        else:
            raise ValueError("empty timestamp")
    except (ValueError, OverflowError, OSError) as error:
        raise TelemetryError("timestamp must be valid ISO-8601 or a supported epoch value.") from error
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)

    raw_type = _first(record, ALIASES["event_type"])
    if not isinstance(raw_type, str) or not raw_type.strip():
        raise TelemetryError("event_type is required.")
    event_type = raw_type.strip().lower()
    event_type = {"flow": "network", "audit": "monitoring"}.get(event_type, event_type)
    if event_type not in EVENT_TYPES:
        raise TelemetryError(f"unknown event_type '{event_type}'.")

    def text(field: str, default: str) -> str:
        value = _first(record, ALIASES[field], default)
        if value is None:
            return default
        if not isinstance(value, (str, int, float)):
            raise TelemetryError(f"{field} must be text.")
        return str(value).strip() or default

    source_ip = text("source_ip", "")
    if not source_ip:
        raise TelemetryError("source_ip is required for per-source feature aggregation.")
    try:
        source_ip = str(ipaddress.ip_address(source_ip))
    except ValueError as error:
        raise TelemetryError("source_ip must be a valid IPv4 or IPv6 address.") from error
    destination_ip = text("destination_ip", "unknown")
    if destination_ip != "unknown":
        try:
            destination_ip = str(ipaddress.ip_address(destination_ip))
        except ValueError as error:
            raise TelemetryError("destination_ip must be a valid IPv4 or IPv6 address.") from error
    direction = text("direction", "outbound").lower()
    if direction not in {"inbound", "outbound", "internal", "unknown"}:
        raise TelemetryError("direction must be inbound, outbound, internal, or unknown.")
    bytes_sent_value = _first(record, ALIASES["bytes_sent"])
    bytes_received_value = _first(record, ALIASES["bytes_received"])
    total_bytes_value = _first(record, ALIASES["bytes"])
    if total_bytes_value is None:
        total_bytes_value = bytes_sent_value if bytes_sent_value is not None else bytes_received_value
    byte_count = _integer(total_bytes_value if total_bytes_value is not None else 0, "bytes")
    bytes_sent = _integer(bytes_sent_value if bytes_sent_value is not None else (byte_count if direction == "outbound" else 0), "bytes_sent")
    bytes_received = _integer(bytes_received_value if bytes_received_value is not None else (byte_count if direction == "inbound" else 0), "bytes_received")

    source_port = _integer(_first(record, ALIASES["source_port"], 0), "source_port", 0, 65535)
    destination_port = _integer(
        _first(record, ALIASES["destination_port"], 0), "destination_port", 0, 65535
    )
    protocol = text("protocol", "unknown").upper()
    action = text("action", "observed").lower()
    auth_value = _first(record, ALIASES["auth_status"])
    success_value = _first(record, ALIASES["success"])
    if success_value is None and auth_value is not None:
        auth_text = str(auth_value).strip().lower()
        if auth_text in {"success", "succeeded", "pass", "true", "1"}:
            success_value = True
        elif auth_text in {"fail", "failed", "failure", "false", "0", "denied"}:
            success_value = False
    success = _boolean(success_value)
    is_noise, noise_reasons = _noise_indicators(
        event_type, protocol, destination_port, source_port, destination_ip,
    )
    normalized = {
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "event_type": event_type,
        "bytes": byte_count,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "packets": _integer(_first(record, ALIASES["packets"], 0), "packets"),
        "duration_ms": _integer(_first(record, ALIASES["duration_ms"], 0), "duration_ms"),
        "protocol": protocol.lower(),
        "action": action,
        "success": success,
        "auth_status": "SUCCESS" if success is True else "FAILURE" if success is False else "NONE",
        "user": text("user", "unknown"),
        "direction": direction,
        "service": text("service", ""),
        "label": {
            "Exfiltration": "DataExfiltration",
            "Port Scan": "PortScan",
            "Brute Force": "BruteForce",
            "Lateral Movement": "LateralMovement",
            "Data Exfiltration": "DataExfiltration",
        }.get(text("label", ""), text("label", "")),
        "is_noise": is_noise,
        "noise_reasons": noise_reasons,
        "line_number": line_number,
        "raw": record,
    }
    normalized["record_id"] = hashlib.sha256(
        json.dumps({"line_number": line_number, "record": record}, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()[:20]
    return normalized


def _noise_indicators(
    event_type: str,
    protocol: str,
    destination_port: int,
    source_port: int,
    destination_ip: str,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if event_type in NOISE_EVENT_TYPES:
        reasons.append(f"background event type: {event_type}")
    common_ports = {destination_port, source_port} & NOISE_PORTS
    if common_ports:
        reasons.append("background service port: " + ", ".join(map(str, sorted(common_ports))))
    try:
        address = ipaddress.ip_address(destination_ip)
    except ValueError:
        address = None
    if address and (
        address.is_multicast
        or address.is_unspecified
        or address == ipaddress.ip_address("255.255.255.255")
    ):
        reasons.append("multicast/broadcast destination")
    if protocol.upper() in {"ARP", "IGMP", "LLMNR"}:
        reasons.append(f"discovery protocol: {protocol.upper()}")
    return bool(reasons), reasons


def read_jsonl(stream: Iterable[str]) -> Iterator[tuple[int, dict[str, Any] | None, str | None]]:
    for line_number, line in enumerate(stream, 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line, parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-standard numeric constant '{value}' is not valid JSON")
            ))
        except json.JSONDecodeError as error:
            yield line_number, None, f"malformed JSON: {error.msg}"
            continue
        except ValueError as error:
            yield line_number, None, f"malformed JSON: {error}"
            continue
        if not isinstance(payload, dict):
            yield line_number, None, "record must be a JSON object"
            continue
        try:
            yield line_number, normalize(payload, line_number), None
        except TelemetryError as error:
            yield line_number, None, str(error)


def read_csv(stream: Iterable[str]) -> Iterator[tuple[int, dict[str, Any] | None, str | None]]:
    """Read headered CSV while preserving the JSONL per-row recovery contract."""
    reader = csv.DictReader(stream)
    if not reader.fieldnames:
        yield 1, None, "CSV input must include a header row"
        return
    try:
        for row in reader:
            line_number = max(2, reader.line_num)
            if row is None or None in row:
                yield line_number, None, "CSV row has more fields than its header"
                continue
            try:
                yield line_number, normalize(row, line_number), None
            except TelemetryError as error:
                yield line_number, None, str(error)
    except csv.Error as error:
        yield max(2, reader.line_num), None, f"malformed CSV: {error}"


def read_telemetry(
    stream: Iterable[str], input_format: str = "jsonl"
) -> Iterator[tuple[int, dict[str, Any] | None, str | None]]:
    if input_format == "csv":
        yield from read_csv(stream)
    elif input_format == "jsonl":
        yield from read_jsonl(stream)
    else:
        raise ValueError("input_format must be 'jsonl' or 'csv'.")


def follow_lines(stream: Any, poll_seconds: float = 0.25) -> Iterator[str]:
    """Yield only complete appended lines, waiting at EOF for further file growth."""
    pending = ""
    while True:
        line = stream.readline()
        if line:
            pending += line
            if pending.endswith("\n"):
                yield pending
                pending = ""
        else:
            time.sleep(poll_seconds)


class FeatureEngine:
    def __init__(
        self,
        window_seconds: int = 60,
        max_history: int = 1000,
        internal_networks: tuple[str, ...] = (),
        administrative_ports: tuple[int, ...] = (22, 135, 139, 389, 445, 636, 1433, 3306, 3389, 5432, 5985, 5986),
    ) -> None:
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1.")
        if max_history < 1:
            raise ValueError("max_history must be at least 1.")
        self.window = timedelta(seconds=window_seconds)
        self.internal_networks = tuple(ipaddress.ip_network(network) for network in internal_networks)
        self.administrative_ports = frozenset(administrative_ports)
        self.max_history = max_history
        self.events: dict[str, deque[dict[str, Any]]] = {}

    def _is_internal(self, value: str) -> bool:
        if value == "unknown":
            return False
        address = ipaddress.ip_address(value)
        return address.is_private or any(address in network for network in self.internal_networks)

    def features_for(self, event: dict[str, Any]) -> dict[str, Any]:
        timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        entity = event["source_ip"]
        history = self.events.setdefault(entity, deque())
        cutoff = timestamp - self.window
        retained = [
            prior for prior in history
            if datetime.fromisoformat(prior["timestamp"].replace("Z", "+00:00")) >= cutoff
        ]
        history.clear()
        history.extend(retained[-self.max_history :])

        prior_events = [
            prior for prior in history
            if datetime.fromisoformat(prior["timestamp"].replace("Z", "+00:00")) <= timestamp
        ]
        current = prior_events + [event]
        def in_window(seconds: int) -> list[dict[str, Any]]:
            lower_bound = timestamp - timedelta(seconds=seconds)
            return [
                item for item in current
                if lower_bound <= datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")) <= timestamp
            ]

        short_events = in_window(30)
        medium_events = in_window(60)
        def is_authentication(item: dict[str, Any]) -> bool:
            return item["event_type"] in {"auth", "login"} or item["success"] is not None

        previous_peers = {item["destination_ip"] for item in prior_events if item["destination_ip"] != "unknown"}
        failures = sum(
            is_authentication(item) and item["success"] is False
            for item in current
        )
        denied = sum(item["action"] in {"deny", "denied", "block", "blocked", "drop"} for item in current)
        destinations = {item["destination_ip"] for item in current if item["destination_ip"] != "unknown"}
        ports = {item["destination_port"] for item in current if item["destination_port"] > 0}
        total_auth = sum(is_authentication(item) for item in current)
        prior_timestamps = [
            datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
            for item in prior_events
        ]
        interarrival = (
            (timestamp - max(prior_timestamps)).total_seconds()
            if prior_timestamps else 0.0
        )
        recent_interarrivals = [
            (datetime.fromisoformat(right["timestamp"].replace("Z", "+00:00")) -
             datetime.fromisoformat(left["timestamp"].replace("Z", "+00:00"))).total_seconds()
            for left, right in zip(medium_events, medium_events[1:])
        ]
        average_interarrival = (
            sum(recent_interarrivals) / len(recent_interarrivals)
            if recent_interarrivals else 0.0
        )
        interarrival_variance = (
            sum((value - average_interarrival) ** 2 for value in recent_interarrivals) /
            len(recent_interarrivals)
            if recent_interarrivals else 0.0
        )
        successes = sum(
            is_authentication(item) and item["success"] is True
            for item in current
        )
        internal_destinations = {
            item["destination_ip"] for item in current if self._is_internal(item["destination_ip"])
        }
        internal_connections_60s = sum(
            self._is_internal(item["destination_ip"]) for item in medium_events
        )
        novelty_cutoff = timestamp - timedelta(seconds=60)
        established_peers = {
            item["destination_ip"] for item in history
            if datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")) < novelty_cutoff
        }
        new_internal_peers = {
            item["destination_ip"] for item in medium_events
            if self._is_internal(item["destination_ip"]) and item["destination_ip"] not in established_peers
        }
        service_names = {
            item["service"] or self._service_for_port(item["destination_port"])
            for item in current if item["destination_port"] > 0
        }
        previous_bytes = sum(item["bytes_sent"] + item["bytes_received"] for item in prior_events)
        average_prior_bytes = previous_bytes / max(len(prior_events), 1)
        bytes_sent = sum(item["bytes_sent"] for item in current)
        bytes_received = sum(item["bytes_received"] for item in current)
        recent_peer_count = len({
            item["destination_ip"] for item in medium_events if item["destination_ip"] != "unknown"
        })
        service_access_count = sum(
            item["destination_port"] in self.administrative_ports for item in medium_events
        )
        features = {
            "bytes": float(event["bytes"]),
            "packets": float(event["packets"]),
            "dst_port": float(event["destination_port"]),
            "src_port": float(event["source_port"]),
            "window_event_count": float(len(current)),
            "window_bytes": float(sum(item["bytes"] for item in current)),
            "window_bytes_sent": float(bytes_sent),
            "window_bytes_received": float(bytes_received),
            "window_unique_destinations": float(len(destinations)),
            "window_unique_ports": float(len(ports)),
            "window_unique_services": float(len(service_names)),
            "window_failed_auth": float(failures),
            "window_successful_auth": float(successes),
            "window_denied": float(denied),
            "window_failure_ratio": float(failures / max(total_auth, 1)),
            "window_failure_success_ratio": float(failures / max(successes, 1)),
            "window_connection_rate_30s": float(len(short_events) / 30),
            "window_connection_rate_60s": float(len(medium_events) / 60),
            "window_connection_rate_300s": float(len(current) / max(self.window.total_seconds(), 1)),
            "window_short_event_count": float(len(short_events)),
            "window_medium_event_count": float(len(medium_events)),
            "window_internal_peers": float(len(internal_destinations)),
            "window_new_internal_peers_60s": float(len(new_internal_peers)),
            "window_admin_service_access_60s": float(service_access_count),
            "window_bytes_per_connection": float(sum(item["bytes"] for item in current) / len(current)),
            "window_packets_per_connection": float(sum(item["packets"] for item in current) / len(current)),
            "window_outbound_inbound_ratio": float(bytes_sent / max(bytes_received, 1)),
            "window_bytes_vs_prior_average": float(bytes_sent / max(average_prior_bytes, 1)),
            "destination_novelty": float(event["destination_ip"] not in previous_peers and event["destination_ip"] != "unknown"),
            "source_destination_pair_novelty": float(not any(
                item["destination_ip"] == event["destination_ip"] for item in prior_events
            )),
            "window_unique_accounts": float(len({
                item["user"] for item in current
                if is_authentication(item) and item["user"] != "unknown"
            })),
            "window_unique_protocols": float(len({item["protocol"] for item in current})),
            "window_admin_port_coverage": float(len({
                item["destination_port"] for item in medium_events
                if item["destination_port"] in self.administrative_ports
            })),
            "window_short_lived_connections": float(sum(
                item["duration_ms"] <= 500 for item in medium_events
                if item["event_type"] in {"network", "connection"}
            )),
            "interarrival_seconds": float(interarrival),
            "window_mean_interarrival_60s": float(average_interarrival),
            "window_interarrival_cv_60s": float(
                (interarrival_variance ** 0.5) / average_interarrival
                if average_interarrival else 0.0
            ),
            "event_count": float(len(current)),
            "unique_dest_ips": float(len(destinations)),
            "unique_dest_ports": float(len(ports)),
            "auth_attempts": float(total_auth),
            "auth_failures": float(failures),
            "auth_fail_ratio": float(failures / max(total_auth, 1)),
            "total_bytes_sent": float(bytes_sent),
            "total_bytes_received": float(bytes_received),
            "bytes_out_ratio": float(bytes_sent / max(bytes_sent + bytes_received, 1)),
            "total_packets": float(sum(item["packets"] for item in current)),
            "protocol_diversity": float(len({item["protocol"] for item in current})),
            "peer_rarity_score": float(
                len(new_internal_peers) / max(internal_connections_60s, 1)
            ),
            "high_port_ratio": float(
                sum(item["destination_port"] > 1024 for item in current) / len(current)
            ),
            "event_rate_per_sec": float(len(medium_events) / max(
                1.0,
                (timestamp - min(
                    datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
                    for item in medium_events
                )).total_seconds(),
            )),
            "is_noise": float(event["is_noise"]),
            "window_record_ids": [item["record_id"] for item in current],
            "window_line_numbers": [item["line_number"] for item in current],
            "event_type": event["event_type"],
            "protocol": event["protocol"],
            "action": event["action"],
        }
        history.append(event)
        history = deque(sorted(
            history,
            key=lambda item: datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")),
        ))
        self.events[entity] = history
        while len(history) > self.max_history:
            history.popleft()
        return features

    @staticmethod
    def _service_for_port(port: int) -> str:
        services = {
            20: "ftp", 21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 67: "dhcp",
            68: "dhcp", 80: "http", 123: "ntp", 135: "rpc", 139: "netbios",
            389: "ldap", 443: "https", 445: "smb", 3389: "rdp", 5432: "database",
        }
        return services.get(port, f"port-{port}")
