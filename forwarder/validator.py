"""
Security-Core Event Forwarder — Schema Validator & Timestamp Normalizer

Validates and normalizes runtime security events according to the
Security Unified Event Contract (schema_version 1.0.0).
"""

import datetime
import re
import uuid
from typing import Any

KNOWN_EVENT_TYPES = {
    "process_exec",
    "process_exit",
    "process_kprobe",
    "process_tracepoint",
    "process_loader",
}

REQUIRED_TOP_LEVEL_FIELDS = {
    "event_id",
    "timestamp",
    "source",
    "event_type",
    "node_name",
    "telemetry",
    "schema_version",
    "capture_mode",
}

REQUIRED_TELEMETRY_FIELDS = {
    "pid",
    "binary",
    "args",
    "uid",
    "user",
    "namespace",
    "pod",
    "parent_binary",
    "parent_pid",
}


def normalize_timestamp(raw_ts: Any) -> str:
    """
    Normalizes various timestamp representations into consistent ISO-8601 UTC with 'Z'.
    Supports:
      - ISO-8601 strings (with or without Z / timezone offsets)
      - Unix epoch numbers (int/float seconds or ms)
      - datetime objects
      - Falls back to current UTC timestamp on invalid/missing input
    """
    if raw_ts is None:
        return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    if isinstance(raw_ts, datetime.datetime):
        if raw_ts.tzinfo is None:
            raw_ts = raw_ts.replace(tzinfo=datetime.timezone.utc)
        return raw_ts.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    # If numeric timestamp (epoch seconds or milliseconds)
    if isinstance(raw_ts, (int, float)):
        try:
            # Check if timestamp is in milliseconds (> 1e11)
            val = raw_ts / 1000.0 if raw_ts > 1e11 else float(raw_ts)
            dt = datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except Exception:
            return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    if isinstance(raw_ts, str):
        clean_str = raw_ts.strip()
        if not clean_str:
            return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        # Normalize trailing Z for fromisoformat if needed
        iso_str = clean_str.replace("Z", "+00:00")
        try:
            dt = datetime.datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            # Try parsing common formats
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
            ):
                try:
                    dt = datetime.datetime.strptime(clean_str, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=datetime.timezone.utc)
                    return dt.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                except ValueError:
                    continue

    # Fallback for unrecognized or corrupted timestamp strings
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def validate_security_event(event: dict[str, Any]) -> tuple[bool, str | None]:
    """
    Validate an event against the Security Unified Event Schema.
    Returns (True, None) if valid, or (False, error_reason) if invalid.
    """
    if not isinstance(event, dict):
        return False, "Event is not a dictionary"

    # Check top-level required fields
    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field not in event:
            return False, f"Missing required top-level field: '{field}'"

    # Check event_type is known
    etype = event.get("event_type")
    if etype not in KNOWN_EVENT_TYPES:
        return False, f"Unknown or invalid event_type: '{etype}'"

    # Check event_id
    eid = event.get("event_id")
    if not isinstance(eid, str) or not eid:
        return False, "event_id must be a non-empty string"

    # Check telemetry block
    telemetry = event.get("telemetry")
    if not isinstance(telemetry, dict):
        return False, "telemetry must be a dictionary"

    for t_field in REQUIRED_TELEMETRY_FIELDS:
        if t_field not in telemetry:
            return False, f"Missing required telemetry field: '{t_field}'"

    # Check telemetry field types
    if not isinstance(telemetry.get("pid"), int):
        return False, "telemetry.pid must be an integer"
    if not isinstance(telemetry.get("args"), list):
        return False, "telemetry.args must be a list"
    if not isinstance(telemetry.get("binary"), str):
        return False, "telemetry.binary must be a string"

    return True, None
