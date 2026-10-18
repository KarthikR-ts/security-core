"""
Tests for Event Normalization & Validation (Section 8)

Validates:
- Valid event transformation
- Missing optional fields
- Missing or invalid required fields
- Invalid timestamp handling and normalization to ISO-8601 UTC
- Unknown event type handling
- Missing event ID generation
- Nested or unexpected input structures
- Deduplication behavior
"""

import json
from pathlib import Path

import pytest

from forwarder.config import Config
from forwarder.transformer import clear_dedup_cache, transform_event
from forwarder.validator import normalize_timestamp, validate_security_event

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


@pytest.fixture(autouse=True)
def reset_cache():
    clear_dedup_cache()
    yield
    clear_dedup_cache()


def test_valid_event_normalization():
    """Verify normalization of a valid process_exec event."""
    raw = {
        "process_exec": {
            "process": {
                "pid": 5001,
                "uid": 0,
                "binary": "/bin/bash",
                "arguments": "-c whoami",
                "cwd": "/root",
                "pod": {"name": "test-pod", "namespace": "prod"},
            }
        },
        "node_name": "worker-1",
        "time": "2026-03-01T12:00:00Z",
    }
    event = transform_event(raw, capture_mode="fixture_replay")
    assert event is not None
    is_valid, err = validate_security_event(event)
    assert is_valid, f"Validation failed: {err}"

    assert event["event_type"] == "process_exec"
    assert event["capture_mode"] == "fixture_replay"
    assert event["event_source"] == "tetragon-replay"
    assert event["schema_version"] == "1.0.0"
    assert event["timestamp"] == "2026-03-01T12:00:00Z"
    assert event["telemetry"]["pid"] == 5001
    assert event["telemetry"]["binary"] == "/bin/bash"
    assert event["telemetry"]["args"] == ["-c", "whoami"]
    assert event["telemetry"]["uid"] == 0
    assert event["telemetry"]["user"] == "root"


def test_missing_optional_fields():
    """Verify transformation succeeds with missing optional fields."""
    raw = {
        "process_exec": {
            "process": {
                "binary": "/usr/bin/python3",
            }
        }
    }
    event = transform_event(raw)
    assert event is not None
    is_valid, err = validate_security_event(event)
    assert is_valid, f"Validation failed: {err}"

    # Defaults should be safely applied
    assert event["telemetry"]["pid"] == 0
    assert event["telemetry"]["uid"] == 0
    assert event["telemetry"]["args"] == []
    assert event["telemetry"]["pod"] == ""
    assert event["telemetry"]["namespace"] == ""
    assert event["node_name"] == "unknown"


def test_unknown_event_type_handled():
    """Verify unknown or unhandled event types return None."""
    raw = {
        "unknown_syscall_trace": {"data": 123},
        "time": "2026-01-01T00:00:00Z",
    }
    event = transform_event(raw)
    assert event is None


def test_invalid_and_various_timestamp_handling():
    """Verify timestamps in various formats are normalized to ISO-8601 UTC."""
    # RFC3339 with offset +05:30
    ts1 = normalize_timestamp("2026-03-01T17:30:00+05:30")
    assert ts1 == "2026-03-01T12:00:00Z"

    # Unix epoch in seconds
    ts2 = normalize_timestamp(1772366400)
    assert ts2.endswith("Z")

    # None / Missing timestamp
    ts_none = normalize_timestamp(None)
    assert isinstance(ts_none, str)
    assert ts_none.endswith("Z")

    # Corrupted timestamp string falls back to valid UTC timestamp
    ts_corrupt = normalize_timestamp("not-a-timestamp-12345")
    assert isinstance(ts_corrupt, str)
    assert ts_corrupt.endswith("Z")


def test_missing_event_id_generation():
    """Verify that a valid UUID is assigned when input does not supply one."""
    raw = {
        "process_exec": {
            "process": {"binary": "/bin/ls"}
        }
    }
    event = transform_event(raw)
    assert event is not None
    assert "event_id" in event
    assert len(event["event_id"]) == 36


def test_nested_unexpected_input_structures():
    """Verify robustness against corrupted or unexpected nested data types."""
    raw = {
        "process_exec": {
            "process": {
                "pid": "not-an-int",
                "uid": None,
                "binary": None,
                "arguments": ["array", "instead", "of", "string"],
                "parent": "unexpected-string-instead-of-dict",
            }
        },
        "node_name": 12345,  # int instead of string
    }
    event = transform_event(raw)
    assert event is not None
    is_valid, err = validate_security_event(event)
    assert is_valid, f"Validation error: {err}"
    assert event["telemetry"]["pid"] == 0
    assert event["telemetry"]["args"] == ["array", "instead", "of", "string"]
    assert event["telemetry"]["parent_pid"] == 0
    assert event["node_name"] == "12345"


def test_safe_deduplication():
    """Verify safe deduplication when enabled."""
    raw = {
        "process_exec": {
            "process": {"pid": 9999, "binary": "/bin/echo", "arguments": "hello"}
        },
        "time": "2026-01-01T00:00:00Z",
    }
    # First pass: processed
    event1 = transform_event(raw, deduplicate=True)
    assert event1 is not None

    # Immediate second pass with exact same raw content: dropped as duplicate
    event2 = transform_event(raw, deduplicate=True)
    assert event2 is None
