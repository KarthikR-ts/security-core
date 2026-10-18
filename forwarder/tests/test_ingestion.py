"""
Tests for Ingestion Pipeline (Section 8)

Validates:
- Multiple valid JSONL records
- Malformed record followed by valid record
- Empty fixture file
- Invalid JSON line
- Standard input handling
- Accurate capture-mode metadata
"""

import io
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from forwarder.config import Config
from forwarder.main import process_line, stream_from_file, stream_from_stdin
from forwarder.publisher import EventPublisher


@pytest.fixture
def mock_publisher():
    pub = MagicMock(spec=EventPublisher)
    pub.is_connected = False
    pub.publish.return_value = None
    return pub


def test_multiple_valid_jsonl_records(mock_publisher):
    """Verify processing multiple records sequentially from a file."""
    events = [
        {"process_exec": {"process": {"pid": 1, "binary": "/bin/systemd"}}, "time": "2026-01-01T00:00:00Z"},
        {"process_exit": {"process": {"pid": 2, "binary": "/bin/sleep"}}, "time": "2026-01-01T00:00:01Z"},
    ]
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl") as tf:
        for ev in events:
            tf.write(json.dumps(ev) + "\n")
        temp_path = tf.name

    try:
        cfg = Config()
        count = stream_from_file(temp_path, mock_publisher, cfg)
        assert count == 2
        assert mock_publisher.publish.call_count == 2
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_malformed_record_followed_by_valid_record(mock_publisher):
    """Verify that a malformed JSON line does not abort ingestion of subsequent records."""
    lines = [
        "{ this is broken json",
        json.dumps({"process_exec": {"process": {"pid": 42, "binary": "/usr/bin/id"}}, "time": "2026-01-01T00:00:00Z"}),
    ]
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl") as tf:
        for line in lines:
            tf.write(line + "\n")
        temp_path = tf.name

    try:
        cfg = Config()
        count = stream_from_file(temp_path, mock_publisher, cfg)
        # Should process 1 valid event and skip the bad one
        assert count == 1
        assert mock_publisher.publish.call_count == 1
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_empty_fixture_file(mock_publisher):
    """Verify processing an empty file returns count 0 without error."""
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl") as tf:
        temp_path = tf.name

    try:
        cfg = Config()
        count = stream_from_file(temp_path, mock_publisher, cfg)
        assert count == 0
        assert mock_publisher.publish.call_count == 0
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_stdin_ingestion(monkeypatch, mock_publisher):
    """Verify streaming events from stdin."""
    sample_json = json.dumps({
        "process_exec": {"process": {"pid": 88, "binary": "/bin/date"}},
        "time": "2026-01-01T00:00:00Z",
    }) + "\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(sample_json))

    cfg = Config()
    count = stream_from_stdin(mock_publisher, cfg)
    assert count == 1
    assert mock_publisher.publish.call_count == 1

    # Verify capture_mode tag on published event
    published_event = mock_publisher.publish.call_args[0][0]
    assert published_event["capture_mode"] == "stdin"


def test_capture_mode_metadata_tagging(mock_publisher):
    """Verify that fixture replay events are strictly tagged with 'fixture_replay'."""
    raw_line = json.dumps({
        "process_exec": {"process": {"pid": 99, "binary": "/bin/ps"}},
        "time": "2026-01-01T00:00:00Z",
    })
    event = process_line(raw_line, mock_publisher, capture_mode="fixture_replay")
    assert event is not None
    assert event["capture_mode"] == "fixture_replay"
    assert event["event_source"] == "tetragon-replay"
