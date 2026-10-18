"""
Tests for Redis Publisher & Resilience (Section 8)

Validates:
- Correct event payload is published to Redis stream
- Connection failure is handled gracefully with stdout fallback
- Retry limits and backoff behavior
- Publishing failure does not crash subsequent events
- Health reporting
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import redis

from forwarder.config import Config
from forwarder.publisher import EventPublisher


def test_publisher_success_path():
    """Verify event payload is serialized and sent to xadd with configured stream key."""
    cfg = Config()
    cfg.REDIS_STREAM_KEY = "security:test_stream"
    cfg.REDIS_MAXLEN = 500

    with patch("redis.Redis") as mock_redis_cls:
        mock_instance = MagicMock()
        mock_instance.ping.return_value = True
        mock_instance.xadd.return_value = "1772366400000-0"
        mock_redis_cls.return_value = mock_instance

        publisher = EventPublisher(cfg)
        assert publisher.is_connected is True

        event = {"event_id": "test-123", "event_type": "process_exec"}
        msg_id = publisher.publish(event)

        assert msg_id == "1772366400000-0"
        mock_instance.xadd.assert_called_once()
        args, kwargs = mock_instance.xadd.call_args
        assert args[0] == "security:test_stream"
        assert "event" in args[1]
        assert json.loads(args[1]["event"]) == event
        assert kwargs["maxlen"] == 500


def test_publisher_connection_failure_fallback(capsys):
    """Verify that when Redis is unreachable, publisher falls back to stdout without raising."""
    cfg = Config()

    with patch("redis.Redis") as mock_redis_cls:
        mock_instance = MagicMock()
        mock_instance.ping.side_effect = redis.ConnectionError("Connection refused")
        mock_redis_cls.return_value = mock_instance

        publisher = EventPublisher(cfg)
        assert publisher.is_connected is False

        event = {"event_id": "fallback-123", "event_type": "process_exit"}
        msg_id = publisher.publish(event)

        assert msg_id is None
        captured = capsys.readouterr()
        assert "fallback-123" in captured.out


def test_publisher_retry_on_timeout():
    """Verify bounded exponential retry occurs on transient Redis error."""
    cfg = Config()
    cfg.REDIS_RETRY_ATTEMPTS = 3
    cfg.REDIS_RETRY_BACKOFF_BASE = 0.01  # Fast for tests

    with patch("redis.Redis") as mock_redis_cls, patch("time.sleep") as mock_sleep:
        mock_instance = MagicMock()
        mock_instance.ping.return_value = True
        # Fail twice, succeed on 3rd attempt
        mock_instance.xadd.side_effect = [
            redis.TimeoutError("Timeout 1"),
            redis.TimeoutError("Timeout 2"),
            "1772366400000-1",
        ]
        mock_redis_cls.return_value = mock_instance

        publisher = EventPublisher(cfg)
        event = {"event_id": "retry-123"}
        msg_id = publisher.publish(event)

        assert msg_id == "1772366400000-1"
        assert mock_instance.xadd.call_count == 3
        assert mock_sleep.call_count == 2


def test_publisher_health():
    """Verify publisher health reporting dictionary."""
    cfg = Config()
    with patch("redis.Redis") as mock_redis_cls:
        mock_instance = MagicMock()
        mock_instance.ping.return_value = True
        mock_redis_cls.return_value = mock_instance

        publisher = EventPublisher(cfg)
        health = publisher.get_health()

        assert health["connected"] is True
        assert health["host"] == cfg.REDIS_HOST
        assert health["stream_key"] == cfg.REDIS_STREAM_KEY
