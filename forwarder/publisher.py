"""
Security-Core Event Forwarder — Redis Publisher

Publishes transformed Security events to a Redis Stream with bounded exponential backoff.
Falls back to stdout logging if Redis is unavailable.
"""

import json
import logging
import time
from typing import Any

import redis

from .config import Config

logger = logging.getLogger("security.publisher")


class EventPublisher:
    """Publishes Security events to Redis Streams with retries and stdout fallback."""

    RECONNECT_COOLDOWN = 10.0  # seconds between reconnect attempts when Redis is down

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self._redis: redis.Redis | None = None
        self._connected = False
        self._last_connect_attempt = 0.0
        self._connect()

    def _connect(self) -> None:
        """Attempt to connect to Redis with configurable timeout and cooldown."""
        self._last_connect_attempt = time.time()
        try:
            self._redis = redis.Redis(
                host=self.config.REDIS_HOST,
                port=self.config.REDIS_PORT,
                db=self.config.REDIS_DB,
                password=self.config.REDIS_PASSWORD,
                decode_responses=True,
                socket_connect_timeout=self.config.REDIS_CONNECT_TIMEOUT,
                socket_timeout=self.config.REDIS_CONNECT_TIMEOUT,
                retry_on_timeout=True,
            )
            self._redis.ping()
            self._connected = True
            logger.info(
                "Connected to Redis at %s:%d (stream: %s)",
                self.config.REDIS_HOST,
                self.config.REDIS_PORT,
                self.config.REDIS_STREAM_KEY,
            )
        except (redis.ConnectionError, redis.TimeoutError, Exception) as e:
            self._connected = False
            logger.warning(
                "Redis unavailable (%s). Degrading to stdout fallback.", e
            )

    @property
    def is_connected(self) -> bool:
        """Check if Redis connection is active."""
        if not self._connected or self._redis is None:
            return False
        try:
            return bool(self._redis.ping())
        except Exception:
            self._connected = False
            return False

    def publish(self, event: dict[str, Any]) -> str | None:
        """
        Publish an event to the Redis stream with bounded retry.

        Returns the stream message ID on success, or None on fallback/failure.
        """
        event_json = json.dumps(event, default=str)

        # If not connected, attempt reconnection only if cooldown elapsed
        if not self._connected:
            if time.time() - self._last_connect_attempt > self.RECONNECT_COOLDOWN:
                self._connect()


        # Try publishing to Redis with bounded exponential backoff
        if self._connected and self._redis is not None:
            attempts = max(1, self.config.REDIS_RETRY_ATTEMPTS)
            for attempt in range(attempts):
                try:
                    msg_id = self._redis.xadd(
                        self.config.REDIS_STREAM_KEY,
                        {"event": event_json},
                        maxlen=self.config.REDIS_MAXLEN,
                    )
                    logger.debug(
                        "Published event %s -> Redis stream %s (ID: %s)",
                        event.get("event_id"),
                        self.config.REDIS_STREAM_KEY,
                        msg_id,
                    )
                    return str(msg_id)
                except (redis.ConnectionError, redis.TimeoutError) as e:
                    logger.warning(
                        "Redis publish attempt %d/%d failed: %s",
                        attempt + 1,
                        attempts,
                        e,
                    )
                    if attempt < attempts - 1:
                        backoff = self.config.REDIS_RETRY_BACKOFF_BASE * (2 ** attempt)
                        time.sleep(backoff)
                    else:
                        self._connected = False
                        logger.warning("Redis publish retries exhausted. Falling back to stdout.")
                except Exception as e:
                    logger.error("Unexpected error publishing to Redis: %s", e)
                    self._connected = False
                    break

        # Fallback: write to stdout
        print(event_json, flush=True)
        return None

    def get_health(self) -> dict[str, Any]:
        """Return connectivity and publishing health metrics."""
        return {
            "connected": self.is_connected,
            "host": self.config.REDIS_HOST,
            "port": self.config.REDIS_PORT,
            "stream_key": self.config.REDIS_STREAM_KEY,
        }

    def close(self) -> None:
        """Close the Redis connection safely."""
        if self._redis is not None:
            try:
                self._redis.close()
            except Exception:
                pass
            self._redis = None
            self._connected = False
