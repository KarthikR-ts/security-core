#!/usr/bin/env python3
"""
Workload Security — Person 2 Event Pipeline Smoke Test

Verifies the end-to-end replay pipeline without requiring live eBPF/Tetragon:
  1. Validates Redis connectivity (security:events stream).
  2. Ingests a deterministic fixture containing both valid events and a malformed record.
  3. Verifies schema normalization, timestamp UTC formatting, and provenance tagging.
  4. Verifies policy-driven privacy redaction (IPs, credentials, secrets masked).
  5. Confirms published events in the Redis stream match expected schema and IDs.
  6. Confirms malformed records are quarantined/counted without aborting the run.
  7. Exits with 0 on success, non-zero on failure.
"""

import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import redis
from forwarder.api import _metrics
from forwarder.config import Config
from forwarder.main import process_line, stream_from_file
from forwarder.publisher import EventPublisher
from forwarder.validator import validate_security_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("security.smoke_test")


def main() -> int:
    logger.info("============================================================")
    logger.info("  Workload Security Replay Pipeline — Verification Smoke Test  ")
    logger.info("============================================================")

    config = Config()
    config.REDIS_STREAM_KEY = os.getenv("SMOKE_STREAM_KEY", "security:smoke_events")
    config.PRIVACY_REDACTION_ENABLED = True

    # 1. Verify Redis connectivity
    logger.info("[1/5] Checking Redis connectivity at %s:%d...", config.REDIS_HOST, config.REDIS_PORT)
    r = redis.Redis(
        host=config.REDIS_HOST,
        port=config.REDIS_PORT,
        db=config.REDIS_DB,
        password=config.REDIS_PASSWORD,
        socket_connect_timeout=3,
        decode_responses=True,
    )
    try:
        r.ping()
        logger.info("  -> Redis is online and responding to PING.")
    except Exception as e:
        logger.error("  -> Redis connection failed: %s", e)
        logger.error("  -> Prerequisite: Please start Redis before running the smoke test.")
        logger.error("     Command: docker run -d --name security-redis -p 6379:6379 redis:7-alpine")
        return 1

    # Clean smoke test stream key before test
    r.delete(config.REDIS_STREAM_KEY)

    # 2. Build deterministic test fixture
    logger.info("[2/5] Preparing deterministic fixture (including malformed record)...")
    sample_raw_file = ROOT_DIR / "fixtures" / "sample-tetragon-raw.jsonl"
    if not sample_raw_file.exists():
        logger.error("Fixture file missing: %s", sample_raw_file)
        return 1

    with open(sample_raw_file, "r", encoding="utf-8") as f:
        valid_lines = [line.strip() for line in f if line.strip()]

    # Inject a malformed line in the middle to verify fault tolerance
    smoke_lines = valid_lines[:2] + ["{corrupted_json_line: INVALID_RECORD}"] + valid_lines[2:]

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl") as tf:
        for sl in smoke_lines:
            tf.write(sl + "\n")
        temp_fixture_path = tf.name

    publisher = EventPublisher(config)
    assert publisher.is_connected, "Publisher must be connected to Redis for this test"

    initial_errors = _metrics["errors_total"]

    # 3. Stream through the ingestion pipeline
    logger.info("[3/5] Streaming fixture through ingestion and redaction pipeline...")
    try:
        processed_count = stream_from_file(temp_fixture_path, publisher, config)
    finally:
        Path(temp_fixture_path).unlink(missing_ok=True)
        publisher.close()

    # 4. Verify Ingestion Assertions
    logger.info("[4/5] Evaluating pipeline assertions...")
    logger.info("  Valid events processed: %d (expected 4)", processed_count)
    if processed_count != 4:
        logger.error("Assertion failed: expected 4 valid events, got %d", processed_count)
        return 1

    new_errors = _metrics["errors_total"] - initial_errors
    logger.info("  Malformed records quarantined: %d (expected >= 1)", new_errors)
    if new_errors < 1:
        logger.error("Assertion failed: malformed record was not detected and counted")
        return 1

    # 5. Verify published events directly from the Redis stream
    logger.info("[5/5] Inspecting published events from Redis stream '%s'...", config.REDIS_STREAM_KEY)
    stream_entries = r.xrange(config.REDIS_STREAM_KEY)
    if len(stream_entries) != 4:
        logger.error("Assertion failed: expected 4 stream entries in Redis, found %d", len(stream_entries))
        return 1

    for msg_id, data in stream_entries:
        raw_event_json = data.get("event")
        if not raw_event_json:
            logger.error("Stream message %s has no 'event' field", msg_id)
            return 1

        event = json.loads(raw_event_json)
        is_valid, err = validate_security_event(event)
        if not is_valid:
            logger.error("Event validation failed for ID %s: %s", event.get("event_id"), err)
            return 1

        # Check Datathon requirements
        assert event["schema_version"] == "1.0.0", f"Unexpected schema_version: {event['schema_version']}"
        assert event["capture_mode"] == "fixture_replay", f"Replay event mislabeled as: {event['capture_mode']}"
        assert event["event_source"] == "tetragon-replay", f"Unexpected event_source: {event['event_source']}"
        assert "privacy" in event, "Privacy metadata missing"
        assert event["privacy"]["enabled"] is True, "Privacy redaction was not enabled"

        # Check reverse shell privacy redaction specifically
        if event["telemetry"]["binary"] == "/bin/nc":
            assert event["privacy"]["redacted"] is True
            assert "10.0.0.99" not in " ".join(event["telemetry"]["args"]), "Raw IP leaked in process args!"
            assert "10.0.0.xxx" in " ".join(event["telemetry"]["args"]), "IP was not properly masked!"
            logger.info("  -> Verified reverse-shell IP masking: '10.0.0.xxx' present, raw IP redacted.")

        # Check kprobe socket address redaction
        if event["event_type"] == "process_kprobe":
            assert event["privacy"]["redacted"] is True
            logger.info("  -> Verified kprobe syscall telemetry redaction.")

    # Clean up test stream
    r.delete(config.REDIS_STREAM_KEY)

    logger.info("============================================================")
    logger.info("  ALL SMOKE TEST ASSERTIONS PASSED (100%% SUCCESS)           ")
    logger.info("============================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
