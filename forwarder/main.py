"""
Security-Core Event Forwarder — Main Entry Point

Unified ingestion pipeline supporting:
  1. live_tetragon  — live Tetragon eBPF telemetry via tetra CLI / gRPC
  2. fixture_replay — replay events from a JSONL fixture file
  3. stdin          — pipe JSON lines into the forwarder

Applies unified validation, timestamp normalization, privacy redaction,
and publishing to Redis Streams (security:events) with stdout fallback.
"""

import argparse
import json
import logging
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import uvicorn

from .api import app as fastapi_app
from .api import record_error, record_event, set_ml_triage, set_redis_status
from .config import Config
from .ml_triage import MLTriage
from .publisher import EventPublisher
from .redaction import sanitize_for_logging
from .transformer import transform_event

# ── Logging Setup ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-22s │ %(levelname)-5s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("security.forwarder")

# ── Globals ───────────────────────────────────────────────────────
_shutdown = threading.Event()
_ml_triage: MLTriage | None = None


def start_api_server(config: Config) -> None:
    """Run the FastAPI metrics server in a background thread."""
    uvicorn.run(
        fastapi_app,
        host=config.API_HOST,
        port=config.API_PORT,
        log_level="warning",
    )


def process_line(
    line: str,
    publisher: EventPublisher,
    capture_mode: str = "fixture_replay",
    config: Config | None = None,
) -> dict[str, Any] | None:
    """
    Parse a single JSON line, validate, normalize, redact, and publish.
    Handles malformed records gracefully without aborting the pipeline.
    """
    line = line.strip()
    if not line:
        return None

    cfg = config or Config()

    try:
        raw_event = json.loads(line)
    except json.JSONDecodeError as e:
        # Sanitize error message to prevent sensitive payload reflection in logs
        logger.warning("Skipping malformed JSON line (parse error: %s)", type(e).__name__)
        record_error()
        return None

    if not isinstance(raw_event, dict):
        logger.warning("Skipping non-dictionary JSON record")
        record_error()
        return None

    security_event = transform_event(raw_event, capture_mode=capture_mode, config=cfg)
    if security_event is None:
        return None  # Filtered or duplicate or irrelevant event type

    # Run ML/Rule Triage if enabled
    if _ml_triage and cfg.ML_TRIAGE_ENABLED:
        try:
            triage_results = _ml_triage.triage_event(security_event)
            security_event["triage"] = triage_results.get("triage")
            security_event["explanation"] = triage_results.get("explanation")
        except Exception as e:
            logger.error("Triage evaluation error: %s", e)

    # Publish to Redis Stream (or stdout fallback)
    publisher.publish(security_event)

    # Record for API metrics
    record_event(security_event)

    # Privacy-safe structured log
    safe_summary = sanitize_for_logging(security_event)
    logger.info(
        "📡 [%s] mode=%s pid=%s binary=%s pod=%s redacted=%s",
        safe_summary.get("event_type"),
        safe_summary.get("capture_mode"),
        safe_summary.get("pid"),
        safe_summary.get("binary"),
        safe_summary.get("pod"),
        safe_summary.get("redacted"),
    )
    return security_event


def stream_from_tetra(config: Config, publisher: EventPublisher) -> None:
    """Stream live events from the tetra CLI subprocess."""
    cmd = [
        config.TETRA_BIN,
        "getevents",
        "-o", "json",
        "--server-address", config.TETRAGON_GRPC_ADDRESS,
    ]
    logger.info("🚀 Starting live tetra stream: %s", " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line-buffered
        )
    except FileNotFoundError:
        logger.error(
            "❌ Tetra binary '%s' not found. Ensure tetra CLI is installed or use --mode fixture_replay.",
            config.TETRA_BIN,
        )
        sys.exit(1)

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if _shutdown.is_set():
                break
            process_line(line, publisher, capture_mode="live_tetragon", config=config)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logger.info("🛑 Tetra process terminated.")


def stream_from_file(filepath: str, publisher: EventPublisher, config: Config) -> int:
    """
    Read events sequentially from a JSON-lines file (bounded memory streaming).
    Returns count of valid events processed.
    """
    path = Path(filepath)
    if not path.exists():
        logger.error("❌ Fixture file not found: %s", filepath)
        sys.exit(1)

    logger.info("📂 Replaying events from fixture file: %s", filepath)
    processed_count = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if _shutdown.is_set():
                break
            event = process_line(line, publisher, capture_mode="fixture_replay", config=config)
            if event is not None:
                processed_count += 1

    logger.info("✅ Finished fixture replay (%d valid events processed)", processed_count)
    return processed_count


def stream_from_stdin(publisher: EventPublisher, config: Config) -> int:
    """Read events from standard input line by line."""
    logger.info("📥 Reading events from standard input...")
    processed_count = 0
    try:
        for line in sys.stdin:
            if _shutdown.is_set():
                break
            event = process_line(line, publisher, capture_mode="stdin", config=config)
            if event is not None:
                processed_count += 1
    except KeyboardInterrupt:
        pass
    logger.info("✅ Finished stdin stream (%d valid events processed)", processed_count)
    return processed_count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Security-Core Event Forwarder — Unified eBPF/Replay Ingestion Pipeline"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["live_tetragon", "fixture_replay", "stdin", "live", "replay"],
        help="Ingestion mode: 'live_tetragon', 'fixture_replay', or 'stdin'",
    )
    parser.add_argument(
        "--file", "-f",
        help="Path to a JSON-lines file for replay mode",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read events from stdin",
    )
    parser.add_argument(
        "--no-api",
        action="store_true",
        help="Disable background metrics/health FastAPI server",
    )
    args = parser.parse_args()

    config = Config()
    logging.getLogger().setLevel(config.LOG_LEVEL)

    # Determine execution mode with safe fallback to replay
    mode = config.FORWARDER_MODE
    if args.mode:
        if args.mode in ("live", "live_tetragon"):
            mode = "live_tetragon"
        elif args.mode in ("replay", "fixture_replay"):
            mode = "fixture_replay"
        elif args.mode == "stdin":
            mode = "stdin"
    elif args.file:
        mode = "fixture_replay"
    elif args.stdin:
        mode = "stdin"

    # ── Signal Handling ───────────────────────────────────────────
    def _handle_signal(signum, frame):
        logger.info("Received signal %d, initiating graceful shutdown...", signum)
        _shutdown.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # ── Publisher ─────────────────────────────────────────────────
    publisher = EventPublisher(config)
    set_redis_status(publisher.is_connected)

    # ── ML/Rule Triage ────────────────────────────────────────────
    global _ml_triage
    if config.ML_TRIAGE_ENABLED:
        _ml_triage = MLTriage(
            model_path=Path(config.ML_MODEL_PATH),
            feature_list_path=Path(config.FEATURE_LIST_PATH),
        )
        set_ml_triage(_ml_triage)

    # ── API Server (background thread) ────────────────────────────
    if not args.no_api:
        api_thread = threading.Thread(
            target=start_api_server,
            args=(config,),
            daemon=True,
        )
        api_thread.start()
        logger.info("🌐 API server active on http://%s:%d", config.API_HOST, config.API_PORT)

    # ── Event Ingestion Stream ────────────────────────────────────
    try:
        if mode == "fixture_replay":
            file_to_replay = args.file or config.FIXTURE_PATH
            stream_from_file(file_to_replay, publisher, config)
        elif mode == "stdin":
            stream_from_stdin(publisher, config)
        elif mode == "live_tetragon":
            stream_from_tetra(config, publisher)
        else:
            logger.error("Unknown ingestion mode: %s. Defaulting to fixture replay.", mode)
            stream_from_file(config.FIXTURE_PATH, publisher, config)
    finally:
        publisher.close()
        logger.info("🏁 Security Event Forwarder stopped cleanly.")


if __name__ == "__main__":
    main()
