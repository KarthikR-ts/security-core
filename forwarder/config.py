"""
Security-Core Event Forwarder — Configuration

All settings are loaded from environment variables with sensible defaults.
"""

import os
import platform


class Config:
    """Central configuration loaded from environment variables."""

    # ── Input & Capture Mode ──────────────────────────────────────
    FORWARDER_MODE: str = os.getenv("FORWARDER_MODE", "fixture_replay")
    FIXTURE_PATH: str = os.getenv("FIXTURE_PATH", "fixtures/sample-tetragon-raw.jsonl")
    CAPTURE_MODE: str = os.getenv("CAPTURE_MODE", "fixture_replay")  # fixture_replay | live_tetragon | stdin

    # ── Platform & Provenance Metadata ────────────────────────────
    SOURCE_HOST: str = os.getenv("SOURCE_HOST", "linuxone-node-01")
    SOURCE_ARCH: str = os.getenv("SOURCE_ARCH", platform.machine() or "s390x")
    SCHEMA_VERSION: str = os.getenv("SCHEMA_VERSION", "1.0.0")

    # ── Tetragon ──────────────────────────────────────────────────
    TETRAGON_GRPC_ADDRESS: str = os.getenv("TETRAGON_GRPC_ADDRESS", "localhost:54321")
    TETRA_BIN: str = os.getenv("TETRA_BIN", "tetra")

    # ── /proc Sensor ──────────────────────────────────────────────
    # procfs_live is NOT eBPF. It polls the /proc process table and therefore
    # observes process state rather than kernel events: it can miss processes
    # that exit between two polls, and it cannot observe connect() or similar
    # syscalls at all. It is cheap, unprivileged, and portable to s390x, which
    # is what makes live capture possible on IBM LinuxONE at all.
    PROCFS_POLL_INTERVAL: float = float(os.getenv("PROCFS_POLL_INTERVAL", "2.0"))
    # Denylist is matched against /proc/PID/comm (the kernel-truncated process
    # name), not the command line, so it cannot be evaded with a long argv.
    # Matching is EXACT, not prefix: "systemd" excludes PID 1 only, while
    # systemd-journal, systemd-resolved and friends stay visible — which is
    # what you want, since those are meaningful runtime behaviour. Use
    # substring semantics here and you hide everything.
    # The default excludes credential-bearing daemons that would otherwise
    # capture interactive login sessions. Set to an empty value for full
    # coverage.
    PROCFS_DENYLIST: str = os.getenv("PROCFS_DENYLIST", "sshd,cron,unattended-upgrades,systemd")
    PROCFS_EMIT_EXITS: bool = os.getenv("PROCFS_EMIT_EXITS", "true").lower() in ("true", "1", "yes")
    PROCFS_MAX_ARGS: int = int(os.getenv("PROCFS_MAX_ARGS", "64"))

    # ── Privacy & Redaction ───────────────────────────────────────
    PRIVACY_REDACTION_ENABLED: bool = os.getenv("PRIVACY_REDACTION_ENABLED", "true").lower() in ("true", "1", "yes")
    PRIVACY_POLICY: str = os.getenv("PRIVACY_POLICY", "standard")
    LLM_EXTERNAL_ENRICHMENT_ENABLED: bool = os.getenv("LLM_EXTERNAL_ENRICHMENT_ENABLED", "false").lower() in ("true", "1", "yes")

    # ── Deduplication ─────────────────────────────────────────────
    DEDUPLICATION_ENABLED: bool = os.getenv("DEDUPLICATION_ENABLED", "false").lower() in ("true", "1", "yes")
    DEDUPLICATION_WINDOW_SIZE: int = int(os.getenv("DEDUPLICATION_WINDOW_SIZE", "5000"))


    # ── Redis ─────────────────────────────────────────────────────
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_PASSWORD: str | None = os.getenv("REDIS_PASSWORD")
    REDIS_STREAM_KEY: str = os.getenv("REDIS_STREAM_KEY", "security:events")
    REDIS_MAXLEN: int = int(os.getenv("REDIS_MAXLEN", "10000"))
    REDIS_CONNECT_TIMEOUT: int = int(os.getenv("REDIS_CONNECT_TIMEOUT", "3"))
    REDIS_RETRY_ATTEMPTS: int = int(os.getenv("REDIS_RETRY_ATTEMPTS", "3"))
    REDIS_RETRY_BACKOFF_BASE: float = float(os.getenv("REDIS_RETRY_BACKOFF_BASE", "0.2"))

    # ── Forwarder ─────────────────────────────────────────────────
    EVENT_BUFFER_SIZE: int = int(os.getenv("EVENT_BUFFER_SIZE", "100"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ── API Server ────────────────────────────────────────────────
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "8081"))

    # ── ML Triage ─────────────────────────────────────────────────
    ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", "forwarder/model/xgboost_model.json")
    FEATURE_LIST_PATH: str = os.getenv("FEATURE_LIST_PATH", "forwarder/model/feature_list.json")
    ML_TRIAGE_ENABLED: bool = os.getenv("ML_TRIAGE_ENABLED", "true").lower() in ("true", "1", "yes")

