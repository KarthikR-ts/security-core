"""
Security-Core Event Forwarder — Transformer

Converts raw Tetragon JSON events into the unified Security JSON Schema (v1.0.0).
Performs validation, timestamp normalization, provenance tagging, safe deduplication,
and privacy redaction.
"""

import collections
import hashlib
import json
import logging
import uuid
from typing import Any

from .config import Config
from .redaction import EventRedactor
from .validator import KNOWN_EVENT_TYPES, normalize_timestamp

logger = logging.getLogger("security.transformer")

# Bounded in-memory deduplication cache: stores MD5 hashes of recent events
_DEDUP_CACHE_SIZE = 5000
_dedup_cache: collections.deque[str] = collections.deque(maxlen=_DEDUP_CACHE_SIZE)
_dedup_set: set[str] = set()


def _is_duplicate(raw: dict[str, Any]) -> bool:
    """Check if the raw event was recently processed within a bounded window."""
    try:
        # Use a deterministic fingerprint from event_type, process info, and timestamp
        raw_sig = json.dumps(raw, sort_keys=True, default=str)
        fingerprint = hashlib.md5(raw_sig.encode("utf-8")).hexdigest()
    except Exception:
        return False

    if fingerprint in _dedup_set:
        return True

    # Evict oldest entry if deque is full
    if len(_dedup_cache) >= _DEDUP_CACHE_SIZE:
        oldest = _dedup_cache.popleft()
        _dedup_set.discard(oldest)

    _dedup_cache.append(fingerprint)
    _dedup_set.add(fingerprint)
    return False


def clear_dedup_cache() -> None:
    """Clear deduplication cache (useful for testing)."""
    _dedup_cache.clear()
    _dedup_set.clear()


def _event_source_for(capture_mode: str) -> str:
    """
    Map a capture mode to its event_source label.

    Kept explicit rather than a two-way ternary because procfs_live is a third
    source that is genuinely live but is NOT Tetragon. Collapsing it into the
    replay bucket would misreport it; calling it "tetragon" would be a lie.
    """
    return {
        "live_tetragon": "tetragon",
        "procfs_live": "procfs",
    }.get(capture_mode, "tetragon-replay")


def transform_event(
    raw: dict[str, Any],
    capture_mode: str = "fixture_replay",
    config: Config | None = None,
    deduplicate: bool = False,
) -> dict[str, Any] | None:
    """
    Transform a raw Tetragon JSON event into the Security unified schema.

    Returns None if:
      - raw input is not a dictionary or empty
      - event type is unknown or not a supported security event
      - event is a duplicate (when deduplication is enabled)

    Applies timestamp normalization, metadata enrichment, and privacy redaction.
    """
    if not isinstance(raw, dict) or not raw:
        return None

    cfg = config or Config()

    # Deduplication check
    should_dedup = deduplicate or cfg.DEDUPLICATION_ENABLED
    if should_dedup and _is_duplicate(raw):
        logger.debug("Dropping duplicate event")
        return None


    event_type = _detect_event_type(raw)
    if event_type is None:
        return None

    # Extract the inner event payload
    payload = raw.get(event_type, {})
    if not isinstance(payload, dict):
        payload = {}

    process_info = payload.get("process", {})
    if not isinstance(process_info, dict):
        process_info = {}

    parent_info = process_info.get("parent", {})
    if not isinstance(parent_info, dict):
        parent_info = {}

    pod_info = process_info.get("pod", {})
    if not isinstance(pod_info, dict):
        pod_info = {}

    # Build telemetry block
    telemetry = _build_telemetry(process_info, parent_info, pod_info, event_type, payload)

    # Normalize timestamp
    norm_timestamp = normalize_timestamp(raw.get("time"))

    # Assign stable unique event_id
    event_id = raw.get("event_id") or str(uuid.uuid4())

    # Build base Security event
    security_event: dict[str, Any] = {
        "event_id": str(event_id),
        "schema_version": cfg.SCHEMA_VERSION,
        "capture_mode": capture_mode,
        "event_source": _event_source_for(capture_mode),
        "source_host": cfg.SOURCE_HOST,
        "source_arch": cfg.SOURCE_ARCH,
        "timestamp": norm_timestamp,
        "source": "tetragon",
        "event_type": event_type,
        "node_name": str(raw.get("node_name", "unknown")),
        "telemetry": telemetry,
        # Downstream fields filled by triage/explanation/remediation:
        "triage": None,
        "explanation": None,
        "remediation": None,
    }

    # Apply policy-driven privacy redaction BEFORE persistence or exposure
    redactor = EventRedactor(enabled=cfg.PRIVACY_REDACTION_ENABLED, policy=cfg.PRIVACY_POLICY)
    redacted_event = redactor.redact(security_event)

    return redacted_event


def _detect_event_type(raw: dict[str, Any]) -> str | None:
    """Identify the Tetragon event type from the raw JSON."""
    for t in KNOWN_EVENT_TYPES:
        if t in raw:
            return t
    return None


def _build_telemetry(
    process_info: dict[str, Any],
    parent_info: dict[str, Any],
    pod_info: dict[str, Any],
    event_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Build the telemetry block for a Security event with robust type conversions."""
    binary = str(process_info.get("binary", "unknown") or "unknown")
    arguments = process_info.get("arguments", "")

    if isinstance(arguments, list):
        args_list = [str(a) for a in arguments]
    elif isinstance(arguments, str) and arguments:
        args_list = arguments.split(" ")
    else:
        args_list = []

    # Safe integer parsing
    try:
        pid = int(process_info.get("pid", 0) or 0)
    except (ValueError, TypeError):
        pid = 0

    try:
        uid = int(process_info.get("uid", 0) or 0)
    except (ValueError, TypeError):
        uid = 0

    try:
        parent_pid = int(parent_info.get("pid", 0) or 0)
    except (ValueError, TypeError):
        parent_pid = 0

    telemetry: dict[str, Any] = {
        "pid": pid,
        "binary": binary,
        "args": args_list,
        "uid": uid,
        "user": _uid_to_user(uid),
        "cwd": str(process_info.get("cwd", "") or ""),
        "namespace": str(pod_info.get("namespace", "") or ""),
        "pod": str(pod_info.get("name", "") or ""),
        "container_id": str(process_info.get("docker", "") or ""),
        "parent_binary": str(parent_info.get("binary", "") or ""),
        "parent_pid": parent_pid,
    }

    # For kprobe events, extract syscall-specific data
    if event_type == "process_kprobe":
        kprobe_data = _extract_kprobe_data(payload)
        telemetry["kprobe"] = kprobe_data

    return telemetry


def _extract_kprobe_data(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract kprobe-specific data (syscall name, arguments, return value)."""
    function_name = str(payload.get("function_name", "unknown") or "unknown")
    policy_name = str(payload.get("policy_name", "unknown") or "unknown")
    action = str(payload.get("action", "KPROBE_ACTION_POST") or "KPROBE_ACTION_POST")

    # Extract syscall args
    args = []
    for arg in payload.get("args", []):
        if not isinstance(arg, dict):
            continue
        arg_entry: dict[str, Any] = {}
        for key in [
            "string_arg",
            "int_arg",
            "sock_arg",
            "skb_arg",
            "size_arg",
            "bytes_arg",
            "file_arg",
            "truncated_bytes_arg",
        ]:
            if key in arg:
                arg_entry[key] = arg[key]
        if arg_entry:
            args.append(arg_entry)

    ret_val = None
    if isinstance(payload.get("return"), dict):
        ret_val = payload["return"].get("int_arg")

    return {
        "function": function_name,
        "policy": policy_name,
        "action": action,
        "args": args,
        "return_value": ret_val,
    }


def _uid_to_user(uid: int) -> str:
    """Map common UIDs to usernames (best-effort for demo)."""
    uid_map = {
        0: "root",
        33: "www-data",
        65534: "nobody",
        1000: "user",
    }
    return uid_map.get(uid, f"uid:{uid}")
