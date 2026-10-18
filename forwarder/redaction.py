"""
Security-Core Event Forwarder — Privacy Redaction Engine

Applies policy-driven privacy redaction to normalized runtime events
BEFORE Redis persistence, logging, and outbound downstream processing.

Prevents leakage of:
  - Credentials, tokens, API keys, passwords
  - User identifiers (while retaining system roles needed for detection)
  - Raw sensitive paths (e.g., credentials, shadow files)
  - Environment-specific IPs and container IDs
  - Sensitive command-line arguments
"""

import copy
import re
from typing import Any

# Regex patterns for detecting credentials and sensitive tokens
SECRET_PATTERNS = [
    # Bearer tokens / JWTs
    (re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+"), "[REDACTED_JWT]"),
    # Generic API Keys / Tokens / Passwords
    (re.compile(r"(api[_\-]?key|apikey|access[_\-]?token|token|secret|password|passwd)[\s:=]+([^\s,;\"']{6,})", re.IGNORECASE), r"\1=[REDACTED_SECRET]"),
    # URL basic authentication: http://user:pass@host
    (re.compile(r"(https?://)([^:]+):([^@]+)@"), r"\1[REDACTED_USER]:[REDACTED_PASS]@"),
    # Private Key headers
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    # AWS / Cloud Keys
    (re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}"), "[REDACTED_CLOUD_KEY]"),
]

# Sensitive paths that should be masked
SENSITIVE_PATH_PATTERNS = [
    (re.compile(r"^/root/\.ssh(/.*)?$"), "/root/[REDACTED_SSH_KEY_PATH]"),
    (re.compile(r"^/etc/(shadow|gshadow)$"), "/etc/[REDACTED_SHADOW]"),
    (re.compile(r"^/var/run/secrets/kubernetes\.io/serviceaccount/token$"), "/var/run/secrets/.../[REDACTED_K8S_TOKEN]"),
]


# IP Address pattern (IPv4)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Well-known system users that are safe and necessary for security analytics
SYSTEM_USERS = {"root", "nobody", "www-data", "daemon", "sys", "bin", "games", "man", "mail", "news", "uucp", "proxy", "sync"}


def redact_string(val: str, redacted_fields: set[str], field_category: str = "token") -> str:
    """Mask secret patterns and tokens within an arbitrary string."""
    if not isinstance(val, str) or not val:
        return val

    redacted = val
    # Check secrets
    for pattern, replacement in SECRET_PATTERNS:
        if pattern.search(redacted):
            redacted = pattern.sub(replacement, redacted)
            redacted_fields.add(field_category)

    return redacted


def mask_ip(ip_str: str) -> str:
    """Mask IPv4 addresses while preserving network class if needed."""
    if not isinstance(ip_str, str):
        return ip_str
    # Replace last octet
    parts = ip_str.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
    return "[REDACTED_IP]"


class EventRedactor:
    """Configurable, policy-driven event redactor."""

    def __init__(self, enabled: bool = True, policy: str = "standard"):
        self.enabled = enabled
        self.policy = policy

    def redact(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Redacts sensitive fields in the event according to policy.
        Returns a modified deepcopy of the event with a privacy block.
        """
        redacted_event = copy.deepcopy(event)
        redacted_fields: set[str] = set()

        if not self.enabled:
            redacted_event["privacy"] = {
                "redacted": False,
                "redacted_fields": [],
                "policy": "disabled",
                "enabled": False,
            }
            return redacted_event

        telemetry = redacted_event.get("telemetry", {})
        if not isinstance(telemetry, dict):
            telemetry = {}

        # 1. Redact Process Arguments
        args = telemetry.get("args")
        if isinstance(args, list):
            new_args = []
            for arg in args:
                if not isinstance(arg, str):
                    new_args.append(arg)
                    continue

                cleaned_arg = redact_string(arg, redacted_fields, field_category="args.secret")

                # Mask IP addresses in arguments
                if IPV4_PATTERN.search(cleaned_arg):
                    cleaned_arg = IPV4_PATTERN.sub(lambda m: mask_ip(m.group(0)), cleaned_arg)
                    redacted_fields.add("args.ip")

                # Mask sensitive flags like -p password or --token=xyz
                if cleaned_arg != arg:
                    redacted_fields.add("args")
                new_args.append(cleaned_arg)
            telemetry["args"] = new_args

        # 2. Redact Usernames / Identifiers
        user = telemetry.get("user")
        if user and user not in SYSTEM_USERS and not user.startswith("uid:"):
            # Non-system user identity redacted
            telemetry["user"] = "[REDACTED_USER]"
            redacted_fields.add("user")

        # 3. Mask Sensitive Paths
        cwd = telemetry.get("cwd", "")
        if isinstance(cwd, str):
            for path_pat, path_rep in SENSITIVE_PATH_PATTERNS:
                if path_pat.match(cwd):
                    telemetry["cwd"] = path_rep
                    redacted_fields.add("cwd")

        # 4. Truncate / Mask Container IDs
        container_id = telemetry.get("container_id", "")
        if isinstance(container_id, str) and len(container_id) > 12:
            telemetry["container_id"] = container_id[:8] + "..."
            redacted_fields.add("container_id")

        # 5. Redact kprobe network data if present
        kprobe = telemetry.get("kprobe")
        if isinstance(kprobe, dict):
            k_args = kprobe.get("args", [])
            for arg_dict in k_args:
                if isinstance(arg_dict, dict) and "sock_arg" in arg_dict:
                    sock = arg_dict["sock_arg"]
                    if isinstance(sock, dict):
                        if "saddr" in sock:
                            sock["saddr"] = mask_ip(str(sock["saddr"]))
                            redacted_fields.add("kprobe.saddr")
                        if "daddr" in sock:
                            sock["daddr"] = mask_ip(str(sock["daddr"]))
                            redacted_fields.add("kprobe.daddr")

        # 6. Sanitize source_host if it looks like an internal FQDN
        source_host = redacted_event.get("source_host", "")
        if source_host and ("." in source_host or "@" in source_host):
            redacted_event["source_host"] = source_host.split(".")[0]
            redacted_fields.add("source_host")

        # 7. Attach privacy metadata block
        redacted_event["telemetry"] = telemetry
        redacted_event["privacy"] = {
            "redacted": len(redacted_fields) > 0,
            "redacted_fields": sorted(list(redacted_fields)),
            "policy": self.policy,
            "enabled": True,
        }

        return redacted_event


def sanitize_for_logging(event: dict[str, Any]) -> dict[str, Any]:
    """
    Produce a concise, privacy-safe dictionary suitable for structured logs.
    Never includes raw payload strings or secrets.
    """
    telemetry = event.get("telemetry", {})
    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "event_type": event.get("event_type"),
        "capture_mode": event.get("capture_mode"),
        "binary": telemetry.get("binary"),
        "pid": telemetry.get("pid"),
        "user": telemetry.get("user"),
        "pod": telemetry.get("pod"),
        "redacted": event.get("privacy", {}).get("redacted", False),
    }
