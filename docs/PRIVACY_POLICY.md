# Privacy & Redaction Policy

**Owner:** Person 3 (Detection / AI Explainability / Privacy / Remediation Safety)
**Enforced by:** `forwarder/redaction.py` (write-time redaction), `orchestrator.py` (LLM prompt sanitization)
**Contract reference:** `docs/EVENT_CONTRACT.md` §5

---

## 1. Principles

1. **Redact before persistence.** Redaction runs inside
   `forwarder/transformer.py` *before* an event is published to Redis, logged,
   or handed to any downstream consumer. There is no window in which
   unredacted telemetry is stored.
2. **Redact before egress.** When external enrichment (Gemini / Pinecone) is
   enabled, only a sanitized copy of the event
   (`orchestrator.sanitize_event_for_llm`) is placed into prompts and query
   strings. The raw event never leaves the host.
3. **Retain what detection needs, drop what it does not.** Fields required for
   behavioural classification (PID, binary path, syscall, system user, pod /
   namespace) are retained. Identifiers and secrets are masked.
4. **Auditable by design.** Every event carries a `privacy` block listing which
   field categories were redacted, and the streaming pipeline is deterministic —
   the same input produces the same redaction.

---

## 2. Field-by-Field Policy

| Field | Retained / Redacted | Rationale |
|---|---|---|
| `telemetry.pid` | Retained | Numeric process ID; needed for process-lineage correlation. Not PII by itself. |
| `telemetry.binary` | Retained | Core behavioural signal for triage (e.g. `nc`, `curl`, `runc`). |
| `telemetry.args[]` | **Redacted** (partial) | Secrets/tokens/passwords replaced with `[REDACTED_*]`; IPv4 addresses masked to `10.0.0.xxx`; flag names retained so behaviour is still classifiable. |
| `telemetry.uid` | Retained | Numeric UID; needed for privilege classification (uid 0 = root). |
| `telemetry.user` | **Redacted** (conditional) | System accounts (`root`, `nobody`, `www-data`, …) and `uid:*` placeholders retained. Any non-system account masked to `[REDACTED_USER]`. |
| `telemetry.cwd` | **Redacted** (conditional) | Sensitive locations (`/root/.ssh`, `/etc/shadow`, service-account token) masked. Other paths retained. |
| `telemetry.namespace` | Retained | Kubernetes namespace; required to scope remediation. Not PII. |
| `telemetry.pod` | Retained | Pod name; required to scope remediation. Not PII. |
| `telemetry.container_id` | **Truncated** to 8 chars + `...` | Full container ID could enable host correlation; prefix is enough for UI display. |
| `telemetry.parent_binary` / `parent_pid` | Retained | Needed for shell-spawn / lineage detection. |
| `telemetry.kprobe.*` | **IPs masked** | `sock_arg.saddr` / `daddr` last octet masked. Syscall args otherwise retained. |
| `source_host` | **Redacted** (conditional) | FQDN-like or email-like hostnames are cut to their first label. |
| `privacy.*` | Retained | Redaction audit block (`enabled`, `redacted`, `redacted_fields`, `policy`). |

### Secret pattern catalogue (`forwarder/redaction.py`)

| Pattern | Replacement |
|---|---|
| Bearer tokens, JWTs | `Bearer [REDACTED_TOKEN]`, `[REDACTED_JWT]` |
| `api_key=…`, `token=…`, `password=…` etc. | `<key>=[REDACTED_SECRET]` |
| Basic-auth URLs `http://user:pass@host` | `http://[REDACTED_USER]:[REDACTED_PASS]@` |
| Private key blocks | `[REDACTED_PRIVATE_KEY]` |
| AWS/GCP-style access key IDs | `[REDACTED_CLOUD_KEY]` |
| IPv4 anywhere in args / kprobe sockets | last octet → `xxx` |

---

## 3. LLM / External Enrichment Controls

| Control | Default | Effect |
|---|---|---|
| `LLM_EXTERNAL_ENRICHMENT_ENABLED` | `false` | When off, no request is ever made to Gemini or Pinecone. MITRE mapping is done by the deterministic offline rule set (`orchestrator.map_mitre_offline`). |
| `OFFLINE_MODE` | `false` | Hard override — forces offline even if a key is present. |
| Prompt sanitization | always on | Every user-controlled field passes through `sanitize_event_for_llm` before entering a prompt or embedding query. |
| Mitigation provenance | always recorded | `provenance.mitre_mapping` records whether mapping was `offline_rules` or `pinecone_rag`; `provenance.sanitized_input` records whether scrubbed values were used. |

---

## 4. Retention & Exposure

- **Redis stream:** `security:events` (bounded by `MAXLEN ~ 10000`), already
  redacted at write time.
- **Logs:** application loggers must call `sanitize_for_logging(event)`.
  Raw arguments and payload strings are never written to log files.
- **Exports:** anything exported from the dashboard (JSON, screenshots) inherits
  the redactions already applied upstream.

---

## 5. Verification

| Check | Location |
|---|---|
| Redaction unit behaviour (JWT, bearer, password, IP masking, user masking) | `tests/test_forwarder.py`, `forwarder/tests/` |
| LLM prompt sanitization | `tests/test_person3_explainability.py::TestOrchestratorOffline` |
| Offline default (no external calls) | `tests/test_person3_explainability.py`, `scripts/smoke_test_replay.py` asserts `privacy.redacted_fields` on replayed fixtures |
| Redaction markers surfaced in dashboard | `dashboard_api._enrich_event_for_dashboard` → `/api/events`, asserted in `tests/test_dashboard_api.py` |

---

## 6. Known Limitations (stated honestly)

- The secret catalogue is regex-based; a secret that does not match a known
  shape (e.g. a random 12-char password not preceded by a known key name) is
  not detected. Redaction is defence-in-depth, not a guarantee.
- System-user retention means the *existence* of root activity is visible in the
  ledger. That is intentional and required for detection.
- Fixture replay events are synthetic and contain no real personal data, but the
  same pipeline runs on live Tetragon events, which is why the write-time
  redaction guarantee matters.
