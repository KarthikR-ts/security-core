# Integration Status — Person 4 (Integration Lead)

**Purpose:** single place to see what is wired, what is proven green, and what is
still blocked. Update this when the state changes; it is submitted as-is.

**Last updated:** 2026-10-17

---

## 1. Source of Truth

| Artifact | Owner | Status |
|---|---|---|
| `docs/EVENT_CONTRACT.md` (schema `1.0.0`) | Person 2 | ✅ Stable. Person 3 fields are **additive/optional** (§3.1); no breaking change. |
| `docs/PRIVACY_POLICY.md` | Person 3 | ✅ Enforced in `forwarder/redaction.py` at write time. |
| `docs/DEMO_SCRIPT.md` | Person 4 | ✅ Script ready; video recording is a human task. |
| `.env.example` / `.env.remediation.example` | Person 1/3 | ✅ Placeholders only — no real keys committed. |

Schema rule: **no field renames**, additions only, consumers ignore unknown
fields. The replay smoke test asserts `schema_version == "1.0.0"`.

---

## 2. Service & Port Map

| Service | Port | Start command | Health endpoint |
|---|---|---|---|
| Redis (event stream `security:events`) | 6379 | `redis-server --port 6379` | `redis-cli ping` |
| Forwarder API (metrics/recent events) | 8081 | `python live_backend.py` | `GET /health` |
| Dashboard API (this repo's BFF) | 8080 | `python dashboard_api.py` | `GET /api/health` |
| Orchestrator API (analysis) | 8000 | `python main.py` | `GET /health` |
| Frontend (Vite dev) | 5173 | `cd dashboard && npm run dev` | — |
| ChromaDB (optional, docker profile) | 8100 → 8000 | `docker compose up chromadb` | — |

Docker path: `docker compose up --build -d` maps the same ports (see
`docker-compose.yml`). Local (no Docker) path is the supported demo path.

---

## 3. Data Flow (as wired today)

```text
fixtures/sample-tetragon-raw.jsonl
        │  python -m forwarder.main --mode fixture_replay
        ▼
forwarder/transformer.py  ── validate → normalize → redact → privacy block
        │
        ▼
Redis stream  security:events   (XADD MAXLEN ~ 10000)
        │                                  │
        ▼                                  ▼
dashboard_api.py  ── XREVRANGE/XREAD   main.py /security/analyze
  /api/events (enriched)                  │
  /api/health (platform block)            ▼
  WS /api/ws/events                orchestrator.analyze_alert()
        │                            ├─ offline: rule-based MITRE + template report
        ▼                            └─ online (opt-in): Pinecone RAG + Gemini
  React dashboard (5173)
```

---

## 4. Merge / Dependency Status

| Item | Status | Notes |
|---|---|---|
| Event schema v1.0.0 | ✅ Frozen | Additive extensions documented. |
| Forwarder → Redis | ✅ Green | Replay smoke test covers publish + read-back. |
| Redis → Dashboard API | ✅ Green | Degrades to empty cache with `redis: disconnected`. |
| Dashboard API → Frontend | ✅ Green | `capture_mode`, `privacy`, `explanation` passed through and rendered. |
| Orchestrator offline path | ✅ Green | Deterministic MITRE mapping; no external calls by default. |
| Orchestrator online path (Gemini/Pinecone) | ⚪ Opt-in | Gated by `LLM_EXTERNAL_ENRICHMENT_ENABLED=true`; not required for demo. |
| Remediation agent (Node D) | ✅ Green | `event_id` now threaded from `analyze_alert()`; default `human-in-loop` + dry-run. |
| Remediation → Dashboard | ✅ Green | `pending_approval` / `dry_run` rendered explicitly; nothing executes silently. |

### Blocked / open items

| Item | Owner | Blocker |
|---|---|---|
| Demo video recording | Human | Needs quiet 10 minutes + screen recorder. |
| Judge repo access | Human | Private repo — send invite or flip visibility. |
| Live Tetragon capture (optional stretch) | Person 1 | Requires LinuxONE/kind cluster with Tetragon; demo does not depend on it. |
| CIS Azure benchmark context offline | — | Not reproduced offline; UI states it was not retrieved instead of faking it. |

---

## 5. Verification Commands (green-path)

```bash
# 0. Redis up (new terminal)
redis-server --port 6379

# 1. End-to-end replay → Redis → read-back (asserts schema/capture/privacy)
python scripts/smoke_test_replay.py

# 2. Unit + integration suites (no network required)
python -m pytest forwarder/tests tests -v

# 3. Dashboard API up, then
curl -s localhost:8080/api/health | python -m json.tool
# expect: platform.capture_mode = fixture_replay (or stdin/live_tetragon),
#         components.remediation_agent.dry_run = true,
#         components.remediation_agent.autonomy_mode = "human-in-loop"
```

**Smoke result:** see §7 (recorded after the final run).

---

## 6. Known Integration Risks

1. **Frontend build** requires `npm install` on a machine with network — do this
   before the demo day, then `npm run build` produces a static bundle.
2. **Redis version** ≥ 5 required for `XREAD BLOCK` semantics used by the WS
   listener (tested on 7.x/8.x).
3. **Python version** — suites are verified on Python 3.12; XGBoost is optional
   (heuristic triage covers s390x where wheels are unavailable).
4. **Two `XREAD` consumers** (dashboard WS + remediation audit logger) read the
   same stream independently; no consumer-group contention.

---

## 7. Smoke Test Log

| Date | Command | Result |
|---|---|---|
| 2026-10-17 | `python -m pytest forwarder/tests tests -v` | 91 passed, 19 failed — all pre-existing, not caused by Person 3/4 changes (see §8) |
| 2026-10-17 | `python scripts/smoke_test_replay.py` | ✅ ALL ASSERTIONS PASSED — 4 valid events published, malformed line quarantined, `10.0.0.xxx` masking verified |

---

## 8. Pre-existing Test Failures (not Person 3/4 regressions)

The 19 failures in §7 were triaged against the working tree diff and are
unrelated to the Person 3/4 changes:

| Group | Tests | Cause |
|---|---|---|
| Legacy REST surface | 13 × `tests/test_api.py` | Tests target an older `/analyze`, `/status`, `/ingest/trigger` app and patch `main.analyze_alert` / `main.SecurityIngestor`; today's `main.py` (unchanged by this work) serves `/health`, `/security/analyze`, `/`. |
| Async plugin missing | 4 × `tests/test_integration.py` | Tests use `@pytest.mark.asyncio`; `pytest-asyncio` is not installed in this environment. |
| SDK / config rot | 1 × `test_rag_retrieval_success` | Patches `google.genai.embed_content`, which the installed google-genai SDK no longer exposes. |
| Config rot | 1 × `test_pinecone_config_required` | Imports `PINECONE_ENV` from `orchestrator`; the constant is absent at `HEAD` as well. |

The Person 3/4 acceptance suites (`tests/test_person3_explainability.py`,
`tests/test_remediation_safety.py`, `tests/test_dashboard_api.py`) are fully
green: 40 passed.
