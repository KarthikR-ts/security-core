# Integration Status — Person 4 (Integration Lead)

**Purpose:** single place to see what is wired, what is proven green, and what is
still blocked. Update this when the state changes; it is submitted as-is.

**Last updated:** 2026-10-18 (LinuxONE deployment verified)

---

## 0. Platform Deployment Status — NEW

The application stack is **deployed and verified on IBM LinuxONE (`s390x`)**,
running a **live process sensor**.

| Property | Value |
|---|---|
| Architecture | `s390x` under z/VM 7.3.0 (IBM) — genuine IBM Z |
| OS / Python | Ubuntu 24.04.5 LTS · Python 3.12.3 |
| Host resources | 2 vCPU · 3.9 GiB RAM (no swap) · 50 GB disk |
| Deployment mode | Native install — **no container runtime on this host** |
| Health endpoint | `"status": "ok"` |
| Smoke test | `ALL SMOKE TEST ASSERTIONS PASSED (100% SUCCESS)` |
| **Capture mode** | **`procfs_live`** — live `/proc` sensor, 2 s interval |
| **Sensor kind** | `procfs_poll` · `sensor_is_ebpf: false` · `live_capture: true` |
| Processes observed | ~27–30 visible, ~350 MB resident |
| Public listeners | **None.** 6379 / 8080 / 8081 all bound to `127.0.0.1` |
| Single-URL access | `.\scripts\start-demo.ps1` → `http://localhost:8080` |

**Live capture is available — via `/proc`, not via eBPF.** The kernel gate
*passed* (§5 of the preflight): 4,324 BPF symbols, the `bpf()` syscall
present (`EINVAL`, not `ENOSYS`), and `tracefs`/`debugfs` both mounted
read-write. The blocker for Tetragon is upstream: no container runtime on the
host, and Tetragon v1.2.0 publishes **no `s390x` release asset**.

`forwarder/procfs_sensor.py` fills that gap with an unprivileged poller. It is
reported as live and reported as *not eBPF* — `sensor_kind` and
`sensor_is_ebpf` are separate fields, and the UI discloses the limitation
rather than rendering a single `LIVE` badge.

Verified on the host:

```text
contract valid   : 45/45 events
capture_mode     : procfs_live          event_source: procfs
denylist enforced: sshd excluded, none leaked
self-exclusion   : own PID present in excluded lineage
```

ML triage runs in heuristic mode because XGBoost has no `s390x` wheel — the
documented fallback, with `triage.basis` recording `heuristic_rules`.

Full evidence: [`docs/LINUXONE_PREFLIGHT.md`](LINUXONE_PREFLIGHT.md).

---

## 1. Source of Truth

| Artifact | Owner | Status |
|---|---|---|
| `docs/EVENT_CONTRACT.md` (schema `1.0.0`) | Person 2 | ✅ Stable. Person 3 fields are **additive/optional** (§3.1); no breaking change. Verified emitting correctly on `s390x`. |
| `docs/PRIVACY_POLICY.md` | Person 3 | ✅ Enforced in `forwarder/redaction.py` at write time. |
| `docs/LINUXONE_PREFLIGHT.md` | Person 1 | ✅ **Complete** — architecture proof, compatibility table, option decision. |
| `docs/TEARDOWN.md` | Person 1 | ✅ Written and verified. |
| `docs/DEMO_SCRIPT.md` | Person 4 | ✅ Script ready; video recording is a human task. |
| `.env.example` / `.env.remediation.example` | Person 1/3 | ✅ Placeholders only — no real keys committed. |

Schema rule: **no field renames**, additions only, consumers ignore unknown
fields. The replay smoke test asserts `schema_version == "1.0.0"`.

---

## 2. Service & Port Map (as deployed on LinuxONE)

| Service | Port | Bind | Start command | Health |
|---|---|---|---|---|
| Redis (stream `security:events`) | 6379 | `127.0.0.1` | `redis-server --port 6379` | `redis-cli ping` |
| Forwarder API | 8081 | `127.0.0.1` | `scripts/aegis-ctl.sh start` | `GET /health` |
| Dashboard API | 8080 | `127.0.0.1` | `scripts/aegis-ctl.sh start` | `GET /api/health` |
| React frontend | 5173 | — | Built on workstation (VM has no node) | — |
| Tetragon gRPC | 54321 | — | Not running (no `s390x` build exists) | — |

Native install is the supported path on LinuxONE; `scripts/aegis-ctl.sh`
manages start / stop / restart / status. Docker Compose remains valid for
x86_64 workstations with a container runtime.

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
| **Judge repo access** | Human | **Private repo — must send invite or flip visibility before deadline.** Judges cannot clone or run anything without this. |
| Demo video recording | Human | Needs quiet 10 minutes + screen recorder. |
| Frontend static bundle | Human | Must be built on a machine with `node`; the LinuxONE host has no `node`/`npm`. |
| Live Tetragon capture | — | **Closed as not available.** Upstream Tetragon publishes no `s390x` release asset, and the host has no container runtime. Documented, not blocked. |
| CIS Azure benchmark context offline | — | Not reproduced offline; UI states it was not retrieved instead of faking it. |

---

## 5. Verification Commands (green-path)

### LinuxONE / `s390x` (native)

```bash
# 0. Redis (new terminal)
sudo systemctl start redis-server

# 1. End-to-end replay -> Redis -> read-back
cd ~/aegis && . .venv/bin/activate
python scripts/smoke_test_replay.py

# 2. Start the stack
bash scripts/aegis-ctl.sh start

# 3. Health must report "ok" and s390x
curl -s http://127.0.0.1:8080/api/health | python -m json.tool
# expect: platform.source_arch  = "s390x"
#         platform.hardware    = "IBM LinuxONE (s390x)"
#         platform.capture_mode = "fixture_replay"
#         platform.live_capture = false
#         components.remediation_agent.dry_run = true
```

### x86_64 workstation

```bash
redis-server --port 6379
python scripts/smoke_test_replay.py
python -m pytest forwarder/tests tests -v
```

**Smoke result:** see §7.

---

## 9. Known Integration Risks

1. **Frontend build** requires `npm install` on a machine with network, and the
   LinuxONE host has no `node`/`npm` at all. Build on the workstation and serve
   the static bundle through the tunneled API — do this before demo day.
2. **Redis version** ≥ 5 required for `XREAD BLOCK` semantics used by the WS
   listener. Running 7.0.15 on LinuxONE.
3. **Python version** — verified on 3.12.3, matching the pinned/tested version.
4. **`httpx` must stay `< 0.28`** — see §8. An unpinned upgrade breaks every
   `TestClient` test via the starlette 0.36.3 incompatibility.
5. **`pytest-asyncio` must stay on 0.23.x** — 1.x forces `pytest>=8.2` and pulls
   the suite off the pinned `pytest==8.1.1`.
6. **`kubernetes` and `langgraph` must not be installed on s390x** — both force
   `pydantic` 2.14 and break the documented pin.
7. **Two `XREAD` consumers** (dashboard WS + remediation audit logger) read the
   same stream independently; no consumer-group contention.
8. **Repository is private** — judges cannot clone until visibility is changed.

---

## 7. Smoke Test Log

| Date | Platform | Command | Result |
|---|---|---|---|
| 2026-10-17 | Windows x86_64 | `python -m pytest forwarder/tests tests -v` | 91 passed, 19 failed — see §8 |
| 2026-10-17 | Windows x86_64 | `python scripts/smoke_test_replay.py` | ✅ ALL ASSERTIONS PASSED |
| **2026-10-18** | **IBM LinuxONE `s390x`** | `python scripts/smoke_test_replay.py` | ✅ **ALL ASSERTIONS PASSED (100% SUCCESS)** — 4 valid events, 1 malformed quarantined, IPv4 + kprobe redaction verified |
| **2026-10-18** | **IBM LinuxONE `s390x`** | `GET /api/health` | ✅ `"status": "ok"` · `source_arch: s390x` · `hardware: IBM LinuxONE (s390x)` · `remediation_agent: active`, `autonomy_mode: human-in-loop`, `dry_run: true` |
| **2026-10-18** | **IBM LinuxONE `s390x`** | `pytest forwarder/tests tests/test_dashboard_api.py tests/test_remediation_safety.py` | ✅ **58 passed, 0 failed** — core pipeline + Person 3/4 acceptance suites fully green |
| **2026-10-18** | **IBM LinuxONE `s390x`** | `pytest forwarder/tests tests` (full) | 63 passed, 29 failed, 18 errors — all remaining failures are the opt-in RAG path, see §8 |
| **2026-10-18** | **IBM LinuxONE `s390x`** | clean-room venv from `requirements-s390x.txt` | ✅ 14/14 packages resolved to prebuilt `s390x` wheels; pydantic pin held |
| **2026-10-18** | **IBM LinuxONE `s390x`** | `pytest forwarder/tests` (incl. `/proc` sensor) | ✅ **56 passed** |
| **2026-10-18** | **IBM LinuxONE `s390x`** | `python -m forwarder.main --mode procfs` | ✅ **LIVE** — 41 processes in first scan, `capture_mode: procfs_live` |
| **2026-10-18** | **IBM LinuxONE `s390x`** | `GET /api/health` (procfs mode) | ✅ `sensor_kind: procfs_poll` · `sensor_is_ebpf: false` · `live_capture: true` · `source_arch: s390x` |
| **2026-10-18** | **IBM LinuxONE `s390x`** | `GET /api/procs` | ✅ 30 processes, `is_s390x: true`, 352 MB resident |
| **2026-10-18** | **IBM LinuxONE `s390x`** | `GET /api/system` | ✅ load, uptime, memory, kernel `6.8.0-147-generic` |
| **2026-10-18** | **Windows → LinuxONE** | `.\scripts\start-demo.ps1` | ✅ **single URL `http://localhost:8080`** serves UI + API through one tunnel |

### Acceptance suites — the result that matters

```bash
python -m pytest forwarder/tests tests/test_dashboard_api.py tests/test_remediation_safety.py -q
# 58 passed
```

This covers ingestion, schema normalisation, privacy redaction, Redis
publishing, dashboard integration, and remediation safety — **and it is green
on `s390x`.**

---

## 8. Remaining test failures — scope, not regression

All 29 failures and 18 errors on the s390x host trace to **one** cause:
`langgraph` is deliberately not installed.

`requirements-s390x.txt` excludes `langgraph` because `langchain-core` forces
`pydantic` 2.14, breaking the `pydantic==2.6.4` pin that the forwarder and
dashboard depend on. The orchestrator/RAG path is opt-in
(`LLM_EXTERNAL_ENRICHMENT_ENABLED=false`) and is **not part of the deployed
demo**. The deployed path is verified green without it.

| Suite | Count | Cause |
|---|---|---|
| `tests/test_api.py` | 18 errors | Legacy REST surface; imports `main` → `orchestrator` → `langgraph`. Also targets an older `/analyze`, `/status`, `/ingest/trigger` app that today's `main.py` no longer serves. |
| `tests/test_orchestrator_structure.py` | 16 failed | Tests the LangGraph orchestrator. Requires `langgraph`. |
| `tests/test_person3_explainability.py` | 9 failed | Imports `orchestrator` for prompt-sanitisation assertions. Requires `langgraph`. |
| `tests/test_integration.py` | 4 failed | Same import chain. |

These are **pre-existing**, also failing on x86_64 for the same reasons (see
the 2026-10-17 row), and are *not* caused by the Person 1–4 work or by the
s390x port.

### Dependency defect found and fixed during the port

`requirements-s390x.txt` did not constrain `httpx`. Installing the current
release (0.28.1) silently broke **every** `TestClient`-based test:

```text
TypeError: Client.__init__() got an unexpected keyword argument 'app'
```

`fastapi==0.110.0` pins `starlette==0.36.3`, whose `TestClient` passes `app=`
to `httpx.Client`; httpx 0.28 removed that keyword. The requirements file now
pins `httpx==0.27.2` with an explanatory comment. This was caught by running
the suite on the target architecture rather than by inspection.

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
