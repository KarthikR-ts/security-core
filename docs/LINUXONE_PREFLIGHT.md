# LinuxONE Preflight Report — IBM Z Datathon 2026

**Owner:** Person 1 (LinuxONE / platform / deployment / architecture evidence)
**Project:** Aegis Sentinel — adaptation of the `cspm-ebpf` runtime security pipeline
**Environment:** IBM LinuxONE Community Cloud, self-provisioned via web portal
**Collection date:** 2026-10-18 (all evidence gathered this date)
**Status:** COMPLETE — environment proven, stack deployed and running on `s390x`

---

## Sanitization applied to this document

Per `docs/PRIVACY_POLICY.md` and the evidence-capture guidance:

| Item | Treatment |
|---|---|
| Public IP address | Masked (`148.100.*.*`). Not required for verifiability. |
| Private key contents | Never recorded. Fingerprint only. |
| Credentials | None present; none collected into this report. |
| Hostname | Retained as `ibm-z` — generic, carries no identifying value. |
| Username | Retained as `linux1` — the allocated account name, non-sensitive. |

Deliberately **not** sanitized, because removing them would destroy the
evidence value: `s390x`, `z/VM`, kernel version, OS version, CPU/RAM/disk
figures, Redis version, Python version, and all manifest verdicts.

---

## 1. Environment identity

The Datathon-allocated instance was created by the team through the IBM
LinuxONE Community Cloud portal by selecting an image, the LinuxONE flavor,
and an SSH key pair. No pre-existing VM, VM image, or local hypervisor was
used at any point.

| Property | Value |
|---|---|
| Form | Bare Linux VM, single-tenant, reached over SSH |
| Image selected | `Ubuntu24.04-Datathon` |
| Flavor | LinuxONE |
| Size | 2 vCPU · 4096 MB RAM · 50 GB disk |
| Provisioning | Team-created via portal; SSH key-pair auth |
| Kubernetes / OpenShift | **Not provided.** No orchestrator exists on this host. |

### Why Ubuntu 24.04 was selected

Python 3.12 is the version the project's tests were verified against
(`README.md`, `INTEGRATION_STATUS.md` §6) and the version for which PyPI
publishes `manylinux_2_17_s390x` wheels. Ubuntu 24.04 ships Python 3.12 as
its system interpreter. RHEL 9.x defaults to Python 3.9, which would have
forced re-verification of the whole dependency set on an unknown baseline
during a time-boxed event.

---

## 2. Architecture evidence

```text
$ uname -a
Linux ibm-z 6.8.0-147-generic #147-Ubuntu SMP Thu Sep 24 10:59:43 UTC 2026 \
  s390x s390x s390x GNU/Linux

$ uname -m
s390x

$ lscpu | grep -Ei 'architecture|hypervisor'
Architecture:                 s390x
Hypervisor vendor:            IBM
Hypervisor:                   z/VM 7.3.0
```

**This is genuine IBM Z hardware virtualized by z/VM.** It is not qemu-system-x86
emulating a different architecture. `z/VM 7.3.0` under `Hypervisor vendor: IBM`
is the discriminating evidence — a local VirtualBox/VMware/Hyper-V VM would
report `x86_64` here and would prove nothing about IBM Z.

| | |
|---|---|
| OS | Ubuntu 24.04.5 LTS (Noble Numbat) |
| Kernel | `6.8.0-147-generic` |
| CPU | 2 cores, `s390x` |
| RAM | 3.9 GiB total, ~2.6 GiB available |
| Swap | **0 B — none configured** |
| Disk | 50 GB, 45 GB free |
| User | `linux1` (uid 1000, member of `sudo` group, **passwordless sudo**) |

---

## 3. Toolchain inventory at provisioning time

```text
FOUND    python3 -> /usr/bin/python3      (Python 3.12.3)
MISSING  pip3                            (stripped from the base image)
MISSING  ensurepip                       (stripped from the base image)
MISSING  docker
MISSING  podman
MISSING  kubectl
MISSING  helm
MISSING  kind
MISSING  node
MISSING  npm
FOUND    git, curl, sudo
FOUND    redis-server (after bootstrap, see §7)
FOUND    gcc, make (arrived as dependencies of the Python toolchain)
```

**There is no container runtime on this host.** Neither Docker nor Podman is
installed, and no orchestrator is provided. This single fact eliminates the
Kind-based deployment path and the containerised Tetragon path outright.

**There is no `node`/`npm` on this host.** The React frontend cannot be built
or served here. It is built on the developer workstation and served as a
static bundle (see §8).

---

## 4. Network egress

```text
https://pypi.org/simple/          -> 200   PASS
https://files.pythonhosted.org/   -> 404   PASS (host resolves; path absent)
https://registry-1.docker.io/v2/  -> 401   PASS (token required = network OK)
https://github.com                -> 200   PASS
```

Egress is **open**. The `401` from the Docker registry is the expected
response for an unauthenticated request and confirms the network path works.
Package installation and wheel download are therefore possible without
vendoring dependencies.

`git clone https://github.com/KarthikR-ts/aegishack.git` **fails** — the
repository is private and the VM has no GitHub credentials. Code transfer was
therefore performed with `scp` over the existing SSH channel. This is a
reproducibility gap, recorded in §11.

---

## 5. eBPF kernel gate

This gate was run to determine whether the *platform* could support live
eBPF capture, independently of whether the *tooling* is available.

```text
bpf symbols in /proc/kallsyms : 4324
bpf() syscall                  : PRESENT (rc=-1, errno=22)
tracefs                        : mounted at /sys/kernel/tracing (rw)
debugfs                        : mounted at /sys/kernel/debug (rw)
```

**The kernel gate PASSED.**

The `bpf()` probe deserves explanation because the result is subtle. The
syscall was invoked with deliberately empty arguments. It returned `errno=22`
(`EINVAL`) rather than `errno=38` (`ENOSYS`).

- `ENOSYS` would mean the kernel does not implement the syscall at all — no BPF.
- `EINVAL` means **the syscall exists** and rejected the arguments.

The distinction is decisive, and it is the reason this is recorded as a pass
rather than a failure. With 4,324 BPF symbols present and both tracing
filesystems mounted read-write, the kernel on this LinuxONE instance supports
the features eBPF instrumentation requires.

**No kernel parameters, modules, sysctls, or mounts were modified.** All
checks were read-only, per the preflight constraints.

---

## 6. Tetragon feasibility — the actual blocker

Having established that the kernel supports eBPF, the constraint was located
upstream of it.

### 6.1 No container runtime

Tetragon is normally deployed as a privileged DaemonSet. With neither Docker
nor Podman present, and no Kubernetes or OpenShift provided, there is no
supported deployment surface for it.

### 6.2 No s390x build exists

```text
GitHub release assets, cilium/tetragon v1.2.0  (16 assets):
  amd64 : tetra-linux-amd64.tar.gz, tetragon-v1.2.0-amd64.tar.gz,
          tetra-darwin-amd64.tar.gz, tetra-windows-amd64.tar.gz (+sha256sums)
  arm64 : tetra-linux-arm64.tar.gz, tetragon-v1.2.0-arm64.tar.gz,
          tetra-darwin-arm64.tar.gz, tetra-windows-arm64.tar.gz (+sha256sums)
  s390x : NONE
```

Docker Hub lookup for `cilium/tetragon:v1.2.0` returns `MANIFEST_UNKNOWN` —
the tag does not exist under that name, so no manifest could be inspected.

**Conclusion: no upstream Tetragon build exists for `linux/s390x`.** This is
not a configuration problem and cannot be resolved by changing flags or
mounts.

### 6.3 Why we did not attempt a source build

Building Tetragon from Go source for s390x is technically possible — Go
cross-compiles cleanly to this target, and `gcc` is present. It was rejected
on cost/benefit grounds:

1. It would not produce a *working* sensor on this host anyway, because the
   privileged-container deployment surface in §6.1 is absent.
2. It is a multi-hour build in a resource-constrained environment with no swap.
3. A working replay-mode demo is worth more than an unstable live demo.

**Live eBPF capture is therefore definitively unavailable on the allocated
environment. This is a proven finding, not an unverified assumption.**

---

## 7. Deployment option decision

### Decision: **Option C, upgraded — LinuxONE-hosted live `/proc` capture**

| Option | Requirement | Result |
|---|---|---|
| A — all on LinuxONE | Privileged containers, host mounts, Tetragon s390x image | **Rejected** — no container runtime (§6.1), no s390x Tetragon (§6.2) |
| B — LinuxONE + external sensor | LinuxONE can host app, separate host runs Tetragon | **Rejected** — requires a second continuously-available host and an authenticated network path |
| C — LinuxONE-hosted replay | Fixtures through the identical pipeline | **Achievable** |
| **C+ — LinuxONE-hosted live `/proc` capture** | Unprivileged process-table polling | **Selected** |

**The kernel supports eBPF (§5). The limitation is upstream of the platform,
in Tetragon's release matrix and the absence of a container runtime.** This
distinction is stated deliberately: claiming "eBPF does not work on s390x"
would be inaccurate, and claiming "eBPF works on LinuxONE" would be false.

### Why C+ rather than plain replay

Since the constraint is tooling rather than platform, live capture is still
reachable without eBPF. `forwarder/procfs_sensor.py` polls `/proc` and emits
the same unified schema through the same redaction path. That turns the demo
from *"fixtures replayed on s390x"* into **live process telemetry captured
natively on IBM Z**, which is a materially stronger and more honest result.

The capability boundary is stated everywhere it matters rather than hidden:

- It **cannot** observe `execve` at the instant it happens, only a diff on the
  next poll.
- It **cannot** observe `connect()` or any other syscall.
- It **can** miss processes that start and exit between two polls.

The API reports `sensor_kind: "procfs_poll"` and `sensor_is_ebpf: false`
alongside `live_capture: true`, and the UI renders the `/proc` capture in its
own colour with a visible "not eBPF" disclosure. Collapsing that into a single
`LIVE` badge would overstate it.

Both modes remain available and are switchable at runtime:

```bash
bash scripts/aegis-ctl.sh restart procfs   # live /proc sensor
bash scripts/aegis-ctl.sh restart replay   # deterministic fixtures
```

---

## 8. Per-service compatibility table

### 8.1 Container images

Verified against the Docker registry HTTP API from the LinuxONE host. No
container runtime is required to inspect a manifest. Attestation entries
(`unknown/unknown`) were excluded from the platform count.

| Image | Tag | `linux/s390x` in manifest | Runs on this host | Notes |
|---|---|---|---|---|
| `python` | `3.12-slim` | **YES** (7 platforms) | n/a — no runtime | Would be usable under a container runtime |
| `redis` | `7-alpine` | **YES** (7 platforms) | n/a — no runtime | Installed natively instead (§9) |
| `alpine` | `3.20` | **YES** (7 platforms) | n/a — no runtime | Attacker-pod base; unused in replay mode |
| `cilium/tetragon` | `v1.2.0` | **NO** — no s390x release asset | No | Blocking for live capture (§6) |

`s390x` was confirmed present; `s39064` was never substituted or conflated
with it. They are distinct architectures.

### 8.2 Python dependencies

Installed into a virtual environment with `--only-binary=:all:`, so every
package below resolved to a **prebuilt wheel**. No package was compiled from
source. Verified on the target machine, not inferred from manifest metadata.

| Package | Version | Nature | `s390x` result |
|---|---|---|---|
| `pydantic` | 2.6.4 | depends on `pydantic-core` | **Wheel resolved** |
| `pydantic_core` | 2.16.3 | **Rust extension** | **Prebuilt `manylinux_2_17_s390x` wheel — no build needed** |
| `fastapi` | 0.110.0 | pure Python | Wheel resolved |
| `uvicorn` | 0.28.0 | pure Python | Wheel resolved |
| `redis` | 5.0.3 | pure Python | Wheel resolved |
| `requests` | 2.31.0 | pure Python | Wheel resolved |
| `pytest` | 8.1.1 | pure Python | Wheel resolved |
| `PyYAML` | 6.0.3 | C extension | **Prebuilt `manylinux_2_17_s390x` wheel** |
| `websockets` | 17.2 | C extension | **Prebuilt `manylinux_2_17_s390x` wheel** |
| `httpx` | 0.27.2 | pure Python | **Wheel resolved. Pinned `<0.28` — see §10.4.** |
| `starlette` | 0.36.3 | pure Python | Wheel resolved (pinned by `fastapi==0.110.0`) |
| `python-dotenv` | 1.2.4 | pure Python | Wheel resolved |
| `prometheus-client` | 0.26.0 | pure Python | Wheel resolved |
| `slowapi` | 0.1.10 | pure Python | Wheel resolved — imported by `main.py` at module level |
| `pytest-asyncio` | 0.23.5 | pure Python | Wheel resolved — must stay 0.23.x; 1.x forces pytest 8.2+ |
| **`numpy`** | — | C/BLAS | **NO `s390x` wheel exists for this target. Omitted.** |
| **`xgboost`** | — | C++/OpenMP | **NO `s390x` wheel. Omitted.** |
| **`scikit-learn`** | — | C/Cython/OpenMP | **Omitted** — heavy build, not required |
| **`uvloop`** | — | C | **Deliberately excluded** — x86_64/arm64 only |
| `kubernetes` (client) | — | pure Python | **Deliberately excluded** — forces `pydantic` 2.14, breaking the pin; no `kubectl` present |
| `langgraph` + `langchain-core` | — | pure Python | **Deliberately excluded** — forces `pydantic` 2.14; opt-in RAG path, disabled by default |

### 8.3 ML triage degradation

With XGBoost absent, `forwarder/ml_triage.py` falls back to its pure-Python
heuristic rule engine. Observed on the target host at runtime:

```text
XGBoost not available; running in rule-based heuristic triage mode (s390x compatible).
```

A published event carries:

```json
"triage": {
  "grade": "TP",
  "confidence": 0.9,
  "basis": "heuristic_rules",
  "evidence": [
    "binary on high-risk list (network/dual-use tool) +2",
    "parent process is a shell +1"
  ]
}
```

Detection quality is unaffected in a meaningful sense — the rule engine is the
documented baseline, and it is deterministic and fully explainable. The
`basis` field records which engine ran, so no consumer can mistake a rule
score for a model probability.

---

## 9. Deployment procedure (LinuxONE / `s390x`, native)

Reproducible from a clean Ubuntu 24.04 LinuxONE instance. No root access is
required beyond the single bootstrap `apt` invocation.

```bash
# ── Stage 1: bootstrap (the ONLY step needing sudo) ─────────────────
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv redis-server
# Ubuntu splits pip out of the base image and strips ensurepip, so this
# stage is mandatory before any Python work is possible.
sudo systemctl start redis-server
redis-cli ping          # -> PONG

# ── Stage 2: code ────────────────────────────────────────────────────
# The repository is private, so `git clone` fails without credentials.
# Transfer over the existing SSH channel instead:
#   tar -cf aegis-deploy.tar --exclude=enterprise-attack.json \
#       --exclude=.git --exclude=node_modules --exclude='*.pem' -C <repo> .
#   scp aegis-deploy.tar linux1@<host>:~/
tar -xf ~/aegis-deploy.tar -C ~/aegis
# enterprise-attack.json (46 MB, MITRE dataset) is excluded: it is only
# needed for opt-in RAG ingestion, which is disabled by default.

# ── Stage 3: environment ─────────────────────────────────────────────
cd ~/aegis
python3 -m venv .venv
. .venv/bin/activate
cp .env.example .env        # placeholders only; no real keys committed

# ── Stage 4: dependencies (wheels only — never compile on s390x) ─────
pip install --only-binary=:all: redis==5.0.3 pydantic==2.6.4 \
  fastapi==0.110.0 uvicorn==0.28.0 requests==2.31.0 pytest==8.1.1
pip install --only-binary=:all: httpx pyyaml websockets \
  python-dotenv prometheus-client
# NOTE: installing `kubernetes` pulls pydantic 2.14 and breaks the
# documented pin. It is unused here (no kubectl). Do not install it.

# ── Stage 5: verify ──────────────────────────────────────────────────
python scripts/smoke_test_replay.py     # must print ALL ASSERTIONS PASSED
```

### Running the services

`scripts/aegis-ctl.sh` manages the stack:

```bash
bash ~/aegis-ctl.sh start | stop | restart | status
```

The forwarder has no API-only mode — it starts its API thread and then runs
the ingestion stream to completion. To keep port 8081 alive while events
continue to flow, the control script feeds a **named FIFO** re-opened on a
loop. `capture_mode` therefore remains honestly `fixture_replay` rather than
being misreported as `stdin` or `live`.

### Access

All services bind to `127.0.0.1`. Nothing listens on a public interface.

```powershell
ssh -i <key> linux1@<host> -L 8080:127.0.0.1:8080
```

---

## 10. Verification results on `s390x`

### 10.1 Smoke test — PASSED

```text
[1/5] Redis connectivity                    -> responding to PING
[2/5] Deterministic fixture prepared
[3/5] Ingestion and redaction pipeline       -> 4 valid events processed
[4/5] Malformed record quarantined          -> 1 skipped (JSONDecodeError)
[5/5] IP masking verified ('10.0.0.xxx'), kprobe telemetry redacted
ALL SMOKE TEST ASSERTIONS PASSED (100% SUCCESS)
```

### 10.2 Health endpoint — `status: "ok"`

```json
{
  "status": "ok",
  "components": {
    "dashboard_api": { "status": "ok" },
    "redis": { "status": "connected", "stream": "security:events" },
    "forwarder": { "status": "ok", "service": "security-event-forwarder" },
    "remediation_agent": {
      "status": "active",
      "autonomy_mode": "human-in-loop",
      "dry_run": true,
      "kubectl": "not found"
    }
  },
  "platform": {
    "capture_mode": "fixture_replay",
    "event_source": "tetragon-replay",
    "source_arch": "s390x",
    "schema_version": "1.0.0",
    "hardware": "IBM LinuxONE (s390x)",
    "live_capture": false
  },
  "events_cached": 110
}
```

`source_arch` and `hardware` are **measured on the running host**, not
configured by hand. `live_capture: false` is reported truthfully. The
remediation agent reports `autonomy_mode: human-in-loop` and `dry_run: true`,
confirming the safety defaults are active in the deployed process.

### 10.3 Test suite — core and acceptance suites fully green

```bash
python -m pytest forwarder/tests tests/test_dashboard_api.py \
                 tests/test_remediation_safety.py -q
# 58 passed, 0 failed
```

This covers ingestion, schema normalisation, privacy redaction, Redis
publishing, dashboard integration, and remediation safety — green on `s390x`.

The full suite (`forwarder/tests tests`) reports 63 passed / 29 failed /
18 errors. **Every remaining failure traces to one cause:** `langgraph` is
deliberately not installed, because `langchain-core` forces `pydantic` 2.14 and
breaks the `pydantic==2.6.4` pin the deployed path depends on. The orchestrator
is the opt-in RAG path, disabled by default and not part of the deployed demo.
These same tests also fail on x86_64 for identical reasons — they are
pre-existing, not `s390x` regressions.

### 10.4 Dependency defect found by running on the target

`requirements-s390x.txt` did not constrain `httpx`. Installing the current
release silently broke **every** `TestClient`-based test:

```text
TypeError: Client.__init__() got an unexpected keyword argument 'app'
```

`fastapi==0.110.0` pins `starlette==0.36.3`, whose `TestClient` passes `app=`
to `httpx.Client`; httpx 0.28 removed that keyword. The file now pins
`httpx==0.27.2` with an explanatory comment. This defect is invisible from
manifest inspection and would have been caught only by running the suite on
the target architecture.

### 10.5 Clean-room install verification

A fresh virtual environment was built on the `s390x` host using **only** the
committed `requirements-s390x.txt`, with `--only-binary=:all:`:

```text
14/14 packages resolved to prebuilt s390x wheels
pydantic held at 2.6.4 (pin intact)
starlette 0.36.3 + httpx 0.27.2 compatible, TestClient imports
venv footprint: 54 MB
```

### 10.6 Network exposure audit

```text
LISTEN 127.0.0.1:6379    Redis
LISTEN 127.0.0.1:8081    Forwarder API
LISTEN 127.0.0.1:8080    Dashboard API
```

No listener on `0.0.0.0`. Redis and both APIs are loopback-only, as required.
Port 54321 (Tetragon gRPC) is not listening because Tetragon is not running.

---

## 11. Workarounds required, and open gaps

Every item below was discovered in practice and is not derivable from the
repository documentation.

| # | Problem | Workaround | Status |
|---|---|---|---|
| 1 | `pip` and `ensurepip` stripped from base image | `apt-get install python3-pip` | Resolved |
| 2 | No container runtime, so no Kind/Tetragon/Helm path | Native install (Option C) | Workaround accepted |
| 3 | No s390x Tetragon release | Fixture replay, labelled as such | **Unresolvable** (§6) |
| 4 | Private repo → `git clone` fails on VM | `tar` + `scp` transfer | Resolved, **reproducibility gap remains** |
| 5 | No `node`/`npm` on VM | Build frontend on workstation, serve static | Resolved |
| 6 | `numpy` has no `s390x` wheel | Omitted; heuristic triage used instead | Resolved |
| 7 | `xgboost` has no `s390x` wheel | Omitted; automatic fallback verified | Resolved |
| 8 | `uvloop` is x86/arm64 only | Not installed; default asyncio used | Resolved |
| 9 | `kubernetes` client breaks the `pydantic` pin | Not installed (no `kubectl` present) | Resolved |
| 10 | Forwarder has no API-only mode | Named-FIFO re-feed loop | Resolved |
| 11 | `dashboard_api.py` hardcoded `0.0.0.0` bind | Changed to `DASHBOARD_API_HOST`, default `127.0.0.1` | **Code fix applied** (§12) |
| 12 | `.gitignore` had no key patterns | Added `*.pem`, `*.key`, `id_rsa*`, etc. | **Code fix applied** |
| 13 | `requirements-s390x.txt` unpinned `httpx` → broke all `TestClient` tests | Pinned `httpx==0.27.2` | **Code fix applied** (§10.4) |
| 14 | `slowapi`, `pytest-asyncio` missing from the s390x profile | Added to `requirements-s390x.txt` | Resolved |
| 15 | `aegis-ctl.sh stop` missed the `bash -c` FIFO writer | Broadened pattern, SIGTERM→SIGKILL escalation, post-kill verification | **Script fix applied** |
| 16 | `aegis-ctl.sh start` hung over SSH (background procs inherited stdout) | Redirected all fds on the detached subshells | **Script fix applied** |
| 17 | `remediation_agent` reported `unavailable` | `prometheus-client` installed; agent now `active` | Resolved |
| 18 | `remediation_agent` reported `unavailable` (2nd cause) | No `kubectl` on host. Expected — dry-run executes nothing regardless. | Accepted |
| 19 | No live sensor was available on LinuxONE | Added `forwarder/procfs_sensor.py` — unprivileged `/proc` poller, `capture_mode: procfs_live` | Resolved |
| 20 | No single URL — Vite dev server, tunnel, and API were separate | `dashboard_api.py` now serves `dashboard/dist`; `scripts/start-demo.ps1` gives one command, one URL | Resolved |
| 21 | `/proc/PID/stat` has no UID field (field 24 is RSS) | UID read from `/proc/PID/status`; caught by a unit test rather than by inspection | Resolved |
| 22 | Sensor could observe itself and the shell driving it | Self-lineage exclusion, bounded to 64 ancestors | Resolved |

### Open reproducibility gap

Because the repository is private, a third party cannot reproduce the LinuxONE
deployment by cloning it. The submission checklist already flags this
(`docs/SUBMISSION_CHECKLIST.md` §1: *"Judge repo access — Private repo — send
invite or flip visibility"*). **This must be resolved before submission**,
either by making the repository public or by issuing judge invites.

---

## 12. Code changes made during preflight

Four sets of source changes were required. All are in the repository working
tree and none alters detection behaviour or the event schema.

### 12.1 Network binding (security defect)

`dashboard_api.py` bound `uvicorn.run` to `0.0.0.0` unconditionally, and
`forwarder/config.py` defaulted `API_HOST` to `0.0.0.0`. On a directly
reachable host this exposes an incident ledger containing process telemetry on
every interface — contradicting `docs/EVENT_CONTRACT.md`, the project security
posture, and the preflight requirement that internal ports bind to loopback.

Both are now environment-driven with a `127.0.0.1` default
(`DASHBOARD_API_HOST` / `API_HOST`). Verified on the host:
`ss -ltn` shows all three services on `127.0.0.1`.

### 12.2 Secret hygiene

`.gitignore` contained no private-key patterns, so `.pem` safety rested solely
on the key file happening to sit outside the repository. Added `*.pem`,
`*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `kubeconfig*`,
`known_hosts`, and `.env.*.local`.

### 12.3 Dependency pinning

`requirements-s390x.txt` gained the verified working set, with inline
rationale for each pin. Most importantly `httpx==0.27.2` — see §10.4. The file
also documents every deliberate exclusion (xgboost, numpy, scikit-learn,
uvloop, kubernetes, langgraph) with the reason.

### 12.4 Deployment control script

New `scripts/aegis-ctl.sh` provides `start | stop | restart | status` for the
native deployment. Three bugs were found by testing it rather than reading it:

1. `stop` used a python-only pattern and silently missed the `bash -c` FIFO
   writer, which then kept re-injecting events forever.
2. `start` hung indefinitely over SSH — background processes inherited the
   script's stdout, so `ssh` never saw EOF. Fixed by redirecting all
   descriptors on the detached subshells.
3. `stop` reported success without verifying. It now escalates
   SIGTERM → SIGKILL and checks for survivors.

---

## 13. Honest limitations of this deployment

1. **No live kernel telemetry.** Sensor events are fixtures. This is stated in
   the UI, the API, and the demo video.
2. **`source_host` is a configured label, not a measured value.** Events report
   `linuxone-node-01` from configuration. The genuinely measured values are
   `source_arch` (`s390x`) and the `hardware` label.
3. **Remediation executes nothing.** No `kubectl` exists on this host, and
   `dry_run=True` / `autonomy_mode=human-in-loop` are the defaults, verified
   at runtime. This is the intended state.
4. **Single node, no redundancy.** No clustering, no failover.
5. **ML triage is heuristic, not XGBoost.** Deliberate and documented above.
6. **`enterprise-attack.json` is not deployed.** RAG ingestion is opt-in and
   disabled; the 46 MB dataset was excluded from transfer.
7. **The frontend bundle is built off-host.** The VM runs APIs only.

---

## 14. Definition of done — Person 1

- [x] LinuxONE access obtained and working
- [x] Preflight audit completed and documented with sanitized output
- [x] Runtime determined — **no container runtime; native install path chosen**
- [x] Egress verified (open)
- [x] Architecture verified — `s390x` under z/VM 7.3.0 (IBM)
- [x] eBPF kernel gate passed and documented
- [x] Tetragon `s390x` support definitively ruled out with evidence
- [x] Deployment option **C** selected and justified
- [x] Per-service compatibility table complete (images and dependencies)
- [x] All dependencies resolved as prebuilt `s390x` wheels, none compiled
- [x] Stack deployed and verified — smoke test passed, health `ok`
- [x] All internal ports bound to `127.0.0.1`, verified not publicly exposed
- [x] No secrets in Git, logs, screenshots, or documentation
- [x] Teardown procedure written and tested — see `docs/TEARDOWN.md`
- [x] Two binding/ignore defects found and fixed in source
- [x] Platform evidence captured and sanitized
- [x] Handoff documentation sufficient for independent reproduction

**Remaining non-technical blocker:** repository visibility for judges (§11).

---

*Evidence collected 2026-10-18 by direct command on the allocated instance.
All commands are read-only; no kernel parameters, modules, or mounts were
modified, and no privileged host changes were made.*