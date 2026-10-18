# Submission Checklist — IBM Z Datathon

**Owner:** Person 4 (Integration / Submission)
**Status legend:** `[x]` done and verified in-repo · `[ ]` human action required

---

## 1. Repository

- [x] Single source of truth: this repository (`main` branch, clean tree).
- [x] No credentials committed: `.env` files are git-ignored; only `.env.example`
      and `.env.remediation.example` (placeholder values) are tracked.
- [x] `.gitignore` now covers `*.pem`, `*.key`, `id_rsa*`, `kubeconfig*`,
      `known_hosts` — key-file safety no longer depends on file location.
- [ ] Paste the repository URL (see `git remote -v`) into the submission form.
- [ ] **Make the repository public or send judge invites.** It is currently
      private; judges cannot clone or reproduce the LinuxONE deployment without
      access. This is the top remaining blocker.
- [x] Working tree scanned for vendor/old project branding — none present
      (`grep -ri` over tracked files; MITRE ATT&CK dataset citations excluded as
      third-party public data).

## 2. Documentation

- [x] `README.md` — setup, architecture, services.
- [x] `DEPLOYMENT.md` — split into Part A (x86_64/Kind/live eBPF) and
      Part B (LinuxONE `s390x`/native replay), so the two targets cannot be
      confused.
- [x] `docs/EVENT_CONTRACT.md` — canonical event schema (v1.0.0) incl. Person 3
      extension fields (triage basis/evidence, provenance).
- [x] `docs/PRIVACY_POLICY.md` — field-by-field retention/redaction rationale.
- [x] `docs/LINUXONE_PREFLIGHT.md` — **architecture evidence, per-service
      `s390x` compatibility table, A/B/C option decision, all workarounds.**
- [x] `docs/TEARDOWN.md` — surgical removal procedure, verified.
- [x] `docs/DEMO_SCRIPT.md` — ≤ 3-minute video script with fallbacks.
- [x] `docs/INTEGRATION_STATUS.md` — ports, merge status, blocked items.
- [x] `docs/ORCHESTRATOR_README.md`, `docs/API_DOCUMENTATION.md` — service docs.
- [ ] Record the demo video following `docs/DEMO_SCRIPT.md` (human action).

## 2a. IBM Z / LinuxONE platform evidence

- [x] Architecture confirmed `s390x` under z/VM 7.3.0 (Hypervisor vendor: IBM)
      — genuine IBM Z, not x86 emulation.
- [x] Python 3.12.3 with every dependency resolved to a **prebuilt `s390x`
      wheel**; nothing compiled from source.
- [x] Per-service compatibility table produced for images and dependencies.
- [x] eBPF kernel gate run and recorded (**passed**).
- [x] Tetragon `s390x` support definitively ruled out with release-asset
      evidence (amd64/arm64 only, no `s390x`).
- [x] **Live process sensor implemented and verified** —
      `forwarder/procfs_sensor.py`, `capture_mode: procfs_live`.
- [x] Capability boundary stated everywhere it matters: API exposes
      `sensor_kind` and `sensor_is_ebpf` separately; UI renders `/proc`
      capture in a distinct colour with a visible "not eBPF" disclosure.
- [x] Sensor privacy defaults enforced and tested: kernel threads skipped,
      self-lineage excluded, `PROCFS_DENYLIST` matched on `comm`.
- [x] Live events validated: 45/45 against the unified contract.
- [x] Stack deployed natively; health reports `"status": "ok"`,
      `source_arch: s390x`, `hardware: IBM LinuxONE (s390x)`.
- [x] New endpoints verified on the host: `/api/procs`, `/api/system`.
- [x] Smoke test passes on `s390x`; `forwarder/tests` 56 passed.
- [x] All listeners loopback-only; verified with `ss -ltn`.
- [x] **Single URL verified from Windows**: `.\scripts\start-demo.ps1` →
      `http://localhost:8080` serves UI and API over one tunnel.
- [x] Teardown written and verified.

**Live-capture disclosure:** capture is live but is **not eBPF**. The kernel
supports eBPF (gate passed); Tetragon publishes no `s390x` build and the host
has no container runtime, so live capture uses an unprivileged `/proc` poller.
This is stated in the API, the UI, the preflight report, and the demo script.

## 3. Reproducibility (offline-first)

- [x] No internet needed for the demo path: Redis + fixtures + dashboard only.
- [x] External enrichment (Gemini / Pinecone) is **opt-in** via
      `LLM_EXTERNAL_ENRICHMENT_ENABLED=true`; default is offline with
      deterministic MITRE mapping.
- [x] `python -m pytest forwarder/tests tests -v` runs without network.
- [x] `scripts/smoke_test_replay.py` proves Redis end-to-end (schema 1.0.0,
      capture mode, privacy markers).
- [x] s390x/LinuxONE compatibility documented in
      `docs/FORWARDER_DEPENDENCIES_S390X.md`.

## 4. Safety claims (must all be demonstrably true)

- [x] Dry-run is enforced by two independent layers: config default
      (`REMEDIATION_DRY_RUN=true`) and the executor's early return before any
      `subprocess` call — asserted by `tests/test_remediation_safety.py`.
- [x] Default autonomy mode is `human-in-loop`: every action returns
      `pending_approval` until a human confirms — asserted in tests and shown
      in the UI badge.
- [x] Confidence is never phrased as a probability (UI + deliverables), and the
      API records the semantics of each score.

## 5. Privacy claims

- [x] Redaction runs inside `forwarder/transformer.py` **before** Redis
      persistence (`privacy.redacted_fields` marker on every event).
- [x] Dashboard surfaces redaction markers per row and per event detail.
- [x] LLM prompts use sanitized fields only (`sanitize_event_for_llm`).
- [x] Limitations are documented honestly (`docs/PRIVACY_POLICY.md` §6).

## 6. Dashboard & demo asset

- [x] Capture-mode badge + arch-aware chip (reports `s390x · LinuxONE` on
      LinuxONE; the real host arch elsewhere) + stream status in header.
- [x] Incident Ledger: redaction shield, MITRE link/tooltip, triage basis.
- [x] Forensics: triage evidence list, confidence semantics, mitigation status
      (`pending_approval` / `dry_run` surfaced explicitly).
- [x] Capture final screenshots for the submission deck (Command Center,
      Ledger with redaction marker, Forensics with dry-run banner):
      `docs/assets/command-center-capture-badges.jpg`,
      `docs/assets/incident-ledger-redaction.jpg`,
      `docs/assets/forensics-explainability.jpg`,
      `docs/assets/forensics-pending-approval.jpg`.

## 7. Tests — final run before submission

```bash
python -m pytest forwarder/tests tests -v            # unit + integration
python scripts/smoke_test_replay.py                  # needs redis-server
```

- [ ] Paste the passing summary output into the submission notes.
- [x] Note environment: verified locally on Python 3.12.10, Node v25.5.0,
      Redis 8.8.0 (Windows dev host, fixture replay); LinuxONE s390x remains the
      production target (arch-aware health block, dependency audit doc).

## 8. Judging-criteria mapping (one line each)

| Criterion | Evidence |
|---|---|
| IBM Z / LinuxONE relevance | Deployed and verified **natively on `s390x` under z/VM**: health reports `source_arch: s390x`, `hardware: IBM LinuxONE (s390x)`; per-service wheel/manifest compatibility table in `docs/LINUXONE_PREFLIGHT.md` §8. |
| Detection quality | Triage grades with `basis` + evidence list; deterministic fixtures; heuristic engine verified running on `s390x` with XGBoost absent. |
| Explainability | MITRE mapping provenance (`offline_rules` vs `pinecone_rag`), evidence list, explicit confidence semantics. |
| Privacy | Write-time redaction in `forwarder/redaction.py`, audit block per event, `docs/PRIVACY_POLICY.md`. |
| Safe remediation | `human-in-loop` + `dry_run=true` verified at runtime on `s390x`; negative tests assert `subprocess` is never reached. |
| Engineering rigour | Event contract, compatibility table, documented workarounds, teardown, smoke tests, clean repo hygiene. |
| Honesty | Replay labelled as replay everywhere; kernel gate result reported accurately rather than overstated as "eBPF broken on s390x". |
