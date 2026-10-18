# Submission Checklist — IBM Z Datathon

**Owner:** Person 4 (Integration / Submission)
**Status legend:** `[x]` done and verified in-repo · `[ ]` human action required

---

## 1. Repository

- [x] Single source of truth: this repository (`main` branch, clean tree).
- [x] No credentials committed: `.env` files are git-ignored; only `.env.example`
      and `.env.remediation.example` (placeholder values) are tracked.
- [ ] Paste the repository URL (see `git remote -v`) into the submission form.
- [ ] Confirm judge access (repo invite or public toggle) **before** deadline.
- [x] Working tree scanned for vendor/old project branding — none present
      (`grep -ri` over tracked files; MITRE ATT&CK dataset citations excluded as
      third-party public data).

## 2. Documentation

- [x] `README.md` — setup, architecture, services.
- [x] `docs/EVENT_CONTRACT.md` — canonical event schema (v1.0.0) incl. Person 3
      extension fields (triage basis/evidence, provenance).
- [x] `docs/PRIVACY_POLICY.md` — field-by-field retention/redaction rationale.
- [x] `docs/DEMO_SCRIPT.md` — ≤ 3-minute video script with fallbacks.
- [x] `docs/INTEGRATION_STATUS.md` — ports, merge status, blocked items.
- [x] `docs/ORCHESTRATOR_README.md`, `docs/API_DOCUMENTATION.md` — service docs.
- [ ] Record the demo video following `docs/DEMO_SCRIPT.md` (human action).

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
| IBM Z / LinuxONE relevance | Arch-aware ingestion: `source_arch` mirrors the event's host (`s390x` on LinuxONE, the real host arch elsewhere); health `platform.hardware` label follows it; dependency audit doc. |
| Detection quality | Triage grades with basis + evidence; deterministic fixtures; tests. |
| Explainability | MITRE mapping provenance (`offline_rules` vs `pinecone_rag`), evidence list, confidence semantics. |
| Privacy | Write-time redaction + audit block + policy doc. |
| Safe remediation | Human-in-loop + dry-run + negative tests (subprocess never called). |
| Engineering rigour | Event contract, integration status, smoke tests, clean repo hygiene. |
