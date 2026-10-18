# Demo Script — Security-Core (≤ 3 minutes)

**Owner:** Person 4 (Dashboard / Integration / Demo)
**Format:** Screen recording, 1080p, no external audio needed (captions + voiceover).
**Hard limit:** 180 seconds. Timings below total 2:50, leaving 10 s of slack.

---

## Pre-recording checklist (do this before hitting record)

```bash
# 1. Redis
redis-server --port 6379            # new terminal, leave running

# 2. Forwarder — deterministic fixture replay (never claims live capture)
python -m forwarder.main --mode fixture_replay --file fixtures/sample-tetragon-raw.jsonl

# 3. Dashboard API (port 8080)
python dashboard_api.py

# 4. Frontend (port 5173)
cd dashboard && npm install && npm run dev
```

- [ ] Browser at `http://localhost:5173`, window 1600×900, zoom 100%.
- [ ] Terminal font ≥ 14 pt, dark background.
- [ ] `curl -s localhost:8080/api/health | python -m json.tool` returns
      `"capture_mode": "fixture_replay"` and a truthful `"source_arch"` —
      `s390x` on LinuxONE, the real host arch on the recording machine (e.g.
      `AMD64` on a laptop) — this is the evidence shot.
- [ ] Close email/Slack/notifications.

---

## Script

### 0:00 – 0:20 · Hook (Command Center on screen)

> "Container escapes are silent: a shell spawns from a web pod at 2 a.m. and
> nothing pages anyone. This is Security-Core — eBPF detection, explainable
> triage, and remediation that never fires without a human. Everything you're
> about to see runs offline from a deterministic fixture replay; the stack
> targets IBM LinuxONE s390x, and it labels the real host it runs on."

**On screen:** Command Center. Point at the header badges: capture mode chip
(`FIXTURE REPLAY`), arch chip (reads `s390x · LinuxONE` on LinuxONE, the real
host arch elsewhere), stream status.

### 0:20 – 0:45 · The honest-data point (stay on Command Center)

> "First, provenance. Every event is tagged at ingestion: capture mode, source
> architecture, schema version. If this were live Tetragon data the chip would
> read LIVE — it doesn't, because it isn't. Judges shouldn't have to trust us on
> that; the pipeline records it."

Hover the `FIXTURE REPLAY` chip to show the tooltip (source, schema).

### 0:45 – 1:25 · Incident Ledger (click Ledger in the sidebar)

> "The ledger is the triage queue. Red means verified threat. The shield icon on
> a row means fields were redacted before this event was ever written to Redis —
> hover it to see exactly which fields. The MITRE column is a live link with the
> technique name and tactic. And every grade carries its basis — heuristic rules
> or model-plus-gates — never a bare number."

**On screen:** filter to `TP`; hover the shield marker; hover a MITRE chip;
click one row to open Forensics.

### 1:25 – 2:05 · Forensics (Forensics Deep-Dive)

> "Here's the explainability layer. This is the triage evidence: each signal
> that pushed the score, with its weight — root execution, high-risk binary,
> network arguments, sensitive path access. The confidence note says it plainly:
> this is signal strength, not a probability. The attribution panel shows the
> same story for the model view — rule-weighted factors, not SHAP values — and
> the MITRE grid places the technique in its tactic."

**On screen:** left panel telemetry (capture mode, arch/host, redacted fields);
triage evidence list; MITRE technique card.

### 2:05 – 2:40 · Remediation is a recommendation (same page, scroll down)

> "Remediation is staged, not fired. The agent runs human-in-loop with dry-run
> enforced — see the badge. I click Request Remediation… and the result is
> `pending_approval`: the YAML diff is validated and ready, nothing was applied,
> no kubectl call was made. A human approves in production; the demo never
> pretends otherwise."

**On screen:** point at `HUMAN-IN-LOOP · DRY-RUN` chip → click
**Request Remediation** → amber result bar: `pending_approval · Human approval
required — nothing executed`; flip to the `secure` YAML tab briefly.

### 2:40 – 2:50 · Close (terminal)

```bash
curl -s localhost:8080/api/health | python -m json.tool | head -30
```

> "One curl proves the platform story: capture mode, the arch it actually runs
> on — s390x on LinuxONE — schema version, and the remediation agent's safe
> defaults. Detection you can explain, privacy you can audit, remediation you
> can stop. Security-Core."

---

## What NOT to show (and why)

| Trap | Why it must not appear |
|---|---|
| "Neutralize & Patch" executed for real | Nothing executes without human approval; claiming otherwise falsifies the safety story. |
| Live Tetragon claimed from replay | `capture_mode` says `fixture_replay`; contradicting it is dishonest and detectable. |
| "94% true positive" phrasing | Confidence is signal strength, not probability. The UI and script never say "chance". |
| Real credentials/IPs | All events shown are fixtures, already redacted at ingestion. |

---

## Backup plan if something fails on the day

| Failure | Offline fallback |
|---|---|
| Redis down | Dashboard shows empty ledger + `degraded` health; pre-record a clip from the working run and narrate over it. |
| Gemini/Pinecone unreachable | This is the default path — offline rule-based MITRE mapping produces the same demo output. |
| No internet at all | Nothing in the demo requires internet: fixtures, Redis, dashboard are all local. |

---

## Recording tips

- Record in one take per section, then cut; keep the 10-s slack.
- Mouse movements slow and deliberate; no rapid window switching.
- If using voiceover, read the quoted lines verbatim — they match the UI wording.
