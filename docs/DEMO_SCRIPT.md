# Demo Script — Security-Core (≤ 3 minutes)

**Owner:** Person 4 (Dashboard / Integration / Demo)
**Format:** Screen recording, 1080p, no external audio needed (captions + voiceover).
**Hard limit:** 180 seconds. Timings below total 2:50, leaving 10 s of slack.

---

## Pre-recording checklist (do this before hitting record)

```powershell
# On your workstation — one command, one URL
.\scripts\start-demo.ps1
```

That opens the SSH tunnel, waits for the API, and opens
**http://localhost:8080** with the live `/proc` sensor already running on the
remote host. Keep the window open for the whole recording.

If you need the deterministic fallback instead:

```bash
# On LinuxONE, before opening the tunnel
bash ~/aegis/scripts/aegis-ctl.sh restart replay
```

- [ ] Browser at `http://localhost:8080`, window 1600×900, zoom 100%.
- [ ] Sidebar shows **Live Processes**.
- [ ] Header badge reads `LIVE · /proc` in sky blue — **not** green. Green
      means eBPF, and this is not eBPF. If the badge says `FIXTURE REPLAY`
      you are on the fallback; say so in the narration.
- [ ] `curl -s localhost:8080/api/health | python -m json.tool` returns
      `"capture_mode": "procfs_live"`, `"sensor_kind": "procfs_poll"`,
      `"sensor_is_ebpf": false`, and `"source_arch": "s390x"` — the evidence shot.
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

> "Provenance first. Every event is tagged at ingestion: capture mode, source
> architecture, schema version. This badge reads LIVE · /proc — that's a real
> sensor polling this IBM Z machine's process table, but it is not eBPF, and
> we don't colour it green. Green would mean Tetragon, and Tetragon publishes
> no s390x build. The chip is blue because blue means /proc, and because /proc
> has limits we don't hide: it sees process state on an interval, so it can
> miss a process that lives less than two seconds, and it cannot see syscalls
> at all. You shouldn't have to trust us on any of that — the pipeline records
> it and the UI says it out loud."

Hover the badge to show the tooltip, which states the limitation.

### 0:45 – 1:15 · Live Processes (click Live Processes in the sidebar)

> "This is the actual process table, read live from /proc on the s390x host —
> two vCPUs under z/VM. Every row is a real process. Two things worth noticing:
> the architecture block reads s390x because that's measured on the running
> host, not configured. And the count is lower than `ps` would give you,
> because we've excluded kernel threads, the sensor's own shell lineage, and
> anything on the denylist — which by default includes sshd, so this table
> can't capture your login session. That's the project's thesis applied to the
> sensor itself."

Point at the arch block, the process count, then start a process from a second
terminal to show a row appear:

```bash
sleep 90 &
curl -s https://example.com -o /dev/null &
```

### 1:15 – 1:55 · Incident Ledger (click Ledger)

> "The ledger is the triage queue. Red means verified threat. The shield icon on
> a row means fields were redacted before this event was ever written to Redis —
> hover it to see exactly which fields. And every grade carries its basis, which
> here reads heuristic_rules, because XGBoost has no s390x wheel and we would
> rather degrade honestly than pretend."

**On screen:** filter to `TP`; hover the shield marker; hover a MITRE chip;
click one row to open Forensics.

### 1:55 – 2:15 · Forensics (Forensics Deep-Dive)

> "The explainability layer: each signal that pushed the score, with its
> weight. The confidence note says it plainly — signal strength, not a
> probability. And the capture mode line reads procfs_live, so you always know
> whether you're looking at a kernel event or a poll."

### 2:15 – 2:40 · Remediation is a recommendation

> "Remediation is staged, not fired. Human-in-loop, dry-run enforced. I request
> remediation and the result is pending_approval — the YAML is validated and
> ready, nothing applied, no kubectl call. And there is no kubectl on this box
> to call."

**On screen:** point at the `HUMAN-IN-LOOP · DRY-RUN` chip → click
**Request Remediation** → amber result bar.

### 2:40 – 2:50 · Close (terminal)

```bash
curl -s localhost:8080/api/health | python -m json.tool | head -30
```

> "One curl proves the platform story: architecture measured on the running
> host — s390x on IBM LinuxONE — sensor kind, schema version, and the
> remediation agent's safe defaults. Live telemetry you can audit, privacy you
> can measure, remediation you can stop. Aegis Sentinel."

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
| Calling `/proc` capture "eBPF" or showing it in green | It is not eBPF. The badge is blue for exactly this reason. Overstating it is the single easiest way to lose a technical judge. |
| "Live kernel monitoring on IBM Z" | The kernel would support it; Tetragon has no s390x build. Say "live process state", not "kernel-level". |
| "Neutralize & Patch" executed for real | Nothing executes without human approval; claiming otherwise falsifies the safety story. |
| "94% true positive" phrasing | Confidence is signal strength, not probability. The UI and script never say "chance". |
| Real credentials/IPs | The denylist excludes sshd; everything shown is already redacted at ingestion. |

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
