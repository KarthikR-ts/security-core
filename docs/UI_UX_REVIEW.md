# UI/UX Review — Security-Core / Aegis Sentinel Dashboard

**Purpose:** a complete handoff document describing the current interface, its
data provenance, its known defects, and concrete opportunities for improvement.
Written to be given to another engineer or LLM as standalone context — no
access to the conversation or the git history is assumed.

**Snapshot date:** 2026-10-18
**Stack:** React 18 + Vite 7 + Tailwind CSS v4 + shadcn/ui + Zustand + Framer Motion
**Served as:** a static bundle from `dashboard_api.py` at `http://localhost:8080`
**Deployed and running on:** IBM LinuxONE, `s390x`, Ubuntu 24.04, Python 3.12.3

---

## 1. System context

This is the operator console for a runtime-security pipeline. Data flows:

```text
  /proc sensor (or fixtures, or Tetragon where available)
        │  normalised, redacted, published
        ▼
  Redis Stream  security:events
        │
        ├─► WebSocket /api/ws/events   → live push to the browser
        └─► REST /api/events etc.      → polling snapshot
                 ▼
        dashboard_api.py  (FastAPI, port 8080, loopback only)
                 ▼
        static React bundle + REST API on the same origin
```

The dashboard is the only UI. There is no second console, no admin panel, no
mobile layout.

### Where the code lives

| Path | Role | Status |
|---|---|---|
| `dashboard/src/App.jsx` | Shell, routing, WebSocket lifecycle | Active |
| `dashboard/src/store.js` | Zustand store, all data fetching | Active |
| `dashboard/src/index.css` | Design tokens, base styles | Active |
| `dashboard/src/components/` | 8 live components | Active |
| `dashboard/src/components/ui/` | shadcn primitives | Active, mostly unused |
| `dashboard/src/main.ts` | Vite starter entry | **Dead — delete** |
| `dashboard/src/style.css` | Vite starter CSS | **Dead — delete** |
| `dashboard/src/counter.ts` | Vite starter | **Dead — delete** |
| `dashboard/src/typescript.svg` | Vite starter | **Dead — delete** |

---

## 2. Information architecture

Four routes exist; three are reachable from the sidebar.

```text
Sidebar (w-64, fixed)
├── Command Center     ← default route
├── Incident Ledger    ← badge shows active alert count
├── Live Processes     ← added most recently
└── (Forensics)        ← NO sidebar entry; reached only by clicking a ledger row

Header (h-16, sticky)
├── breadcrumb: Security-Core / <page>
└── capture-mode badge · arch badge · stream status · UTC clock

SyscallTicker (h-7, fixed bottom, always mounted)
└── scrolling event strip, label derived from capture_mode
```

**Route defect:** `PAGE_TITLES` in `Header.jsx:11-16` includes `forensics`, and
`App.jsx` renders it, but `NAV` in `Sidebar.jsx:14-18` omits it. The page is
reachable but not discoverable, and there is no way back except the in-page
close button. An analyst who lands there and reloads has no nav route home.

---

## 3. Design system

### Colour — `index.css:8-41`

Dark-only. There is no light theme and no `.dark` class in use, though
`@custom-variant dark` is declared at `index.css:6`.

| Token | Value (oklch) | Notes |
|---|---|---|
| `--background` | `0.13 0.028 261` | Very dark blue-black |
| `--card` | `0.16 0.025 261` | |
| `--primary` | `0.65 0.15 250` | Blue |
| `--muted-foreground` | `0.65 0.02 261` | Low-chroma grey — body text |
| `--destructive` | `0.6 0.2 25` | Red |
| `--border` | `0.25 0.03 261` | |
| `--chart-1..5` | blue → cyan → green → yellow → orange | **defined but never used** |

Beyond these, components hardcode Tailwind palette colours that are **not** in
the token set: `emerald-400/500`, `sky-400/500`, `amber-400/500`,
`text-red-500`, `text-orange-500`, `slate-600/700`. This is the single largest
consistency problem — see §6.

### Typography

Three font sources, which is one too many:

| Source | Where | Fonts |
|---|---|---|
| `@fontsource-variable/geist` | `index.css:4` | Geist Variable (bundled) |
| Google Fonts `<link>` | `index.html` | Inter, JetBrains Mono |
| CSS fallback stack | `index.css:44-45` | system-ui / monospace |

`--font-sans` resolves to `Geist Variable` first, so the Google-hosted Inter is
requested but almost never used. `--font-mono` resolves to JetBrains Mono, which
*is* the Google one. Net effect: an unnecessary external request on a page that
also declares itself offline-first.

`font-mono` is used pervasively for data — table cells, badges, counts, argv.
That is a good choice for this domain and should be kept.

### Motion

- `animate-ticker` — 60s linear scroll, pauses on hover (`index.css:110-116`)
- Page transitions — Framer Motion fade + 12px slide, 0.3s in / 0.2s out
- `animate-pulse` on live-status dots

### Utilities

`.glass-panel`, `.glass-card`, `.premium-shadow` at `index.css:119-127`.
`.glass-card` and `.premium-shadow` are **never used** in the codebase.

---

## 4. Screen-by-screen

### 4.1 Command Center — `CommandCenter.jsx` (default)

Three-column layout:

- **Left (~flex-1): Execution Topology.** A vertical stack of four cards —
  Execution Host, Sensor, TracingPolicies, Event Stream — each showing real
  values with an ok/not-ok state. Replaced a hardcoded fake Kubernetes SVG.
- **Right (w-340px):** Auto-Block Config panel, Active Severity Breakdown,
  Triage Distribution, Frequency Chart.
- **Header strip:** real hostname, arch, `native install` marker, live/no-live.

Data: `/api/cluster`, `/api/health`, `/api/policies`, `/api/metrics`,
`/api/triage/stats`, `/api/events/timeline`, plus store `events`.

### 4.2 Incident Ledger — `IncidentLedger.jsx`

The triage queue. Three stacked regions:

1. **Sparkline strip** — 30-minute event timeline, capture-mode badge, count
   of redacted events.
2. **Filter bar** — text search across description/binary/pod/MITRE, grade
   toggles (TP/BP/FP), severity toggles, sort control.
3. **Table** — severity, time, binary, MITRE chip, triage grade, redaction
   shield, status. Clicking a row opens Forensics.

Has the most sophisticated interaction of any screen: multi-axis filtering,
client-side sort, derived counts that exclude neutralized events.

### 4.3 Live Processes — `LiveProcesses.jsx` (newest screen)

- Platform evidence grid: architecture, kernel, vCPU, load, uptime, memory
- Process table: PID, PPID, user, command, state, threads, RSS
- Text filter across name/exe/pid
- Per-row `shielded` badge where arguments were redacted
- Header reports redacted row count
- Honest capability disclosure banner explaining /proc ≠ eBPF

Polls `/api/procs` and `/api/system` every 3 s, independent of the rest of the
app.

### 4.4 Forensics Deep-Dive — `ForensicsPanel.jsx`

Reached by clicking a ledger row. Empty state offers a button back to the
ledger. Shows telemetry grid, attribution factors, MITRE technique card,
explainability narrative, YAML diff, and the remediation panel.

This screen **does not share the design system** — it uses hardcoded
`bg-[#0a0e1a]`, `text-slate-400`, `text-slate-600`, `border-white/[0.08]`
throughout, bypassing every token.

### 4.5 SyscallTicker — `SyscallTicker.jsx`

Fixed bottom strip, always mounted. Shows the 6 most recent events as
`{ type:"…", bin:"…", pid:…, grade:"…" }`. Label is `eBPF` / `/proc` / `REPLAY`
/ `STREAM` based on real capture mode.

---

## 5. Data provenance — what is real

This matters more than usual here: the project's thesis is honest telemetry, so
any value the UI asserts must trace to a measurement.

| Surface | Source | Status |
|---|---|---|
| Architecture, kernel, vCPU | `/api/system` — read from `/proc` at request time | **Measured** |
| Process table | `/api/procs` — `/proc` walk at request time | **Measured** |
| Load, uptime, memory | `/proc/loadavg`, `/proc/uptime`, `/proc/meminfo` | **Measured** |
| Capture mode, sensor kind | `/api/health` ← latest ingested event | **Real, derived** |
| Event rows | Redis stream, redacted at write time | **Real** |
| Triage grade / confidence | Pure-Python heuristic rule engine (XGBoost absent on s390x) | **Real, deterministic** |
| Explanation text | Deterministic templates + rule reasoning | **Real, but static** |
| MITRE mapping | Static rule table | **Real lookup, not inferred** |
| Remediation result | Real API call; returns `pending_approval` in dry-run | **Real** |
| Orchestrator / cluster | `/api/cluster` — `null`, `nodes: []` | **Honest empty** |
| Policy enforcement | `/api/policies` — `enforced: false` (no Tetragon process) | **Honest empty** |

Everything on this list is currently traceable to a measurement or an explicit
absence. That was not true before commit `84f5db2`; see §6.1.

---

## 6. Defect register

### 6.1 Resolved — previously fabricated (context for reviewers)

These were removed in `84f5db2` and `2edbf0d`. Listed so a future change does
not reintroduce them:

- `_build_cluster_info()` returned a hardcoded 3-node Kind cluster with
  `tetragon: true`, on a host with no Kubernetes and no Tetragon
- `LiveNodeGraph` drew a hardcoded SVG of that same fictional cluster
- `_load_policies()` marked every YAML `status: "active"` regardless of
  enforcement
- `/api/procs` returned raw argv while the event stream redacted it
- 7 components that were never mounted and could not have worked

### 6.2 Still open — lying or fabricated indicators

**`Sidebar.jsx:87-88` — two connection indicators hardcoded green.**

```jsx
<ConnRow label="REST Backend"  ok={true} />
<ConnRow label="Tetragon Agent" ok={true} />
```

`Tetragon Agent` shows a green "connected" dot on a host where Tetragon does not
exist and cannot be installed (no `s390x` release). `REST Backend` cannot be
false, so the indicator carries no information. Both should derive from
`health.components`.

**`Sidebar.jsx:35` — branding claims eBPF unconditionally.**

```jsx
<div className="text-xs text-muted-foreground mt-0.5 font-mono">eBPF · v2.0</div>
```

Sits directly under the product name, permanently, regardless of sensor. The
Header handles this correctly; the Sidebar does not.

**`ForensicsPanel.jsx:51-68` — simulated streaming that is not streaming.**

```jsx
setStreamedText('')
setStreamComplete(false)
const text = forensicsData.reasoning   // already fetched
let idx = 0
streamRef.current = setInterval(() => { idx += 10; ... }, 20)
```

A typewriter effect reveals already-retrieved text at 10 chars / 20 ms. It
reads as an LLM generating a response. In reality the text came from a
deterministic rule engine with no LLM involved, and there is no model call
anywhere in this path.

This matters more than a cosmetic wart: for a project arguing that detection
and explanation are explainable, an animation that implies AI reasoning is
actively counter to the thesis. It also gates a real action —
`ForensicsPanel.jsx:332` disables the remediation button until
`streamComplete`, so a fake animation is blocking a real control.

**`ForensicsPanel.jsx:86,101,117` — hardcoded hex outside the token system.**

`bg-[#0a0e1a]`, `text-slate-400/600/700`, `border-white/[0.08]`. The rest of the
app uses `oklch` tokens. The Forensics screen is visually a different product.

### 6.3 Dead code

- `main.ts`, `style.css`, `counter.ts`, `typescript.svg` — Vite scaffold,
  never loaded (`index.html` → `main.jsx`)
- `--chart-1..5` tokens — defined, never referenced
- `.glass-card`, `.premium-shadow` — defined, never used
- `Crosshair` imported in `Sidebar.jsx:11`, never used
- `Compass`, `HardHat`, `Cog`, `Hexagon`, `Box`, `Zap` imported in
  `CommandCenter.jsx:16` — remnants of the deleted fake SVG
- 11 shadcn primitives in `components/ui/` — most unused

### 6.4 External dependency

`index.html` requests Inter and JetBrains Mono from `fonts.googleapis.com`.
The submission checklist claims *"No internet needed for the demo path"*. With
the bundle served over an SSH tunnel to a laptop that may be offline, this is a
soft failure — the page renders in fallback fonts rather than breaking, but the
claim and the implementation disagree. `Geist Variable` is already bundled via
`@fontsource-variable/geist`; self-hosting JetBrains Mono would close the gap.

### 6.5 Network load

`store.js:207-232` issues **7 parallel requests** every 15 s, plus a chained
`fetchImmunityScore()` making 8. `LiveProcesses.jsx` independently polls 2
endpoints every 3 s. Steady state is roughly:

- 32 requests/min from `fetchAllData`
- 40 requests/min from `LiveProcesses`
- plus WebSocket push

None of this is rate-limited, de-duplicated, or paused when the tab is hidden.
Over SSH that latency multiplies.

---

## 7. UX problems

Ordered roughly by impact on an operator trying to use this under time pressure.

### 7.1 The remediation button is gated behind a fake animation

A real control — the only path to human-approved remediation — is disabled until
a cosmetic typewriter effect finishes. If `forensicsData.reasoning` is empty or
absent, the interval never completes and **the button is disabled permanently**.
The operator has no indication why.

### 7.2 No global loading or error state

If `/api/health` fails, the Header badges silently fall back to
`capture_mode: "unknown"` → label `"UNKNOWN"`. The store catches errors with
`console.error` and no user-visible state. An analyst staring at a frozen
dashboard cannot distinguish "no threats" from "backend is down" — the single
most dangerous ambiguity in a SOC tool.

### 7.3 Colour carries meaning without a legend

Grade colours (TP red / BP blue / FP grey), severity colours, capture-mode
colours (green eBPF / blue /proc / amber replay) are all loaded. No key exists
anywhere. A first-time viewer cannot decode them, and the green-means-eBPF
convention is exactly the sort of thing that needs stating once rather than
implying.

### 7.4 Density is inconsistent between screens

Command Center and Ledger are dense, aligned and information-rich. Live
Processes is comfortable. Forensics is a different visual language entirely
with generous spacing and hardcoded dark blues. The transition between adjacent
screens is jarring.

### 7.5 No keyboard path

`EventDetail`, `ForensicsPanel` and the Ledger rows are click-only. There is no
`/`-to-search, no arrow-key row navigation, no `Esc` to close Forensics, no
visible focus ring on table rows. An analyst triaging a queue works faster with
keyboard-only.

### 7.6 The ticker is decorative

It duplicates the top six events already visible in the Ledger, takes 28 px of
permanent vertical space, and animates constantly — motion that never stops in
a tool people stare at for hours. It also cannot be dismissed.

### 7.7 Live Processes has no time dimension

Rows update every 3 s but nothing indicates *when* a process appeared, whether
a PID is new, or which processes are new since the last look. The sensor emits
`process_exec` and `process_exit` events precisely to express change, and the
screen discards that. Sorting by arrival, or flashing genuinely new PIDs, would
make the screen demonstrate the thing it exists to show.

### 7.8 Alert badge semantics

`Sidebar.jsx:61-65` shows `metrics.active_alerts` (critical + high severity) on
the Incident Ledger nav item. But with the `/proc` sensor the stream is
dominated by ordinary system processes, so severity counts reflect *volume*,
not *risk*. A badge that reads "37" because systemd started 37 things is noise
dressed as urgency.

### 7.9 No responsive behaviour

The layout assumes ≥1280 px. The Sidebar is a fixed `w-64`, the Command Center
right panel a fixed `w-[340px]`. Below ~1100 px the columns crush. There is no
mobile story and no tablet story, which may be acceptable for a SOC tool —
but it should be a deliberate decision rather than an absence.

### 7.10 Timezone inconsistency

`Header.jsx:22-34` renders a UTC clock with a manual offset suffix. Event
timestamps render through `formatTime()` helpers that use local time. Two time
bases in one interface.

---

## 8. Prioritised improvement proposals

### P0 — correctness and trust

These are cases where the interface asserts something untrue or blocks a real
action.

1. **Derive the Sidebar connection rows from `health.components`.** Remove
   `ok={true}` literals. Show `Tetragon / eBPF` as *absent* with the reason
   (no `s390x` build). A dead indicator should read dead.
2. **Replace the fake streaming with the real thing.** Either call a genuine
   streaming endpoint when `LLM_EXTERNAL_ENRICHMENT_ENABLED=true`, or drop the
   animation and render the text immediately with an honest provenance chip
   (`rule-engine` / `llm`). Remove `streamComplete` from the button's disabled
   condition — the action must not depend on an animation.
3. **Add a global connection/error banner.** If `/api/health` fails or the
   WebSocket drops, say so in the Header. Silence must never mean "healthy".
4. **Make the Sidebar brand line sensor-aware.** Mirror the Header logic
   instead of hardcoding `eBPF · v2.0`.

### P1 — consistency and legibility

5. **Migrate `ForensicsPanel` onto the design tokens.** Replace every
   `bg-[#0a0e1a]` / `slate-*` with `--background` / `--card` / token classes.
   This alone makes the app feel like one product.
6. **Add a colour legend.** One compact key — ideally on the Ledger filter bar
   — decoding grade, severity, and capture-mode colours.
7. **Self-host the fonts.** Drop the Google `<link>`, bundle JetBrains Mono
   like Geist, and make the offline claim true.
8. **Delete the dead scaffold.** `main.ts`, `style.css`, `counter.ts`,
   `typescript.svg`, unused lucide imports, unused shadcn primitives, unused
   CSS tokens.

### P2 — operator workflow

9. **Give Live Processes a time dimension.** Mark newly-appeared PIDs, show
   arrival time, offer sort-by-arrival, and surface `process_exit` events so
   the churn loop visibly produces departures.
10. **Add keyboard navigation.** `/` focuses search, arrows move the selected
    ledger row, `Enter` opens forensics, `Esc` closes it. Visible focus rings.
11. **Collapse the ticker by default.** Make it a one-line collapsed strip that
    expands on click, or a user preference. Permanent motion should be opt-in.
12. **Tie the alert badge to risk, not volume.** Base it on TP count and
    severity, not total events, so it means "look at this" rather than "the
    sensor is working".

### P3 — polish

13. **Unify time.** One UTC base across header, ledger, forensics, and process
    timestamps.
14. **Reduce request volume.** Pause polling on `visibilitychange`, collapse
    `fetchAllData` into a single aggregate endpoint, and let the WebSocket
    carry everything the ticker needs.
15. **Consider a light theme.** Tokens already use `oklch` and the `.dark`
    variant exists; a second theme is mostly a token swap.
16. **Empty and error states per screen.** Every screen currently has a
    loading skeleton at best.

---

## 9. Guardrails

Anything touching this UI must not break the following. Each is load-bearing
for the project's stated thesis or for its demo.

- **Capture-mode labelling.** `/proc` capture must never render as green
  "LIVE" or be described as eBPF. The distinction is the single most
  defensible thing about the interface. See `Header.jsx:36-66`.
- **Redaction consistency.** `/api/procs` and the event stream must apply the
  same policy. A raw secret in one panel and masked in the other is worse than
  either alone.
- **Sensor honesty.** No indicator may claim a component that does not exist.
- **Remediation must remain visibly gated.** Human-in-loop and dry-run must stay
  legible in the UI. Nothing may imply an action executed.
- **Loopback binding.** All services bind `127.0.0.1`; access is via SSH
  tunnel. Do not add public exposure.
- **No fabricated defaults.** Empty is a valid value. Do not substitute a
  plausible number when a measurement is missing — `immunityScore` was `85`
  and is now `null` for this reason.
- **Data shape.** `capture_mode`, `sensor_kind`, and `sensor_is_ebpf` are three
  separate fields by design. Do not collapse them into one boolean.

---

## 10. Open questions for whoever designs next

1. **Is dark-only correct?** A SOC tool used in a darkened room is defensible.
   But the tokens are already theme-ready, so this is cheap to reverse.
2. **Should the sidebar be collapsible?** At 256 px it is permanently consumed.
   On a 1280 px screen that is 20% of the width spent on navigation and four
   stat rows.
3. **Is the ticker earning its space?** It is the only always-animating element
   and it duplicates information available elsewhere.
4. **Should `/api/procs` and `/api/events` be separate mental models?** The app
   currently has "what is running now" and "what changed recently" as two
   screens with no link between them. A process in the table and its originating
   event in the Ledger are the same object viewed two ways, and nothing
   connects them.
5. **What is the primary loop?** Watch a live screen, or work a queue and
   respond? The current design serves both equally and therefore neither.

---

*Compiled from a direct read of the codebase and a live inspection of the
running instance on 2026-10-18. File and line references are accurate as of
commit `2edbf0d`.*