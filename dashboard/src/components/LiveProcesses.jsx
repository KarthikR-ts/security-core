/**
 * LiveProcesses.jsx — Live process table for the host running the sensor.
 *
 * HONESTY CONTRACT
 * ----------------
 * This panel shows REAL process state read directly from /proc on the host,
 * but it is NOT eBPF. The header states the sensor kind explicitly and never
 * renders "live" without saying what is producing it. /proc polling can miss
 * processes that start and exit between polls and cannot observe syscalls;
 * that limitation is surfaced in the UI rather than buried in the docs.
 *
 * Data comes from /api/procs, which applies the same denylist and
 * self-exclusion rules as the sensor itself, so what is shown here is exactly
 * what the sensor is permitted to observe.
 */

import { useEffect, useMemo, useState } from 'react'
import { useStore } from '../store'
import {
  Cpu, Search, RefreshCw, Radio, ShieldAlert, Layers, Clock,
} from 'lucide-react'

const REFRESH_MS = 3000

function fmtUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0))
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d) return `${d}d ${h}h`
  if (h) return `${h}h ${m}m`
  return `${m}m ${s % 60}s`
}

function fmtBytes(kb) {
  const v = Number(kb || 0)
  if (v >= 1024 * 1024) return `${(v / 1024 / 1024).toFixed(2)} GB`
  if (v >= 1024) return `${(v / 1024).toFixed(1)} MB`
  return `${v} kB`
}

function basename(p) {
  if (!p) return ''
  const parts = p.split('/')
  return parts[parts.length - 1] || p
}

function Stat({ label, value, tone = 'default', title }) {
  const toneClass =
    tone === 'good' ? 'text-emerald-400'
      : tone === 'warn' ? 'text-amber-400'
        : 'text-foreground'
  return (
    <div className="flex flex-col gap-0.5" title={title}>
      <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <span className={`text-sm font-mono font-semibold ${toneClass}`}>{value}</span>
    </div>
  )
}

export default function LiveProcesses() {
  const health = useStore((s) => s.health)
  const [data, setData] = useState(null)
  const [sys, setSys] = useState(null)
  const [err, setErr] = useState(null)
  const [query, setQuery] = useState('')
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [p, y] = await Promise.all([
          fetch('/api/procs').then((r) => r.json()),
          fetch('/api/system').then((r) => r.json()),
        ])
        if (cancelled) return
        setData(p)
        setSys(y)
        setErr(p?.status === 'error' ? p.reason : null)
      } catch (e) {
        if (!cancelled) setErr('Failed to reach the dashboard API')
      }
    }
    load()
    const id = setInterval(load, REFRESH_MS)
    return () => { cancelled = true; clearInterval(id) }
  }, [tick])

  const platform = health?.platform || {}
  const sensorKind = platform.sensor_kind || (data ? 'unknown' : 'unknown')
  const isProcfs = platform.capture_mode === 'procfs_live'
  const isEbpf = platform.capture_mode === 'live_tetragon'

  const rows = useMemo(() => {
    const all = data?.processes || []
    const q = query.trim().toLowerCase()
    if (!q) return all
    return all.filter((r) =>
      [r.comm, r.exe, r.pid, r.args?.join(' ')]
        .filter(Boolean)
        .some((f) => String(f).toLowerCase().includes(q)),
    )
  }, [data, query])

  const sensorBadge = isEbpf
    ? { label: 'LIVE · eBPF/TETRAGON', cls: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10', dot: 'bg-emerald-400 animate-pulse' }
    : isProcfs
      ? { label: 'LIVE · /proc POLL', cls: 'text-sky-400 border-sky-500/30 bg-sky-500/10', dot: 'bg-sky-400 animate-pulse' }
      : { label: 'FIXTURE REPLAY', cls: 'text-amber-400 border-amber-500/30 bg-amber-500/10', dot: 'bg-amber-400' }

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-4">
      {/* ── Sensor identity: never claim eBPF we are not using ── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Live Processes</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Process table read directly from <code className="text-foreground">/proc</code> on the sensor host.
          </p>
        </div>
        <span className={`flex items-center gap-1.5 text-[10px] font-mono font-bold tracking-wider px-2 py-1 rounded border ${sensorBadge.cls}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${sensorBadge.dot}`} />
          {sensorBadge.label}
        </span>
      </div>

      {/* ── Honest capability disclosure ── */}
      <div className="flex items-start gap-2.5 rounded-md border border-sky-500/25 bg-sky-500/5 px-3 py-2.5">
        <ShieldAlert size={15} className="text-sky-400 mt-0.5 shrink-0" />
        <div className="text-[11px] leading-relaxed text-muted-foreground">
          {isProcfs ? (
            <>
              <span className="text-sky-400 font-semibold">Not eBPF.</span> Upstream Tetragon
              publishes no <code className="text-foreground">s390x</code> build and this host has no
              container runtime, so live capture comes from polling the process table instead.
              <span className="text-foreground"> It observes process state, not kernel events</span>:
              a process that starts and exits between two polls is never seen, and syscalls such as{' '}
              <code className="text-foreground">connect()</code> are not observable at all.
            </>
          ) : isEbpf ? (
            <>
              <span className="text-emerald-400 font-semibold">eBPF via Tetragon.</span> Kernel-level
              execve and syscall observation.
            </>
          ) : (
            <>
              No live sensor detected. This host is replaying fixtures, so nothing below is a real
              process on this machine.
            </>
          )}
        </div>
      </div>

      {/* ── Platform evidence ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 rounded-lg border border-border bg-card/40 px-4 py-3">
        <Stat
          label="Architecture"
          value={data?.platform?.machine || platform.source_arch || '—'}
          tone={data?.platform?.is_s390x ? 'good' : 'default'}
          title="Measured on the running host, not configured"
        />
        <Stat label="Kernel" value={sys?.release || '—'} title={sys?.system} />
        <Stat label="vCPU" value={sys?.cpu_count ?? '—'} />
        <Stat
          label="Load (1m)"
          value={sys?.load_average ? sys.load_average['1m'].toFixed(2) : '—'}
          tone={(sys?.load_average?.['1m'] ?? 0) > 1.5 ? 'warn' : 'default'}
        />
        <Stat label="Uptime" value={fmtUptime(sys?.uptime_seconds)} />
        <Stat
          label="Memory"
          value={sys?.memory ? `${sys.memory.available_mb} MB free` : '—'}
          title={sys?.memory ? `${sys.memory.total_mb} MB total` : undefined}
        />
      </div>

      {/* ── Process table ── */}
      <div className="rounded-lg border border-border bg-card/40 overflow-hidden">
        <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-border flex-wrap">
          <div className="flex items-center gap-2">
            <Layers size={14} className="text-muted-foreground" />
            <span className="text-xs font-mono font-semibold">
              {rows.length}
              <span className="text-muted-foreground font-normal">
                {data?.counts?.total ? ` / ${data.counts.total}` : ''} processes
              </span>
            </span>
            {data?.counts?.total_rss_mb ? (
              <span className="text-[11px] text-muted-foreground font-mono">
                · {data.counts.total_rss_mb} MB resident
              </span>
            ) : null}
          </div>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by name, exe, or pid"
                className="pl-8 pr-3 py-1.5 text-xs font-mono bg-background border border-border rounded text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-sky-500/50 w-56"
              />
            </div>
            <button
              onClick={() => setTick((t) => t + 1)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] font-mono border border-border rounded hover:bg-muted/40 transition-colors"
              title="Refresh now"
            >
              <RefreshCw size={12} />
              refresh
            </button>
          </div>
        </div>

        {err ? (
          <div className="px-4 py-8 text-center text-xs text-amber-400">{err}</div>
        ) : rows.length === 0 ? (
          <div className="px-4 py-8 text-center text-xs text-muted-foreground">
            {data ? 'No processes match this filter.' : 'Waiting for the dashboard API…'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[11px] font-mono">
              <thead>
                <tr className="text-muted-foreground border-b border-border">
                  <th className="text-left font-normal px-4 py-2 w-16">PID</th>
                  <th className="text-left font-normal px-2 py-2 w-16">PPID</th>
                  <th className="text-left font-normal px-2 py-2 w-28">USER</th>
                  <th className="text-left font-normal px-2 py-2">COMMAND</th>
                  <th className="text-left font-normal px-2 py-2 w-14">STATE</th>
                  <th className="text-right font-normal px-2 py-2 w-16">THR</th>
                  <th className="text-right font-normal px-4 py-2 w-24">RSS</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.pid}
                    className="border-b border-border/40 hover:bg-muted/25 transition-colors"
                    title={r.exe || r.comm}
                  >
                    <td className="px-4 py-1.5 text-muted-foreground">{r.pid}</td>
                    <td className="px-2 py-1.5 text-muted-foreground">{r.ppid}</td>
                    <td className={`px-2 py-1.5 ${Number(r.uid) === 0 ? 'text-amber-400/90' : ''}`}>
                      {r.uid === 0 ? 'root' : `uid:${r.uid}`}
                    </td>
                    <td className="px-2 py-1.5">
                      <span className="text-foreground">{r.comm}</span>
                      {r.args && r.args.length > 1 && (
                        <span className="text-muted-foreground">
                          {' '}
                          {r.args.slice(1).join(' ').slice(0, 120)}
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-1.5 text-muted-foreground">{r.state}</td>
                    <td className="px-2 py-1.5 text-right text-muted-foreground">{r.threads}</td>
                    <td className="px-4 py-1.5 text-right text-muted-foreground">
                      {fmtBytes(r.rss_kb)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <p className="text-[10px] text-muted-foreground font-mono flex items-center gap-1.5">
        <Clock size={11} />
        Polling every {REFRESH_MS / 1000}s · kernel threads and the sensor's own lineage excluded ·
        denylist enforced on comm
      </p>
    </div>
  )
}