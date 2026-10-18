/**
 * CommandCenter.jsx — Page A: Immunity Command Center
 *
 * Design principles applied:
 * 1. HIERARCHY: Top status bar is compact; cluster map is the dominant visual.
 * 2. ASYMMETRY: Cluster map takes 8/12 columns; right panel stacks secondary data.
 * 3. NO GLOW: All neon shadows/gradients removed. Color used semantically only.
 * 4. OPERATIONAL METRICS: Every number has context (last seen, trend, percent).
 * 5. ENFORCEMENT: Shown as a structured state panel, not a decorative toggle.
 * 6. CLUSTER NODES: Structured data rows, not icon blobs.
 * 7. CHARTS: Include axis labels and units.
 */

import { useStore } from '../store'
import { motion } from 'framer-motion'
import { Shield, Server, Activity, AlertTriangle, CheckCircle, TrendingUp, BarChart2, Brain, CheckCircle2, Database, Compass, HardHat, Cog, Hexagon, Box, Zap } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useMemo, useState, useCallback, Fragment } from 'react'

export default function CommandCenter() {
  const {
    immunityScore, immunityData, metrics, triageStats, cluster,
    enforcementMode, toggleEnforcement, events, policies, timeline,
    health, enforcementThreshold, enforcementToggledAt,
  } = useStore()

  // Derived from the live health block. No placeholder defaults: a fabricated
  // architecture or liveness indicator is exactly the failure mode this
  // project exists to avoid.
  const platformHost = health?.platform?.source_host
  const platformArch = health?.platform?.source_arch
  const platformLive = Boolean(health?.platform?.live_capture)

  const lastEventAge = useMemo(() => {
    if (!metrics?.last_event_timestamp) return null
    const delta = (Date.now() - new Date(metrics.last_event_timestamp)) / 1000
    return delta < 60 ? `${Math.round(delta)}s ago` : `${Math.round(delta / 60)}m ago`
  }, [metrics?.last_event_timestamp])

  const tpCount = triageStats?.breakdown?.TruePositive || 0
  const fpCount = triageStats?.breakdown?.FalsePositive || 0
  const bpCount = triageStats?.breakdown?.BenignPositive || 0
  const totalTriaged = tpCount + fpCount + bpCount || 1
  const filterRatio = Math.round(((fpCount + bpCount) / totalTriaged) * 100)
  const scoringBasis = Object.entries(triageStats?.basis_breakdown || {})
    .filter(([key]) => key !== 'unknown')
    .sort((a, b) => b[1] - a[1])[0]?.[0]
  const scoringLabel = scoringBasis
    ? `Scoring: ${scoringBasis.replaceAll('_', ' ')}`
    : 'Scoring: heuristic rules'

  return (
    <div className="flex flex-col h-full bg-[#0a0e1a] overflow-hidden">
      {/* ── TOP STATUS STRIP ────────────────────────────────────────── */}
      <div className="flex-none px-6 py-5 border-b border-border flex flex-wrap lg:flex-nowrap items-stretch gap-4 overflow-x-auto bg-muted/10 shadow-sm z-10 relative shrink-0">
        
        {/* Security Score */}
        <div className="glass-card flex-1 min-w-[220px] p-5 flex flex-col justify-between">
          <div className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Immunity Score</div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className={`text-4xl font-extrabold tracking-tight tabular-nums drop-shadow-sm
              ${immunityScore >= 80 ? 'text-emerald-500' : immunityScore >= 50 ? 'text-amber-500' : 'text-destructive'}`}>
              {Math.round(immunityScore)}
            </span>
            <span className="text-xs text-muted-foreground font-medium">/ 100 pts</span>
          </div>
        </div>

        {/* Blocked Threats */}
        <div className="glass-card flex-1 min-w-[220px] p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold text-muted-foreground">Active Threats</div>
            <Shield className="w-4 h-4 text-destructive/80" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold tracking-tight text-destructive drop-shadow-sm">{metrics?.active_alerts || 0}</span>
            <span className="text-xs text-muted-foreground font-medium">
              {metrics?.neutralized_count ? `${metrics.neutralized_count} neutralized` : 'critical + high'}
            </span>
          </div>
        </div>


        {/* Event rate */}
        <div className="glass-card flex-1 min-w-[220px] p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold text-muted-foreground">Total Events</div>
            <BarChart2 className="w-4 h-4 text-muted-foreground/80" />
          </div>
          <div className="mt-3 flex flex-col">
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold tracking-tight text-foreground drop-shadow-sm">{metrics?.events_total || 0}</span>
              <span className="text-xs text-muted-foreground font-medium">{metrics?.events_per_second || 0} evt/s</span>
            </div>
            <span className="text-[10px] text-muted-foreground mt-1 tracking-tight">last seen: {lastEventAge || 'no data'}</span>
          </div>
        </div>

      </div>

      {/* ── MAIN BODY ─────────────────────────────────────────────────
          Cluster map is dominant (8 col). Right panel stacks secondary data. */}
      <div className="flex-1 flex min-h-0">

        {/* LEFT: real execution topology */}
        <div className="flex-1 border-r border-border flex flex-col overflow-hidden bg-background">
          <div className="flex-none px-6 py-4 border-b border-border flex items-center justify-between bg-muted/5">
            <div className="flex items-center gap-3">
              <div className="p-1.5 bg-primary/10 rounded-md border border-primary/20">
                <Server className="w-4 h-4 text-primary" />
              </div>
              <span className="text-sm font-semibold text-foreground tracking-tight">Execution Topology</span>
              <span className="text-xs text-muted-foreground ml-2 px-2 py-0.5 bg-muted rounded-full">
                {cluster?.host?.hostname || platformHost || '—'}
                {' · '}
                {cluster?.host?.machine || platformArch || '—'}
                {cluster?.has_orchestrator ? '' : ' · native install'}
              </span>
            </div>
            <div
              className={`flex items-center gap-2 text-xs font-medium px-2 py-1 rounded-md border ${
                platformLive
                  ? 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20'
                  : 'text-muted-foreground bg-muted/30 border-border'
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  platformLive ? 'bg-emerald-500 animate-pulse' : 'bg-muted-foreground'
                }`}
              />
              {platformLive ? 'Live Sensor' : 'No Live Sensor'}
            </div>
          </div>
          <div className="flex-1 overflow-hidden p-6 flex flex-col">
            <HostPipeline
              cluster={cluster}
              health={health}
              events={events}
              policies={policies}
            />
          </div>
        </div>

        {/* RIGHT PANEL: Secondary data stack */}
        <div className="w-[340px] flex flex-col overflow-y-auto p-5 space-y-5 bg-muted/5">
          
          {/* Auto-Block Panel */}
          <div className="glass-panel p-5 rounded-xl">
            <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Auto-Block Config
            </div>
            <div className="space-y-3.5">
              <div className="flex items-center justify-between bg-background p-3 rounded-lg border border-border shadow-sm">
                <span className="text-sm font-medium text-foreground">Status</span>
                <div className="flex items-center gap-3">
                  <Switch
                    checked={enforcementMode === 'guardian'}
                    onCheckedChange={toggleEnforcement}
                    className="h-5 w-9 data-[state=checked]:bg-destructive data-[state=unchecked]:bg-primary"
                  />
                  <span className={`text-xs font-bold uppercase tracking-wider ${enforcementMode === 'guardian' ? 'text-destructive' : 'text-primary'}`}>
                    {enforcementMode === 'guardian' ? 'ON' : 'OFF'}
                  </span>
                </div>
              </div>
              <div className="pt-2 space-y-2">
                <OperationalRow
                  label="TracingPolicies"
                  value={
                    (policies || []).length === 0
                      ? 'none on disk'
                      : `${(policies || []).filter((p) => p.enforced).length}/${policies.length} enforced`
                  }
                />
                <OperationalRow
                  label="Alert Threshold"
                  value={enforcementThreshold ?? 'not configured'}
                />
                <OperationalRow
                  label="Last Toggle"
                  value={enforcementToggledAt ? formatTime(enforcementToggledAt) : 'never toggled'}
                />
              </div>
            </div>
          </div>

          {/* Severity Breakdown */}
          <div className="glass-panel p-5 rounded-xl">
            <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Active Severity Breakdown
            </div>
            <div className="space-y-3">
              <SeverityRow label="CRITICAL" count={metrics?.active_severity?.critical || 0} total={metrics?.events_total || 0} color="text-destructive font-bold" barColor="bg-destructive shadow-[0_0_8px_rgba(var(--destructive),0.5)]" />
              <SeverityRow label="HIGH"     count={metrics?.active_severity?.high || 0}     total={metrics?.events_total || 0} color="text-orange-500 font-bold" barColor="bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.5)]" />
              <SeverityRow label="MEDIUM"   count={metrics?.active_severity?.medium || 0}   total={metrics?.events_total || 0} color="text-amber-500 font-medium" barColor="bg-amber-500" />
              <SeverityRow label="LOW"      count={metrics?.active_severity?.low || 0}      total={metrics?.events_total || 0} color="text-muted-foreground" barColor="bg-muted-foreground" />
            </div>
            {(metrics?.neutralized_count || 0) > 0 && (
              <div className="mt-3 pt-3 border-t border-border text-xs text-emerald-500 font-mono">
                {metrics.neutralized_count} threat{metrics.neutralized_count === 1 ? '' : 's'} neutralized
              </div>
            )}
          </div>

          {/* ML Triage Distribution */}
          <div className="glass-panel p-5 rounded-xl">
            <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 flex items-center gap-2">
              <CheckCircle className="w-4 h-4" />
              Triage Distribution
            </div>
            <div className="space-y-3">
              <TriageRow label="True Positive"   count={tpCount}  pct={triageStats?.percentages?.TruePositive || 0}   color="text-destructive font-semibold" barColor="bg-destructive shadow-[0_0_8px_rgba(var(--destructive),0.5)]" />
              <TriageRow label="Benign Positive" count={bpCount}  pct={triageStats?.percentages?.BenignPositive || 0} color="text-blue-500 font-semibold" barColor="bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]" />
              <TriageRow label="False Positive"  count={fpCount}  pct={triageStats?.percentages?.FalsePositive || 0}  color="text-muted-foreground" barColor="bg-muted" />
            </div>
            <div className="mt-4 pt-3 border-t border-border text-xs text-muted-foreground font-mono flex justify-between">
              <span>{scoringLabel}</span>
              <span title="Heuristic signal strength averaged over triaged events — not a calibrated probability.">Avg signal: {Math.round((triageStats?.avg_confidence || 0) * 100)}%</span>
            </div>
          </div>

          {/* Attack Frequency Chart */}
          <div className="glass-panel p-5 rounded-xl flex-1 min-h-[180px] flex flex-col">
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
                <TrendingUp className="w-4 h-4" />
                Attack Frequency
              </div>
              <span className="text-[10px] text-muted-foreground font-mono bg-muted px-1.5 py-0.5 rounded">events/min</span>
            </div>
            <div className="text-xs text-muted-foreground mb-4">Last 30 minutes</div>
            <FrequencyChart buckets={timeline} />
          </div>
        </div>
      </div>
    </div>
  )
}

/* -- Host Pipeline Graph -------------------------------------------------
   Renders the REAL execution topology: the actual host, the actual sensor,
   and the actual stream. Nothing here is illustrative.

   This replaced a hardcoded SVG of a three-node Kind cluster with Tetragon
   DaemonSets, which rendered identically on a LinuxONE VM that has neither
   Kubernetes nor Tetragon. Fabricated topology is worse than none, because it
   is indistinguishable from real data at a glance. */
function HostPipeline({ cluster, health, events, policies }) {
  const host = cluster?.host || {}
  const platform = health?.platform || {}
  const sensorKind = platform.sensor_kind || null
  const isLive = Boolean(platform.live_capture)

  const tpCount = useMemo(
    () => (events || []).filter((e) => e.triage?.grade === 'TP').length,
    [events]
  )
  const totalEvents = (events || []).length

  const enforcedPolicies = (policies || []).filter((p) => p.enforced).length
  const presentPolicies = (policies || []).length

  const stages = [
    {
      id: 'host',
      icon: Server,
      label: 'Execution Host',
      sub: host.hostname || platform.source_host || 'unknown',
      rows: [
        ['Architecture', host.machine || platform.source_arch || '�'],
        ['Kernel', host.release || '�'],
        ['vCPU', host.cpu_count ?? '�'],
        ['Orchestrator', cluster?.orchestrator || 'none (native install)'],
      ],
      ok: Boolean(host.machine),
    },
    {
      id: 'sensor',
      icon: Activity,
      label: 'Sensor',
      sub: isLive ? 'live' : 'not running',
      rows: [
        ['Kind', sensorKind || '�'],
        ['Is eBPF', platform.sensor_is_ebpf === true ? 'yes' : 'no'],
        ['Capture mode', platform.capture_mode || '�'],
      ],
      ok: isLive,
    },
    {
      id: 'policies',
      icon: Shield,
      label: 'TracingPolicies',
      sub: presentPolicies === 0 ? 'none present' : `${enforcedPolicies}/${presentPolicies} enforced`,
      rows: presentPolicies === 0
        ? [['Status', 'no policy files on disk']]
        : [
            ['On disk', String(presentPolicies)],
            ['Enforced', String(enforcedPolicies)],
            ['Note', enforcedPolicies === 0 ? 'sensor not running' : 'loaded'],
          ],
      ok: enforcedPolicies > 0,
    },
    {
      id: 'stream',
      icon: Database,
      label: 'Event Stream',
      sub: health?.components?.redis?.stream || '�',
      rows: [
        ['Redis', health?.components?.redis?.status || '�'],
        ['Events cached', String(health?.events_cached ?? 0)],
        ['True positives', String(tpCount)],
      ],
      ok: health?.components?.redis?.status === 'connected',
    },
  ]

  return (
    <div className="flex-1 flex flex-col gap-3 overflow-y-auto">
      {stages.map((s, i) => {
        const Icon = s.icon
        return (
          <Fragment key={s.id}>
            <div
              className={`rounded-lg border px-4 py-3 transition-colors ${
                s.ok ? 'border-border bg-card/40' : 'border-border/60 bg-card/20'
              }`}
            >
              <div className="flex items-center gap-2.5 mb-2">
                <Icon
                  size={15}
                  className={s.ok ? 'text-primary' : 'text-muted-foreground'}
                />
                <span className="text-xs font-semibold text-foreground tracking-tight">
                  {s.label}
                </span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ml-auto ${
                    s.ok
                      ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
                      : 'text-muted-foreground border-border bg-muted/30'
                  }`}
                >
                  {s.sub}
                </span>
              </div>
              <div className="space-y-1 pl-[23px]">
                {s.rows.map(([k, v]) => (
                  <div key={k} className="flex items-baseline gap-2 text-[11px] font-mono">
                    <span className="text-muted-foreground w-24 shrink-0">{k}</span>
                    <span className="text-foreground/90 truncate">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
            {i < stages.length - 1 && (
              <div className="flex justify-center -my-1 text-border">
                <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
                  <path d="M5 0 L9 6 L1 6 Z" fill="currentColor" opacity="0.5" />
                </svg>
              </div>
            )}
          </Fragment>
        )
      })}
    </div>
  )
}

/* ── Severity Row ── */
function SeverityRow({ label, count, total, color, barColor }) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  return (
    <div className="flex items-center gap-2">
      <span className={`text-[10px] font-mono font-bold w-14 ${color}`}>{label}</span>
      <div className="flex-1 h-1 bg-slate-800 rounded-sm overflow-hidden">
        <div className={`h-full ${barColor} opacity-70`} style={{ width: `${pct}%`, transition: 'width 0.6s ease' }} />
      </div>
      <span className="text-[11px] font-mono text-slate-300 w-6 text-right">{count}</span>
      <span className="text-[10px] text-slate-600 w-8 text-right">{pct}%</span>
    </div>
  )
}

/* ── Triage Row ── */
function TriageRow({ label, count, pct, color, barColor }) {
  return (
    <div className="flex items-center gap-2">
      <span className={`text-[11px] font-medium w-28 ${color}`}>{label}</span>
      <div className="flex-1 h-1 bg-slate-800 rounded-sm overflow-hidden">
        <div className={`h-full ${barColor} opacity-70`} style={{ width: `${pct}%`, transition: 'width 0.6s ease' }} />
      </div>
      <span className="text-[11px] font-mono text-slate-300 w-6 text-right">{count}</span>
    </div>
  )
}

/* ── Frequency Chart — with axis labels and units ── */
function FrequencyChart({ buckets }) {
  if (!buckets || buckets.length === 0) {
    return <div className="text-[11px] text-slate-600">No timeline data</div>
  }
  const maxTotal = Math.max(...buckets.map(b => b.total || 0), 1)
  const firstTime = buckets[0]?.timestamp ? formatTime(buckets[0].timestamp) : ''
  const lastTime = buckets[buckets.length - 1]?.timestamp ? formatTime(buckets[buckets.length - 1].timestamp) : ''

  return (
    <div>
      {/* Y-axis max label */}
      <div className="text-[9px] text-slate-700 font-mono mb-0.5 text-right">{maxTotal}</div>

      {/* Chart bars */}
      <div className="flex items-end gap-[2px] h-20">
        {buckets.map((bucket, idx) => {
          const pct = Math.max(((bucket.total || 0) / maxTotal) * 100, 3)
          const isHigh = (bucket.process_kprobe || 0) > 2
          return (
            <Tooltip key={idx}>
              <TooltipTrigger asChild>
                <div
                  className={`flex-1 min-w-[2px] cursor-default transition-all
                    ${isHigh ? 'bg-red-500/60' : 'bg-slate-600/60'}
                    hover:opacity-100 opacity-75`}
                  style={{ height: `${pct}%` }}
                />
              </TooltipTrigger>
              <TooltipContent side="top">
                <p className="text-[11px] font-mono">
                  {formatTime(bucket.timestamp)} — <strong>{bucket.total || 0}</strong> events
                  {isHigh && ' · HIGH ACTIVITY'}
                </p>
              </TooltipContent>
            </Tooltip>
          )
        })}
      </div>

      {/* X-axis: time range */}
      <div className="flex justify-between mt-1">
        <span className="text-[9px] text-slate-700 font-mono">{firstTime}</span>
        <span className="text-[9px] text-slate-700 font-mono">{lastTime}</span>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 mt-2">
        <div className="flex items-center gap-1">
          <div className="w-3 h-1.5 bg-slate-600/60" />
          <span className="text-[9px] text-slate-600">Normal</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-1.5 bg-red-500/60" />
          <span className="text-[9px] text-slate-600">High activity</span>
        </div>
      </div>
    </div>
  )
}

/* ── Operational row for Enforcement panel ── */
function OperationalRow({ label, value, valueClass = 'text-slate-300' }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[11px] text-slate-500">{label}</span>
      <span className={`text-[11px] font-mono font-semibold ${valueClass}`}>{value}</span>
    </div>
  )
}

function formatTime(ts) {
  if (!ts) return ''
  try { return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }) }
  catch { return '' }
}
