/**
 * Header.jsx — Production Page Header
 *
 * Design: Minimal top bar. Page context + system state. No decorative elements.
 * Typography hierarchy: title 16px, badges 10px, clock 12px mono.
 */

import { useStore } from '../store'
import { useState, useEffect } from 'react'

const PAGE_TITLES = {
  command:    'Command Center',
  ledger:     'Incident Ledger',
  forensics:  'Forensics Deep-Dive',
  processes:  'Live Processes',
}

export default function Header() {
  const { currentPage, health, wsConnected } = useStore()
  const [clock, setClock] = useState('')

  useEffect(() => {
    const tick = () => {
      const now = new Date()
      const offset = -now.getTimezoneOffset()
      const sign = offset >= 0 ? '+' : '-'
      const h = String(Math.abs(Math.floor(offset / 60))).padStart(2, '0')
      const m = String(Math.abs(offset % 60)).padStart(2, '0')
      setClock(now.toLocaleTimeString('en-US', { hour12: false }) + ` UTC${sign}${h}:${m}`)
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  const platform = health?.platform || {}
  const captureMode = platform.capture_mode || 'unknown'
  const isEbpf = captureMode === 'live_tetragon'
  const isProcfs = captureMode === 'procfs_live'
  // Both are live, but they are not the same thing. Rendering /proc capture as
  // plain "LIVE" would imply eBPF fidelity we do not have, so each gets its
  // own colour and its own label.
  const isLive = isEbpf || isProcfs
  const arch = platform.source_arch || 'unknown'

  const captureLabel = isEbpf
    ? 'LIVE · eBPF'
    : isProcfs
      ? 'LIVE · /proc'
      : captureMode === 'fixture_replay'
        ? 'FIXTURE REPLAY'
        : captureMode.toUpperCase().replace(/_/g, ' ')

  const captureStyle = isEbpf
    ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
    : isProcfs
      ? 'text-sky-400 border-sky-500/30 bg-sky-500/10'
      : captureMode === 'fixture_replay'
        ? 'text-amber-400 border-amber-500/30 bg-amber-500/10'
        : 'text-muted-foreground border-border bg-muted/30'

  const captureTitle = isEbpf
    ? 'Live kernel-level telemetry from Tetragon/eBPF'
    : isProcfs
      ? 'Live process state polled from /proc — NOT eBPF. Short-lived processes can be missed and syscalls are not observable.'
      : 'Replaying stored fixtures — not a live sensor'

  return (
    <header className="h-16 min-h-[4rem] flex flex-row items-center justify-between px-6 border-b border-border bg-background backdrop-blur-md sticky top-0 z-50">
      {/* Left: breadcrumb-style title */}
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-muted-foreground mr-1">Security-Core</span>
        <span className="text-sm text-muted-foreground mr-1">/</span>
        <span className="text-lg font-semibold text-foreground tracking-tight">{PAGE_TITLES[currentPage] || 'Dashboard'}</span>
      </div>

      {/* Right: platform truth + system status */}
      <div className="flex items-center gap-4">
        <span
          title={`${captureTitle}\n\nCapture mode: ${captureMode} · source: ${platform.event_source || 'unknown'} · schema: ${platform.schema_version || 'unknown'}`}
          className={`flex items-center gap-1.5 text-[10px] font-mono font-bold tracking-wider px-2 py-1 rounded border ${captureStyle}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${isEbpf ? 'bg-emerald-400 animate-pulse' : isProcfs ? 'bg-sky-400 animate-pulse' : 'bg-amber-400'}`} />
          {captureLabel}
        </span>

        <span
          title={`Host: ${platform.source_host || 'unknown'} · hardware: ${platform.hardware || 'unknown'}`}
          className="text-[10px] font-mono text-muted-foreground border border-border bg-muted/30 px-2 py-1 rounded"
        >
          {arch}{String(arch).toLowerCase() === 's390x' ? ' · LinuxONE' : ''}
        </span>

        <span
          title={wsConnected ? 'Live event stream connected' : 'Event stream disconnected'}
          className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground"
        >
          <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-slate-600'}`} />
          {wsConnected ? 'streaming' : 'offline'}
        </span>

        <span className="text-sm text-muted-foreground font-mono">{clock}</span>
      </div>
    </header>
  )
}
