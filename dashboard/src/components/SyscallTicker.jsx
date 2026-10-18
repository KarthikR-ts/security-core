/**
 * SyscallTicker.jsx — Bottom status strip
 *
 * Shows recent raw events as a scrolling ticker.
 * Minimal, monospace, low visual weight — like a terminal log strip.
 *
 * The label reflects the ACTUAL sensor. It previously read "eBPF" and
 * "Awaiting eBPF telemetry..." unconditionally, which was false whenever the
 * forwarder ran the /proc sensor or a fixture replay.
 */

import { useStore } from '../store'
import { useEffect, useState } from 'react'

export default function SyscallTicker() {
  const { events, health } = useStore()
  const [tickerEvents, setTickerEvents] = useState([])

  useEffect(() => {
    if (events.length > 0) setTickerEvents(events.slice(0, 6))
  }, [events])

  const captureMode = health?.platform?.capture_mode
  const isEbpf = captureMode === 'live_tetragon'
  const isProcfs = captureMode === 'procfs_live'

  // Never claim eBPF unless it actually is.
  const streamLabel = isEbpf
    ? 'eBPF'
    : isProcfs
      ? '/proc'
      : captureMode === 'fixture_replay'
        ? 'REPLAY'
        : 'STREAM'

  const idleText = captureMode
    ? `Awaiting ${streamLabel} telemetry...`
    : 'Awaiting telemetry...'

  if (tickerEvents.length === 0) {
    return (
      <div className="h-7 min-h-7 bg-[#080b14] border-t border-white/[0.04] flex items-center px-4">
        <span className="text-[9px] text-slate-700 font-mono">{idleText}</span>
      </div>
    )
  }

  const renderEntry = (event, ariaHidden) => {
    const gradeColor = event.triage?.grade === 'TP' ? '#f87171' : event.triage?.grade === 'BP' ? '#60a5fa' : '#64748b'
    return (
      <span
        key={event.event_id}
        className="shrink-0 text-[9px] font-mono text-slate-700 whitespace-nowrap"
        aria-hidden={ariaHidden ? 'true' : undefined}
      >
        <span className="text-slate-600">{'{'}</span>
        <span className="text-slate-600"> type:</span><span className="text-slate-500">"{event.event_type}"</span>
        <span className="text-slate-600">, bin:</span><span className="text-slate-500">"{event.telemetry?.binary?.split('/').pop()}"</span>
        <span className="text-slate-600">, pid:</span><span className="text-slate-500">{event.telemetry?.pid}</span>
        <span className="text-slate-600">, grade:</span>
        <span style={{ color: gradeColor }}>"{event.triage?.grade}"</span>
        <span className="text-slate-600"> {'}'}</span>
      </span>
    )
  }

  return (
    <div className="h-7 min-h-7 bg-[#080b14] border-t border-white/[0.04] flex items-center overflow-hidden px-4 gap-3">
      <span className="text-[9px] font-mono font-semibold text-slate-700 uppercase tracking-wider shrink-0">
        {streamLabel}&nbsp;&nbsp;▶
      </span>

      <div className="flex-1 overflow-hidden">
        <div className="flex items-center gap-4 animate-ticker">
          {tickerEvents.map((event) => renderEntry(event, false))}
          {/* Duplicated for a seamless loop; hidden from assistive tech. */}
          {tickerEvents.map((event) => renderEntry(event, true))}
        </div>
      </div>
    </div>
  )
}
