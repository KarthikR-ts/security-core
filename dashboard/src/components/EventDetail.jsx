export default function EventDetail({ event, onClose }) {
  if (!event) return null

  const tel = event.telemetry || {}

  return (
    <div className="event-detail-overlay" onClick={onClose}>
      <div className="event-detail-modal" onClick={e => e.stopPropagation()}>
        <div className="event-detail-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className={`severity-badge ${event.severity || 'medium'}`}>
                {event.severity}
              </span>
              <span style={{ fontSize: '16px', fontWeight: 700 }}>
                {event.event_type?.replace('process_', '').toUpperCase()}
              </span>
              <span title="Heuristic signal strength — not a calibrated probability." className={`triage-badge ${(event.triage?.grade || '').toLowerCase()}`}>
                {event.triage?.grade} {event.triage?.confidence ? `${Math.round(event.triage.confidence * 100)}% signal` : ''}
              </span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              {event.description}
            </div>
          </div>
          <button className="event-detail-close" onClick={onClose}>✕</button>
        </div>
        <div className="event-detail-body">
          <div className="detail-section">
            <div className="detail-section-title">Event Metadata</div>
            <div className="detail-grid">
              <span className="detail-key">Event ID</span>
              <span className="detail-value">{event.event_id}</span>
              <span className="detail-key">Timestamp</span>
              <span className="detail-value">{event.timestamp}</span>
              <span className="detail-key">Source</span>
              <span className="detail-value">{event.source}</span>
              <span className="detail-key">Node</span>
              <span className="detail-value">{event.node_name}</span>
              <span className="detail-key">Event Type</span>
              <span className="detail-value">{event.event_type}</span>
            </div>
          </div>

          <div className="detail-section">
            <div className="detail-section-title">Capture & Platform</div>
            <div className="detail-grid">
              <span className="detail-key">Capture Mode</span>
              <span className="detail-value">
                <span
                  style={{
                    fontFamily: 'monospace',
                    fontSize: '11px',
                    fontWeight: 700,
                    letterSpacing: '0.05em',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    color: event.capture_mode === 'live_tetragon' ? 'var(--green, #34d399)' : 'var(--amber)',
                    border: `1px solid ${event.capture_mode === 'live_tetragon' ? 'rgba(52, 211, 153, 0.3)' : 'rgba(251, 191, 36, 0.3)'}`,
                  }}
                >
                  {event.capture_mode || event.platform?.capture_mode || 'unknown'}
                </span>
              </span>
              <span className="detail-key">Event Source</span>
              <span className="detail-value">{event.event_source || event.platform?.event_source || '—'}</span>
              <span className="detail-key">Source Host</span>
              <span className="detail-value">{event.source_host || event.platform?.source_host || '—'}</span>
              <span className="detail-key">Architecture</span>
              <span className="detail-value">
                {event.source_arch || event.platform?.source_arch || '—'}
                {(event.source_arch || event.platform?.source_arch) === 's390x' ? ' (IBM LinuxONE)' : ''}
              </span>
              <span className="detail-key">Schema Version</span>
              <span className="detail-value">{event.schema_version || event.platform?.schema_version || '—'}</span>
              <span className="detail-key">Node</span>
              <span className="detail-value">{event.node_name || event.platform?.node_name || '—'}</span>
            </div>
          </div>

          <div className="detail-section">
            <div className="detail-section-title">Privacy & Redaction</div>
            {(() => {
              const privacy = event.privacy || {}
              const fields = privacy.redacted_fields || []
              return (
                <div className="detail-grid">
                  <span className="detail-key">Redacted</span>
                  <span className="detail-value" style={{ color: privacy.redacted ? 'var(--amber)' : 'var(--text-muted)' }}>
                    {privacy.redacted ? 'Yes — before persistence' : 'No sensitive fields matched'}
                  </span>
                  <span className="detail-key">Policy</span>
                  <span className="detail-value">{privacy.policy || 'unknown'}</span>
                  <span className="detail-key">Redacted Fields</span>
                  <span className="detail-value">
                    {fields.length > 0 ? (
                      <span style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {fields.map(f => (
                          <span
                            key={f}
                            style={{
                              fontFamily: 'monospace',
                              fontSize: '10px',
                              padding: '1px 6px',
                              borderRadius: '4px',
                              background: 'rgba(251, 191, 36, 0.12)',
                              color: 'var(--amber)',
                            }}
                          >
                            {f}
                          </span>
                        ))}
                      </span>
                    ) : '—'}
                  </span>
                </div>
              )
            })()}
          </div>

          <div className="detail-section">
            <div className="detail-section-title">Process Telemetry</div>
            <div className="detail-grid">
              <span className="detail-key">Binary</span>
              <span className="detail-value" style={{ color: 'var(--cyan)' }}>{tel.binary}</span>
              <span className="detail-key">Arguments</span>
              <span className="detail-value">{(tel.args || []).join(' ') || '—'}</span>
              <span className="detail-key">PID</span>
              <span className="detail-value">{tel.pid}</span>
              <span className="detail-key">UID / User</span>
              <span className="detail-value">{tel.uid} ({tel.user})</span>
              <span className="detail-key">CWD</span>
              <span className="detail-value">{tel.cwd || '—'}</span>
              <span className="detail-key">Namespace</span>
              <span className="detail-value">{tel.namespace || '—'}</span>
              <span className="detail-key">Pod</span>
              <span className="detail-value" style={{ color: 'var(--purple)' }}>{tel.pod || '—'}</span>
              <span className="detail-key">Container ID</span>
              <span className="detail-value">{tel.container_id || '—'}</span>
              <span className="detail-key">Parent Binary</span>
              <span className="detail-value">{tel.parent_binary || '—'}</span>
              <span className="detail-key">Parent PID</span>
              <span className="detail-value">{tel.parent_pid || '—'}</span>
            </div>
          </div>

          {tel.kprobe && (
            <div className="detail-section">
              <div className="detail-section-title">KProbe Data</div>
              <div className="detail-grid">
                <span className="detail-key">Function</span>
                <span className="detail-value" style={{ color: 'var(--amber)' }}>{tel.kprobe.function}</span>
                <span className="detail-key">Policy</span>
                <span className="detail-value">{tel.kprobe.policy}</span>
                <span className="detail-key">Action</span>
                <span className="detail-value">{tel.kprobe.action}</span>
              </div>
            </div>
          )}

          {event.triage && (
            <div className="detail-section">
              <div className="detail-section-title">Triage Result</div>
              <div className="detail-grid">
                <span className="detail-key">Grade</span>
                <span className="detail-value">
                  <span className={`triage-badge ${(event.triage.grade || '').toLowerCase()}`}>
                    {event.triage.grade}
                  </span>
                </span>
                <span className="detail-key" title="Heuristic signal strength — not a calibrated probability.">Signal strength</span>
                <span className="detail-value">{Math.round((event.triage.confidence || 0) * 100)}%{event.explanation?.basis ? ` · ${event.explanation.basis}` : ''}</span>
                <span className="detail-key">Status</span>
                <span className="detail-value">{event.triage.status}</span>
              </div>
            </div>
          )}

          {event.explanation && (
            <div className="detail-section">
              <div className="detail-section-title">Threat Intelligence</div>
              <div className="detail-grid">
                <span className="detail-key">MITRE ATT&CK</span>
                <span className="detail-value" style={{ color: 'var(--red)' }}>
                  {event.explanation.mitre_url ? (
                    <a
                      href={event.explanation.mitre_url}
                      target="_blank"
                      rel="noreferrer"
                      style={{ color: 'inherit', textDecoration: 'underline' }}
                      title="Open technique on attack.mitre.org"
                    >
                      {event.explanation.mitre_id} ↗
                    </a>
                  ) : event.explanation.mitre_id}
                  {event.explanation.mitre_name && event.explanation.mitre_name !== 'Unknown Technique'
                    ? ` — ${event.explanation.mitre_name}`
                    : ''}
                </span>
                <span className="detail-key">Tactic</span>
                <span className="detail-value">{event.explanation.mitre_tactic || '—'}</span>
                <span className="detail-key">Analysis Basis</span>
                <span className="detail-value" style={{ fontFamily: 'monospace', fontSize: '11px' }}>
                  {event.explanation.basis || 'unknown'}
                </span>
                {(event.explanation.evidence || []).length > 0 && (
                  <>
                    <span className="detail-key">Evidence</span>
                    <span className="detail-value">
                      <span style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                        {event.explanation.evidence.map((item, i) => (
                          <span key={i} style={{ fontSize: '11px', color: 'var(--text-muted)' }}>• {item}</span>
                        ))}
                      </span>
                    </span>
                  </>
                )}
                <span className="detail-key">Recommended Action</span>
                <span className="detail-value">{event.explanation.recommended_action || '—'}</span>
                <span className="detail-key">Guidance</span>
                <span className="detail-value">{event.explanation.guidance}</span>
                {event.explanation.confidence_semantics && (
                  <>
                    <span className="detail-key">Confidence Note</span>
                    <span className="detail-value" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {event.explanation.confidence_semantics}
                    </span>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
