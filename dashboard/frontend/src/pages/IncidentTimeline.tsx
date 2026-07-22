import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { getIncidentTimeline, type TimelineEntry } from '../api/client'

export default function IncidentTimeline() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [entries, setEntries] = useState<TimelineEntry[]>([])

  useEffect(() => {
    if (id) {
      getIncidentTimeline(id).then(setEntries).catch(() => setEntries([]))
    }
  }, [id])

  if (!id) return null

  return (
    <div style={{ maxWidth: 840, margin: '0 auto' }}>
      <div className="page-header" style={{ marginBottom: 32 }}>
        <div>
          <button className="btn secondary" style={{ marginBottom: 16 }} onClick={() => navigate(-1)}>
            ← Back to Incident
          </button>
          <p className="eyebrow">AUDIT LEDGER SEQUENCE</p>
          <h1 className="mono">{id} Event Timeline</h1>
          <p className="subtle">Chronological sequence of telemetry, AI agent inferences, honeypot triggers, and SOAR containment actions.</p>
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <p className="subtle">No ledger events recorded for this incident yet.</p>
        </div>
      ) : (
        <div style={{ position: 'relative', paddingLeft: 20 }}>
          {/* Vertical Timeline Line */}
          <div style={{ position: 'absolute', top: 12, bottom: 12, left: 34, width: 2, background: 'var(--border)' }} />

          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            {entries.map((entry, idx) => {
              const date = new Date(entry.timestamp)
              const timeString = date.toLocaleTimeString()
              
              let color = 'var(--primary)'
              let icon = '⚡'
              if (entry.event_type.includes('DETECTION')) { color = 'var(--danger)'; icon = '🚨' }
              if (entry.event_type.includes('AI_')) { color = 'var(--ai-purple)'; icon = '🧠' }
              if (entry.event_type.includes('ACTION') || entry.event_type.includes('MONITOR')) { color = 'var(--safe)'; icon = '🛡️' }
              if (entry.event_type.includes('ESCALAT')) { color = 'var(--warning)'; icon = '⚠️' }

              return (
                <div key={idx} style={{ position: 'relative', paddingLeft: 40 }}>
                  {/* Timeline Step Icon */}
                  <div 
                    style={{ 
                      position: 'absolute', 
                      left: 0, 
                      top: 4, 
                      width: 30, 
                      height: 30, 
                      borderRadius: '50%', 
                      background: 'var(--panel-bg-solid)', 
                      border: `2px solid ${color}`, 
                      display: 'flex', 
                      alignItems: 'center', 
                      justifyContent: 'center', 
                      fontSize: 13, 
                      zIndex: 2,
                      boxShadow: `0 0 12px ${color}40`
                    }}
                  >
                    {icon}
                  </div>

                  <div className="card tight" style={{ borderColor: `${color}35` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10, alignItems: 'center' }}>
                      <strong style={{ color, fontFamily: 'var(--font-mono)', fontSize: 14 }}>
                        {entry.event_type}
                      </strong>
                      <span className="mono subtle" style={{ fontSize: 12 }}>
                        {timeString}
                      </span>
                    </div>

                    <pre style={{ margin: 0, padding: 12, background: 'rgba(0,0,0,0.35)', borderRadius: 8, fontSize: 12, color: '#cbd5e1', overflowX: 'auto', fontFamily: 'var(--font-mono)', border: '1px solid var(--border)' }}>
                      {JSON.stringify(entry.data, null, 2)}
                    </pre>

                    <div style={{ marginTop: 10, textAlign: 'right' }}>
                      <span className="mono subtle" style={{ fontSize: 11 }}>
                        SHA256: 0x{(entry.hash || '').replace(/\.+$/, '')}...
                      </span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
