import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
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
    <div className="reasoning-grid" style={{ maxWidth: 800, margin: '0 auto' }}>
      <div className="page-header" style={{ marginBottom: 32 }}>
        <div>
          <button className="btn secondary" style={{ marginBottom: 16 }} onClick={() => navigate(-1)}>← Back</button>
          <p className="eyebrow">Audit Ledger</p>
          <h1 className="mono">{id} Timeline</h1>
          <p className="subtle">Chronological sequence of events, AI inferences, and SOAR actions</p>
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 48 }}>
          <p className="subtle">No ledger entries found for this incident.</p>
        </div>
      ) : (
        <div style={{ position: 'relative', paddingLeft: 24 }}>
          {/* Vertical line */}
          <div style={{ position: 'absolute', top: 0, bottom: 0, left: 24, width: 2, background: 'var(--border)' }} />
          
          <div style={{ display: 'grid', gap: 24 }}>
            {entries.map((entry, idx) => {
              const date = new Date(entry.timestamp)
              const timeString = date.toLocaleTimeString()
              
              let color = 'var(--primary)'
              let icon = '⚡'
              if (entry.event_type.includes('DETECTION')) { color = 'var(--danger)'; icon = '🚨' }
              if (entry.event_type.includes('AI_')) { color = '#a855f7'; icon = '🧠' }
              if (entry.event_type.includes('ACTION') || entry.event_type.includes('MONITOR')) { color = 'var(--safe)'; icon = '🛡️' }
              if (entry.event_type.includes('ESCALAT')) { color = 'var(--warning)'; icon = '⚠️' }

              return (
                <div key={idx} style={{ position: 'relative', paddingLeft: 32 }}>
                  <div style={{ position: 'absolute', left: -14, top: 4, width: 28, height: 28, borderRadius: '50%', background: 'var(--card-bg)', border: `2px solid ${color}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, zIndex: 1 }}>
                    {icon}
                  </div>
                  
                  <div className="card tight" style={{ borderColor: `${color}40`, background: 'rgba(7,12,24,0.6)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, alignItems: 'center' }}>
                      <strong style={{ color }}>{entry.event_type}</strong>
                      <span className="subtle" style={{ fontSize: 12 }}>{timeString}</span>
                    </div>
                    
                    <pre style={{ margin: 0, padding: 8, background: 'rgba(0,0,0,0.3)', borderRadius: 4, fontSize: 12, color: 'var(--muted)', overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
                      {JSON.stringify(entry.data, null, 2)}
                    </pre>

                    <div style={{ marginTop: 8, textAlign: 'right' }}>
                      <span className="mono" style={{ fontSize: 10, color: 'var(--muted-2)' }}>SHA256: {entry.hash}</span>
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
