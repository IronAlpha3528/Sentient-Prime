import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { approveIncident, getApprovalQueue, rejectIncident, type Incident } from '../api/client'
import StatusBadge from '../components/StatusBadge'

export default function ApprovalQueue() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState<string | null>(null)
  const [messages, setMessages] = useState<Record<string, string>>({})
  const navigate = useNavigate()

  const load = () => getApprovalQueue().then(setIncidents).catch(() => setIncidents([]))

  useEffect(() => { load() }, [])

  const handle = async (id: string, action: 'approve' | 'reject') => {
    setSubmitting(id)
    try {
      if (action === 'approve') {
        await approveIncident(id)
        setMessages((m) => ({ ...m, [id]: '✓ Containment approved. SOAR playbook dispatched.' }))
      } else {
        await rejectIncident(id)
        setMessages((m) => ({ ...m, [id]: '✓ Action rejected. Incident remains in monitoring queue.' }))
      }
      await load()
    } catch (e) {
      setMessages((m) => ({ ...m, [id]: e instanceof Error ? e.message : 'Action failed.' }))
    } finally {
      setSubmitting(null)
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <p className="eyebrow">Human-in-the-Loop</p>
          <h1>Approval Queue</h1>
          <p className="subtle">Incidents awaiting analyst decision before containment is executed</p>
        </div>
        <span className="badge danger" style={{ fontSize: 14, padding: '4px 16px' }}>{incidents.length} Pending</span>
      </div>

      {incidents.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 48 }}>
          <div style={{ fontSize: 40, marginBottom: 16 }}>✓</div>
          <h2 style={{ color: 'var(--safe)' }}>Queue Clear</h2>
          <p className="subtle">No incidents currently require manual approval. All actions were auto-authorized by the policy gate.</p>
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 12 }}>
          {incidents.map((inc) => {
            const isExpanded = expanded === inc.incident_id
            const threatColor = inc.unified_threat_score >= 0.75 ? 'var(--danger)' : inc.unified_threat_score >= 0.5 ? 'var(--warning)' : 'var(--safe)'
            return (
              <div key={inc.incident_id} className="card" style={{ borderColor: inc.unified_threat_score >= 0.75 ? 'rgba(239,68,68,0.30)' : 'var(--border)' }}>
                {/* Row header */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', alignItems: 'center', gap: 16, cursor: 'pointer' }} onClick={() => setExpanded(isExpanded ? null : inc.incident_id)}>
                  <div>
                    <div className="action-row" style={{ marginBottom: 6 }}>
                      <StatusBadge status={inc.status} />
                      <span className="mono" style={{ color: 'var(--primary)', fontWeight: 700 }}>{inc.incident_id}</span>
                      <span className="badge neutral">{inc.attack_class}</span>
                    </div>
                    <p className="subtle" style={{ margin: 0, fontSize: 12 }}>
                      Target: <strong>{inc.target_asset}</strong> &nbsp;|&nbsp;
                      Hosts: {inc.entities.hosts.join(', ')} &nbsp;|&nbsp;
                      {new Date(inc.timestamp).toLocaleString()}
                    </p>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{ textAlign: 'right' }}>
                      <div className="mono" style={{ color: threatColor, fontSize: 22, fontWeight: 700 }}>{inc.unified_threat_score.toFixed(2)}</div>
                      <div style={{ fontSize: 11, color: 'var(--muted)' }}>Threat Score</div>
                    </div>
                    <div style={{ width: 60, height: 60, borderRadius: '50%', border: `3px solid ${threatColor}`, display: 'grid', placeItems: 'center', background: `${threatColor}14` }}>
                      <span style={{ fontSize: 22 }}>{inc.unified_threat_score >= 0.75 ? '🔴' : '🟡'}</span>
                    </div>
                  </div>
                </div>

                {/* Expanded detail panel */}
                {isExpanded && (
                  <div style={{ marginTop: 20, borderTop: '1px solid var(--border)', paddingTop: 20 }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginBottom: 16 }}>
                      <div className="data-box"><span>Users</span><strong className="mono">{inc.entities.users.join(', ') || '—'}</strong></div>
                      <div className="data-box"><span>Source IPs</span><strong className="mono">{inc.entities.ips.join(', ') || '—'}</strong></div>
                      <div className="data-box"><span>OT Assets</span><strong className="mono">{inc.entities.ot_assets.join(', ') || 'None'}</strong></div>
                    </div>
                    <div className="action-row" style={{ marginBottom: 8 }}>
                      <button className="btn secondary" style={{ fontSize: 12 }} onClick={() => navigate(`/reasoning/${inc.incident_id}`)}>
                        View Full AI Reasoning →
                      </button>
                    </div>
                    {messages[inc.incident_id] && (
                      <div className="warning-card" style={{ marginBottom: 12 }}>{messages[inc.incident_id]}</div>
                    )}
                    <div className="action-row" style={{ marginTop: 8 }}>
                      <button
                        className="btn primary"
                        disabled={submitting === inc.incident_id}
                        onClick={() => handle(inc.incident_id, 'approve')}
                        style={{ background: 'linear-gradient(135deg,#bbf7d0,#6ee7b7)', flex: 1 }}
                      >
                        {submitting === inc.incident_id ? 'Submitting…' : '✓ Approve Containment'}
                      </button>
                      <button
                        className="btn secondary"
                        disabled={submitting === inc.incident_id}
                        onClick={() => handle(inc.incident_id, 'reject')}
                        style={{ borderColor: 'rgba(239,68,68,0.4)', color: 'var(--danger)', flex: 1 }}
                      >
                        ✕ Reject / Monitor Only
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
