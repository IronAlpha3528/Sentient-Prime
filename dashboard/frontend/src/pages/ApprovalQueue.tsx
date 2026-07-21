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
    <div style={{ maxWidth: 1000, margin: '0 auto' }}>
      <div className="page-header">
        <div>
          <p className="eyebrow">HUMAN-IN-THE-LOOP GOVERNANCE</p>
          <h1>Analyst Approval Queue</h1>
          <p className="subtle">High-risk AI containment actions awaiting explicit human decision under policy gate controls.</p>
        </div>
        <span className="badge danger" style={{ fontSize: 13, padding: '6px 16px' }}>
          ⚡ {incidents.length} Pending Actions
        </span>
      </div>

      {incidents.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 60 }}>
          <div style={{ fontSize: 44, marginBottom: 16, color: 'var(--safe)' }}>✓</div>
          <h2 style={{ color: 'var(--safe)' }}>Approval Queue Clear</h2>
          <p className="subtle" style={{ maxWidth: 480, margin: '0 auto' }}>
            No incidents currently require manual analyst authorization. Low-risk containment actions were auto-approved by the policy gate.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {incidents.map((inc) => {
            const isExpanded = expanded === inc.incident_id
            const threatColor = inc.unified_threat_score >= 0.75 ? 'var(--danger)' : inc.unified_threat_score >= 0.5 ? 'var(--warning)' : 'var(--safe)'

            return (
              <div 
                key={inc.incident_id} 
                className={`card accent-${inc.unified_threat_score >= 0.75 ? 'danger' : 'warning'}`}
              >
                {/* Row Header */}
                <div 
                  style={{ display: 'grid', gridTemplateColumns: '1fr auto', alignItems: 'center', gap: 16, cursor: 'pointer' }} 
                  onClick={() => setExpanded(isExpanded ? null : inc.incident_id)}
                >
                  <div>
                    <div className="action-row" style={{ marginBottom: 8 }}>
                      <StatusBadge status={inc.status} />
                      <span className="mono" style={{ color: 'var(--primary)', fontWeight: 700, fontSize: 16 }}>
                        {inc.incident_id}
                      </span>
                      <span className="badge neutral">{inc.attack_class}</span>
                    </div>

                    <p className="subtle" style={{ margin: 0, fontSize: 13 }}>
                      Target: <strong style={{ color: 'var(--text-main)' }}>{inc.target_asset}</strong> &nbsp;|&nbsp;
                      Hosts: <span className="mono">{inc.entities.hosts.join(', ')}</span> &nbsp;|&nbsp;
                      {new Date(inc.timestamp).toLocaleString()}
                    </p>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                    <div style={{ textAlign: 'right' }}>
                      <div className="mono" style={{ color: threatColor, fontSize: 24, fontWeight: 800, lineHeight: 1 }}>
                        {inc.unified_threat_score.toFixed(2)}
                      </div>
                      <div style={{ fontSize: 10, color: 'var(--text-subtle)', textTransform: 'uppercase', letterSpacing: '1px' }}>THREAT SCORE</div>
                    </div>
                    
                    <button className="btn secondary" style={{ height: 32, padding: '0 10px', fontSize: 12 }}>
                      {isExpanded ? 'Hide ▲' : 'Details ▼'}
                    </button>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div style={{ marginTop: 20, paddingTop: 20, borderTop: '1px solid var(--border)' }}>
                    <div className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 16 }}>
                      <div className="data-box">
                        <span>Target User Accounts</span>
                        <strong className="mono">{inc.entities.users.join(', ') || 'None'}</strong>
                      </div>
                      <div className="data-box">
                        <span>Source IP Addresses</span>
                        <strong className="mono">{inc.entities.ips.join(', ') || 'None'}</strong>
                      </div>
                      <div className="data-box">
                        <span>OT Boundary Assets</span>
                        <strong className="mono">{inc.entities.ot_assets.join(', ') || 'None'}</strong>
                      </div>
                    </div>

                    {messages[inc.incident_id] && (
                      <div className="warning-card" style={{ borderColor: 'rgba(52,211,153,0.3)', background: 'rgba(52,211,153,0.08)', color: 'var(--safe)', marginBottom: 16 }}>
                        {messages[inc.incident_id]}
                      </div>
                    )}

                    <div style={{ display: 'flex', gap: 12, marginTop: 12 }}>
                      <button
                        className="btn secondary"
                        style={{ fontSize: 12 }}
                        onClick={() => navigate(`/reasoning/${inc.incident_id}`)}
                      >
                        Inspect AI Reasoning Path →
                      </button>

                      <button
                        className="btn primary"
                        disabled={submitting === inc.incident_id}
                        onClick={() => handle(inc.incident_id, 'approve')}
                        style={{ flex: 1 }}
                      >
                        {submitting === inc.incident_id ? 'Authorizing...' : '✓ Approve & Dispatch Containment'}
                      </button>

                      <button
                        className="btn danger"
                        disabled={submitting === inc.incident_id}
                        onClick={() => handle(inc.incident_id, 'reject')}
                        style={{ flex: 1 }}
                      >
                        ✕ Reject Action / Monitor
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
