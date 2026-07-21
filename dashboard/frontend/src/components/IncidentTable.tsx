import { useNavigate } from 'react-router-dom'
import type { Incident } from '../api/client'
import StatusBadge from './StatusBadge'

const scoreClass = (score: number) => score >= 0.75 ? 'high' : score >= 0.5 ? 'mid' : 'low'
const relativeTime = (iso: string) => {
  const mins = Math.max(1, Math.round((Date.now() - new Date(iso).getTime()) / 60000))
  if (mins < 60) return `${mins}m ago`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return new Date(iso).toLocaleDateString()
}

export default function IncidentTable({ incidents, compact = false }: { incidents: Incident[]; compact?: boolean }) {
  const navigate = useNavigate()

  if (!incidents.length) {
    return (
      <div style={{ textAlign: 'center', padding: '32px 0', color: 'var(--text-subtle)' }}>
        No incidents match the current criteria.
      </div>
    )
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>INCIDENT ID</th>
            <th>STATUS</th>
            <th>THREAT SCORE</th>
            <th>TARGET ASSET</th>
            {!compact && <th>ATTACK CLASS</th>}
            <th>{compact ? 'TIMESTAMP' : 'ENTITIES'}</th>
            <th>ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => {
            const entityCount = incident.entities.users.length + incident.entities.hosts.length + incident.entities.ips.length
            return (
              <tr 
                key={incident.incident_id} 
                className="clickable" 
                onClick={() => navigate(`/reasoning/${incident.incident_id}`)}
              >
                <td className="mono" style={{ fontWeight: 600, color: 'var(--primary)' }}>
                  {incident.incident_id}
                </td>
                <td><StatusBadge status={incident.status} /></td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span className={`score ${scoreClass(incident.unified_threat_score)}`} style={{ fontSize: 15 }}>
                      {incident.unified_threat_score.toFixed(2)}
                    </span>
                  </div>
                </td>
                <td style={{ fontWeight: 500 }}>{incident.target_asset}</td>
                {!compact && (
                  <td>
                    <span className="badge neutral">{incident.attack_class}</span>
                  </td>
                )}
                <td className="subtle" style={{ fontSize: 12 }}>
                  {compact ? relativeTime(incident.timestamp) : `${entityCount} affected`}
                </td>
                <td onClick={(e) => e.stopPropagation()}>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button 
                      className="btn secondary" 
                      style={{ padding: '4px 10px', height: 28, fontSize: 11 }} 
                      onClick={() => navigate(`/reasoning/${incident.incident_id}`)}
                    >
                      AI Reasoning →
                    </button>
                    <button 
                      className="btn secondary" 
                      style={{ padding: '4px 10px', height: 28, fontSize: 11 }} 
                      onClick={() => navigate(`/timeline/${incident.incident_id}`)}
                    >
                      Timeline
                    </button>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
