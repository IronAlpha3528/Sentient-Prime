import { useNavigate } from 'react-router-dom'
import type { Incident } from '../api/client'
import StatusBadge from './StatusBadge'

const scoreClass = (score: number) => score >= 0.75 ? 'high' : score >= 0.5 ? 'mid' : 'low'
const relativeTime = (iso: string) => {
  const mins = Math.max(1, Math.round((Date.now() - new Date(iso).getTime()) / 60000))
  if (mins < 60) return `${mins} min ago`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return new Date(iso).toLocaleDateString()
}

export default function IncidentTable({ incidents, compact = false }: { incidents: Incident[]; compact?: boolean }) {
  const navigate = useNavigate()
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th><th>Status</th><th>Score</th><th>Target</th>{!compact && <th>Attack Class</th>}<th>{compact ? 'Time' : 'Entities'}</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((incident) => {
            const entityCount = incident.entities.users.length + incident.entities.hosts.length
            return (
              <tr key={incident.incident_id} className="clickable" onClick={() => navigate(`/reasoning/${incident.incident_id}`)}>
                <td className="mono">{incident.incident_id}</td>
                <td><StatusBadge status={incident.status} /></td>
                <td className={`score ${scoreClass(incident.unified_threat_score)}`}>{incident.unified_threat_score.toFixed(2)}</td>
                <td>{incident.target_asset}</td>
                {!compact && <td>{incident.attack_class}</td>}
                <td>{compact ? relativeTime(incident.timestamp) : `${entityCount} entities`}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
