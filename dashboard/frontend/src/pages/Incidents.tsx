import { useEffect, useMemo, useState } from 'react'
import { getIncidents, type Incident, type IncidentStatus } from '../api/client'
import IncidentTable from '../components/IncidentTable'

const filters = ['All', 'Active', 'Escalated', 'Resolved']

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [filter, setFilter] = useState('All')
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => { 
    getIncidents().then(setIncidents) 
  }, [])

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchesFilter = filter === 'All' ? true : inc.status === filter.toUpperCase() as IncidentStatus
      const matchesQuery = searchQuery === '' || 
        inc.incident_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inc.target_asset.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inc.attack_class.toLowerCase().includes(searchQuery.toLowerCase())
      return matchesFilter && matchesQuery
    })
  }, [filter, searchQuery, incidents])

  const activeCount = incidents.filter((i) => i.status === 'ACTIVE').length
  const escalatedCount = incidents.filter((i) => i.status === 'ESCALATED').length
  const resolvedCount = incidents.filter((i) => i.status === 'RESOLVED').length

  return (
    <div>
      <div className="page-header">
        <div>
          <p className="eyebrow">INCIDENT MANAGEMENT</p>
          <h1>Active Investigation Surface</h1>
          <p className="subtle">Correlated threat telemetry, multi-stage attack paths, and policy enforcement.</p>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <span className="badge warning" style={{ padding: '6px 14px', fontSize: 12 }}>{activeCount} Active</span>
          <span className="badge danger" style={{ padding: '6px 14px', fontSize: 12 }}>{escalatedCount} Escalated</span>
          <span className="badge safe" style={{ padding: '6px 14px', fontSize: 12 }}>{resolvedCount} Resolved</span>
        </div>
      </div>

      <section className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
          <div className="filter-row" style={{ margin: 0 }}>
            {filters.map((item) => (
              <button 
                key={item} 
                className={`pill-toggle ${filter === item ? 'active' : ''}`} 
                onClick={() => setFilter(item)}
              >
                {item}
              </button>
            ))}
          </div>

          <div style={{ position: 'relative', width: 260 }}>
            <input 
              type="text" 
              placeholder="Search incidents or targets..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="select"
              style={{ width: '100%', paddingLeft: 32 }}
            />
            <svg 
              width="14" 
              height="14" 
              viewBox="0 0 24 24" 
              fill="none" 
              stroke="var(--text-subtle)" 
              strokeWidth="2" 
              style={{ position: 'absolute', left: 10, top: 12 }}
            >
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
          </div>
        </div>

        <IncidentTable incidents={filteredIncidents} />
      </section>
    </div>
  )
}
