import { useEffect, useMemo, useState } from 'react'
import { getIncidents, type Incident, type IncidentStatus } from '../api/client'
import IncidentTable from '../components/IncidentTable'

const filters = ['All', 'Active', 'Escalated', 'Resolved']

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [filter, setFilter] = useState('All')
  useEffect(() => { getIncidents().then(setIncidents) }, [])
  const visible = useMemo(() => filter === 'All' ? incidents : incidents.filter((incident) => incident.status === filter.toUpperCase() as IncidentStatus), [filter, incidents])

  return (
    <div>
      <div className="page-header"><div><p className="eyebrow">Incident Queue</p><h1>Active Investigation Surface</h1><p className="subtle">Filter, inspect, and route AI-correlated incidents.</p></div></div>
      <section className="card">
        <div className="filter-row">
          {filters.map((item) => <button key={item} className={`pill-toggle ${filter === item ? 'active' : ''}`} onClick={() => setFilter(item)}>{item}</button>)}
        </div>
        <IncidentTable incidents={visible} />
      </section>
    </div>
  )
}
