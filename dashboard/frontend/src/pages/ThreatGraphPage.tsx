import { useEffect, useState } from 'react'
import { getTopology, type Topology, type TopologyNode } from '../api/client'
import StatusBadge from '../components/StatusBadge'
import ThreatGraph from '../components/ThreatGraph'

export default function ThreatGraphPage() {
  const [topology, setTopology] = useState<Topology | null>(null)
  const [selected, setSelected] = useState<TopologyNode | null>(null)
  const [showAttackPath, setShowAttackPath] = useState(true)
  const [showHoneypots, setShowHoneypots] = useState(true)
  const [showOtBoundary, setShowOtBoundary] = useState(true)
  const [zone, setZone] = useState('all')
  useEffect(() => { getTopology().then((data) => { setTopology(data); setSelected(data.nodes[4]) }) }, [])

  return (
    <div>
      <div className="page-header">
        <div><p className="eyebrow">Threat Graph</p><h1>CNI Topology Visualizer</h1><p className="subtle">Attack path particles, honeypot placement, and OT boundary context.</p></div>
        <div className="filter-row">
          <button className={`pill-toggle ${showAttackPath ? 'active' : ''}`} onClick={() => setShowAttackPath((v) => !v)}>Attack Path</button>
          <button className={`pill-toggle ${showHoneypots ? 'active' : ''}`} onClick={() => setShowHoneypots((v) => !v)}>Honeypots</button>
          <button className={`pill-toggle ${showOtBoundary ? 'active' : ''}`} onClick={() => setShowOtBoundary((v) => !v)}>OT Boundary</button>
          <select className="select" value={zone} onChange={(event) => setZone(event.target.value)}>
            <option value="all">All Zones</option><option value="external">External</option><option value="dmz">DMZ</option><option value="it">IT</option><option value="ot_boundary">OT Boundary</option><option value="ot">OT</option>
          </select>
        </div>
      </div>
      <div className="graph-layout">
        {topology && <ThreatGraph topology={topology} height={680} full showAttackPath={showAttackPath} showHoneypots={showHoneypots} showOtBoundary={showOtBoundary} zoneFilter={zone} onNodeSelect={setSelected} />}
        <aside className="card entity-panel">
          <h2>Entity Details</h2>
          {selected ? (
            <>
              <div className="action-row"><strong>{selected.label}</strong><StatusBadge status={selected.status} /></div>
              <div className="kv"><span>ID</span><strong className="mono">{selected.id}</strong></div>
              <div className="kv"><span>Criticality</span><strong className="mono">{selected.criticality}/10</strong></div>
              <div className="kv"><span>Zone</span><strong className="mono">{selected.zone}</strong></div>
              <div className="kv"><span>Status</span><strong className="mono">{selected.status}</strong></div>
              <div className="warning-card">Click a compromised entity to open its AI reasoning trace.</div>
            </>
          ) : <p className="subtle">Select a node to inspect its operational context.</p>}
        </aside>
      </div>
    </div>
  )
}
