import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
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

  useEffect(() => { 
    getTopology().then((data) => { 
      setTopology(data)
      if (data.nodes.length > 4) setSelected(data.nodes[4]) 
    }) 
  }, [])

  return (
    <div>
      <div className="page-header">
        <div>
          <p className="eyebrow">TOPOLOGY VISUALIZER</p>
          <h1>Critical Infrastructure Mesh</h1>
          <p className="subtle">Attack path particle simulation, honeypot placement, and IT/OT boundary security monitoring.</p>
        </div>

        <div className="filter-row" style={{ margin: 0 }}>
          <button 
            className={`pill-toggle ${showAttackPath ? 'active' : ''}`} 
            onClick={() => setShowAttackPath((v) => !v)}
          >
            {showAttackPath ? '✓ Attack Path' : 'Attack Path'}
          </button>
          <button 
            className={`pill-toggle ${showHoneypots ? 'active' : ''}`} 
            onClick={() => setShowHoneypots((v) => !v)}
          >
            {showHoneypots ? '✓ Honeypots' : 'Honeypots'}
          </button>
          <button 
            className={`pill-toggle ${showOtBoundary ? 'active' : ''}`} 
            onClick={() => setShowOtBoundary((v) => !v)}
          >
            {showOtBoundary ? '✓ OT Boundary' : 'OT Boundary'}
          </button>

          <select className="select" value={zone} onChange={(e) => setZone(e.target.value)}>
            <option value="all">All Zones</option>
            <option value="external">External</option>
            <option value="dmz">DMZ</option>
            <option value="it">IT Enterprise</option>
            <option value="ot_boundary">OT Boundary</option>
            <option value="ot">OT Process Control</option>
          </select>
        </div>
      </div>

      <div className="graph-layout">
        {topology && (
          <ThreatGraph 
            topology={topology} 
            height={680} 
            full 
            showAttackPath={showAttackPath} 
            showHoneypots={showHoneypots} 
            showOtBoundary={showOtBoundary} 
            zoneFilter={zone} 
            onNodeSelect={setSelected} 
          />
        )}

        <aside className="card entity-panel accent-primary">
          <h2>Entity Context Inspector</h2>
          {selected ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <strong style={{ fontSize: 16 }}>{selected.label}</strong>
                <StatusBadge status={selected.status} />
              </div>

              <div className="kv">
                <span>NODE ID</span>
                <strong className="mono" style={{ color: 'var(--primary)' }}>{selected.id}</strong>
              </div>

              <div className="kv">
                <span>CRITICALITY</span>
                <strong className="mono" style={{ color: selected.criticality >= 7 ? 'var(--danger)' : 'var(--text-main)' }}>
                  {selected.criticality} / 10
                </strong>
              </div>

              <div className="kv">
                <span>SECURITY ZONE</span>
                <strong className="mono">{selected.zone}</strong>
              </div>

              <div className="kv">
                <span>OPERATIONAL STATE</span>
                <strong className="mono">{selected.status}</strong>
              </div>

              {selected.status === 'compromised' ? (
                <div className="warning-card" style={{ marginTop: 16 }}>
                  🚨 <strong>Compromised Entity:</strong> High threat correlation. Click below to inspect AI reasoning.
                  <div style={{ marginTop: 10 }}>
                    <Link to="/reasoning/INC-GRAPH-001" className="btn primary" style={{ width: '100%', fontSize: 12 }}>
                      Inspect AI Reasoning Trace →
                    </Link>
                  </div>
                </div>
              ) : (
                <div className="subtle" style={{ fontSize: 12, marginTop: 16 }}>
                  Select any node in the topology canvas to inspect live telemetry and vulnerability state.
                </div>
              )}
            </>
          ) : (
            <p className="subtle">Select a node in the graph to inspect operational context.</p>
          )}
        </aside>
      </div>
    </div>
  )
}
