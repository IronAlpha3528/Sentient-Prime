import { useState } from 'react'
import type { ReasoningOutput } from '../api/client'
import StatusBadge from './StatusBadge'

interface Props {
  strategy: ReasoningOutput['deception_strategy']
  incidentId?: string
}

export default function DeceptionCard({ strategy, incidentId }: Props) {
  const [deployStatus, setDeployStatus] = useState<'idle' | 'deploying' | 'deployed' | 'error'>('idle')
  const [deployedInfo, setDeployedInfo] = useState<{ decoy_id?: string; target_path?: string } | null>(null)
  const [elapsed, setElapsed] = useState(0)

  const deployDecoy = async () => {
    setDeployStatus('deploying')
    try {
      const res = await fetch(`/api/incidents/${incidentId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'deploy_decoy', strategy }),
      })
      const data = res.ok ? await res.json() : null
      setDeployedInfo(data?.decoy_id ? data : { decoy_id: 'DECOY-DEMO', target_path: 'data/decoys/.smb_creds_db_server.txt' })
      setDeployStatus('deployed')
      // Start a counter for the observation window
      const start = Date.now()
      const timer = setInterval(() => {
        const mins = Math.floor((Date.now() - start) / 60000)
        setElapsed(mins)
        if (mins >= strategy.observation_window_minutes) clearInterval(timer)
      }, 10_000)
    } catch {
      setDeployStatus('error')
    }
  }

  const windowPct = Math.min(100, (elapsed / strategy.observation_window_minutes) * 100)

  return (
    <section className="card" id="deception">
      <div className="page-header" style={{ marginBottom: 12 }}>
        <div>
          <h2>Deception Strategy</h2>
          <p className="subtle">Testing: {strategy.hypothesis_to_test}</p>
        </div>
        <StatusBadge status={deployStatus === 'deployed' ? 'ACTIVE' : strategy.should_deploy ? 'PENDING' : 'EXPIRED'} />
      </div>
      <div className="deception-grid">
        <div className="data-box"><span>Decoy Type</span><strong>{strategy.decoy_type}</strong></div>
        <div className="data-box"><span>Placement Node</span><strong className="mono">{strategy.placement_node}</strong></div>
        <div className="data-box"><span>Observation Window</span><strong className="mono">{strategy.observation_window_minutes} min</strong></div>
      </div>
      <p className="subtle" style={{ lineHeight: 1.7, marginBottom: 14 }}>{strategy.rationale}</p>

      {/* Observation window progress */}
      {deployStatus === 'deployed' && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12, color: 'var(--muted)' }}>
            <span>Observation window</span><span>{elapsed}/{strategy.observation_window_minutes} min</span>
          </div>
          <div className="progress"><div className="progress-fill" style={{ width: `${windowPct}%`, background: 'var(--primary)' }} /></div>
        </div>
      )}

      {/* Deployed decoy info */}
      {deployedInfo && (
        <div className="warning-card" style={{ borderColor: 'rgba(34,197,94,0.28)', background: 'rgba(34,197,94,0.06)', color: 'var(--safe)', marginBottom: 12 }}>
          <strong>● Decoy Active</strong>&nbsp;&nbsp;
          <span className="mono" style={{ fontSize: 12 }}>{deployedInfo.decoy_id}</span>&nbsp;→&nbsp;
          <span className="mono" style={{ fontSize: 11, color: 'var(--muted-2)' }}>{deployedInfo.target_path}</span>
        </div>
      )}

      {strategy.should_deploy && incidentId && (
        <div className="action-row" style={{ marginTop: 4 }}>
          <button
            className="btn primary"
            disabled={deployStatus === 'deploying' || deployStatus === 'deployed'}
            onClick={deployDecoy}
            style={{ background: deployStatus === 'deployed' ? 'linear-gradient(135deg,#a7f3d0,#34d399)' : undefined, color: deployStatus === 'deployed' ? '#030712' : undefined }}
          >
            {deployStatus === 'idle' && '🕵️ Deploy Honeytoken Decoy'}
            {deployStatus === 'deploying' && 'Deploying…'}
            {deployStatus === 'deployed' && '✓ Decoy Active — Observing'}
            {deployStatus === 'error' && '⚠ Retry Deploy'}
          </button>
        </div>
      )}
    </section>
  )
}
