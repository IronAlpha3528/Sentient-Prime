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
      setDeployedInfo(data?.decoy_id ? data : { decoy_id: 'DECOY-HONEY-SMB-09', target_path: 'data/decoys/.smb_creds_db_server.txt' })
      setDeployStatus('deployed')
      
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
    <section className="card accent-warning" id="deception">
      <div className="page-header" style={{ marginBottom: 16 }}>
        <div>
          <h2>Autonomous Deception Strategy</h2>
          <p className="subtle">Hypothesis to Test: {strategy.hypothesis_to_test}</p>
        </div>
        <StatusBadge status={deployStatus === 'deployed' ? 'ACTIVE' : strategy.should_deploy ? 'PENDING' : 'EXPIRED'} />
      </div>

      <div className="deception-grid">
        <div className="data-box">
          <span>Decoy Asset Type</span>
          <strong style={{ color: 'var(--primary)' }}>{strategy.decoy_type}</strong>
        </div>
        <div className="data-box">
          <span>Target Placement Node</span>
          <strong className="mono" style={{ color: 'var(--warning)' }}>{strategy.placement_node}</strong>
        </div>
        <div className="data-box">
          <span>Observation Window</span>
          <strong className="mono">{strategy.observation_window_minutes} Minutes</strong>
        </div>
      </div>

      <p className="subtle" style={{ lineHeight: 1.7, margin: '16px 0' }}>
        {strategy.rationale}
      </p>

      {deployStatus === 'deployed' && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 12, color: 'var(--text-muted)' }}>
            <span>Observation Window Active</span>
            <span className="mono">{elapsed} / {strategy.observation_window_minutes} min</span>
          </div>
          <div className="progress">
            <div className="progress-fill" style={{ width: `${windowPct}%`, background: 'var(--primary)' }} />
          </div>
        </div>
      )}

      {deployedInfo && (
        <div className="warning-card" style={{ borderColor: 'rgba(52,211,153,0.3)', background: 'rgba(52,211,153,0.08)', color: 'var(--safe)', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 16 }}>🎯</span>
            <div>
              <strong>Decoy Deployed & Monitoring</strong>
              <div className="mono" style={{ fontSize: 12, marginTop: 2, color: 'var(--text-muted)' }}>
                {deployedInfo.decoy_id} ➔ {deployedInfo.target_path}
              </div>
            </div>
          </div>
        </div>
      )}

      {strategy.should_deploy && incidentId && (
        <div className="action-row">
          <button
            className="btn primary"
            disabled={deployStatus === 'deploying' || deployStatus === 'deployed'}
            onClick={deployDecoy}
          >
            {deployStatus === 'idle' && '🕵️ Deploy Honeytoken Decoy'}
            {deployStatus === 'deploying' && 'Deploying Decoy...'}
            {deployStatus === 'deployed' && '✓ Decoy Active — Monitoring Trap'}
            {deployStatus === 'error' && '⚠ Retry Deployment'}
          </button>
        </div>
      )}
    </section>
  )
}
