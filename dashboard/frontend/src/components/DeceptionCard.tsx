import type { ReasoningOutput } from '../api/client'
import StatusBadge from './StatusBadge'

export default function DeceptionCard({ strategy }: { strategy: ReasoningOutput['deception_strategy'] }) {
  return (
    <section className="card" id="deception">
      <div className="page-header" style={{ marginBottom: 12 }}>
        <div><h2>Deception Strategy</h2><p className="subtle">Testing: {strategy.hypothesis_to_test}</p></div>
        <StatusBadge status={strategy.should_deploy ? 'ACTIVE' : 'EXPIRED'} />
      </div>
      <div className="deception-grid">
        <div className="data-box"><span>Decoy Type</span><strong>{strategy.decoy_type}</strong></div>
        <div className="data-box"><span>Placement Node</span><strong className="mono">{strategy.placement_node}</strong></div>
        <div className="data-box"><span>Observation Window</span><strong className="mono">{strategy.observation_window_minutes} min</strong></div>
      </div>
      <p className="subtle" style={{ lineHeight: 1.7, marginBottom: 0 }}>{strategy.rationale}</p>
    </section>
  )
}
